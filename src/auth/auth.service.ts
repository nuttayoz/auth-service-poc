import {
  BadRequestException,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UserRole, UserStatus } from '@prisma/client';
import type { User } from '@prisma/client';
import { Request, Response } from 'express';
import { CryptoService } from '../crypto/crypto.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { ZitadelService } from '../zitadel/zitadel.service.js';
import { OidcClientService } from './oidc-client.service.js';
import type { SessionContext } from './session.service.js';

const OIDC_REQUEST_TTL_MS = 10 * 60 * 1000;
const REFRESH_SKEW_MS = 2 * 60 * 1000;
const DEFAULT_SCOPES = 'openid profile email offline_access';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly oidc: OidcClientService,
    private readonly zitadel: ZitadelService,
  ) {}

  async login(res: Response, redirect?: string): Promise<void> {
    await this.startOidc(res, redirect);
  }

  async adminSignup(payload: {
    orgName?: string;
    orgDomain?: string;
    email?: string;
    password?: string;
    firstName?: string;
    lastName?: string;
    userName?: string;
  }): Promise<{ orgId: string; userId: string }> {
    this.assertOidcEnabled();

    const orgName = payload.orgName?.trim();
    const email = payload.email?.trim().toLowerCase();
    const password = payload.password ?? '';

    if (!orgName) {
      throw new BadRequestException('orgName is required');
    }
    if (!email) {
      throw new BadRequestException('email is required');
    }
    if (!password) {
      throw new BadRequestException('password is required');
    }

    this.logger.log(`Admin signup start: org="${orgName}" email="${email}"`);

    const result = await this.zitadel.setupOrganization({
      orgName,
      orgDomain: payload.orgDomain?.trim() || undefined,
      admin: {
        email,
        password,
        firstName: payload.firstName?.trim() || 'Admin',
        lastName: payload.lastName?.trim() || 'User',
        userName: payload.userName?.trim() || email,
      },
    });

    await this.prisma.org.upsert({
      where: { id: result.orgId },
      create: { id: result.orgId, name: orgName },
      update: { name: orgName },
    });

    await this.prisma.user.upsert({
      where: { id: result.userId },
      create: {
        id: result.userId,
        orgId: result.orgId,
        email,
        role: UserRole.ROOT,
        status: UserStatus.ACTIVE,
      },
      update: {
        orgId: result.orgId,
        email,
        role: UserRole.ROOT,
        status: UserStatus.ACTIVE,
      },
    });

    this.logger.log(
      `Admin signup complete: orgId="${result.orgId}" userId="${result.userId}"`,
    );

    return result;
  }

  private async startOidc(
    res: Response,
    redirect: string | undefined,
  ): Promise<void> {
    this.assertOidcEnabled();
    this.assertCryptoEnabled();

    const oidc = this.oidc.getModule();
    const config = await this.oidc.getConfig();

    const state = oidc.randomState();
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
    const nonce = oidc.randomNonce();

    const sanitizedRedirect = this.sanitizeRedirect(redirect);

    await this.prisma.oidcRequest.create({
      data: {
        state,
        codeVerifier,
        nonce,
        redirectUri: sanitizedRedirect,
      },
    });

    const scope = this.buildScope();
    const redirectUri = this.requireConfig('ZITADEL_REDIRECT_URI');

    const url = oidc.buildAuthorizationUrl(config, {
      scope,
      redirect_uri: redirectUri,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      nonce,
    });

    res.redirect(url.toString());
  }

  async callback(req: Request, res: Response): Promise<void> {
    this.assertOidcEnabled();
    this.assertCryptoEnabled();

    const state =
      typeof req.query.state === 'string' ? req.query.state : undefined;

    if (!state) {
      throw new BadRequestException('Missing state');
    }

    const stored = await this.prisma.oidcRequest.findUnique({
      where: { state },
    });

    if (!stored) {
      throw new UnauthorizedException('Invalid state');
    }

    if (Date.now() - stored.createdAt.getTime() > OIDC_REQUEST_TTL_MS) {
      await this.prisma.oidcRequest.delete({ where: { id: stored.id } });
      throw new UnauthorizedException('State expired');
    }

    const oidc = this.oidc.getModule();
    const config = await this.oidc.getConfig();
    const redirectUri = this.requireConfig('ZITADEL_REDIRECT_URI');
    const currentUrl = new URL(
      `${req.protocol}://${req.get('host')}${req.originalUrl}`,
    );

    const tokenSet = await oidc.authorizationCodeGrant(
      config,
      currentUrl,
      {
        pkceCodeVerifier: stored.codeVerifier,
        expectedState: stored.state,
        expectedNonce: stored.nonce,
      },
      { redirect_uri: redirectUri },
    );

    await this.prisma.oidcRequest.delete({ where: { id: stored.id } });

    const accessToken = tokenSet?.access_token ?? '';
    const refreshToken = tokenSet?.refresh_token ?? '';

    if (!accessToken) {
      throw new UnauthorizedException('Missing access token');
    }

    const claims = tokenSet?.claims?.() ?? {};
    const zitadelSub = this.extractUserId(claims);
    const orgId = this.extractOrgId(claims);
    const email = this.extractEmail(claims);
    const roles = this.extractRoles(claims);
    const user = await this.resolveUserFromOidc({
      userId: zitadelSub,
      orgId,
      email,
      roles,
    });

    const accessExpiresAt = this.resolveAccessExpiry(tokenSet);

    const encAccess = this.crypto.encrypt(accessToken);
    const encRefresh = this.crypto.encrypt(refreshToken);

    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        orgId: user.orgId,
        accessExpiresAt,
        refreshExpiresAt: null,
        tokens: {
          create: {
            accessTokenEnc: Buffer.from(encAccess.ciphertext, 'base64'),
            accessTokenNonce: Buffer.from(encAccess.nonce, 'base64'),
            accessTokenTag: Buffer.from(encAccess.tag, 'base64'),
            refreshTokenEnc: Buffer.from(encRefresh.ciphertext, 'base64'),
            refreshTokenNonce: Buffer.from(encRefresh.nonce, 'base64'),
            refreshTokenTag: Buffer.from(encRefresh.tag, 'base64'),
            keyId: encAccess.keyId,
          },
        },
      },
    });

    this.setSessionCookie(res, session.id);

    if (stored.redirectUri) {
      res.redirect(stored.redirectUri);
      return;
    }

    res.json({
      sessionId: session.id,
      userId: user.id,
      orgId: user.orgId,
      roles: [user.role],
    });
  }

  async logout(req: Request, res: Response): Promise<void> {
    this.assertOidcEnabled();

    const cookieName =
      this.config.get<string>('SESSION_COOKIE_NAME') ?? 'auth_session';
    const sessionId = req.cookies?.[cookieName];

    if (sessionId) {
      await this.prisma.session
        .delete({ where: { id: sessionId } })
        .catch(() => undefined);
    }

    this.clearSessionCookie(res);
    res.status(204).send();
  }

  async refreshSession(sessionId: string): Promise<SessionContext> {
    this.assertOidcEnabled();
    this.assertCryptoEnabled();

    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { tokens: true, user: true },
    });

    if (!session || !session.tokens || !session.user) {
      throw new UnauthorizedException('Session not found');
    }

    const now = Date.now();
    if (session.accessExpiresAt.getTime() - now > REFRESH_SKEW_MS) {
      return {
        id: session.id,
        userId: session.userId,
        orgId: session.orgId ?? null,
        roles: [session.user.role],
        permissions: [],
        accessExpiresAt: session.accessExpiresAt,
        accessExpired: false,
      };
    }

    const refreshToken = this.crypto
      .decrypt({
        keyId: session.tokens.keyId,
        ciphertext: Buffer.from(session.tokens.refreshTokenEnc).toString(
          'base64',
        ),
        nonce: Buffer.from(session.tokens.refreshTokenNonce).toString('base64'),
        tag: Buffer.from(session.tokens.refreshTokenTag).toString('base64'),
      })
      .toString('utf8');

    if (!refreshToken) {
      throw new UnauthorizedException('Missing refresh token');
    }

    const oidc = this.oidc.getModule();
    const config = await this.oidc.getConfig();

    const tokenSet = await oidc.refreshTokenGrant(config, refreshToken);

    const accessToken = tokenSet?.access_token ?? '';
    if (!accessToken) {
      throw new UnauthorizedException('Missing access token');
    }

    const accessExpiresAt = this.resolveAccessExpiry(tokenSet);
    const newRefreshToken = tokenSet?.refresh_token || refreshToken;

    const encAccess = this.crypto.encrypt(accessToken);
    const encRefresh = this.crypto.encrypt(newRefreshToken);

    await this.prisma.session.update({
      where: { id: session.id },
      data: {
        accessExpiresAt,
        tokens: {
          upsert: {
            create: {
              accessTokenEnc: Buffer.from(encAccess.ciphertext, 'base64'),
              accessTokenNonce: Buffer.from(encAccess.nonce, 'base64'),
              accessTokenTag: Buffer.from(encAccess.tag, 'base64'),
              refreshTokenEnc: Buffer.from(encRefresh.ciphertext, 'base64'),
              refreshTokenNonce: Buffer.from(encRefresh.nonce, 'base64'),
              refreshTokenTag: Buffer.from(encRefresh.tag, 'base64'),
              keyId: encAccess.keyId,
            },
            update: {
              accessTokenEnc: Buffer.from(encAccess.ciphertext, 'base64'),
              accessTokenNonce: Buffer.from(encAccess.nonce, 'base64'),
              accessTokenTag: Buffer.from(encAccess.tag, 'base64'),
              refreshTokenEnc: Buffer.from(encRefresh.ciphertext, 'base64'),
              refreshTokenNonce: Buffer.from(encRefresh.nonce, 'base64'),
              refreshTokenTag: Buffer.from(encRefresh.tag, 'base64'),
              keyId: encAccess.keyId,
            },
          },
        },
      },
    });

    return {
      id: session.id,
      userId: session.userId,
      orgId: session.orgId ?? null,
      roles: [session.user.role],
      permissions: [],
      accessExpiresAt,
      accessExpired: accessExpiresAt <= new Date(),
    };
  }

  private extractUserId(claims: Record<string, unknown>): string {
    const sub = claims['sub'];
    if (typeof sub === 'string' && sub.length > 0) {
      return sub;
    }
    throw new UnauthorizedException('Missing user id');
  }

  private extractOrgId(claims: Record<string, unknown>): string {
    const orgId =
      (typeof claims['org_id'] === 'string' && claims['org_id']) ||
      (typeof claims['orgId'] === 'string' && claims['orgId']) ||
      (typeof claims['urn:zitadel:iam:org:id'] === 'string' &&
        claims['urn:zitadel:iam:org:id']);
    if (typeof orgId === 'string' && orgId.length > 0) {
      return orgId;
    }
    throw new UnauthorizedException('Missing org id');
  }

  private extractEmail(claims: Record<string, unknown>): string | null {
    const email = claims['email'];
    if (typeof email === 'string' && email.length > 0) {
      return email.toLowerCase();
    }
    return null;
  }

  private extractRoles(claims: Record<string, unknown>): string[] {
    const roles = new Set<string>();
    const projectId =
      this.config.get<string>('ZITADEL_MASTER_PROJECT_ID') ?? '';

    const roleClaims = [
      projectId ? `urn:zitadel:iam:org:project:${projectId}:roles` : '',
      'urn:zitadel:iam:org:project:roles',
      'urn:zitadel:iam:org:projects:roles',
    ].filter(Boolean);

    for (const claimKey of roleClaims) {
      const claimValue = claims[claimKey];
      if (Array.isArray(claimValue)) {
        claimValue.forEach((value) => {
          if (typeof value === 'string' && value.length > 0) {
            roles.add(value);
          }
        });
      } else if (typeof claimValue === 'string') {
        roles.add(claimValue);
      } else if (claimValue && typeof claimValue === 'object') {
        Object.keys(claimValue as Record<string, unknown>).forEach((key) => {
          if (key.length > 0) {
            roles.add(key);
          }
        });
      }
    }

    return Array.from(roles);
  }

  private async resolveUserFromOidc(params: {
    userId: string;
    orgId: string;
    email: string | null;
    roles: string[];
  }): Promise<User> {
    const role = this.mapRolesToUserRole(params.roles);

    await this.prisma.org.upsert({
      where: { id: params.orgId },
      create: { id: params.orgId },
      update: {},
    });

    const existing = await this.prisma.user.findUnique({
      where: { id: params.userId },
    });

    if (existing) {
      if (existing.status === UserStatus.DISABLED) {
        throw new UnauthorizedException('User is disabled');
      }
      if (existing.orgId !== params.orgId) {
        throw new UnauthorizedException('User org mismatch');
      }

      return this.prisma.user.update({
        where: { id: params.userId },
        data: {
          email: params.email ?? existing.email,
          role,
          status: UserStatus.ACTIVE,
        },
      });
    }

    return this.prisma.user.create({
      data: {
        id: params.userId,
        orgId: params.orgId,
        email: params.email,
        role,
        status: UserStatus.ACTIVE,
      },
    });
  }

  private mapRolesToUserRole(roles: string[]): UserRole {
    const adminRole =
      this.config.get<string>('ZITADEL_ADMIN_ROLE_KEY') ?? 'admin';
    const userRole = this.config.get<string>('ZITADEL_USER_ROLE_KEY') ?? 'user';

    if (roles.includes(adminRole)) {
      return UserRole.ROOT;
    }
    if (roles.includes(userRole)) {
      return UserRole.USER;
    }
    if (roles.length > 0) {
      return UserRole.USER;
    }
    throw new UnauthorizedException('Missing required role assignment');
  }

  private resolveAccessExpiry(tokenSet: any): Date {
    const expiresIn =
      typeof tokenSet?.expiresIn === 'function'
        ? tokenSet.expiresIn()
        : typeof tokenSet?.expires_in === 'number'
          ? tokenSet.expires_in
          : undefined;

    if (typeof expiresIn === 'number' && expiresIn > 0) {
      return new Date(Date.now() + expiresIn * 1000);
    }

    return new Date(Date.now() + 3600 * 1000);
  }

  private setSessionCookie(res: Response, sessionId: string): void {
    const name =
      this.config.get<string>('SESSION_COOKIE_NAME') ?? 'auth_session';
    const domain =
      this.config.get<string>('SESSION_COOKIE_DOMAIN') || undefined;
    const path = this.config.get<string>('SESSION_COOKIE_PATH') ?? '/';
    const secure = this.config.get<boolean>('SESSION_COOKIE_SECURE') ?? false;
    const sameSite = (this.config.get<string>('SESSION_COOKIE_SAMESITE') ??
      'lax') as 'lax' | 'strict' | 'none';
    const maxAge =
      (this.config.get<number>('SESSION_COOKIE_MAX_AGE_SEC') ?? 604800) * 1000;

    res.cookie(name, sessionId, {
      httpOnly: true,
      secure,
      sameSite,
      domain,
      path,
      maxAge,
    });
  }

  private clearSessionCookie(res: Response): void {
    const name =
      this.config.get<string>('SESSION_COOKIE_NAME') ?? 'auth_session';
    const domain =
      this.config.get<string>('SESSION_COOKIE_DOMAIN') || undefined;
    const path = this.config.get<string>('SESSION_COOKIE_PATH') ?? '/';

    res.clearCookie(name, { domain, path });
  }

  private sanitizeRedirect(redirect?: string): string | null {
    if (!redirect) {
      return null;
    }
    if (redirect.startsWith('/')) {
      return redirect;
    }
    return null;
  }

  private buildScope(): string {
    const base = this.config.get<string>('ZITADEL_SCOPES') ?? DEFAULT_SCOPES;
    const projectId =
      this.config.get<string>('ZITADEL_MASTER_PROJECT_ID') ?? '';
    if (!projectId) {
      return base;
    }
    const roleScope = `urn:zitadel:iam:org:project:${projectId}:roles`;
    const scopes = new Set(base.split(' ').filter(Boolean));
    scopes.add(roleScope);
    return Array.from(scopes).join(' ');
  }

  private assertOidcEnabled(): void {
    const enabled = this.config.get<boolean>('OIDC_ENABLED') ?? false;
    if (!enabled) {
      throw new ServiceUnavailableException('OIDC is disabled');
    }
  }

  private assertCryptoEnabled(): void {
    if (!this.crypto.isEnabled()) {
      throw new ServiceUnavailableException('Crypto is disabled');
    }
  }

  private requireConfig(key: string): string {
    const value = this.config.get<string>(key);
    if (!value) {
      throw new ServiceUnavailableException(`${key} is not configured`);
    }
    return value;
  }
}
