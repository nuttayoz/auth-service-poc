import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Prisma,
  UserOrgAccessSource,
  UserOrgAccessStatus,
  UserRole,
  UserStatus,
} from '@prisma/client';
import type { User } from '@prisma/client';
import { Request, Response } from 'express';
import { CryptoService } from '../crypto/crypto.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { OidcClientService } from './oidc-client.service.js';
import type { SessionContext } from './session.service.js';

const OIDC_REQUEST_TTL_MS = 10 * 60 * 1000;
const REFRESH_SKEW_MS = 2 * 60 * 1000;
const DEFAULT_SCOPES = 'openid profile email offline_access';

type SessionWithTokens = Prisma.SessionGetPayload<{
  include: { tokens: true; user: true };
}> & {
  tokens: NonNullable<
    Prisma.SessionGetPayload<{
      include: { tokens: true; user: true };
    }>['tokens']
  >;
  user: NonNullable<
    Prisma.SessionGetPayload<{ include: { tokens: true; user: true } }>['user']
  >;
};

type AuthorizedOrgAccess = {
  orgId: string;
  primaryDomain: string | null;
  role: UserRole;
  source: UserOrgAccessSource;
};
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly oidc: OidcClientService,
  ) {}

  async login(
    res: Response,
    redirect?: string,
    options?: { orgId?: string; orgDomain?: string },
  ): Promise<void> {
    await this.startOidc(res, redirect, options);
  }

  private async startOidc(
    res: Response,
    redirect: string | undefined,
    options?: { orgId?: string; orgDomain?: string },
  ): Promise<void> {
    this.assertOidcEnabled();
    this.assertCryptoEnabled();

    const oidc = this.oidc.getModule();
    const config = await this.oidc.getConfig();
    const requestedOrg = this.sanitizeRequestedOrgSelection(options);
    const scope = this.buildScope(requestedOrg);

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
        requestedOrgId: requestedOrg.orgId,
        requestedOrgDomain: requestedOrg.orgDomain,
        redirectUri: sanitizedRedirect,
      },
    });

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
    const email = this.extractEmail(claims);
    this.logger.log({
      event: 'oidc.home_org.claims.id_token',
      claimKeys: this.getOrgClaimKeysPresent(claims),
    });
    const userInfo = await this.loadUserInfoClaims(accessToken, zitadelSub);
    const homeOrgId = await this.resolveHomeOrgId(
      claims,
      accessToken,
      zitadelSub,
      userInfo,
    );
    const authorizedAccesses = await this.resolveAuthorizedOrgAccesses({
      claims,
      accessToken,
      userId: zitadelSub,
      homeOrgId,
      userInfo,
    });
    const homeAccess =
      authorizedAccesses.find(
        (access) =>
          access.orgId === homeOrgId &&
          access.source === UserOrgAccessSource.DIRECT,
      ) ?? null;
    const user = await this.resolveUserFromOidc({
      userId: zitadelSub,
      homeOrgId,
      email,
      role: homeAccess?.role ?? UserRole.USER,
    });
    await this.syncAuthorizedOrgAccessProjection(user.id, {
      homeOrgId: user.homeOrgId,
      accesses: authorizedAccesses,
    });
    const activeAccess = this.resolveActiveOrgAccess({
      accesses: authorizedAccesses,
      homeOrgId: user.homeOrgId,
      requestedOrgId: stored.requestedOrgId ?? undefined,
      requestedOrgDomain: stored.requestedOrgDomain ?? undefined,
    });

    const accessExpiresAt = this.resolveAccessExpiry(tokenSet);

    const encAccess = this.crypto.encrypt(accessToken);
    const encRefresh = this.crypto.encrypt(refreshToken);

    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        homeOrgId: user.homeOrgId,
        activeOrgId: activeAccess.orgId,
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
      homeOrgId: user.homeOrgId,
      activeOrgId: session.activeOrgId,
      orgId: session.activeOrgId,
      accessSource: activeAccess.source,
      roles: [activeAccess.role],
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

  async switchActiveOrg(
    session: SessionContext,
    orgId: string | undefined,
  ): Promise<SessionContext> {
    const targetOrgId = orgId?.trim();
    if (!targetOrgId) {
      throw new BadRequestException('orgId is required');
    }
    if (/\s/.test(targetOrgId)) {
      throw new BadRequestException('orgId must not contain spaces');
    }

    const sessionRecord = await this.loadSessionWithTokens(session.id);
    const { accessToken, accessExpiresAt } =
      await this.getCurrentAccessToken(sessionRecord);
    const userInfo = await this.loadUserInfoClaims(accessToken, session.userId);
    const authorizedAccesses = await this.resolveAuthorizedOrgAccesses({
      claims: this.decodeJwtPayload(accessToken) ?? {},
      accessToken,
      userId: session.userId,
      homeOrgId: sessionRecord.homeOrgId,
      userInfo,
    });
    await this.syncAuthorizedOrgAccessProjection(session.userId, {
      homeOrgId: sessionRecord.homeOrgId,
      accesses: authorizedAccesses,
    });
    const targetAccess = this.requireAuthorizedOrgAccess(
      authorizedAccesses,
      targetOrgId,
    );

    if (session.activeOrgId === targetOrgId) {
      return {
        ...session,
        accessExpiresAt,
        accessExpired: accessExpiresAt <= new Date(),
        activeOrgId: targetOrgId,
        orgId: targetOrgId,
        accessSource: targetAccess.source,
        roles: [targetAccess.role],
      };
    }

    await this.prisma.session.update({
      where: { id: session.id },
      data: { activeOrgId: targetOrgId },
    });

    await this.writeAuditLogSafe(
      session.userId,
      'auth.session.active_org.switch',
      {
        sessionId: session.id,
        homeOrgId: session.homeOrgId,
        previousActiveOrgId: session.activeOrgId,
        activeOrgId: targetOrgId,
        role: targetAccess.role,
        source: targetAccess.source,
      },
    );

    return {
      ...session,
      accessExpiresAt,
      accessExpired: accessExpiresAt <= new Date(),
      activeOrgId: targetOrgId,
      orgId: targetOrgId,
      accessSource: targetAccess.source,
      roles: [targetAccess.role],
    };
  }

  async refreshSession(sessionId: string): Promise<SessionContext> {
    return this.syncSessionAuthorization(sessionId);
  }

  async validateSessionAuthorization(
    sessionId: string,
  ): Promise<SessionContext> {
    return this.syncSessionAuthorization(sessionId);
  }

  async revalidateSession(sessionId: string): Promise<SessionContext> {
    return this.syncSessionAuthorization(sessionId, { forceRefresh: true });
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
      (typeof claims['urn:zitadel:iam:user:resourceowner:id'] === 'string' &&
        claims['urn:zitadel:iam:user:resourceowner:id']) ||
      (typeof claims['urn:zitadel:iam:org:id'] === 'string' &&
        claims['urn:zitadel:iam:org:id']);
    if (typeof orgId === 'string' && orgId.length > 0) {
      return orgId;
    }
    throw new UnauthorizedException('Missing org id');
  }

  private async resolveHomeOrgId(
    claims: Record<string, unknown>,
    accessToken: string,
    userId: string,
    userInfo?: Record<string, unknown> | null,
  ): Promise<string> {
    const directOrgId = this.tryExtractOrgId(claims);
    if (directOrgId) {
      this.logger.log({
        event: 'oidc.home_org.resolved',
        source: 'id_token',
        orgId: directOrgId,
      });
      return directOrgId;
    }

    const accessClaims = this.decodeJwtPayload(accessToken);
    if (accessClaims) {
      this.logger.log({
        event: 'oidc.home_org.claims.access_token',
        claimKeys: this.getOrgClaimKeysPresent(accessClaims),
      });
    } else {
      this.logger.warn({
        event: 'oidc.home_org.claims.access_token',
        claimKeys: [],
        message: 'access token is opaque or could not be decoded',
      });
    }
    const accessOrgId = accessClaims
      ? this.tryExtractOrgId(accessClaims)
      : null;
    if (accessOrgId) {
      this.logger.log({
        event: 'oidc.home_org.resolved',
        source: 'access_token',
        orgId: accessOrgId,
      });
      return accessOrgId;
    }

    try {
      const userInfoClaims =
        typeof userInfo === 'undefined'
          ? await this.loadUserInfoClaims(accessToken, userId)
          : userInfo;
      if (userInfoClaims) {
        this.logger.log({
          event: 'oidc.home_org.claims.userinfo',
          claimKeys: this.getOrgClaimKeysPresent(userInfoClaims),
        });
        const userInfoOrgId = this.tryExtractOrgId(userInfoClaims);
        if (userInfoOrgId) {
          this.logger.log({
            event: 'oidc.home_org.resolved',
            source: 'userinfo',
            orgId: userInfoOrgId,
          });
          return userInfoOrgId;
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      this.logger.warn(
        `Userinfo request failed while resolving home org: ${message}`,
      );
    }

    throw new UnauthorizedException('Missing org id');
  }

  private async loadUserInfoClaims(
    accessToken: string,
    userId: string,
  ): Promise<Record<string, unknown> | null> {
    const oidc = this.oidc.getModule();
    const config = await this.oidc.getConfig();

    try {
      return (await oidc.fetchUserInfo(config, accessToken, userId)) as Record<
        string,
        unknown
      >;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      this.logger.warn(`Userinfo request failed: ${message}`);
      return null;
    }
  }

  private tryExtractOrgId(claims: Record<string, unknown>): string | null {
    const orgId =
      (typeof claims['org_id'] === 'string' && claims['org_id']) ||
      (typeof claims['orgId'] === 'string' && claims['orgId']) ||
      (typeof claims['urn:zitadel:iam:user:resourceowner:id'] === 'string' &&
        claims['urn:zitadel:iam:user:resourceowner:id']) ||
      (typeof claims['urn:zitadel:iam:org:id'] === 'string' &&
        claims['urn:zitadel:iam:org:id']);

    if (typeof orgId === 'string' && orgId.length > 0) {
      return orgId;
    }

    return null;
  }

  private getOrgClaimKeysPresent(claims: Record<string, unknown>): string[] {
    const candidates = [
      'org_id',
      'orgId',
      'urn:zitadel:iam:user:resourceowner:id',
      'urn:zitadel:iam:org:id',
    ];

    return candidates.filter((key) => {
      const value = claims[key];
      return typeof value === 'string' && value.length > 0;
    });
  }

  private extractEmail(claims: Record<string, unknown>): string | null {
    const email = claims['email'];
    if (typeof email === 'string' && email.length > 0) {
      return email.toLowerCase();
    }
    return null;
  }

  private extractRoles(
    claims: Record<string, unknown>,
    accessToken?: string,
  ): string[] {
    const roles = this.collectRolesFromClaims(claims);

    if (roles.size === 0 && accessToken) {
      const accessClaims = this.decodeJwtPayload(accessToken);
      if (accessClaims) {
        this.collectRolesFromClaims(accessClaims, roles);
      }
    }

    return Array.from(roles);
  }

  private async resolveAuthorizedOrgAccesses(params: {
    claims: Record<string, unknown>;
    accessToken: string;
    userId: string;
    homeOrgId: string;
    userInfo?: Record<string, unknown> | null;
  }): Promise<AuthorizedOrgAccess[]> {
    const authApiAccesses = await this.loadAuthorizedOrgAccessesFromAuthApi(
      params.accessToken,
      params.homeOrgId,
    );
    if (authApiAccesses !== null) {
      if (authApiAccesses.length > 0) {
        return authApiAccesses;
      }
      throw new UnauthorizedException('No authorized org access found');
    }

    const byOrg = new Map<
      string,
      { primaryDomain: string | null; roleKeys: Set<string> }
    >();

    this.collectAuthorizedOrgAccessesFromClaims(params.claims, byOrg);

    const accessClaims = this.decodeJwtPayload(params.accessToken);
    if (accessClaims) {
      this.collectAuthorizedOrgAccessesFromClaims(accessClaims, byOrg);
    }

    if (params.userInfo) {
      this.collectAuthorizedOrgAccessesFromClaims(params.userInfo, byOrg);
    }

    const accesses: AuthorizedOrgAccess[] = [];
    for (const [orgId, value] of byOrg.entries()) {
      const role = this.mapRoleKeysToUserRole(Array.from(value.roleKeys));
      if (!role) {
        continue;
      }

      const source =
        orgId === params.homeOrgId
          ? UserOrgAccessSource.DIRECT
          : UserOrgAccessSource.EXTERNAL;

      if (source === UserOrgAccessSource.EXTERNAL && role === UserRole.ROOT) {
        this.logger.warn(
          `Ignoring invalid external root access from ZITADEL for user "${params.userId}" org "${orgId}"`,
        );
        continue;
      }

      accesses.push({
        orgId,
        primaryDomain: value.primaryDomain,
        role,
        source,
      });
    }

    if (accesses.length > 0) {
      return accesses;
    }

    const fallbackRoles = this.extractRoles(params.claims, params.accessToken);
    if (
      fallbackRoles.length === 0 &&
      params.userInfo &&
      Object.keys(params.userInfo).length > 0
    ) {
      fallbackRoles.push(...this.extractRoles(params.userInfo));
    }

    return [
      {
        orgId: params.homeOrgId,
        primaryDomain: null,
        role: this.mapRolesToUserRole(fallbackRoles),
        source: UserOrgAccessSource.DIRECT,
      },
    ];
  }

  private async loadAuthorizedOrgAccessesFromAuthApi(
    accessToken: string,
    homeOrgId: string,
  ): Promise<AuthorizedOrgAccess[] | null> {
    const issuer = this.config.get<string>('ZITADEL_ISSUER');
    if (!issuer) {
      return null;
    }

    const endpoint = new URL('/auth/v1/usergrants/me/_search', issuer);
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        query: {
          offset: '0',
          limit: 100,
          asc: true,
        },
      }),
    }).catch((error) => {
      const message = error instanceof Error ? error.message : 'unknown error';
      this.logger.warn(`Auth API user grant lookup failed: ${message}`);
      return null;
    });

    if (!response) {
      return null;
    }
    if (!response.ok) {
      const responseText = await response.text().catch(() => '');
      this.logger.warn(
        `Auth API user grant lookup failed with status ${response.status}${responseText ? `: ${responseText}` : ''}`,
      );
      return null;
    }

    const payload = (await response.json().catch(() => null)) as {
      result?: Array<{
        orgId?: string;
        orgDomain?: string;
        roleKeys?: string[];
        roles?: string[];
      }>;
    } | null;

    const results = Array.isArray(payload?.result) ? payload.result : [];
    const accesses: AuthorizedOrgAccess[] = [];

    for (const result of results) {
      const orgId = result.orgId?.trim();
      if (!orgId) {
        continue;
      }

      const roleKeys = Array.isArray(result.roleKeys)
        ? result.roleKeys.filter(
            (roleKey): roleKey is string =>
              typeof roleKey === 'string' && roleKey.length > 0,
          )
        : Array.isArray(result.roles)
          ? result.roles.filter(
              (roleKey): roleKey is string =>
                typeof roleKey === 'string' && roleKey.length > 0,
            )
          : [];

      const role = this.mapRoleKeysToUserRole(roleKeys);
      if (!role) {
        continue;
      }

      const source =
        orgId === homeOrgId
          ? UserOrgAccessSource.DIRECT
          : UserOrgAccessSource.EXTERNAL;
      if (source === UserOrgAccessSource.EXTERNAL && role === UserRole.ROOT) {
        this.logger.warn(
          `Ignoring invalid external root access from Auth API for org "${orgId}"`,
        );
        continue;
      }

      accesses.push({
        orgId,
        primaryDomain: result.orgDomain?.trim().toLowerCase() ?? null,
        role,
        source,
      });
    }

    return accesses;
  }

  private collectAuthorizedOrgAccessesFromClaims(
    claims: Record<string, unknown>,
    byOrg: Map<string, { primaryDomain: string | null; roleKeys: Set<string> }>,
  ): void {
    for (const claimKey of this.getRoleClaimKeys()) {
      const claimValue = claims[claimKey];
      if (!claimValue || typeof claimValue !== 'object') {
        continue;
      }

      const containers = Array.isArray(claimValue) ? claimValue : [claimValue];
      for (const container of containers) {
        if (!container || typeof container !== 'object') {
          continue;
        }

        for (const [roleKey, organizations] of Object.entries(
          container as Record<string, unknown>,
        )) {
          if (!organizations || typeof organizations !== 'object') {
            continue;
          }

          if (Array.isArray(organizations)) {
            for (const organization of organizations) {
              if (
                organization &&
                typeof organization === 'object' &&
                'id' in organization
              ) {
                const orgRecord = organization as Record<string, unknown>;
                this.addAuthorizedOrgRole(
                  byOrg,
                  String(orgRecord.id),
                  roleKey,
                  this.extractPrimaryDomainValue(orgRecord),
                );
              }
            }
            continue;
          }

          for (const [orgId, meta] of Object.entries(
            organizations as Record<string, unknown>,
          )) {
            this.addAuthorizedOrgRole(
              byOrg,
              orgId,
              roleKey,
              this.extractPrimaryDomainValue(meta),
            );
          }
        }
      }
    }
  }

  private addAuthorizedOrgRole(
    byOrg: Map<string, { primaryDomain: string | null; roleKeys: Set<string> }>,
    orgId: string,
    roleKey: string,
    primaryDomain: string | null,
  ): void {
    if (!orgId || !roleKey) {
      return;
    }

    const existing = byOrg.get(orgId) ?? {
      primaryDomain: null,
      roleKeys: new Set<string>(),
    };
    if (!existing.primaryDomain && primaryDomain) {
      existing.primaryDomain = primaryDomain;
    }
    existing.roleKeys.add(roleKey);
    byOrg.set(orgId, existing);
  }

  private extractPrimaryDomainValue(value: unknown): string | null {
    if (typeof value === 'string' && value.length > 0) {
      return value.toLowerCase();
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return null;
    }

    const record = value as Record<string, unknown>;
    const candidates = ['primaryDomain', 'primary_domain', 'domain', 'name'];

    for (const candidate of candidates) {
      const candidateValue = record[candidate];
      if (typeof candidateValue === 'string' && candidateValue.length > 0) {
        return candidateValue.toLowerCase();
      }
    }

    return null;
  }

  private mapRoleKeysToUserRole(roleKeys: string[]): UserRole | null {
    if (roleKeys.length === 0) {
      return null;
    }

    return this.mapRolesToUserRole(roleKeys);
  }

  private collectRolesFromClaims(
    claims: Record<string, unknown>,
    roles: Set<string> = new Set(),
  ): Set<string> {
    const roleClaims = this.getRoleClaimKeys();

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

    return roles;
  }

  private getRoleClaimKeys(): string[] {
    const projectId =
      this.config.get<string>('ZITADEL_MASTER_PROJECT_ID') ?? '';

    return [
      projectId ? `urn:zitadel:iam:org:project:${projectId}:roles` : '',
      'urn:zitadel:iam:org:project:roles',
      'urn:zitadel:iam:org:projects:roles',
    ].filter(Boolean);
  }

  private decodeJwtPayload(token: string): Record<string, unknown> | null {
    const parts = token.split('.');
    if (parts.length < 2) {
      return null;
    }

    const payload = parts[1];
    try {
      const normalized = payload
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(payload.length + ((4 - (payload.length % 4)) % 4), '=');
      const json = Buffer.from(normalized, 'base64').toString('utf8');
      return JSON.parse(json) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  private async loadSessionWithTokens(
    sessionId: string,
  ): Promise<SessionWithTokens> {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { tokens: true, user: true },
    });

    if (!session || !session.tokens || !session.user) {
      throw new UnauthorizedException('Session not found');
    }

    return session as SessionWithTokens;
  }

  private async getCurrentAccessToken(
    session: SessionWithTokens,
    options: { forceRefresh?: boolean } = {},
  ): Promise<{ accessToken: string; accessExpiresAt: Date }> {
    const now = Date.now();
    const shouldRefresh =
      options.forceRefresh === true ||
      session.accessExpiresAt.getTime() - now <= REFRESH_SKEW_MS;

    if (!shouldRefresh) {
      return {
        accessToken: this.decryptSessionAccessToken(session),
        accessExpiresAt: session.accessExpiresAt,
      };
    }

    const refreshToken = this.decryptSessionRefreshToken(session);
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

    return { accessToken, accessExpiresAt };
  }

  private decryptSessionAccessToken(session: SessionWithTokens): string {
    return this.crypto
      .decrypt({
        keyId: session.tokens.keyId,
        ciphertext: Buffer.from(session.tokens.accessTokenEnc).toString(
          'base64',
        ),
        nonce: Buffer.from(session.tokens.accessTokenNonce).toString('base64'),
        tag: Buffer.from(session.tokens.accessTokenTag).toString('base64'),
      })
      .toString('utf8');
  }

  private decryptSessionRefreshToken(session: SessionWithTokens): string {
    return this.crypto
      .decrypt({
        keyId: session.tokens.keyId,
        ciphertext: Buffer.from(session.tokens.refreshTokenEnc).toString(
          'base64',
        ),
        nonce: Buffer.from(session.tokens.refreshTokenNonce).toString('base64'),
        tag: Buffer.from(session.tokens.refreshTokenTag).toString('base64'),
      })
      .toString('utf8');
  }

  private async resolveUserFromOidc(params: {
    userId: string;
    homeOrgId: string;
    email: string | null;
    role: UserRole;
  }): Promise<User> {
    return this.prisma.$transaction(async (tx) => {
      await tx.org.upsert({
        where: { id: params.homeOrgId },
        create: { id: params.homeOrgId },
        update: {},
      });

      const existing = await tx.user.findUnique({
        where: { id: params.userId },
      });

      if (existing?.status === UserStatus.DISABLED) {
        throw new UnauthorizedException('User is disabled');
      }
      if (existing && existing.homeOrgId !== params.homeOrgId) {
        throw new UnauthorizedException('User org mismatch');
      }

      return existing
        ? await tx.user.update({
            where: { id: params.userId },
            data: {
              email: params.email ?? existing.email,
              role: params.role,
              status: UserStatus.ACTIVE,
            },
          })
        : await tx.user.create({
            data: {
              id: params.userId,
              homeOrgId: params.homeOrgId,
              email: params.email,
              role: params.role,
              status: UserStatus.ACTIVE,
            },
          });
    });
  }

  private async syncSessionAuthorization(
    sessionId: string,
    options: { forceRefresh?: boolean } = {},
  ): Promise<SessionContext> {
    this.assertOidcEnabled();
    this.assertCryptoEnabled();

    const session = await this.loadSessionWithTokens(sessionId);
    if (session.user.status === UserStatus.DISABLED) {
      throw new UnauthorizedException('User is disabled');
    }

    const { accessToken, accessExpiresAt } = await this.getCurrentAccessToken(
      session,
      options,
    );
    const userInfo = await this.loadUserInfoClaims(accessToken, session.userId);
    const authorizedAccesses = await this.resolveAuthorizedOrgAccesses({
      claims: this.decodeJwtPayload(accessToken) ?? {},
      accessToken,
      userId: session.userId,
      homeOrgId: session.homeOrgId,
      userInfo,
    });
    const homeAccess =
      authorizedAccesses.find(
        (access) =>
          access.orgId === session.homeOrgId &&
          access.source === UserOrgAccessSource.DIRECT,
      ) ?? null;

    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: session.userId },
        data: {
          role: homeAccess?.role ?? UserRole.USER,
          status: UserStatus.ACTIVE,
        },
      });

      await this.syncAuthorizedOrgAccessProjectionTx(tx, session.userId, {
        homeOrgId: session.homeOrgId,
        accesses: authorizedAccesses,
      });
    });

    return this.buildSessionContext(session, accessExpiresAt);
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

  private async buildSessionContext(
    session: Pick<
      SessionWithTokens,
      'id' | 'userId' | 'homeOrgId' | 'activeOrgId'
    >,
    accessExpiresAt: Date,
  ): Promise<SessionContext> {
    const access = await this.loadActiveOrgAccess(
      session.userId,
      session.activeOrgId ?? session.homeOrgId,
    );

    return {
      id: session.id,
      userId: session.userId,
      homeOrgId: session.homeOrgId,
      activeOrgId: access.orgId,
      orgId: access.orgId,
      accessSource: access.source,
      roles: [access.role],
      permissions: [],
      accessExpiresAt,
      accessExpired: accessExpiresAt <= new Date(),
    };
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

  private sanitizeRequestedOrgSelection(options?: {
    orgId?: string;
    orgDomain?: string;
  }): { orgId?: string; orgDomain?: string } {
    const orgId = options?.orgId?.trim();
    const orgDomain = options?.orgDomain?.trim().toLowerCase();

    if (orgId && orgDomain) {
      throw new BadRequestException(
        'Provide either orgId or orgDomain, not both',
      );
    }
    if (orgId && /\s/.test(orgId)) {
      throw new BadRequestException('orgId must not contain spaces');
    }
    if (orgDomain && /\s/.test(orgDomain)) {
      throw new BadRequestException('orgDomain must not contain spaces');
    }

    return {
      ...(orgId ? { orgId } : {}),
      ...(orgDomain ? { orgDomain } : {}),
    };
  }

  private buildScope(options?: { orgId?: string; orgDomain?: string }): string {
    const base = this.config.get<string>('ZITADEL_SCOPES') ?? DEFAULT_SCOPES;
    const projectId =
      this.config.get<string>('ZITADEL_MASTER_PROJECT_ID') ?? '';
    const orgDomain = options?.orgDomain;
    const resourceOwnerScope = 'urn:zitadel:iam:user:resourceowner';
    const zitadelApiAudienceScope =
      'urn:zitadel:iam:org:project:id:zitadel:aud';

    const roleScope = `urn:zitadel:iam:org:project:${projectId}:roles`;
    const scopes = new Set(base.split(' ').filter(Boolean));
    if (projectId) {
      scopes.add(roleScope);
    }
    scopes.add(resourceOwnerScope);
    scopes.add(zitadelApiAudienceScope);
    if (orgDomain) {
      scopes.add(`urn:zitadel:iam:org:domain:primary:${orgDomain}`);
    }
    return Array.from(scopes).join(' ');
  }

  private resolveActiveOrgAccess(params: {
    accesses: AuthorizedOrgAccess[];
    homeOrgId: string;
    requestedOrgId?: string;
    requestedOrgDomain?: string;
  }) {
    if (params.accesses.length === 0) {
      throw new UnauthorizedException('No active org access found');
    }

    const requestedById = params.requestedOrgId
      ? params.accesses.find((access) => access.orgId === params.requestedOrgId)
      : null;
    if (params.requestedOrgId) {
      if (!requestedById) {
        throw new ForbiddenException('No access to requested org');
      }
      this.assertAccessRoleAllowed(requestedById);
      return requestedById;
    }

    if (params.requestedOrgDomain) {
      const requestedByDomain = params.accesses.find(
        (access) =>
          access.primaryDomain?.toLowerCase() ===
          params.requestedOrgDomain?.toLowerCase(),
      );
      if (!requestedByDomain) {
        throw new ForbiddenException('No access to requested org');
      }
      this.assertAccessRoleAllowed(requestedByDomain);
      return requestedByDomain;
    }

    const homeAccess =
      params.accesses.find((access) => access.orgId === params.homeOrgId) ??
      (params.accesses.length === 1 ? params.accesses[0] : null);

    if (!homeAccess) {
      throw new BadRequestException(
        'Multiple org accesses found; specify orgId to choose the active org',
      );
    }

    this.assertAccessRoleAllowed(homeAccess);
    return homeAccess;
  }

  private requireAuthorizedOrgAccess(
    accesses: AuthorizedOrgAccess[],
    orgId: string,
  ): AuthorizedOrgAccess {
    const access = accesses.find((candidate) => candidate.orgId === orgId);
    if (!access) {
      throw new ForbiddenException('No access to requested org');
    }
    this.assertAccessRoleAllowed(access);
    return access;
  }

  private async syncAuthorizedOrgAccessProjection(
    userId: string,
    params: { homeOrgId: string; accesses: AuthorizedOrgAccess[] },
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await this.syncAuthorizedOrgAccessProjectionTx(tx, userId, params);
    });
  }

  private async syncAuthorizedOrgAccessProjectionTx(
    tx: Prisma.TransactionClient,
    userId: string,
    params: { homeOrgId: string; accesses: AuthorizedOrgAccess[] },
  ): Promise<void> {
    for (const access of params.accesses) {
      await tx.org.upsert({
        where: { id: access.orgId },
        create: { id: access.orgId, name: access.primaryDomain ?? undefined },
        update: {},
      });

      await tx.userOrgAccess.upsert({
        where: {
          userId_orgId: {
            userId,
            orgId: access.orgId,
          },
        },
        create: {
          userId,
          orgId: access.orgId,
          role: access.role,
          source: access.source,
          status: UserOrgAccessStatus.ACTIVE,
        },
        update: {
          role: access.role,
          source: access.source,
          status: UserOrgAccessStatus.ACTIVE,
        },
      });
    }

    const externalOrgIds = params.accesses
      .filter((access) => access.source === UserOrgAccessSource.EXTERNAL)
      .map((access) => access.orgId);

    await tx.userOrgAccess.updateMany({
      where: {
        userId,
        source: UserOrgAccessSource.EXTERNAL,
        ...(externalOrgIds.length > 0
          ? { orgId: { notIn: externalOrgIds } }
          : {}),
      },
      data: { status: UserOrgAccessStatus.REVOKED },
    });

    const hasHomeDirectAccess = params.accesses.some(
      (access) =>
        access.orgId === params.homeOrgId &&
        access.source === UserOrgAccessSource.DIRECT,
    );

    if (!hasHomeDirectAccess) {
      await tx.userOrgAccess.updateMany({
        where: {
          userId,
          orgId: params.homeOrgId,
          source: UserOrgAccessSource.DIRECT,
        },
        data: { status: UserOrgAccessStatus.REVOKED },
      });
    }
  }

  private async loadActiveOrgAccess(userId: string, orgId: string) {
    const access = await this.prisma.userOrgAccess.findUnique({
      where: {
        userId_orgId: {
          userId,
          orgId,
        },
      },
    });

    if (!access || access.status !== UserOrgAccessStatus.ACTIVE) {
      throw new UnauthorizedException('No active org access found');
    }

    this.assertAccessRoleAllowed(access);
    return access;
  }

  private assertAccessRoleAllowed(access: {
    source: UserOrgAccessSource;
    role: UserRole;
  }): void {
    if (
      access.source === UserOrgAccessSource.EXTERNAL &&
      access.role === UserRole.ROOT
    ) {
      throw new ForbiddenException('External org access cannot be root');
    }
  }

  private async writeAuditLogSafe(
    actorUserId: string | null,
    action: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          actorUserId,
          action,
          metadata: metadata as Prisma.InputJsonValue,
        },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      this.logger.warn(
        `Audit log write failed for action "${action}": ${message}`,
      );
    }
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
