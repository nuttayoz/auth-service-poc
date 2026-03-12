import {
  BadRequestException,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { CryptoService } from '../crypto/crypto.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { OidcClientService } from './oidc-client.service.js';

const OIDC_REQUEST_TTL_MS = 10 * 60 * 1000;

@Injectable()
export class AuthService {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly oidc: OidcClientService,
  ) {}

  async login(res: Response, redirect?: string): Promise<void> {
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

    const scope =
      this.config.get<string>('ZITADEL_SCOPES') ??
      'openid profile email offline_access';
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
    const userId = this.extractUserId(claims);
    const orgId = this.extractOrgId(claims);

    const accessExpiresAt = this.resolveAccessExpiry(tokenSet);

    const encAccess = this.crypto.encrypt(accessToken);
    const encRefresh = this.crypto.encrypt(refreshToken);

    const session = await this.prisma.session.create({
      data: {
        userId,
        orgId,
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
      userId,
      orgId,
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

  private extractUserId(claims: Record<string, unknown>): string {
    const sub = claims['sub'];
    if (typeof sub === 'string' && sub.length > 0) {
      return sub;
    }
    throw new UnauthorizedException('Missing user id');
  }

  private extractOrgId(claims: Record<string, unknown>): string | null {
    const orgId =
      (typeof claims['org_id'] === 'string' && claims['org_id']) ||
      (typeof claims['orgId'] === 'string' && claims['orgId']) ||
      (typeof claims['urn:zitadel:iam:org:id'] === 'string' &&
        claims['urn:zitadel:iam:org:id']);
    return typeof orgId === 'string' && orgId.length > 0 ? orgId : null;
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
