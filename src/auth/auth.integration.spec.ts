import { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { jest } from '@jest/globals';
import { CryptoService } from '../crypto/crypto.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { AdminSignupService } from './admin-signup.service.js';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { OidcClientService } from './oidc-client.service.js';
import { SessionGuard } from './session.guard.js';
import { SessionService } from './session.service.js';

type OidcRequestRecord = {
  id: string;
  state: string;
  codeVerifier: string;
  nonce: string;
  requestedOrgId: string | null;
  requestedOrgDomain: string | null;
  redirectUri: string | null;
  createdAt: Date;
};

type UserRecord = {
  id: string;
  homeOrgId: string;
  email: string | null;
  role: 'ROOT' | 'USER';
  status: 'PENDING' | 'ACTIVE' | 'DISABLED';
  createdAt: Date;
  updatedAt: Date;
};

type SessionRecord = {
  id: string;
  userId: string;
  homeOrgId: string;
  activeOrgId: string | null;
  expiresAt: Date;
  lastActivityAt: Date;
  accessExpiresAt: Date;
  refreshExpiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

type SessionTokenRecord = {
  id: string;
  sessionId: string;
  accessTokenEnc: Buffer;
  accessTokenNonce: Buffer;
  accessTokenTag: Buffer;
  refreshTokenEnc: Buffer;
  refreshTokenNonce: Buffer;
  refreshTokenTag: Buffer;
  keyId: string;
  createdAt: Date;
  updatedAt: Date;
};

type UserOrgAccessRecord = {
  id: string;
  userId: string;
  orgId: string;
  role: 'ROOT' | 'USER';
  source: 'DIRECT' | 'EXTERNAL';
  projectGrantId: string | null;
  zitadelRoleAssignmentId: string | null;
  status: 'ACTIVE' | 'REVOKED';
  createdAt: Date;
  updatedAt: Date;
};

type OidcTokenSet = {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  refresh_expires_in: number;
  claims: () => Record<string, unknown>;
};

class InMemoryPrisma {
  private ids = {
    session: 1,
    sessionToken: 1,
    userOrgAccess: 1,
  };

  readonly oidcRequests = new Map<string, OidcRequestRecord>();
  readonly users = new Map<string, UserRecord>();
  readonly orgs = new Map<string, { id: string; name?: string | null }>();
  readonly sessions = new Map<string, SessionRecord>();
  readonly sessionTokens = new Map<string, SessionTokenRecord>();
  readonly userOrgAccesses = new Map<string, UserOrgAccessRecord>();
  readonly auditLogs: Array<Record<string, unknown>> = [];

  readonly oidcRequest = {
    findUnique: ({ where }: { where: { state?: string; id?: string } }) => {
      if (where.state) {
        return this.oidcRequests.get(where.state) ?? null;
      }
      if (where.id) {
        return (
          Array.from(this.oidcRequests.values()).find(
            (item) => item.id === where.id,
          ) ?? null
        );
      }
      return null;
    },
    create: ({ data }: { data: Record<string, unknown> }) => {
      const record: OidcRequestRecord = {
        id: String(
          data.id
            ? JSON.stringify(data.id)
            : `oidc-${this.oidcRequests.size + 1}`,
        ),
        state: String(data.state),
        codeVerifier: String(data.codeVerifier),
        nonce: String(data.nonce),
        requestedOrgId:
          typeof data.requestedOrgId === 'string' ? data.requestedOrgId : null,
        requestedOrgDomain:
          typeof data.requestedOrgDomain === 'string'
            ? data.requestedOrgDomain
            : null,
        redirectUri:
          typeof data.redirectUri === 'string' ? data.redirectUri : null,
        createdAt: data.createdAt instanceof Date ? data.createdAt : new Date(),
      };
      this.oidcRequests.set(record.state, record);
      return record;
    },
    delete: ({ where }: { where: { id: string } }) => {
      const record = Array.from(this.oidcRequests.values()).find(
        (item) => item.id === where.id,
      );
      if (record) {
        this.oidcRequests.delete(record.state);
      }
      return record ?? null;
    },
  };

  readonly org = {
    upsert: ({
      where,
      create,
    }: {
      where: { id: string };
      create: { id: string; name?: string };
      update: Record<string, unknown>;
    }) => {
      const existing = this.orgs.get(where.id);
      if (existing) {
        return existing;
      }
      const created = { id: create.id, name: create.name ?? null };
      this.orgs.set(created.id, created);
      return created;
    },
  };

  readonly user = {
    findUnique: ({ where }: { where: { id: string } }) => {
      return this.users.get(where.id) ?? null;
    },
    create: ({ data }: { data: Record<string, unknown> }) => {
      const now = new Date();
      const created: UserRecord = {
        id: String(data.id),
        homeOrgId: String(data.homeOrgId),
        email: typeof data.email === 'string' ? data.email : null,
        role: data.role === 'ROOT' ? 'ROOT' : 'USER',
        status: data.status === 'DISABLED' ? 'DISABLED' : 'ACTIVE',
        createdAt: now,
        updatedAt: now,
      };
      this.users.set(created.id, created);
      return created;
    },
    update: ({
      where,
      data,
    }: {
      where: { id: string };
      data: Partial<UserRecord>;
    }) => {
      const existing = this.users.get(where.id);
      if (!existing) {
        throw new Error(`User ${where.id} not found`);
      }
      const updated = {
        ...existing,
        ...data,
        updatedAt: new Date(),
      };
      this.users.set(where.id, updated);
      return updated;
    },
  };

  readonly session = {
    create: ({ data }: { data: Record<string, any> }) => {
      const now = new Date();
      const id = `session-${this.ids.session++}`;
      const created: SessionRecord = {
        id,
        userId: String(data.userId),
        homeOrgId: String(data.homeOrgId),
        activeOrgId:
          typeof data.activeOrgId === 'string' ? data.activeOrgId : null,
        expiresAt: data.expiresAt,
        lastActivityAt: data.lastActivityAt,
        accessExpiresAt: data.accessExpiresAt,
        refreshExpiresAt: data.refreshExpiresAt ?? null,
        createdAt: now,
        updatedAt: now,
      };
      this.sessions.set(id, created);

      if (data.tokens?.create) {
        const tokenNow = new Date();
        this.sessionTokens.set(id, {
          id: `session-token-${this.ids.sessionToken++}`,
          sessionId: id,
          ...data.tokens.create,
          createdAt: tokenNow,
          updatedAt: tokenNow,
        });
      }

      return created;
    },
    findUnique: ({
      where,
      include,
    }: {
      where: { id: string };
      include?: { tokens?: boolean; user?: boolean };
    }) => {
      const session = this.sessions.get(where.id);
      if (!session) {
        return null;
      }
      return {
        ...session,
        ...(include?.tokens
          ? { tokens: this.sessionTokens.get(session.id) ?? null }
          : {}),
        ...(include?.user
          ? { user: this.users.get(session.userId) ?? null }
          : {}),
      };
    },
    update: ({
      where,
      data,
    }: {
      where: { id: string };
      data: Record<string, any>;
    }) => {
      const existing = this.sessions.get(where.id);
      if (!existing) {
        throw new Error(`Session ${where.id} not found`);
      }
      const updated: SessionRecord = {
        ...existing,
        ...Object.fromEntries(
          Object.entries(data).filter(([key]) => key !== 'tokens'),
        ),
        updatedAt: new Date(),
      };
      this.sessions.set(where.id, updated);

      if (data.tokens?.upsert) {
        const tokenData = this.sessionTokens.get(where.id);
        const now = new Date();
        if (tokenData) {
          this.sessionTokens.set(where.id, {
            ...tokenData,
            ...data.tokens.upsert.update,
            updatedAt: now,
          });
        } else {
          this.sessionTokens.set(where.id, {
            id: `session-token-${this.ids.sessionToken++}`,
            sessionId: where.id,
            ...data.tokens.upsert.create,
            createdAt: now,
            updatedAt: now,
          });
        }
      }

      return {
        ...updated,
        tokens: this.sessionTokens.get(where.id) ?? null,
        user: this.users.get(updated.userId) ?? null,
      };
    },
    delete: ({ where }: { where: { id: string } }) => {
      const existing = this.sessions.get(where.id) ?? null;
      this.sessions.delete(where.id);
      this.sessionTokens.delete(where.id);
      return existing;
    },
  };

  readonly userOrgAccess = {
    findUnique: ({
      where,
    }: {
      where: { userId_orgId: { userId: string; orgId: string } };
    }) => {
      return (
        this.userOrgAccesses.get(
          `${where.userId_orgId.userId}:${where.userId_orgId.orgId}`,
        ) ?? null
      );
    },
    upsert: ({
      where,
      create,
      update,
    }: {
      where: { userId_orgId: { userId: string; orgId: string } };
      create: Record<string, any>;
      update: Record<string, any>;
    }) => {
      const key = `${where.userId_orgId.userId}:${where.userId_orgId.orgId}`;
      const existing = this.userOrgAccesses.get(key);
      const now = new Date();
      if (existing) {
        const merged = { ...existing, ...update, updatedAt: now };
        this.userOrgAccesses.set(key, merged);
        return merged;
      }
      const created: UserOrgAccessRecord = {
        id: `user-org-access-${this.ids.userOrgAccess++}`,
        userId: String(create.userId),
        orgId: String(create.orgId),
        role: create.role === 'ROOT' ? 'ROOT' : 'USER',
        source: create.source === 'EXTERNAL' ? 'EXTERNAL' : 'DIRECT',
        projectGrantId: create.projectGrantId ?? null,
        zitadelRoleAssignmentId: create.zitadelRoleAssignmentId ?? null,
        status: create.status === 'REVOKED' ? 'REVOKED' : 'ACTIVE',
        createdAt: now,
        updatedAt: now,
      };
      this.userOrgAccesses.set(key, created);
      return created;
    },
    updateMany: ({
      where,
      data,
    }: {
      where: Record<string, any>;
      data: Partial<UserOrgAccessRecord>;
    }) => {
      let count = 0;
      for (const [key, access] of this.userOrgAccesses.entries()) {
        if (where.userId && access.userId !== where.userId) {
          continue;
        }
        if (where.source && access.source !== where.source) {
          continue;
        }
        if (
          where.orgId &&
          typeof where.orgId === 'string' &&
          access.orgId !== where.orgId
        ) {
          continue;
        }
        if (where.orgId?.notIn && where.orgId.notIn.includes(access.orgId)) {
          continue;
        }
        const updated = {
          ...access,
          ...data,
          updatedAt: new Date(),
        };
        this.userOrgAccesses.set(key, updated);
        count += 1;
      }
      return { count };
    },
  };

  readonly auditLog = {
    create: ({ data }: { data: Record<string, unknown> }) => {
      this.auditLogs.push(data);
      return data;
    },
  };

  async $transaction<T>(fn: (tx: this) => Promise<T>): Promise<T> {
    return fn(this);
  }
}

function createConfigService() {
  const values: Record<string, unknown> = {
    OIDC_ENABLED: true,
    CRYPTO_ENABLED: true,
    ZITADEL_REDIRECT_URI: 'http://localhost/auth/callback',
    ZITADEL_MASTER_PROJECT_ID: 'project-1',
    ZITADEL_USER_ROLE_KEY: 'user',
    ZITADEL_ADMIN_ROLE_KEY: 'admin',
    SESSION_COOKIE_NAME: 'auth_session',
    SESSION_COOKIE_PATH: '/',
    SESSION_COOKIE_SECURE: false,
    SESSION_COOKIE_SAMESITE: 'lax',
    SESSION_COOKIE_MAX_AGE_SEC: 604800,
    SESSION_IDLE_TIMEOUT_SEC: 604800,
    SESSION_ABSOLUTE_MAX_AGE_SEC: 2592000,
    REFRESH_TOKEN_IDLE_TIMEOUT_SEC: 2592000,
    REFRESH_TOKEN_ABSOLUTE_MAX_AGE_SEC: 7776000,
    SESSION_ENC_KEY_ID: 'v1',
    HEADER_SIGNING_KEY_ID: 'v1',
    SESSION_ENC_KEY: Buffer.alloc(32, 1).toString('base64'),
    HEADER_SIGNING_KEY: Buffer.alloc(32, 2).toString('base64'),
  };

  return {
    get<T>(key: string): T | undefined {
      return values[key] as T | undefined;
    },
  } as ConfigService;
}

function base64Url(input: string): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function makeJwt(payload: Record<string, unknown>): string {
  return `${base64Url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${base64Url(
    JSON.stringify(payload),
  )}.sig`;
}

function roleClaims(orgId: string) {
  return {
    'urn:zitadel:iam:org:project:project-1:roles': {
      user: {
        [orgId]: {
          primaryDomain: 'home.example.com',
        },
      },
    },
  };
}

function makeTokenSet(params: {
  userId: string;
  orgId: string;
  email: string;
  accessToken: string;
  refreshToken: string;
  expiresIn?: number;
  refreshExpiresIn?: number;
}) {
  return {
    access_token: params.accessToken,
    refresh_token: params.refreshToken,
    expires_in: params.expiresIn ?? 3600,
    refresh_expires_in: params.refreshExpiresIn ?? 7200,
    claims: () => ({
      sub: params.userId,
      email: params.email,
      'urn:zitadel:iam:user:resourceowner:id': params.orgId,
      ...roleClaims(params.orgId),
    }),
  };
}

describe('Auth integration', () => {
  let app: INestApplication;
  let prisma: InMemoryPrisma;
  let crypto: CryptoService;

  const oidcModule = {
    authorizationCodeGrant:
      jest.fn<(...args: unknown[]) => Promise<OidcTokenSet>>(),
    refreshTokenGrant:
      jest.fn<
        (config: unknown, refreshToken: string) => Promise<OidcTokenSet>
      >(),
    fetchUserInfo:
      jest.fn<
        (
          config: unknown,
          accessToken: string,
          userId: string,
        ) => Promise<Record<string, unknown> | null>
      >(),
  };

  beforeEach(async () => {
    prisma = new InMemoryPrisma();
    oidcModule.authorizationCodeGrant.mockReset();
    oidcModule.refreshTokenGrant.mockReset();
    oidcModule.fetchUserInfo.mockReset();
    oidcModule.fetchUserInfo.mockResolvedValue(null);

    prisma.oidcRequest.create({
      data: {
        id: 'oidc-1',
        state: 'state-1',
        codeVerifier: 'verifier-1',
        nonce: 'nonce-1',
        requestedOrgId: 'org-1',
        requestedOrgDomain: null,
        redirectUri: null,
        createdAt: new Date(),
      },
    });

    const configService = createConfigService();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        AuthService,
        SessionService,
        CryptoService,
        SessionGuard,
        { provide: PrismaService, useValue: prisma },
        { provide: ConfigService, useValue: configService },
        {
          provide: OidcClientService,
          useValue: {
            getModule: () => oidcModule,
            getConfig: () => ({}),
          },
        },
        {
          provide: AdminSignupService,
          useValue: {
            createAdminSignupJob:
              jest.fn<(body: Record<string, unknown>) => Promise<unknown>>(),
            getAdminSignupJob: jest.fn<(jobId: string) => Promise<unknown>>(),
          },
        },
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.use(cookieParser());
    await app.init();

    crypto = moduleFixture.get(CryptoService);
  });

  afterEach(async () => {
    await app.close();
  });

  it('creates a session cookie and persists encrypted tokens on callback', async () => {
    const accessToken = makeJwt({
      sub: 'user-1',
      email: 'franky@mail.com',
      'urn:zitadel:iam:user:resourceowner:id': 'org-1',
      ...roleClaims('org-1'),
    });
    oidcModule.authorizationCodeGrant.mockResolvedValue(
      makeTokenSet({
        userId: 'user-1',
        orgId: 'org-1',
        email: 'franky@mail.com',
        accessToken,
        refreshToken: 'refresh-token-1',
      }),
    );

    const response = await request(app.getHttpServer())
      .get('/auth/callback?code=code-1&state=state-1')
      .expect(200);

    expect(response.body).toMatchObject({
      userId: 'user-1',
      homeOrgId: 'org-1',
      activeOrgId: 'org-1',
      roles: ['USER'],
    });
    expect(response.headers['set-cookie'][0]).toContain('auth_session=');
    expect(prisma.sessions.size).toBe(1);
    expect(prisma.sessionTokens.size).toBe(1);

    const createdSession = Array.from(prisma.sessions.values())[0];
    expect(createdSession.refreshExpiresAt).toBeInstanceOf(Date);
    expect(createdSession.expiresAt.getTime()).toBeGreaterThan(
      createdSession.createdAt.getTime(),
    );

    const tokenRecord = prisma.sessionTokens.get(createdSession.id);
    expect(tokenRecord).toBeDefined();
    expect(
      crypto
        .decrypt({
          keyId: tokenRecord!.keyId,
          nonce: tokenRecord!.accessTokenNonce.toString('base64'),
          ciphertext: tokenRecord!.accessTokenEnc.toString('base64'),
          tag: tokenRecord!.accessTokenTag.toString('base64'),
        })
        .toString('utf8'),
    ).toBe(accessToken);
  });

  it('refreshes tokens on authenticated access when the access token is expired', async () => {
    const initialAccessToken = makeJwt({
      sub: 'user-1',
      email: 'franky@mail.com',
      'urn:zitadel:iam:user:resourceowner:id': 'org-1',
      ...roleClaims('org-1'),
    });
    oidcModule.authorizationCodeGrant.mockResolvedValue(
      makeTokenSet({
        userId: 'user-1',
        orgId: 'org-1',
        email: 'franky@mail.com',
        accessToken: initialAccessToken,
        refreshToken: 'refresh-token-1',
      }),
    );

    const callbackResponse = await request(app.getHttpServer())
      .get('/auth/callback?code=code-1&state=state-1')
      .expect(200);
    const cookie = callbackResponse.headers['set-cookie'][0];
    const sessionId = cookie.match(/auth_session=([^;]+)/)?.[1];
    if (!sessionId) {
      throw new Error('missing session cookie');
    }

    const session = prisma.sessions.get(sessionId);
    if (!session) {
      throw new Error('missing session record');
    }
    session.accessExpiresAt = new Date(Date.now() - 60_000);
    prisma.sessions.set(sessionId, session);

    const refreshedAccessToken = makeJwt({
      sub: 'user-1',
      email: 'franky@mail.com',
      'urn:zitadel:iam:user:resourceowner:id': 'org-1',
      ...roleClaims('org-1'),
    });
    oidcModule.refreshTokenGrant.mockResolvedValue(
      makeTokenSet({
        userId: 'user-1',
        orgId: 'org-1',
        email: 'franky@mail.com',
        accessToken: refreshedAccessToken,
        refreshToken: 'refresh-token-2',
        expiresIn: 1800,
        refreshExpiresIn: 5400,
      }),
    );

    const meResponse = await request(app.getHttpServer())
      .get('/auth/me')
      .set('Cookie', `auth_session=${sessionId}`)
      .expect(200);

    expect(meResponse.body).toMatchObject({
      userId: 'user-1',
      orgId: 'org-1',
      roles: ['USER'],
    });
    expect(oidcModule.refreshTokenGrant).toHaveBeenCalledTimes(1);

    const updatedSession = prisma.sessions.get(sessionId)!;
    expect(updatedSession.accessExpiresAt.getTime()).toBeGreaterThan(
      Date.now(),
    );
    expect(updatedSession.refreshExpiresAt?.getTime()).toBeGreaterThan(
      Date.now(),
    );

    const tokenRecord = prisma.sessionTokens.get(sessionId)!;
    expect(
      crypto
        .decrypt({
          keyId: tokenRecord.keyId,
          nonce: tokenRecord.accessTokenNonce.toString('base64'),
          ciphertext: tokenRecord.accessTokenEnc.toString('base64'),
          tag: tokenRecord.accessTokenTag.toString('base64'),
        })
        .toString('utf8'),
    ).toBe(refreshedAccessToken);
  });

  it('logs out by deleting the session and clearing the cookie', async () => {
    const accessToken = makeJwt({
      sub: 'user-1',
      email: 'franky@mail.com',
      'urn:zitadel:iam:user:resourceowner:id': 'org-1',
      ...roleClaims('org-1'),
    });
    oidcModule.authorizationCodeGrant.mockResolvedValue(
      makeTokenSet({
        userId: 'user-1',
        orgId: 'org-1',
        email: 'franky@mail.com',
        accessToken,
        refreshToken: 'refresh-token-1',
      }),
    );

    const callbackResponse = await request(app.getHttpServer())
      .get('/auth/callback?code=code-1&state=state-1')
      .expect(200);
    const cookie = callbackResponse.headers['set-cookie'][0];
    const sessionId = cookie.match(/auth_session=([^;]+)/)?.[1];
    if (!sessionId) {
      throw new Error('missing session cookie');
    }

    const logoutResponse = await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', `auth_session=${sessionId}`)
      .expect(204);

    expect(prisma.sessions.has(sessionId)).toBe(false);
    expect(prisma.sessionTokens.has(sessionId)).toBe(false);
    expect(logoutResponse.headers['set-cookie'][0]).toContain('auth_session=;');
  });
});
