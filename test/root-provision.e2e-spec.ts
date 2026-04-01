import { INestApplication } from '@nestjs/common';
import { jest } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AdminService } from '../src/auth/admin.service.js';
import { AuthService } from '../src/auth/auth.service.js';
import { RootGuard } from '../src/auth/root.guard.js';
import { RootKeyController } from '../src/auth/root-key.controller.js';
import { RootKeyGuard } from '../src/auth/root-key.guard.js';
import {
  RootKeyService,
  type RootKeyIssueResponse,
  type RootKeySummary,
} from '../src/auth/root-key.service.js';
import { RootProvisionController } from '../src/auth/root-provision.controller.js';
import { SessionGuard } from '../src/auth/session.guard.js';
import {
  SessionService,
  type SessionContext,
} from '../src/auth/session.service.js';
import type {
  ProvisioningJobResponse,
  RootCreateUserPayload,
} from '../src/auth/admin.service.js';

const session: SessionContext = {
  id: 'session-1',
  userId: 'user-root',
  homeOrgId: 'org-1',
  activeOrgId: 'org-1',
  orgId: 'org-1',
  accessSource: 'DIRECT',
  roles: ['ROOT'],
  permissions: [],
  accessExpiresAt: new Date(Date.now() + 60_000),
  accessExpired: false,
};

const rootKeySummary: RootKeySummary = {
  id: 'rk-1',
  orgId: 'org-1',
  createdByUserId: 'user-root',
  status: 'ACTIVE',
  lastUsedAt: null,
  createdAt: new Date('2026-03-30T00:00:00.000Z'),
  revokedAt: null,
};

const issuedRootKey: RootKeyIssueResponse = {
  ...rootKeySummary,
  key: 'rk_live_secret',
};

describe('Root provisioning flow (e2e)', () => {
  let app: INestApplication;

  const adminService = {
    createUserWithRootKey:
      jest.fn<
        (
          rootKey: { id: string; orgId: string },
          payload: RootCreateUserPayload,
        ) => Promise<ProvisioningJobResponse>
      >(),
    getProvisioningJobForRootKey:
      jest.fn<
        (
          rootKey: { orgId: string },
          jobId: string,
        ) => Promise<ProvisioningJobResponse>
      >(),
  };

  const rootKeyService = {
    createRootKey:
      jest.fn<
        (actorUserId: string, orgId: string) => Promise<RootKeyIssueResponse>
      >(),
    listRootKeys: jest.fn<(orgId: string) => Promise<RootKeySummary[]>>(),
    rotateRootKey:
      jest.fn<
        (
          rootKeyId: string,
          actorUserId: string,
          orgId: string,
        ) => Promise<RootKeyIssueResponse>
      >(),
    revokeRootKey:
      jest.fn<
        (
          rootKeyId: string,
          actorUserId: string,
          orgId: string,
        ) => Promise<RootKeySummary>
      >(),
    validateRootKey:
      jest.fn<(rawKey: string, expectedOrgId?: string) => RootKeySummary>(),
  };
  const sessionService = {
    loadSession:
      jest.fn<(sessionId: string) => Promise<SessionContext | null>>(),
  };
  const authService = {
    validateSessionAuthorization:
      jest.fn<(sessionId: string) => Promise<SessionContext>>(),
    refreshSession: jest.fn<(sessionId: string) => Promise<SessionContext>>(),
    revalidateSession:
      jest.fn<(sessionId: string) => Promise<SessionContext>>(),
  };
  const configService = {
    get: jest.fn((key: string): string | undefined => {
      if (key === 'SESSION_COOKIE_NAME') {
        return 'auth_session';
      }
      return undefined;
    }),
  };

  beforeEach(async () => {
    jest.resetAllMocks();

    rootKeyService.createRootKey.mockResolvedValue(issuedRootKey);
    rootKeyService.validateRootKey.mockImplementation(
      (rawKey: string, expectedOrgId?: string) => {
        if (rawKey !== 'rk_live_secret') {
          throw new Error('unexpected key');
        }
        if (expectedOrgId && expectedOrgId !== 'org-1') {
          throw new Error('unexpected org');
        }
        return rootKeySummary;
      },
    );
    adminService.createUserWithRootKey.mockResolvedValue({
      id: 'job-1',
      orgId: 'org-1',
      email: 'franky@mail.com',
      userName: 'franky@mail.com',
      role: 'USER',
      status: 'QUEUED',
      resultUserId: null,
      errorMessage: null,
      createdAt: new Date('2026-03-30T00:00:00.000Z'),
      updatedAt: new Date('2026-03-30T00:00:00.000Z'),
      startedAt: null,
      completedAt: null,
    });
    adminService.getProvisioningJobForRootKey.mockResolvedValue({
      id: 'job-1',
      orgId: 'org-1',
      email: 'franky@mail.com',
      userName: 'franky@mail.com',
      role: 'USER',
      status: 'SUCCEEDED',
      resultUserId: 'user-2',
      errorMessage: null,
      createdAt: new Date('2026-03-30T00:00:00.000Z'),
      updatedAt: new Date('2026-03-30T00:01:00.000Z'),
      startedAt: new Date('2026-03-30T00:00:10.000Z'),
      completedAt: new Date('2026-03-30T00:01:00.000Z'),
    });
    sessionService.loadSession.mockResolvedValue(session);
    authService.validateSessionAuthorization.mockResolvedValue(session);
    authService.refreshSession.mockResolvedValue(session);
    authService.revalidateSession.mockResolvedValue(session);

    const moduleFixture: TestingModule = await Test.createTestingModule({
      controllers: [RootKeyController, RootProvisionController],
      providers: [
        RootKeyGuard,
        SessionGuard,
        RootGuard,
        { provide: AdminService, useValue: adminService },
        { provide: RootKeyService, useValue: rootKeyService },
        { provide: SessionService, useValue: sessionService },
        { provide: AuthService, useValue: authService },
        { provide: ConfigService, useValue: configService },
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.use(cookieParser());
    await app.init();
  });

  afterEach(async () => {
    if (app) {
      await app.close();
    }
  });

  it('creates a root key for the active org', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/admin/root-keys')
      .set('Cookie', 'auth_session=session-1')
      .expect(201);

    expect(response.body).toMatchObject({
      id: 'rk-1',
      orgId: 'org-1',
      key: 'rk_live_secret',
      status: 'ACTIVE',
    });
    expect(rootKeyService.createRootKey).toHaveBeenCalledWith(
      'user-root',
      'org-1',
    );
  });

  it('rejects root provisioning when the root key header is missing', async () => {
    await request(app.getHttpServer())
      .post('/auth/root/users')
      .send({
        email: 'franky@mail.com',
        password: 'Secret123!',
        userName: 'franky@mail.com',
        role: 'USER',
      })
      .expect(401);
  });

  it('creates a user through the root key flow', async () => {
    const payload = {
      email: 'franky@mail.com',
      password: 'Secret123!',
      userName: 'franky@mail.com',
      role: 'USER',
    };

    const response = await request(app.getHttpServer())
      .post('/auth/root/users')
      .set('x-root-key', 'rk_live_secret')
      .send(payload)
      .expect(202);

    expect(response.body).toMatchObject({
      id: 'job-1',
      orgId: 'org-1',
      email: 'franky@mail.com',
      status: 'QUEUED',
    });
    expect(rootKeyService.validateRootKey).toHaveBeenCalledWith(
      'rk_live_secret',
      undefined,
    );
    expect(adminService.createUserWithRootKey).toHaveBeenCalledWith(
      rootKeySummary,
      payload,
    );
  });

  it('returns the provisioning job status for the same root key org', async () => {
    const response = await request(app.getHttpServer())
      .get('/auth/root/jobs/job-1')
      .set('x-root-key', 'rk_live_secret')
      .expect(200);

    expect(response.body).toMatchObject({
      id: 'job-1',
      orgId: 'org-1',
      status: 'SUCCEEDED',
      resultUserId: 'user-2',
    });
    expect(adminService.getProvisioningJobForRootKey).toHaveBeenCalledWith(
      rootKeySummary,
      'job-1',
    );
  });

  it('rejects admin root-key creation when the session cookie is missing', async () => {
    await request(app.getHttpServer())
      .post('/auth/admin/root-keys')
      .expect(401);
  });
});
