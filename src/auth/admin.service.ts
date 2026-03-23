import { randomUUID } from 'crypto';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import {
  Prisma,
  ProvisioningJob,
  ProvisioningJobStatus,
  ProvisioningJobType,
  User,
  UserOrgAccess,
  UserOrgAccessSource,
  UserOrgAccessStatus,
  UserRole,
  UserStatus,
} from '@prisma/client';
import { Queue } from 'bullmq';
import { CryptoService } from '../crypto/crypto.service.js';
import { LoggingContextService } from '../logging/logging-context.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { SessionContext } from './session.service.js';
import {
  USER_PROVISION_JOB,
  USER_PROVISION_QUEUE,
  type UserProvisionJobData,
} from './user-provision.queue.js';

export type CreateUserPayload = {
  email?: string;
  password?: string;
  firstName?: string;
  lastName?: string;
  userName?: string;
  role?: 'ROOT' | 'USER';
};

export type RootCreateUserPayload = CreateUserPayload;

export type GrantExternalAccessPayload = {
  userId?: string;
  email?: string;
  projectGrantId?: string;
  zitadelRoleAssignmentId?: string;
};

export type ExternalAccessResponse = {
  id: string;
  userId: string;
  email: string | null;
  homeOrgId: string;
  orgId: string;
  role: UserRole;
  source: UserOrgAccessSource;
  status: UserOrgAccessStatus;
  projectGrantId: string | null;
  zitadelRoleAssignmentId: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type ProvisioningJobResponse = {
  id: string;
  orgId: string | null;
  email: string;
  userName: string;
  role: UserRole;
  status: ProvisioningJobStatus;
  resultUserId: string | null;
  errorMessage: string | null;
  createdAt: Date;
  updatedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
};

@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly loggingContext: LoggingContextService,
    @InjectQueue(USER_PROVISION_QUEUE)
    private readonly provisionQueue: Queue<UserProvisionJobData>,
  ) {}

  async createUser(
    session: SessionContext,
    payload: CreateUserPayload,
  ): Promise<ProvisioningJobResponse> {
    const orgId = session.activeOrgId ?? session.orgId;
    if (!orgId) {
      throw new BadRequestException('Missing org');
    }

    return this.enqueueUserProvisioning({
      orgId,
      requestedByUserId: session.userId,
      payload,
      auditAction: 'admin.user.create_requested',
    });
  }

  async createUserWithRootKey(
    rootKey: { id: string; orgId: string },
    payload: RootCreateUserPayload,
  ): Promise<ProvisioningJobResponse> {
    if (
      'orgId' in (payload as Record<string, unknown>) &&
      typeof (payload as Record<string, unknown>).orgId !== 'undefined'
    ) {
      throw new BadRequestException('orgId is derived from the root key');
    }

    return this.enqueueUserProvisioning({
      orgId: rootKey.orgId,
      requestedByRootKeyId: rootKey.id,
      payload,
      auditAction: 'root_key.user.create_requested',
    });
  }

  async getProvisioningJob(
    session: SessionContext,
    jobId: string,
  ): Promise<ProvisioningJobResponse> {
    const orgId = session.activeOrgId ?? session.orgId;
    if (!orgId) {
      throw new BadRequestException('Missing org');
    }

    const job = await this.prisma.provisioningJob.findUnique({
      where: { id: jobId },
    });

    if (
      !job ||
      job.jobType !== ProvisioningJobType.USER_CREATE ||
      job.orgId !== orgId
    ) {
      throw new NotFoundException('Provisioning job not found');
    }

    return this.toProvisioningJobResponse(job);
  }

  async getProvisioningJobForRootKey(
    rootKey: { orgId: string },
    jobId: string,
  ): Promise<ProvisioningJobResponse> {
    const job = await this.prisma.provisioningJob.findUnique({
      where: { id: jobId },
    });

    if (
      !job ||
      job.jobType !== ProvisioningJobType.USER_CREATE ||
      job.orgId !== rootKey.orgId
    ) {
      throw new NotFoundException('Provisioning job not found');
    }

    return this.toProvisioningJobResponse(job);
  }

  async listExternalAccesses(
    session: SessionContext,
  ): Promise<ExternalAccessResponse[]> {
    const orgId = session.activeOrgId ?? session.orgId;
    if (!orgId) {
      throw new BadRequestException('Missing org');
    }

    const accesses = await this.prisma.userOrgAccess.findMany({
      where: {
        orgId,
        source: UserOrgAccessSource.EXTERNAL,
      },
      include: { user: true },
      orderBy: [{ status: 'asc' }, { createdAt: 'desc' }],
    });

    return accesses.map((access) =>
      this.toExternalAccessResponse(access, access.user),
    );
  }

  async grantExternalAccess(
    session: SessionContext,
    payload: GrantExternalAccessPayload,
  ): Promise<ExternalAccessResponse> {
    const orgId = session.activeOrgId ?? session.orgId;
    if (!orgId) {
      throw new BadRequestException('Missing org');
    }

    const user = await this.resolveUserForExternalAccess(payload);
    if (user.status === UserStatus.DISABLED) {
      throw new ConflictException('User is disabled');
    }
    if (user.homeOrgId === orgId) {
      throw new ConflictException('User already belongs directly to this org');
    }

    const existing = await this.prisma.userOrgAccess.findUnique({
      where: {
        userId_orgId: {
          userId: user.id,
          orgId,
        },
      },
    });

    if (existing?.source === UserOrgAccessSource.DIRECT) {
      throw new ConflictException(
        'Direct org membership cannot be replaced with external access',
      );
    }

    const access = await this.prisma.userOrgAccess.upsert({
      where: {
        userId_orgId: {
          userId: user.id,
          orgId,
        },
      },
      create: {
        userId: user.id,
        orgId,
        role: UserRole.USER,
        source: UserOrgAccessSource.EXTERNAL,
        status: UserOrgAccessStatus.ACTIVE,
        projectGrantId: payload.projectGrantId?.trim() || null,
        zitadelRoleAssignmentId:
          payload.zitadelRoleAssignmentId?.trim() || null,
      },
      update: {
        role: UserRole.USER,
        source: UserOrgAccessSource.EXTERNAL,
        status: UserOrgAccessStatus.ACTIVE,
        projectGrantId: payload.projectGrantId?.trim() || null,
        zitadelRoleAssignmentId:
          payload.zitadelRoleAssignmentId?.trim() || null,
      },
    });

    await this.writeAuditLogSafe(
      session.userId,
      'admin.external_access.grant',
      {
        orgId,
        targetUserId: user.id,
        targetEmail: user.email,
        homeOrgId: user.homeOrgId,
        role: UserRole.USER,
        source: UserOrgAccessSource.EXTERNAL,
        projectGrantId: access.projectGrantId,
        zitadelRoleAssignmentId: access.zitadelRoleAssignmentId,
      },
    );

    return this.toExternalAccessResponse(access, user);
  }

  async revokeExternalAccess(
    session: SessionContext,
    payload: GrantExternalAccessPayload,
  ): Promise<ExternalAccessResponse> {
    const orgId = session.activeOrgId ?? session.orgId;
    if (!orgId) {
      throw new BadRequestException('Missing org');
    }

    const user = await this.resolveUserForExternalAccess(payload);
    const access = await this.prisma.userOrgAccess.findUnique({
      where: {
        userId_orgId: {
          userId: user.id,
          orgId,
        },
      },
    });

    if (!access || access.source !== UserOrgAccessSource.EXTERNAL) {
      throw new NotFoundException('External access not found');
    }

    const revoked = await this.prisma.userOrgAccess.update({
      where: { id: access.id },
      data: { status: UserOrgAccessStatus.REVOKED },
    });

    await this.writeAuditLogSafe(
      session.userId,
      'admin.external_access.revoke',
      {
        orgId,
        targetUserId: user.id,
        targetEmail: user.email,
        homeOrgId: user.homeOrgId,
        source: UserOrgAccessSource.EXTERNAL,
      },
    );

    return this.toExternalAccessResponse(revoked, user);
  }

  private async enqueueUserProvisioning(params: {
    orgId: string;
    requestedByUserId?: string;
    requestedByRootKeyId?: string;
    payload: CreateUserPayload;
    auditAction: string;
  }): Promise<ProvisioningJobResponse> {
    const email = params.payload.email?.trim().toLowerCase();
    if (!email) {
      throw new BadRequestException('email is required');
    }

    const password = params.payload.password ?? '';
    if (!password) {
      throw new BadRequestException('password is required');
    }

    const rawRole = (params.payload.role ?? 'USER').toUpperCase();
    if (rawRole !== UserRole.ROOT && rawRole !== UserRole.USER) {
      throw new BadRequestException('role must be ROOT or USER');
    }

    const role = rawRole === UserRole.ROOT ? UserRole.ROOT : UserRole.USER;
    const firstName = params.payload.firstName?.trim() || 'User';
    const lastName = params.payload.lastName?.trim() || '';
    const userName = params.payload.userName?.trim() || email;

    const existing = await this.prisma.provisioningJob.findFirst({
      where: {
        jobType: ProvisioningJobType.USER_CREATE,
        orgId: params.orgId,
        email,
        status: {
          in: [ProvisioningJobStatus.QUEUED, ProvisioningJobStatus.PROCESSING],
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (existing) {
      throw new ConflictException(
        `A provisioning job is already in progress for "${email}" (jobId: ${existing.id})`,
      );
    }

    const jobId = randomUUID();
    const provisioningJob = await this.prisma.provisioningJob.create({
      data: {
        id: jobId,
        jobType: ProvisioningJobType.USER_CREATE,
        orgId: params.orgId,
        ...(params.requestedByUserId
          ? { requestedByUserId: params.requestedByUserId }
          : {}),
        ...(params.requestedByRootKeyId
          ? { requestedByRootKeyId: params.requestedByRootKeyId }
          : {}),
        email,
        firstName,
        lastName,
        userName,
        requestedRole: role,
        status: ProvisioningJobStatus.QUEUED,
      },
    });

    try {
      await this.provisionQueue.add(
        USER_PROVISION_JOB,
        {
          ...(this.loggingContext.get('requestId')
            ? { requestId: this.loggingContext.get('requestId') }
            : {}),
          provisioningJobId: jobId,
          orgId: params.orgId,
          ...(params.requestedByUserId
            ? { requestedByUserId: params.requestedByUserId }
            : {}),
          ...(params.requestedByRootKeyId
            ? { requestedByRootKeyId: params.requestedByRootKeyId }
            : {}),
          email,
          firstName,
          lastName,
          userName,
          role,
          encryptedPassword: this.crypto.encrypt(password),
        },
        {
          jobId,
          attempts: 1,
          removeOnComplete: 1000,
          removeOnFail: 1000,
        },
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Failed to enqueue job';

      await this.prisma.provisioningJob.update({
        where: { id: jobId },
        data: {
          status: ProvisioningJobStatus.FAILED,
          errorMessage,
          completedAt: new Date(),
        },
      });

      this.logger.error(
        `Failed to enqueue provisioning job: orgId="${params.orgId}" email="${email}"`,
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException(
        'Failed to enqueue provisioning job',
      );
    }

    await this.writeAuditLogSafe(
      params.requestedByUserId ?? null,
      params.auditAction,
      {
        orgId: params.orgId,
        provisioningJobId: jobId,
        email,
        role,
        ...(params.requestedByRootKeyId
          ? { rootKeyId: params.requestedByRootKeyId }
          : {}),
      },
    );

    return this.toProvisioningJobResponse(provisioningJob);
  }

  private toProvisioningJobResponse(
    job: ProvisioningJob,
  ): ProvisioningJobResponse {
    return {
      id: job.id,
      orgId: job.orgId ?? null,
      email: job.email,
      userName: job.userName,
      role: job.requestedRole,
      status: job.status,
      resultUserId: job.resultUserId ?? null,
      errorMessage: job.errorMessage ?? null,
      createdAt: job.createdAt,
      updatedAt: job.updatedAt,
      startedAt: job.startedAt ?? null,
      completedAt: job.completedAt ?? null,
    };
  }

  private async resolveUserForExternalAccess(
    payload: GrantExternalAccessPayload,
  ): Promise<User> {
    const userId = payload.userId?.trim();
    const email = payload.email?.trim().toLowerCase();

    if ((userId ? 1 : 0) + (email ? 1 : 0) !== 1) {
      throw new BadRequestException('Provide exactly one of userId or email');
    }

    const user = await this.prisma.user.findFirst({
      where: userId ? { id: userId } : { email },
    });

    if (!user) {
      throw new NotFoundException(
        'User not found locally. The user must exist in auth-service before external access can be synced.',
      );
    }

    return user;
  }

  private toExternalAccessResponse(
    access: UserOrgAccess,
    user: User,
  ): ExternalAccessResponse {
    return {
      id: access.id,
      userId: access.userId,
      email: user.email ?? null,
      homeOrgId: user.homeOrgId,
      orgId: access.orgId,
      role: access.role,
      source: access.source,
      status: access.status,
      projectGrantId: access.projectGrantId ?? null,
      zitadelRoleAssignmentId: access.zitadelRoleAssignmentId ?? null,
      createdAt: access.createdAt,
      updatedAt: access.updatedAt,
    };
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
      this.logger.warn(
        `Audit log write failed for action "${action}": ${error instanceof Error ? error.message : 'unknown error'}`,
      );
    }
  }
}
