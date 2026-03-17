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
  UserRole,
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
    const orgId = session.orgId;
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
    const orgId = session.orgId;
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
