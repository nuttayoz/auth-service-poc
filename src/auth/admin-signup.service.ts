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
import {
  ADMIN_SIGNUP_JOB,
  ADMIN_SIGNUP_QUEUE,
  type AdminSignupJobData,
} from './admin-signup.queue.js';

export type AdminSignupPayload = {
  orgName?: string;
  orgDomain?: string;
  email?: string;
  password?: string;
  firstName?: string;
  lastName?: string;
  userName?: string;
};

export type AdminSignupJobResponse = {
  id: string;
  orgName: string | null;
  orgDomain: string | null;
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
export class AdminSignupService {
  private readonly logger = new Logger(AdminSignupService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly loggingContext: LoggingContextService,
    @InjectQueue(ADMIN_SIGNUP_QUEUE)
    private readonly signupQueue: Queue<AdminSignupJobData>,
  ) {}

  async createAdminSignupJob(
    payload: AdminSignupPayload,
  ): Promise<AdminSignupJobResponse> {
    if (!this.crypto.isEnabled()) {
      throw new ServiceUnavailableException('Crypto is disabled');
    }

    const orgName = payload.orgName?.trim();
    const orgDomain = payload.orgDomain?.trim().toLowerCase() || undefined;
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

    const firstName = payload.firstName?.trim() || 'Admin';
    const lastName = payload.lastName?.trim() || 'User';
    const userName = payload.userName?.trim() || email;

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });
    if (existingUser) {
      throw new ConflictException(`User already exists for "${email}"`);
    }

    const existingJob = await this.prisma.provisioningJob.findFirst({
      where: {
        jobType: ProvisioningJobType.ADMIN_SIGNUP,
        email,
        status: {
          in: [ProvisioningJobStatus.QUEUED, ProvisioningJobStatus.PROCESSING],
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (existingJob) {
      throw new ConflictException(
        `An admin signup job is already in progress for "${email}" (jobId: ${existingJob.id})`,
      );
    }

    const jobId = randomUUID();
    const provisioningJob = await this.prisma.provisioningJob.create({
      data: {
        id: jobId,
        jobType: ProvisioningJobType.ADMIN_SIGNUP,
        orgName,
        orgDomain,
        email,
        firstName,
        lastName,
        userName,
        requestedRole: UserRole.ROOT,
        status: ProvisioningJobStatus.QUEUED,
      },
    });

    try {
      await this.signupQueue.add(
        ADMIN_SIGNUP_JOB,
        {
          ...(this.loggingContext.get('requestId')
            ? { requestId: this.loggingContext.get('requestId') }
            : {}),
          provisioningJobId: jobId,
          orgName,
          ...(orgDomain ? { orgDomain } : {}),
          email,
          firstName,
          lastName,
          userName,
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
        `Failed to enqueue admin signup job: email="${email}" org="${orgName}"`,
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException('Failed to enqueue admin signup');
    }

    await this.writeAuditLogSafe(null, 'auth.admin_signup.requested', {
      provisioningJobId: jobId,
      orgName,
      orgDomain,
      email,
    });

    return this.toResponse(provisioningJob);
  }

  async getAdminSignupJob(jobId: string): Promise<AdminSignupJobResponse> {
    const job = await this.prisma.provisioningJob.findUnique({
      where: { id: jobId },
    });

    if (!job || job.jobType !== ProvisioningJobType.ADMIN_SIGNUP) {
      throw new NotFoundException('Admin signup job not found');
    }

    return this.toResponse(job);
  }

  private toResponse(job: ProvisioningJob): AdminSignupJobResponse {
    return {
      id: job.id,
      orgName: job.orgName ?? null,
      orgDomain: job.orgDomain ?? null,
      orgId: job.resultOrgId ?? job.orgId ?? null,
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
