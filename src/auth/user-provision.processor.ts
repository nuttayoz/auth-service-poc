import { Logger } from '@nestjs/common';
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { ConfigService } from '@nestjs/config';
import {
  Prisma,
  ProvisioningJobStatus,
  ProvisioningJobType,
  UserOrgAccessSource,
  UserOrgAccessStatus,
  UserRole,
  UserStatus,
} from '@prisma/client';
import { Job } from 'bullmq';
import { CryptoService } from '../crypto/crypto.service.js';
import { LoggingContextService } from '../logging/logging-context.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { ZitadelService } from '../zitadel/zitadel.service.js';
import {
  USER_PROVISION_QUEUE,
  type UserProvisionJobData,
} from './user-provision.queue.js';

@Processor(USER_PROVISION_QUEUE)
export class UserProvisionProcessor extends WorkerHost {
  private readonly logger = new Logger(UserProvisionProcessor.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly loggingContext: LoggingContextService,
    private readonly crypto: CryptoService,
    private readonly config: ConfigService,
    private readonly zitadel: ZitadelService,
  ) {
    super();
  }

  async process(job: Job<UserProvisionJobData>): Promise<void> {
    return this.loggingContext.run(
      {
        requestId:
          job.data.requestId ?? `job:${job.id ?? job.data.provisioningJobId}`,
        jobId: job.id ?? undefined,
        jobName: job.name,
        provisioningJobId: job.data.provisioningJobId,
      },
      () => this.processWithinContext(job),
    );
  }

  private async processWithinContext(
    job: Job<UserProvisionJobData>,
  ): Promise<void> {
    const provisioningJobId = job.data.provisioningJobId;
    const provisioningJob = await this.prisma.provisioningJob.findUnique({
      where: { id: provisioningJobId },
    });

    if (!provisioningJob) {
      this.logger.warn(`Provisioning job not found: ${provisioningJobId}`);
      return;
    }

    if (provisioningJob.jobType !== ProvisioningJobType.USER_CREATE) {
      this.logger.warn(
        `Skipping provisioning job ${provisioningJobId}: expected USER_CREATE but found ${provisioningJob.jobType}`,
      );
      return;
    }

    if (
      provisioningJob.status === ProvisioningJobStatus.SUCCEEDED ||
      provisioningJob.status === ProvisioningJobStatus.RECONCILIATION_REQUIRED
    ) {
      return;
    }

    await this.prisma.provisioningJob.update({
      where: { id: provisioningJobId },
      data: {
        status: ProvisioningJobStatus.PROCESSING,
        startedAt: provisioningJob.startedAt ?? new Date(),
        errorMessage: null,
      },
    });

    const role =
      job.data.role === UserRole.ROOT ? UserRole.ROOT : UserRole.USER;
    const roleKey =
      role === UserRole.ROOT ? this.getAdminRoleKey() : this.getUserRoleKey();
    const auditActionPrefix = job.data.requestedByRootKeyId
      ? 'root_key.user'
      : 'admin.user';

    if (!roleKey) {
      await this.markFailed(
        provisioningJobId,
        job.data.requestedByUserId ?? null,
        job.data.requestedByRootKeyId,
        job.data.orgId,
        job.data.email,
        role,
        `${auditActionPrefix}.create_failed`,
        'ZITADEL role key is missing',
      );
      return;
    }

    const password = this.crypto
      .decrypt(job.data.encryptedPassword)
      .toString('utf8');

    let userId: string;
    try {
      userId = await this.zitadel.createUserInOrganization({
        orgId: job.data.orgId,
        user: {
          email: job.data.email,
          password,
          firstName: job.data.firstName,
          lastName: job.data.lastName,
          userName: job.data.userName,
        },
        roleKeys: [roleKey],
      });
    } catch (error) {
      await this.markFailed(
        provisioningJobId,
        job.data.requestedByUserId ?? null,
        job.data.requestedByRootKeyId,
        job.data.orgId,
        job.data.email,
        role,
        `${auditActionPrefix}.create_failed`,
        error instanceof Error ? error.message : 'ZITADEL create failed',
      );
      return;
    }

    try {
      await this.prisma.$transaction(async (tx) => {
        await tx.org.upsert({
          where: { id: job.data.orgId },
          create: { id: job.data.orgId },
          update: {},
        });

        await tx.user.upsert({
          where: { id: userId },
          create: {
            id: userId,
            homeOrgId: job.data.orgId,
            email: job.data.email,
            role,
            status: UserStatus.ACTIVE,
          },
          update: {
            homeOrgId: job.data.orgId,
            email: job.data.email,
            role,
            status: UserStatus.ACTIVE,
          },
        });

        await tx.userOrgAccess.upsert({
          where: {
            userId_orgId: {
              userId,
              orgId: job.data.orgId,
            },
          },
          create: {
            userId,
            orgId: job.data.orgId,
            role,
            source: UserOrgAccessSource.DIRECT,
            status: UserOrgAccessStatus.ACTIVE,
          },
          update: {
            role,
            source: UserOrgAccessSource.DIRECT,
            status: UserOrgAccessStatus.ACTIVE,
          },
        });

        await tx.provisioningJob.update({
          where: { id: provisioningJobId },
          data: {
            status: ProvisioningJobStatus.SUCCEEDED,
            resultUserId: userId,
            errorMessage: null,
            completedAt: new Date(),
          },
        });

        await tx.auditLog.create({
          data: {
            actorUserId: job.data.requestedByUserId ?? null,
            action: `${auditActionPrefix}.create`,
            metadata: {
              orgId: job.data.orgId,
              provisioningJobId,
              userId,
              email: job.data.email,
              role,
              ...(job.data.requestedByRootKeyId
                ? { rootKeyId: job.data.requestedByRootKeyId }
                : {}),
            } as Prisma.InputJsonValue,
          },
        });
      });
    } catch (error) {
      await this.markReconciliationRequired(
        provisioningJobId,
        job.data.requestedByUserId ?? null,
        job.data.requestedByRootKeyId,
        job.data.orgId,
        job.data.email,
        role,
        userId,
        `${auditActionPrefix}.create_reconciliation_required`,
        error instanceof Error ? error.message : 'Local sync failed',
      );
    }
  }

  private async markFailed(
    provisioningJobId: string,
    actorUserId: string | null,
    rootKeyId: string | undefined,
    orgId: string,
    email: string,
    role: UserRole,
    action: string,
    errorMessage: string,
  ): Promise<void> {
    await this.prisma.provisioningJob.update({
      where: { id: provisioningJobId },
      data: {
        status: ProvisioningJobStatus.FAILED,
        errorMessage,
        completedAt: new Date(),
      },
    });

    await this.writeAuditLogSafe(actorUserId, action, {
      orgId,
      provisioningJobId,
      email,
      role,
      error: errorMessage,
      ...(rootKeyId ? { rootKeyId } : {}),
    });
  }

  private async markReconciliationRequired(
    provisioningJobId: string,
    actorUserId: string | null,
    rootKeyId: string | undefined,
    orgId: string,
    email: string,
    role: UserRole,
    userId: string,
    action: string,
    errorMessage: string,
  ): Promise<void> {
    await this.prisma.provisioningJob.update({
      where: { id: provisioningJobId },
      data: {
        status: ProvisioningJobStatus.RECONCILIATION_REQUIRED,
        resultUserId: userId,
        errorMessage,
        completedAt: new Date(),
      },
    });

    await this.writeAuditLogSafe(actorUserId, action, {
      orgId,
      provisioningJobId,
      userId,
      email,
      role,
      error: errorMessage,
      ...(rootKeyId ? { rootKeyId } : {}),
    });
  }

  private getAdminRoleKey(): string | null {
    const key = this.config.get<string>('ZITADEL_ADMIN_ROLE_KEY') ?? 'admin';
    return key ? key : null;
  }

  private getUserRoleKey(): string | null {
    const key = this.config.get<string>('ZITADEL_USER_ROLE_KEY') ?? 'user';
    return key ? key : null;
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
