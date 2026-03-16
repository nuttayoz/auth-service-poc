import { Logger } from '@nestjs/common';
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { ConfigService } from '@nestjs/config';
import {
  Prisma,
  ProvisioningJobStatus,
  ProvisioningJobType,
  UserRole,
  UserStatus,
} from '@prisma/client';
import { Job } from 'bullmq';
import { CryptoService } from '../crypto/crypto.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import {
  type SetupOrganizationParams,
  ZitadelService,
} from '../zitadel/zitadel.service.js';
import {
  ADMIN_SIGNUP_QUEUE,
  type AdminSignupJobData,
} from './admin-signup.queue.js';

@Processor(ADMIN_SIGNUP_QUEUE)
export class AdminSignupProcessor extends WorkerHost {
  private readonly logger = new Logger(AdminSignupProcessor.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
    private readonly config: ConfigService,
    private readonly zitadel: ZitadelService,
  ) {
    super();
  }

  async process(job: Job<AdminSignupJobData>): Promise<void> {
    const provisioningJobId = job.data.provisioningJobId;
    const provisioningJob = await this.prisma.provisioningJob.findUnique({
      where: { id: provisioningJobId },
    });

    if (!provisioningJob) {
      this.logger.warn(`Admin signup job not found: ${provisioningJobId}`);
      return;
    }

    if (provisioningJob.jobType !== ProvisioningJobType.ADMIN_SIGNUP) {
      this.logger.warn(
        `Skipping provisioning job ${provisioningJobId}: expected ADMIN_SIGNUP but found ${provisioningJob.jobType}`,
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

    const projectId = this.getProjectId();
    if (!projectId) {
      await this.markFailed(
        provisioningJobId,
        job.data.orgName,
        job.data.orgDomain,
        job.data.email,
        'ZITADEL_MASTER_PROJECT_ID is not configured',
      );
      return;
    }

    const adminRoleKey = this.getAdminRoleKey();
    if (!adminRoleKey) {
      await this.markFailed(
        provisioningJobId,
        job.data.orgName,
        job.data.orgDomain,
        job.data.email,
        'ZITADEL admin role key is missing',
      );
      return;
    }

    const password = this.crypto
      .decrypt(job.data.encryptedPassword)
      .toString('utf8');

    const adminUser: SetupOrganizationParams['admin'] = {
      email: job.data.email,
      password,
      firstName: job.data.firstName,
      lastName: job.data.lastName,
      userName: job.data.userName,
    };

    let orgId = provisioningJob.resultOrgId ?? provisioningJob.orgId ?? null;
    if (!orgId) {
      try {
        orgId = await this.zitadel.createOrganization(job.data.orgName);
      } catch (error) {
        await this.markFailed(
          provisioningJobId,
          job.data.orgName,
          job.data.orgDomain,
          job.data.email,
          error instanceof Error ? error.message : 'ZITADEL org create failed',
        );
        return;
      }

      try {
        await this.recordExternalProgress(provisioningJobId, { orgId });
      } catch (error) {
        await this.markReconciliationRequired(
          provisioningJobId,
          job.data.orgName,
          job.data.orgDomain,
          job.data.email,
          orgId,
          null,
          error instanceof Error
            ? error.message
            : 'Failed to record created organization',
        );
        return;
      }
    }

    if (job.data.orgDomain) {
      try {
        await this.zitadel.addOrganizationDomain(orgId, job.data.orgDomain);
      } catch (error) {
        await this.markReconciliationRequired(
          provisioningJobId,
          job.data.orgName,
          job.data.orgDomain,
          job.data.email,
          orgId,
          null,
          error instanceof Error ? error.message : 'ZITADEL domain add failed',
        );
        return;
      }
    }

    try {
      await this.zitadel.createProjectGrant(
        projectId,
        orgId,
        this.getProjectRoleKeys(),
      );
    } catch (error) {
      await this.markReconciliationRequired(
        provisioningJobId,
        job.data.orgName,
        job.data.orgDomain,
        job.data.email,
        orgId,
        null,
        error instanceof Error ? error.message : 'ZITADEL project grant failed',
      );
      return;
    }

    let userId = provisioningJob.resultUserId ?? null;
    if (!userId) {
      try {
        userId = await this.zitadel.createHumanUser(orgId, adminUser);
      } catch (error) {
        await this.markReconciliationRequired(
          provisioningJobId,
          job.data.orgName,
          job.data.orgDomain,
          job.data.email,
          orgId,
          null,
          error instanceof Error
            ? error.message
            : 'ZITADEL admin create failed',
        );
        return;
      }

      try {
        await this.recordExternalProgress(provisioningJobId, { orgId, userId });
      } catch (error) {
        await this.markReconciliationRequired(
          provisioningJobId,
          job.data.orgName,
          job.data.orgDomain,
          job.data.email,
          orgId,
          userId,
          error instanceof Error
            ? error.message
            : 'Failed to record created admin user',
        );
        return;
      }
    }

    try {
      await this.zitadel.createAuthorization(userId, projectId, orgId, [
        adminRoleKey,
      ]);
    } catch (error) {
      await this.markReconciliationRequired(
        provisioningJobId,
        job.data.orgName,
        job.data.orgDomain,
        job.data.email,
        orgId,
        userId,
        error instanceof Error
          ? error.message
          : 'ZITADEL admin authorization failed',
      );
      return;
    }

    try {
      await this.prisma.$transaction(async (tx) => {
        await tx.org.upsert({
          where: { id: orgId },
          create: { id: orgId, name: job.data.orgName },
          update: { name: job.data.orgName },
        });

        await tx.user.upsert({
          where: { id: userId },
          create: {
            id: userId,
            orgId,
            email: job.data.email,
            role: UserRole.ROOT,
            status: UserStatus.ACTIVE,
          },
          update: {
            orgId,
            email: job.data.email,
            role: UserRole.ROOT,
            status: UserStatus.ACTIVE,
          },
        });

        await tx.provisioningJob.update({
          where: { id: provisioningJobId },
          data: {
            status: ProvisioningJobStatus.SUCCEEDED,
            orgId,
            resultOrgId: orgId,
            resultUserId: userId,
            errorMessage: null,
            completedAt: new Date(),
          },
        });

        await tx.auditLog.create({
          data: {
            actorUserId: null,
            action: 'auth.admin_signup.completed',
            metadata: {
              orgId,
              provisioningJobId,
              userId,
              orgName: job.data.orgName,
              orgDomain: job.data.orgDomain ?? null,
              email: job.data.email,
              role: UserRole.ROOT,
            } as Prisma.InputJsonValue,
          },
        });
      });
    } catch (error) {
      await this.markReconciliationRequired(
        provisioningJobId,
        job.data.orgName,
        job.data.orgDomain,
        job.data.email,
        orgId,
        userId,
        error instanceof Error ? error.message : 'Local sync failed',
      );
    }
  }

  private async recordExternalProgress(
    provisioningJobId: string,
    params: { orgId: string; userId?: string },
  ): Promise<void> {
    await this.prisma.provisioningJob.update({
      where: { id: provisioningJobId },
      data: {
        orgId: params.orgId,
        resultOrgId: params.orgId,
        ...(params.userId ? { resultUserId: params.userId } : {}),
      },
    });
  }

  private async markFailed(
    provisioningJobId: string,
    orgName: string,
    orgDomain: string | undefined,
    email: string,
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

    await this.writeAuditLogSafe(null, 'auth.admin_signup.failed', {
      provisioningJobId,
      orgName,
      orgDomain: orgDomain ?? null,
      email,
      role: UserRole.ROOT,
      error: errorMessage,
    });
  }

  private async markReconciliationRequired(
    provisioningJobId: string,
    orgName: string,
    orgDomain: string | undefined,
    email: string,
    orgId: string,
    userId: string | null,
    errorMessage: string,
  ): Promise<void> {
    await this.prisma.provisioningJob.update({
      where: { id: provisioningJobId },
      data: {
        status: ProvisioningJobStatus.RECONCILIATION_REQUIRED,
        orgId,
        resultOrgId: orgId,
        ...(userId ? { resultUserId: userId } : {}),
        errorMessage,
        completedAt: new Date(),
      },
    });

    await this.writeAuditLogSafe(
      null,
      'auth.admin_signup.reconciliation_required',
      {
        provisioningJobId,
        orgId,
        userId,
        orgName,
        orgDomain: orgDomain ?? null,
        email,
        role: UserRole.ROOT,
        error: errorMessage,
      },
    );
  }

  private getProjectId(): string | null {
    const projectId =
      this.config.get<string>('ZITADEL_MASTER_PROJECT_ID') ?? '';
    return projectId || null;
  }

  private getProjectRoleKeys(): string[] {
    const raw =
      this.config.get<string>('ZITADEL_PROJECT_GRANT_ROLE_KEYS') ?? '';
    return raw
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
  }

  private getAdminRoleKey(): string | null {
    const key = this.config.get<string>('ZITADEL_ADMIN_ROLE_KEY') ?? 'admin';
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
