import {
  BadRequestException,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma, UserRole, UserStatus } from '@prisma/client';
import type { SessionContext } from './session.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { ZitadelService } from '../zitadel/zitadel.service.js';

export type CreateUserPayload = {
  email?: string;
  password?: string;
  firstName?: string;
  lastName?: string;
  userName?: string;
  role?: 'ROOT' | 'USER';
};

@Injectable()
export class AdminService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly zitadel: ZitadelService,
    private readonly config: ConfigService,
  ) {}

  async createUser(session: SessionContext, payload: CreateUserPayload) {
    const orgId = session.orgId;
    if (!orgId) {
      throw new BadRequestException('Missing org');
    }

    const email = payload.email?.trim().toLowerCase();
    if (!email) {
      throw new BadRequestException('email is required');
    }

    const password = payload.password ?? '';
    if (!password) {
      throw new BadRequestException('password is required');
    }

    const rawRole = (payload.role ?? 'USER').toUpperCase();
    if (rawRole !== UserRole.ROOT && rawRole !== UserRole.USER) {
      throw new BadRequestException('role must be ROOT or USER');
    }
    const role = rawRole === UserRole.ROOT ? UserRole.ROOT : UserRole.USER;

    const roleKey =
      role === UserRole.ROOT ? this.getAdminRoleKey() : this.getUserRoleKey();
    if (!roleKey) {
      throw new ServiceUnavailableException('ZITADEL role key is missing');
    }

    try {
      const userId = await this.zitadel.createUserInOrganization({
        orgId,
        user: {
          email,
          password,
          firstName: payload.firstName?.trim() || 'User',
          lastName: payload.lastName?.trim() || '',
          userName: payload.userName?.trim() || email,
        },
        roleKeys: [roleKey],
      });

      await this.prisma.org.upsert({
        where: { id: orgId },
        create: { id: orgId },
        update: {},
      });

      await this.prisma.user.upsert({
        where: { id: userId },
        create: {
          id: userId,
          orgId,
          email,
          role,
          status: UserStatus.ACTIVE,
        },
        update: {
          orgId,
          email,
          role,
          status: UserStatus.ACTIVE,
        },
      });

      await this.writeAuditLog(session.userId, 'admin.user.create', {
        orgId,
        userId,
        email,
        role,
      });

      return {
        id: userId,
        orgId,
        role,
      };
    } catch (error) {
      await this.writeAuditLog(session.userId, 'admin.user.create_failed', {
        orgId,
        email,
        role,
        error: error instanceof Error ? error.message : 'unknown error',
      });
      throw error;
    }
  }

  private getAdminRoleKey(): string | null {
    const key = this.config.get<string>('ZITADEL_ADMIN_ROLE_KEY') ?? 'admin';
    return key ? key : null;
  }

  private getUserRoleKey(): string | null {
    const key = this.config.get<string>('ZITADEL_USER_ROLE_KEY') ?? 'user';
    return key ? key : null;
  }

  private async writeAuditLog(
    actorUserId: string,
    action: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        actorUserId,
        action,
        metadata: metadata as Prisma.InputJsonValue,
      },
    });
  }
}
