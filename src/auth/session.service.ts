import { Injectable } from '@nestjs/common';
import {
  UserOrgAccessSource,
  UserOrgAccessStatus,
  UserRole,
} from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service.js';

export type SessionContext = {
  id: string;
  userId: string;
  homeOrgId: string | null;
  activeOrgId: string | null;
  orgId: string | null;
  roles: string[];
  permissions: string[];
  accessExpiresAt: Date;
  accessExpired: boolean;
};

@Injectable()
export class SessionService {
  constructor(private readonly prisma: PrismaService) {}

  async loadSession(sessionId: string): Promise<SessionContext | null> {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: true },
    });

    if (!session || !session.user) {
      return null;
    }

    const orgId = session.activeOrgId ?? session.homeOrgId;
    const access = await this.prisma.userOrgAccess.findUnique({
      where: {
        userId_orgId: {
          userId: session.userId,
          orgId,
        },
      },
    });

    if (!access || access.status !== UserOrgAccessStatus.ACTIVE) {
      return null;
    }
    if (
      access.source === UserOrgAccessSource.EXTERNAL &&
      access.role === UserRole.ROOT
    ) {
      return null;
    }

    const accessExpired = session.accessExpiresAt <= new Date();

    return {
      id: session.id,
      userId: session.userId,
      homeOrgId: session.homeOrgId ?? null,
      activeOrgId: orgId,
      orgId,
      roles: [access.role],
      permissions: [],
      accessExpiresAt: session.accessExpiresAt,
      accessExpired,
    };
  }
}
