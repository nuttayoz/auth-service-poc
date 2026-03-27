import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  UserOrgAccessSource,
  UserOrgAccessStatus,
  UserRole,
  UserStatus,
} from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service.js';

export type SessionContext = {
  id: string;
  userId: string;
  homeOrgId: string | null;
  activeOrgId: string | null;
  orgId: string | null;
  accessSource?: UserOrgAccessSource;
  roles: string[];
  permissions: string[];
  accessExpiresAt: Date;
  accessExpired: boolean;
};

const SESSION_ACTIVITY_TOUCH_INTERVAL_MS = 60 * 1000;

@Injectable()
export class SessionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  async loadSession(sessionId: string): Promise<SessionContext | null> {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: true },
    });

    if (!session || !session.user) {
      return null;
    }
    if (session.user.status !== UserStatus.ACTIVE) {
      await this.invalidateSession(session.id);
      return null;
    }

    const now = new Date();
    if (this.isSessionExpired(session, now)) {
      await this.invalidateSession(session.id);
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
      await this.invalidateSession(session.id);
      return null;
    }
    if (
      access.source === UserOrgAccessSource.EXTERNAL &&
      access.role === UserRole.ROOT
    ) {
      await this.invalidateSession(session.id);
      return null;
    }

    if (
      now.getTime() - session.lastActivityAt.getTime() >=
      SESSION_ACTIVITY_TOUCH_INTERVAL_MS
    ) {
      await this.prisma.session
        .update({
          where: { id: session.id },
          data: { lastActivityAt: now },
        })
        .catch(() => undefined);
    }

    const accessExpired = session.accessExpiresAt <= now;

    return {
      id: session.id,
      userId: session.userId,
      homeOrgId: session.homeOrgId ?? null,
      activeOrgId: orgId,
      orgId,
      accessSource: access.source,
      roles: [access.role],
      permissions: [],
      accessExpiresAt: session.accessExpiresAt,
      accessExpired,
    };
  }

  private isSessionExpired(
    session: { expiresAt: Date; lastActivityAt: Date },
    now: Date,
  ): boolean {
    if (session.expiresAt <= now) {
      return true;
    }

    const idleTimeoutMs =
      (this.config.get<number>('SESSION_IDLE_TIMEOUT_SEC') ??
        60 * 60 * 24 * 7) * 1000;

    return session.lastActivityAt.getTime() + idleTimeoutMs <= now.getTime();
  }

  private async invalidateSession(sessionId: string): Promise<void> {
    await this.prisma.session.delete({ where: { id: sessionId } }).catch(() => {
      return undefined;
    });
  }
}
