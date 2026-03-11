import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export type SessionContext = {
  id: string;
  userId: string;
  orgId: string | null;
  accessExpiresAt: Date;
  accessExpired: boolean;
};

@Injectable()
export class SessionService {
  constructor(private readonly prisma: PrismaService) {}

  async loadSession(sessionId: string): Promise<SessionContext | null> {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
    });

    if (!session) {
      return null;
    }

    const accessExpired = session.accessExpiresAt <= new Date();

    return {
      id: session.id,
      userId: session.userId,
      orgId: session.orgId ?? null,
      accessExpiresAt: session.accessExpiresAt,
      accessExpired,
    };
  }
}
