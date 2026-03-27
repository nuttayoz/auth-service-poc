import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AuthService } from './auth.service.js';
import { SessionService } from './session.service.js';

export type RequestWithSession = Request & {
  session?: Awaited<ReturnType<SessionService['loadSession']>>;
};

@Injectable()
export class SessionGuard implements CanActivate {
  constructor(
    private readonly config: ConfigService,
    private readonly sessions: SessionService,
    private readonly auth: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<RequestWithSession>();
    const cookieName =
      this.config.get<string>('SESSION_COOKIE_NAME') ?? 'auth_session';
    const sessionId = req.cookies?.[cookieName];

    if (!sessionId) {
      throw new UnauthorizedException('Missing session cookie');
    }

    let session = await this.sessions.loadSession(sessionId);
    if (!session) {
      throw new UnauthorizedException('Invalid session');
    }

    const isCrossOrgSession =
      !!session.activeOrgId &&
      !!session.homeOrgId &&
      session.activeOrgId !== session.homeOrgId;

    if (isCrossOrgSession) {
      session = await this.auth.validateSessionAuthorization(session.id);
    } else if (session.accessExpired) {
      session = await this.auth.refreshSession(session.id);
    }

    req.session = session;
    return true;
  }
}
