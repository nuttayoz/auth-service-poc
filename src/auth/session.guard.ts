import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { SessionService } from './session.service';

export type RequestWithSession = Request & {
  session?: Awaited<ReturnType<SessionService['loadSession']>>;
};

@Injectable()
export class SessionGuard implements CanActivate {
  constructor(
    private readonly config: ConfigService,
    private readonly sessions: SessionService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<RequestWithSession>();
    const cookieName =
      this.config.get<string>('SESSION_COOKIE_NAME') ?? 'auth_session';
    const sessionId = req.cookies?.[cookieName];

    if (!sessionId) {
      throw new UnauthorizedException('Missing session cookie');
    }

    const session = await this.sessions.loadSession(sessionId);
    if (!session) {
      throw new UnauthorizedException('Invalid session');
    }

    req.session = session;
    return true;
  }
}
