import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UserRole } from '@prisma/client';
import { AuthService } from './auth.service.js';
import { RequestWithSession } from './session.guard.js';

@Injectable()
export class RootGuard implements CanActivate {
  constructor(private readonly auth: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<RequestWithSession>();
    const session = req.session;

    if (!session) {
      throw new UnauthorizedException('Missing session');
    }

    const currentSession = await this.auth.revalidateSession(session.id);
    req.session = currentSession;

    if (!currentSession.roles?.includes(UserRole.ROOT)) {
      throw new ForbiddenException('Root access required');
    }

    return true;
  }
}
