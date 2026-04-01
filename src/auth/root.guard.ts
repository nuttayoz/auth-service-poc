import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UserOrgAccessSource, UserRole } from '@prisma/client';
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

    const activeOrgId = currentSession.activeOrgId ?? currentSession.orgId;
    if (!activeOrgId) {
      throw new ForbiddenException('Active org is required');
    }

    const hasDirectRootAccess =
      currentSession.accessSource === UserOrgAccessSource.DIRECT &&
      currentSession.roles?.includes(UserRole.ROOT);

    if (!hasDirectRootAccess) {
      throw new ForbiddenException(
        'Direct root access is required for the active org',
      );
    }

    return true;
  }
}
