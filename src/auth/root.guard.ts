import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UserRole } from '@prisma/client';
import { RequestWithSession } from './session.guard.js';

@Injectable()
export class RootGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<RequestWithSession>();
    const session = req.session;

    if (!session) {
      throw new UnauthorizedException('Missing session');
    }

    if (!session.roles?.includes(UserRole.ROOT)) {
      throw new ForbiddenException('Root access required');
    }

    return true;
  }
}
