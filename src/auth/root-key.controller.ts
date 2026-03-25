import {
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { RootGuard } from './root.guard.js';
import { RootKeyService } from './root-key.service.js';
import { Session } from './session.decorator.js';
import { SessionGuard } from './session.guard.js';
import type { SessionContext } from './session.service.js';

@Controller('auth/admin/root-keys')
@UseGuards(SessionGuard, RootGuard)
export class RootKeyController {
  constructor(private readonly rootKeys: RootKeyService) {}

  @Get()
  async listRootKeys(@Session() session: SessionContext) {
    return this.rootKeys.listRootKeys(this.requireActiveOrgId(session));
  }

  @Post()
  async createRootKey(@Session() session: SessionContext) {
    return this.rootKeys.createRootKey(
      session.userId,
      this.requireActiveOrgId(session),
    );
  }

  @Post(':rootKeyId/rotate')
  async rotateRootKey(
    @Session() session: SessionContext,
    @Param('rootKeyId') rootKeyId: string,
  ) {
    return this.rootKeys.rotateRootKey(
      rootKeyId,
      session.userId,
      this.requireActiveOrgId(session),
    );
  }

  @Post(':rootKeyId/revoke')
  @HttpCode(HttpStatus.OK)
  async revokeRootKey(
    @Session() session: SessionContext,
    @Param('rootKeyId') rootKeyId: string,
  ) {
    return this.rootKeys.revokeRootKey(
      rootKeyId,
      session.userId,
      this.requireActiveOrgId(session),
    );
  }

  private requireActiveOrgId(session: SessionContext): string {
    const activeOrgId = session.activeOrgId ?? session.orgId;
    if (!activeOrgId) {
      throw new ForbiddenException('Missing active org');
    }
    return activeOrgId;
  }
}
