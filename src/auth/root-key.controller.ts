import {
  Controller,
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
    return this.rootKeys.listRootKeys((session.activeOrgId ?? session.orgId)!);
  }

  @Post()
  async createRootKey(@Session() session: SessionContext) {
    return this.rootKeys.createRootKey(
      session.userId,
      (session.activeOrgId ?? session.orgId)!,
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
      (session.activeOrgId ?? session.orgId)!,
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
      (session.activeOrgId ?? session.orgId)!,
    );
  }
}
