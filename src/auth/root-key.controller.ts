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
import {
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { RootGuard } from './root.guard.js';
import { RootKeyService } from './root-key.service.js';
import { Session } from './session.decorator.js';
import { SessionGuard } from './session.guard.js';
import type { SessionContext } from './session.service.js';
import { RootKeyIssueResponseDto, RootKeySummaryDto } from './swagger.dto.js';

@Controller('auth/admin/root-keys')
@UseGuards(SessionGuard, RootGuard)
@ApiTags('Root Keys')
@ApiSecurity('session-cookie')
@ApiUnauthorizedResponse({
  description: 'Returned when the session cookie is missing or invalid.',
})
@ApiForbiddenResponse({
  description: 'Direct ROOT access is required for the active org.',
})
export class RootKeyController {
  constructor(private readonly rootKeys: RootKeyService) {}

  @Get()
  @ApiOperation({ summary: 'List root keys for the active org' })
  @ApiOkResponse({ type: RootKeySummaryDto, isArray: true })
  async listRootKeys(@Session() session: SessionContext) {
    return this.rootKeys.listRootKeys(this.requireActiveOrgId(session));
  }

  @Post()
  @ApiOperation({ summary: 'Create a new root key for the active org' })
  @ApiOkResponse({ type: RootKeyIssueResponseDto })
  async createRootKey(@Session() session: SessionContext) {
    return this.rootKeys.createRootKey(
      session.userId,
      this.requireActiveOrgId(session),
    );
  }

  @Post(':rootKeyId/rotate')
  @ApiOperation({ summary: 'Rotate an existing root key' })
  @ApiOkResponse({ type: RootKeyIssueResponseDto })
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
  @ApiOperation({ summary: 'Revoke an active root key' })
  @ApiOkResponse({ type: RootKeySummaryDto })
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
