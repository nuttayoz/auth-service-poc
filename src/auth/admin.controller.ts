import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AdminService } from './admin.service.js';
import { Session } from './session.decorator.js';
import { RootGuard } from './root.guard.js';
import { SessionGuard } from './session.guard.js';
import type {
  CreateUserPayload,
  GrantExternalAccessPayload,
} from './admin.service.js';
import type { SessionContext } from './session.service.js';

@Controller('auth/admin')
@UseGuards(SessionGuard, RootGuard)
export class AdminController {
  constructor(private readonly admin: AdminService) {}

  @Post('users')
  @HttpCode(HttpStatus.ACCEPTED)
  async createUser(
    @Session() session: SessionContext,
    @Body() body: CreateUserPayload,
  ) {
    return this.admin.createUser(session, body);
  }

  @Get('jobs/:jobId')
  async getProvisioningJob(
    @Session() session: SessionContext,
    @Param('jobId') jobId: string,
  ) {
    return this.admin.getProvisioningJob(session, jobId);
  }

  @Get('external-access')
  async listExternalAccesses(@Session() session: SessionContext) {
    return this.admin.listExternalAccesses(session);
  }

  @Post('external-access')
  async grantExternalAccess(
    @Session() session: SessionContext,
    @Body() body: GrantExternalAccessPayload,
  ) {
    return this.admin.grantExternalAccess(session, body);
  }

  @Post('external-access/revoke')
  async revokeExternalAccess(
    @Session() session: SessionContext,
    @Body() body: GrantExternalAccessPayload,
  ) {
    return this.admin.revokeExternalAccess(session, body);
  }
}
