import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AdminService } from './admin.service.js';
import { Session } from './session.decorator.js';
import { RootGuard } from './root.guard.js';
import { SessionGuard } from './session.guard.js';
import type { CreateUserPayload } from './admin.service.js';
import type { SessionContext } from './session.service.js';

@Controller('auth/admin')
@UseGuards(SessionGuard, RootGuard)
export class AdminController {
  constructor(private readonly admin: AdminService) {}

  @Post('users')
  async createUser(
    @Session() session: SessionContext,
    @Body() body: CreateUserPayload,
  ) {
    return this.admin.createUser(session, body);
  }
}
