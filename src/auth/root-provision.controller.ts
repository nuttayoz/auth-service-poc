import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { RootCreateUserPayload } from './admin.service.js';
import { AdminService } from './admin.service.js';
import { RootKeyGuard, type RequestWithRootKey } from './root-key.guard.js';

@Controller('auth/root')
@UseGuards(RootKeyGuard)
export class RootProvisionController {
  constructor(private readonly admin: AdminService) {}

  @Post('users')
  @HttpCode(HttpStatus.ACCEPTED)
  async createUser(
    @Req() req: RequestWithRootKey,
    @Body() body: RootCreateUserPayload,
  ) {
    return this.admin.createUserWithRootKey(req.rootKey!, body);
  }

  @Get('jobs/:jobId')
  async getProvisioningJob(
    @Req() req: RequestWithRootKey,
    @Param('jobId') jobId: string,
  ) {
    return this.admin.getProvisioningJobForRootKey(req.rootKey!, jobId);
  }
}
