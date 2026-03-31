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
import {
  ApiAcceptedResponse,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { AdminService } from './admin.service.js';
import { Session } from './session.decorator.js';
import { RootGuard } from './root.guard.js';
import { SessionGuard } from './session.guard.js';
import type { SessionContext } from './session.service.js';
import {
  CreateUserRequestDto,
  ProvisioningJobResponseDto,
} from './swagger.dto.js';

@Controller('auth/admin')
@UseGuards(SessionGuard, RootGuard)
@ApiTags('Admin')
@ApiSecurity('session-cookie')
@ApiUnauthorizedResponse({
  description: 'Returned when the session cookie is missing or invalid.',
})
@ApiForbiddenResponse({
  description: 'Direct ROOT access is required for the active org.',
})
export class AdminController {
  constructor(private readonly admin: AdminService) {}

  @Post('users')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Enqueue user provisioning for the active org' })
  @ApiAcceptedResponse({ type: ProvisioningJobResponseDto })
  async createUser(
    @Session() session: SessionContext,
    @Body() body: CreateUserRequestDto,
  ) {
    return this.admin.createUser(session, body);
  }

  @Get('jobs/:jobId')
  @ApiOperation({ summary: 'Get provisioning job status for the active org' })
  @ApiOkResponse({ type: ProvisioningJobResponseDto })
  async getProvisioningJob(
    @Session() session: SessionContext,
    @Param('jobId') jobId: string,
  ) {
    return this.admin.getProvisioningJob(session, jobId);
  }
}
