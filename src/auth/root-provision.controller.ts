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
import { RootKeyGuard, type RequestWithRootKey } from './root-key.guard.js';
import {
  CreateUserRequestDto,
  ProvisioningJobResponseDto,
} from './swagger.dto.js';

@Controller('auth/root')
@UseGuards(RootKeyGuard)
@ApiTags('Root Provisioning')
@ApiSecurity('root-key')
@ApiUnauthorizedResponse({
  description: 'Returned when x-root-key is missing or invalid.',
})
@ApiForbiddenResponse({
  description: 'Returned when the root key does not match the requested org.',
})
export class RootProvisionController {
  constructor(private readonly admin: AdminService) {}

  @Post('users')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Enqueue user provisioning using a root key' })
  @ApiAcceptedResponse({ type: ProvisioningJobResponseDto })
  async createUser(
    @Req() req: RequestWithRootKey,
    @Body() body: CreateUserRequestDto,
  ) {
    return this.admin.createUserWithRootKey(req.rootKey!, body);
  }

  @Get('jobs/:jobId')
  @ApiOperation({ summary: 'Get provisioning job status using a root key' })
  @ApiOkResponse({ type: ProvisioningJobResponseDto })
  async getProvisioningJob(
    @Req() req: RequestWithRootKey,
    @Param('jobId') jobId: string,
  ) {
    return this.admin.getProvisioningJobForRootKey(req.rootKey!, jobId);
  }
}
