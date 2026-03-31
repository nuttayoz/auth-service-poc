import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiFoundResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiSecurity,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { AdminSignupService } from './admin-signup.service.js';
import { AuthService } from './auth.service.js';
import { Session } from './session.decorator.js';
import { SessionGuard } from './session.guard.js';
import type { SessionContext } from './session.service.js';
import {
  AdminSignupJobResponseDto,
  AdminSignupRequestDto,
  CallbackSessionResponseDto,
  SessionResponseDto,
  SwitchActiveOrgRequestDto,
} from './swagger.dto.js';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly adminSignup: AdminSignupService,
  ) {}

  @Get('login')
  @ApiOperation({
    summary: 'Start OIDC login',
    description:
      'Creates an OIDC authorization request and redirects the browser to ZITADEL.',
  })
  @ApiQuery({
    name: 'redirect',
    required: false,
    description:
      'Optional post-login redirect URI. If omitted, callback returns JSON.',
  })
  @ApiQuery({
    name: 'orgId',
    required: false,
    description:
      'Requested org id. Cross-org access is allowed only when ZITADEL-backed authorization proves access.',
  })
  @ApiQuery({
    name: 'orgDomain',
    required: false,
    description:
      'Requested org primary domain. Do not send this together with orgId.',
  })
  @ApiFoundResponse({
    description: 'Redirects the browser to the ZITADEL hosted login page.',
  })
  async login(
    @Res() res: Response,
    @Query('redirect') redirect?: string,
    @Query('orgId') orgId?: string,
    @Query('orgDomain') orgDomain?: string,
  ): Promise<void> {
    await this.auth.login(res, redirect, { orgId, orgDomain });
  }

  @Post('signup/admin')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Enqueue tenant admin signup',
    description:
      'Creates an async provisioning job that creates the org, project grant, and first root admin.',
  })
  @ApiAcceptedResponse({ type: AdminSignupJobResponseDto })
  async createAdminSignupJob(@Body() body: AdminSignupRequestDto) {
    return this.adminSignup.createAdminSignupJob(body);
  }

  @Get('signup/admin/jobs/:jobId')
  @ApiOperation({ summary: 'Get admin signup job status' })
  @ApiOkResponse({ type: AdminSignupJobResponseDto })
  async getAdminSignupJob(@Param('jobId') jobId: string) {
    return this.adminSignup.getAdminSignupJob(jobId);
  }

  @Get('callback')
  @ApiOperation({
    summary: 'OIDC callback',
    description:
      'Consumes the ZITADEL authorization response, creates a local session, and either redirects or returns session JSON.',
  })
  @ApiFoundResponse({
    description:
      'Redirects to the requested post-login URI when one was stored.',
  })
  @ApiOkResponse({
    type: CallbackSessionResponseDto,
    description:
      'Returns session context when no redirect URI was stored in the OIDC request.',
  })
  @ApiUnauthorizedResponse({
    description: 'Returned when the OIDC callback state is invalid or expired.',
  })
  async callback(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.auth.callback(req, res);
  }

  @Post('logout')
  @ApiOperation({ summary: 'Log out the current session' })
  @ApiSecurity('session-cookie')
  @ApiNoContentResponse({
    description:
      'Deletes the local session and clears the auth_session cookie.',
  })
  async logout(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.auth.logout(req, res);
  }

  @Get('me')
  @UseGuards(SessionGuard)
  @ApiOperation({ summary: 'Get current session context' })
  @ApiSecurity('session-cookie')
  @ApiOkResponse({ type: SessionResponseDto })
  @ApiUnauthorizedResponse({
    description: 'Returned when the session cookie is missing or invalid.',
  })
  me(@Session() session: unknown) {
    return session;
  }

  @Post('session/active-org')
  @UseGuards(SessionGuard)
  @ApiOperation({
    summary: 'Switch the active org for the current session',
    description:
      'Revalidates target-org authorization against ZITADEL before updating the session activeOrgId.',
  })
  @ApiSecurity('session-cookie')
  @ApiOkResponse({ type: SessionResponseDto })
  @ApiUnauthorizedResponse({
    description: 'Returned when the session cookie is missing or invalid.',
  })
  switchActiveOrg(
    @Session() session: SessionContext,
    @Body() body: SwitchActiveOrgRequestDto,
  ) {
    return this.auth.switchActiveOrg(session, body.orgId);
  }
}
