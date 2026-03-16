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
import type { Request, Response } from 'express';
import { AdminSignupService } from './admin-signup.service.js';
import { AuthService } from './auth.service.js';
import { Session } from './session.decorator.js';
import { SessionGuard } from './session.guard.js';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly adminSignup: AdminSignupService,
  ) {}

  @Get('login')
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
  async createAdminSignupJob(
    @Body()
    body: {
      orgName?: string;
      orgDomain?: string;
      email?: string;
      password?: string;
      firstName?: string;
      lastName?: string;
      userName?: string;
    },
  ) {
    return this.adminSignup.createAdminSignupJob(body);
  }

  @Get('signup/admin/jobs/:jobId')
  async getAdminSignupJob(@Param('jobId') jobId: string) {
    return this.adminSignup.getAdminSignupJob(jobId);
  }

  @Get('callback')
  async callback(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.auth.callback(req, res);
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.auth.logout(req, res);
  }

  @Get('me')
  @UseGuards(SessionGuard)
  me(@Session() session: unknown) {
    return session;
  }
}
