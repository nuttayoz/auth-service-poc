import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service.js';
import { Session } from './session.decorator.js';
import { SessionGuard } from './session.guard.js';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Get('login')
  async login(
    @Res() res: Response,
    @Query('redirect') redirect?: string,
  ): Promise<void> {
    await this.auth.login(res, redirect);
  }

  @Post('signup/admin')
  async adminSignup(
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
    return this.auth.adminSignup(body);
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
