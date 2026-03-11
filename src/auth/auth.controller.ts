import {
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { Session } from './session.decorator';
import { SessionGuard } from './session.guard';

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
