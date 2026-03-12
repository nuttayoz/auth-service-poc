import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { OidcClientService } from './oidc-client.service.js';
import { SessionGuard } from './session.guard.js';
import { SessionService } from './session.service.js';

@Module({
  controllers: [AuthController],
  providers: [AuthService, OidcClientService, SessionService, SessionGuard],
})
export class AuthModule {}
