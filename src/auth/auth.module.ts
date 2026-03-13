import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { GatewayController } from './gateway.controller.js';
import { AuthService } from './auth.service.js';
import { OidcClientService } from './oidc-client.service.js';
import { SessionGuard } from './session.guard.js';
import { SessionService } from './session.service.js';
import { ZitadelService } from '../zitadel/zitadel.service.js';

@Module({
  controllers: [AuthController, GatewayController],
  providers: [
    AuthService,
    OidcClientService,
    SessionService,
    SessionGuard,
    ZitadelService,
  ],
})
export class AuthModule {}
