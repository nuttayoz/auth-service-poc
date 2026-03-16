import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { AdminController } from './admin.controller.js';
import { AdminService } from './admin.service.js';
import { GatewayController } from './gateway.controller.js';
import { AuthService } from './auth.service.js';
import { OidcClientService } from './oidc-client.service.js';
import { RootGuard } from './root.guard.js';
import { SessionGuard } from './session.guard.js';
import { SessionService } from './session.service.js';
import { ZitadelService } from '../zitadel/zitadel.service.js';

@Module({
  controllers: [AuthController, AdminController, GatewayController],
  providers: [
    AdminService,
    AuthService,
    OidcClientService,
    RootGuard,
    SessionService,
    SessionGuard,
    ZitadelService,
  ],
})
export class AuthModule {}
