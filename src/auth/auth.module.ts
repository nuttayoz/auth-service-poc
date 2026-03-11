import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { OidcClientService } from './oidc-client.service';

@Module({
  controllers: [AuthController],
  providers: [AuthService, OidcClientService],
})
export class AuthModule {}
