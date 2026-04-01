import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as oidc from 'openid-client';

type OidcModule = typeof oidc;
type OidcConfig = oidc.Configuration;

@Injectable()
export class OidcClientService {
  private configPromise: Promise<OidcConfig> | null = null;
  private readonly moduleRef: OidcModule = oidc;

  constructor(private readonly config: ConfigService) {}

  getModule(): OidcModule {
    return this.moduleRef;
  }

  async getConfig(): Promise<OidcConfig> {
    if (!this.configPromise) {
      this.configPromise = this.buildConfig();
    }
    return this.configPromise;
  }

  private async buildConfig(): Promise<OidcConfig> {
    const issuerUrl = this.config.get<string>('ZITADEL_ISSUER');
    const clientId = this.config.get<string>('ZITADEL_CLIENT_ID');
    const clientSecret =
      this.config.get<string>('ZITADEL_CLIENT_SECRET') || undefined;
    const allowInsecure =
      this.config.get<boolean>('OIDC_ALLOW_INSECURE_HTTP') ?? false;

    if (!issuerUrl || !clientId) {
      throw new ServiceUnavailableException('OIDC is not configured');
    }

    const oidc = this.getModule();
    const issuer = new URL(issuerUrl);
    const clientAuth = clientSecret
      ? oidc.ClientSecretBasic(clientSecret)
      : oidc.None();

    const options = allowInsecure
      ? { execute: [oidc.allowInsecureRequests] }
      : undefined;

    const config = await oidc.discovery(
      issuer,
      clientId,
      clientSecret || undefined,
      clientAuth,
      options,
    );

    return config;
  }
}
