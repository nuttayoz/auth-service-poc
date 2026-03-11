import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

type OidcModule = typeof import('openid-client');
type OidcConfig = import('openid-client').Configuration;

@Injectable()
export class OidcClientService {
  private modulePromise: Promise<OidcModule> | null = null;
  private configPromise: Promise<OidcConfig> | null = null;

  constructor(private readonly config: ConfigService) {}

  async getModule(): Promise<OidcModule> {
    if (!this.modulePromise) {
      this.modulePromise = import('openid-client');
    }
    return this.modulePromise;
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

    if (!issuerUrl || !clientId) {
      throw new ServiceUnavailableException('OIDC is not configured');
    }

    const oidc = await this.getModule();
    const issuer = new URL(issuerUrl);
    const clientAuth = clientSecret
      ? oidc.ClientSecretBasic(clientSecret)
      : oidc.None();

    const config = await oidc.discovery(
      issuer,
      clientId,
      clientSecret || undefined,
      clientAuth,
    );

    return config;
  }
}
