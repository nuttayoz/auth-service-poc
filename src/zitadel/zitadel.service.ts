import {
  BadRequestException,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export type SetupOrganizationParams = {
  orgName: string;
  orgDomain?: string;
  admin: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    userName: string;
  };
};

export type SetupOrganizationResult = {
  orgId: string;
  userId: string;
};

@Injectable()
export class ZitadelService {
  private readonly logger = new Logger(ZitadelService.name);

  constructor(private readonly config: ConfigService) {}

  async setupOrganization(
    params: SetupOrganizationParams,
  ): Promise<SetupOrganizationResult> {
    this.logger.log(
      `ZITADEL org setup start: org="${params.orgName}" email="${params.admin.email}"`,
    );

    const orgId = await this.createOrganization(params.orgName);
    if (params.orgDomain) {
      await this.addOrganizationDomain(orgId, params.orgDomain);
    }

    const userId = await this.createHumanUser(orgId, params.admin);

    this.logger.log(`ZITADEL org created: orgId="${orgId}" userId="${userId}"`);

    const projectId =
      this.config.get<string>('ZITADEL_MASTER_PROJECT_ID') ?? '';
    const grantRoleKeys = this.getProjectRoleKeys();
    const adminRoleKey = this.getAdminRoleKey();

    if (projectId) {
      await this.createProjectGrant(projectId, orgId, grantRoleKeys);
      if (adminRoleKey) {
        await this.createAuthorization(userId, projectId, orgId, [
          adminRoleKey,
        ]);
      }

      this.logger.log(
        `ZITADEL project grant complete: projectId="${projectId}" orgId="${orgId}"`,
      );
    }

    return { orgId, userId };
  }

  private async createOrganization(name: string): Promise<string> {
    const response = await this.requestJson<{
      organizationId?: string;
    }>('/v2/organizations', { name });

    if (!response?.organizationId) {
      throw new BadRequestException('Missing organization id');
    }

    return response.organizationId;
  }

  private async addOrganizationDomain(
    orgId: string,
    domain: string,
  ): Promise<void> {
    await this.requestJson(`/v2/organizations/${orgId}/domains`, { domain });
  }

  private async createHumanUser(
    orgId: string,
    admin: SetupOrganizationParams['admin'],
  ): Promise<string> {
    const response = await this.requestJson<{ id?: string }>('/v2/users/new', {
      organizationId: orgId,
      username: admin.userName,
      human: {
        profile: {
          givenName: admin.firstName,
          familyName: admin.lastName,
          displayName: `${admin.firstName} ${admin.lastName}`.trim(),
        },
        email: {
          email: admin.email,
          isVerified: false,
        },
        password: {
          password: admin.password,
          changeRequired: false,
        },
      },
    });

    if (!response?.id) {
      throw new BadRequestException('Missing user id');
    }

    return response.id;
  }

  private async createProjectGrant(
    projectId: string,
    orgId: string,
    roleKeys: string[],
  ): Promise<void> {
    await this.requestJson(
      '/zitadel.project.v2.ProjectService/CreateProjectGrant',
      {
        projectId,
        grantedOrganizationId: orgId,
        ...(roleKeys.length > 0 ? { roleKeys } : {}),
      },
      { connect: true },
    );
  }

  private async createAuthorization(
    userId: string,
    projectId: string,
    organizationId: string,
    roleKeys: string[],
  ): Promise<void> {
    await this.requestJson(
      '/zitadel.authorization.v2.AuthorizationService/CreateAuthorization',
      {
        userId,
        projectId,
        organizationId,
        ...(roleKeys.length > 0 ? { roleKeys } : {}),
      },
      { connect: true },
    );
  }

  private getProjectRoleKeys(): string[] {
    const raw =
      this.config.get<string>('ZITADEL_PROJECT_GRANT_ROLE_KEYS') ?? '';
    return raw
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
  }

  private getAdminRoleKey(): string | null {
    const key = this.config.get<string>('ZITADEL_ADMIN_ROLE_KEY') ?? 'admin';
    return key ? key : null;
  }

  private getApiBaseUrl(): string {
    const base = this.config.get<string>('ZITADEL_API_BASE_URL');
    if (base) {
      return base.replace(/\/$/, '');
    }
    const issuer = this.config.get<string>('ZITADEL_ISSUER');
    if (!issuer) {
      throw new ServiceUnavailableException('ZITADEL_ISSUER is not configured');
    }
    return new URL(issuer).origin;
  }

  private getApiToken(): string {
    const token = this.config.get<string>('ZITADEL_API_TOKEN');
    if (!token) {
      throw new ServiceUnavailableException('ZITADEL_API_TOKEN is not set');
    }
    return token;
  }

  private async requestJson<T>(
    path: string,
    body?: Record<string, unknown>,
    options: { connect?: boolean } = {},
  ): Promise<T> {
    const base = this.getApiBaseUrl();
    const url = `${base}${path}`;
    const token = this.getApiToken();

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(options.connect ? { 'Connect-Protocol-Version': '1' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new BadRequestException(
        `ZITADEL API error (${response.status}): ${text}`,
      );
    }

    if (response.status === 204) {
      return {} as T;
    }

    return (await response.json()) as T;
  }
}
