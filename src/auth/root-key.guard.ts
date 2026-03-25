import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { RootKeyService, type RootKeySummary } from './root-key.service.js';

export const ROOT_KEY_HEADER = 'x-root-key';

export type RequestWithRootKey = Request & {
  rootKey?: RootKeySummary;
};

@Injectable()
export class RootKeyGuard implements CanActivate {
  constructor(private readonly rootKeys: RootKeyService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<RequestWithRootKey>();
    const header = req.headers[ROOT_KEY_HEADER];

    const rawKey = Array.isArray(header) ? header[0] : header;
    if (typeof rawKey !== 'string') {
      throw new UnauthorizedException('Missing root key');
    }

    req.rootKey = await this.rootKeys.validateRootKey(
      rawKey,
      this.extractRequestedOrgId(req),
    );
    return true;
  }

  private extractRequestedOrgId(req: RequestWithRootKey): string | undefined {
    const bodyOrgId =
      req.body &&
      typeof req.body === 'object' &&
      !Array.isArray(req.body) &&
      typeof (req.body as Record<string, unknown>).orgId === 'string'
        ? ((req.body as Record<string, unknown>).orgId as string).trim()
        : '';
    if (bodyOrgId) {
      return bodyOrgId;
    }

    const queryOrgId =
      typeof req.query?.orgId === 'string' ? req.query.orgId.trim() : '';
    if (queryOrgId) {
      return queryOrgId;
    }

    const paramOrgId =
      typeof req.params?.orgId === 'string' ? req.params.orgId.trim() : '';
    if (paramOrgId) {
      return paramOrgId;
    }

    return undefined;
  }
}
