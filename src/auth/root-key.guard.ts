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

    req.rootKey = await this.rootKeys.validateRootKey(rawKey);
    return true;
  }
}
