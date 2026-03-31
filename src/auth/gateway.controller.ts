import {
  All,
  BadGatewayException,
  Controller,
  InternalServerErrorException,
  Logger,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiExcludeController } from '@nestjs/swagger';
import type { Request, Response as ExpressResponse } from 'express';
import { CryptoService } from '../crypto/crypto.service.js';
import { Session } from './session.decorator.js';
import { SessionGuard } from './session.guard.js';
import type { SessionContext } from './session.service.js';

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const STRIP_REQUEST_HEADERS = new Set([
  'host',
  'content-length',
  'accept-encoding',
  'cookie',
  'authorization',
  'x-user-id',
  'x-org-id',
  'x-roles',
  'x-permissions',
  'x-signed-headers',
  'x-signature',
  'x-signature-key-id',
  'x-signature-at',
]);

const STRIP_RESPONSE_HEADERS = new Set([
  ...HOP_BY_HOP_HEADERS,
  'content-length',
  'content-encoding',
  'set-cookie',
]);

const SIGNED_HEADER_KEYS = [
  'x-user-id',
  'x-org-id',
  'x-roles',
  'x-permissions',
  'x-signature-at',
  'x-signed-headers',
];

@Controller('gateway')
@ApiExcludeController()
export class GatewayController {
  private readonly logger = new Logger(GatewayController.name);

  constructor(
    private readonly config: ConfigService,
    private readonly crypto: CryptoService,
  ) {}

  @UseGuards(SessionGuard)
  @All('*path')
  async proxy(
    @Req() req: Request,
    @Res() res: ExpressResponse,
    @Session() session: SessionContext,
  ): Promise<void> {
    const baseUrl = this.config.get<string>('INTERNAL_API_BASE_URL');
    if (!baseUrl) {
      throw new InternalServerErrorException(
        'INTERNAL_API_BASE_URL is not configured',
      );
    }

    const target = this.buildTargetUrl(baseUrl, req.url.slice(8));
    const { headers, body } = this.buildRequestOptions(req, session);

    let upstream: Awaited<ReturnType<typeof fetch>>;
    try {
      upstream = await fetch(target, {
        method: req.method,
        headers,
        body,
        redirect: 'manual',
      });
    } catch (error) {
      this.logger.error(
        {
          event: 'gateway.upstream_failed',
          method: req.method,
          target,
          message: error instanceof Error ? error.message : 'unknown error',
        },
        error instanceof Error ? error.stack : undefined,
      );
      throw new BadGatewayException('Upstream request failed');
    }

    res.status(upstream.status);
    upstream.headers.forEach((value, key) => {
      if (STRIP_RESPONSE_HEADERS.has(key.toLowerCase())) {
        return;
      }
      res.setHeader(key, value);
    });

    if (upstream.status === 204 || upstream.status === 304) {
      res.end();
      return;
    }

    const buffer = Buffer.from(await upstream.arrayBuffer());
    res.send(buffer);
  }

  private buildTargetUrl(baseUrl: string, pathWithQuery: string): string {
    const trimmed = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
    const path = pathWithQuery.startsWith('/')
      ? pathWithQuery
      : `/${pathWithQuery}`;
    return `${trimmed}${path}`;
  }

  private buildRequestOptions(
    req: Request,
    session: SessionContext,
  ): {
    headers: Record<string, string>;
    body?: BodyInit;
  } {
    const headers: Record<string, string> = {};

    for (const [key, value] of Object.entries(req.headers)) {
      const lower = key.toLowerCase();
      if (HOP_BY_HOP_HEADERS.has(lower) || STRIP_REQUEST_HEADERS.has(lower)) {
        continue;
      }
      if (Array.isArray(value)) {
        headers[lower] = value.join(',');
      } else if (typeof value === 'string') {
        headers[lower] = value;
      }
    }

    if (req.ip) {
      headers['x-forwarded-for'] = req.ip;
    }
    if (req.protocol) {
      headers['x-forwarded-proto'] = req.protocol;
    }
    const host = req.get('host');
    if (host) {
      headers['x-forwarded-host'] = host;
    }

    const signedHeaders: Record<string, string> = {
      'x-user-id': session.userId,
      'x-org-id': session.activeOrgId ?? session.orgId ?? '',
      'x-roles': session.roles.join(','),
      'x-permissions': session.permissions.join(','),
      'x-signature-at': new Date().toISOString(),
      'x-signed-headers': SIGNED_HEADER_KEYS.join(','),
    };

    const signature = this.crypto.signHeaders(signedHeaders);

    Object.assign(headers, signedHeaders, {
      'x-signature': signature.signature,
      'x-signature-key-id': signature.keyId,
    });

    let body: BodyInit | undefined;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      if (req.body === undefined || req.body === null) {
        body = undefined;
      } else if (Buffer.isBuffer(req.body)) {
        body = req.body as unknown as BodyInit;
      } else if (typeof req.body === 'string') {
        body = req.body;
      } else {
        body = JSON.stringify(req.body);
        if (!headers['content-type']) {
          headers['content-type'] = 'application/json';
        }
      }
    }

    return { headers, body };
  }
}
