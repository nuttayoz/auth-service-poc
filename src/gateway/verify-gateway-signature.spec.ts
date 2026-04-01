import { createHmac } from 'crypto';
import { verifyGatewayHeaders } from './verify-gateway-signature.js';

const signingKey = Buffer.alloc(32, 7).toString('base64');

function signHeaders(headers: Record<string, string>): string {
  const canonical = Object.keys(headers)
    .map((key) => key.toLowerCase())
    .sort()
    .map((key) => `${key}:${headers[key] ?? ''}`)
    .join('\n');

  return createHmac('sha256', Buffer.from(signingKey, 'base64'))
    .update(canonical)
    .digest('base64');
}

describe('verifyGatewayHeaders', () => {
  it('accepts valid signed headers and returns parsed context', () => {
    const payload = {
      'x-user-id': 'user-1',
      'x-org-id': 'org-1',
      'x-roles': 'ROOT,USER',
      'x-permissions': 'users:write',
      'x-signature-at': new Date().toISOString(),
    };

    const result = verifyGatewayHeaders(
      {
        ...payload,
        'x-signed-headers':
          'x-user-id,x-org-id,x-roles,x-permissions,x-signature-at',
        'x-signature': signHeaders(payload),
      },
      signingKey,
      { maxSkewSec: 60 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.context.userId).toBe('user-1');
    expect(result.context.orgId).toBe('org-1');
    expect(result.context.roles).toEqual(['ROOT', 'USER']);
    expect(result.context.permissions).toEqual(['users:write']);
  });

  it('rejects a tampered signature payload', () => {
    const payload = {
      'x-user-id': 'user-1',
      'x-org-id': 'org-1',
    };

    const result = verifyGatewayHeaders(
      {
        'x-user-id': 'user-1',
        'x-org-id': 'org-2',
        'x-signed-headers': 'x-user-id,x-org-id',
        'x-signature': signHeaders(payload),
      },
      signingKey,
    );

    expect(result).toEqual({ ok: false, reason: 'Invalid signature' });
  });

  it('rejects when a signed header is missing', () => {
    const result = verifyGatewayHeaders(
      {
        'x-user-id': 'user-1',
        'x-signed-headers': 'x-user-id,x-org-id',
        'x-signature': signHeaders({
          'x-user-id': 'user-1',
          'x-org-id': 'org-1',
        }),
      },
      signingKey,
    );

    expect(result).toEqual({
      ok: false,
      reason: 'Missing signed header: x-org-id',
    });
  });

  it('rejects stale signatures when max skew is exceeded', () => {
    const payload = {
      'x-user-id': 'user-1',
      'x-signature-at': new Date(Date.now() - 120_000).toISOString(),
    };

    const result = verifyGatewayHeaders(
      {
        ...payload,
        'x-signed-headers': 'x-user-id,x-signature-at',
        'x-signature': signHeaders(payload),
      },
      signingKey,
      { maxSkewSec: 30 },
    );

    expect(result).toEqual({
      ok: false,
      reason: 'Signature timestamp out of range',
    });
  });
});
