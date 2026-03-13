import { createHmac } from 'crypto';

type HeaderMap = Record<string, string | string[] | undefined>;

type VerifyGatewayOptions = {
  maxSkewSec?: number;
};

type VerifyGatewayContext = {
  userId: string;
  orgId: string | null;
  roles: string[];
  permissions: string[];
  signatureAt: Date | null;
  signedHeaders: string[];
};

type VerifyGatewayResult =
  | { ok: true; context: VerifyGatewayContext }
  | { ok: false; reason: string };

export function verifyGatewayHeaders(
  headers: HeaderMap,
  signingKeyBase64: string,
  options: VerifyGatewayOptions = {},
): VerifyGatewayResult {
  const key = Buffer.from(signingKeyBase64, 'base64');
  if (key.length !== 32) {
    return { ok: false, reason: 'Invalid signing key' };
  }

  const normalized = normalizeHeaders(headers);

  const signedHeadersValue = normalized['x-signed-headers'];
  if (!signedHeadersValue) {
    return { ok: false, reason: 'Missing x-signed-headers' };
  }

  const signedHeaders = signedHeadersValue
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  if (signedHeaders.length === 0) {
    return { ok: false, reason: 'Empty x-signed-headers' };
  }

  const signature = normalized['x-signature'];
  if (!signature) {
    return { ok: false, reason: 'Missing x-signature' };
  }

  const payload: Record<string, string> = {};
  for (const keyName of signedHeaders) {
    const value = normalized[keyName];
    if (value === undefined) {
      return { ok: false, reason: `Missing signed header: ${keyName}` };
    }
    payload[keyName] = value;
  }

  const canonical = canonicalizeHeaders(payload);
  const expected = createHmac('sha256', key).update(canonical).digest('base64');

  if (!timingSafeEqualBase64(expected, signature)) {
    return { ok: false, reason: 'Invalid signature' };
  }

  const signatureAtRaw = payload['x-signature-at'];
  const signatureAt = signatureAtRaw ? new Date(signatureAtRaw) : null;
  if (
    options.maxSkewSec !== undefined &&
    options.maxSkewSec > 0 &&
    signatureAt &&
    !Number.isNaN(signatureAt.getTime())
  ) {
    const skewMs = Math.abs(Date.now() - signatureAt.getTime());
    if (skewMs > options.maxSkewSec * 1000) {
      return { ok: false, reason: 'Signature timestamp out of range' };
    }
  }

  const roles = splitCsv(payload['x-roles']);
  const permissions = splitCsv(payload['x-permissions']);

  return {
    ok: true,
    context: {
      userId: payload['x-user-id'] ?? '',
      orgId: payload['x-org-id'] || null,
      roles,
      permissions,
      signatureAt,
      signedHeaders,
    },
  };
}

function normalizeHeaders(headers: HeaderMap): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }
    const lower = key.toLowerCase();
    normalized[lower] = Array.isArray(value) ? value.join(',') : value;
  }
  return normalized;
}

function canonicalizeHeaders(headers: Record<string, string>): string {
  return Object.keys(headers)
    .map((key) => key.toLowerCase())
    .sort()
    .map((key) => `${key}:${headers[key] ?? ''}`)
    .join('\n');
}

function splitCsv(value?: string): string[] {
  if (!value) {
    return [];
  }
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function timingSafeEqualBase64(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, 'base64');
  const bBuf = Buffer.from(b, 'base64');
  if (aBuf.length !== bBuf.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < aBuf.length; i += 1) {
    result |= aBuf[i] ^ bBuf[i];
  }
  return result === 0;
}

// use this in an internal service in order to verify header result
// import { verifyGatewayHeaders } from './verify-gateway-signature.js';

// const result = verifyGatewayHeaders(req.headers, process.env.HEADER_SIGNING_KEY ?? '', {
//   maxSkewSec: 300,
// });

// if (!result.ok) {
//   return res.status(401).json({ error: result.reason });
// }

// const { userId, orgId, roles, permissions } = result.context;
