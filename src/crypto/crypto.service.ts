import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
} from 'crypto';

export type EncryptedPayload = {
  keyId: string;
  nonce: string;
  ciphertext: string;
  tag: string;
};

export type HeaderSignature = {
  keyId: string;
  signature: string;
};

@Injectable()
export class CryptoService {
  private readonly cryptoEnabled: boolean;
  private readonly sessionKey: Buffer | null;
  private readonly sessionKeyId: string;
  private readonly headerKey: Buffer | null;
  private readonly headerKeyId: string;

  constructor(private readonly config: ConfigService) {
    this.cryptoEnabled = this.config.get<boolean>('CRYPTO_ENABLED') ?? false;
    this.sessionKeyId = this.config.get<string>('SESSION_ENC_KEY_ID') ?? 'v1';
    this.headerKeyId = this.config.get<string>('HEADER_SIGNING_KEY_ID') ?? 'v1';

    const sessionKeyRaw = this.config.get<string>('SESSION_ENC_KEY') ?? '';
    const headerKeyRaw = this.config.get<string>('HEADER_SIGNING_KEY') ?? '';

    this.sessionKey = sessionKeyRaw
      ? Buffer.from(sessionKeyRaw, 'base64')
      : null;
    this.headerKey = headerKeyRaw ? Buffer.from(headerKeyRaw, 'base64') : null;
  }

  isEnabled(): boolean {
    return this.cryptoEnabled;
  }

  encrypt(plaintext: Buffer | string): EncryptedPayload {
    this.assertCryptoEnabled();
    const key = this.requireSessionKey();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);

    const input = Buffer.isBuffer(plaintext)
      ? plaintext
      : Buffer.from(plaintext, 'utf8');
    const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      keyId: this.sessionKeyId,
      nonce: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
    };
  }

  decrypt(payload: EncryptedPayload): Buffer {
    this.assertCryptoEnabled();
    const key = this.requireSessionKey();

    const iv = Buffer.from(payload.nonce, 'base64');
    const ciphertext = Buffer.from(payload.ciphertext, 'base64');
    const tag = Buffer.from(payload.tag, 'base64');

    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  signHeaders(headers: Record<string, string>): HeaderSignature {
    this.assertCryptoEnabled();
    const key = this.requireHeaderKey();
    const canonical = this.canonicalizeHeaders(headers);
    const signature = createHmac('sha256', key)
      .update(canonical)
      .digest('base64');

    return { keyId: this.headerKeyId, signature };
  }

  verifyHeaders(
    headers: Record<string, string>,
    signature: HeaderSignature,
  ): boolean {
    this.assertCryptoEnabled();
    const key = this.requireHeaderKey();
    const canonical = this.canonicalizeHeaders(headers);
    const expected = createHmac('sha256', key)
      .update(canonical)
      .digest('base64');

    return timingSafeEqualBase64(expected, signature.signature);
  }

  private canonicalizeHeaders(headers: Record<string, string>): string {
    return Object.keys(headers)
      .map((key) => key.toLowerCase())
      .sort()
      .map((key) => `${key}:${headers[key] ?? ''}`)
      .join('\n');
  }

  private requireSessionKey(): Buffer {
    if (!this.sessionKey || this.sessionKey.length !== 32) {
      throw new Error('SESSION_ENC_KEY is not configured or invalid');
    }
    return this.sessionKey;
  }

  private requireHeaderKey(): Buffer {
    if (!this.headerKey || this.headerKey.length !== 32) {
      throw new Error('HEADER_SIGNING_KEY is not configured or invalid');
    }
    return this.headerKey;
  }

  private assertCryptoEnabled(): void {
    if (!this.cryptoEnabled) {
      throw new Error('CRYPTO_ENABLED is false');
    }
  }
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
