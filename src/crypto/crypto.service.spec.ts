import { ConfigService } from '@nestjs/config';
import { CryptoService } from './crypto.service.js';

function createConfig(overrides: Record<string, unknown> = {}) {
  return new ConfigService({
    CRYPTO_ENABLED: true,
    SESSION_ENC_KEY_ID: 'session-v1',
    HEADER_SIGNING_KEY_ID: 'header-v1',
    SESSION_ENC_KEY: Buffer.alloc(32, 1).toString('base64'),
    HEADER_SIGNING_KEY: Buffer.alloc(32, 2).toString('base64'),
    ...overrides,
  });
}

describe('CryptoService', () => {
  it('encrypts and decrypts a plaintext round-trip', () => {
    const service = new CryptoService(createConfig());

    const encrypted = service.encrypt('hello world');
    const decrypted = service.decrypt(encrypted).toString('utf8');

    expect(encrypted.keyId).toBe('session-v1');
    expect(decrypted).toBe('hello world');
  });

  it('rejects tampered ciphertext', () => {
    const service = new CryptoService(createConfig());
    const encrypted = service.encrypt('hello world');
    const tampered = {
      ...encrypted,
      tag: Buffer.alloc(16, 9).toString('base64'),
    };

    expect(() => service.decrypt(tampered)).toThrow();
  });

  it('signs and verifies canonicalized headers', () => {
    const service = new CryptoService(createConfig());
    const headers = {
      'X-User-Id': 'user-1',
      'x-org-id': 'org-1',
      'X-Roles': 'USER',
    };

    const signature = service.signHeaders(headers);

    expect(signature.keyId).toBe('header-v1');
    expect(
      service.verifyHeaders(
        {
          'x-roles': 'USER',
          'x-user-id': 'user-1',
          'x-org-id': 'org-1',
        },
        signature,
      ),
    ).toBe(true);
  });

  it('fails verification when a signed header is changed', () => {
    const service = new CryptoService(createConfig());
    const signature = service.signHeaders({
      'x-user-id': 'user-1',
      'x-org-id': 'org-1',
    });

    expect(
      service.verifyHeaders(
        {
          'x-user-id': 'user-1',
          'x-org-id': 'org-2',
        },
        signature,
      ),
    ).toBe(false);
  });

  it('throws when crypto is disabled', () => {
    const service = new CryptoService(
      createConfig({
        CRYPTO_ENABLED: false,
      }),
    );

    expect(() => service.encrypt('hello world')).toThrow(
      'CRYPTO_ENABLED is false',
    );
  });
});
