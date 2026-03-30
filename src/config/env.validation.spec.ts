import { envValidationSchema } from './env.validation.js';

function validEnv(overrides: Record<string, unknown> = {}) {
  return {
    DATABASE_URL: 'postgresql://postgres:postgres@localhost:5432/auth_service',
    REDIS_URL: 'redis://localhost:6380/0',
    OIDC_ENABLED: false,
    CRYPTO_ENABLED: false,
    SESSION_COOKIE_SECURE: false,
    SESSION_COOKIE_SAMESITE: 'lax',
    SESSION_COOKIE_MAX_AGE_SEC: 604800,
    SESSION_IDLE_TIMEOUT_SEC: 604800,
    SESSION_ABSOLUTE_MAX_AGE_SEC: 2592000,
    REFRESH_TOKEN_IDLE_TIMEOUT_SEC: 2592000,
    REFRESH_TOKEN_ABSOLUTE_MAX_AGE_SEC: 7776000,
    ...overrides,
  };
}

describe('envValidationSchema', () => {
  it('accepts a valid minimal configuration', () => {
    const { error, value } = envValidationSchema.validate(validEnv());

    expect(error).toBeUndefined();
    expect(value.SESSION_IDLE_TIMEOUT_SEC).toBe(604800);
  });

  it('rejects production with insecure session cookies', () => {
    const { error } = envValidationSchema.validate(
      validEnv({
        NODE_ENV: 'production',
        SESSION_COOKIE_SECURE: false,
      }),
    );

    expect(error?.message).toContain(
      'SESSION_COOKIE_SECURE must be true when NODE_ENV=production',
    );
  });

  it('rejects SameSite=None without secure cookies', () => {
    const { error } = envValidationSchema.validate(
      validEnv({
        SESSION_COOKIE_SAMESITE: 'none',
        SESSION_COOKIE_SECURE: false,
      }),
    );

    expect(error?.message).toContain(
      'SESSION_COOKIE_SECURE must be true when SESSION_COOKIE_SAMESITE=none',
    );
  });

  it('rejects cookie lifetime longer than idle timeout', () => {
    const { error } = envValidationSchema.validate(
      validEnv({
        SESSION_COOKIE_MAX_AGE_SEC: 7200,
        SESSION_IDLE_TIMEOUT_SEC: 3600,
      }),
    );

    expect(error?.message).toContain(
      'SESSION_COOKIE_MAX_AGE_SEC must be less than or equal to SESSION_IDLE_TIMEOUT_SEC',
    );
  });

  it('rejects refresh idle timeout longer than refresh absolute lifetime', () => {
    const { error } = envValidationSchema.validate(
      validEnv({
        REFRESH_TOKEN_IDLE_TIMEOUT_SEC: 7776001,
        REFRESH_TOKEN_ABSOLUTE_MAX_AGE_SEC: 7776000,
      }),
    );

    expect(error?.message).toContain(
      'REFRESH_TOKEN_IDLE_TIMEOUT_SEC must be less than or equal to REFRESH_TOKEN_ABSOLUTE_MAX_AGE_SEC',
    );
  });
});
