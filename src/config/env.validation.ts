import Joi from 'joi';

const base64Key32 = Joi.string()
  .pattern(/^[A-Za-z0-9+/]+={0,2}$/)
  .custom((value, helpers) => {
    const buf = Buffer.from(value, 'base64');
    if (buf.length !== 32) {
      return helpers.error('any.invalid');
    }
    return value;
  }, '32-byte base64 key')
  .messages({
    'string.pattern.base': 'must be base64 encoded',
    'any.invalid': 'must be a 32-byte base64 key',
  });

const base64Key32Optional = base64Key32.allow('').optional();

export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'test', 'production')
    .default('development'),
  PORT: Joi.number().integer().min(1).max(65535).default(3000),
  LOG_FORMAT: Joi.string().valid('json', 'pretty').optional(),

  DATABASE_URL: Joi.string().uri().required(),

  // Feature flags
  OIDC_ENABLED: Joi.boolean().truthy('true').falsy('false').default(false),
  CRYPTO_ENABLED: Joi.boolean()
    .truthy('true')
    .falsy('false')
    .default(false)
    .when('OIDC_ENABLED', {
      is: true,
      then: Joi.valid(true).required(),
    }),

  // Crypto keys (required only when CRYPTO_ENABLED=true)
  SESSION_ENC_KEY: Joi.when('CRYPTO_ENABLED', {
    is: true,
    then: base64Key32.required(),
    otherwise: base64Key32Optional,
  }),
  SESSION_ENC_KEY_ID: Joi.string().default('v1'),
  HEADER_SIGNING_KEY: Joi.when('CRYPTO_ENABLED', {
    is: true,
    then: base64Key32.required(),
    otherwise: base64Key32Optional,
  }),
  HEADER_SIGNING_KEY_ID: Joi.string().default('v1'),

  // ZITADEL OIDC (required only when OIDC_ENABLED=true)
  ZITADEL_ISSUER: Joi.when('OIDC_ENABLED', {
    is: true,
    then: Joi.string().uri().required(),
    otherwise: Joi.string().uri().optional(),
  }),
  ZITADEL_CLIENT_ID: Joi.when('OIDC_ENABLED', {
    is: true,
    then: Joi.string().required(),
    otherwise: Joi.string().optional(),
  }),
  ZITADEL_CLIENT_SECRET: Joi.string().allow('').optional(),
  ZITADEL_REDIRECT_URI: Joi.when('OIDC_ENABLED', {
    is: true,
    then: Joi.string().uri().required(),
    otherwise: Joi.string().uri().optional(),
  }),
  ZITADEL_POST_LOGOUT_REDIRECT_URI: Joi.string().uri().optional(),
  ZITADEL_SCOPES: Joi.string().default('openid profile email offline_access'),
  OIDC_ALLOW_INSECURE_HTTP: Joi.boolean()
    .truthy('true')
    .falsy('false')
    .default(false),

  // ZITADEL Management API (for org/project/user provisioning)
  ZITADEL_API_BASE_URL: Joi.string().uri().optional(),
  ZITADEL_API_TOKEN: Joi.string().allow('').optional(),
  ZITADEL_MASTER_PROJECT_ID: Joi.string().allow('').optional(),
  ZITADEL_PROJECT_GRANT_ROLE_KEYS: Joi.string().allow('').optional(),
  ZITADEL_ADMIN_ROLE_KEY: Joi.string().default('admin'),
  ZITADEL_USER_ROLE_KEY: Joi.string().default('user'),

  // Session cookie settings
  SESSION_COOKIE_NAME: Joi.string().default('auth_session'),
  SESSION_COOKIE_DOMAIN: Joi.string().allow('').optional(),
  SESSION_COOKIE_PATH: Joi.string().default('/'),
  SESSION_COOKIE_SECURE: Joi.boolean()
    .truthy('true')
    .falsy('false')
    .default(false),
  SESSION_COOKIE_SAMESITE: Joi.string()
    .valid('lax', 'strict', 'none')
    .default('lax'),
  SESSION_COOKIE_MAX_AGE_SEC: Joi.number()
    .integer()
    .min(60)
    .default(60 * 60 * 24 * 7),
  SESSION_IDLE_TIMEOUT_SEC: Joi.number()
    .integer()
    .min(60 * 5)
    .default(60 * 60 * 24 * 7),
  SESSION_ABSOLUTE_MAX_AGE_SEC: Joi.number()
    .integer()
    .min(60 * 60)
    .default(60 * 60 * 24 * 30),

  // Queue / Redis
  REDIS_URL: Joi.string().uri().required(),

  // Gateway proxy
  INTERNAL_API_BASE_URL: Joi.string().uri().optional(),
})
  .custom((value, helpers) => {
    if (
      value.NODE_ENV === 'production' &&
      value.SESSION_COOKIE_SECURE !== true
    ) {
      return helpers.message({
        custom: 'SESSION_COOKIE_SECURE must be true when NODE_ENV=production',
      });
    }

    if (
      value.SESSION_COOKIE_SAMESITE === 'none' &&
      value.SESSION_COOKIE_SECURE !== true
    ) {
      return helpers.message({
        custom:
          'SESSION_COOKIE_SECURE must be true when SESSION_COOKIE_SAMESITE=none',
      });
    }

    if (value.SESSION_IDLE_TIMEOUT_SEC > value.SESSION_ABSOLUTE_MAX_AGE_SEC) {
      return helpers.message({
        custom:
          'SESSION_IDLE_TIMEOUT_SEC must be less than or equal to SESSION_ABSOLUTE_MAX_AGE_SEC',
      });
    }

    if (value.SESSION_COOKIE_MAX_AGE_SEC > value.SESSION_IDLE_TIMEOUT_SEC) {
      return helpers.message({
        custom:
          'SESSION_COOKIE_MAX_AGE_SEC must be less than or equal to SESSION_IDLE_TIMEOUT_SEC',
      });
    }

    return value;
  }, 'session cookie security rules')
  .unknown(true);
