import * as Joi from 'joi';

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
}).unknown(true);
