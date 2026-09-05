require('dotenv').config();

function decodeKey(base64Value, label) {
  if (!base64Value) return undefined;
  try {
    return Buffer.from(base64Value, 'base64').toString('utf8');
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`[env] Failed to decode ${label}:`, err.message);
    return undefined;
  }
}

const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT) || 5000,
  serviceName: process.env.SERVICE_NAME || 'auth-service',
  corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:3000')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),

  mongoUri: process.env.MONGODB_URI,
  mongoDatabase: process.env.MONGODB_DATABASE || 'auth_db',

  // Backs the Redis-backed rate limiter (see middleware/rateLimiter.js) —
  // required so limits are shared across horizontally-scaled instances
  // instead of reset-per-replica, same as main-service.
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',

  jwt: {
    privateKey: decodeKey(process.env.JWT_PRIVATE_KEY_BASE64, 'JWT_PRIVATE_KEY_BASE64'),
    publicKey: decodeKey(process.env.JWT_PUBLIC_KEY_BASE64, 'JWT_PUBLIC_KEY_BASE64'),
    // Optional: the public key from BEFORE the most recent rotation, kept
    // around only so tokens signed under the old key still verify during the
    // handover window (up to JWT_REFRESH_EXPIRES_IN, since that's the
    // longest-lived token type). Verification tries the current key first,
    // then falls back to this one — see utils/jwt.js#verifyToken. Never used
    // for signing. Unset once every outstanding token from before the
    // rotation has expired.
    previousPublicKey: decodeKey(process.env.JWT_PREVIOUS_PUBLIC_KEY_BASE64, 'JWT_PREVIOUS_PUBLIC_KEY_BASE64'),
    previousKid: process.env.JWT_PREVIOUS_KID || undefined,
    issuer: process.env.JWT_ISSUER || 'hackathon-auth-service',
    audience: process.env.JWT_AUDIENCE || 'patchline',
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    kid: process.env.JWT_KID || 'key-1',
  },

  cookie: {
    domain: process.env.COOKIE_DOMAIN || undefined,
    secure: (process.env.COOKIE_SECURE || 'true') === 'true',
    sameSite: process.env.COOKIE_SAMESITE || 'none',
  },

  projectName: process.env.PROJECT_NAME || 'hackathon-template',
};

const requiredInProd = ['mongoUri'];
if (env.nodeEnv === 'production') {
  for (const key of requiredInProd) {
    if (!env[key]) throw new Error(`[env] Missing required env var for: ${key}`);
  }
  if (!env.jwt.privateKey || !env.jwt.publicKey) {
    throw new Error('[env] JWT_PRIVATE_KEY_BASE64 / JWT_PUBLIC_KEY_BASE64 must be set in production. Run `npm run generate-keys`.');
  }
  // CORS_ORIGINS is this service's only CSRF defense (see docs/security.md) —
  // there's no separate CSRF token, so cookies being httpOnly + a tight
  // origin allow-list is what stops a cross-origin page from riding the
  // user's session. A wildcard silently removes that protection while every
  // other safeguard keeps working, so it's worth failing loudly rather than
  // deploying with CORS effectively open.
  if (env.corsOrigins.includes('*')) {
    throw new Error(
      "[env] CORS_ORIGINS must not contain '*' in production — this is the service's CSRF defense (see docs/security.md). List explicit origins instead."
    );
  }
}

module.exports = env;
