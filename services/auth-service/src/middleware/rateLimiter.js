const rateLimit = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');
const redis = require('../config/redis');

// Redis-backed store so limits are shared across every replica of this
// service instead of reset-per-instance — the same reason main-service
// moved off the in-memory express-rate-limit default. This matters more
// here, not less: auth-service is exactly the thing you'd want a tight,
// consistent brute-force ceiling on regardless of which instance a login
// attempt lands on behind a load balancer.
function makeLimiter({ windowMs, limit, prefix, message }) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    store: new RedisStore({
      prefix,
      // Pass commands straight through to ioredis. If Redis is offline,
      // ioredis throws, rate-limit-redis catches it, and passOnStoreError
      // below lets the request through instead of crashing. Returning null
      // was causing "unexpected reply from redis client" at startup because
      // rate-limit-redis runs SCRIPT LOAD during initialisation and cannot
      // handle a null response.
      sendCommand: (...args) => redis.call(...args),
    }),
    passOnStoreError: true,
    message: { error: { message, code: 'RATE_LIMITED' } },
  });
}

// Tighter limits on auth endpoints to blunt credential stuffing / brute force.
const authLimiter = makeLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  prefix: 'rl:auth:',
  message: 'Too many attempts, please try again later.',
});

const generalLimiter = makeLimiter({
  windowMs: 60 * 1000,
  limit: 120,
  prefix: 'rl:general:',
  message: 'Too many requests, slow down.',
});

module.exports = { authLimiter, generalLimiter };
