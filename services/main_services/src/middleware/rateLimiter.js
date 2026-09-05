const rateLimit = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');
const redis = require('../config/redis');

// Redis-backed store so rate limits are consistent across horizontally-scaled
// instances (each App Service instance would otherwise keep its own counters).
function makeLimiter({ windowMs, limit, prefix }) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    store: new RedisStore({
      prefix,
      // Direct passthrough — if Redis is offline ioredis throws, and
      // passOnStoreError below lets the request through instead of crashing.
      // The previous null-guard broke rate-limit-redis's SCRIPT LOAD init.
      sendCommand: (...args) => redis.call(...args),
    }),
    passOnStoreError: true,
    message: { error: { message: 'Too many requests, slow down.', code: 'RATE_LIMITED' } },
  });
}

const generalLimiter = makeLimiter({ windowMs: 60 * 1000, limit: 300, prefix: 'rl:general:' });
const strictLimiter = makeLimiter({ windowMs: 60 * 1000, limit: 300, prefix: 'rl:strict:' });

module.exports = { generalLimiter, strictLimiter };
