const redis = require('../config/redis');
const logger = require('../config/logger');

// Simple GET-response cache keyed by URL + user id. Redis is treated as best-effort:
// any Redis error falls through to hitting the real handler instead of failing the request.
function cacheResponse(ttlSeconds = 30) {
  return async (req, res, next) => {
    if (req.method !== 'GET') return next();
    const key = `cache:${req.originalUrl}:${req.user?.id || 'anon'}`;
    try {
      const cached = await redis.get(key);
      if (cached) {
        res.setHeader('x-cache', 'HIT');
        return res.status(200).json(JSON.parse(cached));
      }
    } catch (err) {
      logger.warn({ err }, 'cache read failed, continuing without cache');
    }

    const originalJson = res.json.bind(res);
    res.json = (body) => {
      if (res.statusCode === 200) {
        redis.set(key, JSON.stringify(body), 'EX', ttlSeconds).catch((err) => logger.warn({ err }, 'cache write failed'));
      }
      res.setHeader('x-cache', 'MISS');
      return originalJson(body);
    };
    return next();
  };
}

module.exports = { cacheResponse };
