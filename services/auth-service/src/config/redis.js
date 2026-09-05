const Redis = require('ioredis');
const env = require('./env');
const logger = require('./logger');

// Backs the rate limiter only (auth-service has no queues) — but that's
// still a piece of shared state that must not live in-process, or rate
// limits reset per-instance the moment this service scales past one
// replica. Same client pattern as main-service/src/config/redis.js so both
// Node services behave identically under a Redis blip.
const redis = new Redis(env.redisUrl, {
  maxRetriesPerRequest: null,
  // enableOfflineQueue defaults to true — commands issued before the
  // connection is ready (e.g. SCRIPT LOAD from RedisStore's constructor,
  // which runs at module-load time) are queued and flushed once the socket
  // opens. Setting it to false caused an immediate rejection of that command
  // and a startup crash. lazyConnect still prevents an eager TCP dial; the
  // queue just holds the command until redis.connect() / redis.ping() fires
  // in server.js.
  lazyConnect: true,
  retryStrategy: (times) => Math.min(times * 1000, 10000),
});

redis.on('connect', () => logger.info('Redis connected (auth-service)'));
redis.on('error', (err) => logger.warn({ err: err.message }, 'Redis offline — continuing without cache'));

module.exports = redis;
