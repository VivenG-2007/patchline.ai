const Redis = require('ioredis');
const env = require('./env');
const logger = require('./logger');

// Deliberately a SEPARATE ioredis connection from config/redis.js — see
// docker-compose.yml's "Redis topology" comment. This one talks to the
// Redis instance auth-service and ai-storage-service actually run against
// (redis-shared), not the one main-service's own BullMQ queues/cache/rate
// limiter use (redis-main / config/redis.js). The ONLY thing main-service
// reads from it is scan:stage:{scanId} — a checkpoint ai-storage-service's
// app/services/scan_progress.py writes as it completes each real pipeline
// step (see scanStore.js's getScanStage). main-service never writes to
// this connection; it is read-only in practice even though nothing here
// enforces that at the client level.
//
// When SHARED_REDIS_URL is unset, env.sharedRedisUrl falls back to the same
// URL as the main connection, so a single-Redis deployment (pre-split, or a
// smaller install that doesn't need two instances) works identically to
// before — this module just becomes a second connection to the same Redis.
const sharedRedis = new Redis(env.sharedRedisUrl, {
  maxRetriesPerRequest: 2,
  lazyConnect: true,
  retryStrategy: (times) => Math.min(times * 1000, 10000),
});

sharedRedis.on('connect', () => logger.info('Redis connected (main-service -> shared/stage-read connection)'));
sharedRedis.on('error', (err) =>
  logger.warn({ err: err.message }, 'Shared Redis (stage checkpoints) offline — stage will read as null, scan/fix outcomes are unaffected')
);

module.exports = sharedRedis;
