const Redis = require('ioredis');
const env = require('./env');
const logger = require('./logger');

const redis = new Redis(env.redisUrl, {
  maxRetriesPerRequest: null,
  // enableOfflineQueue defaults to true — commands issued before the
  // connection is ready (e.g. redis.ping() in server.js, which fires before
  // the lazyConnect socket opens) are queued and flushed once connected.
  // Setting it to false caused an immediate rejection and a startup crash.
  lazyConnect: true,
  retryStrategy: (times) => Math.min(times * 1000, 10000),
});

redis.on('connect', () => logger.info('Redis connected (main-service)'));
redis.on('error', (err) => logger.warn({ err: err.message }, 'Redis offline — continuing without cache'));

module.exports = redis;
