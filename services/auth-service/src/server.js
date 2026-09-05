const app = require('./app');
const env = require('./config/env');
const connectDB = require('./config/db');
const redis = require('./config/redis');
const logger = require('./config/logger');

async function start() {
  try {
    await connectDB();

    // Redis now backs the rate limiter (see middleware/rateLimiter.js),
    // which every request path — including /health-adjacent public routes
    // like /register and /login — passes through. An unreachable Redis at
    // boot should fail the service the same way an unreachable Mongo does
    // above, rather than surfacing later as every request 500ing inside
    // the limiter's RedisStore.
    await redis.ping();
    logger.info('Redis reachable (auth-service)');

    const server = app.listen(env.port, () => {
      logger.info(`auth-service listening on :${env.port} [${env.nodeEnv}]`);
    });

    const shutdown = (signal) => {
      logger.info(`${signal} received, shutting down gracefully`);
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(1), 10000).unref();
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (err) {
    // Covers connectDB() and redis.ping() failures alike.
    logger.error(err, 'failed to start auth-service');
    process.exit(1);
  }
}

start();
