const app = require('./app');
const env = require('./config/env');
const logger = require('./config/logger');
const redis = require('./config/redis');
const { startWorkers } = require('./workers/scannerWorkers');

// FIXED: previously this called app.listen() unconditionally, with Redis
// connecting lazily in the background — a Redis outage at boot wasn't
// detected until the first request that needed it (rate limiting or a
// scan/fix enqueue) failed. That contradicts docs/architecture.md's "fail
// fast when required datastores are unavailable", and Redis specifically
// isn't optional here (unlike its "continuing without cache" error-log
// wording suggests) — it backs both the BullMQ queues that make scans work
// at all and the rate limiter. Ping it before listening, same pattern
// auth-service already uses for MongoDB in this file's sibling.
async function start() {
    try {
        await redis.ping();
        logger.info('Redis reachable (main-service)');
    } catch (err) {
        logger.error({ err }, 'failed to reach Redis at startup — main-service cannot run without it');
        process.exit(1);
    }

    const server = app.listen(env.port, () => {
        logger.info(`main-service listening on :${env.port} [${env.nodeEnv}] — targeting ~3k rps under light benchmark load (see /load-test)`);
    });

    // Scan/fix jobs run through BullMQ (see config/queue.js, workers/scannerWorkers.js)
    // instead of blocking the request handler. By default the workers run
    // in-process here, which is the simplest thing that works for a single-instance
    // hackathon deployment. Set DISABLE_INLINE_WORKERS=true and run `node src/worker.js`
    // as its own process/container to scale scan/fix workers independently from the API,
    // per docs/architecture.md ("scanner workers can scale independently from the API").
    let workers = null;
    if (process.env.DISABLE_INLINE_WORKERS !== 'true') {
        workers = startWorkers();
        logger.info('BullMQ scan/fix workers started in-process');
    } else {
        logger.info('Inline workers disabled (DISABLE_INLINE_WORKERS=true) — run `node src/worker.js` separately');
    }

    const shutdown = async (signal) => {
        logger.info(`${signal} received, shutting down gracefully`);
        server.close(() => process.exit(0));
        if (workers) {
            try {
                await Promise.all([workers.scanWorker.close(), workers.fixWorker.close()]);
            } catch (err) {
                logger.error({ err }, 'error closing workers during shutdown');
            }
        }
        setTimeout(() => process.exit(1), 10000).unref();
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

start();
