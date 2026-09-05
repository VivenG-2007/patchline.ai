const { Queue } = require('bullmq');
const Redis = require('ioredis');
const env = require('./env');
const logger = require('./logger');

// BullMQ requires maxRetriesPerRequest: null on any ioredis connection it
// manages (it issues blocking commands internally) — this is deliberately a
// SEPARATE connection from config/redis.js, which is tuned for ordinary
// cache/rate-limit use (maxRetriesPerRequest: 2, lazyConnect: false).
// Each Queue/Worker gets its own connection per BullMQ's recommendation.
//
// BullMQ does NOT close a connection you hand it yourself via `connection:`
// (as opposed to one it constructs internally) — `Queue#close()` only closes
// what the Queue owns, so the raw ioredis client stays connected after
// close(). That's harmless in production (server.js's shutdown handler calls
// process.exit(0) right after, which tears down every socket regardless),
// but it matters anywhere something waits for a clean, handle-free exit
// instead of forcing one — e.g. the test suite (see test/health.test.js).
// Tracking every connection this module opens lets closeAll() below actually
// close them, without changing anything about how the app runs normally.
const _connections = [];
function makeBullConnection(label) {
  const conn = new Redis(env.redisUrl, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
    retryStrategy: (times) => Math.min(times * 200, 2000),
  });
  conn.on('error', (err) => logger.error({ err, label }, 'BullMQ redis connection error'));
  _connections.push(conn);
  return conn;
}

const SCAN_QUEUE_NAME = 'scanner-scan';
const FIX_QUEUE_NAME = 'scanner-fix';

const scanQueue = new Queue(SCAN_QUEUE_NAME, {
  connection: makeBullConnection('scanQueue'),
  defaultJobOptions: {
    removeOnComplete: 500,
    removeOnFail: 200,
  },
});

const fixQueue = new Queue(FIX_QUEUE_NAME, {
  connection: makeBullConnection('fixQueue'),
  defaultJobOptions: {
    removeOnComplete: 500,
    removeOnFail: 200,
  },
});

scanQueue.on('error', (err) => logger.error({ err }, 'scanQueue error'));
fixQueue.on('error', (err) => logger.error({ err }, 'fixQueue error'));

// Closes the queues AND the raw connections behind them (see the comment on
// makeBullConnection above for why both steps are needed). Not used by the
// running service — server.js's own shutdown handler exits the process
// outright — this exists for callers (tests) that need every socket this
// module opened to actually go away.
async function closeAll() {
  await Promise.all([scanQueue.close(), fixQueue.close()]);
  await Promise.all(_connections.map((conn) => conn.quit().catch(() => conn.disconnect())));
}

module.exports = {
  scanQueue,
  fixQueue,
  SCAN_QUEUE_NAME,
  FIX_QUEUE_NAME,
  makeBullConnection,
  closeAll,
};
