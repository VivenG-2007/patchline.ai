const test = require('node:test');
const assert = require('node:assert');
const { quitOrDisconnect } = require('./helpers/redisCleanup');

test('app module loads without throwing', async () => {
  const app = require('../src/app');
  assert.ok(app);

  // src/app.js transitively requires config/redis.js and config/queue.js,
  // each of which opens its own live ioredis connection at require-time
  // (config/queue.js's own comment explains why BullMQ needs a separate
  // connection per queue rather than sharing config/redis.js's). None of
  // that is closed on its own, so — smoke test or not — this file leaves
  // the event loop with open handles once it's the only thing requiring
  // `../src/app` in the process. `node --test` waits for a natural exit
  // rather than force-exiting (no --test-force-exit on Node 18), so
  // without this the whole suite hangs instead of finishing, in CI same as
  // locally. Close every connection this require pulled in so the process
  // can exit cleanly once tests are done.
  //
  // This environment has no real Redis to connect to (CI/sandbox/local dev
  // without `docker run redis` — same as any of those). A graceful
  // `.quit()` against an unreachable server never gets a reply, and
  // `maxRetriesPerRequest: null` (required by BullMQ) means it never gives
  // up on its own — quitOrDisconnect races a short timeout and falls back
  // to a hard `.disconnect()` so this test finishes either way, whether or
  // not Redis happens to be running.
  const redis = require('../src/config/redis');
  const queue = require('../src/config/queue');
  await Promise.race([
    queue.closeAll().catch(() => {}),
    new Promise((resolve) => setTimeout(resolve, 1500)),
  ]);
  await quitOrDisconnect(redis);
  // Belt and suspenders: closeAll()'s own BullMQ connections might have won
  // their internal race already, but if Queue#close() itself hung waiting
  // on the connection, nothing above actually tore those sockets down —
  // disconnect them directly so no real Redis is required for this test to
  // exit cleanly.
  const { scanQueue, fixQueue } = queue;
  scanQueue.disconnect?.();
  fixQueue.disconnect?.();
});
