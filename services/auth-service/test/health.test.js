const test = require('node:test');
const assert = require('node:assert');

// Minimal smoke test that doesn't require a live Mongo connection —
// verifies the Express app boots and responds. Extend with supertest +
// mongodb-memory-server for full integration coverage.
process.env.JWT_PRIVATE_KEY_BASE64 = process.env.JWT_PRIVATE_KEY_BASE64 || '';
process.env.JWT_PUBLIC_KEY_BASE64 = process.env.JWT_PUBLIC_KEY_BASE64 || '';

test('app module loads without throwing', async () => {
  const app = require('../src/app');
  assert.ok(app);

  // src/app.js -> middleware/rateLimiter -> config/redis.js opens a live
  // ioredis connection at require-time and nothing else in this process
  // closes it. `node --test` waits for a natural exit rather than force-
  // exiting (no --test-force-exit on Node 18), so left open this leaves the
  // whole file — and, since this suite runs with effectively serial
  // process-per-file scheduling on a single-core runner, every test file
  // queued after it too — hanging instead of finishing. Same root cause as
  // the equivalent fix in services/main-service/test/health.test.js.
  const redis = require('../src/config/redis');
  await redis.quit();
});
