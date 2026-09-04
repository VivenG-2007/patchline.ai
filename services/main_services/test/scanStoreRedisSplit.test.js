const test = require('node:test');
const assert = require('node:assert');

const redis = require('../src/config/redis');
const sharedRedis = require('../src/config/sharedRedis');
const scanStore = require('../src/services/scanStore');
const { quitOrDisconnect } = require('./helpers/redisCleanup');

// Regression test for the Redis split: ai-storage-service writes
// scan:stage:{scanId} to the SHARED Redis instance (the one auth-service
// also uses), which is deliberately a different instance from the one
// main-service's own BullMQ/cache/rate-limit traffic runs on (see
// docker-compose.yml's "Redis topology" comment). getScanStage must read
// from sharedRedis, not from main's own `redis` client — reading from the
// wrong instance would silently and permanently break the live-progress UI
// the moment the two Redis instances are actually split in a real
// deployment, without ever throwing an error to say so.

test.after(async () => {
  await Promise.all([quitOrDisconnect(redis), quitOrDisconnect(sharedRedis)]);
});

test('getScanStage reads from the SHARED redis client, not main-service\'s own', async (t) => {
  const sharedCalls = [];
  t.mock.method(sharedRedis, 'get', async (key) => {
    sharedCalls.push(key);
    return 'AI_ANALYSIS';
  });
  const mainCalls = [];
  t.mock.method(redis, 'get', async (key) => {
    mainCalls.push(key);
    return 'THIS-WOULD-BE-WRONG';
  });

  const stage = await scanStore.getScanStage('scan-abc');

  assert.strictEqual(stage, 'AI_ANALYSIS');
  assert.deepStrictEqual(sharedCalls, ['scan:stage:scan-abc']);
  assert.deepStrictEqual(mainCalls, [], 'getScanStage must never touch the main redis client');
});

test('getScanStage fails safe (returns null, does not throw) if the shared Redis is unreachable', async (t) => {
  t.mock.method(sharedRedis, 'get', async () => {
    throw new Error('ECONNREFUSED (simulated)');
  });

  const stage = await scanStore.getScanStage('scan-xyz');
  assert.strictEqual(stage, null);
});

test('getScan/saveScan/transitionScan still use main-service\'s OWN redis client (unaffected by the split)', async (t) => {
  const mainCalls = [];
  t.mock.method(redis, 'set', async (key, value) => {
    mainCalls.push(key);
    return 'OK';
  });
  t.mock.method(redis, 'get', async () => null);

  await scanStore.saveScan('scan-own', { status: 'QUEUED' });
  assert.deepStrictEqual(mainCalls, ['scan:record:scan-own']);
});
