const test = require('node:test');
const assert = require('node:assert');

const scanStore = require('../src/services/scanStore');
const ctrl = require('../src/controllers/scannerController');

// Regression test for the "stale stage leak" bug: scan_progress's Redis
// checkpoint (scan:stage:{scanId}) is written by ai-storage-service while a
// scan/fix is in flight and cleared once it reaches a terminal state (see
// app/services/scan_progress.py). Its own TTL is a generous 15 minutes as a
// backstop, NOT the primary cleanup mechanism — clear_stage() firing on
// every exit path (see run_scan's try/finally, and generate_and_verify_fix's
// explicit clear before returning) is. But main-service's getScanStatus
// reads main-service's OWN scan:record:{scanId} status field to decide
// whether the stage key is even still meaningful, independent of whether
// ai-storage-service actually cleared it in time — so even a stage key that
// is still sitting in Redis (TTL not yet expired, or a clear that raced/
// failed) must never be surfaced once THIS service's own record says the
// scan/fix is done. That's the property this test locks in.
//
//   PROCESSING       + stage present -> response DOES surface the stage
//   SCAN_COMPLETED   + stale stage   -> response does NOT surface the stage
//   SCAN_FAILED      + stale stage   -> response does NOT surface the stage
//   FIX_VERIFIED     + stale stage   -> response does NOT surface the stage
//   FIX_UNRESOLVED   + stale stage   -> response does NOT surface the stage

function fakeReqRes(scanId, userId) {
  const req = { params: { scanId }, user: { id: userId } };
  const res = {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
  return { req, res };
}

async function runWith(t, scanRecord, stageInRedis) {
  t.mock.method(scanStore, 'getScan', async () => scanRecord);
  const stageCalls = [];
  t.mock.method(scanStore, 'getScanStage', async () => {
    stageCalls.push(true);
    return stageInRedis;
  });
  const { req, res } = fakeReqRes('scan-abc', 'u1');
  await ctrl.getScanStatus(req, res, (err) => {
    throw err;
  });
  return { res, stageCallCount: stageCalls.length };
}

test('PROCESSING scan: an in-flight stage IS surfaced', async (t) => {
  const { res, stageCallCount } = await runWith(
    t,
    { userId: 'u1', status: 'PROCESSING' },
    'AI_ANALYSIS'
  );
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.body.stage, 'AI_ANALYSIS');
  assert.strictEqual(stageCallCount, 1);
});

test('SCAN_COMPLETED_WAITING_APPROVAL: a stale stage key must not leak into the response', async (t) => {
  const { res } = await runWith(
    t,
    { userId: 'u1', status: 'COMPLETED_WAITING_APPROVAL' },
    'RISK_ENGINE' // stale — TTL hasn't expired yet, but the scan is done
  );
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.body.stage, null, 'a completed scan must report stage: null, never a stale stage string');
});

test('SCAN_FAILED: a stale stage key must not leak into the response', async (t) => {
  const { res } = await runWith(
    t,
    { userId: 'u1', status: 'SCAN_FAILED' },
    'DETERMINISTIC_SCAN' // stale — the scan blew up mid-pipeline
  );
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.body.stage, null);
});

test('FIX_VERIFIED (no other fix in flight): a stale stage key must not leak into the response', async (t) => {
  const { res } = await runWith(
    t,
    {
      userId: 'u1',
      status: 'COMPLETED_WAITING_APPROVAL',
      fixes: { f1: { status: 'FIX_VERIFIED' } },
    },
    'CODEX_VERIFYING' // stale
  );
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.body.stage, null);
});

test('FIX_UNRESOLVED (no other fix in flight): a stale stage key must not leak into the response', async (t) => {
  const { res } = await runWith(
    t,
    {
      userId: 'u1',
      status: 'COMPLETED_WAITING_APPROVAL',
      fixes: { f1: { status: 'FIX_UNRESOLVED', manualInterventionRequired: true, reasonCode: 'NO_VALID_FIX' } },
    },
    'FIX_GENERATING' // stale
  );
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.body.stage, null);
});

test('a DIFFERENT finding still FIX_PROCESSING keeps the stage visible even once one fix is terminal', async (t) => {
  const { res } = await runWith(
    t,
    {
      userId: 'u1',
      status: 'COMPLETED_WAITING_APPROVAL',
      fixes: {
        f1: { status: 'FIX_VERIFIED' },
        f2: { status: 'FIX_PROCESSING' },
      },
    },
    'RISK_RECALCULATING'
  );
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.body.stage, 'RISK_RECALCULATING');
});
