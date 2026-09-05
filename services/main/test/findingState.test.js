const test = require('node:test');
const assert = require('node:assert');
const {
  MAX_FIX_ATTEMPTS,
  currentStatus,
  attemptsSoFar,
  assertTransition,
  InvalidTransitionError,
} = require('../src/services/findingState');

function scanRecordWith(findingId, status, attempts = 0) {
  return { fixes: { [findingId]: { status, attempts } } };
}

test('currentStatus defaults to AWAITING_APPROVAL when no fix record exists', () => {
  assert.strictEqual(currentStatus({}, 'f1'), 'AWAITING_APPROVAL');
  assert.strictEqual(currentStatus(undefined, 'f1'), 'AWAITING_APPROVAL');
  assert.strictEqual(currentStatus({ fixes: {} }, 'f1'), 'AWAITING_APPROVAL');
});

test('attemptsSoFar defaults to 0 when no fix record exists', () => {
  assert.strictEqual(attemptsSoFar({}, 'f1'), 0);
  assert.strictEqual(attemptsSoFar(scanRecordWith('f1', 'FIX_FAILED', 2), 'f1'), 2);
});

test('happy path: AWAITING_APPROVAL -> FIX_QUEUED -> FIX_PROCESSING -> FIX_VERIFIED', () => {
  let record = {};
  assert.strictEqual(assertTransition(record, 'f1', 'FIX_QUEUED'), 'AWAITING_APPROVAL');

  record = scanRecordWith('f1', 'FIX_QUEUED');
  assert.strictEqual(assertTransition(record, 'f1', 'FIX_PROCESSING'), 'FIX_QUEUED');

  record = scanRecordWith('f1', 'FIX_PROCESSING');
  assert.strictEqual(assertTransition(record, 'f1', 'FIX_VERIFIED'), 'FIX_PROCESSING');
});

test('FIX_PROCESSING self-loop is allowed (BullMQ retry re-asserting the same status)', () => {
  const record = scanRecordWith('f1', 'FIX_PROCESSING');
  assert.strictEqual(assertTransition(record, 'f1', 'FIX_PROCESSING'), 'FIX_PROCESSING');
});

test('FIX_VERIFIED is terminal — no transition out of it is legal', () => {
  const record = scanRecordWith('f1', 'FIX_VERIFIED');
  for (const to of ['FIX_QUEUED', 'FIX_PROCESSING', 'FIX_VERIFIED', 'FIX_NEEDS_REVIEW', 'FIX_FAILED']) {
    assert.throws(() => assertTransition(record, 'f1', to), InvalidTransitionError);
  }
});

test('cannot approve an already-verified finding again (regression: double-approve)', () => {
  const record = scanRecordWith('f1', 'FIX_VERIFIED');
  assert.throws(
    () => assertTransition(record, 'f1', 'FIX_QUEUED'),
    (err) => err instanceof InvalidTransitionError && err.status === 409
  );
});

test('cannot re-approve mid-flight (FIX_PROCESSING is not directly re-queueable)', () => {
  const record = scanRecordWith('f1', 'FIX_PROCESSING');
  assert.throws(() => assertTransition(record, 'f1', 'FIX_QUEUED'), InvalidTransitionError);
});

test('cannot skip AWAITING_APPROVAL and jump straight to FIX_PROCESSING', () => {
  const record = {};
  assert.throws(() => assertTransition(record, 'f1', 'FIX_PROCESSING'), InvalidTransitionError);
});

test('cannot skip AWAITING_APPROVAL and jump straight to FIX_VERIFIED', () => {
  const record = {};
  assert.throws(() => assertTransition(record, 'f1', 'FIX_VERIFIED'), InvalidTransitionError);
});

test('FIX_NEEDS_REVIEW and FIX_FAILED can retry back to FIX_QUEUED', () => {
  assert.strictEqual(
    assertTransition(scanRecordWith('f1', 'FIX_NEEDS_REVIEW', 1), 'f1', 'FIX_QUEUED'),
    'FIX_NEEDS_REVIEW'
  );
  assert.strictEqual(
    assertTransition(scanRecordWith('f1', 'FIX_FAILED', 1), 'f1', 'FIX_QUEUED'),
    'FIX_FAILED'
  );
});

test('retry is blocked once MAX_FIX_ATTEMPTS is reached', () => {
  const record = scanRecordWith('f1', 'FIX_FAILED', MAX_FIX_ATTEMPTS);
  assert.throws(
    () => assertTransition(record, 'f1', 'FIX_QUEUED'),
    (err) => err instanceof InvalidTransitionError && err.code === 'FIX_ATTEMPTS_EXHAUSTED'
  );
});

test('retry is still allowed one attempt below the cap (off-by-one boundary)', () => {
  const record = scanRecordWith('f1', 'FIX_FAILED', MAX_FIX_ATTEMPTS - 1);
  assert.strictEqual(assertTransition(record, 'f1', 'FIX_QUEUED'), 'FIX_FAILED');
});

test('FIX_QUEUED can fail before ever reaching FIX_PROCESSING', () => {
  const record = scanRecordWith('f1', 'FIX_QUEUED');
  assert.strictEqual(assertTransition(record, 'f1', 'FIX_FAILED'), 'FIX_QUEUED');
});

test('unknown status string is rejected rather than silently allowed', () => {
  const record = scanRecordWith('f1', 'SOME_MADE_UP_STATUS');
  assert.throws(
    () => assertTransition(record, 'f1', 'FIX_QUEUED'),
    (err) => err instanceof InvalidTransitionError && err.code === 'UNKNOWN_STATUS'
  );
});

test('two findings on the same scan record are tracked independently', () => {
  const record = {
    fixes: {
      f1: { status: 'FIX_VERIFIED', attempts: 1 },
      f2: { status: 'AWAITING_APPROVAL', attempts: 0 },
    },
  };
  assert.throws(() => assertTransition(record, 'f1', 'FIX_QUEUED'), InvalidTransitionError);
  assert.strictEqual(assertTransition(record, 'f2', 'FIX_QUEUED'), 'AWAITING_APPROVAL');
});

test('FIX_PROCESSING can move directly to FIX_UNRESOLVED (last attempt exhausted)', () => {
  const record = scanRecordWith('f1', 'FIX_PROCESSING', MAX_FIX_ATTEMPTS);
  assert.strictEqual(assertTransition(record, 'f1', 'FIX_UNRESOLVED'), 'FIX_PROCESSING');
});

test('FIX_UNRESOLVED is terminal — no transition out of it is legal', () => {
  const record = scanRecordWith('f1', 'FIX_UNRESOLVED');
  for (const to of ['FIX_QUEUED', 'FIX_PROCESSING', 'FIX_VERIFIED', 'FIX_NEEDS_REVIEW', 'FIX_FAILED', 'FIX_UNRESOLVED']) {
    assert.throws(() => assertTransition(record, 'f1', to), InvalidTransitionError);
  }
});

test('FIX_UNRESOLVED is not a retry source — a re-approve attempt is rejected, not silently allowed', () => {
  const record = scanRecordWith('f1', 'FIX_UNRESOLVED', MAX_FIX_ATTEMPTS);
  assert.throws(() => assertTransition(record, 'f1', 'FIX_QUEUED'), InvalidTransitionError);
});
