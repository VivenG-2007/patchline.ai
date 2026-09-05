const test = require('node:test');
const assert = require('node:assert');
const {
  currentStatus,
  assertTransition,
  InvalidScanTransitionError,
} = require('../src/services/scanState');

test('currentStatus defaults to QUEUED when the record has no status yet', () => {
  assert.strictEqual(currentStatus({}), 'QUEUED');
  assert.strictEqual(currentStatus(undefined), 'QUEUED');
});

test('happy path: QUEUED -> PROCESSING -> COMPLETED_WAITING_APPROVAL', () => {
  let record = {};
  assert.strictEqual(assertTransition(record, 'PROCESSING'), 'QUEUED');

  record = { status: 'PROCESSING' };
  assert.strictEqual(assertTransition(record, 'COMPLETED_WAITING_APPROVAL'), 'PROCESSING');
});

test('a scan can also fail from PROCESSING', () => {
  const record = { status: 'PROCESSING' };
  assert.strictEqual(assertTransition(record, 'SCAN_FAILED'), 'PROCESSING');
});

test('PROCESSING self-loop is allowed (BullMQ retry re-asserting the same status)', () => {
  const record = { status: 'PROCESSING' };
  assert.strictEqual(assertTransition(record, 'PROCESSING'), 'PROCESSING');
});

test('COMPLETED_WAITING_APPROVAL is terminal', () => {
  const record = { status: 'COMPLETED_WAITING_APPROVAL' };
  for (const to of ['QUEUED', 'PROCESSING', 'COMPLETED_WAITING_APPROVAL', 'SCAN_FAILED']) {
    assert.throws(() => assertTransition(record, to), InvalidScanTransitionError);
  }
});

test('SCAN_FAILED is terminal', () => {
  const record = { status: 'SCAN_FAILED' };
  for (const to of ['QUEUED', 'PROCESSING', 'COMPLETED_WAITING_APPROVAL', 'SCAN_FAILED']) {
    assert.throws(() => assertTransition(record, to), InvalidScanTransitionError);
  }
});

test('cannot skip QUEUED and jump straight to COMPLETED_WAITING_APPROVAL', () => {
  const record = {};
  assert.throws(() => assertTransition(record, 'COMPLETED_WAITING_APPROVAL'), InvalidScanTransitionError);
});

test('invalid transitions carry a 409 status for the caller to surface', () => {
  const record = { status: 'COMPLETED_WAITING_APPROVAL' };
  assert.throws(
    () => assertTransition(record, 'PROCESSING'),
    (err) => err instanceof InvalidScanTransitionError && err.status === 409
  );
});

test('unknown status string is rejected rather than silently allowed', () => {
  const record = { status: 'SOME_MADE_UP_STATUS' };
  assert.throws(
    () => assertTransition(record, 'PROCESSING'),
    (err) => err instanceof InvalidScanTransitionError && err.code === 'UNKNOWN_STATUS'
  );
});
