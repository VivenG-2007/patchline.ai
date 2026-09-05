// Explicit state machine for a scan's own lifecycle (separate from the
// per-finding fix lifecycle in findingState.js). Mirrors the same pattern:
// a small transition table plus an assert helper that throws a 409-carrying
// error instead of letting a worker silently stamp an out-of-order status.

const TRANSITIONS = {
  QUEUED: ['PROCESSING'],
  // PROCESSING -> PROCESSING is a deliberate self-loop: BullMQ's own
  // `attempts` retries re-run processScanJob from the top on a transient
  // failure, which re-asserts PROCESSING before doing any work. Without the
  // self-loop that re-assertion would itself be an "invalid transition" and
  // BullMQ's retry would never get a chance to run.
  PROCESSING: ['PROCESSING', 'COMPLETED_WAITING_APPROVAL', 'SCAN_FAILED'],
  COMPLETED_WAITING_APPROVAL: [],
  SCAN_FAILED: [],
};

class InvalidScanTransitionError extends Error {
  constructor(message, { from, to, code = 'INVALID_SCAN_TRANSITION', status = 409 } = {}) {
    super(message);
    this.name = 'InvalidScanTransitionError';
    this.from = from;
    this.to = to;
    this.code = code;
    this.status = status;
  }
}

function currentStatus(scanRecord) {
  return scanRecord?.status || 'QUEUED';
}

function assertTransition(scanRecord, toStatus) {
  const from = currentStatus(scanRecord);
  const allowed = TRANSITIONS[from];
  if (!allowed) {
    throw new InvalidScanTransitionError(`Unknown scan status '${from}'`, { from, to: toStatus, code: 'UNKNOWN_STATUS' });
  }
  if (!allowed.includes(toStatus)) {
    throw new InvalidScanTransitionError(`Cannot move scan from ${from} to ${toStatus}`, { from, to: toStatus });
  }
  return from;
}

module.exports = { TRANSITIONS, currentStatus, assertTransition, InvalidScanTransitionError };
