// Explicit state machine for a finding's remediation lifecycle.
//
// Previously statuses were just strings written by whichever caller felt
// like it (see scanStore.updateFix) — nothing stopped e.g. calling
// approve-fix twice, or re-triggering a fix on a finding that was already
// FIX_VERIFIED, or bypassing AWAITING_APPROVAL entirely by hitting the fix
// endpoint directly. This module is the single source of truth for which
// transitions are legal; scanStore and scannerController both go through it.
//
// AWAITING_APPROVAL is implicit: a finding that exists on a completed scan
// but has no entry in scanRecord.fixes yet is awaiting approval. Once a fix
// record exists, its `status` field drives everything below.
//
// FIX_VERIFIED is the only terminal state. FIX_NEEDS_REVIEW and FIX_FAILED
// can be retried (a human re-approves), but only up to MAX_FIX_ATTEMPTS —
// "bounded rather than continuing forever", per the product spec.

const MAX_FIX_ATTEMPTS = 3;

const TRANSITIONS = {
  // NOTE: ai-storage-service's copy of this state machine (state_machine.py)
  // intentionally diverges here — it additionally allows
  // AWAITING_APPROVAL -> FIX_PROCESSING, because its Mongo-backed copy of
  // finding status never learns about the FIX_QUEUED write below (that
  // write only ever reaches Redis, here). See the comment on that file's
  // TRANSITIONS map for the full explanation. This map stays as the
  // textbook 3-step version because main-service's own Redis-backed flow
  // really does pass through FIX_QUEUED first (see approveAndFix in
  // scannerController.js) before the worker ever asserts FIX_PROCESSING.
  AWAITING_APPROVAL: ['FIX_QUEUED'],
  // FIX_QUEUED -> FIX_FAILED covers a job that dies before it can even
  // record FIX_PROCESSING (e.g. Redis hiccup on the very first write).
  FIX_QUEUED: ['FIX_PROCESSING', 'FIX_FAILED'],
  // FIX_PROCESSING -> FIX_PROCESSING is a deliberate self-loop for the same
  // reason as scanState.js: BullMQ's own `attempts` retries re-run
  // processFixJob from the top, which re-asserts FIX_PROCESSING before
  // redoing the work. FIX_UNRESOLVED is the terminal "no valid fix / human
  // review required" state, reached directly from FIX_PROCESSING (ai-storage
  // -service decides "this was the last bounded attempt" in the same
  // request that just finished verifying it — see generate_and_verify_fix's
  // Step 5 terminal-state comment in scanner.py).
  FIX_PROCESSING: ['FIX_PROCESSING', 'FIX_VERIFIED', 'FIX_NEEDS_REVIEW', 'FIX_FAILED', 'FIX_UNRESOLVED'],
  FIX_NEEDS_REVIEW: ['FIX_QUEUED'],
  FIX_FAILED: ['FIX_QUEUED'],
  FIX_VERIFIED: [],
  // Terminal, like FIX_VERIFIED — no outgoing transitions. Reached once a
  // finding has exhausted MAX_FIX_ATTEMPTS bounded remediation attempts
  // without a verified fix. Distinct from FIX_NEEDS_REVIEW (which IS
  // retryable) so a finding here reads as "needs a human to intervene
  // directly", not "try again" — processFixJob (scannerWorkers.js) reads
  // this off ai-storage-service's FixResponse.status and raises a Jira
  // ticket instead of leaving it to be silently re-approved forever.
  FIX_UNRESOLVED: [],
};

const RETRY_SOURCES = new Set(['FIX_NEEDS_REVIEW', 'FIX_FAILED']);

class InvalidTransitionError extends Error {
  constructor(message, { from, to, code = 'INVALID_TRANSITION', status = 409 } = {}) {
    super(message);
    this.name = 'InvalidTransitionError';
    this.from = from;
    this.to = to;
    this.code = code;
    this.status = status;
  }
}

function currentStatus(scanRecord, findingId) {
  return scanRecord?.fixes?.[findingId]?.status || 'AWAITING_APPROVAL';
}

function attemptsSoFar(scanRecord, findingId) {
  return scanRecord?.fixes?.[findingId]?.attempts || 0;
}

// Throws InvalidTransitionError if `toStatus` isn't reachable from the
// finding's current status (or if a retry would exceed MAX_FIX_ATTEMPTS).
// Returns the current ("from") status on success, for logging/bookkeeping.
function assertTransition(scanRecord, findingId, toStatus) {
  const from = currentStatus(scanRecord, findingId);
  const allowed = TRANSITIONS[from];
  if (!allowed) {
    throw new InvalidTransitionError(`Unknown finding status '${from}'`, { from, to: toStatus, code: 'UNKNOWN_STATUS' });
  }
  if (!allowed.includes(toStatus)) {
    throw new InvalidTransitionError(
      `Cannot move finding ${findingId} from ${from} to ${toStatus}`,
      { from, to: toStatus }
    );
  }
  if (toStatus === 'FIX_QUEUED' && RETRY_SOURCES.has(from)) {
    const attempts = attemptsSoFar(scanRecord, findingId);
    if (attempts >= MAX_FIX_ATTEMPTS) {
      throw new InvalidTransitionError(
        `Finding ${findingId} has exhausted its ${MAX_FIX_ATTEMPTS} bounded fix attempts`,
        { from, to: toStatus, code: 'FIX_ATTEMPTS_EXHAUSTED' }
      );
    }
  }
  return from;
}

module.exports = {
  MAX_FIX_ATTEMPTS,
  TRANSITIONS,
  currentStatus,
  attemptsSoFar,
  assertTransition,
  InvalidTransitionError,
};