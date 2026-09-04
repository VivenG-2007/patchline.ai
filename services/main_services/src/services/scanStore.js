const redis = require('../config/redis');
const sharedRedis = require('../config/sharedRedis');
const findingState = require('./findingState');
const scanState = require('./scanState');

// Bridges triggerScan -> approveAndFix: we need repoOwner/repoName/branch/userId
// again when the user approves a specific finding. Previously kept in a
// process-local Map, which loses every in-flight scan on a restart/deploy and
// breaks the moment main-service runs more than one instance (see
// docs/architecture.md — main-service is meant to be stateless so it can
// scale horizontally). Redis fixes both, using the same pattern as
// utils/oauthState.js.
const TTL_SECONDS = 24 * 60 * 60; // a scan's approval window shouldn't need to outlive a day

function keyFor(scanId) {
  return `scan:record:${scanId}`;
}

async function saveScan(scanId, record) {
  await redis.set(keyFor(scanId), JSON.stringify(record), 'EX', TTL_SECONDS);
}

async function getScan(scanId) {
  const raw = await redis.get(keyFor(scanId));
  return raw ? JSON.parse(raw) : null;
}

// Merges a partial update into an existing scan record — used for
// non-status bookkeeping fields. Any patch that includes `status` must go
// through transitionScan instead, which validates the move is legal.
async function updateScan(scanId, patch) {
  if (patch && Object.prototype.hasOwnProperty.call(patch, 'status')) {
    throw new Error('updateScan() cannot change `status` directly — use transitionScan()');
  }
  const existing = (await getScan(scanId)) || {};
  const merged = { ...existing, ...patch };
  await saveScan(scanId, merged);
  return merged;
}

// Validates QUEUED -> PROCESSING -> COMPLETED_WAITING_APPROVAL/SCAN_FAILED
// (see scanState.js) before writing the new status, so a worker retry or a
// racing job can't stamp an out-of-order scan status.
async function transitionScan(scanId, toStatus, patch = {}) {
  const existing = (await getScan(scanId)) || {};
  const from = scanState.assertTransition(existing, toStatus);
  const merged = { ...existing, ...patch, status: toStatus, previousStatus: from };
  await saveScan(scanId, merged);
  return merged;
}

// Non-status patch to a single finding's fix record (e.g. attaching a Jira
// link after the fact). Anything that changes `status` must go through
// transitionFix instead.
async function updateFix(scanId, findingId, patch) {
  if (patch && Object.prototype.hasOwnProperty.call(patch, 'status')) {
    throw new Error('updateFix() cannot change `status` directly — use transitionFix()');
  }
  const existing = (await getScan(scanId)) || {};
  const fixes = existing.fixes || {};
  fixes[findingId] = { ...(fixes[findingId] || {}), ...patch };
  const merged = { ...existing, fixes };
  await saveScan(scanId, merged);
  return merged;
}

// Validates AWAITING_APPROVAL -> FIX_QUEUED -> FIX_PROCESSING ->
// FIX_VERIFIED/FIX_NEEDS_REVIEW/FIX_FAILED (see findingState.js), bumping
// the bounded attempt counter whenever a finding (re-)enters FIX_QUEUED,
// before writing the new status. Throws findingState.InvalidTransitionError
// (409) on an illegal move — e.g. approving a finding twice, or retrying a
// finding that's already exhausted MAX_FIX_ATTEMPTS.
async function transitionFix(scanId, findingId, toStatus, patch = {}) {
  const existing = (await getScan(scanId)) || {};
  const from = findingState.assertTransition(existing, findingId, toStatus);
  const fixes = existing.fixes || {};
  const current = fixes[findingId] || {};
  const attempts = findingState.attemptsSoFar(existing, findingId);
  fixes[findingId] = {
    ...current,
    ...patch,
    status: toStatus,
    previousStatus: from,
    attempts: toStatus === 'FIX_QUEUED' ? attempts + 1 : attempts,
  };
  const merged = { ...existing, fixes };
  await saveScan(scanId, merged);
  return merged;
}

// Real, backend-confirmed pipeline checkpoint — written directly by
// ai-storage-service (app/services/scan_progress.py) to a key SEPARATE from
// scan:record:{scanId} above, so reading it here can never race with or
// corrupt transitionScan/transitionFix. Absent/expired simply means "no
// checkpoint newer than 15 min" (see that module's _TTL_SECONDS) — callers
// must treat a null return as "unknown", not as an error.
//
// Read via `sharedRedis`, NOT the `redis` client the rest of this file
// uses — ai-storage-service writes this key to the redis-shared instance
// (same one auth-service uses), which is a DIFFERENT Redis instance from
// the one main-service's own scan:record:*/BullMQ traffic lives on (see
// docker-compose.yml's "Redis topology" comment + config/sharedRedis.js).
// A Redis error here is caught and treated as "no checkpoint" rather than
// propagated — a stage-read failure must never fail the whole status
// response the way a scan:record read failure legitimately would.
function stageKeyFor(scanId) {
  return `scan:stage:${scanId}`;
}

async function getScanStage(scanId) {
  try {
    const stage = await sharedRedis.get(stageKeyFor(scanId));
    if (stage) return stage;
  } catch (err) {
    // sharedRedis read failure — fall through to redis
  }
  try {
    return await redis.get(stageKeyFor(scanId));
  } catch (err) {
    return null;
  }
}

module.exports = { saveScan, getScan, updateScan, transitionScan, updateFix, transitionFix, getScanStage };
