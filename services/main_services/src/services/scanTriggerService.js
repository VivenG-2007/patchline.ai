const { v4: uuidv4 } = require('uuid');
const scanStore = require('./scanStore');
const { scanQueue } = require('../config/queue');
const logger = require('../config/logger');

// Single source of truth for "enqueue a scan job" — previously this logic
// lived only inline in scannerController.triggerScan. Now both the manual
// POST /api/scanner/scan endpoint AND githubController.handleWebhook's
// auto-rescan path call this, so the QUEUED bookkeeping, job idempotency key,
// and retry/backoff settings can't silently drift apart between the two
// triggers.
async function enqueueScan({
  userId,
  repoOwner,
  repoName,
  branch = 'main',
  githubToken,
  authHeader,
  requestId,
  trigger = 'manual', // 'manual' | 'webhook'
  changedFiles, // present only for webhook-triggered incremental rescans
  watchedRepositoryId, // present only when this repo is in the watched-repository registry
  commitSha, // the pushed commit's sha, for webhook triggers — recorded on scan completion
}) {
  const scanId = `scan-${uuidv4().replace(/-/g, '').slice(0, 10)}`;

  // Record the scan as queued immediately so GET /status/:scanId works right
  // away, before the worker has even picked the job up.
  await scanStore.saveScan(scanId, {
    userId,
    repoOwner,
    repoName,
    repo: `${repoOwner}/${repoName}`,
    branch,
    status: 'QUEUED',
    trigger,
    changedFiles: changedFiles || null,
    createdAt: new Date().toISOString(),
  });

  await scanQueue.add(
    'scan',
    {
      scanId,
      userId,
      repoOwner,
      repoName,
      branch,
      githubToken,
      authHeader,
      requestId,
      trigger,
      changedFiles: changedFiles || null,
      watchedRepositoryId: watchedRepositoryId || null,
      commitSha: commitSha || null,
    },
    {
      jobId: scanId, // idempotency: re-posting the same scanId won't spawn a duplicate job
      attempts: 2,
      backoff: { type: 'exponential', delay: 3000 },
    }
  );

  logger.info(
    { scanId, repo: `${repoOwner}/${repoName}`, trigger, changedFileCount: changedFiles ? changedFiles.length : undefined },
    'scan job enqueued'
  );

  return { scanId };
}

module.exports = { enqueueScan };
