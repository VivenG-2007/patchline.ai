const { Worker } = require('bullmq');
const { fetchWithTimeout } = require('../utils/httpClient');
const { makeBullConnection, SCAN_QUEUE_NAME, FIX_QUEUE_NAME } = require('../config/queue');
const scanStore = require('../services/scanStore');
const githubService = require('../services/githubService');
const jiraService = require('../services/jiraService');
const watchedRepoStore = require('../services/watchedRepoStore');
const env = require('../config/env');
const logger = require('../config/logger');

function upstreamHeaders({ authHeader, requestId, userId }) {
  const headers = {
    'content-type': 'application/json',
    'x-internal-service-token': env.internalServiceToken,
  };
  if (requestId) headers['x-request-id'] = requestId;
  if (authHeader) {
    headers.authorization = authHeader;
  } else if (userId) {
    // Webhook-triggered scans have no live browser session/JWT to forward —
    // assert the watched repo's owner instead. ai-storage-service's
    // require_auth_optional() only trusts this when x-internal-service-token
    // (above) is also present and valid — see core/security.py.
    headers['x-system-user-id'] = userId;
  }
  return headers;
}

// ──────────────────────── Scan job ────────────────────────

async function processScanJob(job) {
  const { scanId, userId, repoOwner, repoName, branch, githubToken, authHeader, requestId, changedFiles, watchedRepositoryId, commitSha } = job.data;
  logger.info({ scanId, repo: `${repoOwner}/${repoName}`, jobId: job.id, trigger: job.data.trigger }, 'scan job started');

  try {
    await scanStore.transitionScan(scanId, 'PROCESSING', { startedAt: new Date().toISOString() });

    const response = await fetchWithTimeout(`${env.aiStorageServiceUrl}/api/v1/scanner/scan`, {
      method: 'POST',
      headers: upstreamHeaders({ authHeader, requestId, userId }),
      body: JSON.stringify({ scanId, repoOwner, repoName, branch, githubToken, changedFiles: changedFiles || undefined }),
      // Generous: a full repo scan fans out AI calls across batches of files
      // before this responds — see env.timeouts.scan.
      timeoutMs: env.timeouts.scan,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`AI Scanner failed: ${errorText || response.statusText}`);
    }

    const scanResults = await response.json();

    // Optionally auto-create a Jira ticket if the user has Jira connected —
    // best-effort, never fails the scan job itself.
    //
    // BUG FIXED: jiraService.createIssue() takes ONE object argument
    // ({ userId, summary, description, issueType }) — see jiraService.js.
    // This call was passing userId as a separate positional first argument
    // (copy-pasted from githubService.createIssue()'s different signature),
    // so `userId` was silently undefined inside createIssue on every call.
    // That made getValidConnection(undefined) always throw JIRA_NOT_CONNECTED,
    // which landed in the catch below and was swallowed as a warning — so no
    // ticket was EVER actually created, even for a user with Jira properly
    // connected, and jiraTicket stayed null every time.
    let jiraTicket = null;
    try {
      if (scanResults.findings && scanResults.findings.length > 0) {
        jiraTicket = await jiraService.createIssue({
          userId,
          summary: `[DevSecOps AI] Security Vulnerabilities in ${repoOwner}/${repoName}`,
          description:
            `AI Vulnerability Scan completed.\nFound ${scanResults.findings.length} issue(s).\n` +
            `Scan ID: ${scanId}\nBlob URI: ${scanResults.blobUri || 'N/A'}` +
            (scanResults.aiAnalysisNote ? `\n\n${scanResults.aiAnalysisNote}` : ''),
          issueType: 'Bug',
        });
        if (jiraTicket) {
          try {
            await fetchWithTimeout(`${env.aiStorageServiceUrl}/api/v1/scanner/scan/${scanId}/jira-ticket`, {
              method: 'POST',
              headers: upstreamHeaders({ userId, requestId }),
              body: JSON.stringify({ jiraTicket }),
              timeoutMs: env.timeouts.aiStorage,
            });
          } catch (syncErr) {
            logger.warn({ syncErr, scanId }, 'Failed to sync Jira ticket to ai-storage service');
          }
        }
      }
    } catch (jiraErr) {
      logger.warn({ jiraErr, scanId }, 'Failed to create Jira ticket automatically');
    }

    await scanStore.transitionScan(scanId, 'COMPLETED_WAITING_APPROVAL', {
      findingsCount: (scanResults.findings || []).length,
      findings: scanResults.findings,
      blobUri: scanResults.blobUri,
      scanTier: scanResults.scanTier,
      aiAnalysisNote: scanResults.aiAnalysisNote,
      ragMemoryEnabled: !!scanResults.ragMemoryEnabled,
      jiraTicket,
      completedAt: new Date().toISOString(),
    });

    // Best-effort: if this scan came from a watched repository (manual
    // "Scan Now" on a watched repo, or a webhook-triggered auto-rescan),
    // update its dashboard row so Last Scan / Findings reflect the result
    // without the browser needing to poll for it.
    if (watchedRepositoryId) {
      try {
        await watchedRepoStore.recordScanResult(watchedRepositoryId, {
          lastScanId: scanId,
          lastScannedCommit: commitSha,
          findingsCount: (scanResults.findings || []).length,
        });
      } catch (updateErr) {
        logger.warn({ updateErr, scanId, watchedRepositoryId }, 'failed to update watched-repository record after scan');
      }
    }

    logger.info({ scanId, jobId: job.id, findingsCount: (scanResults.findings || []).length }, 'scan job completed');
  } catch (err) {
    logger.error({ err, scanId, jobId: job.id, attempt: job.attemptsMade + 1 }, 'scan job failed');
    const attemptsAllowed = job.opts?.attempts || 1;
    const isFinalAttempt = job.attemptsMade + 1 >= attemptsAllowed;
    if (isFinalAttempt) {
      // Only stamp the terminal SCAN_FAILED status once BullMQ has no more
      // retries left — marking it failed after attempt 1 of 2 would make
      // attempt 2's re-assertion of PROCESSING look like a real state-machine
      // violation instead of a normal retry.
      await scanStore.transitionScan(scanId, 'SCAN_FAILED', {
        error: err.message,
        failedAt: new Date().toISOString(),
      });
    } else {
      logger.warn({ scanId, jobId: job.id }, 'scan job failed but will retry — leaving status PROCESSING');
    }
    throw err; // re-throw so BullMQ marks the job failed (and retries per queue settings)
  }
}

// ──────────────────────── Fix job ────────────────────────

async function processFixJob(job) {
  const { scanId, findingId, userId, repoOwner, repoName, branch, githubToken, authHeader, requestId } = job.data;
  logger.info({ scanId, findingId, jobId: job.id, attempt: job.attemptsMade + 1 }, 'fix job started');

  try {
    await scanStore.transitionFix(scanId, findingId, 'FIX_PROCESSING', { startedAt: new Date().toISOString() });

    const fixResponse = await fetchWithTimeout(`${env.aiStorageServiceUrl}/api/v1/scanner/generate-and-verify-fix`, {
      method: 'POST',
      // Fix jobs use x-system-user-id + x-internal-service-token instead of the
      // caller's browser JWT (authHeader). The browser JWT expires in 15 minutes
      // but fix jobs can queue for longer — especially when 3 fixes run sequentially.
      // require_auth_optional() on ai-storage-service trusts x-system-user-id when
      // x-internal-service-token is present (see core/security.py).
      headers: upstreamHeaders({ userId, requestId }),
      body: JSON.stringify({ scanId, findingId, repoOwner, repoName, branch, githubToken }),
      // Generous: fix generation + AI verification + a rescan pass — see env.timeouts.fix.
      timeoutMs: env.timeouts.fix,
    });

    if (!fixResponse.ok) {
      const errorText = await fixResponse.text();
      throw new Error(`AI fix generation failed: ${errorText || fixResponse.statusText}`);
    }

    const fixResult = await fixResponse.json();

    if (!fixResult.verified) {
      // ai-storage-service's FixResponse.status tells us exactly which
      // outcome this is — FIX_NEEDS_REVIEW (retryable, bounded by
      // MAX_FIX_ATTEMPTS) or FIX_UNRESOLVED (terminal: every bounded
      // attempt has now been exhausted with no verified fix). Both have
      // verified=false, but only one of them should still look retryable
      // to a human looking at the dashboard.
      const toStatus = fixResult.status === 'FIX_UNRESOLVED' ? 'FIX_UNRESOLVED' : 'FIX_NEEDS_REVIEW';

      await scanStore.transitionFix(scanId, findingId, toStatus, {
        verified: false,
        summary: fixResult.summary,
        details: fixResult.details,
        fixBranch: fixResult.fixBranch,
        similarPastFixes: fixResult.similarPastFixes || [],
        manualInterventionRequired: !!fixResult.manualInterventionRequired,
        reasonCode: fixResult.reasonCode || null,
        model: fixResult.fixModel,
        provider: fixResult.fixProvider,
        codexReview: {
          model: fixResult.codexModel,
          provider: fixResult.codexProvider,
        },
        aiVerification: fixResult.aiVerification,
        deterministicVerification: fixResult.deterministicVerification,
        riskEvaluation: fixResult.riskEvaluation,
        completedAt: new Date().toISOString(),
      });


      if (toStatus === 'FIX_UNRESOLVED') {
        // Best-effort: raise a ticket so "no valid fix found after N bounded
        // attempts" reaches a human somewhere other than a dashboard status
        // badge — same pattern as the scan-completion ticket above.
        let jiraTicket = null;
        try {
          jiraTicket = await jiraService.createIssue({
            userId,
            summary: `[DevSecOps AI] Manual review required — no valid fix found for ${findingId}`,
            description:
              `PatchLine exhausted its bounded remediation attempts for this finding without producing a ` +
              `verified fix.\n\nScan ID: ${scanId}\nFinding: ${findingId}\nRepo: ${repoOwner}/${repoName}\n\n` +
              `${fixResult.details || fixResult.summary || ''}`,
            issueType: 'Bug',
          });
          if (jiraTicket) {
            await scanStore.updateFix(scanId, findingId, { jiraTicket });
            try {
              await fetchWithTimeout(`${env.aiStorageServiceUrl}/api/v1/scanner/scan/${scanId}/finding/${findingId}/jira-ticket`, {
                method: 'POST',
                headers: upstreamHeaders({ userId, requestId }),
                body: JSON.stringify({ jiraTicket }),
                timeoutMs: env.timeouts.aiStorage,
              });
            } catch (syncErr) {
              logger.warn({ syncErr, scanId, findingId }, 'Failed to sync finding Jira ticket to ai-storage service');
            }
          }
        } catch (jiraErr) {
          logger.warn({ jiraErr, scanId, findingId }, 'Failed to create Jira ticket for unresolved finding');
        }
        logger.warn({ scanId, findingId, jobId: job.id }, 'fix job completed — UNRESOLVED, manual intervention required');
      } else {
        // Not a job failure — the fix genuinely didn't verify. Bounded
        // retries exist for transient infra failures, not for "the AI's
        // patch didn't pass verification"; that outcome goes back to a
        // human for manual re-approval (still within the attempt budget).
        logger.info({ scanId, findingId, jobId: job.id }, 'fix job completed — not verified, needs human review');
      }
      return;
    }

    // Resolve a fresh token if the one from the job is stale/missing —
    // GitHub App installation tokens expire after 1 hour; a long-queued job
    // may have waited past that, or the token was never stored in job data
    // (webhook-triggered scans). getRepoToken() checks the user's stored
    // connection first, then falls back to the App installation for the repo.
    let effectiveToken = githubToken;
    if (!effectiveToken) {
      try {
        effectiveToken = await githubService.getRepoToken(repoOwner, repoName, userId);
        if (effectiveToken) {
          logger.info({ scanId, findingId }, 'Resolved fresh GitHub token for PR creation via getRepoToken()');
        }
      } catch (tokenErr) {
        logger.warn({ tokenErr: tokenErr.message, scanId, findingId }, 'Could not resolve fresh GitHub token — PR creation may fail');
      }
    }

    let pr = null;
    try {
      pr = await githubService.createPullRequest(userId, {
        owner: repoOwner,
        repo: repoName,
        title: `[AI Security Fix] ${fixResult.summary || 'Remediate vulnerability'}`,
        body: `### DevSecOps AI Vulnerability Fix\n\n- **Scan ID**: \`${scanId}\`\n- **Finding**: \`${findingId}\`\n- **Fix Verified**: Yes\n\n${fixResult.details || ''}`,
        head: fixResult.fixBranch,
        base: branch,
        githubToken: effectiveToken,
      });
      logger.info({ prNumber: pr?.number, prUrl: pr?.url, scanId, findingId }, 'GitHub pull request successfully opened for verified fix');
    } catch (prErr) {
      logger.error({ prErr: prErr.message, prErrStatus: prErr.status, prErrDetails: prErr.details, scanId, findingId }, 'Failed to create GitHub PR');
    }

    await scanStore.transitionFix(scanId, findingId, 'FIX_VERIFIED', {
      verified: true,
      fixBranch: fixResult.fixBranch,
      summary: fixResult.summary,
      details: fixResult.details,
      similarPastFixes: fixResult.similarPastFixes || [],
      pullRequest: pr,
      model: fixResult.fixModel,
      provider: fixResult.fixProvider,
      codexReview: {
        model: fixResult.codexModel,
        provider: fixResult.codexProvider,
      },
      aiVerification: fixResult.aiVerification,
      deterministicVerification: fixResult.deterministicVerification,
      riskEvaluation: fixResult.riskEvaluation,
      completedAt: new Date().toISOString(),
    });

    // Sync the PR to MongoDB so scan history and dashboard metrics retain
    // the PR link across page reloads. Best-effort — a transient failure
    // here must not cause BullMQ to retry an already-verified fix.
    if (pr) {
      try {
        await fetchWithTimeout(`${env.aiStorageServiceUrl}/api/v1/scanner/scan/${scanId}/finding/${findingId}/pull-request`, {
          method: 'POST',
          headers: upstreamHeaders({ userId, requestId }),
          body: JSON.stringify({ pullRequest: pr }),
          timeoutMs: env.timeouts.aiStorage,
        });
        logger.info({ prNumber: pr.number, scanId, findingId }, 'PR synced to MongoDB');
      } catch (syncErr) {
        logger.warn({ syncErr: syncErr.message, scanId, findingId }, 'Failed to sync PR to MongoDB — PR link visible in Redis only until TTL');
      }
    }

    logger.info({ scanId, findingId, jobId: job.id, prCreated: !!pr }, 'fix job completed and verified');

  } catch (err) {
    logger.error({ err, scanId, findingId, jobId: job.id, attempt: job.attemptsMade + 1 }, 'fix job failed');
    const attemptsAllowed = job.opts?.attempts || 1;
    const isFinalAttempt = job.attemptsMade + 1 >= attemptsAllowed;
    if (isFinalAttempt) {
      // Same reasoning as the scan worker: only stamp the terminal
      // FIX_FAILED status (which a human can retry from, bounded by
      // MAX_FIX_ATTEMPTS) once BullMQ itself has no more job-level retries
      // left, so intermediate retries don't collide with the state machine.
      try {
        await scanStore.transitionFix(scanId, findingId, 'FIX_FAILED', {
          error: err.message,
          failedAt: new Date().toISOString(),
        });
      } catch (transitionErr) {
        logger.warn({ transitionErr, scanId, findingId }, 'could not record FIX_FAILED');
      }
    } else {
      logger.warn({ scanId, findingId, jobId: job.id }, 'fix job failed but will retry — leaving status FIX_PROCESSING');
    }
    throw err; // re-throw so BullMQ applies the bounded retry/backoff configured on the job
  }
}

// ──────────────────────── Worker lifecycle ────────────────────────

function startWorkers() {
  const scanWorker = new Worker(SCAN_QUEUE_NAME, processScanJob, {
    connection: makeBullConnection('scanWorker'),
    concurrency: Number(process.env.SCAN_WORKER_CONCURRENCY || 3),
  });

  const fixWorker = new Worker(FIX_QUEUE_NAME, processFixJob, {
    connection: makeBullConnection('fixWorker'),
    concurrency: Number(process.env.FIX_WORKER_CONCURRENCY || 3),
  });

  scanWorker.on('failed', (job, err) => logger.error({ err, jobId: job?.id, scanId: job?.data?.scanId }, 'scan worker job failed'));
  fixWorker.on('failed', (job, err) => logger.error({ err, jobId: job?.id, scanId: job?.data?.scanId, findingId: job?.data?.findingId }, 'fix worker job failed'));

  return { scanWorker, fixWorker };
}

module.exports = { startWorkers, processScanJob, processFixJob };
