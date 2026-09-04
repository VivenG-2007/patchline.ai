const { body, param } = require('express-validator');
const githubService = require('../services/githubService');
const scanStore = require('../services/scanStore');
const scanTriggerService = require('../services/scanTriggerService');
const { fixQueue } = require('../config/queue');
const env = require('../config/env');
const logger = require('../config/logger');
const { fetchWithTimeout } = require('../utils/httpClient');

// Same headers proxyController.js attaches: the caller's own bearer token
// (ai-storage-service verifies it locally too — defense in depth) plus the
// shared internal-service token so ai-storage-service can trust this is a
// server-to-server call from the gateway. Captured here at enqueue time and
// carried in the job payload so the background worker (which has no `req`)
// can present the same identity when it eventually calls ai-storage-service.
function callerAuthHeader(req) {
  return req.headers.authorization || (req.accessToken ? `Bearer ${req.accessToken}` : '');
}

async function triggerScan(req, res, next) {
  try {
    const { repoOwner, repoName, branch = 'main', githubToken } = req.body;
    let token = githubToken;
    if (!token) {
      try {
        const connection = await githubService.getConnection(req.user.id);
        token = connection?.accessToken;
      } catch (connErr) {
        logger.warn({ connErr: connErr.message, userId: req.user.id }, 'Could not get GitHub connection for triggerScan');
        throw connErr;
      }
    }

    const { scanId } = await scanTriggerService.enqueueScan({
      userId: req.user.id,
      repoOwner,
      repoName,
      branch,
      githubToken: token,
      authHeader: callerAuthHeader(req),
      requestId: req.id,
      trigger: 'manual',
    });

    return res.status(202).json({
      scanId,
      status: 'QUEUED',
      repo: `${repoOwner}/${repoName}`,
      message: 'Scan queued for background processing. Poll GET /api/scanner/status/:scanId for progress and results.',
    });
  } catch (err) {
    return next(err);
  }
}

async function getScanStatus(req, res, next) {
  try {
    const { scanId } = req.params;
    const scanRecord = await scanStore.getScan(scanId);

    if (!scanRecord) {
      return res.status(404).json({ error: { message: 'Scan record not found or expired', code: 'SCAN_NOT_FOUND', requestId: req.id } });
    }
    if (scanRecord.userId !== req.user.id) {
      return res.status(403).json({ error: { message: 'This scan does not belong to your account', code: 'FORBIDDEN', requestId: req.id } });
    }

    // Real backend-confirmed checkpoint from ai-storage-service (see
    // scanStore.getScanStage) — only meaningful while the scan itself is
    // still in flight; once it's terminal, `status`/`fixes[...].status`
    // are the source of truth and a leftover/racing stage key must not
    // override them client-side.
    let stage = null;
    if (scanRecord.status === 'PROCESSING') {
      stage = await scanStore.getScanStage(scanId);
    } else if (scanRecord.fixes) {
      const inFlightFindingId = Object.keys(scanRecord.fixes).find(
        (fId) => scanRecord.fixes[fId]?.status === 'FIX_PROCESSING' || scanRecord.fixes[fId]?.status === 'FIX_QUEUED'
      );
      if (inFlightFindingId) {
        stage = await scanStore.getScanStage(scanId);
      }
    }

    return res.status(200).json({ scanId, ...scanRecord, stage });
  } catch (err) {
    return next(err);
  }
}

async function approveAndFix(req, res, next) {
  try {
    const { scanId, findingId } = req.body;
    const scanRecord = await scanStore.getScan(scanId);

    if (!scanRecord) {
      return res.status(404).json({ error: { message: 'Scan record not found or expired', code: 'SCAN_NOT_FOUND', requestId: req.id } });
    }
    // A scanId is guessable-ish (see ai-storage-service's uuid-derived ids,
    // but don't rely on that alone) — make sure the caller actually owns it.
    if (scanRecord.userId !== req.user.id) {
      return res.status(403).json({ error: { message: 'This scan does not belong to your account', code: 'FORBIDDEN', requestId: req.id } });
    }
    if (!scanRecord.findings?.some((f) => f.id === findingId)) {
      return res.status(404).json({ error: { message: `Finding '${findingId}' not found on this scan`, code: 'FINDING_NOT_FOUND', requestId: req.id } });
    }

    let token = req.body.githubToken || scanRecord.githubToken;
    if (!token) {
      try {
        token = await githubService.getRepoToken(scanRecord.repoOwner, scanRecord.repoName, req.user.id);
      } catch (repoTokenErr) {
        logger.warn({ repoTokenErr: repoTokenErr.message, userId: req.user.id }, 'Could not resolve repo token via getRepoToken in approveAndFix');
      }
    }
    if (!token) {
      try {
        const connection = await githubService.getConnection(req.user.id);
        token = connection?.accessToken;
      } catch (connErr) {
        logger.warn({ connErr: connErr.message, userId: req.user.id }, 'Could not resolve GitHub connection in approveAndFix');
      }
    }

    // This is THE human-approval gate the product spec calls out as "the
    // most important safety boundary": it's the only place a finding can
    // move out of AWAITING_APPROVAL. transitionFix rejects (409) if the
    // finding is already queued/processing/verified, or has exhausted its
    // bounded retry budget — so re-clicking "Approve & fix", approving an
    // already-verified finding, or calling this endpoint directly to skip
    // approval all fail instead of silently re-queuing work.
    await scanStore.transitionFix(scanId, findingId, 'FIX_QUEUED', {
      queuedAt: new Date().toISOString(),
    });

    await fixQueue.add(
      'fix',
      {
        scanId,
        findingId,
        userId: req.user.id,
        repoOwner: scanRecord.repoOwner,
        repoName: scanRecord.repoName,
        branch: scanRecord.branch,
        githubToken: token,
        authHeader: callerAuthHeader(req),
        requestId: req.id,
      },
      {
        jobId: `fix-${scanId}-${findingId}`, // idempotency: re-clicking "Approve & fix" won't duplicate an in-flight fix
        attempts: 3, // bounded retries — a fix job that keeps transiently failing doesn't retry forever
        backoff: { type: 'exponential', delay: 5000 },
      }
    );

    logger.info({ scanId, findingId }, 'fix job enqueued');

    return res.status(202).json({
      scanId,
      findingId,
      status: 'FIX_QUEUED',
      message: 'Fix queued for background processing. Poll GET /api/scanner/status/:scanId for progress and results.',
    });
  } catch (err) {
    return next(err);
  }
}

async function getScanHistory(req, res, next) {
  try {
    const limit = req.query.limit || 20;
    const headers = { 'content-type': 'application/json', 'x-internal-service-token': env.internalServiceToken, 'x-request-id': req.id };
    const authHeader = req.headers.authorization || (req.accessToken ? `Bearer ${req.accessToken}` : '');
    if (authHeader) headers.authorization = authHeader;

    const response = await fetchWithTimeout(`${env.aiStorageServiceUrl}/api/v1/scanner/history?limit=${limit}`, {
      headers,
      timeoutMs: env.timeouts.aiStorage,
    });
    if (!response.ok) {
      const text = await response.text();
      const err = new Error(`Failed to fetch scan history: ${text || response.statusText}`);
      err.status = response.status >= 400 && response.status < 600 ? response.status : 502;
      throw err;
    }
    const data = await response.json();
    return res.status(200).json(data);
  } catch (err) {
    return next(err);
  }
}

async function getAiProviderStatus(req, res, next) {
  try {
    const headers = {
      'content-type': 'application/json',
      'x-internal-service-token': env.internalServiceToken,
      'x-request-id': req.id,
    };
    const authHeader = req.headers.authorization || (req.accessToken ? `Bearer ${req.accessToken}` : '');
    if (authHeader) headers.authorization = authHeader;

    const response = await fetchWithTimeout(`${env.aiStorageServiceUrl}/api/v1/scanner/ai-provider-status`, {
      headers,
      timeoutMs: env.timeouts.aiStorage,
    });
    if (!response.ok) {
      const text = await response.text();
      const err = new Error(`Failed to fetch AI provider status: ${text || response.statusText}`);
      err.status = response.status >= 400 && response.status < 600 ? response.status : 502;
      throw err;
    }
    const data = await response.json();
    return res.status(200).json(data);
  } catch (err) {
    return next(err);
  }
}

const triggerScanValidators = [
  body('repoOwner').trim().notEmpty().withMessage('repoOwner is required'),
  body('repoName').trim().notEmpty().withMessage('repoName is required'),
  body('branch').optional().trim(),
];

const approveFixValidators = [
  body('scanId').trim().notEmpty().withMessage('scanId is required'),
  body('findingId').trim().notEmpty().withMessage('findingId is required'),
];

const scanStatusValidators = [
  param('scanId').trim().notEmpty().withMessage('scanId is required'),
];

const createPrValidators = [
  param('scanId').trim().notEmpty().withMessage('scanId is required'),
  param('findingId').trim().notEmpty().withMessage('findingId is required'),
];

// Manual PR creation: for a finding that is FIX_VERIFIED with a fixBranch but
// no pullRequest yet (e.g. automatic PR creation failed transiently). The
// frontend can surface a "Create Pull Request" button for this case.
async function createPr(req, res, next) {
  try {
    const { scanId, findingId } = req.params;
    const scanRecord = await scanStore.getScan(scanId);

    if (!scanRecord) {
      return res.status(404).json({ error: { message: 'Scan record not found or expired', code: 'SCAN_NOT_FOUND', requestId: req.id } });
    }
    if (scanRecord.userId !== req.user.id) {
      return res.status(403).json({ error: { message: 'This scan does not belong to your account', code: 'FORBIDDEN', requestId: req.id } });
    }

    const fixRecord = scanRecord.fixes?.[findingId];
    if (!fixRecord) {
      return res.status(404).json({ error: { message: `Finding '${findingId}' has no fix record`, code: 'FIX_NOT_FOUND', requestId: req.id } });
    }
    if (fixRecord.status !== 'FIX_VERIFIED') {
      return res.status(409).json({ error: { message: `Cannot create PR: fix status is '${fixRecord.status}' (expected FIX_VERIFIED)`, code: 'INVALID_FIX_STATUS', requestId: req.id } });
    }
    if (!fixRecord.fixBranch) {
      return res.status(409).json({ error: { message: 'No fix branch recorded for this finding', code: 'NO_FIX_BRANCH', requestId: req.id } });
    }
    if (fixRecord.pullRequest) {
      // PR already exists — return it so the frontend can link it without a new API call
      return res.status(200).json({ scanId, findingId, pullRequest: fixRecord.pullRequest, alreadyExists: true });
    }

    let token = req.body.githubToken || scanRecord.githubToken;
    if (!token) {
      try {
        token = await githubService.getRepoToken(scanRecord.repoOwner, scanRecord.repoName, req.user.id);
      } catch (tokenErr) {
        logger.warn({ tokenErr: tokenErr.message, scanId, findingId }, 'Could not resolve GitHub token for manual PR creation');
      }
    }
    if (!token) {
      try {
        const conn = await githubService.getConnection(req.user.id);
        token = conn?.accessToken;
      } catch (connErr) {
        logger.warn({ connErr: connErr.message }, 'getConnection failed in createPr');
      }
    }

    const pr = await githubService.createPullRequest(req.user.id, {
      owner: scanRecord.repoOwner,
      repo: scanRecord.repoName,
      title: `[AI Security Fix] ${fixRecord.summary || 'Remediate vulnerability'}`,
      body: `### DevSecOps AI Vulnerability Fix\n\n- **Scan ID**: \`${scanId}\`\n- **Finding**: \`${findingId}\`\n- **Fix Verified**: Yes\n\n${fixRecord.details || ''}`,
      head: fixRecord.fixBranch,
      base: scanRecord.branch || 'main',
      githubToken: token,
    });

    logger.info({ prNumber: pr.number, prUrl: pr.url, scanId, findingId }, 'Manual PR creation succeeded');

    // Persist to Redis
    await scanStore.updateFix(scanId, findingId, { pullRequest: pr });

    // Persist to MongoDB (best-effort)
    try {
      await fetchWithTimeout(`${env.aiStorageServiceUrl}/api/v1/scanner/scan/${scanId}/finding/${findingId}/pull-request`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-internal-service-token': env.internalServiceToken,
          'x-request-id': req.id,
          ...(req.headers.authorization ? { authorization: req.headers.authorization } : { 'x-system-user-id': req.user.id }),
        },
        body: JSON.stringify({ pullRequest: pr }),
        timeoutMs: env.timeouts.aiStorage,
      });
    } catch (syncErr) {
      logger.warn({ syncErr: syncErr.message, scanId, findingId }, 'Manual PR: failed to sync to MongoDB — Redis has it');
    }

    return res.status(201).json({ scanId, findingId, pullRequest: pr });
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  triggerScan,
  getScanStatus,
  approveAndFix,
  createPr,
  getScanHistory,
  getAiProviderStatus,
  triggerScanValidators,
  approveFixValidators,
  scanStatusValidators,
  createPrValidators,
};
