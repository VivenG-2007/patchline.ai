const { fetchWithTimeout } = require('../utils/httpClient');
const env = require('../config/env');
const logger = require('../config/logger');

// Main backend acts as the front door: it forwards the caller's own bearer
// token to the AI/Storage service, which verifies it locally too (defense in
// depth — it does not trust main-service blindly). We also attach an internal
// service token so ai-storage-service can distinguish "trusted gateway call"
// from a direct call, useful if you later want stricter internal-only routes.
const ZERO_DASHBOARD_STATS = {
  kpis: {
    connectedRepos: { value: 0, deltaLabel: null },
    openFindings: { value: 0 },
    criticalIssues: { value: 0 },
    aiFixesApplied: { value: 0, windowLabel: null },
  },
  activePipelineCount: 0,
  clearanceRate: 100.0,
  averageFixTime: 'N/A',
  globalRiskScore: 0,
  riskScoreSeries: [],
  activityFeed: [],
  repoHealth: [],
  severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
  aiFixEngine: {
    fixesGenerated: 0,
    fixesVerified: 0,
    prsCreated: 0,
    verificationRate: 0.0,
    modelUsage: { featherlessCalls: 0, fallbackCalls: 0, fallbackModels: [] },
  },
  pipelineStatus: [
    { id: 'scan', status: 'waiting', count: 0 },
    { id: 'root_cause', status: 'waiting', model: 'gpt-4.1-mini', provider: 'azure_openai', count: 0 },
    { id: 'rag_retrieval', status: 'waiting', count: 0 },
    { id: 'rank_top3', status: 'waiting', count: 0 },
    { id: 'fix_generation', status: 'waiting', model: 'gpt-5.2', provider: 'azure_openai', count: 0 },
    { id: 'deterministic_rescan', status: 'waiting', count: 0 },
    { id: 'codex_review', status: 'waiting', model: 'gpt-5.3-codex', provider: 'azure_openai', count: 0 },
    { id: 'risk_recalc', status: 'waiting', count: 0 },
    { id: 'pr_created', status: 'waiting', count: 0 },
  ],
  vulnHeatmap: [
    { type: 'SQL Injection', weeks: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
    { type: 'XSS', weeks: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
    { type: 'Secrets', weeks: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
    { type: 'Cmd Injection', weeks: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
    { type: 'Weak Crypto', weeks: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
    { type: 'Path Traversal', weeks: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
  ],
  reposAtRisk: [],
  securityRadar: [
    { axis: 'Secrets', value: 0 },
    { axis: 'Injection', value: 0 },
    { axis: 'XSS', value: 0 },
    { axis: 'Crypto', value: 0 },
    { axis: 'Commands', value: 0 },
    { axis: 'Dependencies', value: 0 },
  ],
  isElasticActive: false,
};

async function proxyToAiStorage(req, res, next) {
  try {
    const targetPath = req.originalUrl.replace(/^\/api\/proxy/, '');
    const url = `${env.aiStorageServiceUrl}${targetPath}`;

    const headers = {
      'x-internal-service-token': env.internalServiceToken,
      'x-request-id': req.id,
    };

    if (req.headers['content-type']) {
      headers['content-type'] = req.headers['content-type'];
    }

    // Forward Authorization header or use req.accessToken verified by requireAuth
    const authHeader = req.headers.authorization || (req.accessToken ? `Bearer ${req.accessToken}` : '');
    if (authHeader) {
      headers.authorization = authHeader;
    }

    let body;
    const contentType = req.headers['content-type'] || '';
    if (['GET', 'HEAD'].includes(req.method)) {
      body = undefined;
    } else if (contentType.includes('application/json')) {
      body = JSON.stringify(req.body);
    } else {
      body = req;
    }

    const fetchOptions = {
      method: req.method,
      headers,
      body,
      timeoutMs: env.timeouts.proxy,
    };

    if (body === req) {
      fetchOptions.duplex = 'half';
    }

    const response = await fetchWithTimeout(url, fetchOptions);

    const resContentType = response.headers.get('content-type') || '';
    const status = response.status;

    if (response.ok && resContentType.includes('application/json')) {
      const data = await response.json();
      return res.status(status).json(data);
    }

    // If upstream returns an error or non-JSON (e.g. 429 HTML or 502 from Render edge)
    logger.warn(
      { targetUrl: url, status, resContentType, requestId: req.id },
      'AI/Storage upstream service returned non-200 or non-JSON response'
    );

    // If dashboard stats request failed, gracefully return zero telemetry so UI does not crash
    if (targetPath === '/api/v1/dashboard/stats') {
      return res.status(200).json(ZERO_DASHBOARD_STATS);
    }

    if (resContentType.includes('application/json')) {
      const data = await response.json();
      return res.status(status).json(data);
    }

    const text = await response.text();
    return res.status(status >= 400 ? status : 502).json({
      error: {
        message: status === 429 ? 'Upstream AI service rate limit reached' : (text.slice(0, 150) || 'AI/Storage upstream error'),
        code: status === 429 ? 'RATE_LIMITED' : 'UPSTREAM_ERROR',
        requestId: req.id,
      },
    });
  } catch (err) {
    logger.error({ err, targetUrl: env.aiStorageServiceUrl }, 'proxy to ai-storage-service failed');
    const targetPath = req.originalUrl.replace(/^\/api\/proxy/, '');
    if (targetPath === '/api/v1/dashboard/stats') {
      return res.status(200).json(ZERO_DASHBOARD_STATS);
    }
    return res.status(502).json({ error: { message: 'AI/Storage service unavailable', code: 'UPSTREAM_UNAVAILABLE', requestId: req.id } });
  }
}

module.exports = { proxyToAiStorage, ZERO_DASHBOARD_STATS };

