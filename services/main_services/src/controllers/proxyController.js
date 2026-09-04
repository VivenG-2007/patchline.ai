const { fetchWithTimeout } = require('../utils/httpClient');
const env = require('../config/env');
const logger = require('../config/logger');

// Main backend acts as the front door: it forwards the caller's own bearer
// token to the AI/Storage service, which verifies it locally too (defense in
// depth — it does not trust main-service blindly). We also attach an internal
// service token so ai-storage-service can distinguish "trusted gateway call"
// from a direct call, useful if you later want stricter internal-only routes.
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
    if (resContentType.includes('application/json')) {
      const data = await response.json();
      return res.status(status).json(data);
    }
    const text = await response.text();
    return res.status(status).send(text);
  } catch (err) {
    logger.error({ err }, 'proxy to ai-storage-service failed');
    return res.status(502).json({ error: { message: 'AI/Storage service unavailable', code: 'UPSTREAM_UNAVAILABLE', requestId: req.id } });
  }
}

module.exports = { proxyToAiStorage };

