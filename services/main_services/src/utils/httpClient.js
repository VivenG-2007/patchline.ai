// Thin wrapper around Node's built-in `fetch` (global since Node 18, which
// is this service's minimum engine — see package.json) that enforces a
// request timeout via AbortSignal.timeout().
//
// Previously every outbound call (GitHub, Jira, ai-storage-service) used
// node-fetch with no timeout option set at all, meaning a stalled upstream
// could hang a request — or, worse, a BullMQ worker (scannerWorkers.js) —
// indefinitely, quietly eating one of its limited concurrency slots. This
// also drops node-fetch as a dependency: nothing here needs it once every
// call site goes through this wrapper.
const DEFAULT_TIMEOUT_MS = 15000;

class UpstreamTimeoutError extends Error {
  constructor(url, timeoutMs) {
    super(`Request to ${url} timed out after ${timeoutMs}ms`);
    this.name = 'UpstreamTimeoutError';
    this.code = 'UPSTREAM_TIMEOUT';
    this.status = 504;
  }
}

async function fetchWithTimeout(url, { timeoutMs = DEFAULT_TIMEOUT_MS, ...options } = {}) {
  try {
    return await fetch(url, { ...options, signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      throw new UpstreamTimeoutError(url, timeoutMs);
    }
    throw err;
  }
}

module.exports = { fetchWithTimeout, UpstreamTimeoutError, DEFAULT_TIMEOUT_MS };
