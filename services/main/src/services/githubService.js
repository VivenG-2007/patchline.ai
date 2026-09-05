const { fetchWithTimeout } = require('../utils/httpClient');
const githubConfig = require('../config/github');
const tokenStore = require('./githubTokenStore');
const env = require('../config/env');

// No refresh logic needed here — classic GitHub OAuth App tokens don't
// expire, so getConnection() is enough (contrast with jiraService.js, which
// has to check expiry and refresh on every call).
async function getConnection(userId) {
  const connection = await tokenStore.getConnection(userId);
  if (!connection) {
    const err = new Error('GitHub is not connected for this account — visit /api/github/oauth/start first');
    err.status = 409;
    err.code = 'GITHUB_NOT_CONNECTED';
    throw err;
  }
  return connection;
}

async function listRepos(userId, { perPage = 30 } = {}) {
  const connection = await getConnection(userId);
  const response = await fetchWithTimeout(`${githubConfig.API_BASE}/user/repos?sort=updated&per_page=${perPage}`, {
    headers: { authorization: `Bearer ${connection.accessToken}`, accept: 'application/vnd.github+json', 'user-agent': 'patchline' },
    timeoutMs: env.timeouts.github,
  });
  if (!response.ok) {
    const err = new Error('Failed to list GitHub repositories');
    err.status = 502;
    throw err;
  }
  const repos = await response.json();
  return repos.map((r) => ({
    id: r.id,
    fullName: r.full_name,
    private: r.private,
    url: r.html_url,
    description: r.description,
    updatedAt: r.updated_at,
  }));
}

async function createIssue(userId, { owner, repo, title, body }) {
  const connection = await getConnection(userId);
  const response = await fetchWithTimeout(`${githubConfig.API_BASE}/repos/${owner}/${repo}/issues`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${connection.accessToken}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
      'user-agent': 'patchline',
    },
    body: JSON.stringify({ title, body }),
    timeoutMs: env.timeouts.github,
  });
  const data = await response.json();
  if (!response.ok) {
    const err = new Error(data?.message || 'GitHub rejected the issue creation request');
    err.status = response.status === 404 ? 404 : 502;
    throw err;
  }
  return { number: data.number, url: data.html_url, title: data.title };
}

async function createPullRequest(userId, { owner, repo, title, body, head, base = 'main' }) {
  const connection = await getConnection(userId);
  const response = await fetchWithTimeout(`${githubConfig.API_BASE}/repos/${owner}/${repo}/pulls`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${connection.accessToken}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
      'user-agent': 'patchline',
    },
    body: JSON.stringify({ title, body, head, base }),
    timeoutMs: env.timeouts.github,
  });
  const data = await response.json();
  if (!response.ok) {
    const err = new Error(data?.message || 'GitHub rejected the Pull Request creation request');
    err.status = response.status === 404 ? 404 : 502;
    throw err;
  }
  return { number: data.number, url: data.html_url, title: data.title };
}

async function getRepo(userId, { owner, repo }) {
  const connection = await getConnection(userId);
  const response = await fetchWithTimeout(`${githubConfig.API_BASE}/repos/${owner}/${repo}`, {
    headers: { authorization: `Bearer ${connection.accessToken}`, accept: 'application/vnd.github+json', 'user-agent': 'patchline' },
    timeoutMs: env.timeouts.github,
  });
  const data = await response.json();
  if (!response.ok) {
    const err = new Error(data?.message || 'Failed to fetch repository from GitHub');
    err.status = response.status === 404 ? 404 : 502;
    throw err;
  }
  return { id: data.id, fullName: data.full_name, defaultBranch: data.default_branch, private: data.private };
}

async function listWebhooks(userId, { owner, repo }) {
  const connection = await getConnection(userId);
  const response = await fetchWithTimeout(`${githubConfig.API_BASE}/repos/${owner}/${repo}/hooks`, {
    headers: { authorization: `Bearer ${connection.accessToken}`, accept: 'application/vnd.github+json', 'user-agent': 'patchline' },
    timeoutMs: env.timeouts.github,
  });
  if (!response.ok) {
    const err = new Error('Failed to list webhooks for repository');
    err.status = response.status === 404 ? 404 : 502;
    throw err;
  }
  return response.json();
}

// Idempotent: if a hook already pointed at our webhook URL exists on this
// repo (e.g. a previous watchRepo() call that half-completed), reuse it
// instead of creating a duplicate that would double-fire every push.
async function createWebhook(userId, { owner, repo }) {
  if (!githubConfig.isWebhookConfigured()) {
    const err = new Error('GitHub webhook is not configured (GITHUB_WEBHOOK_SECRET / GITHUB_WEBHOOK_URL)');
    err.status = 503;
    throw err;
  }

  const existing = await listWebhooks(userId, { owner, repo });
  const ours = existing.find((hook) => hook.config && hook.config.url === env.github.webhookUrl);
  if (ours) return { id: ours.id, url: ours.config.url, reused: true };

  const connection = await getConnection(userId);
  const response = await fetchWithTimeout(`${githubConfig.API_BASE}/repos/${owner}/${repo}/hooks`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${connection.accessToken}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
      'user-agent': 'patchline',
    },
    body: JSON.stringify({
      name: 'web',
      active: true,
      events: ['push'],
      config: {
        url: env.github.webhookUrl,
        content_type: 'json',
        secret: env.github.webhookSecret,
        insecure_ssl: '0',
      },
    }),
    timeoutMs: env.timeouts.github,
  });
  const data = await response.json();
  if (!response.ok) {
    const err = new Error(data?.message || 'GitHub rejected the webhook creation request');
    err.status = response.status === 404 ? 404 : 502;
    throw err;
  }
  return { id: data.id, url: data.config?.url, reused: false };
}

async function deleteWebhook(userId, { owner, repo, hookId }) {
  const connection = await getConnection(userId);
  const response = await fetchWithTimeout(`${githubConfig.API_BASE}/repos/${owner}/${repo}/hooks/${hookId}`, {
    method: 'DELETE',
    headers: { authorization: `Bearer ${connection.accessToken}`, accept: 'application/vnd.github+json', 'user-agent': 'patchline' },
    timeoutMs: env.timeouts.github,
  });
  // 404 is fine here — the hook may have already been removed on GitHub's
  // side (e.g. manually), and unwatchRepo() should still clear our record.
  if (!response.ok && response.status !== 404) {
    const err = new Error('Failed to delete GitHub webhook');
    err.status = 502;
    throw err;
  }
}

module.exports = {
  getConnection,
  listRepos,
  getRepo,
  createIssue,
  createPullRequest,
  listWebhooks,
  createWebhook,
  deleteWebhook,
};

