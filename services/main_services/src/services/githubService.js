const { fetchWithTimeout } = require('../utils/httpClient');
const githubConfig = require('../config/github');
const githubApp = require('../config/githubApp');
const tokenStore = require('./githubTokenStore');
const installationStore = require('./githubAppInstallationStore');
const env = require('../config/env');
const logger = require('../config/logger');

async function getConnection(userId) {
  // 1. Try GitHub App installation token
  if (githubApp.isConfigured()) {
    try {
      let installation = await installationStore.getInstallationForUser(userId);

      // If not linked yet in DB, auto-discover live installations from GitHub API
      if (!installation) {
        const liveInstallations = await githubApp.listAppInstallations();
        if (Array.isArray(liveInstallations) && liveInstallations.length > 0) {
          const first = liveInstallations[0];
          await installationStore.upsertInstallation({
            installationId: first.id,
            accountLogin: first.account ? first.account.login : 'user',
            accountType: first.account ? first.account.type : 'User',
            connectedByUserId: userId,
            repositorySelection: first.repository_selection || 'all',
          });
          installation = {
            installationId: first.id,
            accountLogin: first.account ? first.account.login : 'user',
          };
        }
      }

      if (installation) {
        const { token } = await githubApp.getInstallationToken(installation.installationId);
        return {
          accessToken: token,
          type: 'github_app',
          installationId: installation.installationId,
          username: installation.accountLogin,
        };
      }
    } catch (err) {
      logger.error({ err: err.message, userId }, 'GitHub App installation resolution failed');
      if (env.githubAuthMode === 'github_app') {
        const enhancedErr = new Error(`GitHub App installation found but token generation failed: ${err.message}`);
        enhancedErr.status = err.status || 502;
        enhancedErr.code = 'GITHUB_APP_TOKEN_ERROR';
        throw enhancedErr;
      }
    }
  }

  // 2. Fall back to classic OAuth App connection if present
  const connection = await tokenStore.getConnection(userId);
  if (connection) {
    return { ...connection, type: 'oauth_app' };
  }

  const err = new Error('GitHub is not connected for this account — visit /api/github/oauth/start first');
  err.status = 409;
  err.code = 'GITHUB_NOT_CONNECTED';
  throw err;
}

async function listRepos(userId, { perPage = 100 } = {}) {
  const connection = await getConnection(userId);

  if (connection.type === 'github_app') {
    const response = await fetchWithTimeout(`${githubConfig.API_BASE}/installation/repositories?per_page=${perPage}`, {
      headers: { authorization: `Bearer ${connection.accessToken}`, accept: 'application/vnd.github+json', 'user-agent': 'patchline' },
      timeoutMs: env.timeouts.github,
    });
    if (!response.ok) {
      const errBody = await response.text().catch(() => '');
      logger.error({ status: response.status, errBody }, 'Failed to list GitHub repositories from App installation');
      const err = new Error(`Failed to list GitHub repositories from App installation: ${response.status} ${errBody}`.trim());
      err.status = 502;
      throw err;
    }
    const data = await response.json();
    const repos = Array.isArray(data.repositories) ? data.repositories : [];
    return repos.map((r) => ({
      id: r.id,
      fullName: r.full_name,
      private: r.private,
      url: r.html_url,
      description: r.description,
      updatedAt: r.updated_at,
    }));
  }

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
