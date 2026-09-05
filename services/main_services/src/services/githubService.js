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
      const installation = await installationStore.getInstallationForUser(userId);

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

async function getRepoToken(owner, repo, userId) {
  // 1. Try resolving via user's connection
  if (userId) {
    try {
      const conn = await getConnection(userId);
      if (conn?.accessToken) return conn.accessToken;
    } catch {}
  }

  // 2. Query GitHub App installation for this specific repository
  if (githubApp.isConfigured() && owner && repo) {
    try {
      const repoInstall = await githubApp.getRepoInstallation(owner, repo);
      if (repoInstall?.id) {
        const { token } = await githubApp.getInstallationToken(repoInstall.id);
        if (userId) {
          installationStore.upsertInstallation({
            installationId: repoInstall.id,
            accountLogin: repoInstall.account?.login || owner,
            connectedByUserId: userId,
            repositorySelection: repoInstall.repository_selection || 'selected',
          }).catch(() => {});
        }
        return token;
      }
    } catch (appErr) {
      logger.warn({ appErr: appErr.message, owner, repo }, 'Could not resolve repo installation token');
    }
  }

  // 3. Fall back to any user installation
  if (userId) {
    try {
      const userInstalls = await installationStore.listInstallationsForUser(userId);
      if (userInstalls.length > 0) {
        const { token } = await githubApp.getInstallationToken(userInstalls[0].installationId);
        return token;
      }
    } catch {}
  }

  return null;
}

async function createPullRequest(userId, { owner, repo, title, body, head, base = 'main', githubToken, accessToken }) {
  let token = accessToken || githubToken;
  if (!token && userId) {
    token = await getRepoToken(owner, repo, userId);
  }
  if (!token && userId) {
    try {
      const connection = await getConnection(userId);
      token = connection?.accessToken;
    } catch (connErr) {
      logger.warn({ connErr: connErr.message, userId }, 'Could not get connection for createPullRequest');
    }
  }

  if (!token) {
    const err = new Error('No GitHub token available to create pull request — connect GitHub or provide a repository token');
    err.status = 401;
    throw err;
  }

  const authHeader = token.startsWith('Bearer ') || token.startsWith('token ') ? token : (token.startsWith('ghp_') ? `token ${token}` : `Bearer ${token}`);

  const postPR = async (baseBranch, headBranch) => {
    return fetchWithTimeout(`${githubConfig.API_BASE}/repos/${owner}/${repo}/pulls`, {
      method: 'POST',
      headers: {
        authorization: authHeader,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
        'user-agent': 'patchline',
      },
      body: JSON.stringify({ title, body, head: headBranch, base: baseBranch }),
      timeoutMs: env.timeouts.github,
    });
  };

  const hasNoCommits = (d) => {
    const full = String(d?.message || '') + ' ' + (d?.errors ? JSON.stringify(d.errors) : '');
    return full.toLowerCase().includes('no commits between');
  };

  const hasAlreadyExists = (d) => {
    const full = String(d?.message || '') + ' ' + (d?.errors ? JSON.stringify(d.errors) : '');
    return full.toLowerCase().includes('already exists');
  };

  let targetBase = base || 'main';
  let response = await postPR(targetBase, head);
  let data = await response.json().catch(() => ({}));

  // If GitHub says no commits between base and head, wait for git ref replication and retry up to 2 times
  for (let attempt = 0; attempt < 2 && !response.ok && response.status === 422 && hasNoCommits(data); attempt++) {
    const waitTime = (attempt + 1) * 1500;
    logger.info({ owner, repo, head, attempt: attempt + 1, waitTime }, 'Waiting for GitHub git ref replication before retrying PR creation');
    await new Promise((r) => setTimeout(r, waitTime));
    response = await postPR(targetBase, head);
    data = await response.json().catch(() => ({}));
  }

  // If base branch failed (e.g. 422 invalid base 'main'), resolve default_branch and retry
  if (!response.ok && response.status === 422) {
    try {
      const repoResp = await fetchWithTimeout(`${githubConfig.API_BASE}/repos/${owner}/${repo}`, {
        headers: { authorization: authHeader, accept: 'application/vnd.github+json', 'user-agent': 'patchline' },
        timeoutMs: env.timeouts.github,
      });
      if (repoResp.ok) {
        const repoData = await repoResp.json();
        const defaultBranch = repoData.default_branch;
        if (defaultBranch && defaultBranch !== targetBase) {
          logger.info({ owner, repo, defaultBranch }, 'Retrying pull request creation with repo default_branch');
          targetBase = defaultBranch;
          response = await postPR(targetBase, head);
          data = await response.json().catch(() => ({}));
        }
      }
    } catch (retryErr) {
      logger.warn({ retryErr: retryErr.message }, 'Failed retrying PR creation with default branch');
    }
  }

  // If head ref is not found, try qualifying with owner:head
  if (!response.ok && response.status === 422 && !head.includes(':')) {
    response = await postPR(targetBase, `${owner}:${head}`);
    data = await response.json().catch(() => ({}));
  }

  // If a pull request already exists for this head branch, retrieve and return it
  if (!response.ok && response.status === 422 && hasAlreadyExists(data)) {
    try {
      const listResp = await fetchWithTimeout(`${githubConfig.API_BASE}/repos/${owner}/${repo}/pulls?head=${owner}:${head}&state=all`, {
        headers: { authorization: authHeader, accept: 'application/vnd.github+json', 'user-agent': 'patchline' },
        timeoutMs: env.timeouts.github,
      });
      if (listResp.ok) {
        const list = await listResp.json();
        if (Array.isArray(list) && list.length > 0) {
          logger.info({ owner, repo, head, prNumber: list[0].number }, 'Found existing PR for head branch');
          return { number: list[0].number, url: list[0].html_url, title: list[0].title };
        }
      }
    } catch (findErr) {
      logger.warn({ findErr: findErr.message }, 'Failed retrieving existing PR after 422');
    }
  }

  if (!response.ok) {
    const errorDetails = data?.errors ? JSON.stringify(data.errors) : (data?.message || response.statusText);
    const err = new Error(`GitHub rejected the Pull Request creation request: ${errorDetails}`);
    err.status = response.status === 404 ? 404 : 502;
    err.details = data;
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
  getRepoToken,
  listRepos,
  getRepo,
  createIssue,
  createPullRequest,
  listWebhooks,
  createWebhook,
  deleteWebhook,
};
