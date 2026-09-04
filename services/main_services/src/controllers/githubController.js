const { body, param, query } = require('express-validator');
const githubConfig = require('../config/github');
const githubApp = require('../config/githubApp');
const githubService = require('../services/githubService');
const tokenStore = require('../services/githubTokenStore');
const installationStore = require('../services/githubAppInstallationStore');
const watchedRepoStore = require('../services/watchedRepoStore');
const scanTriggerService = require('../services/scanTriggerService');
const oauthState = require('../utils/oauthState');
const { sanitizeReturnTo } = require('../utils/safeRedirect');
const env = require('../config/env');
const logger = require('../config/logger');

function assertConfigured() {
  if (env.githubAuthMode === 'github_app') {
    if (!env.githubApp.slug) {
      const err = new Error('GitHub App slug is not configured (GITHUB_APP_SLUG)');
      err.status = 503;
      throw err;
    }
    return;
  }
  if (!githubConfig.isConfigured()) {
    const err = new Error('GitHub OAuth is not configured (GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET / GITHUB_REDIRECT_URI)');
    err.status = 503;
    throw err;
  }
}

const oauthStartValidators = [query('redirect').optional().isString().isLength({ max: 200 })];

// ── GitHub App install flow (opt-in / default, GITHUB_AUTH_MODE=github_app) ──

// GET /api/github/app/install — full-page redirect to the App's public install page.
async function installStart(req, res, next) {
  try {
    if (!env.githubApp.slug) {
      const err = new Error('GitHub App slug is not configured (GITHUB_APP_SLUG)');
      err.status = 503;
      throw err;
    }
    const returnTo = sanitizeReturnTo(req.query.redirect, '/github');
    const state = await oauthState.createState('github_app_install', req.user.id, returnTo);
    return res.redirect(`https://github.com/apps/${env.githubApp.slug}/installations/new?state=${encodeURIComponent(state)}`);
  } catch (err) {
    return next(err);
  }
}

// GET /api/github/app/install/callback — GitHub redirects here after the
// user finishes the install flow, with ?installation_id=&setup_action=
async function installCallback(req, res, next) {
  try {
    const { state, setup_action: setupAction, installation_id: installationId } = req.query;
    let returnTo = '/github';
    let userId = null;
    if (state) {
      const consumed = await oauthState.consumeState('github_app_install', state);
      if (consumed) {
        if (consumed.returnTo) returnTo = sanitizeReturnTo(consumed.returnTo, '/github');
        userId = consumed.userId;
      }
    }
    if (installationId && userId) {
      await installationStore.upsertInstallation({
        installationId: Number(installationId),
        connectedByUserId: userId,
      });
    }
    const separator = returnTo.includes('?') ? '&' : '?';
    return res.redirect(`${env.frontendUrl}${returnTo}${separator}connected=true&provider=github&github_app_setup=${encodeURIComponent(setupAction || 'unknown')}`);
  } catch (err) {
    logger.error({ err }, 'GitHub App install callback failed');
    return res.redirect(`${env.frontendUrl}/github?error=github_app_install_failed`);
  }
}

async function oauthStart(req, res, next) {
  try {
    if (env.githubAuthMode === 'github_app') {
      return installStart(req, res, next);
    }
    assertConfigured();
    const returnTo = sanitizeReturnTo(req.query.redirect, '/github');
    const state = await oauthState.createState('github', req.user.id, returnTo);
    return res.redirect(githubConfig.buildAuthorizationUrl(state));
  } catch (err) {
    return next(err);
  }
}

// GET /api/github/oauth/start-url — returns JSON { url } for client-side navigation.
async function oauthStartUrl(req, res, next) {
  try {
    if (env.githubAuthMode === 'github_app') {
      if (!env.githubApp.slug) {
        const err = new Error('GitHub App slug is not configured (GITHUB_APP_SLUG)');
        err.status = 503;
        throw err;
      }
      const returnTo = sanitizeReturnTo(req.query.redirect, '/github');
      const state = await oauthState.createState('github_app_install', req.user.id, returnTo);
      return res.status(200).json({ url: `https://github.com/apps/${env.githubApp.slug}/installations/new?state=${encodeURIComponent(state)}` });
    }
    assertConfigured();
    const returnTo = sanitizeReturnTo(req.query.redirect, '/github');
    const state = await oauthState.createState('github', req.user.id, returnTo);
    return res.status(200).json({ url: githubConfig.buildAuthorizationUrl(state) });
  } catch (err) {
    return next(err);
  }
}

// GET /api/github/oauth/callback — classic OAuth App callback
async function oauthCallback(req, res, next) {
  try {
    assertConfigured();
    const { code, state, error: oauthError } = req.query;

    if (oauthError) {
      return res.redirect(`${env.frontendUrl}/github?error=${encodeURIComponent(String(oauthError))}`);
    }
    if (!code || !state) {
      return res.redirect(`${env.frontendUrl}/github?error=missing_code_or_state`);
    }

    const consumed = await oauthState.consumeState('github', state);
    if (!consumed) {
      return res.redirect(`${env.frontendUrl}/github?error=state_expired_or_invalid`);
    }
    const { userId } = consumed;
    const returnTo = sanitizeReturnTo(consumed.returnTo, '/github');

    const tokenResponse = await githubConfig.exchangeCodeForToken(code);
    const profile = await githubConfig.getAuthenticatedUser(tokenResponse.access_token);

    await tokenStore.upsertConnection({
      userId,
      githubUserId: profile.id,
      username: profile.login,
      avatarUrl: profile.avatar_url,
      accessToken: tokenResponse.access_token,
      scopes: tokenResponse.scope,
    });

    logger.info({ userId, username: profile.login }, 'GitHub account connected');
    const separator = returnTo.includes('?') ? '&' : '?';
    return res.redirect(`${env.frontendUrl}${returnTo}${separator}connected=true&provider=github`);
  } catch (err) {
    logger.error({ err }, 'GitHub OAuth callback failed');
    const msg = err.message || 'oauth_failed';
    return res.redirect(`${env.frontendUrl}/github?error=${encodeURIComponent(msg)}`);
  }
}

// GET /api/github/status
async function status(req, res, next) {
  try {
    if (githubApp.isConfigured()) {
      let appInstallation = await installationStore.getInstallationForUser(req.user.id);
      if (!appInstallation) {
        const liveInstallations = await githubApp.listAppInstallations();
        if (Array.isArray(liveInstallations) && liveInstallations.length > 0) {
          const first = liveInstallations[0];
          await installationStore.upsertInstallation({
            installationId: first.id,
            accountLogin: first.account ? first.account.login : 'user',
            accountType: first.account ? first.account.type : 'User',
            connectedByUserId: req.user.id,
            repositorySelection: first.repository_selection || 'all',
          });
          appInstallation = {
            installationId: first.id,
            accountLogin: first.account ? first.account.login : 'user',
          };
        }
      }
      if (appInstallation) {
        return res.status(200).json({
          connected: true,
          username: appInstallation.accountLogin,
          type: 'github_app',
          installationId: appInstallation.installationId,
        });
      }
    }
    const connection = await tokenStore.getConnection(req.user.id);
    if (!connection) return res.status(200).json({ connected: false });
    return res.status(200).json({
      connected: true,
      username: connection.username,
      avatarUrl: connection.avatarUrl,
      scopes: connection.scopes,
      type: 'oauth_app',
    });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/github/disconnect
async function disconnect(req, res, next) {
  try {
    const connection = await tokenStore.getConnection(req.user.id);
    const appInstallation = await installationStore.getInstallationForUser(req.user.id);

    const watchedRepos = await watchedRepoStore.listForUser(req.user.id);
    let webhooksRemoved = 0;
    for (const watched of watchedRepos) {
      if (watched.webhookId && connection) {
        try {
          const [owner, repo] = watched.githubRepo.split('/');
          await githubService.deleteWebhook(req.user.id, { owner, repo, hookId: watched.webhookId });
          webhooksRemoved += 1;
        } catch (hookErr) {
          logger.warn(
            { hookErr, userId: req.user.id, repo: watched.githubRepo },
            'failed to delete GitHub webhook during disconnect — removing watch record anyway'
          );
        }
      }
      await watchedRepoStore.deleteWatch(watched.repositoryId);
    }

    if (connection) {
      const result = await githubConfig.revokeToken(connection.accessToken);
      if (!result.revoked) {
        logger.warn({ userId: req.user.id, reason: result.reason }, 'GitHub token revocation failed — removing local connection anyway');
      }
      await tokenStore.deleteConnection(req.user.id);
    }

    if (appInstallation) {
      await installationStore.deleteInstallationForUser(req.user.id);
    }

    logger.info(
      { userId: req.user.id, watchedReposRemoved: watchedRepos.length, webhooksRemoved },
      'GitHub account disconnected'
    );
    return res.status(200).json({
      message: 'GitHub disconnected',
      watchedReposRemoved: watchedRepos.length,
    });
  } catch (err) {
    return next(err);
  }
}

const listReposValidators = [query('perPage').optional().isInt({ min: 1, max: 100 })];

async function listRepos(req, res, next) {
  try {
    const repos = await githubService.listRepos(req.user.id, { perPage: req.query.perPage ? Number(req.query.perPage) : undefined });
    return res.status(200).json({ repos });
  } catch (err) {
    return next(err);
  }
}

const createIssueValidators = [
  body('owner').trim().isLength({ min: 1, max: 100 }),
  body('repo').trim().isLength({ min: 1, max: 100 }),
  body('title').trim().isLength({ min: 1, max: 250 }),
  body('body').optional().isString(),
];

async function createIssue(req, res, next) {
  try {
    const { owner, repo, title, body } = req.body;
    const issue = await githubService.createIssue(req.user.id, { owner, repo, title, body });
    return res.status(201).json({ issue });
  } catch (err) {
    return next(err);
  }
}

// ──────────────────────── Continuous scanning (watch / webhook) ────────────────────────

const watchRepoValidators = [
  body('repoOwner').trim().isLength({ min: 1, max: 100 }),
  body('repoName').trim().isLength({ min: 1, max: 100 }),
  body('branch').optional().trim().isLength({ min: 1, max: 200 }),
];

// POST /api/github/watched — registers a repository for continuous scanning.
async function watchRepo(req, res, next) {
  try {
    const { repoOwner, repoName, branch = 'main' } = req.body;
    const repo = await githubService.getRepo(req.user.id, { owner: repoOwner, repo: repoName });

    let hookId = null;
    let hookReused = false;
    let installationId = null;

    if (env.githubAuthMode === 'github_app' && githubApp.isConfigured()) {
      const appInstallation = await installationStore.getInstallationForUser(req.user.id);
      installationId = appInstallation ? appInstallation.installationId : null;
    } else {
      try {
        const hook = await githubService.createWebhook(req.user.id, { owner: repoOwner, repo: repoName });
        hookId = hook.id;
        hookReused = hook.reused;
      } catch (err) {
        logger.warn({ err: err.message }, 'Could not create per-repo webhook');
      }
    }

    const record = await watchedRepoStore.upsertWatch({
      userId: req.user.id,
      repositoryId: repo.id,
      githubRepo: repo.fullName,
      branch: branch || repo.defaultBranch || 'main',
      installationId: installationId || null,
      webhookId: hookId,
      webhookActive: true,
      autoRescan: true,
    });

    logger.info({ userId: req.user.id, repo: repo.fullName, webhookReused: hookReused }, 'repository registered for continuous scanning');
    return res.status(201).json({ repository: record });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/github/watched/:repositoryId
async function unwatchRepo(req, res, next) {
  try {
    const { repositoryId } = req.params;
    const watched = await watchedRepoStore.getByRepositoryId(repositoryId);
    if (!watched || watched.userId !== req.user.id) {
      return res.status(404).json({ error: { message: 'Watched repository not found', code: 'NOT_FOUND', requestId: req.id } });
    }

    if (watched.webhookId) {
      try {
        const [owner, repo] = watched.githubRepo.split('/');
        await githubService.deleteWebhook(req.user.id, { owner, repo, hookId: watched.webhookId });
      } catch (hookErr) {
        logger.warn({ hookErr, repositoryId }, 'failed to delete GitHub webhook — removing watch record anyway');
      }
    }

    await watchedRepoStore.deleteWatch(repositoryId);
    return res.status(200).json({ message: 'Repository unwatched' });
  } catch (err) {
    return next(err);
  }
}

const updateRepoSettingsValidators = [body('autoRescan').isBoolean()];

// PATCH /api/github/watched/:repositoryId/settings
async function updateRepoSettings(req, res, next) {
  try {
    const { repositoryId } = req.params;
    const watched = await watchedRepoStore.getByRepositoryId(repositoryId);
    if (!watched || watched.userId !== req.user.id) {
      return res.status(404).json({ error: { message: 'Watched repository not found', code: 'NOT_FOUND', requestId: req.id } });
    }
    const updated = await watchedRepoStore.updateSettings(repositoryId, { autoRescan: req.body.autoRescan });
    return res.status(200).json({ repository: updated });
  } catch (err) {
    return next(err);
  }
}

// GET /api/github/watched
async function listWatched(req, res, next) {
  try {
    const repositories = await watchedRepoStore.listForUser(req.user.id);
    return res.status(200).json({ repositories });
  } catch (err) {
    return next(err);
  }
}

// POST /api/github/webhook — public webhook handler for push & installation events.
async function handleWebhook(req, res, next) {
  try {
    const event = req.headers['x-github-event'];
    const signature = req.headers['x-hub-signature-256'];

    // GitHub App events (installation lifecycle)
    if (event === 'installation' || event === 'installation_repositories') {
      if (!env.githubApp.webhookSecret) {
        return res.status(503).json({ error: { message: 'GitHub App webhook is not configured on this server', code: 'GITHUB_APP_WEBHOOK_NOT_CONFIGURED' } });
      }
      if (!githubConfig.verifyWebhookSignatureWithSecret(req.rawBody, signature, env.githubApp.webhookSecret)) {
        logger.warn({ requestId: req.id, event }, 'GitHub App webhook signature verification failed');
        return res.status(401).json({ error: { message: 'Invalid webhook signature', code: 'INVALID_SIGNATURE' } });
      }
      return handleInstallationEvent(req, res);
    }

    if (env.githubAuthMode === 'github_app' && env.githubApp.webhookSecret) {
      if (!githubConfig.verifyWebhookSignatureWithSecret(req.rawBody, signature, env.githubApp.webhookSecret)) {
        logger.warn({ requestId: req.id }, 'GitHub App push webhook signature verification failed');
        return res.status(401).json({ error: { message: 'Invalid webhook signature', code: 'INVALID_SIGNATURE' } });
      }
    } else {
      if (!githubConfig.isWebhookConfigured()) {
        return res.status(503).json({ error: { message: 'GitHub webhook is not configured on this server', code: 'WEBHOOK_NOT_CONFIGURED' } });
      }
      if (!githubConfig.verifyWebhookSignature(req.rawBody, signature)) {
        logger.warn({ requestId: req.id }, 'GitHub webhook signature verification failed');
        return res.status(401).json({ error: { message: 'Invalid webhook signature', code: 'INVALID_SIGNATURE' } });
      }
    }

    if (event === 'ping') {
      return res.status(200).json({ message: 'pong' });
    }
    if (event !== 'push') {
      return res.status(200).json({ message: `ignored event type '${event}'`, scanned: false });
    }

    const payload = req.body;
    const repositoryId = payload.repository && payload.repository.id != null ? String(payload.repository.id) : null;
    if (!repositoryId) {
      return res.status(400).json({ error: { message: "Push payload is missing 'repository.id'", code: 'BAD_PAYLOAD', requestId: req.id } });
    }

    // ── Gate 1: is this repository registered at all? ──
    const watched = await watchedRepoStore.getByRepositoryId(repositoryId);
    if (!watched) {
      logger.info({ repositoryId, requestId: req.id }, 'push event for an unregistered repository — ignoring');
      return res.status(200).json({ message: 'repository not registered — ignored', scanned: false });
    }

    // Branch match check
    const pushedBranch = String(payload.ref || '').replace('refs/heads/', '');
    if (watched.branch && pushedBranch && pushedBranch !== watched.branch) {
      logger.info({ repositoryId, pushedBranch, trackedBranch: watched.branch }, 'push to untracked branch — ignoring');
      return res.status(200).json({ message: `push to untracked branch '${pushedBranch}' — ignored`, scanned: false });
    }

    // ── Gate 2: is auto-rescan turned on for this repository? ──
    if (!watched.autoRescan) {
      logger.info({ repositoryId, requestId: req.id }, 'auto-rescan disabled for this repository — ignoring push');
      return res.status(200).json({ message: 'auto-rescan disabled — ignored', scanned: false });
    }

    let githubToken = null;
    if (payload.installation && payload.installation.id) {
      try {
        const { token } = await githubApp.getInstallationToken(payload.installation.id);
        githubToken = token;
      } catch (tokenErr) {
        logger.warn({ err: tokenErr.message }, 'Failed to mint token from payload installation');
      }
    }
    if (!githubToken && watched.installationId) {
      try {
        const { token } = await githubApp.getInstallationToken(watched.installationId);
        githubToken = token;
      } catch (tokenErr) {
        logger.warn({ err: tokenErr.message }, 'Failed to mint token from watched installation');
      }
    }
    if (!githubToken) {
      const connection = await tokenStore.getConnection(watched.userId);
      if (connection) githubToken = connection.accessToken;
    }
    if (!githubToken) {
      logger.warn({ repositoryId, userId: watched.userId }, 'watched repository owner has no GitHub connection / installation — cannot rescan');
      return res.status(200).json({ message: 'repository owner is not connected to GitHub — ignored', scanned: false });
    }

    const changedFiles = Array.from(
      new Set(
        (payload.commits || []).flatMap((commit) => [...(commit.added || []), ...(commit.modified || []), ...(commit.removed || [])])
      )
    );

    const { scanId } = await scanTriggerService.enqueueScan({
      userId: watched.userId,
      repoOwner: (payload.repository.owner && (payload.repository.owner.login || payload.repository.owner.name)) || watched.githubRepo.split('/')[0],
      repoName: payload.repository.name,
      branch: watched.branch,
      githubToken,
      requestId: req.id,
      trigger: 'webhook',
      changedFiles,
      watchedRepositoryId: watched.repositoryId,
      commitSha: payload.after,
    });

    logger.info({ repositoryId, scanId, changedFileCount: changedFiles.length }, 'webhook-triggered rescan queued');
    return res.status(202).json({ message: 'rescan queued', scanId, scanned: true });
  } catch (err) {
    return next(err);
  }
}

// Handles GitHub App installation webhook lifecycle events
async function handleInstallationEvent(req, res) {
  const event = req.headers['x-github-event'];
  const { action, installation } = req.body;
  if (!installation || installation.id == null) {
    return res.status(400).json({ error: { message: "Payload is missing 'installation.id'", code: 'BAD_PAYLOAD' } });
  }

  if (event === 'installation' && (action === 'deleted' || action === 'suspend')) {
    await installationStore.deleteInstallation(installation.id);
    await githubApp.invalidateInstallationToken(installation.id);
    logger.info({ installationId: installation.id, action }, 'GitHub App installation removed');
    return res.status(200).json({ message: 'installation removed', processed: true });
  }

  await installationStore.upsertInstallation({
    installationId: installation.id,
    accountLogin: installation.account && installation.account.login,
    accountType: installation.account && installation.account.type,
    repositorySelection: installation.repository_selection,
  });
  logger.info({ installationId: installation.id, action, event }, 'GitHub App installation updated');
  return res.status(200).json({ message: 'installation updated', processed: true });
}

module.exports = {
  oauthStart,
  oauthStartUrl,
  oauthStartValidators,
  oauthCallback,
  installStart,
  installCallback,
  status,
  disconnect,
  listRepos,
  createIssue,
  listReposValidators,
  createIssueValidators,
  watchRepo,
  watchRepoValidators,
  unwatchRepo,
  updateRepoSettings,
  updateRepoSettingsValidators,
  listWatched,
  handleWebhook,
};
