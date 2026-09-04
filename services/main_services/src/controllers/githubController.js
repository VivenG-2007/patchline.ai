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
  if (!githubConfig.isConfigured()) {
    const err = new Error('GitHub OAuth is not configured (GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET / GITHUB_REDIRECT_URI)');
    err.status = 503;
    throw err;
  }
}

const oauthStartValidators = [query('redirect').optional().isString().isLength({ max: 200 })];

// ── GitHub App install flow (opt-in, GITHUB_AUTH_MODE=github_app) ──
// Parallel to oauthStart/oauthCallback above, not a replacement — see
// docs/github-app-migration.md. "Installing" an App is a different flow
// from OAuth authorization: there's no client_secret exchange on our end at
// all, GitHub just redirects back with an installation_id once the user
// picks which repos to grant the App access to.

// GET /api/github/app/install — full-page redirect to the App's public
// install page. Requires GITHUB_APP_SLUG (the App's public URL slug, set
// once at registration time — see env.js).
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
// (setup_action is 'install' or 'update'). The actual installation<->account
// mapping is populated by the `installation` webhook event
// (handleInstallationEvent below), which is the authoritative source — this
// callback only has to know where to send the browser next; treating a
// webhook (server-to-server, signed) as the source of truth rather than this
// redirect (browser-driven, no signature) is deliberate defense against a
// forged redirect claiming an installation that was never actually granted.
async function installCallback(req, res, next) {
  try {
    const { state, setup_action: setupAction } = req.query;
    let returnTo = '/github';
    if (state) {
      const consumed = await oauthState.consumeState('github_app_install', state);
      if (consumed && consumed.returnTo) returnTo = sanitizeReturnTo(consumed.returnTo, '/github');
    }
    const separator = returnTo.includes('?') ? '&' : '?';
    return res.redirect(`${env.frontendUrl}${returnTo}${separator}github_app_setup=${encodeURIComponent(setupAction || 'unknown')}`);
  } catch (err) {
    logger.error({ err }, 'GitHub App install callback failed');
    return res.redirect(`${env.frontendUrl}/github?error=github_app_install_failed`);
  }
}

async function oauthStart(req, res, next) {
  // GET /api/github/oauth/start — same pattern as Jira's: requires the user
  // already logged into this app, then does a full-page redirect to GitHub's
  // consent screen (not an XHR call — the user needs to actually see it).
  // Accepts ?redirect=/some/path so callers (e.g. the onboarding wizard) get
  // sent back to where they started instead of always landing on /github.
  try {
    assertConfigured();
    const returnTo = sanitizeReturnTo(req.query.redirect, '/github');
    const state = await oauthState.createState('github', req.user.id, returnTo);
    return res.redirect(githubConfig.buildAuthorizationUrl(state));
  } catch (err) {
    return next(err);
  }
}

// GET /api/github/oauth/start-url — same as oauthStart but returns JSON
// { url } instead of doing a browser redirect. Lets the frontend call this
// via axios (which sends the Authorization: Bearer header) and then navigate
// window.location.href to the returned URL. Needed in cross-domain production
// where a direct browser navigation to /oauth/start carries no cookie/header.
async function oauthStartUrl(req, res, next) {
  try {
    assertConfigured();
    const returnTo = sanitizeReturnTo(req.query.redirect, '/github');
    const state = await oauthState.createState('github', req.user.id, returnTo);
    return res.status(200).json({ url: githubConfig.buildAuthorizationUrl(state) });
  } catch (err) {
    return next(err);
  }
}

// GET /api/github/oauth/callback — public (no requireAuth): GitHub's
// redirect carries no app JWT. The one-time `state` value is what
// authenticates it instead.
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
    const connection = await tokenStore.getConnection(req.user.id);
    if (!connection) return res.status(200).json({ connected: false });
    return res.status(200).json({
      connected: true,
      username: connection.username,
      avatarUrl: connection.avatarUrl,
      scopes: connection.scopes,
    });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/github/disconnect — fully tears down a user's GitHub
// connection, not just the OAuth token row. Order matters:
//
//   1. Delete every push webhook this connection created (needs the
//      access token, which is still valid at this point — this MUST run
//      before step 3's revoke, or GitHub will already be rejecting the
//      token by the time we try to use it here).
//   2. Delete the watched_repositories rows themselves — leaving them
//      behind after disconnecting would mean handleWebhook's Gate 1
//      ("is this repository registered?") still says yes, but Gate 2's
//      `tokenStore.getConnection(watched.userId)` lookup now returns
//      null, so every future push silently no-ops with "owner is not
//      connected" forever: a permanently stale, invisible watch instead
//      of an honest "disconnected" state.
//   3. Revoke the token at GitHub (best effort — classic OAuth App
//      tokens never expire on their own, so this is the only way
//      disconnecting here also invalidates the credential at GitHub
//      instead of just forgetting our local copy of a still-live one).
//   4. Delete the github_connections row.
//
// Each step is best-effort past step 1 in the sense that a failure in one
// doesn't block the next — a GitHub API hiccup deleting one webhook, or a
// failed revoke, must never leave the user stuck unable to disconnect.
async function disconnect(req, res, next) {
  try {
    const connection = await tokenStore.getConnection(req.user.id);

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
    }
    await tokenStore.deleteConnection(req.user.id);

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

// POST /api/github/watched — registers a repository for continuous
// scanning: creates (idempotently) a push webhook on it and writes the
// watched_repositories row that githubController.handleWebhook checks on
// every subsequent push.
async function watchRepo(req, res, next) {
  try {
    const { repoOwner, repoName, branch = 'main' } = req.body;
    const repo = await githubService.getRepo(req.user.id, { owner: repoOwner, repo: repoName });
    const hook = await githubService.createWebhook(req.user.id, { owner: repoOwner, repo: repoName });

    const record = await watchedRepoStore.upsertWatch({
      userId: req.user.id,
      repositoryId: repo.id,
      githubRepo: repo.fullName,
      branch: branch || repo.defaultBranch || 'main',
      installationId: null, // OAuth App flow — no GitHub App installation; kept for schema parity
      webhookId: hook.id,
      webhookActive: true,
      autoRescan: true,
    });

    logger.info({ userId: req.user.id, repo: repo.fullName, webhookReused: hook.reused }, 'repository registered for continuous scanning');
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
        // Best-effort — still remove our record even if GitHub's side fails
        // (hook may already be gone, token may be stale, etc).
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

// PATCH /api/github/watched/:repositoryId/settings — the "Continuous
// Security Scanning" checkbox on the repository page.
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

// POST /api/github/webhook — public: GitHub POSTs every push here. This is
// the three-state gate the product spec calls for:
//   1. repository not registered           -> ignore
//   2. registered, autoRescan disabled     -> ignore
//   3. registered, autoRescan enabled      -> enqueue an incremental rescan
async function handleWebhook(req, res, next) {
  try {
    const event = req.headers['x-github-event'];
    const signature = req.headers['x-hub-signature-256'];

    // GitHub App events (installation lifecycle) are signed with the App's
    // own webhook secret, never the OAuth flow's per-repo push secret —
    // check for these FIRST and verify against the right secret, since
    // falling through to the push-webhook branch below would verify against
    // the wrong secret and reject every legitimate installation event.
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

    if (!githubConfig.isWebhookConfigured()) {
      return res.status(503).json({ error: { message: 'GitHub webhook is not configured on this server', code: 'WEBHOOK_NOT_CONFIGURED' } });
    }

    if (!githubConfig.verifyWebhookSignature(req.rawBody, signature)) {
      logger.warn({ requestId: req.id }, 'GitHub webhook signature verification failed');
      return res.status(401).json({ error: { message: 'Invalid webhook signature', code: 'INVALID_SIGNATURE' } });
    }

    // GitHub fires a harmless "ping" the moment a webhook is created — just
    // acknowledge it so createWebhook()'s own test delivery succeeds.
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
    // A random repository we've never scanned must never auto-trigger a scan
    // — this is the check that enforces that.
    const watched = await watchedRepoStore.getByRepositoryId(repositoryId);
    if (!watched) {
      logger.info({ repositoryId, requestId: req.id }, 'push event for an unregistered repository — ignoring');
      return res.status(200).json({ message: 'repository not registered — ignored', scanned: false });
    }

    // Only rescan pushes to the branch we're actually tracking — a push to
    // some unrelated feature branch shouldn't trigger a rescan of main.
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

    const connection = await tokenStore.getConnection(watched.userId);
    if (!connection) {
      logger.warn({ repositoryId, userId: watched.userId }, 'watched repository owner has no GitHub connection — cannot rescan');
      return res.status(200).json({ message: 'repository owner is not connected to GitHub — ignored', scanned: false });
    }

    // Changed files across every commit in the push — this is what lets
    // ai-storage-service's /scan run incrementally instead of re-walking and
    // re-fetching the entire repo tree on every push.
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
      githubToken: connection.accessToken,
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

// `installation` fires when the App is installed, uninstalled, or its
// permissions/repository access changes; `installation_repositories` fires
// specifically when repos are added/removed from an existing installation
// (repository_selection: 'selected'). Both carry the full `installation`
// object GitHub's docs describe — https://docs.github.com/en/webhooks/webhook-events-and-payloads#installation
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

  // Covers 'created', 'new_permissions_accepted', 'unsuspend' (installation
  // event) and every installation_repositories action — all of these mean
  // "this installation exists and is usable", so upsert unconditionally
  // rather than branching on every possible action string individually.
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
