const express = require('express');
const ctrl = require('../controllers/githubController');
const validate = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const { strictLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// Public: GitHub's own redirect lands here with no app JWT attached — the
// `state` param (bound to a user id in Redis by oauth/start) authenticates
// this request instead. Same pattern as jiraRoutes.js.
router.get('/oauth/callback', ctrl.oauthCallback);

// Public: same reasoning as oauth/callback above, but for the GitHub App
// install flow (see docs/github-app-migration.md) — GitHub redirects the
// browser here with no app JWT, authenticated by the one-time `state` value
// instead.
router.get('/app/install/callback', ctrl.installCallback);

// Public: GitHub's own webhook POST — authenticated via the
// X-Hub-Signature-256 HMAC signature (see ctrl.handleWebhook), not a user
// JWT, so this must stay reachable without requireAuth. Handles both the
// OAuth flow's push events AND the GitHub App's installation lifecycle
// events (verified against separate secrets internally).
router.post('/webhook', ctrl.handleWebhook);

router.use(requireAuth, strictLimiter);
router.get('/oauth/start', ctrl.oauthStartValidators, validate, ctrl.oauthStart);
// JSON-returning variant — frontend calls this via axios (Bearer header),
// then navigates window.location.href to the returned URL.
router.get('/oauth/start-url', ctrl.oauthStartValidators, validate, ctrl.oauthStartUrl);
router.get('/app/install', ctrl.installStart);
router.get('/status', ctrl.status);
router.delete('/disconnect', ctrl.disconnect);
router.get('/repos', ctrl.listReposValidators, validate, ctrl.listRepos);
router.post('/issues', ctrl.createIssueValidators, validate, ctrl.createIssue);

// Continuous scanning (watch / auto-rescan)
router.get('/watched', ctrl.listWatched);
router.post('/watched', ctrl.watchRepoValidators, validate, ctrl.watchRepo);
router.delete('/watched/:repositoryId', ctrl.unwatchRepo);
router.patch('/watched/:repositoryId/settings', ctrl.updateRepoSettingsValidators, validate, ctrl.updateRepoSettings);

module.exports = router;
