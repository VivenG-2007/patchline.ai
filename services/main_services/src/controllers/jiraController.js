const { body, param, query } = require('express-validator');
const jiraConfig = require('../config/jira');
const jiraService = require('../services/jiraService');
const tokenStore = require('../services/jiraTokenStore');
const oauthState = require('../utils/oauthState');
const { sanitizeReturnTo } = require('../utils/safeRedirect');
const env = require('../config/env');
const logger = require('../config/logger');

function assertConfigured(req) {
  if (!jiraConfig.isConfigured()) {
    const err = new Error('Jira OAuth is not configured (JIRA_CLIENT_ID / JIRA_CLIENT_SECRET / JIRA_REDIRECT_URI / JIRA_PROJECT_KEY)');
    err.status = 503;
    throw err;
  }
}

const oauthStartValidators = [query('redirect').optional().isString().isLength({ max: 200 })];

// GET /api/jira/oauth/start — requires the user to already be logged into
// THIS app (requireAuth ran first). Redirects the browser to Atlassian's
// consent screen. Must be a real navigation, not an XHR call, so the user
// can actually see and approve the Jira login prompt.
// Accepts ?redirect=/some/path so callers (e.g. the onboarding wizard) get
// sent back to where they started instead of always landing on /jira.
async function oauthStart(req, res, next) {
  try {
    assertConfigured(req);
    const returnTo = sanitizeReturnTo(req.query.redirect, '/jira');
    const state = await oauthState.createState('jira', req.user.id, returnTo);
    return res.redirect(jiraConfig.buildAuthorizationUrl(state));
  } catch (err) {
    return next(err);
  }
}

// GET /api/jira/oauth/callback — Atlassian redirects the browser here after
// consent. NOT behind requireAuth (Atlassian's redirect carries no app JWT)
// — the `state` param is what proves which logged-in user initiated this.
async function oauthCallback(req, res, next) {
  try {
    assertConfigured(req);
    const { code, state, error: oauthError } = req.query;

    if (oauthError) {
      return res.redirect(`${env.frontendUrl}/jira?error=${encodeURIComponent(String(oauthError))}`);
    }
    if (!code || !state) {
      return res.redirect(`${env.frontendUrl}/jira?error=missing_code_or_state`);
    }

    const consumed = await oauthState.consumeState('jira', state);
    if (!consumed) {
      return res.redirect(`${env.frontendUrl}/jira?error=state_expired_or_invalid`);
    }
    const { userId } = consumed;
    const returnTo = sanitizeReturnTo(consumed.returnTo, '/jira');

    const tokens = await jiraConfig.exchangeCodeForTokens(code);
    const resources = await jiraConfig.getAccessibleResources(tokens.access_token);
    if (!resources.length) {
      return res.redirect(`${env.frontendUrl}/jira?error=no_accessible_sites`);
    }
    // A user could grant access to multiple Jira sites — this template wires
    // up the first one. Extend this to let them pick if you need multi-site support.
    const site = resources[0];

    if (!tokens.refresh_token) {
      logger.warn({ userId }, 'Jira OAuth token exchange did not return a refresh token (offline_access scope missing?)');
      return res.redirect(`${env.frontendUrl}/jira?error=${encodeURIComponent('No refresh token received from Jira. Ensure offline_access scope is enabled in Atlassian Developer Console.')}`);
    }

    await tokenStore.upsertConnection({
      userId,
      cloudId: site.id,
      siteUrl: site.url,
      siteName: site.name,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: new Date(Date.now() + (tokens.expires_in || 3600) * 1000),
    });

    logger.info({ userId, site: site.name }, 'Jira account connected');
    const separator = returnTo.includes('?') ? '&' : '?';
    return res.redirect(`${env.frontendUrl}${returnTo}${separator}connected=true&provider=jira`);
  } catch (err) {
    logger.error({ err }, 'Jira OAuth callback failed');
    const msg = err.message || 'oauth_failed';
    return res.redirect(`${env.frontendUrl}/jira?error=${encodeURIComponent(msg)}`);
  }
}

// GET /api/jira/status — does the current user have Jira connected?
async function status(req, res, next) {
  try {
    const connection = await tokenStore.getConnection(req.user.id);
    if (!connection) return res.status(200).json({ connected: false });
    return res.status(200).json({ connected: true, siteName: connection.siteName, siteUrl: connection.siteUrl });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/jira/disconnect — revokes locally stored tokens. (Does not
// call Atlassian's revoke endpoint — add one if you need server-side
// revocation too; deleting our copy already stops this app from using them.)
async function disconnect(req, res, next) {
  try {
    await tokenStore.deleteConnection(req.user.id);
    return res.status(200).json({ message: 'Jira disconnected' });
  } catch (err) {
    return next(err);
  }
}

const createIssueValidators = [
  body('summary').trim().isLength({ min: 1, max: 250 }),
  body('description').trim().isLength({ min: 1, max: 5000 }),
  body('issueType').optional().isString(),
];

async function createIssue(req, res, next) {
  try {
    const { summary, description, issueType } = req.body;
    const issue = await jiraService.createIssue({ userId: req.user.id, summary, description, issueType });
    return res.status(201).json({ issue });
  } catch (err) {
    return next(err);
  }
}

const getIssueValidators = [param('key').trim().isLength({ min: 1, max: 50 })];

async function getIssue(req, res, next) {
  try {
    const issue = await jiraService.getIssue({ userId: req.user.id, issueKey: req.params.key });
    return res.status(200).json({ issue });
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  oauthStart,
  oauthStartValidators,
  oauthCallback,
  status,
  disconnect,
  createIssue,
  getIssue,
  createIssueValidators,
  getIssueValidators,
};
