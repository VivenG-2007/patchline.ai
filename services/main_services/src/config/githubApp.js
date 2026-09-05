const jwt = require('jsonwebtoken');
const { fetchWithTimeout } = require('../utils/httpClient');
const redis = require('./redis');
const env = require('./env');
const logger = require('./logger');

// GitHub App authentication (https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app).
//
// This is the migration path away from the classic OAuth App flow in
// config/github.js — see docs/github-app-migration.md for the full picture,
// including what's built here vs. what still requires manual setup in
// GitHub's UI (registering the App itself). It's additive and OPT-IN
// (GITHUB_AUTH_MODE=github_app): the existing OAuth App flow keeps working
// unchanged as the default, nothing here runs unless explicitly enabled.
//
// Two token types, not to be confused:
//   - App JWT: signed with the App's own RS256 private key, proves "this
//     request is from the App itself". Short-lived (max 10 minutes per
//     GitHub's own limit), used ONLY to mint installation tokens below —
//     never sent to the GitHub REST API for anything else.
//   - Installation access token: minted BY GitHub in exchange for a valid
//     App JWT, scoped to one installation (one org/user's set of
//     repositories the App was granted access to). This is what actually
//     gets used for repo operations (branches, PRs, etc.) — it's the
//     GitHub App equivalent of the OAuth flow's per-user access_token, but
//     expires in ~1 hour and isn't tied to any one human user, which is
//     exactly why GitHub Apps are the recommended path for a service like
//     PatchLine that acts on repositories somewhat autonomously (auto-
//     rescan on push, PR creation) rather than only in direct response to
//     one logged-in user's click.

const API_BASE = 'https://api.github.com';
// Cache installation tokens a few minutes short of GitHub's own ~1hr expiry
// so a token never gets handed out moments before GitHub itself would
// reject it as expired.
const TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS = 300;
const CACHE_KEY_PREFIX = 'github_app:installation_token:';

function isConfigured() {
  return Boolean(env.githubApp.appId && env.githubApp.privateKeyBase64);
}

function _privateKeyPem() {
  return Buffer.from(env.githubApp.privateKeyBase64, 'base64').toString('utf8');
}

// Exported separately from getInstallationToken so it can be unit-tested on
// its own (decode + verify the JWT's shape/claims) without mocking the
// GitHub API — signing is pure, deterministic-given-inputs crypto with no
// network call.
function signAppJwt() {
  if (!isConfigured()) {
    const err = new Error('GitHub App is not configured (GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY_BASE64)');
    err.status = 500;
    throw err;
  }
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      // Backdated 60s for clock drift between this server and GitHub's —
      // GitHub's own docs recommend this exact pattern.
      iat: now - 60,
      // GitHub hard-caps this at 10 minutes; asking for anything longer is
      // rejected outright, so this isn't a "tune for convenience" value.
      exp: now + 600,
      iss: env.githubApp.appId,
    },
    _privateKeyPem(),
    { algorithm: 'RS256' }
  );
}

async function _mintInstallationToken(installationId) {
  const appJwt = signAppJwt();
  const response = await fetchWithTimeout(`${API_BASE}/app/installations/${installationId}/access_tokens`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${appJwt}`,
      accept: 'application/vnd.github+json',
      'user-agent': 'patchline',
    },
    timeoutMs: env.timeouts.github,
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    const err = new Error(`Failed to mint GitHub App installation token: ${response.status} ${body}`.trim());
    err.status = 502;
    throw err;
  }
  const data = await response.json();
  return { token: data.token, expiresAt: data.expires_at }; // expires_at: ISO 8601
}

// Redis-backed, not in-process — same statelessness requirement as
// everything else in this service (see docs/deployment.md's "Statelessness"
// section). Any instance can mint a token; every instance shares the cache,
// so a scaled-out deployment doesn't mint N redundant tokens (and doesn't
// hit GitHub's rate limit on this endpoint) just because N instances happen
// to handle requests for the same installation.
async function getInstallationToken(installationId) {
  if (!installationId) {
    const err = new Error('installationId is required');
    err.status = 400;
    throw err;
  }
  const cacheKey = `${CACHE_KEY_PREFIX}${installationId}`;
  try {
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);
  } catch (err) {
    // Redis being unavailable degrades to "mint a fresh token every call" —
    // slower and closer to GitHub's rate limit, but never a hard failure.
    logger.warn({ err: err.message, installationId }, 'installation token cache read failed — minting fresh');
  }

  const { token, expiresAt } = await _mintInstallationToken(installationId);
  const ttlSeconds = Math.max(
    0,
    Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000) - TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS
  );
  const result = { token, expiresAt };
  if (ttlSeconds > 0) {
    try {
      await redis.set(cacheKey, JSON.stringify(result), 'EX', ttlSeconds);
    } catch (err) {
      logger.warn({ err: err.message, installationId }, 'installation token cache write failed — continuing uncached');
    }
  }
  return result;
}

async function invalidateInstallationToken(installationId) {
  try {
    await redis.del(`${CACHE_KEY_PREFIX}${installationId}`);
  } catch (err) {
    logger.warn({ err: err.message, installationId }, 'installation token cache invalidation failed');
  }
}

module.exports = {
  isConfigured,
  signAppJwt,
  getInstallationToken,
  invalidateInstallationToken,
  API_BASE,
};
