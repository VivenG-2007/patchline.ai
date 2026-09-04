const jwt = require('jsonwebtoken');
const { fetchWithTimeout } = require('../utils/httpClient');
const redis = require('./redis');
const env = require('./env');
const logger = require('./logger');

// GitHub App authentication (https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app).

const API_BASE = 'https://api.github.com';
const TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS = 300;
const CACHE_KEY_PREFIX = 'github_app:installation_token:';

function isConfigured() {
  return Boolean(env.githubApp.appId && env.githubApp.privateKeyBase64);
}

function _privateKeyPem() {
  const raw = (env.githubApp.privateKeyBase64 || '').trim();
  if (raw.startsWith('-----BEGIN')) {
    return raw;
  }
  return Buffer.from(raw, 'base64').toString('utf8');
}

function signAppJwt() {
  if (!isConfigured()) {
    const err = new Error('GitHub App is not configured (GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY_BASE64)');
    err.status = 500;
    throw err;
  }
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iat: now - 60,
      exp: now + 600,
      iss: env.githubApp.appId,
    },
    _privateKeyPem(),
    { algorithm: 'RS256' }
  );
}

async function listAppInstallations() {
  if (!isConfigured()) return [];
  try {
    const appJwt = signAppJwt();
    const response = await fetchWithTimeout(`${API_BASE}/app/installations`, {
      headers: {
        authorization: `Bearer ${appJwt}`,
        accept: 'application/vnd.github+json',
        'user-agent': 'patchline',
      },
      timeoutMs: env.timeouts.github,
    });
    if (!response.ok) return [];
    return response.json();
  } catch (err) {
    logger.warn({ err: err.message }, 'Failed to list installations from GitHub App API');
    return [];
  }
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
  return { token: data.token, expiresAt: data.expires_at };
}

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
  listAppInstallations,
  getInstallationToken,
  invalidateInstallationToken,
  API_BASE,
};
