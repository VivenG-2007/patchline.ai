const crypto = require('crypto');
const { fetchWithTimeout } = require('../utils/httpClient');
const env = require('./env');

const AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
const TOKEN_URL = 'https://github.com/login/oauth/access_token';
const API_BASE = 'https://api.github.com';

function isConfigured() {
  return Boolean(env.github.clientId && env.github.clientSecret && env.github.redirectUri);
}

function isWebhookConfigured() {
  return Boolean(env.github.webhookSecret && env.github.webhookUrl);
}

// Proves a webhook POST actually came from GitHub (i.e. was signed with the
// secret we set on the hook in githubService.createWebhook) and not from
// anyone who discovers our webhook URL. Must be checked against the RAW
// request body — app.js's express.json() stashes that on req.rawBody before
// parsing, since re-serializing the parsed JSON is not guaranteed to
// byte-for-byte match what GitHub signed.
function verifyWebhookSignature(rawBody, signatureHeader) {
  return verifyWebhookSignatureWithSecret(rawBody, signatureHeader, env.github.webhookSecret);
}

// Parameterized version — GitHub Apps sign every event (including
// `installation`/`installation_repositories`) with the App's OWN webhook
// secret (env.githubApp.webhookSecret), which is deliberately a different
// value from the OAuth flow's per-repo push-webhook secret above. Same HMAC
// verification logic either way, just against whichever secret is relevant
// to the event being verified — see githubController.js#handleWebhook.
function verifyWebhookSignatureWithSecret(rawBody, signatureHeader, secret) {
  if (!secret || !signatureHeader || !rawBody) return false;
  const expected = `sha256=${crypto.createHmac('sha256', secret).update(rawBody).digest('hex')}`;
  const expectedBuf = Buffer.from(expected, 'utf8');
  const actualBuf = Buffer.from(String(signatureHeader), 'utf8');
  // timingSafeEqual throws on mismatched lengths rather than returning false
  if (expectedBuf.length !== actualBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, actualBuf);
}

// Full-page redirect target — the browser must navigate here directly so the
// user sees GitHub's real login/consent screen, not an XHR/fetch call.
function buildAuthorizationUrl(state) {
  const params = new URLSearchParams({
    client_id: env.github.clientId,
    redirect_uri: env.github.redirectUri,
    scope: env.github.scopes,
    state,
    allow_signup: 'true',
  });
  return `${AUTHORIZE_URL}?${params.toString()}`;
}

// Classic GitHub OAuth App tokens do NOT expire and there is no refresh
// token — unlike Jira, there's nothing to rotate here. If you later switch
// to a GitHub App (not an OAuth App) instead, GitHub Apps DO support
// expiring tokens + refresh tokens, and this function's shape would need to
// change to match (see GitHub's "Refreshing user access tokens" docs).
async function exchangeCodeForToken(code) {
  const response = await fetchWithTimeout(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': 'patchline' },
    body: JSON.stringify({
      client_id: env.github.clientId,
      client_secret: env.github.clientSecret,
      code,
      redirect_uri: env.github.redirectUri,
    }),
    timeoutMs: env.timeouts.github,
  });
  const data = await response.json();
  if (!response.ok || data.error) {
    const err = new Error(`GitHub token exchange failed: ${data.error_description || data.error || response.statusText}`);
    err.status = 502;
    throw err;
  }
  return data; // { access_token, scope, token_type }
}

async function getAuthenticatedUser(accessToken) {
  const response = await fetchWithTimeout(`${API_BASE}/user`, {
    headers: { authorization: `Bearer ${accessToken}`, accept: 'application/vnd.github+json', 'user-agent': 'patchline' },
    timeoutMs: env.timeouts.github,
  });
  if (!response.ok) {
    const err = new Error('Failed to fetch GitHub user profile');
    err.status = 502;
    throw err;
  }
  return response.json(); // { id, login, avatar_url, name, ... }
}

// Revokes this specific OAuth token via GitHub's app-token-management API
// (DELETE /applications/{client_id}/token), authenticated as the OAuth App
// itself (Basic auth with client_id:client_secret — not the user's token).
// This is the real mitigation available without migrating off classic OAuth
// Apps: those tokens never expire on their own and there's no user-facing
// refresh/rotation, so an explicit revoke call on disconnect is the only way
// our own "disconnect" button actually invalidates the token at GitHub,
// rather than just forgetting our local copy of a still-live credential.
// Best-effort by design: disconnect should still succeed locally even if
// GitHub's side fails (token already revoked, transient API error, etc).
async function revokeToken(accessToken) {
  if (!accessToken) return { revoked: false, reason: 'no_token' };
  if (!env.github.clientId || !env.github.clientSecret) {
    return { revoked: false, reason: 'oauth_not_configured' };
  }
  try {
    const basicAuth = Buffer.from(`${env.github.clientId}:${env.github.clientSecret}`).toString('base64');
    const response = await fetchWithTimeout(`${API_BASE}/applications/${env.github.clientId}/token`, {
      method: 'DELETE',
      headers: {
        authorization: `Basic ${basicAuth}`,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
        'user-agent': 'patchline',
      },
      body: JSON.stringify({ access_token: accessToken }),
      timeoutMs: env.timeouts.github,
    });
    // GitHub returns 204 on success. 404 means the token is already invalid
    // (already revoked, expired, or never valid) — treat that as success
    // too, since the end state (no live token at GitHub) is what we want.
    if (response.status === 204 || response.status === 404) {
      return { revoked: true };
    }
    return { revoked: false, reason: `unexpected_status_${response.status}` };
  } catch (err) {
    return { revoked: false, reason: err.message };
  }
}

module.exports = {
  isConfigured,
  isWebhookConfigured,
  verifyWebhookSignature,
  verifyWebhookSignatureWithSecret,
  buildAuthorizationUrl,
  exchangeCodeForToken,
  getAuthenticatedUser,
  revokeToken,
  API_BASE,
};
