const { fetchWithTimeout } = require('../utils/httpClient');
const env = require('./env');

const AUTHORIZE_URL = 'https://auth.atlassian.com/authorize';
const TOKEN_URL = 'https://auth.atlassian.com/oauth/token';
const ACCESSIBLE_RESOURCES_URL = 'https://api.atlassian.com/oauth/token/accessible-resources';

function isConfigured() {
  return Boolean(env.jira.clientId && env.jira.clientSecret && env.jira.redirectUri && env.jira.projectKey);
}

// Full-page redirect target — the browser must navigate here directly (not
// an XHR/fetch call) so the user sees Atlassian's real login/consent screen.
function buildAuthorizationUrl(state) {
  const params = new URLSearchParams({
    audience: 'api.atlassian.com',
    client_id: env.jira.clientId,
    scope: env.jira.scopes,
    redirect_uri: env.jira.redirectUri,
    state,
    response_type: 'code',
    prompt: 'consent',
  });
  return `${AUTHORIZE_URL}?${params.toString()}`;
}

async function exchangeCodeForTokens(code) {
  const response = await fetchWithTimeout(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      client_id: env.jira.clientId,
      client_secret: env.jira.clientSecret,
      code,
      redirect_uri: env.jira.redirectUri,
    }),
    timeoutMs: env.timeouts.jira,
  });
  if (!response.ok) {
    const text = await response.text();
    const err = new Error(`Jira token exchange failed: ${text}`);
    err.status = 502;
    throw err;
  }
  return response.json(); // { access_token, refresh_token, expires_in, scope, token_type }
}

async function refreshTokens(refreshToken) {
  const response = await fetchWithTimeout(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'refresh_token',
      client_id: env.jira.clientId,
      client_secret: env.jira.clientSecret,
      refresh_token: refreshToken,
    }),
    timeoutMs: env.timeouts.jira,
  });
  if (!response.ok) {
    const text = await response.text();
    const err = new Error(`Jira token refresh failed: ${text}`);
    err.status = 502;
    throw err;
  }
  return response.json(); // Atlassian rotates the refresh token — always save the new one
}

// A Jira OAuth token isn't scoped to one site by itself — this call resolves
// which Jira Cloud site(s) the user granted access to, and gives us the
// cloudId that every subsequent API call needs in its URL.
async function getAccessibleResources(accessToken) {
  const response = await fetchWithTimeout(ACCESSIBLE_RESOURCES_URL, {
    headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
    timeoutMs: env.timeouts.jira,
  });
  if (!response.ok) {
    const text = await response.text();
    const err = new Error(`Failed to list accessible Jira sites: ${text}`);
    err.status = 502;
    throw err;
  }
  return response.json(); // [{ id: cloudId, url, name, scopes, avatarUrl }, ...]
}

module.exports = {
  isConfigured,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
  refreshTokens,
  getAccessibleResources,
};
