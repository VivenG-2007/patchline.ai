const { fetchWithTimeout } = require('../utils/httpClient');
const env = require('../config/env');
const jiraConfig = require('../config/jira');
const tokenStore = require('./jiraTokenStore');
const logger = require('../config/logger');

const EXPIRY_SKEW_MS = 60 * 1000; // refresh a minute early rather than racing an exact expiry

// Returns a connection with a guaranteed-valid access token, refreshing it
// (and persisting the rotated refresh token — Atlassian rotates it on every
// refresh) if it's expired or about to be.
async function getValidConnection(userId) {
  const connection = await tokenStore.getConnection(userId);
  if (!connection) {
    const err = new Error('Jira is not connected for this account — visit /api/jira/oauth/start first');
    err.status = 409;
    err.code = 'JIRA_NOT_CONNECTED';
    throw err;
  }

  if (connection.expiresAt.getTime() - EXPIRY_SKEW_MS > Date.now()) {
    return connection; // still valid
  }

  const refreshed = await jiraConfig.refreshTokens(connection.refreshToken);
  const updated = {
    userId,
    cloudId: connection.cloudId,
    siteUrl: connection.siteUrl,
    siteName: connection.siteName,
    accessToken: refreshed.access_token,
    refreshToken: refreshed.refresh_token, // Atlassian always issues a new one — the old one stops working
    expiresAt: new Date(Date.now() + refreshed.expires_in * 1000),
  };
  await tokenStore.upsertConnection(updated);
  return updated;
}

function apiBase(cloudId) {
  return `https://api.atlassian.com/ex/jira/${cloudId}`;
}

async function createIssue({ userId, summary, description, issueType }) {
  const connection = await getValidConnection(userId);

  const response = await fetchWithTimeout(`${apiBase(connection.cloudId)}/rest/api/3/issue`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      authorization: `Bearer ${connection.accessToken}`,
    },
    body: JSON.stringify({
      fields: {
        project: { key: env.jira.projectKey },
        summary,
        issuetype: { name: issueType || env.jira.issueType },
        description: {
          type: 'doc',
          version: 1,
          content: [{ type: 'paragraph', content: [{ type: 'text', text: description }] }],
        },
      },
    }),
    timeoutMs: env.timeouts.jira,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    logger.error({ status: response.status, data }, 'Jira issue creation failed');
    const err = new Error(data?.errorMessages?.[0] || 'Jira API rejected the request');
    err.status = 502;
    throw err;
  }

  return { key: data.key, id: data.id, url: `${connection.siteUrl}/browse/${data.key}` };
}

async function getIssue({ userId, issueKey }) {
  const connection = await getValidConnection(userId);
  const response = await fetchWithTimeout(`${apiBase(connection.cloudId)}/rest/api/3/issue/${encodeURIComponent(issueKey)}`, {
    headers: { accept: 'application/json', authorization: `Bearer ${connection.accessToken}` },
    timeoutMs: env.timeouts.jira,
  });
  if (!response.ok) {
    const err = new Error(`Jira issue ${issueKey} not found or inaccessible`);
    err.status = response.status === 404 ? 404 : 502;
    throw err;
  }
  const data = await response.json();
  return {
    key: data.key,
    summary: data.fields?.summary,
    status: data.fields?.status?.name,
    url: `${connection.siteUrl}/browse/${data.key}`,
  };
}

module.exports = { getValidConnection, createIssue, getIssue };
