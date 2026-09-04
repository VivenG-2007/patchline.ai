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

function formatAdfDescription(text) {
  if (!text || typeof text !== 'string') {
    return {
      type: 'doc',
      version: 1,
      content: [
        {
          type: 'paragraph',
          content: [{ type: 'text', text: text ? String(text) : 'No description provided.' }],
        },
      ],
    };
  }

  // Split into paragraphs on blank lines
  const paragraphs = text.split(/\r?\n\r?\n+/);
  const content = [];

  for (const para of paragraphs) {
    const lines = para.split(/\r?\n/);
    const inlineContent = [];
    for (let i = 0; i < lines.length; i++) {
      if (i > 0) {
        inlineContent.push({ type: 'hardBreak' });
      }
      if (lines[i].length > 0) {
        inlineContent.push({ type: 'text', text: lines[i] });
      }
    }
    if (inlineContent.length > 0) {
      content.push({
        type: 'paragraph',
        content: inlineContent,
      });
    }
  }

  if (content.length === 0) {
    content.push({
      type: 'paragraph',
      content: [{ type: 'text', text: text.trim() || 'No description provided.' }],
    });
  }

  return {
    type: 'doc',
    version: 1,
    content,
  };
}

async function createIssue({ userId, summary, description, issueType }) {
  const connection = await getValidConnection(userId);

  const adfDescription = (description && typeof description === 'object' && description.type === 'doc')
    ? description
    : formatAdfDescription(description);

  // Jira Cloud summary limit is 255 chars
  const sanitizedSummary = (summary || 'Patchline AI Scan Report').slice(0, 250);

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
        summary: sanitizedSummary,
        issuetype: { name: issueType || env.jira.issueType },
        description: adfDescription,
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

module.exports = { getValidConnection, createIssue, getIssue, formatAdfDescription };
