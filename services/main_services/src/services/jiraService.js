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

function textToAdf(text) {
  if (!text) {
    return {
      type: 'doc',
      version: 1,
      content: [{ type: 'paragraph', content: [] }],
    };
  }
  const lines = String(text).split('\n');
  const paragraphs = [];
  let currentInlineNodes = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) {
      if (currentInlineNodes.length > 0) {
        paragraphs.push({ type: 'paragraph', content: currentInlineNodes });
        currentInlineNodes = [];
      }
    } else {
      if (currentInlineNodes.length > 0) {
        currentInlineNodes.push({ type: 'hardBreak' });
      }
      currentInlineNodes.push({ type: 'text', text: line });
    }
  }
  if (currentInlineNodes.length > 0) {
    paragraphs.push({ type: 'paragraph', content: currentInlineNodes });
  }
  if (paragraphs.length === 0) {
    paragraphs.push({ type: 'paragraph', content: [{ type: 'text', text: String(text).trim() || 'No details provided' }] });
  }

  return {
    type: 'doc',
    version: 1,
    content: paragraphs,
  };
}

async function resolveProjectAndIssueType(connection, requestedIssueType) {
  let projectKey = env.jira.projectKey;
  let targetIssueType = requestedIssueType || env.jira.issueType || 'Task';

  // If projectKey is not set, try to find the first accessible project
  if (!projectKey) {
    try {
      const projResp = await fetchWithTimeout(`${apiBase(connection.cloudId)}/rest/api/3/project`, {
        headers: { accept: 'application/json', authorization: `Bearer ${connection.accessToken}` },
        timeoutMs: env.timeouts.jira,
      });
      if (projResp.ok) {
        const projects = await projResp.json();
        if (Array.isArray(projects) && projects.length > 0) {
          projectKey = projects[0].key;
          logger.info({ projectKey }, 'Discovered default Jira project key from accessible projects');
        }
      }
    } catch (projErr) {
      logger.warn({ projErr: projErr.message }, 'Failed to query Jira projects list');
    }
  }

  // Next, query project details to verify issue type availability
  if (projectKey) {
    try {
      const detailResp = await fetchWithTimeout(`${apiBase(connection.cloudId)}/rest/api/3/project/${encodeURIComponent(projectKey)}`, {
        headers: { accept: 'application/json', authorization: `Bearer ${connection.accessToken}` },
        timeoutMs: env.timeouts.jira,
      });
      if (detailResp.ok) {
        const projectData = await detailResp.json();
        const availableTypes = (projectData.issueTypes || []).filter((it) => !it.subtask);
        if (availableTypes.length > 0) {
          const match = availableTypes.find((it) => it.name.toLowerCase() === targetIssueType.toLowerCase());
          if (match) {
            targetIssueType = match.name;
          } else {
            const taskFallback = availableTypes.find((it) => it.name.toLowerCase() === 'task') || availableTypes[0];
            logger.info({ originalType: targetIssueType, fallbackType: taskFallback.name, projectKey }, 'Jira project does not have requested issue type, falling back');
            targetIssueType = taskFallback.name;
          }
        }
      }
    } catch (metaErr) {
      logger.warn({ metaErr: metaErr.message, projectKey }, 'Failed to query Jira project issue types');
    }
  }

  return { projectKey: projectKey || 'HACK', issueType: targetIssueType };
}

async function createIssue({ userId, summary, description, issueType }) {
  const connection = await getValidConnection(userId);
  const resolved = await resolveProjectAndIssueType(connection, issueType);

  const postIssue = async (projKey, typeName) => {
    return fetchWithTimeout(`${apiBase(connection.cloudId)}/rest/api/3/issue`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        authorization: `Bearer ${connection.accessToken}`,
      },
      body: JSON.stringify({
        fields: {
          project: { key: projKey },
          summary,
          issuetype: { name: typeName },
          description: textToAdf(description),
        },
      }),
      timeoutMs: env.timeouts.jira,
    });
  };

  let response = await postIssue(resolved.projectKey, resolved.issueType);
  let data = await response.json().catch(() => ({}));

  // If issuetype was rejected with 400, retry with 'Task' or standard issue type
  if (!response.ok && response.status === 400 && JSON.stringify(data).toLowerCase().includes('issuetype')) {
    if (resolved.issueType !== 'Task') {
      logger.info({ projectKey: resolved.projectKey }, 'Retrying Jira issue creation with issuetype: Task');
      response = await postIssue(resolved.projectKey, 'Task');
      data = await response.json().catch(() => ({}));
    }
  }

  if (!response.ok) {
    const errorDetails =
      data?.errorMessages?.join('; ') ||
      (data?.errors ? Object.entries(data.errors).map(([k, v]) => `${k}: ${v}`).join('; ') : '') ||
      response.statusText;
    logger.error({ status: response.status, data, errorDetails }, 'Jira issue creation failed');
    const err = new Error(`Jira issue creation failed (${response.status}): ${errorDetails}`);
    err.status = 502;
    err.details = data;
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
