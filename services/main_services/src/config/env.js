require('dotenv').config();

function decodeKey(base64Value) {
  if (!base64Value) return undefined;
  try {
    return Buffer.from(base64Value, 'base64').toString('utf8');
  } catch {
    return undefined;
  }
}

const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT) || 5001,
  serviceName: process.env.SERVICE_NAME || 'main-service',
  corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',').map((s) => s.trim()).filter(Boolean),

  jwt: {
    publicKey: decodeKey(process.env.JWT_PUBLIC_KEY_BASE64),
    previousPublicKey: decodeKey(process.env.JWT_PREVIOUS_PUBLIC_KEY_BASE64),
    issuer: process.env.JWT_ISSUER || 'hackathon-auth-service',
    audience: process.env.JWT_AUDIENCE || 'patchline',
  },

  supabase: {
    url: process.env.SUPABASE_URL,
    anonKey: process.env.SUPABASE_ANON_KEY,
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
  },

  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  sharedRedisUrl: process.env.SHARED_REDIS_URL || process.env.REDIS_URL || 'redis://localhost:6379',

  aiStorageServiceUrl: process.env.AI_STORAGE_SERVICE_URL || 'http://localhost:5002',
  internalServiceToken: process.env.INTERNAL_SERVICE_TOKEN || '',

  // Where to send the browser after any OAuth callback (Jira, GitHub, ...) completes.
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',

  // Shared 32-byte key (base64) used to encrypt every stored third-party OAuth token at rest.
  oauthTokenEncryptionKeyBase64: process.env.OAUTH_TOKEN_ENCRYPTION_KEY_BASE64 || '',

  // ---- Jira (OAuth 2.0 / 3LO) ----
  jira: {
    clientId: process.env.JIRA_CLIENT_ID || '',
    clientSecret: process.env.JIRA_CLIENT_SECRET || '',
    redirectUri: process.env.JIRA_REDIRECT_URI || 'http://localhost:5001/api/jira/oauth/callback',
    scopes: process.env.JIRA_SCOPES || 'read:jira-work write:jira-work read:jira-user offline_access',
    projectKey: process.env.JIRA_PROJECT_KEY || '',
    issueType: process.env.JIRA_ISSUE_TYPE || 'Task',
  },

  // ---- GitHub (OAuth App — fallback) ----
  github: {
    clientId: process.env.GITHUB_CLIENT_ID || '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    redirectUri: process.env.GITHUB_REDIRECT_URI || 'http://localhost:5001/api/github/oauth/callback',
    scopes: process.env.GITHUB_SCOPES || 'read:user user:email repo',
    webhookSecret: process.env.GITHUB_WEBHOOK_SECRET || '',
    webhookUrl: process.env.GITHUB_WEBHOOK_URL || '',
  },

  // ---- GitHub App (installation tokens) ----
  githubAuthMode: process.env.GITHUB_AUTH_MODE || 'github_app', // 'github_app' | 'oauth_app'
  githubApp: {
    appId: process.env.GITHUB_APP_ID || '',
    privateKeyBase64: process.env.GITHUB_APP_PRIVATE_KEY_BASE64 || '',
    webhookSecret: process.env.GITHUB_APP_WEBHOOK_SECRET || '',
    slug: (process.env.GITHUB_APP_SLUG || '')
      .trim()
      .replace(/^https?:\/\/github\.com\/apps\//i, '')
      .replace(/^\/+|\/+$/g, ''),
  },

  projectName: process.env.PROJECT_NAME || 'hackathon-template',

  timeouts: {
    github: Number(process.env.GITHUB_UPSTREAM_TIMEOUT_MS) || 15000,
    jira: Number(process.env.JIRA_UPSTREAM_TIMEOUT_MS) || 15000,
    aiStorage: Number(process.env.AI_STORAGE_UPSTREAM_TIMEOUT_MS) || 15000,
    scan: Number(process.env.SCAN_UPSTREAM_TIMEOUT_MS) || 180000,
    fix: Number(process.env.FIX_UPSTREAM_TIMEOUT_MS) || 150000,
    proxy: Number(process.env.PROXY_UPSTREAM_TIMEOUT_MS) || 30000,
  },
};

if (env.nodeEnv === 'production' && !env.jwt.publicKey) {
  throw new Error('[env] JWT_PUBLIC_KEY_BASE64 must be set in production (copy it from auth-service).');
}

if (env.nodeEnv === 'production' && env.corsOrigins.includes('*')) {
  throw new Error(
    "[env] CORS_ORIGINS must not contain '*' in production — this is the service's CSRF defense (see docs/security.md). List explicit origins instead."
  );
}

module.exports = env;
