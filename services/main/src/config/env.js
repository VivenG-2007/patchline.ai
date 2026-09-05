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
    // Optional: see auth-service/src/config/env.js for the full explanation —
    // lets verifyLocal() below still accept tokens signed under the
    // pre-rotation key during the handover window.
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
  // Read-mostly connection to the Redis instance auth-service AND
  // ai-storage-service actually run against (see docker-compose.yml's
  // "Redis topology" comment). Used ONLY to read the cross-service
  // scan:stage:{scanId} checkpoint ai-storage-service writes — never for
  // BullMQ, caching, or rate limiting, which all stay on `redisUrl` above.
  // Defaults to `redisUrl` itself so a single-Redis deployment (the var
  // simply unset) behaves exactly as it did before the split.
  sharedRedisUrl: process.env.SHARED_REDIS_URL || process.env.REDIS_URL || 'redis://localhost:6379',

  aiStorageServiceUrl: process.env.AI_STORAGE_SERVICE_URL || 'http://localhost:5002',
  internalServiceToken: process.env.INTERNAL_SERVICE_TOKEN || '',

  // Where to send the browser after any OAuth callback (Jira, GitHub, ...) completes.
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',

  // Shared 32-byte key (base64) used to encrypt every stored third-party OAuth
  // token at rest, across all integrations. Generate with: openssl rand -base64 32
  oauthTokenEncryptionKeyBase64: process.env.OAUTH_TOKEN_ENCRYPTION_KEY_BASE64 || '',

  // ---- Jira (OAuth 2.0 / 3LO — per-user consent, not a shared service account) ----
  // Register an OAuth 2.0 app at https://developer.atlassian.com/console/myapps/
  // Callback URL there must exactly match JIRA_REDIRECT_URI below.
  jira: {
    clientId: process.env.JIRA_CLIENT_ID || '',
    clientSecret: process.env.JIRA_CLIENT_SECRET || '',
    redirectUri: process.env.JIRA_REDIRECT_URI || 'http://localhost:5001/api/jira/oauth/callback',
    scopes: process.env.JIRA_SCOPES || 'read:jira-work write:jira-work read:jira-user offline_access',
    projectKey: process.env.JIRA_PROJECT_KEY || '',
    issueType: process.env.JIRA_ISSUE_TYPE || 'Task',
  },

  // ---- GitHub (OAuth App — per-user consent) ----
  // Register at https://github.com/settings/developers → "New OAuth App".
  // Unlike Jira, classic GitHub OAuth App tokens do NOT expire, so there's no
  // refresh-token flow here — see docs/security.md for the tradeoff.
  github: {
    clientId: process.env.GITHUB_CLIENT_ID || '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    redirectUri: process.env.GITHUB_REDIRECT_URI || 'http://localhost:5001/api/github/oauth/callback',
    scopes: process.env.GITHUB_SCOPES || 'read:user user:email repo',

    // ---- Push webhooks (continuous/auto-rescan) ----
    // GITHUB_WEBHOOK_SECRET is the shared secret set on every hook we create
    // (services/githubService.js#createWebhook) and used to verify GitHub's
    // `X-Hub-Signature-256` header (config/github.js#verifyWebhookSignature).
    // GITHUB_WEBHOOK_URL is the public URL GitHub POSTs pushes to — must
    // resolve to POST /api/github/webhook on this service.
    webhookSecret: process.env.GITHUB_WEBHOOK_SECRET || '',
    webhookUrl: process.env.GITHUB_WEBHOOK_URL || '',
  },

  // ---- GitHub App (installation tokens — see docs/github-app-migration.md) ----
  // OPT-IN via GITHUB_AUTH_MODE=github_app. Default stays 'oauth_app' so
  // existing deployments are unaffected until this is deliberately enabled.
  // Register the App at https://github.com/settings/apps/new — this config
  // block only covers the parts this codebase can act on; the App
  // registration itself (permissions, webhook URL, App slug) is a manual
  // one-time step in GitHub's UI, see the migration doc.
  githubAuthMode: process.env.GITHUB_AUTH_MODE || 'oauth_app', // 'oauth_app' | 'github_app'
  githubApp: {
    appId: process.env.GITHUB_APP_ID || '',
    // Base64-encoded PEM private key downloaded from the App's settings page.
    // base64 -w0 your-app.private-key.pem
    privateKeyBase64: process.env.GITHUB_APP_PRIVATE_KEY_BASE64 || '',
    // Separate from GITHUB_WEBHOOK_SECRET above — GitHub Apps use ONE
    // App-level webhook secret for every event (including `installation`/
    // `installation_repositories`), rather than the OAuth flow's per-repo
    // hook secret created by githubService.js#createWebhook.
    webhookSecret: process.env.GITHUB_APP_WEBHOOK_SECRET || '',
    // The public App page users are sent to install/configure the App on
    // their account or org — https://github.com/apps/<your-app-slug>.
    slug: process.env.GITHUB_APP_SLUG || '',
  },

  projectName: process.env.PROJECT_NAME || 'hackathon-template',

  // Outbound request timeouts (ms) — see utils/httpClient.js. Scan/fix are
  // generous because ai-storage-service's own work (batched AI calls across
  // many files, then a verification pass) genuinely takes a while; everything
  // else is a plain REST call and should fail fast instead of hanging.
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

// CORS_ORIGINS is this service's CSRF defense (see docs/security.md) — there's
// no separate CSRF token, so a tight origin allow-list plus httpOnly cookies
// is what stops a cross-origin page from riding the user's session. A
// wildcard silently removes that protection while everything else keeps
// working, so fail loudly instead of deploying with CORS effectively open.
if (env.nodeEnv === 'production' && env.corsOrigins.includes('*')) {
  throw new Error(
    "[env] CORS_ORIGINS must not contain '*' in production — this is the service's CSRF defense (see docs/security.md). List explicit origins instead."
  );
}

module.exports = env;
