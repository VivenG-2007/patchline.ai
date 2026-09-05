const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const env = require('../src/config/env');

// Real RSA keypair generated once per test run — signAppJwt is pure crypto
// given a private key, so there's no need to mock anything except the key
// itself and the App ID it signs into the `iss` claim.
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function withGithubAppConfigured(appId, fn) {
  const original = { ...env.githubApp };
  env.githubApp.appId = appId;
  env.githubApp.privateKeyBase64 = Buffer.from(privateKey, 'utf8').toString('base64');
  try {
    return fn();
  } finally {
    Object.assign(env.githubApp, original);
  }
}

test('isConfigured is false when appId/privateKey are unset', () => {
  const githubApp = require('../src/config/githubApp');
  const original = { ...env.githubApp };
  env.githubApp.appId = '';
  env.githubApp.privateKeyBase64 = '';
  try {
    assert.strictEqual(githubApp.isConfigured(), false);
  } finally {
    Object.assign(env.githubApp, original);
  }
});

test('isConfigured is true once appId and privateKey are both set', () => {
  const githubApp = require('../src/config/githubApp');
  withGithubAppConfigured('12345', () => {
    assert.strictEqual(githubApp.isConfigured(), true);
  });
});

test('signAppJwt throws a clear error when not configured', () => {
  const githubApp = require('../src/config/githubApp');
  const original = { ...env.githubApp };
  env.githubApp.appId = '';
  env.githubApp.privateKeyBase64 = '';
  try {
    assert.throws(() => githubApp.signAppJwt(), /GitHub App is not configured/);
  } finally {
    Object.assign(env.githubApp, original);
  }
});

test('signAppJwt produces a token that verifies against the matching public key', () => {
  const githubApp = require('../src/config/githubApp');
  withGithubAppConfigured('98765', () => {
    const token = githubApp.signAppJwt();
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    assert.strictEqual(decoded.iss, '98765');
  });
});

test('signAppJwt backdates iat by ~60s for clock drift tolerance', () => {
  const githubApp = require('../src/config/githubApp');
  withGithubAppConfigured('1', () => {
    const before = Math.floor(Date.now() / 1000);
    const token = githubApp.signAppJwt();
    const decoded = jwt.decode(token);
    assert.ok(decoded.iat <= before - 55 && decoded.iat >= before - 65, `iat was ${decoded.iat}, expected ~${before - 60}`);
  });
});

test('signAppJwt caps the token lifetime at GitHub-s 10-minute maximum', () => {
  const githubApp = require('../src/config/githubApp');
  withGithubAppConfigured('1', () => {
    const token = githubApp.signAppJwt();
    const decoded = jwt.decode(token);
    const lifetimeSeconds = decoded.exp - decoded.iat;
    assert.ok(lifetimeSeconds <= 660, `token lifetime was ${lifetimeSeconds}s, GitHub caps this at 600s (+60s backdating)`);
  });
});

test('signAppJwt rejects verification against the wrong public key', () => {
  const githubApp = require('../src/config/githubApp');
  const { publicKey: wrongPublicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  withGithubAppConfigured('1', () => {
    const token = githubApp.signAppJwt();
    assert.throws(() => jwt.verify(token, wrongPublicKey, { algorithms: ['RS256'] }));
  });
});

// ── verifyWebhookSignatureWithSecret (config/github.js) — used for GitHub
// App installation events, verified against env.githubApp.webhookSecret
// rather than the OAuth flow's per-repo push-webhook secret. ──

test('verifyWebhookSignatureWithSecret accepts a correctly-signed payload', () => {
  const github = require('../src/config/github');
  const body = JSON.stringify({ action: 'created', installation: { id: 1 } });
  const secret = 'test-app-webhook-secret';
  const signature = `sha256=${crypto.createHmac('sha256', secret).update(body).digest('hex')}`;
  assert.strictEqual(github.verifyWebhookSignatureWithSecret(body, signature, secret), true);
});

test('verifyWebhookSignatureWithSecret rejects a payload signed with a different secret', () => {
  const github = require('../src/config/github');
  const body = JSON.stringify({ action: 'created', installation: { id: 1 } });
  const signature = `sha256=${crypto.createHmac('sha256', 'the-real-secret').update(body).digest('hex')}`;
  assert.strictEqual(github.verifyWebhookSignatureWithSecret(body, signature, 'a-different-secret'), false);
});

test('verifyWebhookSignatureWithSecret rejects when secret/signature/body is missing', () => {
  const github = require('../src/config/github');
  assert.strictEqual(github.verifyWebhookSignatureWithSecret('body', 'sig', ''), false);
  assert.strictEqual(github.verifyWebhookSignatureWithSecret('body', '', 'secret'), false);
  assert.strictEqual(github.verifyWebhookSignatureWithSecret('', 'sig', 'secret'), false);
});

test('verifyWebhookSignature (OAuth-flow secret) and verifyWebhookSignatureWithSecret agree for the same secret', () => {
  const github = require('../src/config/github');
  const original = env.github.webhookSecret;
  env.github.webhookSecret = 'shared-test-secret';
  try {
    const body = JSON.stringify({ ref: 'refs/heads/main' });
    const signature = `sha256=${crypto.createHmac('sha256', 'shared-test-secret').update(body).digest('hex')}`;
    assert.strictEqual(github.verifyWebhookSignature(body, signature), true);
    assert.strictEqual(github.verifyWebhookSignatureWithSecret(body, signature, 'shared-test-secret'), true);
  } finally {
    env.github.webhookSecret = original;
  }
});
