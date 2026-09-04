const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

// env.js reads process.env and throws at require-time, so each case runs in
// its own subprocess rather than require()-ing the module repeatedly in this
// process (which would just reuse the first cached module.exports).
function runWithEnv(envOverrides) {
  return spawnSync(process.execPath, ['-e', "require('./src/config/env'); console.log('ENV_OK')"], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, ...envOverrides },
    encoding: 'utf8',
  });
}

test('wildcard CORS is rejected in production', () => {
  const result = runWithEnv({
    NODE_ENV: 'production',
    CORS_ORIGINS: '*',
    JWT_PUBLIC_KEY_BASE64: Buffer.from('pub').toString('base64'),
  });
  assert.notStrictEqual(result.status, 0);
  assert.match(result.stderr, /must not contain/);
});

test('an explicit origin is allowed in production', () => {
  const result = runWithEnv({
    NODE_ENV: 'production',
    CORS_ORIGINS: 'https://app.example.com',
    JWT_PUBLIC_KEY_BASE64: Buffer.from('pub').toString('base64'),
  });
  assert.strictEqual(result.status, 0);
  assert.match(result.stdout, /ENV_OK/);
});

test('wildcard CORS is allowed outside production (scoped guard)', () => {
  const result = runWithEnv({
    NODE_ENV: 'development',
    CORS_ORIGINS: '*',
  });
  assert.strictEqual(result.status, 0);
  assert.match(result.stdout, /ENV_OK/);
});
