const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

function runWithEnv(envOverrides) {
  return spawnSync(process.execPath, ['-e', "require('./src/config/env'); console.log('ENV_OK')"], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, ...envOverrides },
    encoding: 'utf8',
  });
}

const baseProd = {
  NODE_ENV: 'production',
  MONGODB_URI: 'mongodb://localhost:27017/test',
  JWT_PRIVATE_KEY_BASE64: Buffer.from('priv').toString('base64'),
  JWT_PUBLIC_KEY_BASE64: Buffer.from('pub').toString('base64'),
};

test('wildcard CORS is rejected in production', () => {
  const result = runWithEnv({ ...baseProd, CORS_ORIGINS: '*' });
  assert.notStrictEqual(result.status, 0);
  assert.match(result.stderr, /must not contain/);
});

test('an explicit origin is allowed in production', () => {
  const result = runWithEnv({ ...baseProd, CORS_ORIGINS: 'https://app.example.com' });
  assert.strictEqual(result.status, 0);
  assert.match(result.stdout, /ENV_OK/);
});

test('wildcard CORS is allowed outside production (scoped guard)', () => {
  const result = runWithEnv({ NODE_ENV: 'development', CORS_ORIGINS: '*' });
  assert.strictEqual(result.status, 0);
  assert.match(result.stdout, /ENV_OK/);
});
