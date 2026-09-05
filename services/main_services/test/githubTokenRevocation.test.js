const test = require('node:test');
const assert = require('node:assert');

const env = require('../src/config/env');

test('revokeToken short-circuits with no_token when accessToken is falsy', async () => {
  const github = require('../src/config/github');
  const result = await github.revokeToken(undefined);
  assert.deepStrictEqual(result, { revoked: false, reason: 'no_token' });
});

test('revokeToken short-circuits with oauth_not_configured when client id/secret are unset', async () => {
  const originalClientId = env.github.clientId;
  const originalClientSecret = env.github.clientSecret;
  env.github.clientId = '';
  env.github.clientSecret = '';
  try {
    // Re-require after mutating env — config/github.js reads env.github.* at
    // call time (not module load time), so no cache-busting needed here.
    const github = require('../src/config/github');
    const result = await github.revokeToken('some-token');
    assert.deepStrictEqual(result, { revoked: false, reason: 'oauth_not_configured' });
  } finally {
    env.github.clientId = originalClientId;
    env.github.clientSecret = originalClientSecret;
  }
});
