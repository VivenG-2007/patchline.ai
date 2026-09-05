const test = require('node:test');
const assert = require('node:assert');
const { generateKeyPairSync } = require('node:crypto');
const jwt = require('jsonwebtoken');

const env = require('../src/config/env');
const { verifyLocal } = require('../src/middleware/auth');

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKey, publicKey };
}

function sign(privateKey) {
  return jwt.sign({ sub: 'user-1', type: 'access' }, privateKey, {
    algorithm: 'RS256',
    expiresIn: '15m',
    issuer: env.jwt.issuer,
    audience: env.jwt.audience,
  });
}

test('verifyLocal accepts a token signed with the current key', () => {
  const current = keyPair();
  const original = { publicKey: env.jwt.publicKey, previousPublicKey: env.jwt.previousPublicKey };
  env.jwt.publicKey = current.publicKey;
  env.jwt.previousPublicKey = undefined;
  try {
    const payload = verifyLocal(sign(current.privateKey));
    assert.strictEqual(payload.sub, 'user-1');
  } finally {
    env.jwt.publicKey = original.publicKey;
    env.jwt.previousPublicKey = original.previousPublicKey;
  }
});

test('verifyLocal falls back to the previous key during a rotation window', () => {
  const previous = keyPair();
  const current = keyPair();
  const original = { publicKey: env.jwt.publicKey, previousPublicKey: env.jwt.previousPublicKey };
  env.jwt.publicKey = current.publicKey;
  env.jwt.previousPublicKey = previous.publicKey;
  try {
    const payload = verifyLocal(sign(previous.privateKey));
    assert.strictEqual(payload.sub, 'user-1');
  } finally {
    env.jwt.publicKey = original.publicKey;
    env.jwt.previousPublicKey = original.previousPublicKey;
  }
});

test('verifyLocal rejects a token that matches neither key', () => {
  const attacker = keyPair();
  const current = keyPair();
  const previous = keyPair();
  const original = { publicKey: env.jwt.publicKey, previousPublicKey: env.jwt.previousPublicKey };
  env.jwt.publicKey = current.publicKey;
  env.jwt.previousPublicKey = previous.publicKey;
  try {
    assert.throws(() => verifyLocal(sign(attacker.privateKey)));
  } finally {
    env.jwt.publicKey = original.publicKey;
    env.jwt.previousPublicKey = original.previousPublicKey;
  }
});
