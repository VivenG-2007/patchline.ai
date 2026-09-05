const test = require('node:test');
const assert = require('node:assert');
const { generateKeyPairSync } = require('node:crypto');
const jwt = require('jsonwebtoken');

const env = require('../src/config/env');
const { verifyToken } = require('../src/utils/jwt');

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKey, publicKey };
}

function sign(privateKey, kid) {
  return jwt.sign({ sub: 'user-1', type: 'access' }, privateKey, {
    algorithm: 'RS256',
    expiresIn: '15m',
    issuer: env.jwt.issuer,
    audience: env.jwt.audience,
    keyid: kid,
  });
}

test('verifyToken accepts a token signed with the current key', () => {
  const current = keyPair();
  const original = { publicKey: env.jwt.publicKey, previousPublicKey: env.jwt.previousPublicKey };
  env.jwt.publicKey = current.publicKey;
  env.jwt.previousPublicKey = undefined;
  try {
    const token = sign(current.privateKey, 'key-2');
    const payload = verifyToken(token);
    assert.strictEqual(payload.sub, 'user-1');
  } finally {
    env.jwt.publicKey = original.publicKey;
    env.jwt.previousPublicKey = original.previousPublicKey;
  }
});

test('verifyToken falls back to the previous key during a rotation window', () => {
  const previous = keyPair();
  const current = keyPair();
  const original = { publicKey: env.jwt.publicKey, previousPublicKey: env.jwt.previousPublicKey };
  // Simulate: auth-service just rotated to `current`, but this token was
  // signed moments before the rotation, under `previous`.
  env.jwt.publicKey = current.publicKey;
  env.jwt.previousPublicKey = previous.publicKey;
  try {
    const tokenFromBeforeRotation = sign(previous.privateKey, 'key-1');
    const payload = verifyToken(tokenFromBeforeRotation);
    assert.strictEqual(payload.sub, 'user-1');
  } finally {
    env.jwt.publicKey = original.publicKey;
    env.jwt.previousPublicKey = original.previousPublicKey;
  }
});

test('verifyToken rejects a token that matches neither current nor previous key', () => {
  const attacker = keyPair();
  const current = keyPair();
  const previous = keyPair();
  const original = { publicKey: env.jwt.publicKey, previousPublicKey: env.jwt.previousPublicKey };
  env.jwt.publicKey = current.publicKey;
  env.jwt.previousPublicKey = previous.publicKey;
  try {
    const forgedToken = sign(attacker.privateKey, 'key-1');
    assert.throws(() => verifyToken(forgedToken));
  } finally {
    env.jwt.publicKey = original.publicKey;
    env.jwt.previousPublicKey = original.previousPublicKey;
  }
});

test('verifyToken rejects an unrecognized token when no previous key is configured (no silent fallback)', () => {
  const attacker = keyPair();
  const current = keyPair();
  const original = { publicKey: env.jwt.publicKey, previousPublicKey: env.jwt.previousPublicKey };
  env.jwt.publicKey = current.publicKey;
  env.jwt.previousPublicKey = undefined;
  try {
    const forgedToken = sign(attacker.privateKey, 'key-1');
    assert.throws(() => verifyToken(forgedToken));
  } finally {
    env.jwt.publicKey = original.publicKey;
    env.jwt.previousPublicKey = original.previousPublicKey;
  }
});
