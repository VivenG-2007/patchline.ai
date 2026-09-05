const express = require('express');
const env = require('../config/env');

const router = express.Router();

// Exposes the current (and, during a rotation window, previous) public key so
// other services — or a human copy-pasting env vars — can see what's live
// without reading auth-service's own .env. Kept intentionally simple (not
// full JWKS/JWK format); the three services here read these keys from their
// own env vars rather than fetching this endpoint at runtime, so this is a
// convenience/audit view, not a live dependency.
router.get('/jwks', (req, res) => {
  const keys = [{ kid: env.jwt.kid, algorithm: 'RS256', publicKeyPem: env.jwt.publicKey || null, status: 'current' }];
  if (env.jwt.previousPublicKey) {
    keys.push({
      kid: env.jwt.previousKid || null,
      algorithm: 'RS256',
      publicKeyPem: env.jwt.previousPublicKey,
      status: 'previous',
    });
  }
  res.status(200).json({
    // Kept for backward compatibility with anything reading the old
    // single-key shape.
    kid: env.jwt.kid,
    algorithm: 'RS256',
    publicKeyPem: env.jwt.publicKey || null,
    keys,
  });
});

module.exports = router;
