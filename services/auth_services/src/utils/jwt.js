const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const env = require('../config/env');

function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, type: 'access' },
    env.jwt.privateKey,
    {
      algorithm: 'RS256',
      expiresIn: env.jwt.accessExpiresIn,
      issuer: env.jwt.issuer,
      audience: env.jwt.audience,
      keyid: env.jwt.kid,
    }
  );
}

function signRefreshToken(user, tokenVersion) {
  return jwt.sign(
    { sub: user.id, type: 'refresh', tv: tokenVersion },
    env.jwt.privateKey,
    {
      algorithm: 'RS256',
      expiresIn: env.jwt.refreshExpiresIn,
      issuer: env.jwt.issuer,
      audience: env.jwt.audience,
      keyid: env.jwt.kid,
    }
  );
}

// Verifies against the current public key first, then falls back to the
// previous one (if configured — see config/env.js) so tokens signed just
// before a key rotation don't get rejected mid-flight. Rotating JWT_KID
// invalidates every outstanding token immediately without this: the whole
// point of the dual-key window is that rotation stops being an
// everyone-logs-out event.
function verifyToken(token) {
  try {
    return jwt.verify(token, env.jwt.publicKey, {
      algorithms: ['RS256'],
      issuer: env.jwt.issuer,
      audience: env.jwt.audience,
    });
  } catch (currentKeyErr) {
    if (!env.jwt.previousPublicKey) throw currentKeyErr;
    try {
      return jwt.verify(token, env.jwt.previousPublicKey, {
        algorithms: ['RS256'],
        issuer: env.jwt.issuer,
        audience: env.jwt.audience,
      });
    } catch {
      // Neither key verified it — surface the current-key error, since that's
      // the one that matters once the previous key is eventually retired.
      throw currentKeyErr;
    }
  }
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = { signAccessToken, signRefreshToken, verifyToken, hashToken };
