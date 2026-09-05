const crypto = require('crypto');
const env = require('../config/env');

// AES-256-GCM at-rest encryption for any third-party OAuth tokens we persist
// ourselves (Jira, GitHub, ...). One shared key across all integrations —
// not used for JWTs, which are signed/verified, never encrypted, elsewhere.
function getKey() {
  if (!env.oauthTokenEncryptionKeyBase64) {
    const err = new Error('OAUTH_TOKEN_ENCRYPTION_KEY_BASE64 is not configured');
    err.status = 500;
    throw err;
  }
  const key = Buffer.from(env.oauthTokenEncryptionKeyBase64, 'base64');
  if (key.length !== 32) {
    throw new Error('OAUTH_TOKEN_ENCRYPTION_KEY_BASE64 must decode to exactly 32 bytes — generate with `openssl rand -base64 32`');
  }
  return key;
}

function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function decrypt(packed) {
  const buf = Buffer.from(packed, 'base64');
  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt };
