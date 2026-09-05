/**
 * Generates an RS256 keypair for JWT signing and prints base64-encoded PEM
 * values ready to paste into JWT_PRIVATE_KEY_BASE64 / JWT_PUBLIC_KEY_BASE64.
 * Run: npm run generate-keys
 */
const { generateKeyPairSync } = require('crypto');

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

console.log('\n=== JWT_PRIVATE_KEY_BASE64 (auth-service ONLY - keep secret) ===\n');
console.log(Buffer.from(privateKey).toString('base64'));
console.log('\n=== JWT_PUBLIC_KEY_BASE64 (safe to share with main-service & ai-storage-service) ===\n');
console.log(Buffer.from(publicKey).toString('base64'));
console.log('\nPaste each value as a single line into the matching .env file(s).\n');
