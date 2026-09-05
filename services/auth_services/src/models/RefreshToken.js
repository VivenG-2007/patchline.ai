const mongoose = require('mongoose');

// Stores a hash of each issued refresh token so a single leaked token can be
// revoked individually (in addition to the bulk `tokenVersion` bump on User).
const refreshTokenSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    tokenHash: { type: String, required: true, unique: true },
    revoked: { type: Boolean, default: false },
    expiresAt: { type: Date, required: true, index: { expires: 0 } }, // TTL index
    userAgent: String,
    ip: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
