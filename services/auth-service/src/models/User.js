const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 120 },
    // `unique: true` already creates an index — an explicit `index: true` on
    // top of it makes Mongoose build the same index twice at startup for no
    // benefit, so it's dropped here.
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    // bump to invalidate every outstanding refresh token for this user (logout-all-devices)
    tokenVersion: { type: Number, default: 0 },
  },
  { timestamps: true }
);

userSchema.methods.comparePassword = function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.passwordHash);
};

userSchema.statics.hashPassword = function hashPassword(plain) {
  return bcrypt.hash(plain, 12);
};

userSchema.methods.toSafeObject = function toSafeObject() {
  return { id: this._id.toString(), name: this.name, email: this.email, role: this.role };
};

module.exports = mongoose.model('User', userSchema);
