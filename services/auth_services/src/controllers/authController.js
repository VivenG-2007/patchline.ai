const { body } = require('express-validator');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { signAccessToken, signRefreshToken, verifyToken, hashToken } = require('../utils/jwt');
const env = require('../config/env');
const logger = require('../config/logger');

const REFRESH_COOKIE = 'refresh_token';
const ACCESS_COOKIE = 'access_token';

function cookieOptions(maxAgeMs) {
  const isProd = env.nodeEnv === 'production';
  return {
    httpOnly: true,
    secure: isProd ? env.cookie.secure : false,
    sameSite: isProd ? env.cookie.sameSite : 'lax',
    domain: env.cookie.domain || undefined,
    maxAge: maxAgeMs,
    path: '/',
  };
}

function msFromExpiry(expiresIn) {
  // supports "15m" / "7d" style strings used by jsonwebtoken
  const match = /^(\d+)([smhd])$/.exec(expiresIn);
  if (!match) return 15 * 60 * 1000;
  const value = Number(match[1]);
  const unit = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[match[2]];
  return value * unit;
}

async function issueTokenPair(user, req, res) {
  const accessToken = signAccessToken(user.toSafeObject());
  const refreshToken = signRefreshToken(user.toSafeObject(), user.tokenVersion);

  await RefreshToken.create({
    userId: user._id,
    tokenHash: hashToken(refreshToken),
    expiresAt: new Date(Date.now() + msFromExpiry(env.jwt.refreshExpiresIn)),
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });

  res.cookie(ACCESS_COOKIE, accessToken, cookieOptions(msFromExpiry(env.jwt.accessExpiresIn)));
  res.cookie(REFRESH_COOKIE, refreshToken, cookieOptions(msFromExpiry(env.jwt.refreshExpiresIn)));
  return { accessToken, refreshToken };
}

const registerValidators = [
  body('name').trim().isLength({ min: 1, max: 120 }),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
];

async function register(req, res, next) {
  try {
    const { name, email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: { message: 'Email already registered', code: 'EMAIL_TAKEN', requestId: req.id } });
    }
    const passwordHash = await User.hashPassword(password);
    const user = await User.create({ name, email, passwordHash });
    const { accessToken } = await issueTokenPair(user, req, res);
    logger.info({ userId: user.id }, 'user registered');
    return res.status(201).json({ user: user.toSafeObject(), accessToken });
  } catch (err) {
    return next(err);
  }
}

const loginValidators = [body('email').isEmail().normalizeEmail(), body('password').notEmpty()];

async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: { message: 'Invalid credentials', code: 'INVALID_CREDENTIALS', requestId: req.id } });
    }
    const { accessToken } = await issueTokenPair(user, req, res);
    return res.status(200).json({ user: user.toSafeObject(), accessToken });
  } catch (err) {
    return next(err);
  }
}

async function refresh(req, res, next) {
  try {
    const token = req.cookies?.[REFRESH_COOKIE] || req.body?.refreshToken;
    if (!token) {
      return res.status(401).json({ error: { message: 'Missing refresh token', code: 'NO_REFRESH_TOKEN', requestId: req.id } });
    }
    const payload = verifyToken(token);
    if (payload.type !== 'refresh') throw new Error('Wrong token type');

    const stored = await RefreshToken.findOne({ tokenHash: hashToken(token), revoked: false });
    if (!stored) {
      return res.status(401).json({ error: { message: 'Refresh token revoked or unknown', code: 'REFRESH_REVOKED', requestId: req.id } });
    }
    const user = await User.findById(payload.sub);
    if (!user || user.tokenVersion !== payload.tv) {
      return res.status(401).json({ error: { message: 'Refresh token no longer valid', code: 'REFRESH_STALE', requestId: req.id } });
    }

    // rotate: revoke old, issue new
    stored.revoked = true;
    await stored.save();
    const { accessToken } = await issueTokenPair(user, req, res);
    return res.status(200).json({ user: user.toSafeObject(), accessToken });
  } catch (err) {
    return res.status(401).json({ error: { message: 'Invalid or expired refresh token', code: 'INVALID_REFRESH', requestId: req.id } });
  }
}

async function logout(req, res, next) {
  try {
    const token = req.cookies?.[REFRESH_COOKIE];
    if (token) {
      await RefreshToken.findOneAndUpdate({ tokenHash: hashToken(token) }, { revoked: true });
    }
    res.clearCookie(ACCESS_COOKIE, cookieOptions(0));
    res.clearCookie(REFRESH_COOKIE, cookieOptions(0));
    return res.status(200).json({ message: 'Logged out' });
  } catch (err) {
    return next(err);
  }
}

async function logoutAll(req, res, next) {
  try {
    await User.findByIdAndUpdate(req.user.id, { $inc: { tokenVersion: 1 } });
    await RefreshToken.updateMany({ userId: req.user.id }, { revoked: true });
    res.clearCookie(ACCESS_COOKIE, cookieOptions(0));
    res.clearCookie(REFRESH_COOKIE, cookieOptions(0));
    return res.status(200).json({ message: 'Logged out on all devices' });
  } catch (err) {
    return next(err);
  }
}

async function me(req, res, next) {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND', requestId: req.id } });
    return res.status(200).json({ user: user.toSafeObject() });
  } catch (err) {
    return next(err);
  }
}

// Lets other services (or the frontend) sanity-check a token against this service directly.
// NOT required for normal request flow — main/AI services verify locally with the public key.
async function verify(req, res) {
  const token = req.body?.token || req.cookies?.[ACCESS_COOKIE];
  try {
    const payload = verifyToken(token);
    return res.status(200).json({ valid: true, payload });
  } catch (err) {
    return res.status(200).json({ valid: false, reason: err.message });
  }
}

module.exports = {
  registerValidators,
  loginValidators,
  register,
  login,
  refresh,
  logout,
  logoutAll,
  me,
  verify,
};
