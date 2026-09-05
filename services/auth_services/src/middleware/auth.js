const { verifyToken } = require('../utils/jwt');

function extractToken(req) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) return header.slice(7);
  if (req.cookies && req.cookies.access_token) return req.cookies.access_token;
  return null;
}

function requireAuth(req, res, next) {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ error: { message: 'Missing access token', code: 'NO_TOKEN', requestId: req.id } });
  }
  try {
    const payload = verifyToken(token);
    if (payload.type !== 'access') throw new Error('Wrong token type');
    req.user = { id: payload.sub, role: payload.role };
    return next();
  } catch (err) {
    return res.status(401).json({ error: { message: 'Invalid or expired token', code: 'INVALID_TOKEN', requestId: req.id } });
  }
}

module.exports = { requireAuth, extractToken };
