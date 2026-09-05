const env = require('../config/env');
const logger = require('../config/logger');

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  const status = err.status || 500;
  logger.error({ err, requestId: req.id, path: req.path }, err.message);
  res.status(status).json({
    error: {
      message: status === 500 && env.nodeEnv === 'production' ? 'Internal server error' : err.message,
      code: err.code || 'INTERNAL_ERROR',
      requestId: req.id,
    },
  });
}

function notFound(req, res) {
  res.status(404).json({ error: { message: 'Route not found', code: 'NOT_FOUND', requestId: req.id } });
}

module.exports = { errorHandler, notFound };
