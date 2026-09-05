const { validationResult } = require('express-validator');

module.exports = function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: { message: 'Validation failed', code: 'VALIDATION_ERROR', details: errors.array(), requestId: req.id } });
  }
  return next();
};
