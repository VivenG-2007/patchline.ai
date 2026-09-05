const { v4: uuid } = require('uuid');
module.exports = function requestId(req, res, next) {
  req.id = req.headers['x-request-id'] || uuid();
  res.setHeader('x-request-id', req.id);
  next();
};
