const pino = require('pino');
const env = require('./env');

module.exports = pino({
  name: env.serviceName,
  level: process.env.LOG_LEVEL || 'info',
  formatters: { level: (label) => ({ level: label }) },
  timestamp: pino.stdTimeFunctions.isoTime,
});
