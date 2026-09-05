const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const pinoHttp = require('pino-http');

const env = require('./config/env');
const logger = require('./config/logger');
const requestId = require('./middleware/requestId');
const { generalLimiter } = require('./middleware/rateLimiter');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const authRoutes = require('./routes/authRoutes');
const jwksRoutes = require('./routes/jwksRoutes');

const app = express();

app.set('trust proxy', 1); // required behind Azure App Service's reverse proxy for correct req.ip / secure cookies

app.use(requestId);
app.use(pinoHttp({ logger, customProps: (req) => ({ requestId: req.id }) }));
app.use(helmet());
app.use(
  cors({
    origin: env.corsOrigins,
    credentials: true,
  })
);
app.use(compression());
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(generalLimiter);

app.get('/health', (req, res) => res.status(200).json({ status: 'ok', service: env.serviceName }));
app.get('/ready', (req, res) => {
  const mongoose = require('mongoose');
  const ready = mongoose.connection.readyState === 1;
  res.status(ready ? 200 : 503).json({ ready, service: env.serviceName });
});
app.get('/metrics', (req, res) => {
  const mem = process.memoryUsage();
  res.status(200).json({
    service: env.serviceName,
    uptimeSeconds: process.uptime(),
    memory: { rssMB: +(mem.rss / 1024 / 1024).toFixed(1), heapUsedMB: +(mem.heapUsed / 1024 / 1024).toFixed(1) },
  });
});

app.use('/api/auth', authRoutes);
app.use('/api/auth', jwksRoutes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
