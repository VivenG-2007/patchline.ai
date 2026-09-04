const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const pinoHttp = require('pino-http');

const env = require('./config/env');
const logger = require('./config/logger');
const redis = require('./config/redis');
const requestId = require('./middleware/requestId');
const { generalLimiter } = require('./middleware/rateLimiter');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const proxyRoutes = require('./routes/proxyRoutes');
const jiraRoutes = require('./routes/jiraRoutes');
const githubRoutes = require('./routes/githubRoutes');
const scannerRoutes = require('./routes/scannerRoutes');

const app = express();
app.set('trust proxy', 1);

app.use(requestId);
app.use(pinoHttp({ logger, customProps: (req) => ({ requestId: req.id }) }));
app.use(helmet());
app.use(cors({ origin: env.corsOrigins, credentials: true }));
app.use(compression());
// `verify` runs on every request BEFORE the body is parsed, so req.rawBody
// is available for githubController.handleWebhook's HMAC signature check
// (config/github.js#verifyWebhookSignature) without disturbing req.body for
// every other route that already expects parsed JSON.
app.use(
    express.json({
        limit: '1mb',
        verify: (req, res, buf) => {
            req.rawBody = buf;
        },
    })
);
app.use(cookieParser());
app.use(generalLimiter);

app.get('/health', (req, res) => res.status(200).json({ status: 'ok', service: env.serviceName }));
app.get('/ready', async (req, res) => {
    let redisOk = false;
    try {
        redisOk = (await redis.ping()) === 'PONG';
    } catch {
        redisOk = false;
    }
    const ready = redisOk; // Supabase has no cheap ping; readiness here focuses on our own dependency
    res.status(ready ? 200 : 503).json({ ready, service: env.serviceName, dependencies: { redis: redisOk } });
});
app.get('/metrics', (req, res) => {
    const mem = process.memoryUsage();
    res.status(200).json({
        service: env.serviceName,
        uptimeSeconds: process.uptime(),
        memory: { rssMB: +(mem.rss / 1024 / 1024).toFixed(1), heapUsedMB: +(mem.heapUsed / 1024 / 1024).toFixed(1) },
    });
});

app.use('/api/proxy', proxyRoutes);
app.use('/api/jira', jiraRoutes);
app.use('/api/github', githubRoutes);
app.use('/api/scanner', scannerRoutes);


app.use(notFound);
app.use(errorHandler);

module.exports = app;
