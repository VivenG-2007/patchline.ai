const express = require('express');
const { proxyToAiStorage } = require('../controllers/proxyController');
const { requireAuth } = require('../middleware/auth');
const { strictLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// Frontend hits: /api/proxy/api/ai/chat, /api/proxy/api/files/upload, etc.
// requireAuth here rejects unauthenticated calls before we even reach the network hop.
router.use(requireAuth, strictLimiter, proxyToAiStorage);

module.exports = router;
