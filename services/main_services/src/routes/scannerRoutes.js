const express = require('express');
const ctrl = require('../controllers/scannerController');
const validate = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const { strictLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

router.use(requireAuth, strictLimiter);

router.post('/scan', ctrl.triggerScanValidators, validate, ctrl.triggerScan);
router.get('/status/:scanId', ctrl.scanStatusValidators, validate, ctrl.getScanStatus);
router.post('/approve-fix', ctrl.approveFixValidators, validate, ctrl.approveAndFix);
router.post('/scan/:scanId/finding/:findingId/create-pr', ctrl.createPrValidators, validate, ctrl.createPr);
router.post('/scan/:scanId/raise-jira', ctrl.scanStatusValidators, validate, ctrl.raiseJiraTicket);
router.get('/history', ctrl.getScanHistory);
// Live AI provider status — proxied from ai-storage-service model_router
router.get('/ai-provider-status', ctrl.getAiProviderStatus);

module.exports = router;
