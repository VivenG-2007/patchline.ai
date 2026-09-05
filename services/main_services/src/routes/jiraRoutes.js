const express = require('express');
const ctrl = require('../controllers/jiraController');
const validate = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const { strictLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// Public: Atlassian's own redirect lands here with no app JWT attached —
// the `state` param (bound to a user id in Redis by oauth/start) is what
// authenticates this request instead.
router.get('/oauth/callback', ctrl.oauthCallback);

// Everything else requires the caller to already be logged into this app.
router.use(requireAuth, strictLimiter);
router.get('/oauth/start', ctrl.oauthStartValidators, validate, ctrl.oauthStart);
router.get('/status', ctrl.status);
router.delete('/disconnect', ctrl.disconnect);
router.post('/issues', ctrl.createIssueValidators, validate, ctrl.createIssue);
router.get('/issues/:key', ctrl.getIssueValidators, validate, ctrl.getIssue);

module.exports = router;
