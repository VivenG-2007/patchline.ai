const express = require('express');
const ctrl = require('../controllers/authController');
const validate = require('../middleware/validate');
const { requireAuth } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// -- Public --
router.post('/register', authLimiter, ctrl.registerValidators, validate, ctrl.register);
router.post('/login', authLimiter, ctrl.loginValidators, validate, ctrl.login);
router.post('/refresh', authLimiter, ctrl.refresh);
router.post('/verify', ctrl.verify); // optional remote-check helper, not on the hot path

// -- Authenticated --
router.post('/logout', ctrl.logout);
router.post('/logout-all', requireAuth, ctrl.logoutAll);
router.get('/me', requireAuth, ctrl.me);

module.exports = router;
