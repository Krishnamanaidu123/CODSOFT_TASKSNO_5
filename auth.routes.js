const express = require('express');
const rateLimit = require('express-rate-limit');
const { register, login, me } = require('../controllers/auth.controller');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// Slow down credential-stuffing / brute-force attempts on auth endpoints.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later' },
});

router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);
router.get('/me', authenticate, me);

module.exports = router;
