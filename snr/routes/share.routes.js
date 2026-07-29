const express = require('express');
const rateLimit = require('express-rate-limit');
const { consumeShareLink } = require('../controllers/share.controller');

const router = express.Router();

// Public endpoint (no auth) — rate-limit to blunt token-guessing attempts.
// Tokens are 256-bit random values so guessing is infeasible, but this adds
// defense in depth against automated abuse of the endpoint itself.
const shareLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

router.get('/:token', shareLimiter, consumeShareLink);

module.exports = router;
