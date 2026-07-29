const jwt = require('jsonwebtoken');
const config = require('../config');
const db = require('../db');

/**
 * Verifies the Bearer JWT on the request, loads the current user record
 * (so role/active-status changes take effect immediately even with a
 * still-valid token), and attaches it to req.user.
 */
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  let payload;
  try {
    payload = jwt.verify(token, config.jwtSecret);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  const user = db.prepare('SELECT id, username, email, role, is_active FROM users WHERE id = ?').get(payload.sub);

  if (!user || !user.is_active) {
    return res.status(401).json({ error: 'Account not found or disabled' });
  }

  req.user = user;
  next();
}

module.exports = { authenticate };
