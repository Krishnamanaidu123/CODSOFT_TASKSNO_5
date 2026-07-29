const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const config = require('../config');

const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_SELF_ROLES = new Set(['user']); // self-registration can never grant elevated roles

function issueToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, config.jwtSecret, {
    expiresIn: config.jwtExpiresIn,
  });
}

function register(req, res) {
  const { username, email, password } = req.body || {};

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'username, email, and password are required' });
  }
  if (!USERNAME_RE.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-32 chars: letters, numbers, _ . -' });
  }
  if (!EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (password.length < 10) {
    return res.status(400).json({ error: 'Password must be at least 10 characters' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
  if (existing) {
    return res.status(409).json({ error: 'Username or email already in use' });
  }

  // Role is always forced to 'user' on self-registration. Promotions must be
  // done by an existing admin via the admin endpoint, never client-supplied.
  const role = 'user';
  const passwordHash = bcrypt.hashSync(password, 12);

  const result = db
    .prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)')
    .run(username, email, passwordHash, role);

  const user = { id: result.lastInsertRowid, username, email, role };
  const token = issueToken(user);

  res.status(201).json({ user: { id: user.id, username, email, role }, token });
}

function login(req, res) {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, username);

  // Constant-shape response whether user exists or not, to avoid username enumeration.
  const passwordHash = user ? user.password_hash : '$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinva';
  const valid = bcrypt.compareSync(password, passwordHash);

  if (!user || !valid || !user.is_active) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = issueToken(user);
  res.json({ user: { id: user.id, username: user.username, email: user.email, role: user.role }, token });
}

function me(req, res) {
  res.json({ user: req.user });
}

module.exports = { register, login, me };
