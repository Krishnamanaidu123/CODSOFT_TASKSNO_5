const db = require('../db');
const { ROLE_LEVEL } = require('../middleware/rbac');

function listUsers(req, res) {
  const users = db.prepare('SELECT id, username, email, role, is_active, created_at FROM users').all();
  res.json({ users });
}

function updateUserRole(req, res) {
  const targetId = parseInt(req.params.userId, 10);
  const { role } = req.body || {};

  if (!ROLE_LEVEL[role]) {
    return res.status(400).json({ error: `role must be one of: ${Object.keys(ROLE_LEVEL).join(', ')}` });
  }
  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'Admins cannot change their own role' });
  }

  const result = db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, targetId);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'User not found' });
  }

  db.prepare('INSERT INTO audit_log (user_id, action, detail) VALUES (?, ?, ?)').run(
    req.user.id,
    'role_change',
    `Set user ${targetId} role to ${role}`
  );

  res.json({ ok: true });
}

function setUserActive(req, res) {
  const targetId = parseInt(req.params.userId, 10);
  const { is_active } = req.body || {};

  if (typeof is_active !== 'boolean') {
    return res.status(400).json({ error: 'is_active must be a boolean' });
  }
  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'Admins cannot deactivate their own account' });
  }

  const result = db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(is_active ? 1 : 0, targetId);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ ok: true });
}

module.exports = { listUsers, updateUserRole, setUserActive };
