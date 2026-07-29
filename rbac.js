const db = require('../db');

// Role hierarchy: higher number = more privilege.
const ROLE_LEVEL = { user: 1, manager: 2, admin: 3 };

/** Express middleware factory: require the caller's role to meet a minimum level. */
function requireRole(minRole) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (ROLE_LEVEL[req.user.role] < ROLE_LEVEL[minRole]) {
      return res.status(403).json({ error: `Requires role '${minRole}' or higher` });
    }
    next();
  };
}

/**
 * Determines whether a user may perform an action on a file.
 * Precedence:
 *   1. Admins can do anything.
 *   2. The file owner can do anything to their own file.
 *   3. An explicit grant in file_permissions covers read/write.
 *   4. Otherwise, for READ only, the file's min_role visibility threshold
 *      is checked against the user's role level ('owner_only' blocks everyone but owner/admin).
 * Write/delete always requires owner, admin, or explicit 'write' grant.
 */
function canAccessFile(user, file, action = 'read') {
  if (user.role === 'admin') return true;
  if (file.owner_id === user.id) return true;

  const grant = db
    .prepare('SELECT permission FROM file_permissions WHERE file_id = ? AND user_id = ?')
    .all(file.id, user.id);
  const permissions = new Set(grant.map((g) => g.permission));

  if (action === 'write' || action === 'delete') {
    return permissions.has('write');
  }

  // action === 'read'
  if (permissions.has('read') || permissions.has('write')) return true;
  if (file.min_role === 'owner_only') return false;
  return ROLE_LEVEL[user.role] >= ROLE_LEVEL[file.min_role];
}

module.exports = { requireRole, canAccessFile, ROLE_LEVEL };
