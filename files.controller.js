const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const config = require('../config');
const { encryptFileStream, decryptFileToBuffer } = require('../utils/encryption');
const { canAccessFile, ROLE_LEVEL } = require('../middleware/rbac');

function audit(userId, action, fileId, req, detail) {
  db.prepare('INSERT INTO audit_log (user_id, action, file_id, ip_address, detail) VALUES (?, ?, ?, ?, ?)').run(
    userId,
    action,
    fileId || null,
    req.ip,
    detail || null
  );
}

/** POST /files  (multipart/form-data, field name "file") */
async function uploadFile(req, res) {
  if (!req.file) {
    return res.status(400).json({ error: 'No file provided (expected multipart field "file")' });
  }

  const validRoles = new Set(['user', 'manager', 'admin', 'owner_only']);
  const minRole = req.body.min_role && validRoles.has(req.body.min_role) ? req.body.min_role : 'owner_only';

  const storageName = `${uuidv4()}.enc`;
  const destPath = path.join(config.encryptedStorageDir, storageName);

  try {
    const { iv, authTag, checksum } = await encryptFileStream(req.file.path, destPath);

    const result = db
      .prepare(
        `INSERT INTO files (owner_id, storage_name, original_name, mime_type, size_bytes, iv, auth_tag, min_role, checksum_sha256)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        req.user.id,
        storageName,
        req.file.originalname,
        req.file.mimetype,
        req.file.size,
        iv,
        authTag,
        minRole,
        checksum
      );

    audit(req.user.id, 'upload', result.lastInsertRowid, req, req.file.originalname);

    res.status(201).json({
      file: {
        id: result.lastInsertRowid,
        original_name: req.file.originalname,
        size_bytes: req.file.size,
        mime_type: req.file.mimetype,
        min_role: minRole,
      },
    });
  } catch (err) {
    res.status(500).json({ error: 'Encryption/storage failed', detail: err.message });
  } finally {
    // Always scrub the plaintext temp upload, success or failure.
    fs.unlink(req.file.path, () => {});
  }
}

/** GET /files  — list files the caller may read */
function listFiles(req, res) {
  const all = db
    .prepare(
      `SELECT f.id, f.original_name, f.mime_type, f.size_bytes, f.min_role, f.owner_id, f.created_at,
              u.username AS owner_username
       FROM files f JOIN users u ON u.id = f.owner_id`
    )
    .all();

  const visible = all.filter((f) => canAccessFile(req.user, f, 'read'));
  res.json({ files: visible });
}

/** GET /files/:id/download */
async function downloadFile(req, res) {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  if (!canAccessFile(req.user, file, 'read')) {
    audit(req.user.id, 'download_denied', file.id, req);
    return res.status(403).json({ error: 'You do not have access to this file' });
  }

  const encryptedPath = path.join(config.encryptedStorageDir, file.storage_name);
  if (!fs.existsSync(encryptedPath)) {
    return res.status(410).json({ error: 'File content missing from storage' });
  }

  let plaintext;
  try {
    // Decrypts and verifies the GCM auth tag BEFORE any response is sent.
    plaintext = decryptFileToBuffer(encryptedPath, file.iv, file.auth_tag);
  } catch (err) {
    audit(req.user.id, 'download_failed', file.id, req, err.message);
    return res.status(500).json({ error: 'Decryption failed — file may be corrupted or tampered with' });
  }

  audit(req.user.id, 'download', file.id, req);
  res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.original_name)}"`);
  res.send(plaintext);
}

/** DELETE /files/:id */
function deleteFile(req, res) {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  if (!canAccessFile(req.user, file, 'delete')) {
    return res.status(403).json({ error: 'You do not have permission to delete this file' });
  }

  const encryptedPath = path.join(config.encryptedStorageDir, file.storage_name);
  fs.unlink(encryptedPath, () => {});
  db.prepare('DELETE FROM files WHERE id = ?').run(file.id);

  audit(req.user.id, 'delete', file.id, req, file.original_name);
  res.json({ ok: true });
}

/** POST /files/:id/permissions  { user_id, permission } */
function grantPermission(req, res) {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  // Only the owner or an admin may manage sharing on a file.
  if (file.owner_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only the file owner or an admin can manage access' });
  }

  const { user_id: targetUserId, permission } = req.body || {};
  if (!targetUserId || !['read', 'write'].includes(permission)) {
    return res.status(400).json({ error: 'user_id and permission ("read"|"write") are required' });
  }

  const targetUser = db.prepare('SELECT id FROM users WHERE id = ?').get(targetUserId);
  if (!targetUser) return res.status(404).json({ error: 'Target user not found' });

  db.prepare(
    `INSERT INTO file_permissions (file_id, user_id, permission, granted_by)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(file_id, user_id, permission) DO NOTHING`
  ).run(file.id, targetUserId, permission, req.user.id);

  audit(req.user.id, 'grant_permission', file.id, req, `user=${targetUserId} perm=${permission}`);
  res.status(201).json({ ok: true });
}

/** DELETE /files/:id/permissions/:userId  ?permission=read|write */
function revokePermission(req, res) {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  if (file.owner_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only the file owner or an admin can manage access' });
  }

  const targetUserId = parseInt(req.params.userId, 10);
  const permission = req.query.permission;

  if (permission) {
    db.prepare('DELETE FROM file_permissions WHERE file_id = ? AND user_id = ? AND permission = ?').run(
      file.id,
      targetUserId,
      permission
    );
  } else {
    db.prepare('DELETE FROM file_permissions WHERE file_id = ? AND user_id = ?').run(file.id, targetUserId);
  }

  audit(req.user.id, 'revoke_permission', file.id, req, `user=${targetUserId}`);
  res.json({ ok: true });
}

module.exports = {
  uploadFile,
  listFiles,
  downloadFile,
  deleteFile,
  grantPermission,
  revokePermission,
};
