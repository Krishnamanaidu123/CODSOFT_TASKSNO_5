const fs = require('fs');
const path = require('path');
const db = require('../db');
const config = require('../config');
const { generateShareToken, hashShareToken, decryptFileToBuffer } = require('../utils/encryption');
const { canAccessFile } = require('../middleware/rbac');

/** POST /files/:id/share  { expires_in_minutes?, max_downloads? } */
function createShareLink(req, res) {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  if (!canAccessFile(req.user, file, 'read')) {
    return res.status(403).json({ error: 'You do not have access to this file' });
  }

  let { expires_in_minutes: expiresIn, max_downloads: maxDownloads } = req.body || {};
  expiresIn = Number.isFinite(expiresIn) ? expiresIn : config.shareLinkDefaultExpiryMinutes;
  expiresIn = Math.min(Math.max(expiresIn, 1), config.shareLinkMaxExpiryMinutes);

  if (maxDownloads !== undefined && (!Number.isInteger(maxDownloads) || maxDownloads < 1)) {
    return res.status(400).json({ error: 'max_downloads must be a positive integer if provided' });
  }

  const token = generateShareToken();
  const tokenHash = hashShareToken(token);
  const expiresAt = new Date(Date.now() + expiresIn * 60_000).toISOString();

  const result = db
    .prepare(
      `INSERT INTO share_links (file_id, token_hash, created_by, expires_at, max_downloads)
       VALUES (?, ?, ?, ?, ?)`
    )
    .run(file.id, tokenHash, req.user.id, expiresAt, maxDownloads || null);

  db.prepare('INSERT INTO audit_log (user_id, action, file_id, ip_address) VALUES (?, ?, ?, ?)').run(
    req.user.id,
    'create_share_link',
    file.id,
    req.ip
  );

  // The raw token is returned exactly once — only its hash is persisted.
  res.status(201).json({
    share_link_id: result.lastInsertRowid,
    token,
    url: `/share/${token}`,
    expires_at: expiresAt,
    max_downloads: maxDownloads || null,
  });
}

/** GET /files/:id/share — list active share links for a file (owner/admin only) */
function listShareLinks(req, res) {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });
  if (file.owner_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only the file owner or an admin can view share links' });
  }

  const links = db
    .prepare(
      `SELECT id, expires_at, max_downloads, download_count, revoked, created_at
       FROM share_links WHERE file_id = ? ORDER BY created_at DESC`
    )
    .all(file.id);

  res.json({ share_links: links });
}

/** DELETE /files/:id/share/:linkId — revoke a share link early */
function revokeShareLink(req, res) {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });
  if (file.owner_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only the file owner or an admin can revoke share links' });
  }

  db.prepare('UPDATE share_links SET revoked = 1 WHERE id = ? AND file_id = ?').run(req.params.linkId, file.id);
  res.json({ ok: true });
}

/**
 * GET /share/:token — public (unauthenticated) endpoint that redeems a
 * temporary link. Validates expiry, revocation, and download cap atomically.
 */
async function consumeShareLink(req, res) {
  const tokenHash = hashShareToken(req.params.token);
  const link = db.prepare('SELECT * FROM share_links WHERE token_hash = ?').get(tokenHash);

  if (!link) return res.status(404).json({ error: 'Invalid or unknown link' });
  if (link.revoked) return res.status(410).json({ error: 'This link has been revoked' });
  if (new Date(link.expires_at).getTime() < Date.now()) {
    return res.status(410).json({ error: 'This link has expired' });
  }
  if (link.max_downloads !== null && link.download_count >= link.max_downloads) {
    return res.status(410).json({ error: 'This link has reached its download limit' });
  }

  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(link.file_id);
  if (!file) return res.status(410).json({ error: 'The shared file no longer exists' });

  const encryptedPath = path.join(config.encryptedStorageDir, file.storage_name);
  if (!fs.existsSync(encryptedPath)) {
    return res.status(410).json({ error: 'File content missing from storage' });
  }

  // Atomically increment first so concurrent requests can't both slip
  // through past the max_downloads check (a simple TOCTOU guard).
  const updateResult = db
    .prepare(
      `UPDATE share_links SET download_count = download_count + 1
       WHERE id = ? AND revoked = 0 AND (max_downloads IS NULL OR download_count < max_downloads)`
    )
    .run(link.id);

  if (updateResult.changes === 0) {
    return res.status(410).json({ error: 'This link has reached its download limit' });
  }

  let plaintext;
  try {
    // Verifies the GCM auth tag before any bytes are sent to the client.
    plaintext = decryptFileToBuffer(encryptedPath, file.iv, file.auth_tag);
  } catch (err) {
    return res.status(500).json({ error: 'Decryption failed — file may be corrupted or tampered with' });
  }

  db.prepare('INSERT INTO audit_log (action, file_id, ip_address, detail) VALUES (?, ?, ?, ?)').run(
    'share_link_download',
    file.id,
    req.ip,
    `link_id=${link.id}`
  );

  res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.original_name)}"`);
  res.send(plaintext);
}

module.exports = { createShareLink, listShareLinks, revokeShareLink, consumeShareLink };
