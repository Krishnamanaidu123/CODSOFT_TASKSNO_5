const crypto = require('crypto');
const fs = require('fs');
const config = require('../config');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV recommended for GCM

/**
 * Encrypts a file on disk (streamed) using AES-256-GCM with a random IV.
 * Returns the IV and auth tag (both hex-encoded) needed for decryption,
 * plus a SHA-256 checksum of the plaintext for integrity verification.
 */
function encryptFileStream(sourcePath, destPath) {
  return new Promise((resolve, reject) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, config.fileEncryptionKey, iv);
    const hash = crypto.createHash('sha256');

    const input = fs.createReadStream(sourcePath);
    const output = fs.createWriteStream(destPath);

    input.on('data', (chunk) => hash.update(chunk));
    input.on('error', reject);
    output.on('error', reject);
    output.on('finish', () => {
      resolve({
        iv: iv.toString('hex'),
        authTag: cipher.getAuthTag().toString('hex'),
        checksum: hash.digest('hex'),
      });
    });

    input.pipe(cipher).pipe(output);
  });
}

/**
 * Decrypts a stored file fully into memory and returns the plaintext Buffer
 * only after the GCM auth tag has been verified.
 *
 * IMPORTANT: this is intentionally NOT a stream-straight-to-response
 * decrypt. With AES-GCM, the authentication tag is only checked when
 * decipher.final() runs at the very end of the ciphertext — if you pipe
 * decrypted chunks to the client as they're produced, unauthenticated
 * (potentially tampered) plaintext can reach the client before the final
 * integrity check fails. Buffering first means a tampered/corrupted file
 * throws BEFORE any bytes are ever sent, so callers can only write headers
 * and respond after verification succeeds. This trades memory for
 * correctness; for very large files a chunked-envelope scheme (encrypt
 * per-chunk with its own tag) would be the production-grade evolution.
 */
function decryptFileToBuffer(encryptedPath, ivHex, authTagHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const ciphertext = fs.readFileSync(encryptedPath);

  const decipher = crypto.createDecipheriv(ALGORITHM, config.fileEncryptionKey, iv);
  decipher.setAuthTag(authTag);

  // decipher.final() throws if the auth tag doesn't match — i.e. the
  // ciphertext was corrupted or tampered with. Nothing is returned to the
  // caller unless this succeeds.
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Generates a cryptographically random URL-safe token for share links. */
function generateShareToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/** One-way hash of a share token for storage (tokens themselves are bearer secrets). */
function hashShareToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = {
  encryptFileStream,
  decryptFileToBuffer,
  generateShareToken,
  hashShareToken,
};
