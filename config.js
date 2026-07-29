const path = require('path');
require('dotenv').config();

function requireEnv(name, { allowDefault } = {}) {
  const value = process.env[name];
  if (!value && !allowDefault) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

const rawKey = requireEnv('FILE_ENCRYPTION_KEY', { allowDefault: process.env.NODE_ENV === 'test' });
const keyBuffer = rawKey ? Buffer.from(rawKey, 'hex') : Buffer.alloc(32);

if (keyBuffer.length !== 32) {
  throw new Error('FILE_ENCRYPTION_KEY must decode to exactly 32 bytes (64 hex characters).');
}

module.exports = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',

  jwtSecret: process.env.JWT_SECRET || 'insecure-dev-secret-do-not-use-in-prod',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '2h',

  fileEncryptionKey: keyBuffer,

  encryptedStorageDir: path.resolve(process.env.ENCRYPTED_STORAGE_DIR || './storage/encrypted'),
  tempUploadDir: path.resolve(process.env.TEMP_UPLOAD_DIR || './uploads'),
  maxFileSizeBytes: parseInt(process.env.MAX_FILE_SIZE_MB || '100', 10) * 1024 * 1024,

  shareLinkDefaultExpiryMinutes: parseInt(process.env.SHARE_LINK_DEFAULT_EXPIRY_MINUTES || '60', 10),
  shareLinkMaxExpiryMinutes: parseInt(process.env.SHARE_LINK_MAX_EXPIRY_MINUTES || '10080', 10),

  dbPath: path.resolve(process.env.DB_PATH || './data/app.db'),
};
