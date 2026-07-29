const multer = require('multer');
const config = require('../config');

// Files land as plaintext only briefly in a non-web-accessible temp dir
// before being streamed through encryption; the controller deletes the
// temp copy immediately after (success or failure).
const upload = multer({
  dest: config.tempUploadDir,
  limits: { fileSize: config.maxFileSizeBytes, files: 1 },
});

module.exports = upload;
