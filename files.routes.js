const express = require('express');
const { authenticate } = require('../middleware/auth');
const upload = require('../middleware/upload');
const files = require('../controllers/files.controller');
const share = require('../controllers/share.controller');

const router = express.Router();

router.use(authenticate); // everything below requires a logged-in user

router.post('/', upload.single('file'), files.uploadFile);
router.get('/', files.listFiles);
router.get('/:id/download', files.downloadFile);
router.delete('/:id', files.deleteFile);

router.post('/:id/permissions', files.grantPermission);
router.delete('/:id/permissions/:userId', files.revokePermission);

router.post('/:id/share', share.createShareLink);
router.get('/:id/share', share.listShareLinks);
router.delete('/:id/share/:linkId', share.revokeShareLink);

module.exports = router;
