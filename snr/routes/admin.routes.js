const express = require('express');
const { authenticate } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const admin = require('../controllers/admin.controller');

const router = express.Router();

router.use(authenticate, requireRole('admin'));

router.get('/users', admin.listUsers);
router.patch('/users/:userId/role', admin.updateUserRole);
router.patch('/users/:userId/status', admin.setUserActive);

module.exports = router;
