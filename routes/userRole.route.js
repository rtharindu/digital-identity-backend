const express = require('express');
const router = express.Router();
const userRoleController = require('../controllers/userRole.controller');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.post('/', authenticateToken, requireRole('admin'), userRoleController.createUserRole);
router.get('/', authenticateToken, userRoleController.getAllUserRoles);
router.get('/:id', authenticateToken, userRoleController.getUserRoleById);
router.put('/:id', authenticateToken, requireRole('admin'), userRoleController.updateUserRole);
router.delete('/:id', authenticateToken, requireRole('admin'), userRoleController.deleteUserRole);

module.exports = router;
