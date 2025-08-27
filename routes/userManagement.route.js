const express = require('express');
const router = express.Router();
const userManagementController = require('../controllers/userManagement.controller');
const { authenticateToken, requireRole } = require('../middleware/auth');

// All routes require admin authentication
router.use(authenticateToken);
router.use(requireRole('admin'));

// Search users with filters
router.get('/search', userManagementController.searchUsers);

// Get user details by ID
router.get('/user/:userId', userManagementController.getUserDetails);

// Update user role
router.put('/user/:userId/role', userManagementController.updateUserRole);

// Delete user
router.delete('/user/:userId', userManagementController.deleteUser);

// Get user statistics
router.get('/stats', userManagementController.getUserStats);

module.exports = router; 