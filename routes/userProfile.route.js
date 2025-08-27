const express = require('express');
const router = express.Router();
const userProfileController = require('../controllers/userProfile.controller');
const { authenticateToken, requireRole } = require('../middleware/auth');

// Get current user's profile
router.get('/', authenticateToken, userProfileController.getProfile);

// Update current user's profile
router.put('/', authenticateToken, userProfileController.updateProfile);

// Delete current user's profile
router.delete('/', authenticateToken, userProfileController.deleteProfile);

// Admin routes - get any user's profile
router.get('/admin/:userId', authenticateToken, requireRole('admin'), userProfileController.getProfileByAdmin);

module.exports = router;