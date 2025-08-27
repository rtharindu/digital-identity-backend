const express = require('express');
const router = express.Router();
const googleAuthController = require('../controllers/googleAuth.controller');
const { authenticateToken } = require('../middleware/auth');

// Google OAuth routes
router.get('/google', googleAuthController.initiateGoogleLogin);
router.get('/google/callback', googleAuthController.handleGoogleCallback);

// Google account management routes (require authentication)
router.post('/link-google', authenticateToken, googleAuthController.linkGoogleAccount);
router.delete('/unlink-google', authenticateToken, googleAuthController.unlinkGoogleAccount);

module.exports = router;
