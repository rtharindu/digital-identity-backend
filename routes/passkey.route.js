const express = require('express');
const router = express.Router();
const passkeyController = require('../controllers/passkey.controller');
const { authenticateToken } = require('../middleware/auth');

// Passkey registration routes (require authentication)
router.post('/register/options', authenticateToken, passkeyController.generatePasskeyRegistrationOptions);
router.post('/register/verify', authenticateToken, passkeyController.verifyPasskeyRegistration);

// Passkey authentication routes
router.post('/authenticate/options', passkeyController.generatePasskeyAuthenticationOptions);
router.post('/authenticate/verify', passkeyController.verifyPasskeyAuthentication);

// Passkey management routes (require authentication)
router.get('/user', authenticateToken, passkeyController.getUserPasskeys);
router.delete('/user/:passkeyId', authenticateToken, passkeyController.deletePasskey);

module.exports = router;
