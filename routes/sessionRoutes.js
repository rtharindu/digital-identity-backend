const express = require('express');
const router = express.Router();
const {
  createSession,
  getSessions,
  logoutSession,
  logoutAllSessions
} = require('../controllers/sessionController');
const { authenticateToken } = require('../middleware/auth');

// Create session endpoint - can be called during login (no auth required)
router.post('/login', createSession);

// Protected routes - require authentication
router.get('/sessions', authenticateToken, getSessions);
router.put('/logout/:id', authenticateToken, logoutSession);
router.put('/logout-all', authenticateToken, logoutAllSessions);

module.exports = router;
