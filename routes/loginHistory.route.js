const express = require('express');
const router = express.Router();
const loginHistoryController = require('../controllers/loginHistory.controller');
const { authenticateToken, requireRole } = require('../middleware/auth');

// ✅ Route that frontend is calling - Authenticated users can view their own history, admins can view all
router.get('/login-history', authenticateToken, loginHistoryController.getAll);

// (Optional) for seeding dummy data - Admin only
router.post('/dummy', authenticateToken, requireRole('admin'), loginHistoryController.addDummyData);

module.exports = router;
