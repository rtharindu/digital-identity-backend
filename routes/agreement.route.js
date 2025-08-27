const express = require('express');
const router = express.Router();
const agreementController = require('../controllers/agreement.controller');
const { authenticateToken, requireRole } = require('../middleware/auth');

router.post('/', authenticateToken, requireRole('admin'), agreementController.createAgreement);
router.get('/', authenticateToken, agreementController.getAllAgreements);
router.get('/:id', authenticateToken, agreementController.getAgreementById);
router.put('/:id', authenticateToken, requireRole('admin'), agreementController.updateAgreement);
router.delete('/:id', authenticateToken, requireRole('admin'), agreementController.deleteAgreement);

module.exports = router;
