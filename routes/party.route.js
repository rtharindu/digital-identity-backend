const express = require('express');
const router = express.Router();
const individualController = require('../controllers/individual.controller');
const organizationController = require('../controllers/organization.controller');
const { authenticateToken, requireRole } = require('../middleware/auth');

// Individual routes
router.post('/individuals', authenticateToken, requireRole('admin'), individualController.createIndividual);
router.get('/individuals', authenticateToken, individualController.getAllIndividuals);
router.get('/individuals/:id', authenticateToken, individualController.getIndividualById);
router.put('/individuals/:id', authenticateToken, requireRole('admin'), individualController.updateIndividual);
router.delete('/individuals/:id', authenticateToken, requireRole('admin'), individualController.deleteIndividual);

// Organization routes
router.post('/organizations', authenticateToken, requireRole('admin'), organizationController.createOrganization);
router.get('/organizations', authenticateToken, organizationController.getAllOrganizations);
router.get('/organizations/:id', authenticateToken, organizationController.getOrganizationById);
router.put('/organizations/:id', authenticateToken, requireRole('admin'), organizationController.updateOrganization);
router.delete('/organizations/:id', authenticateToken, requireRole('admin'), organizationController.deleteOrganization);

module.exports = router;
