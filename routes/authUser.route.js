const express = require('express');
const router = express.Router();
const authUserController = require('../controllers/authUser.controller');

router.post('/register', authUserController.register);
router.post('/login', authUserController.login);
router.post('/user/register', authUserController.registerUser);
router.post('/user/login', authUserController.loginUser);
router.post('/admin/register', authUserController.registerAdmin);
router.post('/admin/login', authUserController.loginAdmin);
router.get('/verify', authUserController.verifyToken);

// Debug route to list admin users
router.get('/admins', authUserController.listAdmins);

module.exports = router; 