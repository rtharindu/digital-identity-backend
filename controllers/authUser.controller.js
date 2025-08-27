const AuthUser = require('../models/authUser.model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const LoginHistory = require('../models/loginHistory.model');

const config = require('../config/config');
const JWT_SECRET = config.JWT_SECRET;

// ✅ Helper to extract IP from request
const getClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0]
    || req.socket?.remoteAddress
    || req.connection?.remoteAddress
    || req.ip
    || 'Unknown IP';
};

exports.register = async (req, res) => {
  try {
    const { email, password, role } = req.body;
    console.log('[Register] Attempt for:', email, 'Role:', role);

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const existing = await AuthUser.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: 'Email already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new AuthUser({ email, password: hashedPassword, role });
    await user.save();

    console.log('[Register] Success:', email);
    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    console.error('[Register] Error:', err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = getClientIP(req);
    console.log('[Login] Attempt for:', email, 'IP:', ip);

    if (!email || !password) {
      await LoginHistory.create({ email, ip, status: 'failure', timestamp: new Date(), userId: null });
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const user = await AuthUser.findOne({ email });
    if (!user) {
      await LoginHistory.create({ email, ip, status: 'failure', timestamp: new Date(), userId: null });
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await LoginHistory.create({ email, ip, status: 'failure', timestamp: new Date(), userId: user._id });
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

    await LoginHistory.create({ 
      email: user.email, 
      ip, 
      status: 'success', 
      timestamp: new Date(), 
      userId: user._id,
      loginMethod: 'password',
      userAgent: req.headers['user-agent'] || 'Unknown',
      location: 'Password Login'
    });
    console.log('[Login] Success for:', email);

    res.json({ token, user: { id: user._id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('[Login] Internal Error:', err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

// Public wrapper for role-based registration
exports.registerUser = async (req, res) => {
  req.body.role = 'user';
  return exports.register(req, res);
};

exports.registerAdmin = async (req, res) => {
  req.body.role = 'admin';
  return exports.register(req, res);
};

// Public wrapper for role-based login
exports.loginUser = async (req, res) => {
  req.body._expectedRole = 'user';
  return exports.loginWithRole(req, res);
};

exports.loginAdmin = async (req, res) => {
  req.body._expectedRole = 'admin';
  return exports.loginWithRole(req, res);
};

// ✅ Role-protected login with logging
exports.loginWithRole = async (req, res) => {
  try {
    const { email, password, _expectedRole } = req.body;
    const ip = getClientIP(req);
    console.log('[LoginWithRole] Attempt for:', email, 'Role:', _expectedRole, 'IP:', ip);

    if (!email || !password) {
      await LoginHistory.create({ email, ip, status: 'failure', timestamp: new Date(), userId: null });
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const user = await AuthUser.findOne({ email });
    if (!user || user.role !== _expectedRole) {
      await LoginHistory.create({ email, ip, status: 'failure', timestamp: new Date(), userId: user?._id || null });
      return res.status(401).json({ message: 'Invalid credentials or role.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await LoginHistory.create({ email, ip, status: 'failure', timestamp: new Date(), userId: user._id });
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

    await LoginHistory.create({ 
      email: user.email, 
      ip, 
      status: 'success', 
      timestamp: new Date(), 
      userId: user._id,
      loginMethod: _expectedRole === 'admin' ? 'admin_password' : 'password',
      userAgent: req.headers['user-agent'] || 'Unknown',
      location: _expectedRole === 'admin' ? 'Admin Portal' : 'Password Login'
    });
    console.log('[LoginWithRole] Success for:', email);

    res.json({ token, user: { id: user._id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('[LoginWithRole] Internal Error:', err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};

// Verify JWT token
exports.verifyToken = async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    console.log('[VerifyToken] Attempting to verify token with secret:', JWT_SECRET.substring(0, 10) + '...');
    
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('[VerifyToken] Token decoded successfully for user:', decoded.id);
    console.log('[VerifyToken] Decoded token payload:', { id: decoded.id, email: decoded.email, role: decoded.role });
    
    const user = await AuthUser.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    res.json({ 
      user: { 
        id: user._id, 
        email: user.email, 
        role: user.role 
      } 
    });
  } catch (err) {
    console.error('[VerifyToken] Error:', err);
    console.error('[VerifyToken] JWT Secret being used:', JWT_SECRET.substring(0, 10) + '...');
    res.status(403).json({ message: 'Invalid token' });
  }
};

// List all admin users (for debugging)
exports.listAdmins = async (req, res) => {
  try {
    const admins = await AuthUser.find({ role: 'admin' }).select('-password');
    res.json({ admins });
  } catch (err) {
    console.error('[ListAdmins] Error:', err);
    res.status(500).json({ message: 'Failed to fetch admin users', error: err.message });
  }
};
