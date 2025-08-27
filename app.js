require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const config = require('./config/config');

// Import routes
const agreementRoutes = require('./routes/agreement.route');
const userRoleRoutes = require('./routes/userRole.route');
const partyRoutes = require('./routes/party.route');
const authUserRoutes = require('./routes/authUser.route');
const loginHistoryRoutes = require('./routes/loginHistory.route');
const sessionRoutes = require('./routes/sessionRoutes');
const userProfileRoutes = require('./routes/userProfile.route');
const userManagementRoutes = require('./routes/userManagement.route');
const passkeyRoutes = require('./routes/passkey.route');
const googleAuthRoutes = require('./routes/googleAuth.route');

const app = express();
// Make sure to set PORT and MONGO_URI in a .env file at the project root
const PORT = config.PORT;
const MONGO_URI = config.MONGO_URI;

// Middleware
app.use(cors({
  origin: config.ALLOWED_ORIGINS.length > 0 ? config.ALLOWED_ORIGINS : config.RP_ORIGIN,
  credentials: true
}));
app.use(bodyParser.json());

// Session middleware
app.use(session({
  secret: config.SESSION_SECRET,
  resave: true, // Changed to true to ensure session is saved
  saveUninitialized: false,
  cookie: {
    secure: config.COOKIE_SECURE, // Use environment-based security
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax', // Added for better compatibility
    domain: config.COOKIE_DOMAIN
  },
  name: 'sid' // Explicit session name
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[Request] ${req.method} ${req.url} - Body:`, req.body);
  console.log(`[Session] ID: ${req.sessionID}, User: ${req.session?.userId || 'None'}`);
  next();
});

// API routes
app.use('/agreements', agreementRoutes);
app.use('/user-roles', userRoleRoutes);
app.use('/parties', partyRoutes);
app.use('/auth', authUserRoutes);
app.use('/auth', googleAuthRoutes);
app.use('/passkey', passkeyRoutes);
app.use('/logs/login-history', loginHistoryRoutes);
app.use('/logs', loginHistoryRoutes);
app.use('/api', sessionRoutes);
app.use('/profile', userProfileRoutes);
app.use('/admin/users', userManagementRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.send('Digital Identity Hub Backend is running');
});

// Validate required environment variables
if (!MONGO_URI) {
  console.error('❌ MONGO_URI environment variable is required');
  process.exit(1);
}

if (!config.JWT_SECRET || config.JWT_SECRET === 'your-super-secret-jwt-key-change-this-in-production') {
  console.error('❌ JWT_SECRET environment variable is required and must be changed from default');
  process.exit(1);
}

if (!config.SESSION_SECRET || config.SESSION_SECRET === 'your-super-secret-session-key-change-this-in-production') {
  console.error('❌ SESSION_SECRET environment variable is required and must be changed from default');
  process.exit(1);
}

if (!config.GOOGLE_CLIENT_ID || !config.GOOGLE_CLIENT_SECRET) {
  console.warn('⚠️  Google OAuth credentials not configured. Google login will not work.');
}

if (!config.RP_ORIGIN) {
  console.warn('⚠️  RP_ORIGIN not configured. Passkey functionality may not work properly.');
}

// Connect to MongoDB and start server
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('✅ MongoDB is connected');
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      if (config.GOOGLE_CALLBACK_URL) {
        console.log(`🔐 Google OAuth callback URL: ${config.GOOGLE_CALLBACK_URL}`);
      }
      if (config.RP_ORIGIN) {
        console.log(`🔑 Frontend origin: ${config.RP_ORIGIN}`);
      }
      if (config.ALLOWED_ORIGINS && config.ALLOWED_ORIGINS.length > 0) {
        console.log(`🌍 CORS origins: ${config.ALLOWED_ORIGINS.join(', ')}`);
      }
    });
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });
