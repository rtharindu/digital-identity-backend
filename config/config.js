require('dotenv').config();

module.exports = {
  PORT: process.env.PORT || 5000,
  MONGO_URI: process.env.MONGO_URI || '',
  JWT_SECRET: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h',
  
  // Google OAuth 2.0 Configuration
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '',
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || '',
  GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL || '',
  
  // Session Configuration
  SESSION_SECRET: process.env.SESSION_SECRET || 'your-super-secret-session-key-change-this-in-production',
  
  // Passkey Configuration
  RP_ID: process.env.RP_ID || '',
  RP_NAME: process.env.RP_NAME || 'Digital Identity Hub',
  RP_ORIGIN: process.env.RP_ORIGIN || '',
  
  // CORS Configuration
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [],
  
  // Security Configuration
  COOKIE_SECURE: process.env.NODE_ENV === 'production',
  COOKIE_DOMAIN: process.env.COOKIE_DOMAIN || undefined
}; 