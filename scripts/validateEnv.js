#!/usr/bin/env node

/**
 * Environment Variables Validation Script
 * Run this script to validate all required environment variables are set
 */

require('dotenv').config();

const requiredVars = [
  'MONGO_URI',
  'JWT_SECRET',
  'SESSION_SECRET'
];

const recommendedVars = [
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_CALLBACK_URL',
  'RP_ID',
  'RP_ORIGIN',
  'ALLOWED_ORIGINS',
  'COOKIE_SECURE',
  'COOKIE_DOMAIN',
  'BACKEND_URL',
  'FRONTEND_URL'
];

const defaultValues = {
  'JWT_SECRET': 'your-super-secret-jwt-key-change-this-in-production',
  'SESSION_SECRET': 'your-super-secret-session-key-change-this-in-production'
};

console.log('🔍 Validating Environment Variables...\n');

let hasErrors = false;
let hasWarnings = false;

// Check required variables
console.log('📋 Required Environment Variables:');
requiredVars.forEach(varName => {
  const value = process.env[varName];
  if (!value) {
    console.log(`  ❌ ${varName}: Missing`);
    hasErrors = true;
  } else if (defaultValues[varName] && value === defaultValues[varName]) {
    console.log(`  ⚠️  ${varName}: Set to default value (should be changed)`);
    hasWarnings = true;
  } else {
    console.log(`  ✅ ${varName}: Set`);
  }
});

console.log('\n📋 Recommended Environment Variables:');
recommendedVars.forEach(varName => {
  const value = process.env[varName];
  if (!value) {
    console.log(`  ⚠️  ${varName}: Not set`);
    hasWarnings = true;
  } else {
    console.log(`  ✅ ${varName}: Set`);
  }
});

// Check MongoDB URI format
const mongoUri = process.env.MONGO_URI;
if (mongoUri) {
  if (mongoUri.includes('localhost') && process.env.NODE_ENV === 'production') {
    console.log('\n⚠️  Warning: Using localhost MongoDB in production environment');
    hasWarnings = true;
  }
  
  if (!mongoUri.startsWith('mongodb://') && !mongoUri.startsWith('mongodb+srv://')) {
    console.log('\n❌ Error: Invalid MongoDB URI format');
    hasErrors = true;
  }
}

// Check security settings
if (process.env.NODE_ENV === 'production') {
  if (process.env.COOKIE_SECURE !== 'true') {
    console.log('\n⚠️  Warning: COOKIE_SECURE should be true in production');
    hasWarnings = true;
  }
  
  if (!process.env.ALLOWED_ORIGINS) {
    console.log('\n⚠️  Warning: ALLOWED_ORIGINS should be set in production');
    hasWarnings = true;
  }
}

console.log('\n' + '='.repeat(50));

if (hasErrors) {
  console.log('\n❌ Validation Failed: Required environment variables are missing');
  console.log('Please set the missing environment variables and try again.');
  process.exit(1);
}

if (hasWarnings) {
  console.log('\n⚠️  Validation completed with warnings');
  console.log('The application will run, but some features may not work properly.');
} else {
  console.log('\n✅ All environment variables are properly configured!');
}

console.log('\n🚀 You can now start the backend server with: npm start');
