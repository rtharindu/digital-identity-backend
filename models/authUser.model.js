const mongoose = require('mongoose');

const authUserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: false }, // Optional for OAuth users
  googleId: { type: String, unique: true, sparse: true }, // Google OAuth ID
  firstName: { type: String, default: '' },
  lastName: { type: String, default: '' },
  profilePicture: { type: String, default: '' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  isEmailVerified: { type: Boolean, default: false },
  lastLogin: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Update the updatedAt field on save
authUserSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Index for faster lookups
authUserSchema.index({ email: 1 });
authUserSchema.index({ googleId: 1 });

module.exports = mongoose.model('AuthUser', authUserSchema); 