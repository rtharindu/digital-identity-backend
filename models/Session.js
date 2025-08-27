const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AuthUser',
    required: true
  },
  userEmail: {
    type: String,
    required: true
  },
  device: String,
  browser: String,
  location: String,
  ipAddress: String,
  lastSeen: String,
  sessionToken: String, // Store part of JWT token for identification
  status: {
    type: String,
    enum: ['Active', 'Inactive'],
    default: 'Active'
  }
}, { timestamps: true });

module.exports = mongoose.model('Session', sessionSchema);
