const mongoose = require('mongoose');

const loginHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'AuthUser' }, // Made optional for failed attempts
  email: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  ip: { type: String },
  status: { type: String, enum: ['success', 'failure'], required: true },
  loginMethod: { type: String, enum: ['password', 'google_oauth', 'passkey', 'admin_password'], default: 'password' },
  userAgent: { type: String },
  location: { type: String }
});

module.exports = mongoose.model('LoginHistory', loginHistorySchema);
