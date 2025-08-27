const mongoose = require('mongoose');

const passkeySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AuthUser',
    required: true
  },
  credentialID: {
    type: String,
    required: true,
    unique: true
  },
  publicKey: {
    type: String,
    required: true
  },
  counter: {
    type: Number,
    default: 0
  },
  transports: [{
    type: String,
    enum: ['usb', 'nfc', 'ble', 'internal', 'hybrid']
  }],
  backupEligible: {
    type: Boolean,
    default: false
  },
  backupState: {
    type: Boolean,
    default: false
  },
  deviceType: {
    type: String,
    enum: ['platform', 'cross-platform'],
    default: 'platform'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastUsed: {
    type: Date,
    default: Date.now
  }
});

// Index for faster lookups
passkeySchema.index({ userId: 1 });
passkeySchema.index({ credentialID: 1 });

module.exports = mongoose.model('Passkey', passkeySchema);
