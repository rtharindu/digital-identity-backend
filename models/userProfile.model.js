const mongoose = require('mongoose');

const userProfileSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AuthUser',
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true
  },
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    trim: true
  },
  dateOfBirth: {
    type: Date
  },
  location: {
    type: String,
    trim: true
  },
  language: {
    type: String,
    enum: ['English', 'Sinhala', 'Tamil'],
    default: 'English'
  },
  profilePicture: {
    type: String // URL to profile picture
  },
  bio: {
    type: String,
    maxlength: 500
  },
  timezone: {
    type: String,
    default: 'Asia/Colombo'
  },
  notifications: {
    email: {
      type: Boolean,
      default: true
    },
    sms: {
      type: Boolean,
      default: false
    },
    push: {
      type: Boolean,
      default: true
    }
  },
  privacy: {
    profileVisibility: {
      type: String,
      enum: ['public', 'private'],
      default: 'private'
    },
    showEmail: {
      type: Boolean,
      default: false
    },
    showPhone: {
      type: Boolean,
      default: false
    }
  }
}, {
  timestamps: true
});

// Index for faster queries
userProfileSchema.index({ userId: 1 });
userProfileSchema.index({ email: 1 });

module.exports = mongoose.model('UserProfile', userProfileSchema);