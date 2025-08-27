const UserProfile = require('../models/userProfile.model');
const AuthUser = require('../models/authUser.model');

// Get user profile
exports.getProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    
    let profile = await UserProfile.findOne({ userId }).populate('userId', 'email role createdAt');
    
    // If no profile exists, create a default one
    if (!profile) {
      const authUser = await AuthUser.findById(userId);
      if (!authUser) {
        return res.status(404).json({ message: 'User not found' });
      }

      profile = new UserProfile({
        userId,
        email: authUser.email,
        fullName: authUser.email.split('@')[0], // Default name from email
        language: 'English'
      });
      
      await profile.save();
      await profile.populate('userId', 'email role createdAt');
    }

    res.json({
      success: true,
      profile: {
        id: profile._id,
        userId: profile.userId._id,
        email: profile.email,
        fullName: profile.fullName,
        phone: profile.phone,
        dateOfBirth: profile.dateOfBirth,
        location: profile.location,
        language: profile.language,
        profilePicture: profile.profilePicture,
        bio: profile.bio,
        timezone: profile.timezone,
        notifications: profile.notifications,
        privacy: profile.privacy,
        accountInfo: {
          email: profile.userId.email,
          role: profile.userId.role,
          accountCreated: profile.userId.createdAt,
          lastUpdated: profile.updatedAt
        }
      }
    });
  } catch (error) {
    console.error('[Get Profile] Error:', error);
    res.status(500).json({ message: 'Failed to fetch profile', error: error.message });
  }
};

// Update user profile
exports.updateProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    const updates = req.body;

    // Fields that can be updated
    const allowedUpdates = [
      'fullName', 'phone', 'dateOfBirth', 'location', 'language', 
      'profilePicture', 'bio', 'timezone', 'notifications', 'privacy'
    ];

    // Filter out non-allowed updates
    const filteredUpdates = {};
    Object.keys(updates).forEach(key => {
      if (allowedUpdates.includes(key)) {
        filteredUpdates[key] = updates[key];
      }
    });

    // Validate data
    if (filteredUpdates.fullName && filteredUpdates.fullName.trim().length === 0) {
      return res.status(400).json({ message: 'Full name cannot be empty' });
    }

    if (filteredUpdates.phone && filteredUpdates.phone.length > 0) {
      // Basic phone validation
      const phoneRegex = /^[\+]?[0-9\s\-\(\)]{7,20}$/;
      if (!phoneRegex.test(filteredUpdates.phone)) {
        return res.status(400).json({ message: 'Invalid phone number format' });
      }
    }

    if (filteredUpdates.bio && filteredUpdates.bio.length > 500) {
      return res.status(400).json({ message: 'Bio cannot exceed 500 characters' });
    }

    // Find and update profile
    const profile = await UserProfile.findOneAndUpdate(
      { userId },
      filteredUpdates,
      { new: true, runValidators: true }
    ).populate('userId', 'email role createdAt');

    if (!profile) {
      return res.status(404).json({ message: 'Profile not found' });
    }

    res.json({
      success: true,
      message: 'Profile updated successfully',
      profile: {
        id: profile._id,
        userId: profile.userId._id,
        email: profile.email,
        fullName: profile.fullName,
        phone: profile.phone,
        dateOfBirth: profile.dateOfBirth,
        location: profile.location,
        language: profile.language,
        profilePicture: profile.profilePicture,
        bio: profile.bio,
        timezone: profile.timezone,
        notifications: profile.notifications,
        privacy: profile.privacy,
        accountInfo: {
          email: profile.userId.email,
          role: profile.userId.role,
          accountCreated: profile.userId.createdAt,
          lastUpdated: profile.updatedAt
        }
      }
    });
  } catch (error) {
    console.error('[Update Profile] Error:', error);
    
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({ message: 'Validation failed', errors: validationErrors });
    }
    
    res.status(500).json({ message: 'Failed to update profile', error: error.message });
  }
};

// Delete user profile (soft delete - mark as inactive)
exports.deleteProfile = async (req, res) => {
  try {
    const userId = req.user.id;

    const profile = await UserProfile.findOneAndUpdate(
      { userId },
      { 
        deletedAt: new Date(),
        isActive: false 
      },
      { new: true }
    );

    if (!profile) {
      return res.status(404).json({ message: 'Profile not found' });
    }

    res.json({
      success: true,
      message: 'Profile deactivated successfully'
    });
  } catch (error) {
    console.error('[Delete Profile] Error:', error);
    res.status(500).json({ message: 'Failed to delete profile', error: error.message });
  }
};

// Get profile by admin (for admin panel)
exports.getProfileByAdmin = async (req, res) => {
  try {
    const { userId } = req.params;

    const profile = await UserProfile.findOne({ userId }).populate('userId', 'email role createdAt');

    if (!profile) {
      return res.status(404).json({ message: 'Profile not found' });
    }

    res.json({
      success: true,
      profile
    });
  } catch (error) {
    console.error('[Get Profile By Admin] Error:', error);
    res.status(500).json({ message: 'Failed to fetch profile', error: error.message });
  }
};