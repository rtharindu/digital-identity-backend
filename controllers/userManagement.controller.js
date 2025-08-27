const AuthUser = require('../models/authUser.model');
const UserProfile = require('../models/userProfile.model');
const LoginHistory = require('../models/loginHistory.model');
const Session = require('../models/Session');

// Search users with filters
exports.searchUsers = async (req, res) => {
  try {
    const { 
      searchTerm, 
      role, 
      status, 
      page = 1, 
      limit = 10,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    // Build filter object
    let filter = {};
    
    if (searchTerm) {
      filter.$or = [
        { email: { $regex: searchTerm, $options: 'i' } }
      ];
    }
    
    if (role) {
      filter.role = role;
    }

    // Calculate pagination
    const skip = (page - 1) * limit;
    const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

    // Get users with pagination
    const users = await AuthUser.find(filter)
      .select('-password')
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const total = await AuthUser.countDocuments(filter);

    // Get additional data for each user
    const usersWithDetails = await Promise.all(
      users.map(async (user) => {
        // Get profile data
        const profile = await UserProfile.findOne({ userId: user._id });
        
        // Get last login
        const lastLogin = await LoginHistory.findOne({ 
          userId: user._id, 
          status: 'success' 
        }).sort({ timestamp: -1 });

        // Get active sessions count
        const activeSessions = await Session.countDocuments({ 
          userId: user._id, 
          status: 'Active' 
        });

        return {
          ...user.toObject(),
          profile: profile || null,
          lastLogin: lastLogin ? lastLogin.timestamp : null,
          activeSessions,
          status: activeSessions > 0 ? 'Active' : 'Inactive'
        };
      })
    );

    res.json({
      users: usersWithDetails,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalUsers: total,
        usersPerPage: parseInt(limit)
      }
    });
  } catch (err) {
    console.error('[SearchUsers] Error:', err);
    res.status(500).json({ message: 'Failed to search users', error: err.message });
  }
};

// Get user details by ID
exports.getUserDetails = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await AuthUser.findById(userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get profile data
    const profile = await UserProfile.findOne({ userId });
    
    // Get login history
    const loginHistory = await LoginHistory.find({ userId })
      .sort({ timestamp: -1 })
      .limit(10);

    // Get active sessions
    const activeSessions = await Session.find({ 
      userId, 
      status: 'Active' 
    }).sort({ lastSeen: -1 });

    res.json({
      user: {
        ...user.toObject(),
        profile: profile || null,
        loginHistory,
        activeSessions
      }
    });
  } catch (err) {
    console.error('[GetUserDetails] Error:', err);
    res.status(500).json({ message: 'Failed to get user details', error: err.message });
  }
};

// Update user role
exports.updateUserRole = async (req, res) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role. Must be "user" or "admin"' });
    }

    const user = await AuthUser.findByIdAndUpdate(
      userId,
      { role },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ 
      message: 'User role updated successfully',
      user 
    });
  } catch (err) {
    console.error('[UpdateUserRole] Error:', err);
    res.status(500).json({ message: 'Failed to update user role', error: err.message });
  }
};

// Delete user
exports.deleteUser = async (req, res) => {
  try {
    const { userId } = req.params;

    // Check if user exists
    const user = await AuthUser.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Prevent admin from deleting themselves
    if (req.user.id === userId) {
      return res.status(400).json({ message: 'Cannot delete your own account' });
    }

    // Delete user and related data
    await Promise.all([
      AuthUser.findByIdAndDelete(userId),
      UserProfile.findOneAndDelete({ userId }),
      Session.deleteMany({ userId }),
      LoginHistory.deleteMany({ userId })
    ]);

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('[DeleteUser] Error:', err);
    res.status(500).json({ message: 'Failed to delete user', error: err.message });
  }
};

// Get user statistics
exports.getUserStats = async (req, res) => {
  try {
    const totalUsers = await AuthUser.countDocuments();
    const adminUsers = await AuthUser.countDocuments({ role: 'admin' });
    const regularUsers = await AuthUser.countDocuments({ role: 'user' });
    
    const activeSessions = await Session.countDocuments({ status: 'Active' });
    const todayLogins = await LoginHistory.countDocuments({
      status: 'success',
      timestamp: { $gte: new Date().setHours(0, 0, 0, 0) }
    });

    res.json({
      totalUsers,
      adminUsers,
      regularUsers,
      activeSessions,
      todayLogins
    });
  } catch (err) {
    console.error('[GetUserStats] Error:', err);
    res.status(500).json({ message: 'Failed to get user statistics', error: err.message });
  }
}; 