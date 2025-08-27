const LoginHistory = require('../models/loginHistory.model');

// Dummy data (optional endpoint)
exports.addDummyData = async (req, res) => {
  try {
    const dummy = [
      {
        userId: '000000000000000000000001',
        email: 'user1@example.com',
        ip: '192.168.1.10',
        status: 'success',
        timestamp: new Date(Date.now() - 86400000)
      },
      {
        userId: '000000000000000000000002',
        email: 'user2@example.com',
        ip: '192.168.1.11',
        status: 'failure',
        timestamp: new Date(Date.now() - 43200000)
      },
      {
        userId: '000000000000000000000001',
        email: 'user1@example.com',
        ip: '192.168.1.10',
        status: 'success',
        timestamp: new Date()
      }
    ];
    await LoginHistory.insertMany(dummy);
    res.json({ message: 'Dummy login history added.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to add dummy data', error: err.message });
  }
};

// GET /logs/login-history?email=user@example.com
exports.getAll = async (req, res) => {
  try {
    const { email } = req.query;
    const userRole = req.user.role;
    const userEmail = req.user.email;

    let filter = {};

    if (userRole === 'admin') {
      // Admins can see all login history or filter by specific email
      filter = email ? { email } : {};
    } else {
      // Regular users can only see their own login history
      filter = { email: userEmail };
    }

    const history = await LoginHistory.find(filter).sort({ timestamp: -1 });
    res.json(history);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch login history', error: err.message });
  }
};
