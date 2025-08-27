const UAParser = require('ua-parser-js');
const Session = require('../models/Session');

// Known screen resolutions → device mappings
const deviceMap = {
  '375x667': 'iPhone SE / 7 / 8',
  '390x844': 'iPhone 13 / 14',
  '414x896': 'iPhone XR / 11',
  '428x926': 'iPhone 13 Pro Max',
  '768x1024': 'iPad Air / Mini',
  '2560x1600': 'MacBook Pro 13"',
};

exports.createSession = async (req, res) => {
  try {
    const { screenResolution, location, userId, userEmail, sessionToken } = req.body;
    const ua = req.headers['user-agent'];
    const parser = new UAParser(ua);
    const result = parser.getResult();

    // Get IP in a cross-platform-safe way
    const ip =
      req.headers['x-forwarded-for']?.split(',')[0] ||
      req.socket?.remoteAddress ||
      req.connection?.remoteAddress ||
      req.ip;

    // Resolve device name
    const deviceName = deviceMap[screenResolution] ||
      result.device.model ||
      'Unknown Device';

    // Check if a session already exists for this user and device combination
    const existingSession = await Session.findOne({
      userId,
      device: deviceName,
      browser: result.browser.name || 'Unknown',
      ipAddress: ip || 'Unknown IP',
      status: 'Active'
    });

    if (existingSession) {
      // Update existing session
      existingSession.lastSeen = new Date().toLocaleString();
      existingSession.sessionToken = sessionToken;
      await existingSession.save();
      return res.status(200).json({ success: true, session: existingSession });
    }

    // Create new session
    const session = new Session({
      userId,
      userEmail,
      device: deviceName,
      browser: result.browser.name || 'Unknown',
      location: location || 'Unknown',
      ipAddress: ip || 'Unknown IP',
      lastSeen: new Date().toLocaleString(),
      sessionToken,
      status: 'Active'
    });

    await session.save();
    res.status(201).json({ success: true, session });
  } catch (error) {
    console.error('[Create Session] Error:', error);
    res.status(500).json({ error: 'Failed to create session' });
  }
};

exports.getSessions = async (req, res) => {
  try {
    // Get sessions only for the authenticated user
    const userId = req.user.id;
    const sessions = await Session.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(sessions);
  } catch (error) {
    console.error('[Get Sessions] Error:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
};

exports.logoutSession = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Only allow users to logout their own sessions
    const updated = await Session.findOneAndUpdate(
      { _id: id, userId },
      {
        status: 'Inactive',
        lastSeen: new Date().toLocaleString()
      }
    );

    if (!updated) {
      return res.status(404).json({ message: 'Session not found or unauthorized' });
    }

    res.status(200).json({ success: true });
  } catch (error) {
    console.error('[Logout Session] Error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
};

exports.logoutAllSessions = async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Only logout sessions for the authenticated user
    await Session.updateMany(
      { userId, status: 'Active' },
      { status: 'Inactive', lastSeen: new Date().toLocaleString() }
    );
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('[Logout All] Error:', error);
    res.status(500).json({ error: 'Logout all failed' });
  }
};
