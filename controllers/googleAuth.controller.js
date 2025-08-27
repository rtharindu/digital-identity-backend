const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const AuthUser = require('../models/authUser.model');
const LoginHistory = require('../models/loginHistory.model');
const jwt = require('jsonwebtoken');
const config = require('../config/config');

// ✅ Helper to extract IP from request
const getClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0]
    || req.socket?.remoteAddress
    || req.connection?.remoteAddress
    || req.ip
    || 'Unknown IP';
};

// Configure Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: config.GOOGLE_CLIENT_ID,
  clientSecret: config.GOOGLE_CLIENT_SECRET,
  callbackURL: config.GOOGLE_CALLBACK_URL,
  scope: ['profile', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    console.log('Google OAuth profile received:', profile.id);
    
    // Check if user already exists
    let user = await AuthUser.findOne({ 
      $or: [
        { email: profile.emails[0].value },
        { googleId: profile.id }
      ]
    });

    if (user) {
      // Update Google ID if not already set
      if (!user.googleId) {
        user.googleId = profile.id;
        await user.save();
      }
      console.log('Existing user found via Google OAuth:', user.email);
      return done(null, user);
    }

    // Create new user
    user = new AuthUser({
      email: profile.emails[0].value,
      googleId: profile.id,
      firstName: profile.name.givenName || '',
      lastName: profile.name.familyName || '',
      role: 'user',
      isEmailVerified: true, // Google emails are verified
      profilePicture: profile.photos[0]?.value || ''
    });

    await user.save();
    console.log('New user created via Google OAuth:', user.email);
    
    return done(null, user);
  } catch (error) {
    console.error('Google OAuth strategy error:', error);
    return done(error, null);
  }
}));

// Serialize user for session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await AuthUser.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Initiate Google OAuth login
const initiateGoogleLogin = (req, res, next) => {
  console.log('Initiating Google OAuth login');
  console.log('Callback URL configured:', config.GOOGLE_CALLBACK_URL);
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })(req, res, next);
};

// Handle Google OAuth callback
const handleGoogleCallback = (req, res, next) => {
  passport.authenticate('google', { 
    failureRedirect: '/login',
    session: false 
  }, async (err, user) => {
    if (err) {
      console.error('Google OAuth callback error:', err);
      // Log failed attempt
      try {
        const ip = getClientIP(req);
        await LoginHistory.create({ 
          email: 'google_oauth_attempt', 
          ip, 
          status: 'failure', 
          timestamp: new Date(), 
          userId: null 
        });
      } catch (historyErr) {
        console.error('Failed to log Google OAuth error to history:', historyErr);
      }
      return res.redirect('/login?error=oauth_failed');
    }

    if (!user) {
      console.error('No user returned from Google OAuth');
      // Log failed attempt
      try {
        const ip = getClientIP(req);
        await LoginHistory.create({ 
          email: 'google_oauth_attempt', 
          ip, 
          status: 'failure', 
          timestamp: new Date(), 
          userId: null 
        });
      } catch (historyErr) {
        console.error('Failed to log Google OAuth error to history:', historyErr);
      }
      return res.redirect('/login?error=no_user');
    }

    try {
      // Generate JWT token
      console.log('[GoogleOAuth] Generating JWT with secret:', config.JWT_SECRET.substring(0, 10) + '...');
      const token = jwt.sign(
        { 
          id: user._id, 
          email: user.email, 
          role: user.role 
        },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
      );

      // Log the successful login
      console.log('Google OAuth login successful for user:', user.email);

      // Log to LoginHistory
      try {
        const ip = getClientIP(req);
        await LoginHistory.create({ 
          email: user.email, 
          ip, 
          status: 'success', 
          timestamp: new Date(), 
          userId: user._id,
          loginMethod: 'google_oauth',
          userAgent: req.headers['user-agent'] || 'Unknown',
          location: 'Google OAuth'
        });
        console.log('[GoogleOAuth] Login history logged for user:', user.email, 'IP:', ip);
      } catch (historyErr) {
        console.error('Login history creation failed for Google OAuth:', historyErr);
        // Don't block login for history creation failure
      }

      // Create device session
      try {
        const screen = `${req.headers['user-agent'] ? 'Unknown' : 'Unknown'}x${req.headers['user-agent'] ? 'Unknown' : 'Unknown'}`;
        const location = "Google OAuth Login";
        
        await fetch(`${process.env.BACKEND_URL || ''}/api/login`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "User-Agent": req.headers['user-agent'] || 'Unknown'
          },
          body: JSON.stringify({ 
            screenResolution: screen, 
            location,
            userId: user._id,
            userEmail: user.email,
            sessionToken: token.substring(0, 10),
            loginMethod: 'google_oauth'
          })
        });
      } catch (sessionErr) {
        console.error('Session creation failed for Google OAuth:', sessionErr);
        // Don't block login for session creation failure
      }

      // Redirect to frontend with token
      const redirectUrl = `${config.RP_ORIGIN}/auth/google/callback?token=${encodeURIComponent(token)}&user=${encodeURIComponent(JSON.stringify({
        id: user._id,
        email: user.email,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName,
        profilePicture: user.profilePicture
      }))}`;
      
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('Error processing Google OAuth callback:', error);
      // Log failed attempt
      try {
        const ip = getClientIP(req);
        await LoginHistory.create({ 
          email: 'google_oauth_attempt', 
          ip, 
          status: 'failure', 
          timestamp: new Date(), 
          userId: null 
        });
      } catch (historyErr) {
        console.error('Failed to log Google OAuth error to history:', historyErr);
      }
      res.redirect('/login?error=token_generation_failed');
    }
  })(req, res, next);
};

// Link Google account to existing user
  const linkGoogleAccount = async (req, res) => {
  try {
    const { googleId, email } = req.body;
    const userId = req.user.id;

    if (!googleId || !email) {
      return res.status(400).json({ error: 'Google ID and email are required' });
    }

    // Check if Google account is already linked to another user
    const existingUser = await AuthUser.findOne({ 
      googleId,
      _id: { $ne: userId }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'This Google account is already linked to another user' });
    }

    // Update current user with Google ID
    const user = await AuthUser.findByIdAndUpdate(
      userId,
      { 
        googleId,
        isEmailVerified: true // Google emails are verified
      },
      { new: true }
    );

    console.log('Google account linked successfully for user:', user.email);
    res.json({ success: true, message: 'Google account linked successfully' });
  } catch (error) {
    console.error('Error linking Google account:', error);
    res.status(500).json({ error: 'Failed to link Google account' });
  }
};

// Unlink Google account
  const unlinkGoogleAccount = async (req, res) => {
  try {
    const userId = req.user.id;

    const user = await AuthUser.findByIdAndUpdate(
      userId,
      { 
        $unset: { googleId: 1 }
      },
      { new: true }
    );

    console.log('Google account unlinked successfully for user:', user.email);
    res.json({ success: true, message: 'Google account unlinked successfully' });
  } catch (error) {
    console.error('Error unlinking Google account:', error);
    res.status(500).json({ error: 'Failed to unlink Google account' });
  }
};

module.exports = {
  initiateGoogleLogin,
  handleGoogleCallback,
  linkGoogleAccount,
  unlinkGoogleAccount
};
