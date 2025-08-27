const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');
const Passkey = require('../models/passkey.model');
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

// Helper function to get rpID and origin
const getRPInfo = () => ({
  rpID: config.RP_ID,
  rpName: config.RP_NAME,
  origin: config.RP_ORIGIN
});

// Generate registration options for passkey
const generatePasskeyRegistrationOptions = async (req, res) => {
  try {
    console.log('Generating passkey registration options for authenticated user');
    console.log('User from token:', req.user);
    console.log('Session:', req.session);
    
    // Get user from authentication token
    const userId = req.user.id;
    if (!userId) {
      console.log('No user ID in token');
      return res.status(401).json({ error: 'User not authenticated' });
    }

    console.log('Looking for user with ID:', userId);

    // Find user by ID
    const user = await AuthUser.findById(userId);
    if (!user) {
      console.log('User not found for ID:', userId);
      return res.status(404).json({ 
        error: 'User not found',
        code: 'USER_NOT_FOUND',
        suggestion: 'Please check your authentication'
      });
    }

    console.log('User found:', { id: user._id, email: user.email });

    const { rpID, rpName, origin } = getRPInfo();
    console.log('RP Info:', { rpID, rpName, origin });

    // Generate registration options
    console.log('Generating WebAuthn registration options...');
    console.log('User data for registration:', {
      rpName,
      rpID,
      userID: user._id.toString(),
      userName: user.email
    });
    
    // Convert MongoDB ObjectId to Buffer properly
    const userIDBuffer = Buffer.from(user._id.toString(), 'utf8');
    console.log('User ID Buffer:', userIDBuffer);
    
    let options;
    try {
      options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: userIDBuffer,
        userName: user.email,
        attestationType: 'none',
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
          authenticatorAttachment: 'platform'
        },
        supportedAlgorithmIDs: [-7, -257] // ES256, RS256
      });
    } catch (webauthnError) {
      console.error('WebAuthn generateRegistrationOptions error:', webauthnError);
      console.error('WebAuthn error details:', {
        message: webauthnError.message,
        stack: webauthnError.stack,
        code: webauthnError.code
      });
      throw new Error(`WebAuthn registration options generation failed: ${webauthnError.message}`);
    }

    console.log('WebAuthn options generated successfully');
    console.log('Generated options:', {
      challenge: options.challenge ? 'Present' : 'Missing',
      rp: options.rp,
      user: options.user,
      pubKeyCredParams: options.pubKeyCredParams?.length || 0
    });

    // Validate options before storing in session
    if (!options.challenge) {
      throw new Error('Generated options missing challenge');
    }

    // Store challenge in session
    req.session.challenge = options.challenge;
    req.session.userId = user._id.toString();
    
    // Ensure session is saved before sending response
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          reject(err);
        } else {
          console.log('Session updated and saved:', { 
            challenge: options.challenge, 
            userId: req.session.userId,
            sessionId: req.session.id
          });
          resolve();
        }
      });
    });

    console.log('Passkey registration options generated successfully');
    res.json(options);
  } catch (error) {
    console.error('Error generating passkey registration options:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to generate registration options' });
  }
};

// Verify passkey registration
const verifyPasskeyRegistration = async (req, res) => {
  try {
    console.log('Verifying passkey registration');
    console.log('Request body:', req.body);
    console.log('Session data:', req.session);
    
    const { credential } = req.body;
    if (!credential) {
      console.log('No credential in request body');
      return res.status(400).json({ error: 'Credential is required' });
    }

    // Check if session data exists
    if (!req.session.challenge || !req.session.userId) {
      console.log('Missing session data:', { 
        challenge: req.session.challenge ? 'Present' : 'Missing',
        userId: req.session.userId ? 'Present' : 'Missing'
      });
      return res.status(400).json({ 
        error: 'Session expired or invalid. Please try registering again.',
        code: 'SESSION_EXPIRED'
      });
    }

    const { rpID, origin } = getRPInfo();
    console.log('RP Info for verification:', { rpID, origin });

    console.log('Starting WebAuthn verification...');
    
    // Verify the registration response
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: req.session.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false
    });

    console.log('Verification result:', { verified: verification.verified });

    if (verification.verified) {
      console.log('Verification successful, saving passkey...');
      console.log('Verification info:', {
        credentialID: verification.registrationInfo.credentialID,
        publicKey: verification.registrationInfo.credentialPublicKey,
        counter: verification.registrationInfo.counter
      });
      
      // Extract data from the WebAuthn verification response
      const credentialID = isoBase64URL.fromBuffer(verification.registrationInfo.credentialID);
      const publicKey = isoBase64URL.fromBuffer(verification.registrationInfo.credentialPublicKey);
      const counter = verification.registrationInfo.counter || 0;
      
      console.log('Extracted data:', { credentialID, publicKey, counter });
      
      // Validate the extracted data
      if (!credentialID || !publicKey) {
        console.error('Missing required data:', { credentialID: !!credentialID, publicKey: !!publicKey });
        throw new Error('Failed to extract required passkey data from WebAuthn response');
      }
      
      // Additional validation
      if (typeof credentialID !== 'string' || credentialID.length === 0) {
        throw new Error('Invalid credential ID format');
      }
      
      if (typeof publicKey !== 'string' || publicKey.length === 0) {
        throw new Error('Invalid public key format');
      }
      
      if (typeof counter !== 'number' || counter < 0) {
        counter = 0; // Default to 0 if invalid
      }
      
      console.log('Data validation passed, proceeding to save passkey');
      
      // Filter and validate transports
      const validTransports = ['usb', 'nfc', 'ble', 'internal', 'hybrid'];
      const transports = (credential.response.transports || [])
        .filter(transport => validTransports.includes(transport));
      
      console.log('Filtered transports:', transports);
      
      // Save the passkey to database
      const passkey = new Passkey({
        userId: req.session.userId,
        credentialID: credentialID,
        publicKey: publicKey,
        counter: counter,
        transports: transports
      });

      await passkey.save();
      console.log('Passkey registered successfully for user:', req.session.userId);
      
      // Clear session
      delete req.session.challenge;
      delete req.session.userId;

      res.json({ success: true, message: 'Passkey registered successfully' });
    } else {
      console.log('Verification failed');
      res.status(400).json({ error: 'Passkey verification failed' });
    }
  } catch (error) {
    console.error('Error verifying passkey registration:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to verify passkey registration' });
  }
};

// Generate authentication options for passkey login
const generatePasskeyAuthenticationOptions = async (req, res) => {
  try {
    console.log('Generating passkey authentication options');
    console.log('Request body:', req.body);
    
    const { email } = req.body;
    if (!email) {
      console.log('No email provided in request');
      return res.status(400).json({ error: 'Email is required' });
    }

    console.log('Looking for user with email:', email);

    // Find user by email
    const user = await AuthUser.findOne({ email });
    if (!user) {
      console.log('User not found for email:', email);
      return res.status(404).json({ 
        error: 'User not found',
        code: 'USER_NOT_FOUND',
        suggestion: 'Please check your email address or create an account first'
      });
    }

    console.log('User found:', { id: user._id, email: user.email });

    // Get user's passkeys
    const passkeys = await Passkey.find({ userId: user._id });
    console.log('Found passkeys for user:', passkeys.length);
    
    if (passkeys.length === 0) {
      console.log('No passkeys found for user:', user.email);
      return res.status(404).json({ 
        error: 'No passkeys found for this user',
        code: 'NO_PASSKEYS',
        suggestion: 'Please register a passkey first in your profile settings',
        userExists: true,
        email: user.email
      });
    }

    const { rpID } = getRPInfo();
    console.log('Using RP ID:', rpID);

    // Generate authentication options
    console.log('Generating authentication options with passkeys:', passkeys.length);
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: passkeys.map(passkey => {
        console.log('Processing passkey:', { id: passkey.credentialID, transports: passkey.transports });
        return {
          id: isoBase64URL.toBuffer(passkey.credentialID),
          type: 'public-key',
          transports: passkey.transports
        };
      }),
      userVerification: 'preferred'
    });

    // Store challenge in session
    req.session.challenge = options.challenge;
    req.session.userId = user._id.toString();

    console.log('Passkey authentication options generated successfully');
    res.json(options);
  } catch (error) {
    console.error('Error generating passkey authentication options:', error);
    res.status(500).json({ error: 'Failed to generate authentication options' });
  }
};

// Verify passkey authentication
const verifyPasskeyAuthentication = async (req, res) => {
  try {
    console.log('Verifying passkey authentication');
    
    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ error: 'Credential is required' });
    }

    const { rpID, origin } = getRPInfo();

    // Find the passkey
    const passkey = await Passkey.findOne({ 
      credentialID: credential.id 
    });
    
    if (!passkey) {
      return res.status(404).json({ error: 'Passkey not found' });
    }

    // Verify the authentication response
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: req.session.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialPublicKey: isoBase64URL.toBuffer(passkey.publicKey),
        credentialID: isoBase64URL.toBuffer(passkey.credentialID),
        counter: passkey.counter
      },
      requireUserVerification: false
    });

    if (verification.verified) {
      // Update counter
      passkey.counter = verification.authenticationInfo.newCounter;
      passkey.lastUsed = new Date();
      await passkey.save();

      // Get user data
      const user = await AuthUser.findById(passkey.userId);
      
      // Generate JWT token
      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
      );

      console.log('Passkey authentication successful for user:', user.email);
      
      // Log to LoginHistory
      try {
        const ip = getClientIP(req);
        await LoginHistory.create({ 
          email: user.email, 
          ip, 
          status: 'success', 
          timestamp: new Date(), 
          userId: user._id,
          loginMethod: 'passkey',
          userAgent: req.headers['user-agent'] || 'Unknown',
          location: 'Passkey Authentication'
        });
        console.log('[Passkey] Login history logged for user:', user.email, 'IP:', ip);
      } catch (historyErr) {
        console.error('Login history creation failed for passkey:', historyErr);
        // Don't block login for history creation failure
      }
      
      // Clear session
      delete req.session.challenge;
      delete req.session.userId;

      res.json({
        success: true,
        token,
        user: {
          id: user._id,
          email: user.email,
          role: user.role
        }
      });
    } else {
      // Log failed attempt
      try {
        const ip = getClientIP(req);
        await LoginHistory.create({ 
          email: 'passkey_attempt', 
          ip, 
          status: 'failure', 
          timestamp: new Date(), 
          userId: null 
        });
      } catch (historyErr) {
        console.error('Failed to log passkey failure to history:', historyErr);
      }
      res.status(400).json({ error: 'Passkey verification failed' });
    }
  } catch (error) {
    console.error('Error verifying passkey authentication:', error);
    // Log failed attempt
    try {
      const ip = getClientIP(req);
      await LoginHistory.create({ 
        email: 'passkey_attempt', 
        ip, 
        status: 'failure', 
        timestamp: new Date(), 
        userId: null 
      });
    } catch (historyErr) {
      console.error('Failed to log passkey error to history:', historyErr);
    }
    res.status(500).json({ error: 'Failed to verify passkey authentication' });
  }
};

// Get user's passkeys
  const getUserPasskeys = async (req, res) => {
  try {
    const userId = req.user.id;
    const passkeys = await Passkey.find({ userId }).select('-publicKey');
    
    res.json(passkeys);
  } catch (error) {
    console.error('Error fetching user passkeys:', error);
    res.status(500).json({ error: 'Failed to fetch passkeys' });
  }
};

// Delete a passkey
  const deletePasskey = async (req, res) => {
  try {
    const { passkeyId } = req.params;
    const userId = req.user.id;

    const passkey = await Passkey.findOneAndDelete({ 
      _id: passkeyId, 
      userId 
    });

    if (!passkey) {
      return res.status(404).json({ error: 'Passkey not found' });
    }

    res.json({ success: true, message: 'Passkey deleted successfully' });
  } catch (error) {
    console.error('Error deleting passkey:', error);
    res.status(500).json({ error: 'Failed to delete passkey' });
  }
};

module.exports = {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  generatePasskeyAuthenticationOptions,
  verifyPasskeyAuthentication,
  getUserPasskeys,
  deletePasskey
};
