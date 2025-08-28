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
const getRPInfo = () => {
  return {
    rpID: config.RP_ID || 'localhost',
    rpName: config.RP_NAME || 'Digital Identity Hub',
    origin: config.RP_ORIGIN || 'http://localhost:3000'
  };
};

// Helper function to create a unique challenge ID
const generateChallengeId = () => {
  return `challenge_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

// Helper function to store challenge in database
const storeChallenge = async (userId, challenge, type = 'registration') => {
  const challengeId = generateChallengeId();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes from now
  
  // Store in database (you can create a separate Challenge model or use a simple approach)
  // For now, we'll store it in the user document as a temporary field
  await AuthUser.findByIdAndUpdate(userId, {
    $set: {
      tempChallenge: {
        id: challengeId,
        challenge: challenge,
        type: type,
        expiresAt: expiresAt
      }
    }
  });
  
  return challengeId;
};

// Helper function to retrieve and validate challenge
const getChallenge = async (userId, type = 'registration') => {
  const user = await AuthUser.findById(userId);
  if (!user || !user.tempChallenge) {
    return null;
  }
  
  const challengeData = user.tempChallenge;
  
  // Check if challenge is expired
  if (new Date() > challengeData.expiresAt) {
    // Clean up expired challenge
    await AuthUser.findByIdAndUpdate(userId, {
      $unset: { tempChallenge: 1 }
    });
    return null;
  }
  
  // Check if challenge type matches
  if (challengeData.type !== type) {
    return null;
  }
  
  return challengeData.challenge;
};

// Helper function to clear challenge
const clearChallenge = async (userId) => {
  await AuthUser.findByIdAndUpdate(userId, {
    $unset: { tempChallenge: 1 }
  });
};

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

    // Store challenge in database
    const challengeId = await storeChallenge(user._id.toString(), options.challenge, 'registration');
    
    console.log('Challenge stored in database:', { 
      challengeId,
      userId: user._id.toString(),
      challenge: options.challenge
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
    console.log('Session ID:', req.sessionID);
    console.log('Session cookie:', req.headers.cookie);
    
    const { credential } = req.body;
    if (!credential) {
      console.log('No credential in request body');
      return res.status(400).json({ error: 'Credential is required' });
    }

    // Get user from authentication token
    const userId = req.user.id;
    if (!userId) {
      console.log('No user ID in token');
      return res.status(401).json({ error: 'User not authenticated' });
    }

    // Get challenge from database
    const challenge = await getChallenge(userId, 'registration');
    
    console.log('Retrieved challenge from database:', { 
      userId,
      challenge: challenge ? 'Present' : 'Missing'
    });

    // Check if challenge exists
    if (!challenge) {
      console.log('No valid challenge found for user:', userId);
      return res.status(400).json({ 
        error: 'Registration session expired or invalid. Please try registering again.',
        code: 'SESSION_EXPIRED'
      });
    }

    const { rpID, origin } = getRPInfo();
    console.log('RP Info for verification:', { rpID, origin });

    console.log('Starting WebAuthn verification...');
    
    // Verify the registration response
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challenge,
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
        userId: userId,
        credentialID: credentialID,
        publicKey: publicKey,
        counter: counter,
        transports: transports
      });

      await passkey.save();
      console.log('Passkey registered successfully for user:', userId);
      
      // Clear session data from temporary storage
      await clearChallenge(userId);

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

    // Store challenge in database
    const challengeId = await storeChallenge(user._id.toString(), options.challenge, 'authentication');
    
    console.log('Authentication challenge stored in database:', { 
      challengeId,
      userId: user._id.toString(),
      challenge: options.challenge
    });

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

    // Get challenge from database
    const challenge = await getChallenge(passkey.userId.toString(), 'authentication');
    
    console.log('Retrieved authentication challenge from database:', { 
      userId: passkey.userId.toString(),
      challenge: challenge ? 'Present' : 'Missing'
    });

    if (!challenge) {
      console.log('No valid authentication challenge found for user:', passkey.userId.toString());
      return res.status(400).json({ 
        error: 'Authentication session expired. Please try logging in again.',
        code: 'SESSION_EXPIRED'
      });
    }

    // Verify the authentication response
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
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
      
      // Clear challenge from database
      await clearChallenge(passkey.userId.toString());

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
