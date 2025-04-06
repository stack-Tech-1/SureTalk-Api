require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { db, FieldValue } = require('./firebase');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const dns = require('dns').promises;
const sanitizeHtml = require('sanitize-html');
const nodemailer = require('nodemailer');
const winston = require('winston');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

// ==================== Initialize Express ====================
const app = express();

// ==================== Logger Configuration (Winston) ====================
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// ==================== Security Middlewares ====================
app.use(helmet());
app.set('trust proxy', 1); // Trust first proxy (Render's load balancer)

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Increased from 5 to 100 requests per window
  message: 'Too many signup attempts from this IP',
  standardHeaders: true,
  legacyHeaders: false
});

// ==================== CORS Configuration ====================
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [
  'https://suretalk-signup.onrender.com',
  'http://localhost:3000'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

// ==================== Email Configuration ====================
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  },
  logger: true,
  debug: true
});

// ==================== Helper Functions ====================
const disposableDomains = process.env.DISPOSABLE_DOMAINS?.split(',') || [
  'tempmail.com', 
  'mailinator.com'
];

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const isDisposableEmail = (email) => {
  const domain = email.split('@')[1];
  return disposableDomains.includes(domain);
};

const isDomainValid = async (email) => {
  try {
    await dns.resolveMx(email.split('@')[1]);
    return true;
  } catch {
    return false;
  }
};

const generateUserId = () => {
  return crypto.randomBytes(16).toString('hex');
};

const sendVerificationEmail = async (email, userId) => {
  const token = crypto.randomBytes(32).toString('hex');
  
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + 24); // 24 hours from now

  logger.debug('Generated token', { 
    token, 
    email, 
    userId,
    expiresAt,
    serverTime: new Date(),
    firestoreServerTime: FieldValue.serverTimestamp()
  });

  await db.collection('verification-tokens').doc(token).set({
    email,
    userId,
    expiresAt,
    used: false,
    createdAt: FieldValue.serverTimestamp()
  });

  const doc = await db.collection('verification-tokens').doc(token).get();
  if (!doc.exists) {
    throw new Error('Token not saved in Firestore');
  }

  const verificationLink = `${process.env.FRONTEND_URL}/recover-account?token=${token}&email=${encodeURIComponent(email)}&userId=${userId}`;

  await transporter.sendMail({
    from: `"SureTalk" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify Your Email Address',
    html: `
      <p>Please click the link below to verify your email:</p>
      <a href="${verificationLink}">Verify Email</a>
      <p>Link expires in 24 hours.</p>
    `
  });
};

function generateAuthToken(userId) {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ==================== Routes ====================
app.post('/api/signup', limiter, async (req, res) => {
  try {
    let { firstName, email, phone, userPin, userId, ...rest } = req.body;

    // Validation
    if (!firstName || !email || !phone || !userPin) {
      logger.warn('Missing fields', { email });
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: { requires: ['firstName', 'email', 'phone', 'userPin'] }
      });
    }

    const normalizedEmail = sanitizeHtml(email).toLowerCase().trim();

    if (!isValidEmail(normalizedEmail)) {
      logger.warn('Invalid email format', { email: normalizedEmail });
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (isDisposableEmail(normalizedEmail)) {
      logger.warn('Disposable email attempt', { email: normalizedEmail });
      return res.status(400).json({ error: 'Disposable emails not allowed' });
    }

    if (!(await isDomainValid(normalizedEmail))) {
      logger.warn('Invalid email domain', { email: normalizedEmail });
      return res.status(400).json({ error: 'Email domain does not exist' });
    }

    // Generate userId if not provided
    userId = userId || generateUserId();

    // Check for existing email or userId
    const usersRef = db.collection('users');
    const emailQuery = await usersRef.where('email', '==', normalizedEmail).limit(1).get();
    const userIdQuery = await usersRef.where('userId', '==', userId).limit(1).get();

    if (!emailQuery.empty) {
      logger.warn('Duplicate email attempt', { email: normalizedEmail });
      return res.status(409).json({ error: 'Email already registered' });
    }

    if (!userIdQuery.empty) {
      logger.warn('Duplicate userId attempt', { userId });
      return res.status(409).json({ error: 'User ID already exists' });
    }

    // Create user with userId as document ID
    await usersRef.doc(userId).set({
      userId,
      firstName: sanitizeHtml(firstName),
      email: normalizedEmail,
      phone: sanitizeHtml(phone),
      userPin: await bcrypt.hash(userPin, parseInt(process.env.BCRYPT_SALT_ROUNDS || 12)),
      ...rest,
      isInterestedInPartnership: Boolean(rest.joinProgram),
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      status: 'pending',
      verified: false,
      emailVerified: false
    });

    // Send verification email
    await sendVerificationEmail(normalizedEmail, userId);
    logger.info('User created and verification email sent', { userId, email: normalizedEmail });

    res.status(201).json({
      success: true,
      message: 'User created. Verification email sent.',
      userId
    });

  } catch (error) {
    logger.error('Signup failed', { 
      error: error.message,
      stack: error.stack 
    });
    res.status(500).json({ 
      error: 'Registration failed',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== Email Verification Route ====================
app.get('/api/verify-email', async (req, res) => {
  const { token, email, userId } = req.query;
  
  try {
    // 1. Validate token exists
    const tokenDoc = await db.collection('verification-tokens').doc(token).get();
    if (!tokenDoc.exists) {
      logger.error('Token not found', { token });
      return res.redirect('https://suretalk-signup.onrender.com/failedEmailVerification.html?error=invalid_token');
    }

    // 2. Check token usage and expiration
    const tokenData = tokenDoc.data();
    if (tokenData.used) {
      return res.redirect('https://suretalk-signup.onrender.com/failedEmailVerification.html?error=used_token');
    }

    let expiresAt = tokenData.expiresAt;
    if (expiresAt?.toDate) expiresAt = expiresAt.toDate();
    if (new Date() > new Date(expiresAt)) {
      return res.redirect('https://suretalk-signup.onrender.com/failedEmailVerification.html?error=expired_token');
    }

    // 3. Verify user exists
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      logger.error('User not found during verification', { userId });
      return res.redirect('https://suretalk-signup.onrender.com/failedEmailVerification.html?error=user_not_found');
    }

    // 4. Update records
    await db.collection('verification-tokens').doc(token).update({ used: true });
    await db.collection('users').doc(userId).update({
      emailVerified: true,
      status: 'active',
      updatedAt: FieldValue.serverTimestamp()
    });

    // 5. Successful redirect
    res.setHeader('Cache-Control', 'no-store');
    return res.redirect('https://buy.stripe.com/bIY1806DG7qw6uk144?verified=true');

  } catch (error) {
    logger.error('Verification failed', { error: error.message });
    return res.redirect('https://suretalk-signup.onrender.com/failedEmailVerification.html?error=server_error');
  }
});

// ==================== Google Auth Endpoint ====================
app.post('/api/google-auth', async (req, res) => {
  try {
    const { credential } = req.body;
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const email = payload.email;
    const userId = generateUserId();
    
    // Check if user exists by email
    const usersRef = db.collection('users');
    const querySnapshot = await usersRef.where('email', '==', email).limit(1).get();
    
    if (querySnapshot.empty) {
      // Create new user with userId as document ID
      await usersRef.doc(userId).set({
        userId,
        email,
        firstName: payload.given_name || '',
        lastName: payload.family_name || '',
        emailVerified: true,
        status: 'active',
        createdAt: FieldValue.serverTimestamp()
      });
    }
    
    // Generate JWT token with userId
    const token = generateAuthToken(querySnapshot.empty ? userId : querySnapshot.docs[0].id);
    
    res.json({ token });
  } catch (error) {
    logger.error('Google auth failed', { error });
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email
    const querySnapshot = await db.collection('users')
      .where('email', '==', email)
      .limit(1)
      .get();

    if (querySnapshot.empty) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userDoc = querySnapshot.docs[0];
    const user = userDoc.data();
    
    if (!user.emailVerified) {
      return res.status(403).json({ error: 'Email not verified' });
    }
    
    const validPassword = await bcrypt.compare(password, user.userPin);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token with userId
    const token = generateAuthToken(user.userId);
    res.json({ 
      token,
      userId: user.userId,
      firstName: user.firstName,
      email: user.email
    });
  } catch (error) {
    logger.error('Login failed', { error });
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==================== Recovery Endpoints ====================

// Request recovery
app.post('/api/request-recovery', limiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const normalizedEmail = sanitizeHtml(email).toLowerCase().trim();

    // Check if user exists
    const querySnapshot = await db.collection('users')
      .where('email', '==', normalizedEmail)
      .limit(1)
      .get();

    if (querySnapshot.empty) {
      return res.status(404).json({ error: 'No account found with this email' });
    }

    const userDoc = querySnapshot.docs[0];
    const user = userDoc.data();

    // Generate recovery token
    const recoveryToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiration

    // Save recovery token
    await db.collection('recovery-tokens').doc(recoveryToken).set({
      email: normalizedEmail,
      userId: user.userId,
      expiresAt,
      used: false,
      createdAt: FieldValue.serverTimestamp()
    });

    // Send recovery email
    const recoveryLink = `${process.env.FRONTEND_URL}/recover-account?token=${recoveryToken}`;
    
    await transporter.sendMail({
      from: `"SureTalk Support" <${process.env.EMAIL_USER}>`,
      to: normalizedEmail,
      subject: 'Account Recovery Request',
      html: `
        <p>We received a request to recover your account information.</p>
        <p>Click the link below to view your User ID and PIN (valid for 1 hour):</p>
        <a href="${recoveryLink}">Recover Account</a>
        <p>If you didn't request this, please ignore this email.</p>
      `
    });

    res.json({ 
      success: true, 
      message: 'Recovery email sent. Please check your inbox.' 
    });

  } catch (error) {
    logger.error('Recovery request failed', { error });
    res.status(500).json({ error: 'Account recovery failed' });
  }
});

// Verify recovery token and send credentials
app.post('/api/complete-recovery', limiter, async (req, res) => {
  try {
    const { token } = req.body;
    
    // Enhanced validation and logging
    if (!token) {
      logger.error('Missing token in request');
      return res.status(400).json({ error: 'Recovery token is required' });
    }

    if (token.length !== 64) {
      logger.error('Invalid token length', { tokenLength: token.length });
      return res.status(400).json({ error: 'Invalid token format' });
    }

    logger.debug('Processing recovery token', { 
      tokenPrefix: token.substring(0, 8) + '...',
      collection: 'recovery-tokens'
    });

    // Debug: List all tokens in collection (remove in production)
    const allTokens = await db.collection('recovery-tokens').limit(5).get();
    logger.debug('First 5 tokens in collection', {
      tokens: allTokens.docs.map(doc => doc.id)
    });

    // Get token document with proper error handling
    let tokenDoc;
    try {
      tokenDoc = await db.collection('recovery-tokens').doc(token).get();
    } catch (err) {
      logger.error('Firestore query failed', { error: err.message });
      return res.status(500).json({ error: 'Database error' });
    }

    if (!tokenDoc.exists) {
      logger.error('Token not found in Firestore', { 
        token: token,
        collection: 'recovery-tokens'
      });
      return res.status(404).json({ 
        error: 'Invalid or expired recovery link',
        code: 'TOKEN_NOT_FOUND'
      });
    }

    const tokenData = tokenDoc.data();
    logger.debug('Token document found', { 
      email: tokenData.email,
      userId: tokenData.userId,
      expiresAt: tokenData.expiresAt,
      used: tokenData.used
    });

    // Convert Firestore timestamp if needed
    let expiresAt = tokenData.expiresAt;
    if (expiresAt?.toDate) expiresAt = expiresAt.toDate();
    if (typeof expiresAt === 'string') expiresAt = new Date(expiresAt);

    // Validation checks
    if (tokenData.used) {
      logger.warn('Recovery token already used', { token });
      return res.status(400).json({ 
        error: 'This recovery link has already been used',
        code: 'TOKEN_USED'
      });
    }

    if (new Date() > new Date(expiresAt)) {
      logger.warn('Recovery token expired', { 
        token, 
        expiresAt,
        currentTime: new Date() 
      });
      return res.status(400).json({ 
        error: 'This recovery link has expired',
        code: 'TOKEN_EXPIRED'
      });
    }

    // Get user document
    const userDoc = await db.collection('users').doc(tokenData.userId).get();
    if (!userDoc.exists) {
      logger.error('User not found during recovery', { 
        userId: tokenData.userId 
      });
      return res.status(404).json({ 
        error: 'User account not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Generate secure temporary PIN
    const tempPin = crypto.randomInt(1000, 9999).toString();
    const tempPinExpiry = new Date(Date.now() + 3600000); // 1 hour
    
    // Batch write for atomic updates
    const batch = db.batch();
    batch.update(db.collection('recovery-tokens').doc(token), { 
      used: true,
      usedAt: FieldValue.serverTimestamp() 
    });
    batch.update(db.collection('users').doc(tokenData.userId), {
      tempPin: await bcrypt.hash(tempPin, 12),
      tempPinExpiry,
      requiresPinReset: true,
      updatedAt: FieldValue.serverTimestamp()
    });
    
    await batch.commit();

    // Send email with temporary credentials
    await transporter.sendMail({
      from: `"SureTalk Support" <${process.env.EMAIL_USER}>`,
      to: tokenData.email,
      subject: 'Your Temporary Access Details',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2c3e50;">Account Recovery</h2>
          <p>Here are your temporary access details:</p>
          <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p><strong>User ID:</strong> <span style="font-family: monospace;">${tokenData.userId}</span></p>
            <p><strong>Temporary PIN:</strong> <span style="font-size: 1.2em; font-weight: bold;">${tempPin}</span></p>
            <p><em>Expires: ${tempPinExpiry.toLocaleString()}</em></p>
          </div>
          <p style="color: #7f8c8d;">If you didn't request this, please secure your account immediately.</p>
        </div>
      `
    });

    logger.info('Recovery completed successfully', { 
      userId: tokenData.userId,
      email: tokenData.email 
    });

    return res.json({ 
      success: true,
      message: 'Temporary access details have been sent to your email'
    });

  } catch (error) {
    logger.error('Recovery completion failed', {
      error: error.message,
      stack: error.stack
    });
    return res.status(500).json({ 
      error: 'Failed to complete account recovery',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ==================== Server Startup ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server started on port ${PORT}`, {
    environment: process.env.NODE_ENV || 'development',
    allowedOrigins,
    serverTime: new Date()
  });
});