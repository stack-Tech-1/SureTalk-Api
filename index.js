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

// ==================== Logger Configuration ====================
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
app.set('trust proxy', 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP',
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

const generateUserId = () => crypto.randomBytes(16).toString('hex');

const generateToken = () => crypto.randomBytes(32).toString('hex');

// ==================== Email Verification Functions ====================
const sendVerificationEmail = async (email, userId) => {
  const token = generateToken();
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + 24);

  await db.collection('verification-tokens').doc(token).set({
    email,
    userId,
    expiresAt,
    used: false,
    type: 'email-verification',
    createdAt: FieldValue.serverTimestamp()
  });

  // Point directly to API endpoint
  const verificationLink = `https://suretalk-api.onrender.com/api/verify-email?token=${token}&email=${encodeURIComponent(email)}&userId=${userId}`;

  await transporter.sendMail({
    from: `"SureTalk" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify Your Email Address',
    html: `
      <p>Welcome to SureTalk! Please verify your email address:</p>
      <a href="${verificationLink}">Click here to verify your email</a>
      <p>This link expires in 24 hours.</p>
      <p>If you didn't create this account, please ignore this email.</p>
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

// Signup Route
app.post('/api/signup', limiter, async (req, res) => {
  try {
    let { firstName, email, phone, userPin, userId, ...rest } = req.body;

    // Validation
    if (!firstName || !email || !phone || !userPin) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: { requires: ['firstName', 'email', 'phone', 'userPin'] }
      });
    }

    const normalizedEmail = sanitizeHtml(email).toLowerCase().trim();

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (isDisposableEmail(normalizedEmail)) {
      return res.status(400).json({ error: 'Disposable emails not allowed' });
    }

    if (!(await isDomainValid(normalizedEmail))) {
      return res.status(400).json({ error: 'Email domain does not exist' });
    }

    // Generate userId if not provided
    userId = userId || generateUserId();

    // Check for existing user
    const usersRef = db.collection('users');
    const emailQuery = await usersRef.where('email', '==', normalizedEmail).limit(1).get();
    const userIdQuery = await usersRef.where('userId', '==', userId).limit(1).get();

    if (!emailQuery.empty) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    if (!userIdQuery.empty) {
      return res.status(409).json({ error: 'User ID already exists' });
    }

    // Create user
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
    logger.error('Signup failed', { error: error.message });
    res.status(500).json({ 
      error: 'Registration failed',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Email Verification Route
app.get('/api/verify-email', async (req, res) => {
  const { token, email, userId } = req.query;
  
  try {
    logger.info('Verification attempt started', { token, email, userId });

    // 1. Validate token exists
    const tokenDoc = await db.collection('verification-tokens').doc(token).get();
    if (!tokenDoc.exists) {
      logger.error('Token not found in Firestore', { token });
      return res.redirect(`${process.env.FRONTEND_URL}/verification-failed?error=invalid_token`);
    }

    // 2. Check token usage and expiration
    const tokenData = tokenDoc.data();
    logger.debug('Token data from Firestore', tokenData);

    if (tokenData.used) {
      logger.warn('Token already used', { token });
      return res.redirect(`${process.env.FRONTEND_URL}/verification-failed?error=used_token`);
    }

    let expiresAt = tokenData.expiresAt;
    if (expiresAt?.toDate) expiresAt = expiresAt.toDate();
    if (new Date() > new Date(expiresAt)) {
      logger.warn('Token expired', { token, expiresAt });
      return res.redirect(`${process.env.FRONTEND_URL}/verification-failed?error=expired_token`);
    }

    // 3. Verify user exists
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      logger.error('User not found during verification', { userId });
      return res.redirect(`${process.env.FRONTEND_URL}/verification-failed?error=user_not_found`);
    }

    // 4. Update records
    await db.collection('verification-tokens').doc(token).update({ used: true });
    await db.collection('users').doc(userId).update({
      emailVerified: true,
      status: 'active',
      updatedAt: FieldValue.serverTimestamp()
    });

    logger.info('Email verification successful', { userId, email });

    // 5. Send success response with redirect
    // After successful verification, send this enhanced HTML response:
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:;");
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Email Verified</title>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="10; url=https://buy.stripe.com/bIY1806DG7qw6uk144">
        <style>
          body {
            font-family: 'Arial', sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f8f9fa;
            color: #333;
          }
          .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            max-width: 500px;
            margin: 0 auto;
          }
          h1 {
            color: #28a745;
            margin-bottom: 20px;
          }
          .countdown {
            font-size: 24px;
            margin: 30px 0;
            font-weight: bold;
            color: #007bff;
          }
          .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-radius: 50%;
            border-top: 4px solid #007bff;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
          }
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
          }
          .btn:hover {
            background: #0056b3;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🎉 Email Verified Successfully!</h1>
          <p>Thank you for verifying your email address.</p>
          
          <div class="spinner"></div>
          
          <div class="countdown">
            Redirecting in <span id="countdown">10</span> seconds...
          </div>
          
          <p>You'll be automatically redirected to complete your payment.</p>
          
          <a href="https://buy.stripe.com/bIY1806DG7qw6uk144" class="btn">
            Proceed Now
          </a>
        </div>

         <script>
  document.addEventListener('DOMContentLoaded', function() {
    var countdownElement = document.getElementById('countdown');
    var seconds = 10;

    function updateCountdown() {
      seconds--;
      if (seconds < 0) {
        window.location.href = 'https://buy.stripe.com/bIY1806DG7qw6uk144';
      } else {
        countdownElement.textContent = seconds;
        setTimeout(updateCountdown, 1000);
      }
    }

    // Show the initial number first
    countdownElement.textContent = seconds;
    setTimeout(updateCountdown, 1000);
  });
</script>

      </body>
      </html>
    `);

  } catch (error) {
    logger.error('Verification failed', { 
      error: error.message,
      stack: error.stack,
      token,
      email,
      userId
    });
    return res.redirect(`${process.env.FRONTEND_URL}/verification-failed?error=server_error`);
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

// ==================== Account Recovery Endpoints ====================

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
    const recoveryToken = generateToken();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiration

    // Save recovery token
    await db.collection('recovery-tokens').doc(recoveryToken).set({
      email: normalizedEmail,
      userId: user.userId,
      expiresAt,
      used: false,
      type: 'account-recovery',
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

// Complete recovery
app.post('/api/complete-recovery', limiter, async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Recovery token is required' });
    }

    // Get token document
    const tokenDoc = await db.collection('recovery-tokens').doc(token).get();
    if (!tokenDoc.exists) {
      return res.status(404).json({ error: 'Invalid or expired recovery link' });
    }

    const tokenData = tokenDoc.data();
    
    // Check token status
    if (tokenData.used) {
      return res.status(400).json({ error: 'This recovery link has already been used' });
    }

    let expiresAt = tokenData.expiresAt;
    if (expiresAt?.toDate) expiresAt = expiresAt.toDate();
    if (new Date() > new Date(expiresAt)) {
      return res.status(400).json({ error: 'This recovery link has expired' });
    }

    // Get user data
    const userDoc = await db.collection('users').doc(tokenData.userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userDoc.data();

    // Generate 4-digit temporary PIN
    const tempPin = Math.floor(1000 + Math.random() * 9000).toString();
    const tempPinExpiry = new Date();
    tempPinExpiry.setHours(tempPinExpiry.getHours() + 1); // Expires in 1 hour

    // Mark token as used and update user with temp PIN
    await db.collection('recovery-tokens').doc(token).update({ used: true });
    await db.collection('users').doc(tokenData.userId).update({
      tempPin: await bcrypt.hash(tempPin, 12),
      tempPinExpiry,
      requiresPinReset: true
    });

    // Send email with User ID + Temporary PIN
    await transporter.sendMail({
      from: `"SureTalk Support" <${process.env.EMAIL_USER}>`,
      to: tokenData.email,
      subject: 'Your Temporary Access Details',
      html: `
        <p>Here are your temporary access details:</p>
        <p><strong>User ID:</strong> ${user.userId}</p>  
        <p><strong>Temporary PIN:</strong> ${tempPin}</p>
        <p>This PIN will expire in 1 hour. You will be required to set a new PIN after login.</p>
        <p>If you didn't request this, please contact our support team immediately.</p>
      `
    });

    res.json({ 
      success: true, 
      message: 'Temporary access details have been sent to your email' 
    });

  } catch (error) {
    logger.error('Recovery completion failed', { error });
    res.status(500).json({ error: 'Failed to complete account recovery' });
  }
});

// ==================== Slot Management Routes ====================

// Verify User PIN
app.get('/verify-user', async (req, res) => {
  if (req.method !== 'GET') {
    return res.status(400).json({ status: 'error', message: 'Invalid request method' });
  }

  const userId = req.query.UserId;
  const userPin = req.query.UserPin;

  if (!userId || !userPin) {
    return res.status(400).json({ status: 'error', message: 'User ID and PIN required' });
  }

  try {
    const userDoc = await db.collection('users').doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    const userData = userDoc.data();

    // 1. First check temporary PIN if it exists
    if (userData.tempPin) {
      const isTempPinValid = await bcrypt.compare(userPin, userData.tempPin);
      const now = new Date();
      const expiry = userData.tempPinExpiry.toDate();

      if (isTempPinValid && now < expiry) {
        return res.json({ 
          status: 'success', 
          message: 'User verified (temporary PIN)',
          requiresPinReset: true
        });
      }
    }

    // 2. Check original PIN
    if (userData.userPin) {
      const isOriginalPinValid = await bcrypt.compare(userPin, userData.userPin);
      if (isOriginalPinValid) {
        return res.json({ 
          status: 'success', 
          message: 'User verified',
          requiresPinReset: false 
        });
      }
    }

    // 3. If neither PIN matched
    return res.status(401).json({ 
      status: 'error', 
      message: 'Invalid PIN' 
    });

  } catch (error) {
    console.error('Verification error:', error);
    return res.status(500).json({ 
      status: 'error', 
      message: 'Verification failed', 
      error: error.message 
    });
  }
});

// Check Slot Availability
app.get('/check-slot', async (req, res) => {
  const { userId, slotNumber } = req.query;

  if (!userId || !slotNumber) {
    return res.status(400).json({ error: 'Missing userId or slotNumber' });
  }

  try {
    const userDoc = await db.collection('users').doc(userId).get();

    if (!userDoc.exists) {
      return res.status(200).json({ available: true });
    }

    const slots = userDoc.data().slots || [];
    const slotExists = slots.some(slot => slot.slotNumber == slotNumber);

    if (slotExists) {
      return res.status(400).json({ error: 'Slot already taken' });
    }

    return res.status(200).json({ available: true });
  } catch (error) {
    console.error('Error checking slot:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Save Slot Data
app.post('/save-slot', async (req, res) => {
  const { userId, slotNumber, contact, voiceMessage } = req.body;

  if (!userId || !slotNumber || !contact || !voiceMessage) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    let slots = [];
    if (userDoc.exists) {
      slots = userDoc.data().slots || [];
    }

    if (slots.some(slot => slot.slotNumber == slotNumber)) {
      return res.status(400).json({ error: 'Slot already taken' });
    }

    slots.push({ slotNumber, contact, voiceMessage });

    await userRef.set({ slots }, { merge: true });

    return res.json({ success: true });
  } catch (error) {
    console.error('Error saving slot:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get Slot Data
app.get('/get-slot', async (req, res) => {
  const userId = req.query.UserId;
  const slotNumber = req.query.SlotNumber;

  if (!userId || !slotNumber) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const slots = userDoc.data().slots || [];
    const selectedSlot = slots.find(slot => slot.slotNumber == slotNumber);

    if (!selectedSlot) {
      return res.status(404).json({ error: 'Slot not found' });
    }

    return res.json({ 
      slotNumber: selectedSlot.slotNumber,
      contact: selectedSlot.contact,
      voiceMessage: selectedSlot.voiceMessage || null
    });
  } catch (error) {
    console.error('Error fetching slot data:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete Slot Data
app.post('/delete-slot', async (req, res) => {
  const { userId, slotNumber } = req.body;

  if (!userId || !slotNumber) {
    return res.status(400).json({ error: 'Missing userId or slotNumber' });
  }

  try {
    const normalizedUserId = userId.toString().trim();
    const normalizedSlotNumber = slotNumber.toString().trim();

    const userRef = db.collection('users').doc(normalizedUserId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = userDoc.data();
    let slots = userData.slots || [];
    const initialLength = slots.length;
    
    const updatedSlots = slots.filter(slot => 
      slot.slotNumber.toString().trim() !== normalizedSlotNumber
    );

    if (updatedSlots.length === initialLength) {
      return res.status(404).json({ 
        error: 'Slot not found',
        details: {
          userId: normalizedUserId,
          slotNumber: normalizedSlotNumber,
          availableSlots: slots.map(s => s.slotNumber)
        }
      });
    }

    await userRef.update({ slots: updatedSlots });

    return res.json({ 
      success: true, 
      message: 'Slot deleted successfully',
      deletedSlot: normalizedSlotNumber,
      remainingSlots: updatedSlots.length
    });

  } catch (error) {
    console.error('Error deleting slot:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      details: error.message 
    });
  }
});

// Update User Credentials
app.post('/update-credentials', async (req, res) => {
  const { oldUserId, newUserId, newPin } = req.body;

  if (!oldUserId || (!newUserId && !newPin)) {
    return res.status(400).json({
      error: 'Missing fields. Provide oldUserId + newUserId or newPin.',
    });
  }

  try {
    const oldUserRef = db.collection('users').doc(oldUserId);
    const oldUserDoc = await oldUserRef.get();

    if (!oldUserDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = oldUserDoc.data();
    const updates = {};
    
    if (newPin) {
      updates.userPin = await bcrypt.hash(newPin, 12);
      updates.requiresPinReset = false;
    }

    if (!newUserId) {
      await oldUserRef.update(updates);
      await oldUserRef.update({
        tempPin: FieldValue.delete(),
        tempPinExpiry: FieldValue.delete(),
      });
      return res.json({ success: true, message: 'PIN updated successfully' });
    }

    updates.userId = newUserId;

    const newUserRef = db.collection('users').doc(newUserId);
    await newUserRef.set({
      ...userData,
      ...updates,
    });

    await oldUserRef.delete();

    if (newPin) {
      await newUserRef.update({
        tempPin: FieldValue.delete(),
        tempPinExpiry: FieldValue.delete(),
      });
    }

    return res.json({
      success: true,
      message: 'User credentials updated successfully',
    });

  } catch (error) {
    console.error('Error updating user:', error);
    return res.status(500).json({
      error: 'Internal server error',
      details: error.message,
    });
  }
});

// Save User PIN and Verify
app.post('/save-pin', async (req, res) => {
  const { userId, userPin } = req.body;

  if (!userId || !userPin) {
    return res.status(400).json({ 
      status: 'error', 
      message: 'userId and userPin are required' 
    });
  }

  try {
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      return res.status(409).json({
        status: 'error',
        message: 'User ID already exists. Choose a different ID.',
        userId: userId
      });
    }

    const hashedPin = await bcrypt.hash(userPin, 12);

    await userRef.set({
      userPin: hashedPin,
      verified: true,
      createdAt: FieldValue.serverTimestamp()
    });

    return res.json({ 
      status: 'success', 
      message: 'User PIN saved and verified successfully',
      userId: userId
    });

  } catch (error) {
    console.error('Error saving PIN:', error);
    return res.status(500).json({ 
      status: 'error', 
      message: 'Failed to save PIN', 
      error: error.message 
    });
  }
});






// ==================== Server Startup ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server started on port ${PORT}`, {
    environment: process.env.NODE_ENV || 'development',
    allowedOrigins
  });
});