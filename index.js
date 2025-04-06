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

// ==================== Server Startup ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server started on port ${PORT}`, {
    environment: process.env.NODE_ENV || 'development',
    allowedOrigins
  });
});