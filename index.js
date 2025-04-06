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

  const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${token}&email=${encodeURIComponent(email)}&userId=${userId}`;

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

// ==================== Account Recovery Functions ====================
const sendRecoveryEmail = async (email, userId) => {
  const token = generateToken();
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + 1);

  await db.collection('recovery-tokens').doc(token).set({
    email,
    userId,
    expiresAt,
    used: false,
    type: 'account-recovery',
    createdAt: FieldValue.serverTimestamp()
  });

  const recoveryLink = `${process.env.FRONTEND_URL}/recover-account?token=${token}`;

  await transporter.sendMail({
    from: `"SureTalk Support" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Account Recovery Request',
    html: `
      <p>We received a request to recover your account.</p>
      <a href="${recoveryLink}">Click here to recover your account</a>
      <p>This link expires in 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>
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
// ==================== Email Verification Route ====================
app.get('/api/verify-email', async (req, res) => {
  const { token, email, userId } = req.query;
  
  try {
    // 1. Validate token exists
    const tokenDoc = await db.collection('verification-tokens').doc(token).get();
    if (!tokenDoc.exists) {
      logger.error('Token not found', { token });
      return res.redirect(`${process.env.FRONTEND_URL}/verification-failed?error=invalid_token`);
    }

    // 2. Check token usage and expiration
    const tokenData = tokenDoc.data();
    if (tokenData.used) {
      return res.redirect(`${process.env.FRONTEND_URL}/verification-failed?error=used_token`);
    }

    let expiresAt = tokenData.expiresAt;
    if (expiresAt?.toDate) expiresAt = expiresAt.toDate();
    if (new Date() > new Date(expiresAt)) {
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

    // 5. Send HTML response with success message and redirect
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Cache-Control', 'no-store');
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Email Verified</title>
        <meta charset="UTF-8">
        <style>
          body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
          }
          .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 500px;
            margin: 0 auto;
          }
          h1 {
            color: #4CAF50;
          }
          .countdown {
            font-size: 18px;
            margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🎉 Email Verified Successfully!</h1>
          <p>Thank you for verifying your email address.</p>
          <p class="countdown">Redirecting to payment page in <span id="count">10</span> seconds...</p>
          <p>If you are not redirected automatically, <a href="https://buy.stripe.com/bIY1806DG7qw6uk144">click here</a>.</p>
        </div>
        <script>
          let seconds = 10;
          const countdown = setInterval(() => {
            seconds--;
            document.getElementById('count').textContent = seconds;
            if (seconds <= 0) {
              clearInterval(countdown);
              window.location.href = 'https://buy.stripe.com/bIY1806DG7qw6uk144';
            }
          }, 1000);
        </script>
      </body>
      </html>
    `);

  } catch (error) {
    logger.error('Verification failed', { error: error.message });
    return res.redirect(`${process.env.FRONTEND_URL}/verification-failed?error=server_error`);
  }
});

// Account Recovery Routes

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

    const user = querySnapshot.docs[0].data();
    await sendRecoveryEmail(normalizedEmail, user.userId);

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
    if (expiresAt.toDate) expiresAt = expiresAt.toDate();
    if (new Date() > expiresAt) {
      return res.status(400).json({ error: 'This recovery link has expired' });
    }

    // Get user data
    const userDoc = await db.collection('users').doc(tokenData.userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate temporary PIN
    const tempPin = Math.floor(1000 + Math.random() * 9000).toString();
    const tempPinExpiry = new Date();
    tempPinExpiry.setHours(tempPinExpiry.getHours() + 1);

    // Update records
    await db.collection('recovery-tokens').doc(token).update({ used: true });
    await db.collection('users').doc(tokenData.userId).update({
      tempPin: await bcrypt.hash(tempPin, 12),
      tempPinExpiry,
      requiresPinReset: true
    });

    // Send email with temporary PIN
    await transporter.sendMail({
      from: `"SureTalk Support" <${process.env.EMAIL_USER}>`,
      to: tokenData.email,
      subject: 'Your Temporary Access Details',
      html: `
        <p>Here are your temporary access details:</p>
        <p><strong>User ID:</strong> ${tokenData.userId}</p>  
        <p><strong>Temporary PIN:</strong> ${tempPin}</p>
        <p>This PIN will expire in 1 hour.</p>
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














































