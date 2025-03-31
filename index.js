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

// The modification of existing limiter configuration:
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Increased from 5 to 100 requests per window
  message: 'Too many signup attempts from this IP',
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false // Disable deprecated headers
});

// Apply to all routes or specific ones
app.use(limiter); // Global application
// OR keep it specific to signup: app.use('/api/signup', limiter);



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
  debug: true // <--  for troubleshooting
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

const sendVerificationEmail = async (email) => {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  await db.collection('verification-tokens').doc(token).set({
    email,
    expiresAt,
    used: false
  });

  const verificationLink = `${process.env.BASE_URL || 'https://suretalk-api.onrender.com'}/verify-email?token=${token}&email=${encodeURIComponent(email)}`;

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

// ==================== Routes ====================
app.post('/api/signup', limiter, async (req, res) => {
  try {
    const { firstName, email, phone, password, ...rest } = req.body;

    // Validation
    if (!firstName || !email || !phone || !password) {
      logger.warn('Missing fields', { email });
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: { requires: ['firstName', 'email', 'phone', 'password'] }
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

    // Check existing user
    const existingUser = await db.collection('Web-Users').doc(normalizedEmail).get();
    if (existingUser.exists) {
      logger.warn('Duplicate registration attempt', { email: normalizedEmail });
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Create user
    await db.collection('Web-Users').doc(normalizedEmail).set({
      firstName: sanitizeHtml(firstName),
      email: normalizedEmail,
      phone: sanitizeHtml(phone),
      password: await bcrypt.hash(password, parseInt(process.env.BCRYPT_SALT_ROUNDS || 12)),
      ...rest,
      isInterestedInPartnership: Boolean(rest.joinProgram),
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      status: 'pending',
      verified: false,
      emailVerified: false
    });

    // Send verification email
    await sendVerificationEmail(normalizedEmail);
    logger.info('User created and verification email sent', { email: normalizedEmail });

    res.status(201).json({
      success: true,
      message: 'User created. Verification email sent.',
      userId: normalizedEmail
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
app.get('/verify-email', async (req, res) => {
  try {
    const { token, email } = req.query;
    
    // 1. Find token in Firestore
    const tokenDoc = await db.collection('verification-tokens').doc(token).get();
    
    if (!tokenDoc.exists || tokenDoc.data().used || new Date() > tokenDoc.data().expiresAt) {
      logger.warn('Invalid verification attempt', { email, token });
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=invalid_token`);
    }

    // 2. Mark token as used
    await db.collection('verification-tokens').doc(token).update({ used: true });

    // 3. Update user status
    await db.collection('Web-Users').doc(email).update({
      emailVerified: true,
      status: 'active',
      updatedAt: FieldValue.serverTimestamp()
    });

    logger.info('Email verified successfully', { email });
    return res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`);
    
  } catch (error) {
    logger.error('Verification failed', { error: error.message });
    return res.redirect(`${process.env.FRONTEND_URL}/login?error=verification_failed`);
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