require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { db, FieldValue, storage } = require('./firebase');
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
const twilio = require('twilio');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const price_id = process.env.STRIPE_PRICE_ID;
const bodyParser = require('body-parser');
const Twilio = require('twilio'); 


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


// ==================== Stripe functions ====================
app.post('/api/stripe-webhook', 
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!sig) {
      logger.error('Missing Stripe-Signature header');
      return res.status(400).json({ error: 'Missing signature header' });
    }
    
    if (!webhookSecret) {
      logger.error('Missing STRIPE_WEBHOOK_SECRET');
      return res.status(500).json({ error: 'Server misconfigured' });
    }

    let event;
    try {
      console.log('[Stripe Hook] Is Buffer:', Buffer.isBuffer(req.body));
      console.log('[Stripe Hook] Raw Body Type:', typeof req.body);
      event = stripe.webhooks.constructEvent(
        req.body, // Raw body buffer
        sig,
        webhookSecret
      );
      logger.info(`Stripe webhook received: ${event.type}`);
    } catch (err) {
      logger.error('Stripe webhook verification failed', { error: err.message });
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      switch (event.type) {
        case 'invoice.paid':
          await handlePaymentSuccess(event.data.object);
          break;
          
        case 'invoice.payment_failed':
          await handlePaymentFailure(event.data.object);
          break;
          
        case 'customer.subscription.deleted':
        case 'customer.subscription.updated':
          await handleSubscriptionChange(event.data.object);
          break;
          
        default:
          logger.debug(`Unhandled event type: ${event.type}`);
      }
      res.status(200).json({ received: true });
    } catch (error) {
      logger.error('Webhook processing failed', { error: error.message });
      res.status(500).json({ error: 'Processing failed' });
    }
  }
);

      //console.log('[Stripe Hook] Headers:', req.headers);
      //console.log('[Stripe Hook] Raw body type:', typeof req.body);

// ==================== Helper Functions ====================

async function handleSubscriptionChange(subscription) {
  try {
    // 1. Find user reference (using metadata, email, or phone)
    const customer = await stripe.customers.retrieve(subscription.customer);
    const userRef = await findUserRef(subscription, customer);
    
    if (!userRef) {
      logger.warn('No matching user found for subscription', {
        subscriptionId: subscription.id,
        customerId: subscription.customer
      });
      return; // Skip processing but don't throw error
    }

    // 2. Prepare update data
    const subscriptionData = {
      stripeSubscriptionId: subscription.id,
      subscriptionStatus: subscription.status,
      plan: subscription.items?.data[0]?.plan?.nickname || 'Unknown Plan',
      currentPeriodEnd: subscription.current_period_end 
        ? new Date(subscription.current_period_end * 1000)
        : null,
      updatedAt: FieldValue.serverTimestamp()
    };

    
      
    // 3. Auto-update verification status based on subscription state
    if (['active', 'trialing'].includes(subscription.status)) {
      subscriptionData.verified = true;
    } else if (['canceled', 'unpaid', 'past_due'].includes(subscription.status)) {
      subscriptionData.verified = false;

      // Get user data to send discontinuation email
      const userDoc = await userRef.get();
      if (userDoc.exists && userDoc.data().email) {
        await sendDiscontinuationEmail(
          userDoc.data().email,
          userDoc.data().firstName || 'Customer'
        );
    }     
  }

    // 4. Update Firestore
    await userRef.update(subscriptionData);
    
    logger.info('Subscription data updated', {
      userId: userRef.id,
      status: subscription.status,
      changes: Object.keys(subscriptionData)
    });

    // 5. Send notifications if subscription ended
    if (subscription.status === 'canceled') {
      await sendSubscriptionEndNotification(userRef.id);
    }

  } catch (error) {
    logger.error('Failed to process subscription change', {
      subscriptionId: subscription.id,
      error: error.message,
      stack: error.stack
    });
    throw error; // Will trigger Stripe retry
  }
}


// Optional notification function
async function sendSubscriptionEndNotification(userId) {
  if (process.env.SEND_SUBSCRIPTION_EMAILS !== 'true') return;
  
  try {
    const userDoc = await db.collection('users').doc(userId).get();
    const user = userDoc.data();
    
    if (user?.email) {
      await transporter.sendMail({
        from: `"SureTalk Support" <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: 'Your Subscription Has Ended',
        html: `
          <h2>Subscription Update</h2>
          <p>Your SureTalk subscription has ended.</p>
          <a href="${process.env.FRONTEND_URL}/resubscribe" style="...">
            Renew Your Subscription
          </a>
        `
      });
    }
  } catch (error) {
    logger.error('Failed to send subscription end notification', { userId, error });
  }
}



async function handlePaymentSuccess(invoice) {
  // 1. Get Stripe customer
  const customer = await stripe.customers.retrieve(invoice.customer);
  
  // 2. Find user by (in order):
  //    - invoice.metadata.userId (existing)
  //    - customer email
  //    - customer phone
  const userRef = await findUserRef(invoice, customer);
  
  if (!userRef) {
    logger.warn('No matching user found for payment', {
      invoiceId: invoice.id,
      customer: customer.id
    });
    return;
  }

  // 3. Update Firestore
  await userRef.update({
    verified: true,
    lastPaymentDate: FieldValue.serverTimestamp(),
    subscriptionStatus: 'active',
    stripeCustomerId: customer.id
  });
  
  logger.info(`User verified via payment: ${userRef.id}`);
}


async function handlePaymentFailure(invoice) {
  const customer = await stripe.customers.retrieve(invoice.customer);
  const userRef = await findUserRef(invoice, customer);
  
  if (userRef) {
    await userRef.update({
      lastPaymentFailed: true,
      paymentFailureDate: FieldValue.serverTimestamp()
      // Don't set verified:false yet (give grace period)
    });
  }
}



async function findUserRef(stripeObject, customer) {
  // 1. Try metadata first
  if (stripeObject.metadata?.userId) {
    const doc = db.collection('users').doc(stripeObject.metadata.userId);
    const exists = (await doc.get()).exists;
    if (exists) return doc;
  }
  
  // 2. Try email lookup
  if (customer.email) {
    const emailQuery = await db.collection('users')
      .where('email', '==', customer.email)
      .limit(1)
      .get();
      
    if (!emailQuery.empty) return emailQuery.docs[0].ref;
  }
  
  // 3. Try phone lookup
  if (customer.phone) {
    const phoneQuery = await db.collection('users')
      .where('phone', '==', customer.phone.replace(/\D/g, ''))
      .limit(1)
      .get();
      
    if (!phoneQuery.empty) return phoneQuery.docs[0].ref;
  }
  
  return null;
}



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
  exposedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200 
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


// ==================== Twilio Configuration ====================
if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN) {
  logger.error("Missing Twilio credentials. Please check your environment variables.");
  process.exit(1);
}

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);


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

  
  const verificationLink = `${process.env.FRONTEND_URL}/confirm-email-link?token=${token}`;
  const subscriptionLink = "https://buy.stripe.com/bIY1806DG7qw6uk144"; // Stripe link

  await transporter.sendMail({
    from: `"SureTalk" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify Your Email Address',
    html: `
      <h2>Welcome to SureTalk!</h2>
      <p>Please verify your email address to complete your registration:</p>
      <a href="${verificationLink}" style="...">Verify Email</a>      
      <p>This link expires in 24 hours.</p>
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

// Check email availability
app.get('/api/check-email', async (req, res) => {
  const email = req.query.email?.toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const snapshot = await db.collection('users')
    .where('email', '==', email)
    .limit(1)
    .get();

  if (!snapshot.empty) {
    return res.status(409).json({ error: 'Email already in use' });
  }

  res.json({ available: true });
});

// Check userId availability
app.get('/api/check-userid', async (req, res) => {
  const userId = req.query.userId?.trim();
  if (!userId) return res.status(400).json({ error: 'User ID is required' });

  const snapshot = await db.collection('users')
    .where('userId', '==', userId)
    .limit(1)
    .get();

  if (!snapshot.empty) {
    return res.status(409).json({ error: 'User ID already taken' });
  }

  res.json({ available: true });
});



// Function to generate a verification token
function generateVerificationToken(userId, email) {
  const token = crypto.randomBytes(32).toString('hex'); 
  return token;
}


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

    //console.log('Checking for email:', normalizedEmail);
    //console.log('Checking for userId:', userId);


    // Check for existing user
    const usersRef = db.collection('users');
   
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
      emailVerified: false,
      smsConsent: true 
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


// Service discontinuation email
const sendDiscontinuationEmail = async (email, firstName) => {
  try {
    await transporter.sendMail({
      from: `"SureTalk" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'We Miss You at SureTalk',
      html: `
        <h2>Hi ${firstName},</h2>
        <p>We noticed your SureTalk service has been discontinued.</p>
        <p>We'd love to have you back! Here's a special link to resubscribe:</p>
        <a href="https://buy.stripe.com/bIY1806DG7qw6uk144">Resubscribe to SureTalk</a>
        <p>If this was a mistake, please contact our support team.</p>
      `
    });
    logger.info('Discontinuation email sent', { email });
  } catch (error) {
    logger.error('Failed to send discontinuation email', { email, error });
  }
};





// Resend Verification Email Route
app.get('/api/resend-verification', async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    // Check if the user exists
    const userDoc = await db.collection('users').where('email', '==', email).limit(1).get();
    if (userDoc.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Assuming `userDoc` is a single document and we're accessing the first item
    const user = userDoc.docs[0].data();
    const userId = user.userId;

    // Generate a new token using the defined function
    const token = generateVerificationToken(userId, email);

    //expiration date set to 24 hours from now
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    
    // Store the token in the Firestore collection
    await db.collection('verification-tokens').doc(token).set({
      userId,
      email,
      used: false,
      expiresAt: FieldValue.serverTimestamp(),  
    });

    // Send the verification email again
    await sendVerificationEmail(email, userId, token);

    res.status(200).json({ message: 'Verification email resent successfully' });

  } catch (error) {
    logger.error('Resend verification failed', { error: error.message });
    res.status(500).json({ error: 'Failed to resend verification email' });
  }
});




const sendWelcomeEmail = async (email, firstName) => {
  try {
    await transporter.sendMail({
      from: `"SureTalk" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Welcome to SureTalk!',
      html: `
        <h2>Welcome to SureTalk, ${firstName}!</h2>
        <p>Thank you for joining our community.</p>
        <p>You can now complete your subscription to start using our services:</p>
        <a href="https://buy.stripe.com/bIY1806DG7qw6uk144">Complete Subscription</a>
        <p>If you have any questions, please reply to this email.</p>
      `
    });
  } catch (error) {
    logger.error('Failed to send welcome email', { email, error });
  }
};



// Email Verification Route
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;

  try {
    // 1. Validate token exists
    const tokenDoc = await db.collection('verification-tokens').doc(token).get();
    if (!tokenDoc.exists) {
      logger.error('Token not found in Firestore', { token });
      return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification?error=invalid_token`);
    }

    // 2. Extract token data
    const tokenData = tokenDoc.data();
    const userId = tokenData.userId;
    const email = tokenData.email;

    logger.info('Verification attempt started', { token, email, userId });

    if (tokenData.used) {
      logger.warn('Token already used', { token });
      return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification?error=used_token`);
    }

    let expiresAt = tokenData.expiresAt;
    if (expiresAt?.toDate) expiresAt = expiresAt.toDate();
    if (new Date() > new Date(expiresAt)) {
      logger.warn('Token expired', { token, expiresAt });
      return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification?error=expired_token`);
    }

    // 3. Verify user exists
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      logger.error('User not found during verification', { userId });
      return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification?error=user_not_found`);
    }

    // 4. Update records
    await db.collection('verification-tokens').doc(token).update({ used: true });
    await db.collection('users').doc(userId).update({
      emailVerified: true,
      status: 'active',
      updatedAt: FieldValue.serverTimestamp()
    });

    logger.info('Email verification successful', { userId, email });

    // 5. Send welcome email
    const user = userDoc.data();
    await sendWelcomeEmail(user.email, user.firstName);

    // 6. Respond with success page
    res.setHeader('Content-Type', 'text/html');
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Email Verified</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          .container { max-width: 500px; margin: 0 auto; }
          h1 { color: #28a745; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Email Verified Successfully!</h1>
          <p>Thank you for verifying your email address. Please check your email for the subscription link.</p>
          <p>You can now close this window.</p>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    logger.error('Verification failed', { error });
    return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification`);
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
      return res.status(400).json({ 
        status: 'error',
        error: 'Email is required',
        code: 'MISSING_EMAIL'
      });
    }

    const normalizedEmail = sanitizeHtml(email).toLowerCase().trim();

    // Check if user exists
    const querySnapshot = await db.collection('users')
      .where('email', '==', normalizedEmail)
      .limit(1)
      .get();

    if (querySnapshot.empty) {
      return res.status(404).json({ 
        status: 'error',
        error: 'No account found with this email',
        code: 'USER_NOT_FOUND'
      });
    }

    const userDoc = querySnapshot.docs[0];
    const user = userDoc.data();

    // Generate recovery token
    const recoveryToken = generateToken();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);

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

    // Consistent success response
    res.status(200).json({ 
      status: 'success',
      message: 'Recovery email sent. Please check your inbox.',
      data: {
        email: normalizedEmail,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    logger.error('Recovery request failed', { 
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ 
      status: 'error',
      error: 'Account recovery failed',
      code: 'SERVER_ERROR',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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




// ==================== Twilio Recording Routes ====================
app.post('/api/fetch-recording', limiter, async (req, res, next) => {
  logger.info("Incoming recording fetch request", { body: req.body });

  const { RECORDING_URL } = req.body;
  if (!RECORDING_URL) {
      return res.status(400).json({ error: 'Missing RECORDING_URL parameter' });
  }

  const match = RECORDING_URL.match(/Recordings\/(RE[a-zA-Z0-9]+)/);
  if (!match) {
      return res.status(400).json({ error: 'Invalid RECORDING_URL format' });
  }

  const recordingSid = match[1];
  logger.info("Extracted Recording SID", { recordingSid });

  try {
      // Fetch recording details
      const recording = await twilioClient.recordings(recordingSid).fetch();
      logger.info("Recording data fetched", { recording });

      const mediaUrl = `https://api.twilio.com${recording.uri.replace('.json', '.mp3')}`;
      logger.info("Downloading recording", { mediaUrl });

      // Download the file
      const response = await axios({
          method: 'GET',
          url: mediaUrl,
          responseType: 'stream',
          auth: {
              username: process.env.TWILIO_ACCOUNT_SID, 
              password: process.env.TWILIO_AUTH_TOKEN
          }
      });

      const tempFilePath = path.join(__dirname, 'temp', `${recordingSid}.mp3`);
      
      // Ensure temp directory exists
      if (!fs.existsSync(path.join(__dirname, 'temp'))) {
          fs.mkdirSync(path.join(__dirname, 'temp'));
      }

      const writer = fs.createWriteStream(tempFilePath);
      response.data.pipe(writer);

      return new Promise((resolve, reject) => {
          writer.on('finish', async () => {
              logger.info(`Recording saved temporarily`, { tempFilePath });

              try {
                  // Upload to Firebase Storage
                  const destination = `recordings/${recordingSid}.mp3`;
                  await storage.upload(tempFilePath, {
                      destination: destination,
                      metadata: { contentType: "audio/mpeg" }
                  });

                  // Get Public URL
                  const publicUrl = `https://firebasestorage.googleapis.com/v0/b/${storage.name}/o/${encodeURIComponent(destination)}?alt=media`;
                  logger.info("Recording uploaded to Firebase", { publicUrl });

                  // Delete temp file
                  try {
                    fs.unlinkSync(tempFilePath);
                  } catch (err) {
                    logger.warn("Temp file already deleted or missing", { path: tempFilePath });
                  }                

                  // Return Public URL
                  res.json({
                      success: true,
                      message: "Recording uploaded successfully",
                      recordingSid: recordingSid,
                      firebaseUrl: publicUrl
                  });
                  resolve();
              } catch (uploadError) {
                  logger.error("Error uploading file to Firebase", { error: uploadError });
                  reject(uploadError);
              }
          });

          writer.on('error', (err) => {
              logger.error("Error saving file", { error: err });
              reject(err);
          });
      });

  } catch (error) {
      logger.error("Error processing recording", { error: error.message, stack: error.stack });
      next(error);
  }
});


// ===========================Verify User PIN=============================
app.get('/api/verify-user', limiter, async (req, res) => {
  const { UserId: userId, UserPin: userPin } = req.query;

  // Input validation
  if (!userId || !userPin) {
    return res.status(400).json({ 
      error: 'Missing credentials',
      details: 'Both UserId and UserPin are required'
    });
  }

  try {
    const userDoc = await db.collection('users').doc(userId).get();

    // User existence check
    if (!userDoc.exists) {
      logger.warn('User not found during verification', { userId });
      return res.status(404).json({ 
        error: 'User not found',
        suggestion: 'Please check your UserId or register first'
      });
    }

    const userData = userDoc.data();

    // Verification status check
    if (userData.verified !== true) {
      logger.warn('Unverified user attempt', { userId, status: userData.verified });
      return res.status(403).json({
        error: 'Account not verified',
        details: 'Please complete your account verification first',
        requiresVerification: true
      });
    }

    // Check temporary PIN (if exists and not expired)
    if (userData.tempPin) {
      const isTempPinValid = await bcrypt.compare(userPin, userData.tempPin);
      const now = new Date();
      const expiry = userData.tempPinExpiry?.toDate?.() || new Date(0);

      if (isTempPinValid && now < expiry) {
        logger.info('Temporary PIN verification successful', { userId });
        return res.json({ 
          success: true,
          message: 'Temporary PIN accepted',
          verified: true,
          requiresPinReset: true,
          temporaryAccess: true
        });
      }
    }

    // Check permanent PIN
    if (userData.userPin) {
      const isPinValid = await bcrypt.compare(userPin, userData.userPin);
      if (isPinValid) {
        logger.info('User PIN verification successful', { userId });
        return res.json({ 
          success: true,
          message: 'PIN verification successful',
          verified: true,
          requiresPinReset: false,
          userId,
          firstName: userData.firstName || null
        });
      }
    }

    // Failed attempts logging
    logger.warn('Invalid PIN attempt', { userId });
    return res.status(401).json({ 
      error: 'Invalid credentials',
      details: 'The UserId or PIN you entered is incorrect',
      remainingAttempts: 3 
    });

  } catch (error) {
    logger.error('Verification failed', { 
      error: error.message,
      stack: error.stack,
      userId
    });
    return res.status(500).json({ 
      error: 'Verification service unavailable',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// =====================Check Slot Availability=======================
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

// =========================Save Slot Data================================
app.post('/save-slot', async (req, res) => {
  const { userId, slotNumber, contact, voiceMessage } = req.body;

  if (!userId || !slotNumber || !voiceMessage) {
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

// ==============================Get Slot Data=================================
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

// ================Delete Slot Data=========================
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

// ===========================Update User Credentials===========================
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

    // Add this check at the beginning of the update logic
    if (!newUserId || newUserId === oldUserId) {
      // Only updating PIN or providing same ID - no document recreation needed
      await oldUserRef.update(updates);
      await oldUserRef.update({
        tempPin: FieldValue.delete(),
        tempPinExpiry: FieldValue.delete(),
      });
      return res.json({ success: true, message: 'PIN updated successfully' });
    }

    // Only reach this point if newUserId is different from oldUserId
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

// =======================Save User PIN=========================== 
app.post('/api/save-pin', limiter, async (req, res) => {
  try {
    const { userId, userPin } = req.body;

    // Validation
    if (!userId || !userPin) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: { requires: ['userId', 'userPin'] }
      });
    }

    // Check if user exists
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      logger.warn('Duplicate user ID attempt', { userId });
      return res.status(409).json({ 
        error: 'User ID already exists',
        suggestion: 'Choose a different user ID or login instead'
      });
    }

    // Hash the PIN
    const hashedPin = await bcrypt.hash(
      userPin, 
      parseInt(process.env.BCRYPT_SALT_ROUNDS || 12)
    );

    // Create user document
    await userRef.set({
      userId,
      userPin: hashedPin,
      signingType: 'call',
      verified: true,
      status: 'active',
      emailVerified: false, 
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });

    logger.info('New user PIN created', { userId });

    return res.status(201).json({ 
      success: true,
      message: 'User credentials saved successfully',
      userId
    });

  } catch (error) {
    logger.error('Failed to save user PIN', { 
      error: error.message,
      stack: error.stack
    });
    return res.status(500).json({ 
      error: 'Failed to save credentials',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// ==================== Update Verification Status Endpoint ====================
app.post('/api/set-verification-false', limiter, async (req, res) => {
  try {
    const { userId, userPin } = req.body;

    // Input validation
    if (!userId || !userPin) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: 'Both userId and userPin are required'
      });
    }

    // Get user document
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    // Check if user exists
    if (!userDoc.exists) {
      return res.status(404).json({ 
        error: 'User not found',
        suggestion: 'Please check your userId'
      });
    }

    const userData = userDoc.data();

    // Verify user PIN
    const isPinValid = await bcrypt.compare(userPin, userData.userPin);
    if (!isPinValid) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        details: 'The userId or userPin you entered is incorrect'
      });
    }

    // Update verification status to false
    await userRef.update({
      verified: false,
      updatedAt: FieldValue.serverTimestamp()
    });

    logger.info('User verification status updated to false', { userId });

    return res.json({ 
      success: true,
      message: 'User verification status set to false',
      userId,
      verified: false
    });

  } catch (error) {
    logger.error('Failed to update verification status', { 
      error: error.message,
      stack: error.stack,
      userId: req.body.userId
    });
    return res.status(500).json({ 
      error: 'Failed to update verification status',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ===================code to use token from Twilio=======================
app.post('/api/subscribe-user', async (req, res) => {
  const { paymentToken, userId, token } = req.body;

  if (!token || token !== process.env.TWILIO_SECRET_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized access' });
  }

  try {
    // 1. Create a new customer and attach the payment token as their default payment method
    const customer = await stripe.customers.create({
      payment_method: paymentToken,
      invoice_settings: { default_payment_method: paymentToken }
    });

    // 2. Create subscription
    const subscription = await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: process.env.STRIPE_MONTHLY_PRICE_ID }],
      expand: ['latest_invoice.payment_intent']
    });

    // 3. Update Firestore
    const userRef = db.collection('users').doc(userId);
    await userRef.update({
      verified: true,
      stripeCustomerId: customer.id,
      subscriptionId: subscription.id,
      subscriptionStatus: 'active',
      updatedAt: FieldValue.serverTimestamp()
    });

    res.status(200).json({ success: true });

  } catch (err) {
    logger.error('Failed to subscribe user via token', { error: err.message });
    res.status(500).json({ error: 'Subscription setup failed', details: err.message });
  }
});

// Verify environment variables
const requiredVars = ['STRIPE_SECRET_KEY', 'TWILIO_ACCOUNT_SID', 'STUDIO_FLOW_SID'];
for (const varName of requiredVars) {
  if (!process.env[varName]) {
    console.error(`❌ Missing required environment variable: ${varName}`);
    process.exit(1);
  }
}

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Twilio endpoint
app.post('/twilio-payment-handler', (req, res) => {
  try {
    const twiml = new Twilio.twiml.VoiceResponse();
    
    twiml.say("We are saving your card for future monthly payments.");
    twiml.pay({
      paymentConnector: "Stripe_Connector_2",
      tokenType: "payment-method",
      postalCode: false,
      action: "https://suretalk-api.onrender.com/start-payment-setup" 
    });

    res.type('text/xml');
res.send(twiml.toString());
  } catch (err) {
    console.error('Twilio handler error:', err);
    res.status(500).send('Server error');
  }
});

// Payment processing endpoint
app.post('/start-payment-setup', async (req, res) => {
  try {
    console.log('Payment webhook received:', req.body); 
    
    const { PaymentToken, Result } = req.body;
    if (Result !== 'success' || !PaymentToken) {
      throw new Error(`Payment failed - Result: ${Result}, Token: ${!!PaymentToken}`);
    }

    // Process Stripe subscription
    const customer = await stripe.customers.create();
    await stripe.paymentMethods.attach(PaymentToken, { customer: customer.id });
    await stripe.customers.update(customer.id, {
      invoice_settings: { default_payment_method: PaymentToken }
    });

    await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: 'price_1RFBXvAOy2W6vlFokwIELKQX' }],
      payment_settings: {
        payment_method_types: ['card'],
        save_default_payment_method: 'on_subscription'
      }
    });

    console.log('✅ Subscription created for:', customer.id);

    // TwiML response
    res.type('text/xml').send(`
      <Response>
        <Say>Thank you! Your payment was processed successfully.</Say>
        <Redirect method="POST">https://webhooks.twilio.com/v1/Accounts/${process.env.TWILIO_ACCOUNT_SID}/Flows/${process.env.STUDIO_FLOW_SID}?FlowEvent=return</Redirect>
      </Response>
    `);

  } catch (err) {
    console.error('❌ Payment processing failed:', err);
    res.type('text/xml').send(`
      <Response>
        <Say>Error: ${err.message.replace(/[^\w\s]/gi, '')}</Say>
        <Hangup/>
      </Response>
    `);
  }
});


// Error-handling middleware
app.use((err, req, res, next) => {
  logger.error("Unhandled error", { 
      error: err.message, 
      stack: err.stack,
      path: req.path,
      method: req.method
  });
  res.status(500).json({ 
      error: "Internal Server Error",
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});


// ==================== Server Startup ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server started on port ${PORT}`, {
    environment: process.env.NODE_ENV || 'development',
    allowedOrigins
  });
});


// Created by: stacktechnologies
// Last Updated: 2025-04-10
// Project: SureTalk backend server
