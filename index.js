require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { db, FieldValue } = require('./firebase');

const app = express();

// Enhanced CORS configuration
const allowedOrigins = [
  'https://suretalk-signup.onrender.com',
  'http://localhost:3000'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
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
app.options('*', cors(corsOptions)); // Enable preflight for all routes
app.use(express.json());

app.post('/api/signup', async (req, res) => {
  try {
    const { 
      firstName, 
      lastName, 
      email, 
      phone, 
      username, 
      password,
      usage,
      joinProgram 
    } = req.body;
    
    // Validate required fields
    if (!firstName || !email || !phone || !password) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: {
          requires: ['firstName', 'email', 'phone', 'password']
        }
      });
    }

    // Create user document
    const userRef = await db.collection('Web-Users').add({
      firstName,
      lastName: lastName || '',
      email,
      phone,
      username: username || '',
      password: hashPassword(password),
      usage: usage || 'not specified',
      isInterestedInPartnership: Boolean(joinProgram),
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      status: 'pending'
    });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      userId: userRef.id,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Firestore error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Improved password hashing
const hashPassword = (plainText) => {
  // In production, replace with:
  // const bcrypt = require('bcrypt');
  // return await bcrypt.hash(plainText, 10);
  return Buffer.from(plainText).toString('base64');
};

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Allowed origins: ${allowedOrigins.join(', ')}`);
});