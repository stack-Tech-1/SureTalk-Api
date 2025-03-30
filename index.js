require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { db, FieldValue } = require('./firebase');

const app = express();
app.use(cors({
  origin: ['https://your-frontend-url.onrender.com', 'http://localhost:3000'],
  methods: ['POST']
}));
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
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Create user document with all fields
    const userRef = await db.collection('Web-Users').add({
      firstName,
      lastName: lastName || '',
      email,
      phone,
      username: username || '',
      password: hashPassword(password), // Always hash passwords!
      usage: usage || 'not specified',
      isInterestedInPartnership: joinProgram || false,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      status: 'pending'
    });

    res.status(201).json({
      message: 'User created successfully',
      userId: userRef.id
    });
    
  } catch (error) {
    console.error('Firestore error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Password hashing function (simplified example)
const hashPassword = (plainText) => {
  // In production, use bcrypt or similar
  return Buffer.from(plainText).toString('base64'); 
};

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});