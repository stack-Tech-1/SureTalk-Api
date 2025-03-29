require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./firebase');

const app = express();
app.use(cors());
app.use(express.json());

// Signup Endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, phone } = req.body;
    
    if (!firstName || !email || !phone) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Use db.FieldValue instead of admin.firestore
    const userRef = await db.collection('users').add({
      firstName,
      lastName: lastName || '',
      email,
      phone,
      createdAt: db.FieldValue.serverTimestamp(), // Fixed this line
      status: 'pending'
    });

    res.status(201).json({
      message: 'User created successfully',
      userId: userRef.id
    });
    
  } catch (error) {
    console.error('Firestore error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});