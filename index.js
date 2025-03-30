require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { db, FieldValue } = require('./firebase'); // Destructure imports

const app = express();
app.use(cors());
app.use(express.json());

app.post('/api/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, phone } = req.body;
    
    if (!firstName || !email || !phone) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const userRef = await db.collection('Web-Users').add({
      firstName,
      lastName: lastName || '',
      email,
      phone,
      createdAt: FieldValue.serverTimestamp(), // Use imported FieldValue
      status: 'pending'
    });

    res.status(201).json({
      message: 'User created successfully',
      userId: userRef.id
    });
    
  } catch (error) {
    console.error('Firestore error:', error);
    res.status(500).json({ error: error.message }); // Return actual error message
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});