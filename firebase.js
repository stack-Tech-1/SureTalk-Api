const admin = require('firebase-admin');
const serviceAccount = require('./firebase-key.json');

// Initialize with explicit FieldValue export
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
  });
}

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue; // Explicitly import FieldValue

module.exports = { db, FieldValue }; // Export both