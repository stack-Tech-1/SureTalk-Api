const admin = require('firebase-admin');

// Initialize Firebase Admin
if (!admin.apps.length) {
  // Use either the service account file or environment variable
  let serviceAccount;
  
  try {
    // Try to use the service account file first
    serviceAccount = require('./firebase-key.json');
  } catch (e) {
    // Fall back to environment variable if file doesn't exist
    serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG || "{}");
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`,
    storageBucket: "suretalkdb.appspot.com"
  });
}

// Get Firestore and Storage instances
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;
const storage = admin.storage().bucket();

// Export all needed services
module.exports = { 
  db, 
  FieldValue, 
  storage 
};