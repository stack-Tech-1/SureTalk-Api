const admin = require('firebase-admin');
const serviceAccount = require('./firebase-key.json');

// Initialize Firebase Admin only once
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
  });
}

// Export Firestore instance directly
module.exports = admin.firestore();