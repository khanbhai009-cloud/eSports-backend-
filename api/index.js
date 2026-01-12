const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// --- CONFIGURATION ---
const CASHFREE_ENV = process.env.CASHFREE_ENV || 'TEST';
const CASHFREE_URL = CASHFREE_ENV === 'PROD' 
    ? 'https://api.cashfree.com/pg' 
    : 'https://sandbox.cashfree.com/pg';

// --- FIREBASE INITIALIZATION ---
if (!admin.apps.length) {
    let privateKey = process.env.FIREBASE_PRIVATE_KEY;
    if (privateKey) {
        if (privateKey.startsWith('"') && privateKey.endsWith('"')) {
            privateKey = privateKey.slice(1, -1);
        }
        privateKey = privateKey.replace(/\\n/g, '\n');
    }

    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: privateKey
        })
    });
}
const db = admin.firestore();

// --- MIDDLEWARE ---
app.use(cors({ origin: true }));
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));

// --- TEST ROUTE (GET Error hatane ke liye) ---
app.get('/api', (req, res) => {
    res.send("Backend is Running! Use POST for actions.");
});

// --- AUTH MIDDLEWARE ---
const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        const token = authHeader.split('Bearer ')[1];
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// --- ROUTES ---

// 1. Signup
app.post('/api/auth/signup', verifyToken, async (req, res) => {
    try {
        const { username, email, referralCode } = req.body;
        const uid = req.user.uid;
        const userRef = db.collection('users').doc(uid);
        const doc = await userRef.get();

        if (!doc.exists) {
            const myReferralCode = username.substring(0, 3).toUpperCase() + Math.floor(1000 + Math.random() * 9000);
            await userRef.set({
                uid, username, email, wallet: 0, totalXP: 0, joinedMatches: [],
                referralCode: myReferralCode, referredBy: referralCode || null,
                matchesPlayed: 0, totalKills: 0, dailyStreak: 0, isVIP: false,
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            });
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. Create Order
app.post('/api/wallet/createOrder', verifyToken, async (req, res) => {
    try {
        const { amount } = req.body;
        const uid = req.user.uid;
        const orderId = `ORDER_${uid}_${Date.now()}`;
        
        const userDoc = await db.collection('users').doc(uid).get();
        if(!userDoc.exists) return res.status(404).json({error: "User not found"});

        const payload = {
            order_id: orderId, order_amount: amount, order_currency: "INR",
            customer_details: { customer_id: uid, customer_email: userDoc.data().email, customer_phone: "9999999999" },
            order_meta: { return_url: `https://google.com` } // Dummy return URL
        };

        const cfRes = await axios.post(`${CASHFREE_URL}/orders`, payload, {
            headers: {
                'x-client-id': process.env.CASHFREE_APP_ID,
                'x-client-secret': process.env.CASHFREE_SECRET_KEY,
                'x-api-version': '2022-09-01'
            }
        });

        await db.collection('transactions').add({
            userId: uid, type: 'deposit', amount: parseFloat(amount), status: 'PENDING',
            orderId: orderId, paymentSessionId: cfRes.data.payment_session_id,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ payment_session_id: cfRes.data.payment_session_id, order_id: orderId });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. Webhook
app.post('/api/webhook/cashfree', async (req, res) => {
    try {
        const ts = req.headers['x-webhook-timestamp'];
        const signature = req.headers['x-webhook-signature'];
        const rawBody = req.rawBody;
        
        const genSignature = crypto.createHmac('sha256', process.env.CASHFREE_SECRET_KEY)
            .update(ts + rawBody).digest('base64');
            
        if (genSignature !== signature) return res.status(403).send('Invalid Sig');

        const data = req.body.data;
        if (req.body.type === 'PAYMENT_SUCCESS_WEBHOOK') {
            const orderId = data.order.order_id;
            const amount = parseFloat(data.payment.payment_amount);
            
            const q = await db.collection('transactions').where('orderId', '==', orderId).limit(1).get();
            if (!q.empty && q.docs[0].data().status !== 'SUCCESS') {
                await db.runTransaction(async (t) => {
                    const tRef = q.docs[0].ref;
                    const uRef = db.collection('users').doc(q.docs[0].data().userId);
                    const uDoc = await t.get(uRef);
                    t.update(uRef, { wallet: (uDoc.data().wallet || 0) + amount });
                    t.update(tRef, { status: 'SUCCESS' });
                });
            }
        }
        res.json({ status: 'OK' });
    } catch (e) { res.status(500).send('Error'); }
});

// 4. Join Match
app.post('/api/match/join', verifyToken, async (req, res) => {
    try {
        const { matchId, gameUids } = req.body;
        const uid = req.user.uid;
        
        await db.runTransaction(async (t) => {
            const mRef = db.collection('matches').doc(matchId);
            const uRef = db.collection('users').doc(uid);
            const tRef = mRef.collection('teams').doc(uid);
            
            const mDoc = await t.get(mRef);
            const uDoc = await t.get(uRef);
            const tDoc = await t.get(tRef);

            if(tDoc.exists) throw new Error("Already joined");
            if(uDoc.data().wallet < mDoc.data().entryFee) throw new Error("Low Balance");
            
            t.update(uRef, { wallet: uDoc.data().wallet - mDoc.data().entryFee, joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId) });
            t.update(mRef, { joinedCount: admin.firestore.FieldValue.increment(1) });
            t.set(tRef, { ownerUid: uid, gameUids, joinedAt: admin.firestore.FieldValue.serverTimestamp(), hasReceivedRewards: false });
        });
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 5. Daily Reward
app.post('/api/rewards/daily', verifyToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const uRef = db.collection('users').doc(uid);
        await db.runTransaction(async (t) => {
            const doc = await t.get(uRef);
            const last = doc.data().lastDailyReward?.toDate();
            if(last && (new Date() - last) < 86400000) throw new Error("Wait 24h");
            
            t.update(uRef, { wallet: (doc.data().wallet||0) + 10, lastDailyReward: admin.firestore.FieldValue.serverTimestamp() });
            db.collection('transactions').add({ userId: uid, type: 'daily', amount: 10, status: 'SUCCESS', timestamp: admin.firestore.FieldValue.serverTimestamp() });
        });
        res.json({ success: true, amount: 10 });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// Export for Vercel
module.exports = app;
