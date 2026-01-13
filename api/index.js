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

// --- TEST ROUTE ---
app.get('/api', (req, res) => {
    res.send("Backend is Running! Use POST requests.");
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

// --- ROUTES (Note: Sabke aage /api laga hai) ---

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
            order_meta: { return_url: `https://google.com` } 
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
            // 24 hours check
            if(last && (new Date() - last) < 86400000) throw new Error("Wait 24h");
            
            t.update(uRef, { wallet: (doc.data().wallet||0) + 10, lastDailyReward: admin.firestore.FieldValue.serverTimestamp() });
            db.collection('transactions').add({ userId: uid, type: 'daily', amount: 10, status: 'SUCCESS', timestamp: admin.firestore.FieldValue.serverTimestamp() });
        });
        res.json({ success: true, amount: 10 });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 6. Withdraw
app.post('/api/wallet/withdraw', verifyToken, async (req, res) => {
    const { amount, upiId } = req.body;
    const uid = req.user.uid;
    const userRef = db.collection('users').doc(uid);
    try {
        await db.runTransaction(async (t) => {
            const doc = await t.get(userRef);
            if (doc.data().wallet < amount) throw new Error("Insufficient funds");
            t.update(userRef, { wallet: doc.data().wallet - amount });
            db.collection('transactions').add({ userId: uid, type: 'withdraw', amount: parseFloat(amount), upi: upiId, status: 'PENDING', timestamp: admin.firestore.FieldValue.serverTimestamp() });
        });
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 7. Admin Distribute
app.post('/api/admin/match/distribute', verifyToken, async (req, res) => {
    const { matchId, gameUid, rank, kills } = req.body;
    try {
        const matchRef = db.collection('matches').doc(matchId);
        const teamQuery = await matchRef.collection('teams').where('gameUids', 'array-contains', gameUid).limit(1).get();
        if (teamQuery.empty) return res.status(404).json({ error: 'Player not found' });
        
        const teamDoc = teamQuery.docs[0];
        const teamRef = teamDoc.ref;
        const ownerUid = teamDoc.data().ownerUid;

        await db.runTransaction(async (t) => {
            const mDoc = await t.get(matchRef);
            const tDoc = await t.get(teamRef);
            if (tDoc.data().hasReceivedRewards) throw new Error("Already distributed");

            const mData = mDoc.data();
            const killPrize = kills * (mData.perKillRate || 0);
            const rankPrize = (mData.rankPrizes && mData.rankPrizes[rank-1]) || 0;
            const total = killPrize + rankPrize;
            const xp = (kills * 10) + 100;

            const uRef = db.collection('users').doc(ownerUid);
            const uDoc = await t.get(uRef);
            
            t.update(uRef, { wallet: (uDoc.data().wallet || 0) + total, totalXP: (uDoc.data().totalXP || 0) + xp, matchesPlayed: admin.firestore.FieldValue.increment(1), totalKills: admin.firestore.FieldValue.increment(kills) });
            t.update(teamRef, { hasReceivedRewards: true, resultRank: rank, resultKills: kills, prizeWon: total });
            
            if (total > 0) {
                db.collection('transactions').add({ userId: ownerUid, type: 'prize_winnings', amount: total, matchId, status: 'SUCCESS', timestamp: admin.firestore.FieldValue.serverTimestamp() });
            }
        });
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

module.exports = app;
