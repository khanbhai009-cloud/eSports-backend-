const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const crypto = require('crypto');
const axios = require('axios');

// --- CONFIGURATION ---
const app = express();
const PORT = process.env.PORT || 3000;
const CASHFREE_ENV = process.env.CASHFREE_ENV || 'TEST';
const CASHFREE_URL = CASHFREE_ENV === 'PROD' 
    ? 'https://api.cashfree.com/pg' 
    : 'https://sandbox.cashfree.com/pg';

// --- FIREBASE INITIALIZATION ---
if (!admin.apps.length) {
    // FIX: Robust Key Parsing for Vercel
    let privateKey = process.env.FIREBASE_PRIVATE_KEY;
    if (privateKey) {
        // Remove quotes if present and replace literal \n with actual newlines
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
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));
app.use(cors({ origin: true }));

// --- AUTH MIDDLEWARE ---
const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized: No token provided' });
        }
        const token = authHeader.split('Bearer ')[1];
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        console.error('Auth Error:', error.message);
        return res.status(403).json({ error: 'Unauthorized: Invalid token' });
    }
};

// --- API ENDPOINTS ---

// 1. AUTH: SIGNUP
app.post('/api/auth/signup', verifyToken, async (req, res) => {
    const { username, email, referralCode } = req.body;
    const uid = req.user.uid;

    if (!username || !email) return res.status(400).json({ error: 'Missing fields' });

    try {
        const userRef = db.collection('users').doc(uid);
        const doc = await userRef.get();

        if (!doc.exists) {
            const myReferralCode = username.substring(0, 3).toUpperCase() + Math.floor(1000 + Math.random() * 9000);
            await userRef.set({
                uid, username, email, wallet: 0, totalXP: 0, joinedMatches: [],
                referralCode: myReferralCode, referredBy: referralCode || null,
                matchesPlayed: 0, totalKills: 0, dailyStreak: 0, lastDailyReward: null,
                isVIP: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
            });
        }
        return res.status(200).json({ success: true, message: 'User synced' });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// 2. WALLET: CREATE ORDER
app.post('/api/wallet/createOrder', verifyToken, async (req, res) => {
    const { amount } = req.body;
    const uid = req.user.uid;
    if (!amount || amount < 1) return res.status(400).json({ error: 'Invalid amount' });

    try {
        const orderId = `ORDER_${uid}_${Date.now()}`;
        const userRef = db.collection('users').doc(uid);
        const userDoc = await userRef.get();
        if (!userDoc.exists) return res.status(404).json({ error: 'User not found' });
        const userData = userDoc.data();

        const payload = {
            order_id: orderId, order_amount: amount, order_currency: "INR",
            customer_details: { customer_id: uid, customer_email: userData.email, customer_phone: "9999999999" },
            order_meta: { return_url: `https://your-frontend-domain.com/wallet?order_id=${orderId}` }
        };

        const cfResponse = await axios.post(`${CASHFREE_URL}/orders`, payload, {
            headers: {
                'x-client-id': process.env.CASHFREE_APP_ID,
                'x-client-secret': process.env.CASHFREE_SECRET_KEY,
                'x-api-version': '2022-09-01', 'Content-Type': 'application/json'
            }
        });

        await db.collection('transactions').add({
            userId: uid, type: 'deposit', amount: parseFloat(amount), status: 'PENDING',
            orderId: orderId, paymentSessionId: cfResponse.data.payment_session_id,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ payment_session_id: cfResponse.data.payment_session_id, order_id: orderId });
    } catch (error) {
        console.error("Cashfree Error:", error.response?.data || error.message);
        res.status(500).json({ error: 'Payment initialization failed' });
    }
});

// 3. WEBHOOK
app.post('/api/webhook/cashfree', async (req, res) => {
    try {
        const ts = req.headers['x-webhook-timestamp'];
        const signature = req.headers['x-webhook-signature'];
        const rawBody = req.rawBody;
        if (!ts || !signature || !rawBody) return res.status(400).send('Missing headers');

        const genSignature = crypto.createHmac('sha256', process.env.CASHFREE_SECRET_KEY)
            .update(ts + rawBody).digest('base64');
        if (genSignature !== signature) return res.status(403).send('Invalid Signature');

        const data = req.body.data;
        const type = req.body.type;

        if (type === 'PAYMENT_SUCCESS_WEBHOOK') {
            const orderId = data.order.order_id;
            const amount = parseFloat(data.payment.payment_amount);
            const txnQuery = await db.collection('transactions').where('orderId', '==', orderId).limit(1).get();
            
            if (!txnQuery.empty) {
                const txnDoc = txnQuery.docs[0];
                if (txnDoc.data().status !== 'SUCCESS') {
                    await db.runTransaction(async (t) => {
                        const userRef = db.collection('users').doc(txnDoc.data().userId);
                        const userSnap = await t.get(userRef);
                        t.update(userRef, { wallet: (userSnap.data().wallet || 0) + amount });
                        t.update(txnDoc.ref, { status: 'SUCCESS', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
                    });
                }
            }
        } else if (type === 'PAYMENT_FAILED_WEBHOOK') {
             const orderId = data.order.order_id;
             const txnQuery = await db.collection('transactions').where('orderId', '==', orderId).limit(1).get();
             if (!txnQuery.empty) await txnQuery.docs[0].ref.update({ status: 'FAILED' });
        }
        res.status(200).json({ status: 'OK' });
    } catch (error) {
        console.error('Webhook Error:', error);
        res.status(500).send('Webhook Processing Failed');
    }
});

// 4. MATCH JOIN
app.post('/api/match/join', verifyToken, async (req, res) => {
    const { matchId, gameUids } = req.body;
    const uid = req.user.uid;
    // ... (Logi same as before) ...
    // Note: Use same robust transaction logic
    try {
        const matchRef = db.collection('matches').doc(matchId);
        const userRef = db.collection('users').doc(uid);
        const teamRef = matchRef.collection('teams').doc(uid);

        await db.runTransaction(async (t) => {
            const matchDoc = await t.get(matchRef);
            const userDoc = await t.get(userRef);
            const teamDoc = await t.get(teamRef);

            if (!matchDoc.exists || !userDoc.exists) throw new Error("Not found");
            if (teamDoc.exists) throw new Error("Already joined");
            const mData = matchDoc.data();
            const uData = userDoc.data();

            if (mData.status !== 'Upcoming' || mData.joinedCount >= mData.maxPlayers) throw new Error("Unavailable");
            if (uData.wallet < mData.entryFee) throw new Error("Insufficient funds");

            t.update(userRef, { wallet: uData.wallet - mData.entryFee, joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId) });
            t.update(matchRef, { joinedCount: admin.firestore.FieldValue.increment(1) });
            t.set(teamRef, { ownerUid: uid, ownerUsername: uData.username, gameUids, joinedAt: admin.firestore.FieldValue.serverTimestamp(), hasReceivedRewards: false });
            
            const txnRef = db.collection('transactions').doc();
            t.set(txnRef, { userId: uid, type: 'join_match', amount: -mData.entryFee, matchId, status: 'SUCCESS', timestamp: admin.firestore.FieldValue.serverTimestamp() });
        });
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 5. DAILY REWARDS
app.post('/api/rewards/daily', verifyToken, async (req, res) => {
    const uid = req.user.uid;
    const REWARD = 10;
    const ONE_DAY = 24 * 60 * 60 * 1000;
    const userRef = db.collection('users').doc(uid);

    try {
        await db.runTransaction(async (t) => {
            const doc = await t.get(userRef);
            const data = doc.data();
            const last = data.lastDailyReward ? data.lastDailyReward.toDate() : null;
            if (last && (new Date() - last) < ONE_DAY) throw new Error("Already claimed today");

            let streak = (data.dailyStreak || 0) + 1;
            if (last && (new Date() - last) > (ONE_DAY * 2)) streak = 1;

            t.update(userRef, { wallet: (data.wallet || 0) + REWARD, dailyStreak: streak, lastDailyReward: admin.firestore.FieldValue.serverTimestamp() });
            const txnRef = db.collection('transactions').doc();
            t.set(txnRef, { userId: uid, type: 'daily_reward', amount: REWARD, status: 'SUCCESS', timestamp: admin.firestore.FieldValue.serverTimestamp() });
        });
        res.json({ success: true, amount: REWARD });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 6. WITHDRAW
app.post('/api/wallet/withdraw', verifyToken, async (req, res) => {
    // Keep logic same, just ensure route is /api/wallet/withdraw
    const { amount, upiId } = req.body;
    const uid = req.user.uid;
    const userRef = db.collection('users').doc(uid);
    try {
        await db.runTransaction(async (t) => {
            const doc = await t.get(userRef);
            if (doc.data().wallet < amount) throw new Error("Insufficient funds");
            t.update(userRef, { wallet: doc.data().wallet - amount });
            const txnRef = db.collection('transactions').doc();
            t.set(txnRef, { userId: uid, type: 'withdraw', amount: parseFloat(amount), upi: upiId, status: 'PENDING', timestamp: admin.firestore.FieldValue.serverTimestamp() });
        });
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 7. ADMIN DISTRIBUTE
app.post('/api/admin/match/distribute', verifyToken, async (req, res) => {
    // Keep logic same
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
                const txnRef = db.collection('transactions').doc();
                t.set(txnRef, { userId: ownerUid, type: 'prize_winnings', amount: total, matchId, status: 'SUCCESS', timestamp: admin.firestore.FieldValue.serverTimestamp() });
            }
        });
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// ---- HEALTH CHECK (ROOT) ----
app.get('/', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Esports API running'
  });
});

// ---- LOCAL DEV ONLY ----
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server running on ${PORT}`);
  });
}

// ---- EXPORT FOR VERCEL ----
module.exports = app;