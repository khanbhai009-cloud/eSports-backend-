const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const crypto = require('crypto');
const axios = require('axios');
const cron = require('node-cron'); // <--- YE HAI MAIN CHEEZ (ALARM CLOCK)

const app = express();

// --- CONFIGURATION ---
// Vercel Environment Variables se values lega
const CASHFREE_ENV = process.env.CASHFREE_ENV || 'TEST';
const CASHFREE_URL = CASHFREE_ENV === 'PROD' 
    ? 'https://api.cashfree.com/pg' 
    : 'https://sandbox.cashfree.com/pg';

// --- FIREBASE SETUP ---
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

// --- SECURITY GUARDS (POLICE) ---

// 1. Verify User (Sabke liye)
const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized: No Token' });
        }
        const token = authHeader.split('Bearer ')[1];
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or Expired Token' });
    }
};

// 2. Verify Admin (Sirf Admin Routes ke liye)
const verifyAdmin = (req, res, next) => {
    // Yahan apna aur apne trusted admin ka email daalo
    const ADMIN_EMAILS = ["admin123@gmail.com", "owner@esports.com"]; 
    
    if (req.user && ADMIN_EMAILS.includes(req.user.email)) {
        next(); // Admin hai, aage jaane do
    } else {
        return res.status(403).json({ error: "Access Denied: Admins Only" });
    }
};

// --- AUTOMATIC MATCH STARTER (CRON JOB) ---
// Ye code Server par 24/7 chalega aur har 1 minute mein check karega
cron.schedule('* * * * *', async () => {
    console.log("⏰ Checking for matches to start...");
    const now = Date.now();

    try {
        // Query: Aise matches jo 'Upcoming' hain PAR unka Time ho chuka hai
        const snapshot = await db.collection('matches')
            .where('status', '==', 'Upcoming')
            .where('unlockTimestamp', '<=', now)
            .get();

        if (snapshot.empty) return;

        const batch = db.batch();
        
        snapshot.docs.forEach(doc => {
            // Status change kar do -> Frontend apne aap Room ID dikha dega
            batch.update(doc.ref, { status: 'Playing' });
            console.log(`✅ Auto-Started Match: ${doc.id}`);
        });

        await batch.commit();
    } catch (error) {
        console.error("❌ Auto-Start Error:", error);
    }
});

// --- API ROUTES ---

// 1. Join Match (Team Logic included)
app.post('/api/match/join', verifyToken, async (req, res) => {
    try {
        const { matchId, gameUids } = req.body; // gameUids array hai
        const uid = req.user.uid;

        await db.runTransaction(async (t) => {
            const mRef = db.collection('matches').doc(matchId);
            const uRef = db.collection('users').doc(uid);
            // Important: Hum 'teams' collection use kar rahe hain
            const teamRef = mRef.collection('teams').doc(uid);

            const mDoc = await t.get(mRef);
            const uDoc = await t.get(uRef);
            const tDoc = await t.get(teamRef);

            if(tDoc.exists) throw new Error("You have already joined this match!");
            if(uDoc.data().wallet < mDoc.data().entryFee) throw new Error("Insufficient Balance! Please Add Cash.");

            // 1. Paise kaato
            t.update(uRef, { 
                wallet: uDoc.data().wallet - mDoc.data().entryFee, 
                joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId) 
            });

            // 2. Match me count badhao
            t.update(mRef, { joinedCount: admin.firestore.FieldValue.increment(1) });

            // 3. Team Entry banao (Captain + UIDs)
            t.set(teamRef, { 
                ownerUid: uid,
                captainName: uDoc.data().username,
                avatar: uDoc.data().avatar || null,
                gameUids: gameUids, // Saari UIDs save hongi
                joinedAt: admin.firestore.FieldValue.serverTimestamp(), 
                hasReceivedRewards: false 
            });
        });
        res.json({ success: true, message: "Joined Successfully" });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 2. Admin Distribute (Prize & XP Logic) - SECURED
app.post('/api/admin/match/distribute', verifyToken, verifyAdmin, async (req, res) => {
    const { matchId, gameUid, rank, kills } = req.body;
    
    try {
        const matchRef = db.collection('matches').doc(matchId);
        
        // Jadoo: Sirf ek Player UID se puri Team dhoondhna
        const teamQuery = await matchRef.collection('teams')
            .where('gameUids', 'array-contains', gameUid) 
            .limit(1).get();

        if (teamQuery.empty) return res.status(404).json({ error: 'Player UID not found in any team!' });

        const teamDoc = teamQuery.docs[0];
        const teamRef = teamDoc.ref;
        const ownerUid = teamDoc.data().ownerUid; // Captain ki ID

        await db.runTransaction(async (t) => {
            const mDoc = await t.get(matchRef);
            const tDoc = await t.get(teamRef);

            if (tDoc.data().hasReceivedRewards) throw new Error("Rewards already distributed to this team!");

            const mData = mDoc.data();
            const killPrize = kills * (mData.perKill || 0);
            const rankPrize = (mData.rankPrizes && mData.rankPrizes[rank-1]) || 0;
            const totalCash = killPrize + rankPrize;
            
            // XP Calculation: 100 XP fixed + 10 XP per kill
            const totalXp = 100 + (kills * 10);

            const uRef = db.collection('users').doc(ownerUid);
            const uDoc = await t.get(uRef);

            // Captain ko Paisa + XP do
            t.update(uRef, { 
                wallet: (uDoc.data().wallet || 0) + totalCash, 
                xp: (uDoc.data().xp || 0) + totalXp,
                matchesPlayed: admin.firestore.FieldValue.increment(1), 
                totalKills: admin.firestore.FieldValue.increment(kills) 
            });

            // Team ko mark kar do
            t.update(teamRef, { 
                hasReceivedRewards: true, 
                resultRank: rank, 
                resultKills: kills, 
                prizeWon: totalCash 
            });

            // Transaction History
            if (totalCash > 0) {
                db.collection('transactions').add({ 
                    userId: ownerUid, 
                    type: 'prize_winnings', 
                    amount: totalCash, 
                    matchId, 
                    status: 'SUCCESS', 
                    timestamp: admin.firestore.FieldValue.serverTimestamp() 
                });
            }
        });
        res.json({ success: true, message: `Sent ₹${totalCash} to Captain` });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 3. Wallet - Withdraw Request
app.post('/api/wallet/withdraw', verifyToken, async (req, res) => {
    const { amount, upiId } = req.body;
    const uid = req.user.uid;
    const userRef = db.collection('users').doc(uid);
    
    try {
        await db.runTransaction(async (t) => {
            const doc = await t.get(userRef);
            if (doc.data().wallet < amount) throw new Error("Insufficient funds");
            
            // Wallet se paise kaato
            t.update(userRef, { wallet: doc.data().wallet - amount });
            
            // Transaction Record (Pending)
            db.collection('transactions').add({ 
                userId: uid, 
                type: 'withdraw', 
                amount: parseFloat(amount), 
                upi: upiId, 
                status: 'Pending', 
                timestamp: admin.firestore.FieldValue.serverTimestamp() 
            });
        });
        res.json({ success: true });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 4. Wallet - Create Deposit Order (Cashfree)
app.post('/api/wallet/createOrder', verifyToken, async (req, res) => {
    try {
        const { amount } = req.body;
        const uid = req.user.uid;
        const orderId = `ORDER_${uid}_${Date.now()}`;

        const userDoc = await db.collection('users').doc(uid).get();
        if(!userDoc.exists) return res.status(404).json({error: "User not found"});

        const payload = {
            order_id: orderId, order_amount: amount, order_currency: "INR",
            customer_details: { 
                customer_id: uid, 
                customer_email: userDoc.data().email, 
                customer_phone: "9999999999" 
            },
            order_meta: { return_url: "https://google.com" } 
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

// 5. Cashfree Webhook (Auto-Confirm Payment)
app.post('/api/webhook/cashfree', async (req, res) => {
    try {
        const ts = req.headers['x-webhook-timestamp'];
        const signature = req.headers['x-webhook-signature'];
        const rawBody = req.rawBody;

        // Security Check: Verify Signature
        const genSignature = crypto.createHmac('sha256', process.env.CASHFREE_SECRET_KEY)
            .update(ts + rawBody).digest('base64');

        if (genSignature !== signature) return res.status(403).send('Invalid Signature');

        const data = req.body.data;
        if (req.body.type === 'PAYMENT_SUCCESS_WEBHOOK') {
            const orderId = data.order.order_id;
            const amount = parseFloat(data.payment.payment_amount);

            // Transaction dhundo aur update karo
            const q = await db.collection('transactions').where('orderId', '==', orderId).limit(1).get();
            if (!q.empty && q.docs[0].data().status !== 'SUCCESS') {
                await db.runTransaction(async (t) => {
                    const tRef = q.docs[0].ref;
                    const uRef = db.collection('users').doc(q.docs[0].data().userId);
                    const uDoc = await t.get(uRef);
                    
                    // User ka wallet badhao
                    t.update(uRef, { wallet: (uDoc.data().wallet || 0) + amount });
                    // Transaction Success karo
                    t.update(tRef, { status: 'SUCCESS' });
                });
            }
        }
        res.json({ status: 'OK' });
    } catch (e) { res.status(500).send('Error'); }
});

// 6. Daily Reward API
app.post('/api/rewards/daily', verifyToken, async (req, res) => {
    try {
        const uid = req.user.uid;
        const uRef = db.collection('users').doc(uid);
        
        await db.runTransaction(async (t) => {
            const doc = await t.get(uRef);
            const last = doc.data().lastDailyReward?.toDate();
            
            // Check: 24 Hours hue ya nahi?
            if(last && (new Date() - last) < 86400000) throw new Error("Please wait 24 hours for next reward!");

            const rewardAmt = 10; // ₹10 Daily Bonus
            
            t.update(uRef, { 
                wallet: (doc.data().wallet || 0) + rewardAmt, 
                lastDailyReward: admin.firestore.FieldValue.serverTimestamp() 
            });
            
            db.collection('transactions').add({ 
                userId: uid, 
                type: 'daily_reward', 
                amount: rewardAmt, 
                status: 'SUCCESS', 
                timestamp: admin.firestore.FieldValue.serverTimestamp() 
            });
        });
        res.json({ success: true, amount: 10 });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// 7. Test Route
app.get('/api', (req, res) => {
    res.send("Esports Backend vFinal is Running! 🚀");
});

module.exports = app;
