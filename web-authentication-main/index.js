const express = require('express');
const cors = require('cors');
const crypto = require('node:crypto');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} = require('@simplewebauthn/server');

if (!globalThis.crypto) {
    globalThis.crypto = crypto;
}

const PORT = 5500;
const app = express();

app.use(cors());
app.use(express.static('public'));
app.use(express.json());
app.use(cors({
    origin: 'http://127.0.0.1:5500' // or specify any other origin you want to allow
}));
// States
const userStore = {};
const challengeStore = {};

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const id = `user_${Date.now()}`;

    const user = {
        id,
        username,
        password
    };

    userStore[id] = user;

    console.log('Register successful', userStore[id]);

    return res.json({ id });
});

app.post('/register-challenge', async (req, res) => {
    const { userId } = req.body;

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' });

    const user = userStore[userId];

    const challengePayload = await generateRegistrationOptions({
        rpID: 'localhost',
        rpName: 'My Localhost Machine',
        attestationType: 'none',
        userName: user.username,
        timeout: 30_000,
    });

    challengeStore[userId] = challengePayload.challenge;

    return res.json({ options: challengePayload });
});

app.post('/register-verify', async (req, res) => {
    const { userId, cred }  = req.body;

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' });

    const user = userStore[userId];
    const challenge = challengeStore[userId];

    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:5500',
        expectedRPID: 'localhost',
        response: cred,
    });

    if (!verificationResult.verified) return res.json({ error: 'could not verify' });
    userStore[userId].passkey = verificationResult.registrationInfo;

    return res.json({ verified: true });
});

app.post('/login-challenge', async (req, res) => {
    const { userId } = req.body;
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' });
    
    const opts = await generateAuthenticationOptions({
        rpID: 'localhost',
    });

    challengeStore[userId] = opts.challenge;

    return res.json({ options: opts });
});

app.post('/login-verify', async (req, res) => {
    const { userId, cred }  = req.body;

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' });
    const user = userStore[userId];
    const challenge = challengeStore[userId];

    const result = await verifyAuthenticationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:5500',
        expectedRPID: 'localhost',
        response: cred,
        authenticator: user.passkey
    });

    if (!result.verified) return res.json({ error: 'something went wrong' });
    
    // Login the user: Session, Cookies, JWT
    return res.json({ success: true, userId });
});

app.listen(PORT, () => console.log(`Server started on PORT:${PORT}`));
