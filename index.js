// index.js
const express = require('express');
const crypto = require('crypto');

const VERIFY_TOKEN = process.env.VERIFY_TOKEN || '0dcf453c51e4a0bb5280fe64493d10a4'; // Must match Meta console
const APP_SECRET = process.env.APP_SECRET || ''; // Facebook App Secret (recommended)
const PORT = process.env.PORT || 3000;

const app = express();

// Keep raw body for signature verification
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// Ignore favicon requests
app.get('/favicon.ico', (req, res) => res.sendStatus(204));

// Verification endpoint (GET)
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('Webhook verified successfully');
    return res.status(200).send(challenge);
  }
  console.warn('Webhook verification failed');
  return res.sendStatus(403);
});

// Helper: verify X-Hub-Signature-256 (preferred) or X-Hub-Signature (fallback)
function verifySignature(req) {
  if (!APP_SECRET) {
    console.warn('APP_SECRET not set — skipping signature verification (dev only).');
    return true;
  }

  const sig256 = req.headers['x-hub-signature-256'];
  const sig = req.headers['x-hub-signature'];
  const body = req.rawBody || Buffer.from(JSON.stringify(req.body)); // fallback to JSON string

  if (sig256) {
    const expected = 'sha256=' + crypto.createHmac('sha256', APP_SECRET).update(body).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig256));
  } else if (sig) {
    const expected = 'sha1=' + crypto.createHmac('sha1', APP_SECRET).update(body).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  }

  // No signature header
  return false;
}

// Receive webhook events (POST)
app.post('/webhook', (req, res) => {
  // Verify signature (if APP_SECRET provided)
  if (APP_SECRET && !verifySignature(req)) {
    console.warn('Signature verification failed');
    return res.sendStatus(403);
  }

  console.log('--- Webhook event received ---');
  console.log(JSON.stringify(req.body, null, 2));

  // Parse WhatsApp messages
  try {
    const entries = req.body.entry || [];
    entries.forEach(entry => {
      (entry.changes || []).forEach(change => {
        const value = change.value || {};
        const messages = value.messages || [];
        messages.forEach(message => {
          const from = message.from; // sender phone number
          const messageId = message.id;
          const type = message.type;
          let text = null;
          if (type === 'text') text = message.text?.body;

          console.log(`Message from ${from}: type=${type}, id=${messageId}, text=${text}`);
          // TODO: add your business logic here (store, respond, etc.)
        });
      });
    });
  } catch (err) {
    console.error('Error handling webhook body:', err);
  }

  // Acknowledge receipt
  res.sendStatus(200);
});

// Start server
app.listen(PORT, () => {
  console.log(`Webhook server listening on port ${PORT}`);
});
