# Payment Webhook & Pages — Node/Express Reference

This document provides a complete, copy-pasteable Node/Express example that implements the same routes and webhook decryption logic used by this Go demo project.

It covers:
- `POST /payment` — webhook receiver (decrypts AES-256-CBC payload with IV prefix, PKCS#7 padding)
- `GET /payment` — serves the `purchase.html` checkout page (optional: existing `templates/purchase.html`)
- `GET /success` and `GET /fail` — simple status pages

Environment variables
- `PORT` — optional, default `8081`.
- `WEBHOOK_SECRET` — required for decrypting incoming webhook `payload`.

Quick setup

1. Install dependencies (Node.js required):

```bash
npm install express
```

2. Save the example server code below as `server.js` (or copy into your project).
3. Set `WEBHOOK_SECRET` in your environment and run:

```bash
export WEBHOOK_SECRET="your-secret-here"
node server.js
```

Full Express server (paste into `server.js`)

```javascript
// server.js
// Minimal Express server that mirrors the Go demo's routes and decryption.
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 8081;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';

// Helper: decrypt payload using AES-256-CBC with IV prefix
function decryptPayload(base64Payload, secret) {
  // Key = SHA-256(secret)
  const key = crypto.createHash('sha256').update(secret).digest(); // 32 bytes

  const raw = Buffer.from(base64Payload, 'base64');
  if (raw.length < 16) throw new Error('payload too short');

  const iv = raw.slice(0, 16);
  const ciphertext = raw.slice(16);

  if (ciphertext.length % 16 !== 0) throw new Error('invalid ciphertext length');

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  // PKCS#7 unpad
  const pad = decrypted[decrypted.length - 1];
  if (pad < 1 || pad > 16) throw new Error('invalid padding');
  return decrypted.slice(0, decrypted.length - pad).toString('utf8');
}

// POST /payment - webhook receiver
// Expects JSON body: { payload: "<base64(iv + ciphertext)>" }
app.post('/payment', (req, res) => {
  console.log('[WEBHOOK] Received body:', req.body);

  const env = req.body || {};
  if (!env.payload) return res.status(400).json({ error: 'missing payload' });

  if (!WEBHOOK_SECRET) {
    console.warn('[WEBHOOK] WEBHOOK_SECRET not configured. Skipping decrypt.');
    return res.status(200).json({ status: 'warning', message: 'webhook received but webhook secret missing' });
  }

  try {
    const plaintext = decryptPayload(env.payload, WEBHOOK_SECRET);
    console.log('[WEBHOOK] Decrypted payload:', plaintext);

    let data;
    try { data = JSON.parse(plaintext); } catch (e) { data = plaintext; }

    // TODO: implement your own business logic: update DB, send notification, etc.
    // Example logging based on structure used in Go demo:
    if (data && data.status) {
      console.log(`[WEBHOOK] payment ${data.status} (id=${data.payment_id || 'unknown'})`);
    }

    return res.status(200).json({ status: 'received' });
  } catch (err) {
    console.error('[WEBHOOK] Decrypt/parse error:', err && err.message ? err.message : err);
    return res.status(422).json({ error: 'decryption failed' });
  }
});

// GET /payment - serves existing `templates/purchase.html` if present
app.get('/payment', (req, res) => {
  const file = path.join(__dirname, 'templates', 'purchase.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  return res.status(404).send('Purchase page not found');
});

// GET /success
app.get('/success', (req, res) => {
  const paymentId = req.query.payment_id || '';
  const status = req.query.status || 'succeeded';
  res.send(`\n    <html><body style="font-family:Arial,Helvetica,sans-serif;padding:40px;">\n      <h1>Payment ${status}</h1>\n      <p>Payment ID: ${paymentId}</p>\n      <p>Thank you — your payment was processed.</p>\n      <a href="/payment">Back to purchase</a>\n    </body></html>\n  `);
});

// GET /fail
app.get('/fail', (req, res) => {
  const paymentId = req.query.payment_id || '';
  const status = req.query.status || 'failed';
  res.send(`\n    <html><body style="font-family:Arial,Helvetica,sans-serif;padding:40px;">\n      <h1>Payment ${status}</h1>\n      <p>Payment ID: ${paymentId}</p>\n      <p>Sorry — your payment could not be processed.</p>\n      <a href="/payment">Try again</a>\n    </body></html>\n  `);
});

// Serve static assets folder (if present)
app.use('/static', express.static(path.join(__dirname, 'static')));

app.listen(PORT, () => console.log(`Demo server listening on http://localhost:${PORT}`));
```

Encryption helper (for testing webhook) — optional snippet you can run with Node to produce the `payload` value to POST to `/payment`.

```javascript
// encrypt_payload.js (run with node)
// Usage: set WEBHOOK_SECRET and run: node encrypt_payload.js
const crypto = require('crypto');

function encryptPayload(jsonObj, secret) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(16);

  // PKCS#7 pad
  let plaintext = Buffer.from(JSON.stringify(jsonObj), 'utf8');
  const padLen = 16 - (plaintext.length % 16) || 16;
  const pad = Buffer.alloc(padLen, padLen);
  plaintext = Buffer.concat([plaintext, pad]);

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  const combined = Buffer.concat([iv, ciphertext]);
  return combined.toString('base64');
}

// Example usage
if (require.main === module) {
  const secret = process.env.WEBHOOK_SECRET || 'test-secret';
  const payload = {
    event: 'payment.updated',
    payment_id: 'pay_123456',
    status: 'succeeded',
    amount: 500,
    currency: 'MMK',
    provider: 'KBZ Pay',
    timestamp: new Date().toISOString(),
  };

  console.log(encryptPayload(payload, secret));
}
```

Example curl to test the webhook (after running the helper above or generating payload by other means):

```bash
# 1) Generate base64 payload using node helper (or your own tool)
#    export WEBHOOK_SECRET="your-secret"; node encrypt_payload.js > payload.txt

# 2) POST to webhook
curl -X POST http://localhost:8081/payment \
  -H 'Content-Type: application/json' \
  -d '{"payload":"<BASE64_FROM_HELPER>"}'
```

Notes and mapping to the Go demo
- Decryption algorithm: SHA-256(secret) -> 32-byte key, payload = base64(iv + ciphertext), AES-256-CBC, PKCS#7 padding. This matches the `decryptPayload` implementation in `main.go`.
- The Go demo expects POST `/payment` to contain an envelope `{ payload: "..." }` and will reply `{"status":"received"}` on success.
- The frontend at `templates/purchase.html` in this repo posts to `/api/checkout` and polls `/api/payment/:id`. The Express example above focuses on the webhook and page routes; adapt `POST /api/checkout` proxy behavior if you need to forward to an upstream gateway (see `main.go` for details).

If you want, I can also:
- Add a ready-to-run `server.js` file into the repo, or
- Produce a small `Makefile` or shell script to quickly test payload encryption and POSTing.

File created: [PAYMENT_WEBHOOK_DOC.md](PAYMENT_WEBHOOK_DOC.md)
