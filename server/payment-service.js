const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// In-memory store (use Redis/DB in production)
const processedWebhooks = new Set();
const pendingPayments = new Map();

// ===== MIDDLEWARE =====

/**
 * Verify Pi Network webhook signature
 */
function verifyWebhookSignature(req) {
  const signature = req.headers['x-signature'];
  if (!signature) return false;

  const payload = JSON.stringify(req.body);
  const hmac = crypto
    .createHmac('sha256', process.env.PI_SECRET_KEY)
    .update(payload)
    .digest('hex');

  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(hmac));
}

/**
 * Authentication middleware
 */
function authenticate(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token || token !== process.env.API_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

/**
 * Rate limiting middleware
 */
const rateLimit = (() => {
  const requests = new Map();
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    const windowStart = now - 60000; // 1 minute window

    if (!requests.has(ip)) requests.set(ip, []);
    const reqs = requests.get(ip).filter(t => t > windowStart);

    if (reqs.length > 30) { // 30 requests per minute
      return res.status(429).json({ error: 'Too many requests' });
    }

    reqs.push(now);
    requests.set(ip, reqs);
    next();
  };
})();

app.use(rateLimit);

// ===== PAYMENT ENDPOINTS =====

/**
 * Create payment (requires authentication)
 */
app.post('/payments', authenticate, async (req, res) => {
  try {
    const { amount, memo, metadata, idempotencyKey } = req.body;

    // Validate request
    if (!amount || amount <= 0 || !Number.isFinite(amount)) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (!memo || typeof memo !== 'string') {
      return res.status(400).json({ error: 'Invalid memo' });
    }
    if (!idempotencyKey) {
      return res.status(400).json({ error: 'Idempotency key required' });
    }

    // Check for duplicate request
    if (pendingPayments.has(idempotencyKey)) {
      return res.status(200).json(pendingPayments.get(idempotencyKey));
    }

    // Create payment with Pi Network
    const piResponse = await axios.post(
      'https://api.minepi.com/v2/payments',
      { amount, memo, metadata },
      {
        headers: {
          Authorization: `Bearer ${process.env.PI_API_KEY}`,
          'X-API-KEY': process.env.PI_API_KEY,
        },
      }
    );

    const payment = {
      paymentId: piResponse.data.payment.identifier,
      status: 'pending',
      amount,
      createdAt: new Date(),
    };

    // Store payment
    pendingPayments.set(idempotencyKey, payment);

    // Don't log sensitive payment details
    console.log(`[Payment] Created: ID=${payment.paymentId}`);

    res.status(201).json(payment);
  } catch (error) {
    console.error('[Payment Error]', error.message);
    res.status(500).json({ error: 'Payment creation failed' });
  }
});

/**
 * Approve payment (requires authentication)
 */
app.post('/payments/:paymentId/approve', authenticate, async (req, res) => {
  try {
    const { paymentId } = req.params;

    if (!paymentId) {
      return res.status(400).json({ error: 'Payment ID required' });
    }

    // Call Pi Network approve endpoint
    await axios.post(
      `https://api.minepi.com/v2/payments/${paymentId}/approve`,
      {},
      {
        headers: {
          Authorization: `Bearer ${process.env.PI_API_KEY}`,
        },
      }
    );

    console.log(`[Payment] Approved: ID=${paymentId}`);
    res.json({ status: 'approved' });
  } catch (error) {
    console.error('[Approve Error]', error.message);
    res.status(500).json({ error: 'Approval failed' });
  }
});

/**
 * Complete payment (requires authentication)
 */
app.post('/payments/:paymentId/complete', authenticate, async (req, res) => {
  try {
    const { paymentId } = req.params;

    if (!paymentId) {
      return res.status(400).json({ error: 'Payment ID required' });
    }

    // Call Pi Network complete endpoint
    await axios.post(
      `https://api.minepi.com/v2/payments/${paymentId}/complete`,
      {},
      {
        headers: {
          Authorization: `Bearer ${process.env.PI_API_KEY}`,
        },
      }
    );

    console.log(`[Payment] Completed: ID=${paymentId}`);
    res.json({ status: 'completed' });
  } catch (error) {
    console.error('[Complete Error]', error.message);
    res.status(500).json({ error: 'Completion failed' });
  }
});

// ===== WEBHOOK ENDPOINT =====

/**
 * Pi Network webhook (unauthenticated but signature-verified)
 */
app.post('/webhooks/payment-completed', (req, res) => {
  try {
    // Verify signature
    if (!verifyWebhookSignature(req)) {
      console.warn('[Webhook] Invalid signature');
      return res.status(401).json({ error: 'Invalid signature' });
    }

    const { identifier, txid } = req.body.payment;

    // Prevent duplicate processing
    if (processedWebhooks.has(identifier)) {
      console.log(`[Webhook] Duplicate payment: ${identifier}`);
      return res.status(200).json({ success: true });
    }

    processedWebhooks.add(identifier);

    // Process payment (don't log full details)
    console.log(`[Webhook] Payment completed: ID=${identifier}`);

    // Update your database/ledger here
    // recordTransaction(identifier, txid);

    res.status(200).json({ success: true });
  } catch (error) {
    console.error('[Webhook Error]', error.message);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// ===== HEALTH CHECK =====

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Secure payment server running on port ${PORT}`));

module.exports = app;
