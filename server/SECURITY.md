# 🔒 Secure Payment Server - Security Implementation Guide

## Overview

This document outlines the security features and best practices implemented in the secure payment server.

## Security Features

### 1. **Webhook Signature Verification**
- ✅ All webhooks are verified using HMAC-SHA256
- ✅ Prevents unauthorized webhook calls
- ✅ Uses timing-safe comparison to prevent timing attacks

```javascript
// Example verification
const hmac = crypto
  .createHmac('sha256', process.env.PI_SECRET_KEY)
  .update(payload)
  .digest('hex');

crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(hmac));
```

### 2. **Authentication & Authorization**
- ✅ All payment endpoints require `Authorization: Bearer TOKEN` header
- ✅ API tokens stored in environment variables
- ✅ No hardcoded secrets in code

### 3. **Rate Limiting**
- ✅ 30 requests per minute per IP address
- ✅ Prevents brute force and DoS attacks
- ✅ Returns 429 (Too Many Requests) when limit exceeded

### 4. **Idempotency Keys**
- ✅ Prevents duplicate payment processing
- ✅ Client must provide unique `idempotencyKey` for each request
- ✅ Same key returns cached response instead of re-processing

### 5. **Duplicate Webhook Detection**
- ✅ Tracks processed webhook IDs
- ✅ Prevents double-charging users
- ✅ Returns 200 OK for duplicate webhooks (safely ignored)

### 6. **Input Validation**
- ✅ Amount must be positive and finite
- ✅ Memo must be valid string
- ✅ Payment IDs must be non-empty
- ✅ All required fields validated before processing

### 7. **Error Handling**
- ✅ Generic error messages (no sensitive data exposure)
- ✅ Proper HTTP status codes
- ✅ Logging for debugging (no passwords/tokens logged)

### 8. **HTTPS/TLS**
- ✅ All external API calls use HTTPS
- ✅ Enforced through axios configuration

## Setup Instructions

### 1. Clone Repository
```bash
git clone https://github.com/Juma-creator/Pay-with-Pi.git
cd Pay-with-Pi
git checkout secure-payment-server
```

### 2. Install Dependencies
```bash
npm install express body-parser axios dotenv
```

### 3. Configure Environment Variables
```bash
# Copy example to .env
cp .env.example .env

# Edit .env and add your credentials
# IMPORTANT: Never commit .env to Git!
nano .env
```

### 4. Generate API Token (for client access)
```bash
# Generate secure random token
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 5. Add .env to .gitignore
```bash
echo ".env" >> .gitignore
git add .gitignore
git commit -m "chore: Add .env to gitignore"
```

### 6. Start Server
```bash
npm start
```

## API Usage Examples

### Create Payment
```bash
curl -X POST http://localhost:3000/payments \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 10,
    "memo": "Order #123",
    "metadata": {"product": "coffee"},
    "idempotencyKey": "unique-key-12345"
  }'
```

### Approve Payment
```bash
curl -X POST http://localhost:3000/payments/PAYMENT_ID/approve \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

### Complete Payment
```bash
curl -X POST http://localhost:3000/payments/PAYMENT_ID/complete \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

## Webhook Configuration

### Register Webhook with Pi Network

1. Log in to [Pi Developer Dashboard](https://developers.pi.app)
2. Go to Application Settings
3. Add webhook URL: `https://your-domain.com/webhooks/payment-completed`
4. Copy the webhook secret
5. Add to `.env`:
   ```
   PI_SECRET_KEY=your_webhook_secret
   ```

### Webhook Signature Verification

Pi Network sends an `x-signature` header with every webhook. The server automatically verifies it using HMAC-SHA256.

## Security Checklist

- [ ] `.env` is in `.gitignore`
- [ ] `PI_SECRET_KEY` is stored securely (not in code)
- [ ] `API_TOKEN` is unique and strong
- [ ] HTTPS is enabled in production
- [ ] Rate limiting is enabled
- [ ] Webhook signature verification is active
- [ ] No sensitive data is logged
- [ ] All external API calls use HTTPS
- [ ] Input validation is in place
- [ ] Error messages don't expose internals

## Production Deployment

### 1. Use Environment-Specific Configuration
```bash
NODE_ENV=production
```

### 2. Use Redis for Session/Cache (instead of in-memory)
```javascript
const redis = require('redis');
const client = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
});
```

### 3. Enable HTTPS/TLS
```javascript
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('path/to/key.pem'),
  cert: fs.readFileSync('path/to/cert.pem'),
};

https.createServer(options, app).listen(443);
```

### 4. Add Request Logging
```javascript
const morgan = require('morgan');
app.use(morgan('combined'));
```

### 5. Add Error Monitoring
```javascript
const Sentry = require("@sentry/node");
Sentry.init({ dsn: process.env.SENTRY_DSN });
```

### 6. Database Integration
Replace in-memory store with database:
```javascript
// Example: PostgreSQL
const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Store/retrieve payments from database
```

## Rotating Secrets

### API Key Rotation
1. Generate new key in Pi Developer Dashboard
2. Update `PI_API_KEY` in `.env`
3. Restart server
4. Revoke old key

### Webhook Secret Rotation
1. Generate new secret in Pi Dashboard
2. Update `PI_SECRET_KEY` in `.env`
3. Restart server
4. Old webhooks will fail validation (safe)

### API Token Rotation
1. Generate new token: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
2. Update `API_TOKEN` in `.env`
3. Restart server
4. Notify clients of new token

## Monitoring & Alerts

### Key Metrics to Monitor
- Failed webhook signatures
- Rate limit violations
- Duplicate payment attempts
- Failed authentication attempts
- API error rates

### Recommended Tools
- Sentry (error tracking)
- DataDog (monitoring)
- CloudFlare (DDoS protection)
- New Relic (performance)

## Compliance

### GDPR
- [ ] Data minimization (only collect necessary data)
- [ ] Data retention policy
- [ ] User data access/deletion endpoints
- [ ] Privacy policy updated

### PCI DSS
- [ ] No storage of full credit card numbers
- [ ] Encrypted sensitive data in transit and at rest
- [ ] Regular security audits
- [ ] Secure API communications

## Reporting Security Issues

If you discover a security vulnerability, please email `security@paywithpi.com` instead of using the issue tracker.

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Pi Network Developer Docs](https://docs.pi.app/)
- [HMAC Verification](https://tools.ietf.org/html/rfc2104)
