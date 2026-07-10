/**
 * PayWithPi Compliance Replay Script
 * Author: Juma
 * Purpose: Automate audit replay and regulator evidence generation
 * Production Version with Encryption, Metrics, and Audit Trails
 */

import fs from 'fs';
import path from 'path';
import axios from 'axios';
import crypto from 'crypto';
import https from 'https';
import prom from 'prom-client';
import express from 'express';

const REGION = process.env.REGION || 'Tanzania';
const CLUSTER = process.env.CLUSTER || 'Africa';
const COMPLIANCE_MODE = process.env.COMPLIANCE_MODE || 'sandbox';
const REGULATOR_WEBHOOK_URL =
  process.env.REGULATOR_WEBHOOK_URL ||
  'https://compliance.paywithpi.global/webhook';

const ENCRYPTION_KEY = fs.readFileSync('/etc/secrets/encryption-key');
const WEBHOOK_KEY = fs.readFileSync('/etc/secrets/webhook-signing-key');

// ==================== PROMETHEUS METRICS ====================

const replayCounter = new prom.Counter({
  name: 'compliance_replay_total',
  help: 'Total compliance replay attempts',
  labelNames: ['region', 'cluster', 'status', 'replay_type']
});

const successCounter = new prom.Counter({
  name: 'compliance_replay_success_total',
  help: 'Successful compliance replays',
  labelNames: ['region', 'cluster']
});

const latencyHistogram = new prom.Histogram({
  name: 'compliance_replay_latency_seconds',
  help: 'Compliance replay latency',
  labelNames: ['region', 'cluster', 'operation'],
  buckets: [0.1, 0.5, 1, 2, 5, 10, 30, 60]
});

const auditLogCounter = new prom.Counter({
  name: 'audit_log_entries_total',
  help: 'Total audit log entries',
  labelNames: ['region', 'cluster', 'log_type']
});

const webhookCounter = new prom.Counter({
  name: 'webhook_delivery_total',
  help: 'Webhook delivery attempts',
  labelNames: ['region', 'cluster', 'status', 'endpoint']
});

const encryptionCounter = new prom.Counter({
  name: 'encryption_operations_total',
  help: 'Encryption/decryption operations',
  labelNames: ['region', 'operation', 'algorithm', 'status']
});

const dataIntegrityGauge = new prom.Gauge({
  name: 'audit_log_integrity_check_pass',
  help: 'Data integrity check result (1=pass, 0=fail)',
  labelNames: ['region', 'cluster']
});

const complianceScoreGauge = new prom.Gauge({
  name: 'compliance_score',
  help: 'Overall compliance score (0-100)',
  labelNames: ['region', 'cluster', 'metric_type']
});

const sloComplianceRatio = new prom.Gauge({
  name: 'slo_compliance_ratio',
  help: 'SLO compliance ratio',
  labelNames: ['region', 'cluster', 'slo_name']
});

// ==================== ENCRYPTION FUNCTIONS ====================

function encryptAuditEntry(entry) {
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);

    let encrypted = cipher.update(JSON.stringify(entry), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    encryptionCounter
      .labels(REGION, 'encrypt', 'aes-256-gcm', 'success')
      .inc();

    return {
      iv: iv.toString('hex'),
      encryptedData: encrypted,
      authTag: authTag.toString('hex'),
      algorithm: 'aes-256-gcm'
    };
  } catch (error) {
    encryptionCounter
      .labels(REGION, 'encrypt', 'aes-256-gcm', 'failure')
      .inc();
    throw error;
  }
}

function signWebhookPayload(payload) {
  const signature = crypto
    .createHmac('sha256', WEBHOOK_KEY)
    .update(JSON.stringify(payload))
    .digest('hex');

  return {
    payload,
    signature: `sha256=${signature}`,
    timestamp: new Date().toISOString(),
    nonce: crypto.randomUUID()
  };
}

function createHashChain(transaction, previousHash) {
  const entry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    timezone: 'Africa/Dar_es_Salaam',
    region: REGION,
    cluster: CLUSTER,
    transaction,
    previousHash,
    context: {
      operator: process.env.OPERATOR_ID || 'system',
      reason: 'scheduled-compliance-replay',
      version: '1.0'
    }
  };

  entry.hash = crypto
    .createHash('sha256')
    .update(JSON.stringify(entry))
    .digest('hex');

  return entry;
}

// ==================== CORE COMPLIANCE FUNCTIONS ====================

async function fetchTransactions() {
  console.log(`🔍 Fetching transactions for ${REGION} cluster...`);
  // In production, fetch from database or API
  return [
    { id: 'TX001', amount: 150000, status: 'success', timestamp: new Date().toISOString() },
    { id: 'TX002', amount: 50000, status: 'failed', timestamp: new Date().toISOString() },
    { id: 'TX003', amount: 200000, status: 'success', timestamp: new Date().toISOString() }
  ];
}

async function replayCompliance(transactions) {
  console.log('🔁 Running compliance replay...');
  let previousHash = null;
  const auditChain = [];
  const logsDir = './logs/compliance';

  // Ensure directory exists
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }

  for (const transaction of transactions) {
    const entry = createHashChain(transaction, previousHash);
    const encrypted = encryptAuditEntry(entry);
    const signed = signWebhookPayload(encrypted);

    auditChain.push(signed);
    previousHash = entry.hash;

    // Append to immutable audit log
    fs.appendFileSync(
      path.join(logsDir, 'audit-chain.json'),
      JSON.stringify(signed) + '\n'
    );
  }

  // Write summary
  fs.writeFileSync(
    path.join(logsDir, 'audit.json'),
    JSON.stringify(auditChain, null, 2)
  );

  console.log('✅ Audit logs generated.');
  auditLogCounter.labels(REGION, CLUSTER, 'compliance').inc(auditChain.length);

  return auditChain;
}

function verifyAuditChainIntegrity(auditChain) {
  console.log('🔐 Verifying audit chain integrity...');
  for (let i = 1; i < auditChain.length; i++) {
    const current = auditChain[i].payload;
    const previous = auditChain[i - 1].payload;

    if (current.previousHash !== previous.hash) {
      console.error(`❌ Chain break at index ${i}`);
      return false;
    }
  }
  console.log('✅ Audit chain integrity verified.');
  return true;
}

async function notifyRegulator(auditChain) {
  console.log('📡 Sending audit summary to regulator...');

  const summary = {
    region: REGION,
    cluster: CLUSTER,
    mode: COMPLIANCE_MODE,
    total: auditChain.length,
    passed: auditChain.filter(t => t.payload.transaction.status === 'success').length,
    failed: auditChain.filter(t => t.payload.transaction.status === 'failed').length,
    timestamp: new Date().toISOString(),
    chainHead: auditChain[auditChain.length - 1].payload.hash
  };

  const signed = signWebhookPayload(summary);

  const httpsAgent = new https.Agent({
    cert: fs.readFileSync('/etc/certs/client.crt'),
    key: fs.readFileSync('/etc/certs/client.key'),
    ca: fs.readFileSync('/etc/certs/regulator-ca.crt'),
    rejectUnauthorized: true
  });

  try {
    await axios.post(REGULATOR_WEBHOOK_URL, signed, {
      httpsAgent,
      headers: {
        'X-Signature': signed.signature,
        'X-Timestamp': signed.timestamp,
        'X-Nonce': signed.nonce,
        'Content-Type': 'application/json'
      },
      timeout: 30000
    });

    webhookCounter.labels(REGION, CLUSTER, 'success', 'regulator').inc();
    console.log('📨 Regulator notified successfully.');
  } catch (error) {
    webhookCounter.labels(REGION, CLUSTER, 'failure', 'regulator').inc();
    throw new Error(`Webhook delivery failed: ${error.message}`);
  }
}

function calculateComplianceScore(metrics) {
  let score = 100;

  if (!metrics.success) score -= 50;
  if (metrics.latency > 10) score -= 20;
  else if (metrics.latency > 5) score -= 10;
  if (!metrics.integrityCheck) score -= 30;
  if (metrics.auditLogCount === 0) score -= 25;
  if (!metrics.webhookDelivery) score -= 20;

  return Math.max(0, score);
}

// ==================== MAIN EXECUTION ====================

(async () => {
  try {
    const startTime = Date.now();

    // Fetch transactions
    let txStart = Date.now();
    const transactions = await fetchTransactions();
    latencyHistogram
      .labels(REGION, CLUSTER, 'fetch_transactions')
      .observe((Date.now() - txStart) / 1000);

    // Replay compliance
    let replayStart = Date.now();
    const audited = await replayCompliance(transactions);
    const replayDuration = (Date.now() - replayStart) / 1000;
    latencyHistogram
      .labels(REGION, CLUSTER, 'replay_compliance')
      .observe(replayDuration);

    // Verify integrity
    let integrityStart = Date.now();
    const integrityCheck = verifyAuditChainIntegrity(audited);
    latencyHistogram
      .labels(REGION, CLUSTER, 'integrity_check')
      .observe((Date.now() - integrityStart) / 1000);

    dataIntegrityGauge.labels(REGION, CLUSTER).set(integrityCheck ? 1 : 0);

    if (!integrityCheck) {
      throw new Error('Audit chain integrity check failed');
    }

    // Notify regulator
    let notifyStart = Date.now();
    await notifyRegulator(audited);
    latencyHistogram
      .labels(REGION, CLUSTER, 'notify_regulator')
      .observe((Date.now() - notifyStart) / 1000);

    // Record success metrics
    replayCounter.labels(REGION, CLUSTER, 'success', 'scheduled').inc();
    successCounter.labels(REGION, CLUSTER).inc();
    sloComplianceRatio
      .labels(REGION, CLUSTER, 'availability')
      .set(1.0);

    // Calculate compliance score
    const complianceScore = calculateComplianceScore({
      success: true,
      latency: replayDuration,
      integrityCheck,
      auditLogCount: audited.length,
      webhookDelivery: true
    });

    complianceScoreGauge
      .labels(REGION, CLUSTER, 'overall')
      .set(complianceScore);

    console.log(`\n✅ Compliance Replay Completed Successfully`);
    console.log(`   Duration: ${replayDuration.toFixed(2)}s`);
    console.log(`   Compliance Score: ${complianceScore}/100`);
    console.log(`   Audit Entries: ${audited.length}`);

  } catch (error) {
    replayCounter.labels(REGION, CLUSTER, 'failure', 'scheduled').inc();
    webhookCounter.labels(REGION, CLUSTER, 'failure', 'regulator').inc();
    complianceScoreGauge.labels(REGION, CLUSTER, 'overall').set(0);
    dataIntegrityGauge.labels(REGION, CLUSTER).set(0);

    console.error('❌ Compliance replay failed:', error.message);
    process.exit(1);
  }
})();

// ==================== METRICS ENDPOINT ====================

const app = express();

app.get('/metrics', (req, res) => {
  res.set('Content-Type', prom.register.contentType);
  res.end(prom.register.metrics());
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', region: REGION, cluster: CLUSTER });
});

const PORT = process.env.METRICS_PORT || 9090;
app.listen(PORT, () => {
  console.log(`📊 Metrics endpoint listening on port ${PORT}`);
});

export { replayCounter, successCounter, latencyHistogram, auditLogCounter };