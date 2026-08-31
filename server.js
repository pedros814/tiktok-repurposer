import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomUUID, createHash } from 'crypto';
import fs from 'fs';
import { createReadStream } from 'fs';
import OpenAI from 'openai';
import Database from 'better-sqlite3';
import Stripe from 'stripe';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = process.env.PORT || 3000;
const FREE_LIMIT = parseInt(process.env.FREE_LIMIT || '3');
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const DOMAIN = process.env.DOMAIN || `http://localhost:${PORT}`;

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const stripe = Stripe(STRIPE_SECRET);

const DB_PATH = join(__dirname, 'database.sqlite');
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT UNIQUE NOT NULL,
    stripe_customer_id TEXT,
    status TEXT DEFAULT 'free',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    count INTEGER DEFAULT 0,
    last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fingerprint)
  );
  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stripe_session_id TEXT UNIQUE,
    stripe_customer_id TEXT,
    fingerprint TEXT,
    amount INTEGER,
    status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const getUserStmt = db.prepare('SELECT * FROM users WHERE fingerprint = ?');
const insertUserStmt = db.prepare('INSERT OR IGNORE INTO users (fingerprint) VALUES (?)');
const getUsageStmt = db.prepare('SELECT * FROM usage WHERE fingerprint = ?');
const upsertUsageStmt = db.prepare(`
  INSERT INTO usage (fingerprint, count, last_used)
  VALUES (?, 1, CURRENT_TIMESTAMP)
  ON CONFLICT(fingerprint) DO UPDATE SET
    count = count + 1,
    last_used = CURRENT_TIMESTAMP
`);
const resetUsageStmt = db.prepare('UPDATE usage SET count = 0 WHERE fingerprint = ?');
const updateUserStatusStmt = db.prepare('UPDATE users SET status = ?, stripe_customer_id = ? WHERE fingerprint = ?');
const insertPaymentStmt = db.prepare('INSERT INTO payments (stripe_session_id, stripe_customer_id, fingerprint, amount, status) VALUES (?, ?, ?, ?, ?)');

function getFingerprint(req) {
  const clientId = req.headers['x-client-id'];
  if (clientId && clientId.length >= 8) return clientId;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';
  return createHash('sha256').update(ip + ua).digest('hex').slice(0, 32);
}

function getOrCreateUser(fingerprint) {
  let user = getUserStmt.get(fingerprint);
  if (!user) {
    insertUserStmt.run(fingerprint);
    user = getUserStmt.get(fingerprint);
  }
  return user;
}

function getUsage(fingerprint) {
  const row = getUsageStmt.get(fingerprint);
  return row ? row.count : 0;
}

function canUse(fingerprint) {
  const user = getOrCreateUser(fingerprint);
  if (user.status === 'active') return { allowed: true, remaining: 999, status: 'active' };
  const used = getUsage(fingerprint);
  const remaining = Math.max(0, FREE_LIMIT - used);
  return { allowed: remaining > 0, remaining, status: 'free', used };
}

const app = express();

app.post('/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  if (STRIPE_WEBHOOK_SECRET) {
    const sig = req.headers['stripe-signature'];
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
  } else {
    try {
      event = JSON.parse(req.body);
    } catch (e) {
      return res.status(400).send('Invalid JSON');
    }
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const fingerprint = session.client_reference_id;
    const customerId = session.customer;
    const amount = session.amount_total;
    if (fingerprint) {
      insertPaymentStmt.run(session.id, customerId, fingerprint, amount, 'completed');
      updateUserStatusStmt.run('active', customerId, fingerprint);
      resetUsageStmt.run(fingerprint);
    }
  }
  res.json({ received: true });
});

app.post('/api/simulate-payment', express.json(), (req, res) => {
  const fingerprint = req.headers['x-client-id'] || req.body?.fingerprint;
  if (!fingerprint) return res.status(400).json({ error: 'Missing fingerprint' });
  const fakeSessionId = 'sim_' + randomUUID().slice(0, 8);
  insertPaymentStmt.run(fakeSessionId, 'cus_sim', fingerprint, 990, 'completed');
  updateUserStatusStmt.run('active', 'cus_sim', fingerprint);
  resetUsageStmt.run(fingerprint);
  res.json({ success: true, message: 'Compte active en mode test' });
});

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static(join(__dirname, 'public')));

app.get('/api/status', (req, res) => {
  const fingerprint = getFingerprint(req);
  const quota = canUse(fingerprint);
  res.json({
    fingerprint,
    status: quota.status,
    remaining: quota.remaining,
    used: quota.used || (FREE_LIMIT - quota.remaining),
    limit: FREE_LIMIT
  });
});

app.post('/api/create-checkout-session', async (req, res) => {
  if (!STRIPE_SECRET) {
    return res.status(500).json({ error: 'Stripe non configure' });
  }
  const fingerprint = getFingerprint(req);
  getOrCreateUser(fingerprint);
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: { name: 'TikTok Repurposer Pro' },
          unit_amount: 990,
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${DOMAIN}/app.html?success=1`,
      cancel_url: `${DOMAIN}/app.html?canceled=1`,
      client_reference_id: fingerprint,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function generateFromText(text, res) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      {
        role: 'system',
        content: `Expert contenu viral. Genere UNIQUEMENT un JSON valide :
{
  "twitter_thread": ["tweet1", "tweet2", "tweet3"],
  "linkedin_post": "string",
  "shorts_script": "string"
}`
      },
      { role: 'user', content: text }
    ],
    response_format: { type: 'json_object' }
  });
  const raw = completion.choices[0].message.content;
  const clean = raw.replace(/```json|```/g, '').trim();
  const result = JSON.parse(clean);
  result.transcript = text;
  res.json(result);
}

app.post('/from-text', async (req, res) => {
  const fingerprint = getFingerprint(req);
  const quota = canUse(fingerprint);
  if (!quota.allowed) {
    return res.status(403).json({ error: 'QUOTA_EXCEEDED', message: 'Limite atteinte. Abonne-toi pour continuer.' });
  }
  const text = req.body?.text?.trim();
  if (!text || text.length < 10) {
    return res.status(400).json({ error: 'Texte trop court (min 10 caracteres)' });
  }
  try {
    await generateFromText(text, res);
    upsertUsageStmt.run(fingerprint);
  } catch (err) {
    console.error('API Error:', err.message);
    res.status(500).json({ error: 'Erreur API : ' + err.message });
  }
});

app.post('/from-audio', async (req, res) => {
  const fingerprint = getFingerprint(req);
  const quota = canUse(fingerprint);
  if (!quota.allowed) {
    return res.status(403).json({ error: 'QUOTA_EXCEEDED', message: 'Limite atteinte. Abonne-toi pour continuer.' });
  }
  const { filename, data } = req.body;
  if (!data) return res.status(400).json({ error: 'Aucun fichier recu' });
  const uid = randomUUID().slice(0, 8);
  const ext = filename?.split('.').pop() || 'mp3';
  const audioPath = join(__dirname, 'tmp', `${uid}.${ext}`);
  try {
    if (!fs.existsSync(join(__dirname, 'tmp'))) fs.mkdirSync(join(__dirname, 'tmp'));
    fs.writeFileSync(audioPath, Buffer.from(data, 'base64'));
    const transcription = await openai.audio.transcriptions.create({
      file: createReadStream(audioPath),
      model: 'whisper-1',
    });
    fs.unlinkSync(audioPath);
    await generateFromText(transcription.text, res);
    upsertUsageStmt.run(fingerprint);
  } catch (err) {
    if (fs.existsSync(audioPath)) fs.unlinkSync(audioPath);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/stats', (req, res) => {
  const users = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const active = db.prepare("SELECT COUNT(*) as count FROM users WHERE status = 'active'").get();
  const payments = db.prepare("SELECT SUM(amount) as total FROM payments WHERE status = 'completed'").get();
  res.json({ users: users.count, active: active.count, revenue: payments.total || 0 });
});

app.listen(PORT, () => {
  console.log(`Server: http://localhost:${PORT}`);
  console.log(`DB: ${DB_PATH}`);
  console.log(`Stripe: ${STRIPE_SECRET ? 'OK' : 'NON CONFIGURE'}`);
});