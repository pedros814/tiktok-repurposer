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
const PRICE_ID = process.env.STRIPE_PRICE_ID;
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const DOMAIN = process.env.DOMAIN || `http://localhost:${PORT}`;
const NODE_ENV = process.env.NODE_ENV || 'development';

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

// ========== STRIPE WEBHOOK (verrouille) ==========
app.post('/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) {
    return res.status(500).send('Webhook secret not configured');
  }
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
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

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(join(__dirname, 'public')));

// ========== API ROUTES ==========

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

// ========== CORE: PROMPT EN 2 ETAPES ==========

async function generateFromText(text, res) {
  // --- ETAPE 1: ANALYSE (gpt-4o-mini, rapide) ---
  const analysisCompletion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      {
        role: 'system',
        content: `Tu analyses une transcription orale brute. Extrais la substance.\n\nReponds UNIQUEMENT en JSON valide :\n{\n  "these": "l'affirmation principale en une phrase, telle qu'un lecteur la retiendrait",\n  "arguments": ["les 2-4 points qui la soutiennent"],\n  "moment_fort": "la phrase ou l'anecdote la plus marquante, citee telle quelle",\n  "public": "a qui ca parle",\n  "registre": "familier | pro | technique | humoristique"\n}\n\nSi la transcription n'a pas d'idee exploitable (unboxing muet, musique sans parole, etc.), mets these a null.`
      },
      { role: 'user', content: text }
    ],
    response_format: { type: 'json_object' }
  });

  const analysisRaw = analysisCompletion.choices[0].message.content;
  const analysis = JSON.parse(analysisRaw.replace(/```json|```/g, '').trim());

  if (!analysis.these) {
    return res.status(422).json({
      error: 'CONTENU_INSUFFISANT',
      message: 'Cette video ne contient pas assez de matiere pour en faire un contenu ecrit. Essaye avec une video ou le locuteur developpe une idee, raconte une histoire ou donne des conseils.'
    });
  }

  // --- ETAPE 2: GENERATION (gpt-4o, qualite) ---
  const genCompletion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      {
        role: 'system',
        content: `Tu ecris pour un createur de contenu. Tu pars d'une analyse, pas d'une transcription : n'essaie jamais de resumer la video, construis un contenu autonome.\n\nRÈGLES ABSOLUES\n- Aucun emoji, sauf si le registre est "humoristique" (max 1 par bloc).\n- Aucune de ces formules : "dans cet article", "plongeons", "il est important de", "voici pourquoi", "game-changer", "spoiler".\n- Phrases courtes. Une idee par phrase.\n- Pas de conclusion qui resume ce qui vient d'etre dit.\n\ntwitter_thread (3 a 5 tweets, 280 car. max chacun)\n- Tweet 1 = le hook. Une affirmation qui cree une tension ou contredit une evidence. Jamais une question rhetorique. Jamais "thread".\n- Tweets suivants = un argument chacun, du concret, des exemples.\n- Dernier tweet = une prise de position, pas un resume.\n\nlinkedin_post (150-250 mots)\n- Ouverture : une situation concrete en 1-2 lignes.\n- Corps : le raisonnement, avec des sauts de ligne frequents.\n- Fin : une question ouverte reelle, pas "qu'en pensez-vous ?".\n\nshorts_script (30-45s a l'oral)\n- Format : [0-3s] hook visuel + phrase / [3-25s] developpement / [25-40s] chute.\n- Ecrit pour etre dit a voix haute, pas lu.\n\nReponds uniquement en JSON : {"twitter_thread": [...], "linkedin_post": "...", "shorts_script": "..."}`
      },
      {
        role: 'user',
        content: `Analyse du contenu source :\n\nThese : ${analysis.these}\nArguments : ${analysis.arguments.join(' | ')}\nMoment fort : ${analysis.moment_fort}\nPublic : ${analysis.public}\nRegistre : ${analysis.registre}\n\nGenere les 3 formats.`
      }
    ],
    response_format: { type: 'json_object' },
    temperature: 0.7
  });

  const raw = genCompletion.choices[0].message.content;
  const clean = raw.replace(/```json|```/g, '').trim();
  const result = JSON.parse(clean);
  result.transcript = text;
  result._analysis = analysis; // debug
  res.json(result);
}

app.post('/from-text', async (req, res) => {
  const fingerprint = getFingerprint(req);
  const quota = canUse(fingerprint);
  if (!quota.allowed) {
    return res.status(403).json({ error: 'QUOTA_EXCEEDED', message: 'Limite atteinte. Abonne-toi pour continuer.' });
  }
  const text = req.body?.text?.trim();
  if (!text || text.length < 20) {
    return res.status(400).json({ error: 'Texte trop court (min 20 caracteres)' });
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

  // Verif taille (Whisper limite a ~25Mo)
  const sizeMB = (data.length * 0.75) / 1024 / 1024;
  if (sizeMB > 25) {
    return res.status(413).json({ error: 'Fichier trop lourd (max 25 Mo). Compresse l\'audio ou coupe en morceaux.' });
  }

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

    // Verif longueur transcription
    if (!transcription.text || transcription.text.trim().length < 20) {
      return res.status(422).json({ error: 'TRANSCRIPTION_VIDE', message: 'L\'audio ne contient pas assez de parole. Assure-toi que la video a du son clair.' });
    }

    await generateFromText(transcription.text, res);
    upsertUsageStmt.run(fingerprint);
  } catch (err) {
    if (fs.existsSync(audioPath)) fs.unlinkSync(audioPath);
    console.error('API Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server: http://localhost:${PORT}`);
  console.log(`DB: ${DB_PATH}`);
  console.log(`Stripe: ${STRIPE_SECRET ? 'OK' : 'NON CONFIGURE'}`);
  console.log(`Env: ${NODE_ENV}`);
});