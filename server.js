import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomUUID, createHash } from 'crypto';
import fs from 'fs';
import { createReadStream } from 'fs';
import { execFile } from 'child_process';
import { promisify } from 'util';
import OpenAI from 'openai';
import Database from 'better-sqlite3';
import Stripe from 'stripe';
import multer from 'multer';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const execFileP = promisify(execFile);

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

const BANNED = /\b(imaginez|plongeons|game-?changer|voici pourquoi|qu'en pensez-vous|et si|la plupart des gens pensent|non, ce n'est pas une blague)\b/i;

function tweetFaible(t) {
  if (!t || t.length > 275) return true;
  if (BANNED.test(t)) return true;
  return !/[A-ZÀ-Ý][a-zà-ÿ]{2,}/.test(t.slice(1)) && !/\d/.test(t) && !/["«]/.test(t);
}

function filtrerThread(thread) {
  return thread.filter((t, i) => {
    const faible = tweetFaible(t);
    if (faible) console.log(`[POST-PROC] Tweet ${i} rejete : "${t.substring(0, 60)}..."`);
    return !faible;
  });
}

function parseJSONRobuste(raw) {
  if (!raw) return null;
  let clean = raw.replace(/```json/g, '').replace(/```/g, '').trim();
  try {
    return JSON.parse(clean);
  } catch (e) {
    const firstBrace = clean.indexOf('{');
    const lastBrace = clean.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      const extracted = clean.substring(firstBrace, lastBrace + 1);
      try {
        return JSON.parse(extracted);
      } catch (e2) {
        const fixed = extracted.replace(/,\s*([}\]])/g, '$1');
        try {
          return JSON.parse(fixed);
        } catch (e3) {
          console.error('[JSON] Echec parsing:', e3.message);
          return null;
        }
      }
    }
    return null;
  }
}

const app = express();

// Multer config
const upload = multer({
  dest: join(__dirname, 'tmp'),
  limits: { fileSize: 200 * 1024 * 1024 }
});

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
          product_data: { name: 'Ricochet Pro' },
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

// ========== CORE: GENERATION ==========

async function generateFromText(text, res) {
  console.log(`[GEN] Starting, text length: ${text.length}`);

  let analysis;
  try {
    const analysisCompletion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        {
          role: 'system',
          content: `Tu analyses une transcription orale brute. Extrais la substance.\n\nReponds UNIQUEMENT en JSON valide :\n{\n  "these": "l'affirmation principale en une phrase",\n  "scene": "les faits bruts dans l'ordre : qui fait quoi, ou, quand",\n  "arguments": ["les 2-4 points"],\n  "moment_fort": "la phrase la plus marquante",\n  "public": "a qui ca parle",\n  "registre": "familier | pro | technique | humoristique"\n}\n\nSi pas d'idee exploitable, mets these a null.`
        },
        { role: 'user', content: text }
      ],
      response_format: { type: 'json_object' }
    });

    analysis = parseJSONRobuste(analysisCompletion.choices[0].message.content);
    if (!analysis) throw new Error('Analyse: JSON invalide');
    console.log(`[GEN] Analysis: ${analysis.these ? 'OK' : 'EMPTY'}`);
  } catch (err) {
    console.error('[GEN] Erreur analyse:', err.message);
    return res.status(500).json({ error: 'Erreur analyse du contenu. Reessaie.' });
  }

  if (!analysis.these) {
    return res.status(422).json({
      error: 'CONTENU_INSUFFISANT',
      message: 'Cette video ne contient pas assez de matiere. Essaye avec une video ou le locuteur developpe une idee ou raconte une histoire.'
    });
  }

  let result;
  try {
    const genCompletion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        {
          role: 'system',
          content: `Tu ecris du contenu viral. Tu pars d'une analyse, pas d'une transcription : ne resume jamais, construis.\n\nRÈGLES ABSOLUES\n- ZERO hashtag. ZERO emoji.\n- Formules interdites : "plongeons", "voici pourquoi", "game-changer", "imaginez", "et si", "la plupart des gens pensent".\n- Chaque bloc doit contenir des faits : qui fait quoi, ou, quand.\n- Phrases courtes. Une idee par phrase.\n- Pas de conclusion qui resume.\n\ntwitter_thread (3-5 tweets, 240c max)\n- Tweet 1 = hook. Affirmation qui cree tension. Jamais question rhetorique.\n- Tweets suivants = un fait ou action par tweet, detail precis.\n- Dernier tweet = prise de position tranchee, pas resume.\n\nlinkedin_post (150-250 mots)\n- Ouverture : situation concrete en 1-2 lignes.\n- Corps : raisonnement, sauts de ligne frequents.\n- Fin : question ouverte reelle, ancree dans le metier du lecteur.\n\nshorts_script (oral, ~2,5 mots/sec)\n- [0-3s] hook : 8 mots max.\n- [3-25s] dev : 45-55 mots, exemple concret.\n- [25-40s] chute : 30-40 mots.\n\nSORTIE JSON : {"twitter_thread": [...], "linkedin_post": "...", "shorts_script": "..."}`
        },
        {
          role: 'user',
          content: `These : ${analysis.these}\nScene : ${analysis.scene || '-'}\nArguments : ${(analysis.arguments || []).join(' | ')}\nMoment fort : ${analysis.moment_fort || '-'}\nPublic : ${analysis.public}\nRegistre : ${analysis.registre}\n\nGenere.`
        }
      ],
      response_format: { type: 'json_object' },
      temperature: 0.8
    });

    result = parseJSONRobuste(genCompletion.choices[0].message.content);
    if (!result) throw new Error('Generation: JSON invalide');
    console.log('[GEN] Writing done');
  } catch (err) {
    console.error('[GEN] Erreur generation:', err.message);
    return res.status(500).json({ error: 'Erreur generation du contenu. Reessaie.' });
  }

  if (Array.isArray(result.twitter_thread)) {
    const avant = result.twitter_thread.length;
    result.twitter_thread = filtrerThread(result.twitter_thread);
    const apres = result.twitter_thread.length;
    if (apres < avant) console.log(`[POST-PROC] ${avant - apres} tweet(s) rejete(s)`);
    if (result.twitter_thread.length < 3) {
      return res.status(422).json({
        error: 'QUALITE_INSUFFISANTE',
        message: 'Le contenu genere n\'est pas assez solide. Essaye avec une video plus riche en faits.'
      });
    }
  }

  result.transcript = text;
  console.log('[GEN] Done, sending');
  res.json(result);
}

// ========== FROM-MEDIA : upload MP4/MP3 avec multer + ffmpeg ==========
app.post('/from-media', upload.single('file'), async (req, res) => {
  const fingerprint = getFingerprint(req);
  const quota = canUse(fingerprint);
  if (!quota.allowed) {
    return res.status(403).json({ error: 'QUOTA_EXCEEDED', message: 'Limite atteinte. Abonne-toi pour continuer.' });
  }
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier recu' });

  const src = req.file.path;
  const audioPath = src + '.mp3';

  try {
    console.log(`[MEDIA] Extracting audio from ${req.file.originalname}...`);
    await execFileP('ffmpeg', [
      '-i', src,
      '-vn',
      '-ac', '1',
      '-ar', '16000',
      '-b:a', '48k',
      '-y', audioPath
    ]);

    const { size } = fs.statSync(audioPath);
    if (size > 24 * 1024 * 1024) {
      return res.status(400).json({ error: 'VIDEO_TROP_LONGUE', message: 'Video trop longue (max ~40 min).' });
    }

    console.log('[MEDIA] Transcribing with Whisper...');
    const transcription = await openai.audio.transcriptions.create({
      file: createReadStream(audioPath),
      model: 'whisper-1'
    });

    if (!transcription.text || transcription.text.trim().length < 20) {
      return res.status(422).json({ error: 'TRANSCRIPTION_VIDE', message: 'L\'audio ne contient pas assez de parole.' });
    }

    console.log(`[MEDIA] Transcribed: ${transcription.text.length} chars`);
    await generateFromText(transcription.text, res);
    upsertUsageStmt.run(fingerprint);
  } catch (err) {
    console.error('[MEDIA ERROR]', err.message);
    res.status(500).json({ error: 'Traitement impossible. Verifie que le fichier est lisible.' });
  } finally {
    [src, audioPath].forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });
  }
});

// Legacy endpoints (gardes pour compatibilite)
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
    console.error('[GEN ERROR]', err.message);
    res.status(500).json({ error: 'Erreur generation : ' + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server: http://localhost:${PORT}`);
  console.log(`FFmpeg: ${process.env.FFMPEG_VERSION || 'system'}`);
});