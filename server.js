import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createHash } from 'crypto';
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
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID; // prix récurrent créé dans le dashboard
const DOMAIN = process.env.DOMAIN || `http://localhost:${PORT}`;

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const stripe = Stripe(STRIPE_SECRET);

const DB_PATH = process.env.DB_PATH || join(__dirname, 'database.sqlite');
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT UNIQUE NOT NULL,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
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
const updateUserStatusStmt = db.prepare(
  'UPDATE users SET status = ?, stripe_customer_id = ?, stripe_subscription_id = ? WHERE fingerprint = ?'
);
const setStatusByCustomerStmt = db.prepare('UPDATE users SET status = ? WHERE stripe_customer_id = ?');
const insertPaymentStmt = db.prepare(
  'INSERT OR IGNORE INTO payments (stripe_session_id, stripe_customer_id, fingerprint, amount, status) VALUES (?, ?, ?, ?, ?)'
);

function getFingerprint(req) {
  const clientId = req.headers['x-client-id'];
  if (clientId && /^[\w-]{8,64}$/.test(clientId)) return clientId;
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
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
  if (user.status === 'active') return { allowed: true, remaining: null, status: 'active' };
  const used = getUsage(fingerprint);
  const remaining = Math.max(0, FREE_LIMIT - used);
  return { allowed: remaining > 0, remaining, status: 'free', used };
}

/* ------------------------------------------------------------------ */
/* Rate limiting simple : protège la facture OpenAI                    */
/* ------------------------------------------------------------------ */
const hits = new Map();
function rateLimit(fingerprint, max = 20, windowMs = 3600000) {
  const now = Date.now();
  const rec = hits.get(fingerprint) || { n: 0, start: now };
  if (now - rec.start > windowMs) { rec.n = 0; rec.start = now; }
  rec.n++;
  hits.set(fingerprint, rec);
  return rec.n <= max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of hits) if (now - v.start > 7200000) hits.delete(k);
}, 3600000).unref();

/* ------------------------------------------------------------------ */
/* Contrôle qualité des tweets                                         */
/* ------------------------------------------------------------------ */
const BANNED = /(imaginez|plongeons|voici pourquoi|game.?changer|qu'en pensez-vous|la plupart des gens pensent|dans cet article|il est important de)/i;

// Un tweet doit s'ancrer dans du concret : un chiffre, une citation, ou un nom propre.
function aAncrageConcret(t) {
  if (/\d/.test(t)) return true;
  if (/["«»]/.test(t)) return true;
  const sansDebutsDePhrase = t.replace(/(^|[.!?]\s+|\n)[A-ZÀ-Ý]/g, '$1x');
  return /[A-ZÀ-Ý]/.test(sansDebutsDePhrase);
}

function diagnostiquerTweet(t) {
  if (!t || typeof t !== 'string') return 'vide';
  if (t.length > 275) return 'trop long';
  if (BANNED.test(t)) return 'formule interdite';
  if (!aAncrageConcret(t)) return 'trop abstrait, aucun fait';
  return null;
}

function parseJSONRobuste(raw) {
  if (!raw) return null;
  const clean = raw.replace(/```json/gi, '').replace(/```/g, '').trim();
  try { return JSON.parse(clean); } catch (_) {}
  const a = clean.indexOf('{'), b = clean.lastIndexOf('}');
  if (a === -1 || b <= a) return null;
  const extrait = clean.slice(a, b + 1);
  try { return JSON.parse(extrait); } catch (_) {}
  try { return JSON.parse(extrait.replace(/,\s*([}\]])/g, '$1')); } catch (e) {
    console.error('[JSON] échec parsing:', e.message);
    return null;
  }
}

function lireCompletion(completion, label) {
  const choice = completion.choices[0];
  if (choice.finish_reason === 'length') {
    throw new Error(`${label}: réponse tronquée (max_tokens)`);
  }
  const parsed = parseJSONRobuste(choice.message.content);
  if (!parsed) {
    console.error(`[${label}] brut:`, choice.message.content?.slice(0, 800));
    throw new Error(`${label}: JSON invalide`);
  }
  return parsed;
}

/* ------------------------------------------------------------------ */
/* Prompts                                                             */
/* ------------------------------------------------------------------ */
const PROMPT_ANALYSE = `Tu analyses une transcription orale brute. Tu extrais des faits, pas des leçons.

Réponds UNIQUEMENT en JSON :
{
  "these": "l'affirmation principale en une phrase, ou null si la source n'a aucune idée exploitable",
  "scene": "les faits concrets dans l'ordre chronologique : qui fait quoi, où, quand, combien. Uniquement ce qui est dit dans la source. Aucune interprétation, aucune morale. Tous les noms, chiffres, lieux, dates et citations présents dans la source doivent apparaître ici.",
  "arguments": ["2 à 4 points qui soutiennent la thèse"],
  "moment_fort": "la phrase ou l'anecdote la plus marquante, citée telle quelle",
  "public": "à qui ça parle",
  "registre": "familier | pro | technique | humoristique",
  "verification": [
    { "affirmation": "une affirmation factuelle de la source", "statut": "verifiable | invérifiable | probablement_faux", "note": "pourquoi, en une phrase" }
  ]
}

Pour "verification" : ne signale que ce qui mérite un doute (attribution contestée, chiffre invraisemblable, anecdote connue pour être apocryphe). Tableau vide si tout est solide.`;
const PROMPT_GENERATION = `Tu écris pour un créateur de contenu. Tu construis un contenu autonome, tu ne résumes jamais la vidéo.

RÈGLES ABSOLUES
- Zéro hashtag. Zéro emoji.
- Formules interdites : "plongeons", "voici pourquoi", "game-changer", "imaginez", "et si", "la plupart des gens pensent", "dans cet article", "il est important de".
- Chaque bloc doit contenir des faits concrets : qui fait quoi, où, quand, combien.
- Phrases courtes et percutantes. Une idée par phrase.
- Pas de conclusion qui résume ce qui précède.

twitter_thread (4 à 5 tweets, 240 caractères max chacun)
STRUCTURE SÉQUENTIELLE STRICTE :
- Tweet 1 (Hook) : Une affirmation paradoxale sur la FIN ou l'impact de l'histoire. Interdiction de raconter les faits ou de présenter les personnages ici.
- Tweet 2 (Début) : L'action initiale uniquement (qui fait quoi au départ).
- Tweet 3 (Conflit) : L'élément perturbateur ou l'accusation.
- Tweet 4 (Climax) : La décision ou la condamnation.
- Tweet 5 (Prise de position) : La leçon finale tranchée.

RÈGLE ANTIDOUBLON X : Chaque tweet traite une étape différente. Un mot-clé, un lieu ou une action utilisé dans un tweet ne doit PLUS JAMAIS réapparaître dans les suivants.

linkedin_post (150 à 250 mots)
- Ouverture : une situation concrète en 1 à 2 lignes, sans préambule.
- Corps : le raisonnement, sauts de ligne fréquents.
- Fin : UNE seule question ouverte, ancrée dans le métier du lecteur. Jamais sur "votre carrière" ou "le monde professionnel d'aujourd'hui".

shorts_script (voix off fluide à lire à voix haute, ~90-100 mots au total)
- AUCUN TIMECODE, AUCUN CROCHET, AUCUN LIBELLÉ. Le texte doit être 100% propre et prêt à être lu au micro.
- Organise le script en 3 paragraphes distincts séparés par un saut de ligne :
  1. L'accroche (3 secondes / 10 mots max, percutante)
  2. Le développement (20 secondes / ~50 mots, avec l'exemple concret)
  3. La chute (15 secondes / ~30 mots, contre-pied ou conclusion forte)

SORTIE JSON : {"twitter_thread": [...], "linkedin_post": "...", "shorts_script": "..."}`;

/* ------------------------------------------------------------------ */
/* Génération                                                          */
/* ------------------------------------------------------------------ */
async function genererDepuisTexte(text) {
  const source = text.length > 12000 ? text.slice(0, 12000) : text;
  console.log(`[GEN] début, ${source.length} caractères`);

  // Étape 1 — analyse (mini suffit : c'est de l'extraction)
  const analysis = lireCompletion(await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: PROMPT_ANALYSE },
      { role: 'user', content: source }
    ],
    response_format: { type: 'json_object' },
    temperature: 0.2,
    max_tokens: 1200
  }), 'analyse');

  console.log('[GEN] analyse:', JSON.stringify({ these: analysis.these, scene: analysis.scene }).slice(0, 400));

  if (!analysis.these) {
    const e = new Error('CONTENU_INSUFFISANT');
    e.code = 'CONTENU_INSUFFISANT';
    throw e;
  }

  // Étape 2 — écriture (gpt-4o : c'est ce que l'utilisateur voit)
  const briefUser = `Analyse :
Thèse : ${analysis.these}
Scène (faits bruts) : ${analysis.scene || '-'}
Arguments : ${(analysis.arguments || []).join(' | ')}
Moment fort : ${analysis.moment_fort || '-'}
Public : ${analysis.public}
Registre : ${analysis.registre}

Transcription source — utilise-la pour les détails concrets (noms, chiffres, lieux, citations). Ne la résume pas :
"""
${source.slice(0, 6000)}
"""

Génère les 3 formats.`;

  const result = lireCompletion(await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: PROMPT_GENERATION },
      { role: 'user', content: briefUser }
    ],
    response_format: { type: 'json_object' },
    temperature: 0.8,
    max_tokens: 2000
  }), 'generation');

  // Contrôle qualité : on RÉÉCRIT les tweets faibles, on ne les supprime pas
  if (Array.isArray(result.twitter_thread)) {
    const faibles = result.twitter_thread
      .map((t, i) => ({ i, t, raison: diagnostiquerTweet(t) }))
      .filter(x => x.raison);

    if (faibles.length) {
      console.log('[QC] à réécrire:', faibles.map(f => `#${f.i} (${f.raison})`).join(', '));
      try {
        const fix = lireCompletion(await openai.chat.completions.create({
          model: 'gpt-4o',
          messages: [
            { role: 'system', content: PROMPT_GENERATION },
            { role: 'user', content: briefUser },
            { role: 'assistant', content: JSON.stringify({ twitter_thread: result.twitter_thread }) },
            {
              role: 'user',
              content: `Ces tweets sont à réécrire :\n${faibles.map(f => `Index ${f.i} — problème : ${f.raison}\n"${f.t}"`).join('\n\n')}\n\nRéécris-les en gardant leur place dans le fil et en y mettant un fait précis de la transcription (nom, chiffre, lieu ou citation). Réponds en JSON : {"corrections": {"index": "nouveau texte"}}`
            }
          ],
          response_format: { type: 'json_object' },
          temperature: 0.9,
          max_tokens: 900
        }), 'correction');

        for (const [idx, txt] of Object.entries(fix.corrections || {})) {
          const i = parseInt(idx, 10);
          if (Number.isInteger(i) && result.twitter_thread[i] && typeof txt === 'string' && !diagnostiquerTweet(txt)) {
            result.twitter_thread[i] = txt;
          }
        }
      } catch (e) {
        console.warn('[QC] correction échouée:', e.message);
      }
    }
  }

  result.transcript = text;
  result.verification = (analysis.verification || []).filter(v => v && v.statut && v.statut !== 'verifiable');
  return result;
}

/* ------------------------------------------------------------------ */
/* App                                                                 */
/* ------------------------------------------------------------------ */
const app = express();
app.set('trust proxy', 1);

// Webhook AVANT express.json (il a besoin du body brut)
app.post('/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) return res.status(500).send('Webhook secret non configuré');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  const o = event.data.object;
  switch (event.type) {
    case 'checkout.session.completed':
      if (o.client_reference_id) {
        insertPaymentStmt.run(o.id, o.customer, o.client_reference_id, o.amount_total, 'completed');
        updateUserStatusStmt.run('active', o.customer, o.subscription || null, o.client_reference_id);
        resetUsageStmt.run(o.client_reference_id);
      }
      break;
    case 'customer.subscription.deleted':
    case 'customer.subscription.paused':
      setStatusByCustomerStmt.run('free', o.customer);
      break;
    case 'invoice.payment_failed':
      setStatusByCustomerStmt.run('free', o.customer);
      break;
  }
  res.json({ received: true });
});

// CORS : ton domaine uniquement (une API ouverte, c'est ta facture OpenAI offerte)
app.use(cors({ origin: process.env.CORS_ORIGIN || DOMAIN }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(join(__dirname, 'public')));

const upload = multer({
  dest: join(__dirname, 'tmp'),
  limits: { fileSize: 200 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^(video|audio)\//.test(file.mimetype)) cb(null, true);
    else cb(new Error('FORMAT_NON_SUPPORTE'));
  }
});

app.get('/api/status', (req, res) => {
  const quota = canUse(getFingerprint(req));
  res.json({ status: quota.status, remaining: quota.remaining, limit: FREE_LIMIT });
});

app.post('/api/create-checkout-session', async (req, res) => {
  if (!STRIPE_SECRET || !STRIPE_PRICE_ID) {
    return res.status(500).json({ error: 'Paiement non configuré' });
  }
  const fingerprint = getFingerprint(req);
  getOrCreateUser(fingerprint);
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${DOMAIN}/app.html?success=1`,
      cancel_url: `${DOMAIN}/app.html?canceled=1`,
      client_reference_id: fingerprint
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[STRIPE]', err.message);
    res.status(500).json({ error: 'Impossible de créer la session de paiement' });
  }
});

function envoyerErreur(res, err) {
  if (res.headersSent) return;
  if (err.code === 'CONTENU_INSUFFISANT') {
    return res.status(422).json({
      error: 'CONTENU_INSUFFISANT',
      message: "Cette vidéo ne développe pas assez d'idée pour en tirer du texte. Essaie avec une vidéo où tu racontes quelque chose."
    });
  }
  console.error('[ERREUR]', err.message);
  res.status(500).json({ error: 'GENERATION_ECHOUEE', message: 'La génération a échoué. Réessaie.' });
}

app.post('/from-media', (req, res) => {
  upload.single('file')(req, res, async (uploadErr) => {
    if (uploadErr) {
      const msg = uploadErr.code === 'LIMIT_FILE_SIZE'
        ? 'Fichier trop lourd (200 Mo maximum).'
        : 'Format non supporté. Envoie une vidéo ou un fichier audio.';
      return res.status(400).json({ error: 'UPLOAD', message: msg });
    }

    const fingerprint = getFingerprint(req);
    const src = req.file?.path;
    const audioPath = src ? src + '.mp3' : null;
    const nettoyer = () => [src, audioPath].forEach(p => { if (p && fs.existsSync(p)) fs.unlinkSync(p); });

    try {
      if (!req.file) return res.status(400).json({ error: 'Aucun fichier reçu' });
      if (!rateLimit(fingerprint)) {
        return res.status(429).json({ error: 'TROP_DE_REQUETES', message: 'Trop de générations. Réessaie dans une heure.' });
      }
      const quota = canUse(fingerprint);
      if (!quota.allowed) {
        return res.status(403).json({ error: 'QUOTA_EXCEEDED', message: 'Limite atteinte.' });
      }

      console.log(`[MEDIA] extraction audio : ${req.file.originalname}`);
      await execFileP('ffmpeg', ['-i', src, '-vn', '-ac', '1', '-ar', '16000', '-b:a', '48k', '-y', audioPath], {
        timeout: 180000,
        maxBuffer: 10 * 1024 * 1024
      });

      if (fs.statSync(audioPath).size > 24 * 1024 * 1024) {
        return res.status(400).json({ error: 'TROP_LONG', message: 'Vidéo trop longue (environ 40 minutes maximum).' });
      }

      const transcription = await openai.audio.transcriptions.create({
        file: createReadStream(audioPath),
        model: 'whisper-1'
      });

      if (!transcription.text || transcription.text.trim().length < 40) {
        return res.status(422).json({ error: 'AUDIO_VIDE', message: "L'audio ne contient pas assez de parole." });
      }

      const result = await genererDepuisTexte(transcription.text);
      upsertUsageStmt.run(fingerprint);            // on ne débite qu'en cas de succès
      result.remaining = canUse(fingerprint).remaining;
      res.json(result);
    } catch (err) {
      envoyerErreur(res, err);
    } finally {
      nettoyer();
    }
  });
});

app.post('/from-text', async (req, res) => {
  const fingerprint = getFingerprint(req);
  if (!rateLimit(fingerprint)) {
    return res.status(429).json({ error: 'TROP_DE_REQUETES', message: 'Trop de générations. Réessaie dans une heure.' });
  }
  const quota = canUse(fingerprint);
  if (!quota.allowed) return res.status(403).json({ error: 'QUOTA_EXCEEDED', message: 'Limite atteinte.' });

  const text = req.body?.text?.trim();
  if (!text || text.length < 40) {
    return res.status(400).json({ error: 'TEXTE_COURT', message: 'Texte trop court (40 caractères minimum).' });
  }
  try {
    const result = await genererDepuisTexte(text);
    upsertUsageStmt.run(fingerprint);
    result.remaining = canUse(fingerprint).remaining;
    res.json(result);
  } catch (err) {
    envoyerErreur(res, err);
  }
});

app.listen(PORT, () => {
  console.log(`Serveur  : http://localhost:${PORT}`);
  console.log(`Stripe   : ${STRIPE_SECRET ? (STRIPE_PRICE_ID ? 'OK' : 'PRICE_ID manquant') : 'non configuré'}`);
  console.log(`Webhook  : ${STRIPE_WEBHOOK_SECRET ? 'OK' : 'NON CONFIGURÉ — les paiements ne seront pas enregistrés'}`);
});