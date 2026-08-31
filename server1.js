import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomUUID } from 'crypto';
import fs from 'fs';
import { createReadStream } from 'fs';
import OpenAI from 'openai';
import 'dotenv/config'; 
dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.static(join(__dirname, 'public')));

const TMP_DIR = join(__dirname, 'tmp');
if (!fs.existsSync(TMP_DIR)) fs.mkdirSync(TMP_DIR, { recursive: true });

async function generateFromText(text, res) {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      {
        role: 'system',
        content: `Expert contenu viral. Génère UNIQUEMENT un JSON valide :
{
  "twitter_thread": ["tweet1", "tweet2"...],
  "linkedin_post": "string",
  "shorts_script": "string"
}`
      },
      { role: 'user', content: text }
    ],
    response_format: { type: 'json_object' }
  });

  const result = JSON.parse(completion.choices[0].message.content);
  result.transcript = text;
  res.json(result);
}

app.post('/from-text', async (req, res) => {
  const text = req.body?.text?.trim();
  if (!text || text.length < 10) {
    return res.status(400).json({ error: 'Texte trop court (min 10 caractères)' });
  }
  await generateFromText(text, res);
});

app.post('/from-audio', async (req, res) => {
  const { filename, data } = req.body;
  if (!data) return res.status(400).json({ error: 'Aucun fichier reçu' });

  const uid = randomUUID().slice(0, 8);
  const ext = filename?.split('.').pop() || 'mp3';
  const audioPath = join(TMP_DIR, `${uid}.${ext}`);

  try {
    fs.writeFileSync(audioPath, Buffer.from(data, 'base64'));

    const transcription = await openai.audio.transcriptions.create({
      file: createReadStream(audioPath),
      model: 'whisper-1',
    });

    fs.unlinkSync(audioPath);
    await generateFromText(transcription.text, res);
  } catch (err) {
    if (fs.existsSync(audioPath)) fs.unlinkSync(audioPath);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Local server: http://localhost:${PORT}`);
});