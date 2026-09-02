import axios from 'axios';
import FormData from 'form-data';
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config();

const HEDRA_API_KEY = process.env.HEDRA_API_KEY;
const BASE_URL = 'https://api.hedra.com/v3';

const headers = {
  'X-API-Key': HEDRA_API_KEY
};

async function uploadFile(filePath) {
  const form = new FormData();
  form.append('file', fs.createReadStream(filePath));

  const response = await axios.post(`${BASE_URL}/files`, form, {
    headers: {
      ...headers,
      ...form.getHeaders()
    }
  });

  return response.data.url || response.data.file_url || response.data.link;
}

async function run() {
  const imagePath = './avatar.jpg';
  const audioPath = './audio.mp3';

  if (!fs.existsSync(imagePath) || !fs.existsSync(audioPath)) {
    console.error('Erreur : vérifie que avatar.jpg et audio.mp3 sont présents.');
    return;
  }

  try {
    console.log('1. Téléversement des fichiers sur /v3/files...');
    const imageUrl = await uploadFile(imagePath);
    const audioUrl = await uploadFile(audioPath);
    console.log(`Image hébergée : ${imageUrl}`);
    console.log(`Audio hébergé : ${audioUrl}`);

    console.log('2. Création du job de génération V3...');
    const response = await axios.post(
      `${BASE_URL}/models/hedra-avatar`,
      {
        input: {
          prompt: 'Un vieil homme chaleureux raconte une histoire',
          aspect_ratio: '9:16',
          resolution: '720p',
          start_image: {
            source: 'url',
            url: imageUrl
          },
          audio: {
            source: 'url',
            url: audioUrl
          }
        }
      },
      {
        headers: {
          ...headers,
          'Content-Type': 'application/json'
        }
      }
    );

    const jobId = response.data.id || response.data.job_id;
    console.log(`Job V3 lancé avec succès ! ID : ${jobId}`);

    // Polling du statut
    let isFinished = false;
    while (!isFinished) {
      await new Promise((resolve) => setTimeout(resolve, 4000));

      const statusRes = await axios.get(`${BASE_URL}/jobs/${jobId}/status`, { headers });
      const statusData = statusRes.data;

      console.log(`Statut : ${statusData.status}`);

      if (statusData.status === 'completed' || statusData.status === 'succeeded') {
        isFinished = true;
        const videoUrl = statusData.output?.video || statusData.output?.url || statusData.url;
        console.log('Vidéo générée avec succès !');
        console.log('Lien de la vidéo :', videoUrl);
      } else if (statusData.status === 'failed') {
        throw new Error(`Échec Hedra : ${JSON.stringify(statusData.error || statusData)}`);
      }
    }
  } catch (err) {
    console.error('Détails de l\'erreur API V3 :');
    console.log(JSON.stringify(err.response?.data || err.message, null, 2));
  }
}

run();