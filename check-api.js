import axios from 'axios';

async function check() {
  try {
    const res = await axios.get('https://api.hedra.com/v3/openapi.json');
    console.log('--- ENDPOINTS HEDRA V3 DISPONIBLES ---');
    console.log(Object.keys(res.data.paths));
  } catch (err) {
    console.error('Erreur d\'accès au schéma API :', err.message);
  }
}

check();