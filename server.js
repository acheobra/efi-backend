const express = require('express');
const axios = require('axios');
const fs = require('fs');
const https = require('https');
const path = require('path');

const app = express();

app.use(express.json());

// ============================================================
// CORS
// ============================================================

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept, Authorization'
  );
  res.header(
    'Access-Control-Allow-Methods',
    'GET, POST, OPTIONS'
  );

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

// ============================================================
// PORTA
// ============================================================

const PORT = process.env.PORT || 10000;

// ============================================================
// CERTIFICADOS
// ============================================================

const certPath = fs.existsSync('/etc/secrets/efi_cert.pem')
  ? '/etc/secrets/efi_cert.pem'
  : path.join(__dirname, 'efi_cert.pem');

const keyPath = fs.existsSync('/etc/secrets/efi_key.pem')
  ? '/etc/secrets/efi_key.pem'
  : path.join(__dirname, 'efi_key.pem');

let httpsAgent = null;

try {
  httpsAgent = new https.Agent({
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),

    // Mantido conforme sua configuração atual.
    // Em produção, o ideal é validar o certificado.
    rejectUnauthorized: false,
  });

  console.log('>>> Certificados carregados com sucesso! <<<');

} catch (err) {

  console.error(
    '>>> ERRO: Falha ao carregar os certificados (.pem):',
    err.message
  );
}

// ============================================================
// URLS DA EFÍ
// ============================================================

// ------------------------------------------------------------
// PIX - HOMOLOGAÇÃO
// ------------------------------------------------------------

const EFI_PIX_AUTH_URL =
  'https://pix-h.api.efipay.com.br/oauth/token';

const EFI_PIX_COB_URL =
  'https://pix-h.api.efipay.com.br/v2/cob';

// ------------------------------------------------------------
// COBRANÇAS - HOMOLOGAÇÃO
// ------------------------------------------------------------

const EFI_COBRANCA_BASE_URL =
  'https://cobrancas-h.api.efipay.com.br';

const EFI_COBRANCA_AUTH_URL =
  `${EFI_COBRANCA_BASE_URL}/v1/authorize`;

const EFI_COBRANCA_API_URL =
  `${EFI_COBRANCA_BASE_URL}/v1`;

// ============================================================
// FUNÇÃO AUXILIAR - CREDENCIAIS
// ============================================================

function obterCredenciais() {

  if (!process.env.EFI_CLIENT_ID) {
    throw new Error(
      'EFI_CLIENT_ID não configurado no Render.'
    );
  }

  if (!process.env.EFI_CLIENT_SECRET) {
    throw new Error(
      'EFI_CLIENT_SECRET não configurado no Render.'
    );
  }

  return Buffer.from(
    `${process.env.EFI_CLIENT_ID}:${process.env.EFI_CLIENT_SECRET}`
  ).toString('base64');
}

// ============================================================
// TOKEN PIX
// ============================================================

async function obterTokenPix() {

  if (!httpsAgent) {
    throw new Error(
      'Agente HTTPS não inicializado.'
    );
  }

  const credentials = obterCredenciais();

  const response = await axios({
    method: 'POST',

    url: EFI_PIX_AUTH_URL,

    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/json',
    },

    data: {
      grant_type: 'client_credentials',
    },

    httpsAgent,

    timeout: 30000,
  });

  return response.data.access_token;
}

// ============================================================
// TOKEN API COBRANÇAS EFÍ
// ============================================================

async function obterTokenCobranca() {

  if (!httpsAgent) {
    throw new Error(
      'Agente HTTPS não inicializado.'
    );
  }

  const credentials = obterCredenciais();

  console.log(
    '>>> Solicitando token da API Cobranças Efí...'
  );

  const response = await axios({
    method: 'POST',

    url: EFI_COBRANCA_AUTH_URL,

    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/json',
    },

    data: {
      grant_type: 'client_credentials',
    },

    httpsAgent,

    timeout: 30000,
  });

  console.log(
    '>>> Token da API Cobranças obtido com sucesso.'
  );

  return response.data.access_token;
}