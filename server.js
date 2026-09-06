const express = require('express');
const axios = require('axios');
const fs = require('fs');
const https = require('https');
const path = require('path');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;

// Lista os arquivos na pasta do Render para debug
console.log('=== LISTA DE ARQUIVOS NA PASTA DO RENDER ===');
try {
  const arquivosNaPasta = fs.readdirSync(__dirname);
  console.log(arquivosNaPasta);
} catch (e) {
  console.log('Erro ao ler diretório:', e.message);
}
console.log('============================================');

// Verifica se os certificados estão nos Secret Files do Render ou na pasta local
const certPath = fs.existsSync('/etc/secrets/efi_cert.pem') 
  ? '/etc/secrets/efi_cert.pem' 
  : path.join(__dirname, 'efi_cert.pem');

const keyPath = fs.existsSync('/etc/secrets/efi_key.pem') 
  ? '/etc/secrets/efi_key.pem' 
  : path.join(__dirname, 'efi_key.pem');

console.log('Caminho final do Certificado:', certPath);
console.log('Caminho final da Chave:', keyPath);

// Carrega os certificados com segurança
let httpsAgent;
try {
  httpsAgent = new https.Agent({
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
    rejectUnauthorized: false,
  });
  console.log('>>> Certificados carregados com sucesso! <<<');
} catch (err) {
  console.error('>>> ERRO: Falha ao carregar os certificados (.pem):', err.message);
}

// URLs oficiais de Homologação da Efí (Sandbox)
const EFI_AUTH_URL = 'https://pix-h.api.efipay.com.br/oauth/token';
const EFI_COB_URL = 'https://pix-h.api.efipay.com.br/v2/cob';

// Função para obter o Token de Acesso da Efí via mTLS
async function obterTokenEfi() {
  if (!httpsAgent) {
    throw new Error('Agente HTTPS não inicializado devido à falta de certificados.');
  }

  const credentials = Buffer.from(
    `${process.env.EFI_CLIENT_ID}:${process.env.EFI_CLIENT_SECRET}`
  ).toString('base64');

  const response = await axios({
    method: 'POST',
    url: EFI_AUTH_URL,
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/json',
    },
    data: { grant_type: 'client_credentials' },
    httpsAgent,
  });

  return response.data.access_token;
}

// Rota chamada pelo aplicativo Flutter
app.post('/gerar-pix', async (req, res) => {
  try {
    const { valor, cpf, nome } = req.body;

    if (!valor || !cpf) {
      return res.status(400).json({ error: 'Valor e CPF são obrigatórios.' });
    }

    if (!process.env.EFI_PIX_KEY) {
      return res.status(500).json({ error: 'Variável EFI_PIX_KEY não configurada no Render.' });
    }

    // 1. Pega o token OAuth da Efí
    const accessToken = await obterTokenEfi();

    // 2. Monta o payload estritamente com os campos obrigatórios da Efí
    const payloadCob = {
      calendario: { 
        expiracao: 3600 
      },
      valor: { 
        original: Number(valor).toFixed(2) 
      },
      chave: process.env.EFI_PIX_KEY,
      devedor: {
        cpf: cpf.replace(/\D/g, ''),
        nome: nome || 'Cliente Ache Obra',
      }
    };

    // 3. Cria a cobrança Pix na Efí
    const responseCob = await axios({
      method: 'POST',
      url: EFI_COB_URL,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      data: payloadCob,
      httpsAgent,
    });

    const cobData = responseCob.data;
    const txid = cobData.txid;

    // 4. Busca o QR Code (pixCopiaECola) gerado para essa cobrança
    const responseQr = await axios({
      method: 'GET',
      url: `https://pix-h.api.efipay.com.br/v2/loc/${cobData.loc.id}`,
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
      httpsAgent,
    });

    // 5. Retorna os dados para o aplicativo Flutter
    return res.json({
      success: true,
      txid: txid,
      pix_copia_e_cola: responseQr.data.pixCopiaECola,
    });

  } catch (error) {
    console.error('Erro ao gerar Pix:', error.response?.data || error.message);
    return res.status(500).json({
      error: error.response?.data?.mensagem || error.response?.data?.message || error.toString(),
    });
  }
});

// Inicializa o servidor na porta do Render
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});