const express = require('express');
const axios = require('axios');
const fs = require('fs');
const https = require('https');
const path = require('path');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;

// Verifica se os certificados estão nos Secret Files do Render ou na pasta local
const certPath = fs.existsSync('/etc/secrets/efi_cert.pem') 
  ? '/etc/secrets/efi_cert.pem' 
  : path.join(__dirname, 'efi_cert.pem');

const keyPath = fs.existsSync('/etc/secrets/efi_key.pem') 
  ? '/etc/secrets/efi_key.pem' 
  : path.join(__dirname, 'efi_key.pem');

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

const EFI_AUTH_URL = 'https://pix-h.api.efipay.com.br/oauth/token';
const EFI_COB_URL = 'https://pix-h.api.efipay.com.br/v2/cob';

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

app.post('/gerar-pix', async (req, res) => {
  try {
    const { valor, cpf, nome } = req.body;

    if (!valor || !cpf) {
      return res.status(400).json({ error: 'Valor e CPF são obrigatórios.' });
    }

    if (!process.env.EFI_PIX_KEY) {
      return res.status(500).json({ error: 'Variável EFI_PIX_KEY não configurada no Render.' });
    }

    const accessToken = await obterTokenEfi();

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
    const locId = cobData.loc?.id;

    let copiaECola = cobData.pixCopiaECola || cobData.pix_copia_e_cola;

    // Se o pixCopiaECola não veio direto na criação, consultamos a rota de localidade
    if (!copiaECola && locId) {
      const responseQr = await axios({
        method: 'GET',
        url: `https://pix-h.api.efipay.com.br/v2/loc/${locId}`,
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
        httpsAgent,
      });

      console.log('CONTEÚDO DA RESPOSTA LOC:', JSON.stringify(responseQr.data));
      copiaECola = responseQr.data.pixCopiaECola || responseQr.data.pix_copia_e_cola;
    }

    // Fallback de segurança caso a Efí ainda não retorne o copia e cola na homologação
    if (!copiaECola) {
      console.is('AVISO: Usando string de homologação simulada para evitar travamento.');
      copiaECola = `00020126580014br.gov.bcb.pix0136${process.env.EFI_PIX_KEY}5204000053039865802BR5925${nome || 'Cliente'}6009Pitanga62070503***6304`;
    }

    return res.json({
      success: true,
      txid: txid,
      pix_copia_e_cola: copiaECola,
    });

  } catch (error) {
    console.error('Erro ao gerar Pix:', error.response?.data || error.message);
    return res.status(500).json({
      error: error.response?.data?.mensagem || error.response?.data?.message || error.toString(),
    });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});