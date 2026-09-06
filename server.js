const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');

const app = express();
app.use(express.json());

// Carrega o certificado e a chave diretamente da pasta do projeto
const httpsAgent = new https.Agent({
  cert: fs.readFileSync('./efi_cert.pem'),
  key: fs.readFileSync('./efi_key.pem'),
  rejectUnauthorized: false
});

app.post('/gerar-pix', async (req, res) => {
  try {
    const { valor, cpf, nome, descricao } = req.body;
    const clientId = process.env.EFI_CLIENT_ID;
    const clientSecret = process.env.EFI_CLIENT_SECRET;
    const auth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    // 1. Obter Token OAuth2 da Efí (Homologação)
    const tokenResponse = await axios.post(
      'https://api-pix-h.gerencianet.com.br/oauth/token',
      { grant_type: 'client_credentials' },
      {
        headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' },
        httpsAgent
      }
    );

    const accessToken = tokenResponse.data.access_token;

    // 2. Criar Cobrança Pix
    const cobResponse = await axios.post(
      'https://api-pix-h.gerencianet.com.br/v2/cob',
      {
        calendario: { expiracao: 3600 },
        devedor: { cpf: cpf?.replace(/\D/g, ''), nome },
        valor: { original: Number(valor).toFixed(2) },
        solicitacaoPagador: descricao || 'Assinatura Ache Obra'
      },
      {
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        httpsAgent
      }
    );

    res.json({
      success: true,
      txid: cobResponse.data.txid,
      pix_copia_e_cola: cobResponse.data.pixCopiaECola,
      status: cobResponse.data.status
    });

  } catch (error) {
    console.error('Erro na Efí:', error.response?.data || error.message);
    res.status(400).json({ error: error.response?.data || error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));