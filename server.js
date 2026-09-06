const express = require('express');
const axios = require('axios');
const fs = require('fs');
const https = require('https');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;

// Configuração mTLS usando os certificados na raiz do projeto
const httpsAgent = new https.Agent({
  cert: fs.readFileSync('./efi_cert.pem'),
  key: fs.readFileSync('./efi_key.pem'),
  rejectUnauthorized: false,
});

// URLs de Homologação da Efí (Sandbox)
const EFI_AUTH_URL = 'https://api-pix-h.gerencianet.com.br/oauth/token';
const EFI_COB_URL = 'https://api-pix-h.gerencianet.com.br/v2/cob';

// Função para obter o Token de Acesso da Efí via mTLS
async function obterTokenEfi() {
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

// Rota que o seu aplicativo Flutter está chamando
app.post('/gerar-pix', async (req, res) => {
  try {
    const { valor, cpf, nome, descricao } = req.body;

    if (!valor || !cpf) {
      return res.status(400).json({ error: 'Valor e CPF são obrigatórios.' });
    }

    // 1. Pega o token OAuth da Efí
    const accessToken = await obterTokenEfi();

    // 2. Monta o payload da cobrança Pix
    const payloadCob = {
      calendario: { expiracao: 3600 },
      devedor: {
        cpf: cpf.replace(/\D/g, ''),
        nome: nome || 'Cliente Ache Obra',
      },
      valor: {
        original: Number(valor).toFixed(2),
      },
      solicitacaoPagamento: descricao || 'Assinatura Ache Obra',
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
      url: `https://api-pix-h.gerencianet.com.br/v2/loc/${cobData.loc.id}`,
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
      error: error.response?.data?.mensaje || error.response?.data?.message || error.toString(),
    });
  }
});

// Inicializa o servidor na porta do Render
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});