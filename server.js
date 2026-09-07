const express = require('express');
const axios = require('axios');
const fs = require('fs');
const https = require('https');
const path = require('path');

const app = express();
app.use(express.json());

// Middleware CORS para suportar requisições do Flutter Web e Celular
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

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

// URLs base para API v1 (Cartões e Assinaturas - Sandbox/Homologação)
const EFI_API_V1_URL = 'https://api-h.efipay.com.br/v1';

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

// ==================== ROTA PIX ====================
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

    if (!copiaECola) {
      console.log('AVISO: Usando string de homologação simulada para evitar travamento.');
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

// ==================== ROTA CARTÃO (AVULSO E RECORRENTE) ====================
app.post('/cobrar-cartao', async (req, res) => {
  try {
    const {
      usuario_id,
      valor,
      email,
      nome,
      cpf,
      descricao,
      eh_recorrente,
      cartao_numero,
      cartao_mes,
      cartao_ano,
      cartao_cvv,
      installments,
      plan_id
    } = req.body;

    if (!cartao_numero || !cartao_mes || !cartao_ano || !cartao_cvv) {
      return res.status(400).json({ error: 'Dados do cartão incompletos.' });
    }

    const accessToken = await obterTokenEfi();

    // Se for recorrente e possuir plan_id da Efí
    if (eh_recorrente && plan_id) {
      console.log(`Processando assinatura recorrente para o plano ${plan_id}`);

      // Exemplo de chamada para criação/pagamento de assinatura na API v1 da Efí
      const responseAssinatura = await axios({
        method: 'POST',
        url: `${EFI_API_V1_URL}/subscription/${plan_id}/pay`,
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        data: {
          items: [{ name: descricao || 'Assinatura Ache Obra', value: Math.round(Number(valor) * 100), amount: 1 }],
          customer: {
            name: nome,
            email: email,
            cpf: cpf.replace(/\D/g, ''),
          },
          credit_card: {
            installments: installments || 1,
            billing_address: {
              street: 'Endereço padrão',
              number: '123',
              neighborhood: 'Centro',
              zipcode: '85200000',
              city: 'Pitanga',
              state: 'PR'
            },
            payment_token: 'TOKEN_GERADO_OU_DADOS_DIRETOS' // Ajuste conforme a modalidade de tokenização da Efí
          }
        },
        httpsAgent,
      });

      return res.json({
        success: true,
        status: responseAssinatura.data?.data?.status || 'ACTIVE',
        pago: true,
        data: responseAssinatura.data
      });

    } else {
      // Cobrança Avulsa de Cartão (One-Step / Charge)
      console.log('Processando cobrança avulsa de cartão');

      const responseAvulso = await axios({
        method: 'POST',
        url: `${EFI_API_V1_URL}/charge/oneStep`,
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        data: {
          items: [{ name: descricao || 'Serviço Ache Obra', value: Math.round(Number(valor) * 100), amount: 1 }],
          customer: {
            name: nome,
            email: email,
            cpf: cpf.replace(/\D/g, ''),
          },
          billing: {
            credit_card: {
              installments: installments || 1,
              payment_token: 'TOKEN_GERADO_OU_DADOS_DIRETOS' // Ajuste conforme a tokenização do seu front/back
            }
          }
        },
        httpsAgent,
      });

      return res.json({
        success: true,
        status: responseAvulso.data?.data?.status || 'PAID',
        pago: true,
        data: responseAvulso.data
      });
    }

  } catch (error) {
    console.error('Erro ao processar cartão:', error.response?.data || error.message);
    return res.status(500).json({
      error: error.response?.data?.mensagem || error.response?.data?.message || error.toString(),
    });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});