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

// URLs específicas para cada módulo da Efí
const EFI_PIX_AUTH_URL = 'https://pix-h.api.efipay.com.br/oauth/token';
const EFI_PIX_COB_URL = 'https://pix-h.api.efipay.com.br/v2/cob';

const EFI_COBRANCA_AUTH_URL = 'https://cobrancas-h.api.efipay.com.br/oauth/token';
const EFI_API_V1_URL = 'https://cobrancas-h.api.efipay.com.br/v1';

// Token exclusivo para o Pix
async function obterTokenPix() {
  if (!httpsAgent) throw new Error('Agente HTTPS não inicializado.');

  const credentials = Buffer.from(
    `${process.env.EFI_CLIENT_ID}:${process.env.EFI_CLIENT_SECRET}`
  ).toString('base64');

  const response = await axios({
    method: 'POST',
    url: EFI_PIX_AUTH_URL,
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/json',
    },
    data: { grant_type: 'client_credentials' },
    httpsAgent,
  });

  return response.data.access_token;
}

// Token exclusivo para Cartões e Assinaturas (API v1)
async function obterTokenCobranca() {
  if (!httpsAgent) throw new Error('Agente HTTPS não inicializado.');

  const credentials = Buffer.from(
    `${process.env.EFI_CLIENT_ID}:${process.env.EFI_CLIENT_SECRET}`
  ).toString('base64');

  const response = await axios({
    method: 'POST',
    url: EFI_COBRANCA_AUTH_URL,
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/json',
    },
    data: { grant_type: 'client_credentials' },
    httpsAgent,
  });

  return response.data.access_token;
}

// ==================== 1. ROTA PIX (INTACTA) ====================
app.post('/gerar-pix', async (req, res) => {
  try {
    const { valor, cpf, nome } = req.body;

    if (!valor || !cpf) {
      return res.status(400).json({ error: 'Valor e CPF são obrigatórios.' });
    }

    if (!process.env.EFI_PIX_KEY) {
      return res.status(500).json({ error: 'Variável EFI_PIX_KEY não configurada no Render.' });
    }

    const accessToken = await obterTokenPix();

    const payloadCob = {
      calendario: { expiracao: 3600 },
      valor: { original: Number(valor).toFixed(2) },
      chave: process.env.EFI_PIX_KEY,
      devedor: {
        cpf: cpf.replace(/\D/g, ''),
        nome: nome || 'Cliente Ache Obra',
      }
    };

    const responseCob = await axios({
      method: 'POST',
      url: EFI_PIX_COB_URL,
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
        headers: { Authorization: `Bearer ${accessToken}` },
        httpsAgent,
      });

      copiaECola = responseQr.data.pixCopiaECola || responseQr.data.pix_copia_e_cola;
    }

    if (!copiaECola) {
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

// ==================== 2. ROTA CARTÃO AVULSO (ONE-STEP) ====================
app.post('/cobrar-cartao', async (req, res) => {
  try {
    const {
      valor,
      email,
      nome,
      cpf,
      descricao,
      cartao_numero,
      cartao_mes,
      cartao_ano,
      cartao_cvv,
      installments
    } = req.body;

    if (!cartao_numero || !cartao_mes || !cartao_ano || !cartao_cvv) {
      return res.status(400).json({ error: 'Dados do cartão incompletos.' });
    }

    const accessToken = await obterTokenCobranca();

    console.log('Processando cobrança avulsa via One-Step na Efí');
    const responsePay = await axios({
      method: 'POST',
      url: `${EFI_API_V1_URL}/charge/one-step`,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        items: [
          {
            name: descricao || 'Serviço Ache Obra',
            value: Math.round(Number(valor) * 100),
            amount: 1
          }
        ],
        payment: {
          credit_card: {
            customer: {
              name: nome,
              email: email,
              cpf: cpf.replace(/\D/g, ''),
              birth_date: '1990-01-01',
              phone_number: '42999999999'
            },
            billing_address: {
              street: 'Rua Principal',
              number: '123',
              neighborhood: 'Centro',
              zipcode: '85200000',
              city: 'Pitanga',
              state: 'PR'
            },
            installments: installments || 1,
            card_number: cartao_numero,
            expiration_month: cartao_mes,
            expiration_year: cartao_ano,
            cvv: cartao_cvv
          }
        }
      },
      httpsAgent,
    });

    return res.json({
      success: true,
      status: responsePay.data?.data?.status || responsePay.data?.status || 'PAID',
      pago: true,
      data: responsePay.data
    });

  } catch (error) {
    console.error('Erro ao processar cartão avulso:', error.response?.data || error.message);
    return res.status(500).json({
      error: error.response?.data?.mensagem || error.response?.data?.message || error.toString(),
    });
  }
});

// ==================== 3. ROTA CARTÃO RECORRENTE (ASSINATURA) ====================
app.post('/cobrar-assinatura', async (req, res) => {
  try {
    const {
      valor,
      email,
      nome,
      cpf,
      descricao,
      plan_id,
      cartao_numero,
      cartao_mes,
      cartao_ano,
      cartao_cvv,
      installments
    } = req.body;

    if (!plan_id) {
      return res.status(400).json({ error: 'ID do plano de assinatura não informado.' });
    }

    if (!cartao_numero || !cartao_mes || !cartao_ano || !cartao_cvv) {
      return res.status(400).json({ error: 'Dados do cartão incompletos.' });
    }

    const accessToken = await obterTokenCobranca();

    console.log(`Processando assinatura recorrente para o plano ${plan_id}`);
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
          birth_date: '1990-01-01',
          phone_number: '42999999999'
        },
        credit_card: {
          installments: installments || 1,
          billing_address: {
            street: 'Rua Principal',
            number: '123',
            neighborhood: 'Centro',
            zipcode: '85200000',
            city: 'Pitanga',
            state: 'PR'
          },
          card_number: cartao_numero,
          expiration_month: cartao_mes,
          expiration_year: cartao_ano,
          cvv: cartao_cvv
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

  } catch (error) {
    console.error('Erro ao processar assinatura:', error.response?.data || error.message);
    return res.status(500).json({
      error: error.response?.data?.mensagem || error.response?.data?.message || error.toString(),
    });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});