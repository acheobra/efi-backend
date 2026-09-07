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
//
// A documentação atual da Efí utiliza:
// https://cobrancas-h.api.efipay.com.br
//
// Autorização:
// POST /v1/authorize
//
// Cartão:
// POST /v1/charge/one-step
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

// ============================================================
// 1. PIX
// ============================================================

app.post('/gerar-pix', async (req, res) => {

  try {

    const {
      valor,
      cpf,
      nome,
      descricao
    } = req.body;

    // --------------------------------------------------------
    // Validações
    // --------------------------------------------------------

    if (!valor || !cpf) {

      return res.status(400).json({
        error:
          'Valor e CPF são obrigatórios.'
      });

    }

    if (!process.env.EFI_PIX_KEY) {

      return res.status(500).json({
        error:
          'Variável EFI_PIX_KEY não configurada no Render.'
      });

    }

    // --------------------------------------------------------
    // Token
    // --------------------------------------------------------

    const accessToken =
      await obterTokenPix();

    // --------------------------------------------------------
    // Dados do PIX
    // --------------------------------------------------------

    const payloadCob = {

      calendario: {
        expiracao: 3600,
      },

      valor: {
        original:
          Number(valor).toFixed(2),
      },

      chave:
        process.env.EFI_PIX_KEY,

      devedor: {

        cpf:
          String(cpf).replace(/\D/g, ''),

        nome:
          nome || 'Cliente Ache Obra',
      },

    };

    // --------------------------------------------------------
    // Cria cobrança PIX
    // --------------------------------------------------------

    const responseCob = await axios({

      method: 'POST',

      url: EFI_PIX_COB_URL,

      headers: {

        Authorization:
          `Bearer ${accessToken}`,

        'Content-Type':
          'application/json',

      },

      data: payloadCob,

      httpsAgent,

      timeout: 30000,
    });

    const cobData =
      responseCob.data;

    const txid =
      cobData.txid;

    const locId =
      cobData.loc?.id;

    let copiaECola =
      cobData.pixCopiaECola ||
      cobData.pix_copia_e_cola;

    // --------------------------------------------------------
    // Se não veio copia e cola, tenta obter pelo LOC
    // --------------------------------------------------------

    if (!copiaECola && locId) {

      const responseQr =
        await axios({

          method: 'GET',

          url:
            `https://pix-h.api.efipay.com.br/v2/loc/${locId}`,

          headers: {

            Authorization:
              `Bearer ${accessToken}`,

          },

          httpsAgent,

          timeout: 30000,
        });

      copiaECola =
        responseQr.data.pixCopiaECola ||
        responseQr.data.pix_copia_e_cola;
    }

    // --------------------------------------------------------
    // IMPORTANTE:
    // Não gerar um "PIX copia e cola" manualmente.
    //
    // Se a Efí não retornar o código, é melhor informar erro
    // do que devolver uma string PIX inválida.
    // --------------------------------------------------------

    if (!copiaECola) {

      throw new Error(
        'A Efí não retornou o código PIX copia e cola.'
      );

    }

    return res.json({

      success: true,

      txid,

      pix_copia_e_cola:
        copiaECola,

    });

  } catch (error) {

    console.error(
      'Erro ao gerar Pix:',
      error.response?.data ||
      error.message
    );

    return res.status(500).json({

      error:
        error.response?.data?.mensagem ||
        error.response?.data?.message ||
        error.response?.data?.error_description ||
        error.message,

    });

  }

});

// ============================================================
// 2. CARTÃO DE CRÉDITO
// ============================================================
//
// IMPORTANTE:
//
// Esta rota NÃO recebe número do cartão.
//
// O Flutter deve gerar o payment_token através da
// biblioteca oficial da Efí.
//
// O backend recebe somente:
// - payment_token
// - valor
// - nome
// - CPF
// - email
// - telefone
// - parcelas
// - descrição
//
// Depois o backend chama:
//
// POST /v1/charge/one-step
//
// ============================================================

app.post('/cobrar-cartao', async (req, res) => {

  try {

    const {
      valor,
      email,
      nome,
      cpf,
      telefone,
      parcelas,
      payment_token,
      descricao
    } = req.body;

    console.log(
      '>>> Nova solicitação de cobrança por cartão.'
    );

    // --------------------------------------------------------
    // Validações básicas
    // --------------------------------------------------------

    if (!valor) {

      return res.status(400).json({
        error:
          'Valor da cobrança é obrigatório.'
      });

    }

    if (!cpf) {

      return res.status(400).json({
        error:
          'CPF é obrigatório.'
      });

    }

    if (!nome) {

      return res.status(400).json({
        error:
          'Nome é obrigatório.'
      });

    }

    if (!email) {

      return res.status(400).json({
        error:
          'E-mail é obrigatório.'
      });

    }

    if (!payment_token) {

      return res.status(400).json({
        error:
          'payment_token é obrigatório.'
      });

    }

    // --------------------------------------------------------
    // Valor em centavos
    // --------------------------------------------------------

    const valorNumerico =
      Number(valor);

    if (
      !Number.isFinite(valorNumerico) ||
      valorNumerico <= 0
    ) {

      return res.status(400).json({
        error:
          'Valor inválido.'
      });

    }

    const valorCentavos =
      Math.round(
        valorNumerico * 100
      );

    // --------------------------------------------------------
    // Parcelas
    // --------------------------------------------------------

    const numeroParcelas =
      Number(parcelas || 1);

    if (
      !Number.isInteger(numeroParcelas) ||
      numeroParcelas < 1 ||
      numeroParcelas > 12
    ) {

      return res.status(400).json({
        error:
          'Número de parcelas inválido. Informe de 1 a 12.'
      });

    }

    // --------------------------------------------------------
    // Token da API Cobranças
    // --------------------------------------------------------

    const accessToken =
      await obterTokenCobranca();

    // --------------------------------------------------------
    // CPF limpo
    // --------------------------------------------------------

    const cpfLimpo =
      String(cpf).replace(/\D/g, '');

    // --------------------------------------------------------
    // Telefone limpo
    // --------------------------------------------------------

    const telefoneLimpo =
      telefone
        ? String(telefone).replace(/\D/g, '')
        : undefined;

    // --------------------------------------------------------
    // Payload oficial da cobrança de cartão
    // --------------------------------------------------------

    const payload = {

      items: [

        {
          name:
            descricao ||
            'Plano Ache Obra',

          value:
            valorCentavos,

          amount: 1,
        },

      ],

      payment: {

        credit_card: {

          customer: {

            name:
              nome,

            cpf:
              cpfLimpo,

            email:
              email,

            ...(telefoneLimpo
              ? {
                  phone_number:
                    telefoneLimpo,
                }
              : {}),

          },

          installments:
            numeroParcelas,

          payment_token:
            payment_token,

        },

      },

    };

    console.log(
      '>>> Enviando cobrança para API Cobranças Efí...'
    );

    console.log(
      '>>> Valor:',
      valorCentavos,
      'centavos'
    );

    console.log(
      '>>> Parcelas:',
      numeroParcelas
    );

    // --------------------------------------------------------
    // NÃO imprimir payment_token no console.
    // --------------------------------------------------------

    const response =
      await axios({

        method: 'POST',

        url:
          `${EFI_COBRANCA_API_URL}/charge/one-step`,

        headers: {

          Authorization:
            `Bearer ${accessToken}`,

          'Content-Type':
            'application/json',

        },

        data:
          payload,

        httpsAgent,

        timeout: 30000,

      });

    const dados =
      response.data;

    console.log(
      '>>> Resposta da Efí recebida.'
    );

    console.log(
      '>>> Status:',
      dados?.data?.status
    );

    console.log(
      '>>> Charge ID:',
      dados?.data?.charge_id
    );

    // --------------------------------------------------------
    // Dados da transação
    // --------------------------------------------------------

    const chargeId =
      dados?.data?.charge_id;

    const status =
      dados?.data?.status;

    // --------------------------------------------------------
    // Retorno
    // --------------------------------------------------------

    return res.json({

      success: true,

      charge_id:
        chargeId,

      status:
        status,

      payment:
        dados?.data?.payment,

      installments:
        dados?.data?.installments,

      installment_value:
        dados?.data?.installment_value,

      total:
        dados?.data?.total,

      refusal:
        dados?.data?.refusal || null,

    });

  } catch (error) {

    console.error(
      '=========================================='
    );

    console.error(
      'ERRO AO COBRAR CARTÃO'
    );

    console.error(
      '=========================================='
    );

    console.error(
      'HTTP:',
      error.response?.status
    );

    console.error(
      'Resposta Efí:',
      error.response?.data
    );

    console.error(
      'Mensagem:',
      error.message
    );

    console.error(
      '=========================================='
    );

    const respostaEfi =
      error.response?.data;

    return res.status(
      error.response?.status || 500
    ).json({

      success: false,

      error:
        respostaEfi?.error_description ||
        respostaEfi?.mensagem ||
        respostaEfi?.message ||
        respostaEfi?.error ||
        error.message,

      efi:
        respostaEfi || null,

    });

  }

});

// ============================================================
// ROTA DE TESTE
// ============================================================

app.get('/', (req, res) => {

  res.json({

    success: true,

    message:
      'Backend Ache Obra funcionando.',

    ambiente:
      'Efí Homologação',

    pix:
      '/gerar-pix',

    cartao:
      '/cobrar-cartao',

  });

});

// ============================================================
// INICIALIZAÇÃO
// ============================================================

app.listen(PORT, () => {

  console.log(
    `Servidor rodando na porta ${PORT}`
  );

  console.log(
    '>>> Backend Ache Obra iniciado com sucesso! <<<'
  );

});