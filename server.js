// ============================================================
// ACHE OBRA - BACKEND EFÍ COM LOGS SEGUROS DE TRANSAÇÕES
// Gerado a partir do server.js fornecido pelo usuário.
// Revisão: histórico recorrente + troca segura completa entre avulso/recorrente + sincronização definitiva de tab_usuarios.
// ============================================================

const express = require('express');
const axios = require('axios');
const fs = require('fs');
const https = require('https');
const path = require('path');
const crypto = require('crypto');
 
const app = express();
 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
// LOGS SEGUROS DE TRANSAÇÕES
// ============================================================
//
// Objetivos:
// - Gerar um ID único para acompanhar cada operação no Render.
// - Registrar início, fim, HTTP, duração e resultado operacional.
// - NÃO registrar CPF, e-mail, telefone, nome, número do cartão,
//   CVV, payment_token, Authorization, Client Secret, chaves,
//   service_role do Supabase ou conteúdo integral de req.body.
// - O usuario_id é convertido em referência SHA-256 curta.
// - IDs técnicos de pagamento (txid, charge_id, subscription_id)
//   podem aparecer para permitir conciliação e suporte.
//
// IMPORTANTE:
// Este bloco é apenas de observabilidade. Ele não altera a regra
// de cobrança, confirmação, cancelamento, estorno ou assinatura.
// ============================================================

function gerarIdOperacao() {
  return (
    `${Date.now().toString(36)}-` +
    crypto.randomBytes(4).toString('hex')
  );
}

function referenciaSegura(valor) {
  const texto = String(valor ?? '').trim();

  if (!texto) {
    return null;
  }

  return crypto
    .createHash('sha256')
    .update(texto)
    .digest('hex')
    .substring(0, 12);
}

function sanitizarTextoSeguro(valor) {
  let texto = String(valor ?? '');

  // E-mail.
  texto = texto.replace(
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    '[EMAIL_REMOVIDO]'
  );

  // Bearer / JWT.
  texto = texto.replace(
    /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
    'Bearer [TOKEN_REMOVIDO]'
  );

  texto = texto.replace(
    /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    '[JWT_REMOVIDO]'
  );

  // Sequências numéricas longas: CPF, cartão, telefone etc.
  // Preserva números pequenos úteis como códigos HTTP.
  texto = texto.replace(
    /\b\d{6,19}\b/g,
    '[NUMERO_REMOVIDO]'
  );

  // Limita tamanho para evitar despejar payloads inteiros.
  if (texto.length > 500) {
    texto = `${texto.substring(0, 500)}...[TRUNCADO]`;
  }

  return texto;
}

function resumirErroSeguro(error) {
  if (typeof error === 'string') {
    return {
      http_status: null,
      codigo: null,
      mensagem: sanitizarTextoSeguro(error),
    };
  }

  const statusHttp =
    error?.response?.status ||
    error?.status ||
    null;

  const dados =
    error?.response?.data ||
    (
      error &&
      typeof error === 'object'
        ? error
        : {}
    );

  let codigo =
    dados?.code ||
    dados?.error_code ||
    (
      typeof dados?.error === 'string'
        ? dados.error
        : null
    ) ||
    error?.code ||
    null;

  if (
    codigo &&
    typeof codigo !== 'string' &&
    typeof codigo !== 'number'
  ) {
    codigo = null;
  }

  const mensagem =
    dados?.error_description ||
    dados?.message ||
    dados?.mensagem ||
    error?.message ||
    'Erro não identificado';

  return {
    http_status: statusHttp,
    codigo: codigo
      ? sanitizarTextoSeguro(codigo)
      : null,
    mensagem: sanitizarTextoSeguro(mensagem),
  };
}

function resumoEntradaSeguro(req) {
  const body =
    req?.body &&
    typeof req.body === 'object'
      ? req.body
      : {};

  const params =
    req?.params &&
    typeof req.params === 'object'
      ? req.params
      : {};

  const resumo = {};

  if (body.valor !== undefined && body.valor !== null) {
    const numero = Number(body.valor);

    resumo.valor =
      Number.isFinite(numero)
        ? numero
        : 'informado';
  }

  if (body.origem_tipo) {
    resumo.origem_tipo =
      sanitizarTextoSeguro(body.origem_tipo);
  }

  if (body.origem_id) {
    resumo.origem_id =
      String(body.origem_id);
  }

  if (body.plano_id) {
    resumo.plano_id =
      String(body.plano_id);
  }

  if (body.pagamento_id) {
    resumo.pagamento_id =
      String(body.pagamento_id);
  }

  if (body.charge_id) {
    resumo.charge_id =
      String(body.charge_id);
  }

  if (body.subscription_id) {
    resumo.subscription_id =
      String(body.subscription_id);
  }

  if (params.txid) {
    resumo.txid =
      String(params.txid);
  }

  if (body.txid) {
    resumo.txid =
      String(body.txid);
  }

  if (body.usuario_id) {
    resumo.usuario_ref =
      referenciaSegura(body.usuario_id);
  }

  // Apenas informa a presença; nunca registra o token.
  if (body.payment_token) {
    resumo.payment_token =
      '[PRESENTE_E_OCULTO]';
  }

  return resumo;
}

function resumoRespostaSeguro(dados) {
  if (
    !dados ||
    typeof dados !== 'object'
  ) {
    return {};
  }

  const resumo = {};

  const chavesSeguras = [
    'success',
    'pago',
    'status',
    'status_efi',
    'txid',
    'charge_id',
    'efi_charge_id',
    'subscription_id',
    'efi_subscription_id',
    'pagamento_id',
    'payment_id',
    'plano_id',
    'ja_estornado',
    'processado',
    'encontrado',
  ];

  for (const chave of chavesSeguras) {
    if (
      dados[chave] !== undefined &&
      dados[chave] !== null &&
      typeof dados[chave] !== 'object'
    ) {
      resumo[chave] =
        dados[chave];
    }
  }

  if (dados.error) {
    if (typeof dados.error === 'string') {
      resumo.erro =
        sanitizarTextoSeguro(dados.error);
    } else {
      resumo.erro =
        '[DETALHES_OCULTOS]';
    }
  }

  if (dados.message && typeof dados.message === 'string') {
    resumo.mensagem =
      sanitizarTextoSeguro(dados.message);
  }

  return resumo;
}

function rotaFinanceiraParaLog(req) {
  const caminho =
    String(req.path || '');

  return (
    caminho === '/sincronizar-planos-efi' ||
    caminho === '/gerar-pix' ||
    caminho.startsWith('/status-pix/') ||
    caminho === '/cobrar-cartao' ||
    caminho === '/cobrar-assinatura' ||
    caminho === '/trocar-assinatura' ||
        caminho.startsWith('/diagnostico-charge/') ||
caminho === '/webhook/efi' ||
    caminho === '/cancelar-pagamento-pix' ||
    caminho === '/cancelar-pagamento-cartao' ||
    caminho === '/cancelar-assinatura' ||
    caminho === '/processar-inadimplencia' ||
    caminho === '/registrar-assinatura-existente' ||
    caminho.startsWith('/sincronizar-pagamentos-recorrentes/')
  );
}

app.use((req, res, next) => {
  if (
    req.method === 'OPTIONS' ||
    !rotaFinanceiraParaLog(req)
  ) {
    return next();
  }

  const operacaoId =
    gerarIdOperacao();

  const inicio =
    Date.now();

  req.operacaoId =
    operacaoId;

  let resumoSaida = {};

  console.log(
    `[TX ${operacaoId}] INICIO ${req.method} ${req.path}`,
    resumoEntradaSeguro(req)
  );

  const jsonOriginal =
    res.json.bind(res);

  res.json = (dados) => {
    try {
      resumoSaida =
        resumoRespostaSeguro(dados);
    } catch (_) {
      resumoSaida = {};
    }

    return jsonOriginal(dados);
  };

  res.on('finish', () => {
    const duracaoMs =
      Date.now() - inicio;

    const nivel =
      res.statusCode >= 400
        ? 'FALHA'
        : 'FIM';

    console.log(
      `[TX ${operacaoId}] ${nivel} ${req.method} ${req.path}` +
      ` | HTTP ${res.statusCode}` +
      ` | ${duracaoMs} ms`,
      resumoSaida
    );
  });

  res.on('close', () => {
    if (!res.writableFinished) {
      console.warn(
        `[TX ${operacaoId}] CONEXÃO ENCERRADA ANTES DA RESPOSTA` +
        ` | ${req.method} ${req.path}`
      );
    }
  });

  next();
});

 
// ============================================================
// CORS
// ============================================================
 
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
 
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Sync-Secret'
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
 
    // PRODUÇÃO: valida a cadeia TLS do servidor da Efí.
    rejectUnauthorized: true,
  });
 
  console.log(
    '>>> Certificados carregados com sucesso! <<<'
  );
 
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
// PIX - PRODUÇÃO
// ------------------------------------------------------------
 
const EFI_PIX_BASE_URL =
  'https://pix.api.efipay.com.br';

const EFI_PIX_AUTH_URL =
  `${EFI_PIX_BASE_URL}/oauth/token`;

const EFI_PIX_COB_URL =
  `${EFI_PIX_BASE_URL}/v2/cob`;
 
// ------------------------------------------------------------
// COBRANÇAS - PRODUÇÃO
// ------------------------------------------------------------
 
const EFI_COBRANCA_BASE_URL =
  'https://cobrancas.api.efipay.com.br';
 
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
// CORREÇÃO / NORMALIZAÇÃO DO CUSTOM_ID DA EFÍ
// ============================================================
//
// A Efí aceita somente caracteres compatíveis com:
// letras, números, "_" e "-".
//
// O código anterior utilizava "|" para separar os dados.
// Exemplo:
//
// acheobra|user-UUID|tipo-plano
//
// O caractere "|" é rejeitado pela Efí.
//
// Agora qualquer informação utilizada no custom_id é
// sanitizada antes de ser enviada.
// ============================================================
 
function limparCustomId(valor) {
 
  return String(valor ?? '')
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[-_]+|[-_]+$/g, '');
}
 
function montarCustomId({
  usuario_id,
  origem_tipo,
  origem_id,
  prefixo = 'acheobra',
}) {
 
  const partes = [
    limparCustomId(prefixo),
 
    usuario_id
      ? `user-${limparCustomId(usuario_id)}`
      : null,
 
    origem_tipo
      ? `tipo-${limparCustomId(origem_tipo)}`
      : null,
 
    origem_id
      ? `origem-${limparCustomId(origem_id)}`
      : null,
  ].filter(Boolean);
 
  const resultado =
    partes
      .join('-')
      .substring(0, 255);
 
  return resultado || 'acheobra';
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
 
  const credentials =
    obterCredenciais();
 
  const response =
    await axios({
      method: 'POST',
 
      url:
        EFI_PIX_AUTH_URL,
 
      headers: {
        Authorization:
          `Basic ${credentials}`,
 
        'Content-Type':
          'application/json',
      },
 
      data: {
        grant_type:
          'client_credentials',
      },
 
      httpsAgent,
 
      timeout:
        30000,
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
 
  const credentials =
    obterCredenciais();
 
  console.log(
    '>>> Solicitando token da API Cobranças Efí...'
  );
 
  const response =
    await axios({
      method: 'POST',
 
      url:
        EFI_COBRANCA_AUTH_URL,
 
      headers: {
        Authorization:
          `Basic ${credentials}`,
 
        'Content-Type':
          'application/json',
      },
 
      data: {
        grant_type:
          'client_credentials',
      },
 
      httpsAgent,
 
      timeout:
        30000,
    });
 
  console.log(
    '>>> Token da API Cobranças obtido com sucesso.'
  );
 
  return response.data.access_token;
}
 
// ============================================================
// SUPABASE - CONFIGURAÇÃO DO BACKEND
// ============================================================
//
// Variáveis esperadas no Render:
//
// SUPABASE_URL
// SUPABASE_SERVICE_ROLE_KEY
// SYNC_PLANOS_SECRET
//
// IMPORTANTE:
// A chave secreta do Supabase fica SOMENTE no backend.
// Nunca envie essa chave ao Flutter.
// ============================================================
 
function obterConfiguracaoSupabase() {
 
  const supabaseUrl =
    process.env.SUPABASE_URL?.trim();
 
  const supabaseServiceRoleKey =
    process.env
      .SUPABASE_SERVICE_ROLE_KEY
      ?.trim();
 
  if (!supabaseUrl) {
    throw new Error(
      'SUPABASE_URL não configurado no Render.'
    );
  }
 
  if (!supabaseServiceRoleKey) {
    throw new Error(
      'SUPABASE_SERVICE_ROLE_KEY não configurado no Render.'
    );
  }
 
  return {
    supabaseUrl:
      supabaseUrl.replace(/\/+$/, ''),
 
    supabaseServiceRoleKey,
  };
}
 
function obterHeadersSupabase() {
 
  const {
    supabaseServiceRoleKey,
  } = obterConfiguracaoSupabase();
 
  return {
    apikey:
      supabaseServiceRoleKey,
 
    Authorization:
      `Bearer ${supabaseServiceRoleKey}`,
 
    'Content-Type':
      'application/json',
  };
}


// ============================================================
// SUPABASE - REQUISIÇÃO INTERNA COM RETRY DE JWT/CLOCK SKEW
// ============================================================
//
// Em algumas execuções agendadas o PostgREST pode responder:
//
//   PGRST303
//   JWT issued at future
//
// Isso normalmente é transitório e pode ocorrer por pequena
// diferença de relógio entre serviços/instâncias.
//
// IMPORTANTE:
// - Não troca a SUPABASE_SERVICE_ROLE_KEY.
// - Não reutiliza token de usuário.
// - Recria os headers internos a cada tentativa.
// - Só repete automaticamente para esse erro específico.
// - Outros erros continuam sendo lançados normalmente.
// ============================================================

function aguardar(ms) {
  return new Promise(
    (resolve) => setTimeout(resolve, ms)
  );
}

function erroSupabaseJwtEmitidoNoFuturo(error) {
  const dados =
    error?.response?.data || {};

  const codigo =
    String(
      dados?.code || ''
    )
      .trim()
      .toUpperCase();

  const mensagem =
    String(
      dados?.message ||
      dados?.msg ||
      error?.message ||
      ''
    )
      .trim()
      .toLowerCase();

  return (
    codigo === 'PGRST303' &&
    mensagem.includes(
      'jwt issued at future'
    )
  );
}

async function requisicaoSupabaseInterna(
  configuracaoAxios,
  {
    maxTentativas = 4,
    atrasoInicialMs = 1500,
  } = {}
) {
  let ultimoErro = null;

  for (
    let tentativa = 1;
    tentativa <= maxTentativas;
    tentativa++
  ) {
    try {
      const headersExtras =
        configuracaoAxios?.headers || {};

      return await axios({
        ...configuracaoAxios,

        headers: {
          ...obterHeadersSupabase(),
          ...headersExtras,
        },
      });

    } catch (error) {
      ultimoErro = error;

      if (
        !erroSupabaseJwtEmitidoNoFuturo(
          error
        )
      ) {
        throw error;
      }

      if (
        tentativa >= maxTentativas
      ) {
        break;
      }

      const esperaMs =
        atrasoInicialMs * tentativa;

      console.warn(
        '>>> Supabase retornou PGRST303 / JWT issued at future. '
        + `Nova tentativa ${tentativa + 1}/${maxTentativas} `
        + `em ${esperaMs} ms.`
      );

      await aguardar(
        esperaMs
      );
    }
  }

  console.error(
    '>>> Supabase continuou retornando PGRST303 / JWT issued at future '
    + `após ${maxTentativas} tentativa(s).`
  );

  throw ultimoErro;
}
 
 
// ============================================================
// SUPABASE - PAGAMENTOS AVULSOS
// ============================================================

function normalizarUuidOuNull(valor) {
  const texto = String(valor ?? '').trim();

  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    .test(texto)
      ? texto
      : null;
}

async function inserirPagamentoAvulsoSupabase(dados) {
  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await axios({
    method: 'POST',
    url: `${supabaseUrl}/rest/v1/tab_pagamentos_avulsos`,
    headers: {
      ...obterHeadersSupabase(),
      Prefer: 'return=representation',
    },
    data: dados,
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}

async function buscarPagamentoAvulsoCartaoPorIdUsuario(
  pagamentoId,
  usuarioId
) {
  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await axios({
    method: 'GET',
    url: `${supabaseUrl}/rest/v1/tab_pagamentos_avulsos`,
    params: {
      select: '*',
      id: `eq.${pagamentoId}`,
      usuario_id: `eq.${usuarioId}`,
      tipo_pagamento: 'eq.cartao',
      limit: 1,
    },
    headers: obterHeadersSupabase(),
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}

async function atualizarPagamentoAvulsoPorId(
  pagamentoId,
  dados
) {
  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await axios({
    method: 'PATCH',
    url: `${supabaseUrl}/rest/v1/tab_pagamentos_avulsos`,
    params: {
      id: `eq.${pagamentoId}`,
    },
    headers: {
      ...obterHeadersSupabase(),
      Prefer: 'return=representation',
    },
    data: dados,
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}


// ============================================================
// SUPABASE / EFÍ - PAGAMENTOS AVULSOS PIX
// ============================================================

async function buscarPagamentoAvulsoPixPorIdUsuario(pagamentoId, usuarioId) {
  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await axios({
    method: 'GET',
    url: `${supabaseUrl}/rest/v1/tab_pagamentos_avulsos`,
    params: {
      select: '*',
      id: `eq.${pagamentoId}`,
      usuario_id: `eq.${usuarioId}`,
      tipo_pagamento: 'eq.pix',
      limit: 1,
    },
    headers: obterHeadersSupabase(),
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}

async function buscarPagamentoAvulsoPixPorTxid(txid, usuarioId = null) {
  const { supabaseUrl } = obterConfiguracaoSupabase();

  const params = {
    select: '*',
    pix_txid: `eq.${txid}`,
    tipo_pagamento: 'eq.pix',
    limit: 1,
  };

  if (usuarioId) {
    params.usuario_id = `eq.${usuarioId}`;
  }

  const response = await axios({
    method: 'GET',
    url: `${supabaseUrl}/rest/v1/tab_pagamentos_avulsos`,
    params,
    headers: obterHeadersSupabase(),
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}

async function consultarCobrancaPixEfi(accessToken, txid) {
  const response = await axios({
    method: 'GET',
    url: `${EFI_PIX_COB_URL}/${encodeURIComponent(txid)}`,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    httpsAgent,
    timeout: 30000,
  });

  return response.data || null;
}

function extrairPixRecebidoDaCobranca(cobranca) {
  const pix = Array.isArray(cobranca?.pix)
    ? cobranca.pix
    : [];

  return pix.length > 0
    ? pix[pix.length - 1] || null
    : null;
}

function gerarIdDevolucaoPix(pagamentoId) {
  const id = String(pagamentoId || '')
    .replace(/[^a-zA-Z0-9]/g, '')
    .substring(0, 35);

  return id || `acheobra${Date.now()}`.substring(0, 35);
}

async function solicitarDevolucaoPixEfi(
  accessToken,
  e2eId,
  devolucaoId,
  valor
) {
  return axios({
    method: 'PUT',
    url:
      `${EFI_PIX_BASE_URL}/v2/pix/${encodeURIComponent(e2eId)}` +
      `/devolucao/${encodeURIComponent(devolucaoId)}`,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    data: {
      valor: Number(valor).toFixed(2),
    },
    httpsAgent,
    timeout: 30000,
  });
}

async function consultarDevolucaoPixEfi(
  accessToken,
  e2eId,
  devolucaoId
) {
  return axios({
    method: 'GET',
    url:
      `${EFI_PIX_BASE_URL}/v2/pix/${encodeURIComponent(e2eId)}` +
      `/devolucao/${encodeURIComponent(devolucaoId)}`,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    httpsAgent,
    timeout: 30000,
  });
}

async function sincronizarPagamentoPixPorTxid(txid, usuarioId = null) {
  const id = String(txid || '').trim();

  if (!id) {
    return {
      encontrado: false,
      pago: false,
      motivo: 'txid_ausente',
    };
  }

  const pagamento =
    await buscarPagamentoAvulsoPixPorTxid(
      id,
      usuarioId
    );

  const accessToken =
    await obterTokenPix();

  const cobranca =
    await consultarCobrancaPixEfi(
      accessToken,
      id
    );

  const statusEfi =
    String(cobranca?.status || '')
      .trim()
      .toUpperCase();

  const pixRecebido =
    extrairPixRecebidoDaCobranca(
      cobranca
    );

  const e2eId =
    pixRecebido?.endToEndId
      ? String(pixRecebido.endToEndId).trim()
      : '';

  const pago =
    statusEfi === 'CONCLUIDA' &&
    Boolean(e2eId);

  let pagamentoAtualizado =
    pagamento;

  if (pagamento) {
    const atualizacao = {
      status:
        pago
          ? 'pago'
          : (
              String(pagamento.status || '')
                .trim()
                .toLowerCase() === 'pago'
                ? 'pago'
                : 'aguardando_pagamento'
            ),
    };

    if (e2eId) {
      atualizacao.pix_e2e_id =
        e2eId;
    }

    if (pago) {
      atualizacao.data_pagamento =
        pixRecebido?.horario ||
        pagamento.data_pagamento ||
        new Date().toISOString();
    }

    pagamentoAtualizado =
      await atualizarPagamentoAvulsoPorId(
        pagamento.id,
        atualizacao
      );
  }

  return {
    encontrado: Boolean(pagamento),
    pago,
    status_efi: statusEfi || null,
    txid: id,
    e2e_id: e2eId || null,
    pix: pixRecebido,
    pagamento: pagamentoAtualizado,
    cobranca,
  };
}

async function processarDevolucaoPixPendente(pagamento) {
  if (!pagamento?.id) {
    return {
      processado: false,
      motivo: 'pagamento_ausente',
    };
  }

  let e2eId =
    String(
      pagamento.pix_e2e_id ||
      ''
    ).trim();

  const txid =
    String(
      pagamento.pix_txid ||
      ''
    ).trim();

  if (!e2eId && txid) {
    const sincronizacao =
      await sincronizarPagamentoPixPorTxid(
        txid,
        pagamento.usuario_id
      );

    e2eId =
      String(
        sincronizacao.e2e_id ||
        ''
      ).trim();
  }

  if (!e2eId) {
    return {
      processado: false,
      aguardando_e2e_id: true,
    };
  }

  const devolucaoId =
    gerarIdDevolucaoPix(
      pagamento.id
    );

  const accessToken =
    await obterTokenPix();

  const consulta =
    await consultarDevolucaoPixEfi(
      accessToken,
      e2eId,
      devolucaoId
    );

  const statusDevolucao =
    String(
      consulta.data?.status ||
      ''
    )
      .trim()
      .toUpperCase();

  if (statusDevolucao === 'DEVOLVIDO') {
    const atualizado =
      await atualizarPagamentoAvulsoPorId(
        pagamento.id,
        {
          status: 'estornado',
          estorno_concluido_em: new Date().toISOString(),
        }
      );

    return {
      processado: true,
      status: 'estornado',
      efi: consulta.data,
      pagamento: atualizado,
    };
  }

  if (statusDevolucao === 'NAO_REALIZADO') {
    const atualizado =
      await atualizarPagamentoAvulsoPorId(
        pagamento.id,
        {
          status: 'estorno_falhou',
        }
      );

    return {
      processado: true,
      status: 'estorno_falhou',
      efi: consulta.data,
      pagamento: atualizado,
    };
  }

  return {
    processado: true,
    status: 'estorno_solicitado',
    efi: consulta.data,
  };
}


// ============================================================
// EFÍ - CONFIRMAÇÃO IMEDIATA DE COBRANÇA NO CARTÃO
// ============================================================
// A API pode retornar "approved" e mudar para "paid" poucos segundos
// depois. Para que a tela só mostre PAGAMENTO CONFIRMADO quando o plano
// já estiver efetivamente ativo, aguardamos por um curto período e
// consultamos a cobrança diretamente na Efí.
//
// O webhook continua sendo a garantia assíncrona caso a confirmação
// aconteça depois desta janela.
// ============================================================

async function consultarCobrancaCartaoEfi(accessToken, chargeId) {
  const response = await axios({
    method: 'GET',
    url: `${EFI_COBRANCA_API_URL}/charge/${encodeURIComponent(String(chargeId))}`,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    httpsAgent,
    timeout: 30000,
  });

  return response.data?.data || {};
}

function statusCobrancaCartaoPago(status) {
  const normalizado = String(status || '').trim().toLowerCase();
  return normalizado === 'paid' || normalizado === 'settled';
}

function statusCobrancaCartaoFinalSemPagamento(status) {
  const normalizado = String(status || '').trim().toLowerCase();
  return [
    'refused',
    'declined',
    'denied',
    'canceled',
    'cancelled',
    'expired',
    'refunded',
  ].includes(normalizado);
}

async function aguardarConfirmacaoCobrancaCartaoEfi(
  accessToken,
  chargeId,
  {
    statusInicial = null,
    tentativas = 12,
    intervaloMs = 1500,
  } = {}
) {
  const id = String(chargeId || '').trim();
  let statusAtual = String(statusInicial || '').trim().toLowerCase();
  let cobranca = null;

  if (!id) {
    return {
      confirmado: statusCobrancaCartaoPago(statusAtual),
      status: statusAtual || null,
      cobranca: null,
    };
  }

  if (statusCobrancaCartaoPago(statusAtual)) {
    return { confirmado: true, status: statusAtual, cobranca: null };
  }

  if (statusCobrancaCartaoFinalSemPagamento(statusAtual)) {
    return { confirmado: false, status: statusAtual, cobranca: null };
  }

  for (let tentativa = 1; tentativa <= tentativas; tentativa++) {
    if (tentativa > 1 || statusAtual) {
      await aguardar(intervaloMs);
    }

    try {
      cobranca = await consultarCobrancaCartaoEfi(accessToken, id);
      statusAtual = String(cobranca?.status || statusAtual || '')
        .trim()
        .toLowerCase();

      console.log(
        `>>> Confirmação cartão ${id}: tentativa ${tentativa}/${tentativas} | status Efí: ${statusAtual || 'não informado'}`
      );

      if (statusCobrancaCartaoPago(statusAtual)) {
        return {
          confirmado: true,
          status: statusAtual,
          cobranca,
        };
      }

      if (statusCobrancaCartaoFinalSemPagamento(statusAtual)) {
        return {
          confirmado: false,
          status: statusAtual,
          cobranca,
        };
      }
    } catch (error) {
      console.warn(
        `>>> Falha transitória ao consultar confirmação da cobrança ${id}:`,
        resumirErroSeguro(error)
      );
    }
  }

  return {
    confirmado: false,
    status: statusAtual || null,
    cobranca,
  };
}

// ============================================================
// ESTORNO PENDENTE - PAGAMENTOS AVULSOS NO CARTÃO
// ============================================================

async function buscarPagamentoAvulsoCartaoPorChargeId(chargeId) {
  const { supabaseUrl } = obterConfiguracaoSupabase();
  const response = await axios({
    method: 'GET',
    url: `${supabaseUrl}/rest/v1/tab_pagamentos_avulsos`,
    params: {
      select: '*',
      efi_charge_id: `eq.${chargeId}`,
      tipo_pagamento: 'eq.cartao',
      limit: 1,
    },
    headers: obterHeadersSupabase(),
    timeout: 30000,
  });
  return Array.isArray(response.data) ? response.data[0] || null : null;
}

async function solicitarEstornoCartaoEfi(accessToken, chargeId) {
  return axios({
    method: 'POST',
    url: `${EFI_COBRANCA_API_URL}/charge/card/${encodeURIComponent(chargeId)}/refund`,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    data: {},
    httpsAgent,
    timeout: 30000,
  });
}

async function processarEstornoPendentePorChargeId(chargeId, statusEfiInformado = null) {
  const id = String(chargeId || '').trim();
  if (!id) return { processado: false, motivo: 'charge_id_ausente' };

  const pagamento = await buscarPagamentoAvulsoCartaoPorChargeId(id);
  if (!pagamento) return { processado: false, motivo: 'pagamento_avulso_nao_encontrado' };

  const statusLocal = String(pagamento.status || '').trim().toLowerCase();
  if (statusLocal === 'estornado' || statusLocal === 'refunded') {
    return { processado: true, ja_estornado: true, pagamento_id: pagamento.id };
  }
  if (statusLocal !== 'estorno_pendente') {
    return { processado: false, motivo: 'sem_estorno_pendente', status_local: statusLocal };
  }

  const accessToken = await obterTokenCobranca();
  let statusEfi = String(statusEfiInformado || '').trim().toLowerCase();
  if (!statusEfi) {
    const consulta = await axios({
      method: 'GET',
      url: `${EFI_COBRANCA_API_URL}/charge/${encodeURIComponent(id)}`,
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      httpsAgent,
      timeout: 30000,
    });
    statusEfi = String(consulta.data?.data?.status || '').trim().toLowerCase();
  }

  console.log(`>>> Processando estorno pendente. Pagamento ${pagamento.id}. Charge ${id}. Status Efí: ${statusEfi}.`);

  if (statusEfi === 'refunded') {
    const atualizado = await atualizarPagamentoAvulsoPorId(pagamento.id, {
      status: 'estornado',
      estorno_concluido_em: new Date().toISOString(),
    });
    return { processado: true, ja_estornado: true, pagamento: atualizado };
  }

  if (statusEfi !== 'paid') {
    return { processado: false, aguardando_paid: true, status_efi: statusEfi || null };
  }

  const respostaEstorno = await solicitarEstornoCartaoEfi(accessToken, id);
  const atualizado = await atualizarPagamentoAvulsoPorId(pagamento.id, {
    status: 'estorno_solicitado',
    estorno_solicitado_em: pagamento.estorno_solicitado_em || new Date().toISOString(),
  });
  console.log(`>>> Estorno pendente enviado à Efí. Pagamento ${pagamento.id}. Charge ${id}.`);
  return { processado: true, status: 'estorno_solicitado', pagamento: atualizado, efi: respostaEstorno.data };
}

// ============================================================
// SUPABASE - ASSINATURAS / WEBHOOK / STATUS
// ============================================================
 
const EFI_NOTIFICATION_URL =
  process.env.EFI_NOTIFICATION_URL?.trim() ||
  `${(process.env.RENDER_EXTERNAL_URL || 'https://efi-backend-1.onrender.com').replace(/\/+$/, '')}/webhook/efi`;
 
function normalizarDataIso(valor) {
  if (!valor) return null;
 
  const data = new Date(valor);
 
  if (Number.isNaN(data.getTime())) {
    return null;
  }
 
  return data.toISOString();
}
 
async function inserirOuAtualizarAssinaturaSupabase(dados) {
  const {
    supabaseUrl,
  } = obterConfiguracaoSupabase();
 
  if (!dados?.efi_subscription_id) {
    throw new Error(
      'efi_subscription_id é obrigatório para registrar a assinatura.'
    );
  }
 
  // IMPORTANTE:
  // Usa o wrapper com retry porque o PostgREST pode retornar
  // transitoriamente PGRST303 / "JWT issued at future" por clock skew.
  // Sem retry, a assinatura já pode existir na Efí e falhar somente
  // na gravação local, gerando 502 e deixando o histórico órfão.
  const response = await requisicaoSupabaseInterna({
    method: 'POST',
 
    url:
      `${supabaseUrl}/rest/v1/tab_assinaturas`,
 
    params: {
      on_conflict:
        'efi_subscription_id',
    },
 
    headers: {
      Prefer:
        'resolution=merge-duplicates,return=representation',
    },
 
    data: dados,
 
    timeout: 30000,
  });
 
  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}
 
async function buscarAssinaturaPorSubscriptionId(
  subscriptionId
) {
  const {
    supabaseUrl,
  } = obterConfiguracaoSupabase();
 
  const response = await requisicaoSupabaseInterna({
    method: 'GET',
 
    url:
      `${supabaseUrl}/rest/v1/tab_assinaturas`,
 
    params: {
      select: '*',
 
      efi_subscription_id:
        `eq.${subscriptionId}`,
 
      limit:
        1,
    },
 
    timeout:
      30000,
  });
 
  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}
 
async function buscarAssinaturaAtivaPorUsuario(
  usuarioId
) {
  const {
    supabaseUrl,
  } = obterConfiguracaoSupabase();
 
  const response = await requisicaoSupabaseInterna({
    method: 'GET',
 
    url:
      `${supabaseUrl}/rest/v1/tab_assinaturas`,
 
    params: {
      select: '*',
 
      usuario_id:
        `eq.${usuarioId}`,
 
      status_assinatura:
        'in.(ativo,pagamento_pendente,inadimplente)',
 
      order:
        'created_at.desc',
 
      limit:
        1,
    },
 
 
    timeout:
      30000,
  });
 
  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}
 


// ============================================================
// SUPABASE - RECONCILIAR PAGAMENTOS RECORRENTES ÓRFÃOS
// ============================================================
//
// O webhook da Efí pode chegar antes de tab_assinaturas ser gravada.
// Nesse caso o histórico é preservado apenas com efi_subscription_id
// e efi_charge_id. Assim que o contrato existir, este helper completa
// assinatura_id, usuario_id, plano_id e efi_plan_id nas linhas órfãs.
// ============================================================

async function vincularPagamentosRecorrentesOrfaosAssinatura(assinatura) {
  const subscriptionId = String(
    assinatura?.efi_subscription_id || ''
  ).trim();

  if (!subscriptionId || !assinatura?.id) {
    return 0;
  }

  const { supabaseUrl } = obterConfiguracaoSupabase();

  const payload = removerCamposUndefined({
    assinatura_id:
      normalizarUuidOuNull(assinatura.id) || undefined,
    usuario_id:
      normalizarUuidOuNull(assinatura.usuario_id) || undefined,
    plano_id:
      normalizarUuidOuNull(assinatura.plano_id) || undefined,
    efi_plan_id:
      assinatura.efi_plan_id
        ? String(assinatura.efi_plan_id)
        : undefined,
  });

  const response = await requisicaoSupabaseInterna({
    method: 'PATCH',
    url: `${supabaseUrl}/rest/v1/tab_pagamentos_recorrentes`,
    params: {
      efi_subscription_id: `eq.${subscriptionId}`,
      assinatura_id: 'is.null',
    },
    headers: {
      Prefer: 'return=representation',
    },
    data: payload,
    timeout: 30000,
  });

  const atualizados = Array.isArray(response.data)
    ? response.data.length
    : 0;

  if (atualizados > 0) {
    console.log(
      `>>> ${atualizados} pagamento(s) recorrente(s) órfão(s) vinculados à assinatura ${subscriptionId}.`
    );
  }

  return atualizados;
}

// ============================================================
// SUPABASE - HISTÓRICO DE PAGAMENTOS RECORRENTES
// ============================================================
//
// tab_assinaturas:
//   representa o contrato/estado atual da assinatura.
//
// tab_pagamentos_recorrentes:
//   representa CADA cobrança individual gerada pela assinatura.
//
// Regra principal:
// - efi_charge_id é a chave única de conciliação;
// - o mesmo webhook pode chegar mais de uma vez sem duplicar linhas;
// - waiting/pending/approved/authorized NÃO são pagamento confirmado;
// - paid/settled confirmam pagamento;
// - um evento antigo/intermediário nunca rebaixa uma cobrança já paga;
// - refunded/estornado pode substituir pago.
// ============================================================

function normalizarStatusPagamentoRecorrente(statusEfi) {
  const status = String(statusEfi || '')
    .trim()
    .toLowerCase();

  if (status === 'paid' || status === 'settled') {
    return 'pago';
  }

  if (status === 'refunded') {
    return 'estornado';
  }

  if (
    status === 'refused' ||
    status === 'declined' ||
    status === 'denied'
  ) {
    return 'recusado';
  }

  if (
    status === 'canceled' ||
    status === 'cancelled'
  ) {
    return 'cancelado';
  }

  if (status === 'expired') {
    return 'expirado';
  }

  if (status === 'unpaid') {
    return 'nao_pago';
  }

  return 'aguardando_pagamento';
}

function statusPagamentoRecorrenteEhPago(statusEfi) {
  const status = String(statusEfi || '')
    .trim()
    .toLowerCase();

  return status === 'paid' || status === 'settled';
}

function statusPagamentoRecorrenteEhRecusado(statusEfi) {
  const status = String(statusEfi || '')
    .trim()
    .toLowerCase();

  return (
    status === 'refused' ||
    status === 'declined' ||
    status === 'denied'
  );
}

function statusPagamentoRecorrenteEhCancelado(statusEfi) {
  const status = String(statusEfi || '')
    .trim()
    .toLowerCase();

  return status === 'canceled' || status === 'cancelled';
}

function statusPagamentoRecorrenteEhEstornado(statusEfi) {
  return String(statusEfi || '')
    .trim()
    .toLowerCase() === 'refunded';
}

function removerCamposUndefined(objeto) {
  return Object.fromEntries(
    Object.entries(objeto || {})
      .filter(([, valor]) => valor !== undefined)
  );
}

async function buscarPagamentoRecorrentePorChargeId(chargeId) {
  const id = String(chargeId || '').trim();

  if (!id) {
    return null;
  }

  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await requisicaoSupabaseInterna({
    method: 'GET',
    url: `${supabaseUrl}/rest/v1/tab_pagamentos_recorrentes`,
    params: {
      select: '*',
      efi_charge_id: `eq.${id}`,
      limit: 1,
    },
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}

function preservarStatusFinalPagamentoRecorrente(
  registroExistente,
  statusLocalNovo,
  statusEfiNovo
) {
  const statusExistente = String(
    registroExistente?.status || ''
  )
    .trim()
    .toLowerCase();

  const statusEfi = String(statusEfiNovo || '')
    .trim()
    .toLowerCase();

  // Estorno é o estado financeiro mais forte.
  if (statusExistente === 'estornado') {
    return 'estornado';
  }

  if (statusPagamentoRecorrenteEhEstornado(statusEfi)) {
    return 'estornado';
  }

  // Não permite que webhook atrasado "waiting", "unpaid",
  // "approved" etc. rebaixe uma cobrança já confirmada.
  if (statusExistente === 'pago') {
    return 'pago';
  }

  return statusLocalNovo;
}

async function inserirOuAtualizarPagamentoRecorrenteSupabase(dados) {
  const chargeId = String(
    dados?.efi_charge_id || ''
  ).trim();

  if (!chargeId) {
    throw new Error(
      'efi_charge_id é obrigatório para registrar pagamento recorrente.'
    );
  }

  const existente =
    await buscarPagamentoRecorrentePorChargeId(chargeId);

  const statusLocalNovo =
    normalizarStatusPagamentoRecorrente(
      dados?.status_efi || dados?.status
    );

  const statusFinal =
    preservarStatusFinalPagamentoRecorrente(
      existente,
      statusLocalNovo,
      dados?.status_efi
    );

  const payload = removerCamposUndefined({
    ...dados,
    efi_charge_id: chargeId,
    status: statusFinal,

    // Nunca perde datas financeiras já conhecidas quando o evento
    // atual não traz novamente essas informações.
    data_cobranca:
      dados?.data_cobranca !== undefined
        ? dados.data_cobranca
        : existente?.data_cobranca,

    data_pagamento:
      dados?.data_pagamento !== undefined
        ? dados.data_pagamento
        : existente?.data_pagamento,

    data_recusa:
      dados?.data_recusa !== undefined
        ? dados.data_recusa
        : existente?.data_recusa,

    data_cancelamento:
      dados?.data_cancelamento !== undefined
        ? dados.data_cancelamento
        : existente?.data_cancelamento,

    data_estorno:
      dados?.data_estorno !== undefined
        ? dados.data_estorno
        : existente?.data_estorno,

    origem_registro:
      existente?.origem_registro ||
      dados?.origem_registro,
  });

  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await requisicaoSupabaseInterna({
    method: 'POST',
    url: `${supabaseUrl}/rest/v1/tab_pagamentos_recorrentes`,
    params: {
      on_conflict: 'efi_charge_id',
    },
    headers: {
      Prefer:
        'resolution=merge-duplicates,return=representation',
    },
    data: payload,
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}

async function registrarHistoricoPagamentoRecorrente({
  assinatura = null,
  assinaturaId = null,
  usuarioId = null,
  planoId = null,
  efiSubscriptionId,
  efiPlanId = null,
  chargeId,
  statusEfi,
  valor = null,
  valorCentavosEvento = null,
  parcelas = null,
  valorParcela = null,
  metodoPagamento = 'credit_card',
  bandeiraCartao = null,
  dataCobranca = null,
  dataPagamento = null,
  dataVencimento = null,
  notificationToken = null,
  tipoEvento = null,
  origemRegistro = null,
  codigoRecusa = null,
  motivoRecusa = null,
  motivoCancelamento = null,
  valorEstornado = null,
  observacao = null,
}) {
  const idCharge = String(chargeId || '').trim();

  if (!idCharge) {
    return null;
  }

  const statusOriginal = String(statusEfi || '')
    .trim()
    .toLowerCase();

  const agora = new Date().toISOString();

  const temValorEvento =
    valorCentavosEvento !== null &&
    valorCentavosEvento !== undefined &&
    String(valorCentavosEvento).trim() !== '';

  const valorEventoNumero =
    temValorEvento
      ? Number(valorCentavosEvento)
      : NaN;

  const temValorNormal =
    valor !== null &&
    valor !== undefined &&
    String(valor).trim() !== '';

  const valorNormal =
    temValorNormal
      ? Number(valor)
      : NaN;

  const valorFinal =
    Number.isFinite(valorEventoNumero) &&
    valorEventoNumero > 0
      ? valorEventoNumero / 100
      : (
          Number.isFinite(valorNormal) &&
          valorNormal >= 0
            ? valorNormal
            : undefined
        );

  const pago =
    statusPagamentoRecorrenteEhPago(statusOriginal);

  const recusado =
    statusPagamentoRecorrenteEhRecusado(statusOriginal);

  const cancelado =
    statusPagamentoRecorrenteEhCancelado(statusOriginal);

  const estornado =
    statusPagamentoRecorrenteEhEstornado(statusOriginal);

  const registro =
    await inserirOuAtualizarPagamentoRecorrenteSupabase({
      assinatura_id:
        normalizarUuidOuNull(
          assinaturaId || assinatura?.id
        ) || undefined,

      usuario_id:
        normalizarUuidOuNull(
          usuarioId || assinatura?.usuario_id
        ) || undefined,

      plano_id:
        normalizarUuidOuNull(
          planoId || assinatura?.plano_id
        ) || undefined,

      efi_subscription_id:
        efiSubscriptionId
          ? String(efiSubscriptionId)
          : (
              assinatura?.efi_subscription_id
                ? String(assinatura.efi_subscription_id)
                : undefined
            ),

      efi_plan_id:
        efiPlanId
          ? String(efiPlanId)
          : (
              assinatura?.efi_plan_id
                ? String(assinatura.efi_plan_id)
                : undefined
            ),

      efi_charge_id:
        idCharge,

      valor:
        valorFinal,

      parcelas:
        Number.isInteger(Number(parcelas)) &&
        Number(parcelas) > 0
          ? Number(parcelas)
          : undefined,

      valor_parcela:
        valorParcela !== null &&
        valorParcela !== undefined &&
        String(valorParcela).trim() !== '' &&
        Number.isFinite(Number(valorParcela)) &&
        Number(valorParcela) >= 0
          ? Number(valorParcela)
          : undefined,

      status_efi:
        statusOriginal || undefined,

      metodo_pagamento:
        metodoPagamento || undefined,

      bandeira_cartao:
        bandeiraCartao || undefined,

      data_cobranca:
        normalizarDataIso(dataCobranca) || undefined,

      data_vencimento:
        normalizarDataIso(dataVencimento) || undefined,

      data_pagamento:
        pago
          ? (
              normalizarDataIso(dataPagamento) ||
              agora
            )
          : undefined,

      data_recusa:
        recusado
          ? agora
          : undefined,

      data_cancelamento:
        cancelado
          ? agora
          : undefined,

      data_estorno:
        estornado
          ? agora
          : undefined,

      codigo_recusa:
        codigoRecusa || undefined,

      motivo_recusa:
        motivoRecusa || undefined,

      motivo_cancelamento:
        motivoCancelamento || undefined,

      valor_estornado:
        valorEstornado !== null &&
        valorEstornado !== undefined &&
        String(valorEstornado).trim() !== '' &&
        Number.isFinite(Number(valorEstornado)) &&
        Number(valorEstornado) >= 0
          ? Number(valorEstornado)
          : undefined,

      ultimo_notification_token:
        notificationToken || undefined,

      ultima_notificacao_efi_em:
        notificationToken
          ? agora
          : undefined,

      ultimo_evento_efi:
        tipoEvento || undefined,

      ultima_sincronizacao_em:
        origemRegistro === 'sincronizacao_assinatura'
          ? agora
          : undefined,

      origem_registro:
        origemRegistro || undefined,

      observacao:
        observacao || undefined,
    });

  console.log(
    `>>> Histórico recorrente conciliado. Charge ${idCharge}. Status: ${statusOriginal || 'desconhecido'}.`
  );

  return registro;
}

async function consultarAssinaturaEfiPorId(
  accessToken,
  subscriptionId
) {
  const response = await axios({
    method: 'GET',
    url:
      `${EFI_COBRANCA_API_URL}/subscription/${encodeURIComponent(
        String(subscriptionId)
      )}`,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    httpsAgent,
    timeout: 30000,
  });

  return response.data?.data || {};
}

async function sincronizarHistoricoPagamentosRecorrentesAssinatura(
  subscriptionId,
  accessTokenInformado = null
) {
  const id = String(subscriptionId || '').trim();

  if (!id) {
    throw new Error(
      'subscription_id é obrigatório para sincronizar o histórico recorrente.'
    );
  }

  const accessToken =
    accessTokenInformado ||
    await obterTokenCobranca();

  const assinaturaEfi =
    await consultarAssinaturaEfiPorId(
      accessToken,
      id
    );

  const assinaturaLocal =
    await buscarAssinaturaPorSubscriptionId(id);

  const historico = Array.isArray(assinaturaEfi?.history)
    ? assinaturaEfi.history
    : [];

  let processados = 0;

  for (const item of historico) {
    const chargeId = item?.charge_id;

    if (!chargeId) {
      continue;
    }

    await registrarHistoricoPagamentoRecorrente({
      assinatura: assinaturaLocal,
      efiSubscriptionId: id,
      efiPlanId:
        assinaturaEfi?.plan?.plan_id ||
        assinaturaLocal?.efi_plan_id ||
        null,
      chargeId,
      statusEfi: item?.status,
      valor:
        assinaturaLocal?.valor_recorrente ??
        (
          Number.isFinite(Number(assinaturaEfi?.value))
            ? Number(assinaturaEfi.value) / 100
            : null
        ),
      metodoPagamento:
        assinaturaEfi?.payment_method ||
        'credit_card',
      dataCobranca:
        item?.created_at ||
        assinaturaEfi?.created_at ||
        null,
      origemRegistro:
        'sincronizacao_assinatura',
      tipoEvento:
        'subscription_history',
    });

    processados++;
  }

  return {
    subscription_id: id,
    total_historico_efi: historico.length,
    cobranças_processadas: processados,
    assinatura_local_encontrada:
      Boolean(assinaturaLocal),
  };
}

// ============================================================
// SUPABASE / EFÍ - AUXILIARES PARA TROCA DE PLANO RECORRENTE
// ============================================================

async function buscarPlanoRecorrentePorIdSupabase(planoId) {
  const id = String(planoId || '').trim();

  if (!id) {
    return null;
  }

  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await requisicaoSupabaseInterna({
    method: 'GET',
    url: `${supabaseUrl}/rest/v1/tab_planos`,
    params: {
      select:
        'id,nome_plano,valor_recorrente,efi_plan_id,recorrencia_ativa,status,tipo_usuario',
      id: `eq.${id}`,
      limit: 1,
    },
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}


// ============================================================
// SUPABASE - PLANO ATIVO DO USUÁRIO
// ============================================================
//
// tab_usuarios é a fonte usada pelo Flutter para descobrir qual
// plano deve aparecer como "PLANO ATUAL".
//
// Portanto, não basta atualizar tab_assinaturas:
// sempre que um pagamento de plano for confirmado, o backend
// também sincroniza tab_usuarios.
//
// Isso permite os quatro fluxos com segurança:
// - avulso -> avulso
// - avulso -> recorrente
// - recorrente -> recorrente
// - recorrente -> avulso
// ============================================================

async function buscarPlanoPorIdSupabase(planoId) {
  const id = String(planoId || '').trim();

  if (!id) {
    return null;
  }

  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await requisicaoSupabaseInterna({
    method: 'GET',
    url: `${supabaseUrl}/rest/v1/tab_planos`,
    params: {
      select: '*',
      id: `eq.${id}`,
      limit: 1,
    },
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}

function obterNomeBasePlano(nomePlano) {
  const nome = String(nomePlano || '').trim();

  if (!nome) {
    return 'Plano';
  }

  const partes = nome
    .split(/\s+-\s+/)
    .map((item) => item.trim())
    .filter(Boolean);

  return partes.length > 0
    ? partes[partes.length - 1]
    : nome;
}

async function atualizarPlanoAtivoUsuarioSupabase({
  usuarioId,
  planoId,
  recorrente,
  dataAtivacao = null,
}) {
  const idUsuario = String(usuarioId || '').trim();
  const idPlano = String(planoId || '').trim();

  if (!idUsuario || !idPlano) {
    throw new Error(
      'usuario_id e plano_id são obrigatórios para atualizar o plano ativo do usuário.'
    );
  }

  const plano = await buscarPlanoPorIdSupabase(idPlano);

  if (!plano?.id) {
    throw new Error(
      'O pagamento foi confirmado, mas o plano não foi encontrado em tab_planos.'
    );
  }

  const { supabaseUrl } = obterConfiguracaoSupabase();

  const agora =
    normalizarDataIso(dataAtivacao) ||
    new Date().toISOString();

  const response = await requisicaoSupabaseInterna({
    method: 'PATCH',
    url: `${supabaseUrl}/rest/v1/tab_usuarios`,
    params: {
      id: `eq.${idUsuario}`,
    },
    headers: {
      Prefer: 'return=representation',
    },
    data: {
      nome_plano_ativo:
        obterNomeBasePlano(plano.nome_plano),
      id_plano_atual:
        idPlano,
      plano_id:
        idPlano,
      recorrente:
        Boolean(recorrente),
      plano_data_ativacao:
        agora,
    },
    timeout: 30000,
  });

  const usuarioAtualizado =
    Array.isArray(response.data)
      ? response.data[0] || null
      : null;

  if (!usuarioAtualizado) {
    throw new Error(
      'O pagamento foi confirmado, mas tab_usuarios não retornou o usuário após atualizar o plano.'
    );
  }

  const planoGravado =
    String(
      usuarioAtualizado.id_plano_atual ||
      usuarioAtualizado.plano_id ||
      ''
    ).trim();

  if (planoGravado !== idPlano) {
    throw new Error(
      'O pagamento foi confirmado, mas o novo plano não foi gravado corretamente em tab_usuarios.'
    );
  }

  console.log(
    `>>> tab_usuarios atualizado. Usuário ref ${referenciaSegura(idUsuario)} | plano ${idPlano} | recorrente=${Boolean(recorrente)}.`
  );

  return {
    usuario: usuarioAtualizado,
    plano,
  };
}

async function buscarAssinaturasAbertasPorUsuario(usuarioId) {
  const idUsuario = String(usuarioId || '').trim();

  if (!idUsuario) {
    return [];
  }

  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await requisicaoSupabaseInterna({
    method: 'GET',
    url: `${supabaseUrl}/rest/v1/tab_assinaturas`,
    params: {
      select: '*',
      usuario_id: `eq.${idUsuario}`,
      status_assinatura:
        'in.(ativo,inadimplente,pagamento_pendente)',
      order: 'created_at.desc',
    },
    timeout: 30000,
  });

  return Array.isArray(response.data)
    ? response.data
    : [];
}

async function cancelarAssinaturasAbertasAntesDePlanoAvulso({
  usuarioId,
  motivo,
}) {
  const assinaturas =
    await buscarAssinaturasAbertasPorUsuario(usuarioId);

  if (assinaturas.length === 0) {
    return [];
  }

  const accessToken = await obterTokenCobranca();
  const canceladas = [];

  for (const assinatura of assinaturas) {
    const subscriptionId =
      String(
        assinatura?.efi_subscription_id || ''
      ).trim();

    if (!subscriptionId) {
      throw new Error(
        'Existe assinatura recorrente aberta sem efi_subscription_id. O plano avulso não será ativado automaticamente.'
      );
    }

    await cancelarAssinaturaEfiConfirmandoEstado(
      accessToken,
      subscriptionId
    );

    const agora = new Date().toISOString();

    await atualizarAssinaturaPorSubscriptionId(
      subscriptionId,
      {
        status_assinatura: 'cancelado',
        ultimo_status_efi: 'canceled',
        cancelado_em: agora,
        motivo_cancelamento:
          motivo ||
          'Cancelamento automático após confirmação de novo plano avulso.',
        data_inicio_inadimplencia: null,
        data_fim_carencia: null,
      }
    );

    canceladas.push(subscriptionId);

    console.log(
      `>>> Assinatura recorrente ${subscriptionId} cancelada antes da ativação do plano avulso.`
    );
  }

  return canceladas;
}

async function finalizarAtivacaoPlanoAvulsoPago({
  usuarioId,
  planoId,
  dataPagamento = null,
  motivoTroca = null,
}) {
  const idUsuario = String(usuarioId || '').trim();
  const idPlano = String(planoId || '').trim();

  if (!idUsuario || !idPlano) {
    throw new Error(
      'Não foi possível ativar o plano avulso: usuario_id ou plano_id ausente.'
    );
  }

  const assinaturasCanceladas =
    await cancelarAssinaturasAbertasAntesDePlanoAvulso({
      usuarioId: idUsuario,
      motivo:
        motivoTroca ||
        `Troca automática para plano avulso ${idPlano} após pagamento confirmado.`,
    });

  const sincronizacaoUsuario =
    await atualizarPlanoAtivoUsuarioSupabase({
      usuarioId: idUsuario,
      planoId: idPlano,
      recorrente: false,
      dataAtivacao:
        dataPagamento ||
        new Date().toISOString(),
    });

  return {
    ativado: true,
    plano_id: idPlano,
    assinaturas_recorrentes_canceladas:
      assinaturasCanceladas,
    usuario:
      sincronizacaoUsuario.usuario,
    plano:
      sincronizacaoUsuario.plano,
  };
}

async function cancelarAssinaturaEfiPorId(
  accessToken,
  subscriptionId
) {
  const id = String(subscriptionId || '').trim();

  if (!id) {
    throw new Error(
      'efi_subscription_id não informado para cancelamento.'
    );
  }

  return axios({
    method: 'PUT',
    url:
      `${EFI_COBRANCA_API_URL}/subscription/${encodeURIComponent(
        id
      )}/cancel`,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    httpsAgent,
    timeout: 30000,
  });
}

async function atualizarAssinaturaPorSubscriptionId(
  subscriptionId,
  dados
) {
  const {
    supabaseUrl,
  } = obterConfiguracaoSupabase();
 
  const response =
      await requisicaoSupabaseInterna({
    method: 'PATCH',
 
    url:
      `${supabaseUrl}/rest/v1/tab_assinaturas`,
 
    params: {
      efi_subscription_id:
        `eq.${subscriptionId}`,
    },
        headers: {
 
      Prefer:
        'return=representation',
    },
 
    data: dados,
 
    timeout:
      30000,
  });
 
  return Array.isArray(response.data)
    ? response.data[0] || null
    : null;
}
 

// ============================================================
// TROCA SEGURA - ATIVA NOVA ASSINATURA SOMENTE APÓS PAGAMENTO
// ============================================================
//
// Regra:
// - pagamento_pendente pode coexistir com a assinatura vigente;
// - quando a nova cobrança chegar a paid/settled, localiza a
//   assinatura vigente anterior do mesmo usuário;
// - cancela a anterior na Efí;
// - marca a anterior como cancelada no Supabase;
// - somente então promove a nova para ativo.
// ============================================================

async function buscarAssinaturaVigenteAnteriorPorUsuario(
  usuarioId,
  subscriptionIdExcluir = null
) {
  const idUsuario = String(usuarioId || '').trim();

  if (!idUsuario) {
    return null;
  }

  const { supabaseUrl } = obterConfiguracaoSupabase();

  const response = await requisicaoSupabaseInterna({
    method: 'GET',
    url: `${supabaseUrl}/rest/v1/tab_assinaturas`,
    params: {
      select: '*',
      usuario_id: `eq.${idUsuario}`,
      status_assinatura: 'in.(ativo,inadimplente)',
      order: 'created_at.desc',
      limit: 10,
    },
    timeout: 30000,
  });

  const lista = Array.isArray(response.data)
    ? response.data
    : [];

  const excluir = String(subscriptionIdExcluir || '').trim();

  return (
    lista.find((item) => {
      const atual = String(item?.efi_subscription_id || '').trim();
      return !excluir || atual !== excluir;
    }) || null
  );
}

async function cancelarAssinaturaEfiConfirmandoEstado(
  accessToken,
  subscriptionId
) {
  const id = String(subscriptionId || '').trim();

  if (!id) {
    return {
      cancelada: false,
      motivo: 'subscription_id_ausente',
    };
  }

  try {
    await cancelarAssinaturaEfiPorId(
      accessToken,
      id
    );

    return {
      cancelada: true,
      ja_estava_cancelada: false,
    };

  } catch (erroCancelamento) {
    try {
      const assinaturaEfi =
        await consultarAssinaturaEfiPorId(
          accessToken,
          id
        );

      const statusEfi = String(
        assinaturaEfi?.status || ''
      )
        .trim()
        .toLowerCase();

      if (
        statusEfi === 'canceled' ||
        statusEfi === 'cancelled' ||
        statusEfi === 'expired'
      ) {
        return {
          cancelada: true,
          ja_estava_cancelada: true,
          status_efi: statusEfi,
        };
      }
    } catch (erroConsulta) {
      console.error(
        '>>> Falha ao confirmar estado da assinatura antiga após erro de cancelamento:',
        resumirErroSeguro(erroConsulta)
      );
    }

    throw erroCancelamento;
  }
}

async function finalizarAtivacaoAssinaturaPaga({
  assinaturaNova,
  dataPagamento = null,
  accessTokenInformado = null,
  motivoTroca = 'Troca automática após confirmação financeira da nova assinatura.',
}) {
  if (!assinaturaNova?.efi_subscription_id) {
    throw new Error(
      'Não foi possível finalizar a ativação: nova assinatura sem efi_subscription_id.'
    );
  }

  if (!assinaturaNova?.usuario_id) {
    throw new Error(
      'Não foi possível finalizar a ativação: nova assinatura sem usuario_id.'
    );
  }

  const novaSubscriptionId =
    String(assinaturaNova.efi_subscription_id).trim();

  const usuarioId =
    String(assinaturaNova.usuario_id).trim();

  const statusLocalAtual =
    String(assinaturaNova.status_assinatura || '')
      .trim()
      .toLowerCase();

  if (statusLocalAtual === 'ativo') {
    const dataAtivacao =
      normalizarDataIso(dataPagamento) ||
      assinaturaNova.data_ultimo_pagamento ||
      new Date().toISOString();

    const atualizada =
      await atualizarAssinaturaPorSubscriptionId(
        novaSubscriptionId,
        {
          data_ultimo_pagamento:
            dataAtivacao,
          data_inicio_inadimplencia: null,
          data_fim_carencia: null,
        }
      );

    await atualizarPlanoAtivoUsuarioSupabase({
      usuarioId,
      planoId:
        assinaturaNova.plano_id,
      recorrente: true,
      dataAtivacao,
    });

    return {
      ativada: true,
      ja_estava_ativa: true,
      assinatura_nova: atualizada || assinaturaNova,
      assinatura_anterior: null,
    };
  }

  const assinaturaAnterior =
    await buscarAssinaturaVigenteAnteriorPorUsuario(
      usuarioId,
      novaSubscriptionId
    );

  const agora = new Date().toISOString();

  if (assinaturaAnterior) {
    const assinaturaAnteriorId = String(
      assinaturaAnterior.efi_subscription_id || ''
    ).trim();

    if (!assinaturaAnteriorId) {
      throw new Error(
        'Existe assinatura vigente anterior sem efi_subscription_id. A nova não será ativada automaticamente.'
      );
    }

    const accessToken =
      accessTokenInformado ||
      await obterTokenCobranca();

    console.log(
      `>>> Nova assinatura ${novaSubscriptionId} paga. Cancelando assinatura anterior ${assinaturaAnteriorId} antes da ativação.`
    );

    await cancelarAssinaturaEfiConfirmandoEstado(
      accessToken,
      assinaturaAnteriorId
    );

    await atualizarAssinaturaPorSubscriptionId(
      assinaturaAnteriorId,
      {
        status_assinatura: 'cancelado',
        ultimo_status_efi: 'canceled',
        cancelado_em: agora,
        motivo_cancelamento:
          motivoTroca,
        data_inicio_inadimplencia: null,
        data_fim_carencia: null,
      }
    );

    console.log(
      `>>> Assinatura anterior ${assinaturaAnteriorId} cancelada com segurança.`
    );
  }

  const assinaturaNovaAtiva =
    await atualizarAssinaturaPorSubscriptionId(
      novaSubscriptionId,
      {
        status_assinatura: 'ativo',
        data_ultimo_pagamento:
          normalizarDataIso(dataPagamento) ||
          assinaturaNova.data_ultimo_pagamento ||
          agora,
        data_inicio_inadimplencia: null,
        data_fim_carencia: null,
        cancelado_em: null,
        motivo_cancelamento: null,
      }
    );

  if (!assinaturaNovaAtiva) {
    throw new Error(
      'A assinatura anterior foi tratada, mas não foi possível ativar a nova assinatura no Supabase.'
    );
  }

  await atualizarPlanoAtivoUsuarioSupabase({
    usuarioId,
    planoId:
      assinaturaNovaAtiva.plano_id ||
      assinaturaNova.plano_id,
    recorrente: true,
    dataAtivacao:
      normalizarDataIso(dataPagamento) ||
      assinaturaNovaAtiva.data_ultimo_pagamento ||
      agora,
  });

  try {
    await vincularPagamentosRecorrentesOrfaosAssinatura(
      assinaturaNovaAtiva
    );
  } catch (erroVinculo) {
    console.error(
      '>>> Nova assinatura ativada, mas falhou a vinculação de pagamentos recorrentes órfãos:',
      resumirErroSeguro(erroVinculo)
    );
  }

  console.log(
    `>>> Nova assinatura ${novaSubscriptionId} ativada após confirmação financeira.`
  );

  return {
    ativada: true,
    ja_estava_ativa: false,
    assinatura_nova: assinaturaNovaAtiva,
    assinatura_anterior: assinaturaAnterior,
  };
}


async function processarCarenciasVencidas() {
  try {
    const {
      supabaseUrl,
    } = obterConfiguracaoSupabase();
 
    const agora =
      new Date().toISOString();
 
    const response = await axios({
      method: 'PATCH',
 
      url:
        `${supabaseUrl}/rest/v1/tab_assinaturas`,
 
      params: {
        status_assinatura:
          'eq.pagamento_pendente',
 
        data_fim_carencia:
          `lte.${agora}`,
      },
 
      headers: {
        ...obterHeadersSupabase(),
 
        Prefer:
          'return=representation',
      },
 
      data: {
        status_assinatura:
          'inadimplente',
 
        updated_at:
          agora,
      },
 
      timeout:
        30000,
    });
 
    const alteradas =
      Array.isArray(response.data)
        ? response.data.length
        : 0;
 
    if (alteradas > 0) {
      console.log(
        `>>> ${alteradas} assinatura(s) passaram para inadimplente.`
      );
    }
 
    return alteradas;
 
  } catch (error) {
    console.error(
      '>>> Erro ao processar carências vencidas:',
      resumirErroSeguro(error)
    );
 
    return 0;
  }
}
 
async function obterUsuarioSupabaseDoBearer(req) {
  const authorization =
    req.headers.authorization || '';
 
  if (
    !authorization
      .toLowerCase()
      .startsWith('bearer ')
  ) {
    return null;
  }
 
  const token =
    authorization
      .substring(7)
      .trim();
 
  if (!token) {
    return null;
  }
 
  const {
    supabaseUrl,
    supabaseServiceRoleKey,
  } = obterConfiguracaoSupabase();
 
  const response = await axios({
    method: 'GET',
 
    url:
      `${supabaseUrl}/auth/v1/user`,
 
    headers: {
      apikey:
        supabaseServiceRoleKey,
 
      Authorization:
        `Bearer ${token}`,
    },
 
    timeout:
      30000,
  });
 
  return response.data || null;
}
 
async function consultarNotificacaoEfi(
  accessToken,
  notificationToken
) {
  const response = await axios({
    method: 'GET',
 
    url:
      `${EFI_COBRANCA_API_URL}/notification/${encodeURIComponent(
        notificationToken
      )}`,
 
    headers: {
      Authorization:
        `Bearer ${accessToken}`,
 
      'Content-Type':
        'application/json',
    },
 
    httpsAgent,
 
    timeout:
      30000,
  });
 
  return Array.isArray(response.data?.data)
    ? response.data.data
    : [];
}
 
async function aplicarEventoNotificacaoEfi(
  evento,
  notificationToken
) {
  const tipo =
    String(evento?.type || '')
      .trim()
      .toLowerCase();
 
  const statusAtual =
    String(
      evento?.status?.current || ''
    )
      .trim()
      .toLowerCase();
 
  const subscriptionId =
    evento?.identifiers?.subscription_id;
 
  const chargeId =
    evento?.identifiers?.charge_id;
 
  // Eventos sem subscription_id podem pertencer a cobranças avulsas.
  // Além de estorno, conciliamos o pagamento e ativamos o plano imediatamente
  // quando a Efí confirmar paid/settled.
  if (!subscriptionId) {
    if (chargeId) {
      const idCharge = String(chargeId);

      try {
        const pagamentoAvulso =
          await buscarPagamentoAvulsoCartaoPorChargeId(idCharge);

        if (pagamentoAvulso?.id) {
          const pago = statusCobrancaCartaoPago(statusAtual);
          const statusLocalAtual = String(pagamentoAvulso.status || '')
            .trim()
            .toLowerCase();

          if (pago) {
            const dataPagamento =
              normalizarDataIso(evento?.received_by_bank_at) ||
              pagamentoAvulso.data_pagamento ||
              new Date().toISOString();

            const pagamentoAtualizado =
              await atualizarPagamentoAvulsoPorId(
                pagamentoAvulso.id,
                {
                  status: 'pago',
                  data_pagamento: dataPagamento,
                }
              );

            const origemTipo = String(pagamentoAvulso.origem_tipo || '')
              .trim()
              .toLowerCase();
            const planoId = normalizarUuidOuNull(pagamentoAvulso.origem_id);

            let planoAtivado = false;

            if (
              pagamentoAvulso.usuario_id &&
              origemTipo === 'plano_categoria' &&
              planoId
            ) {
              await finalizarAtivacaoPlanoAvulsoPago({
                usuarioId: String(pagamentoAvulso.usuario_id),
                planoId,
                dataPagamento,
                motivoTroca:
                  `Troca para plano avulso ${planoId} após confirmação Efí pelo webhook da cobrança ${idCharge}.`,
              });
              planoAtivado = true;
            }

            console.log(
              `>>> Webhook confirmou cobrança avulsa ${idCharge} como paga. Plano ativado: ${planoAtivado}.`
            );

            return {
              ignorado: false,
              tipo,
              status: statusAtual,
              charge_id: idCharge,
              pagamento_avulso_id: pagamentoAtualizado?.id || pagamentoAvulso.id,
              plano_ativado: planoAtivado,
            };
          }

          // Nunca rebaixa um pagamento já confirmado por evento intermediário.
          if (statusLocalAtual !== 'pago') {
            const statusLocal =
              statusCobrancaCartaoFinalSemPagamento(statusAtual)
                ? (
                    statusAtual === 'refunded'
                      ? 'estornado'
                      : 'recusado'
                  )
                : 'aguardando_pagamento';

            await atualizarPagamentoAvulsoPorId(
              pagamentoAvulso.id,
              { status: statusLocal }
            );
          }
        }

        // Mantém a lógica de estorno pendente já existente.
        const resultadoEstorno = await processarEstornoPendentePorChargeId(
          idCharge,
          statusAtual
        );

        return {
          ignorado: !pagamentoAvulso && !resultadoEstorno?.processado,
          tipo,
          status: statusAtual,
          charge_id: idCharge,
          pagamento_avulso_encontrado: Boolean(pagamentoAvulso),
          estorno_avulso: resultadoEstorno,
        };
      } catch (error) {
        console.error(
          '>>> Erro ao conciliar cobrança avulsa pelo webhook:',
          resumirErroSeguro(error)
        );
        return {
          ignorado: false,
          tipo,
          status: statusAtual,
          charge_id: idCharge,
          erro_avulso: resumirErroSeguro(error),
        };
      }
    }
    return { ignorado: true, motivo: 'evento_sem_subscription_id_e_sem_charge_id' };
  }
 
  const assinatura =
    await buscarAssinaturaPorSubscriptionId(
      String(subscriptionId)
    );
 
  if (!assinatura) {
    console.warn(
      `>>> Webhook Efí: assinatura ${subscriptionId} ainda não existe em tab_assinaturas.`
    );

    // Mesmo em uma corrida de eventos (webhook chegando antes do
    // INSERT da assinatura), preservamos a cobrança pelo charge_id.
    // Os vínculos usuario/plano podem ser preenchidos depois pela
    // sincronização da assinatura sem criar duplicidade.
    let historicoMinimoRegistrado = false;

    if (tipo === 'subscription_charge' && chargeId) {
      await registrarHistoricoPagamentoRecorrente({
        efiSubscriptionId:
          String(subscriptionId),
        chargeId:
          String(chargeId),
        statusEfi:
          statusAtual || null,
        valorCentavosEvento:
          evento?.value ?? null,
        metodoPagamento:
          'credit_card',
        dataCobranca:
          evento?.created_at || null,
        dataPagamento:
          evento?.received_by_bank_at || null,
        notificationToken:
          notificationToken,
        tipoEvento:
          tipo,
        origemRegistro:
          'webhook_antes_assinatura',
      });

      historicoMinimoRegistrado = true;
    }
 
    return {
      ignorado: true,
      motivo: 'assinatura_nao_encontrada',
      subscription_id:
        String(subscriptionId),
      charge_id:
        chargeId
          ? String(chargeId)
          : null,
      historico_recorrente_registrado:
        historicoMinimoRegistrado,
    };
  }
 
  const agora =
    new Date();
 
  // ----------------------------------------------------------
  // HISTÓRICO FINANCEIRO RECORRENTE
  // ----------------------------------------------------------
  // Toda mudança de uma subscription_charge é conciliada pelo
  // efi_charge_id. O UNIQUE + upsert impede duplicidade.
  // ----------------------------------------------------------

  if (tipo === 'subscription_charge' && chargeId) {
    await registrarHistoricoPagamentoRecorrente({
      assinatura:
        assinatura,
      efiSubscriptionId:
        String(subscriptionId),
      efiPlanId:
        assinatura.efi_plan_id || null,
      chargeId:
        String(chargeId),
      statusEfi:
        statusAtual || null,
      valor:
        assinatura.valor_recorrente,
      valorCentavosEvento:
        evento?.value ?? null,
      metodoPagamento:
        'credit_card',
      dataCobranca:
        evento?.created_at || null,
      dataPagamento:
        evento?.received_by_bank_at || null,
      notificationToken:
        notificationToken,
      tipoEvento:
        tipo,
      origemRegistro:
        'webhook',
    });
  }

  const atualizacao = {
    ultimo_status_efi:
      statusAtual || null,
 
    ultima_notificacao_efi_em:
      agora.toISOString(),
 
    ultimo_notification_token:
      notificationToken,
  };
 
  if (chargeId) {
    atualizacao.efi_charge_id =
      String(chargeId);
  }
 
  if (tipo === 'subscription') {
    if (statusAtual === 'active') {
      // A assinatura existe/está ativa, mas o pagamento pode estar pendente.
      if (!assinatura.data_ultimo_pagamento) {
        atualizacao.status_assinatura =
          'pagamento_pendente';
      }

      atualizacao.cancelado_em =
        null;
    }
 
    if (
      statusAtual === 'canceled' ||
      statusAtual === 'expired'
    ) {
      atualizacao.status_assinatura =
        'cancelado';
 
      atualizacao.cancelado_em =
        agora.toISOString();
    }
  }
 
  if (tipo === 'subscription_charge') {
    if (
      statusAtual === 'waiting' ||
      statusAtual === 'pending' ||
      statusAtual === 'approved' ||
      statusAtual === 'authorized' ||
      statusAtual === 'new'
    ) {
      atualizacao.status_assinatura =
        'pagamento_pendente';
    }

    if (
      statusAtual === 'paid' ||
      statusAtual === 'settled'
    ) {
      const dataPagamentoConfirmado =
        normalizarDataIso(
          evento?.received_by_bank_at
        ) || agora.toISOString();

      // Antes de promover a nova assinatura para ativo, cancela com
      // segurança eventual assinatura vigente anterior do usuário.
      // Isso evita colisão com uq_tab_assinaturas_usuario_ativa.
      const finalizacao =
        await finalizarAtivacaoAssinaturaPaga({
          assinaturaNova:
            assinatura,
          dataPagamento:
            dataPagamentoConfirmado,
          motivoTroca:
            `Troca automática confirmada pelo webhook Efí para a assinatura ${String(subscriptionId)}.`,
        });

      atualizacao.status_assinatura =
        'ativo';

      atualizacao.data_ultimo_pagamento =
        dataPagamentoConfirmado;

      atualizacao.data_inicio_inadimplencia =
        null;

      atualizacao.data_fim_carencia =
        null;

      if (finalizacao?.assinatura_anterior) {
        console.log(
          `>>> Webhook concluiu troca segura para ${String(subscriptionId)}.`
        );
      }
    }
 
    if (statusAtual === 'unpaid') {
      atualizacao.status_assinatura =
        'pagamento_pendente';
 
      const inicioExistente =
        assinatura.data_inicio_inadimplencia
          ? new Date(
              assinatura.data_inicio_inadimplencia
            )
          : null;
 
      const inicioValido =
        inicioExistente &&
        !Number.isNaN(
          inicioExistente.getTime()
        );
 
      const inicio =
        inicioValido
          ? inicioExistente
          : agora;
 
      const fimCarencia =
        assinatura.data_fim_carencia
          ? new Date(
              assinatura.data_fim_carencia
            )
          : new Date(
              inicio.getTime() +
              7 * 24 * 60 * 60 * 1000
            );
 
      atualizacao.data_inicio_inadimplencia =
        inicio.toISOString();
 
      atualizacao.data_fim_carencia =
        Number.isNaN(
          fimCarencia.getTime()
        )
          ? new Date(
              agora.getTime() +
              7 * 24 * 60 * 60 * 1000
            ).toISOString()
          : fimCarencia.toISOString();
    }
  }
 
  await atualizarAssinaturaPorSubscriptionId(
    String(subscriptionId),
    atualizacao
  );
 
  return {
    ignorado: false,
    tipo,
    status:
      statusAtual,
    subscription_id:
      String(subscriptionId),
    charge_id:
      chargeId
        ? String(chargeId)
        : null,
  };
}
 
// ============================================================
// SUPABASE - CONSULTAR PLANOS RECORRENTES
// ============================================================
 
async function buscarPlanosRecorrentesSupabase() {
 
  const {
    supabaseUrl,
  } = obterConfiguracaoSupabase();
 
  const response =
    await axios({
      method: 'GET',
 
      url:
        `${supabaseUrl}/rest/v1/tab_planos`,
 
      params: {
        select:
          'id,nome_plano,valor,valor_recorrente,efi_plan_id,recorrencia_ativa,efi_sync_status,efi_sync_error,efi_sync_at,status,tipo_usuario',
 
        valor_recorrente:
          'gt.0',
      },
 
      headers:
        obterHeadersSupabase(),
 
      timeout:
        30000,
    });
 
  return Array.isArray(
    response.data
  )
    ? response.data
    : [];
}
 
// ============================================================
// SUPABASE - ATUALIZAR UM PLANO
// ============================================================
 
async function atualizarPlanoSupabase(
  planoId,
  dados
) {
 
  const {
    supabaseUrl,
  } = obterConfiguracaoSupabase();
 
  const response =
    await axios({
      method: 'PATCH',
 
      url:
        `${supabaseUrl}/rest/v1/tab_planos`,
 
      params: {
        id:
          `eq.${planoId}`,
      },
 
      headers: {
        ...obterHeadersSupabase(),
 
        Prefer:
          'return=representation',
      },
 
      data:
        dados,
 
      timeout:
        30000,
    });
 
  return Array.isArray(
    response.data
  )
    ? response.data[0] || null
    : null;
}
 
// ============================================================
// EFÍ - NOME ÚNICO E ESTÁVEL DO PLANO
// ============================================================
//
// Incluímos o UUID interno do Supabase no nome.
//
// Assim, se houver falha após criar na Efí e antes de gravar
// efi_plan_id no banco, uma nova sincronização consegue localizar
// o plano já criado e evita duplicidade.
// ============================================================
 
function montarNomePlanoEfi(plano) {
 
  const nomeBase =
    String(
      plano.nome_plano ||
      'Plano'
    )
      .trim()
      .replace(/\s+/g, ' ');
 
  return (
    `Ache Obra - ${nomeBase} - ${plano.id}`
  );
}
 
// ============================================================
// EFÍ - LOCALIZAR PLANO EXISTENTE PELO NOME
// ============================================================
 
async function localizarPlanoEfiPorNome(
  accessToken,
  nomePlanoEfi
) {
 
  const response =
    await axios({
      method: 'GET',
 
      url:
        `${EFI_COBRANCA_API_URL}/plans`,
 
      headers: {
        Authorization:
          `Bearer ${accessToken}`,
 
        'Content-Type':
          'application/json',
      },
 
      params: {
        name:
          nomePlanoEfi,
 
        limit:
          100,
 
        offset:
          0,
      },
 
      httpsAgent,
 
      timeout:
        30000,
    });
 
  const lista =
    Array.isArray(
      response.data?.data
    )
      ? response.data.data
      : [];
 
  return (
    lista.find(
      (item) =>
        String(
          item?.name || ''
        ).trim() === nomePlanoEfi
    ) || null
  );
}
 
// ============================================================
// EFÍ - CRIAR PLANO MENSAL
// ============================================================
//
// interval = 1:
// cobrança mensal.
//
// repeats = null:
// recorrência por prazo indeterminado, até cancelamento.
// ============================================================
 
async function criarPlanoMensalEfi(
  accessToken,
  nomePlanoEfi
) {
 
  const response =
    await axios({
      method: 'POST',
 
      url:
        `${EFI_COBRANCA_API_URL}/plan`,
 
      headers: {
        Authorization:
          `Bearer ${accessToken}`,
 
        'Content-Type':
          'application/json',
      },
 
      data: {
        name:
          nomePlanoEfi,
 
        interval:
          1,
 
        repeats:
          null,
      },
 
      httpsAgent,
 
      timeout:
        30000,
    });
 
  const planoCriado =
    response.data?.data;
 
  const planId =
    planoCriado?.plan_id;
 
  if (!planId) {
    throw new Error(
      'A Efí não retornou plan_id ao criar o plano.'
    );
  }
 
  return planoCriado;
}
 
// ============================================================
// SEGURANÇA DA ROTA ADMINISTRATIVA DE SINCRONIZAÇÃO
// ============================================================
 
function validarSyncSecret(req) {
 
  const secretEsperado =
    process.env
      .SYNC_PLANOS_SECRET
      ?.trim();
 
  if (!secretEsperado) {
    throw new Error(
      'SYNC_PLANOS_SECRET não configurado no Render.'
    );
  }
 
  const headerDireto =
    req.headers[
      'x-sync-secret'
    ];
 
  const authorization =
    req.headers.authorization;
 
  let recebido =
    headerDireto
      ? String(headerDireto).trim()
      : '';
 
  if (
    !recebido &&
    authorization &&
    authorization
      .toLowerCase()
      .startsWith('bearer ')
  ) {
    recebido =
      authorization
        .substring(7)
        .trim();
  }
 
  return recebido ===
    secretEsperado;
}
 
// Impede duas sincronizações simultâneas na mesma instância.
 
let sincronizacaoPlanosEmAndamento =
  false;
 
// ============================================================
// ROTA ADMINISTRATIVA - SINCRONIZAR PLANOS COM A EFÍ
// ============================================================
//
// POST /sincronizar-planos-efi
//
// Autenticação:
//
// X-Sync-Secret:
// <SYNC_PLANOS_SECRET>
//
// ou:
//
// Authorization:
// Bearer <SYNC_PLANOS_SECRET>
//
// Funcionamento:
//
// 1. Lê tab_planos com valor_recorrente > 0.
// 2. Se já possui efi_plan_id, não cria novamente.
// 3. Se não possui, procura na Efí pelo nome determinístico.
// 4. Se já existir na Efí, reaproveita o plan_id.
// 5. Caso contrário, cria o plano mensal.
// 6. Salva efi_plan_id e status da sincronização no Supabase.
// ============================================================
 
app.post(
  '/sincronizar-planos-efi',
 
  async (req, res) => {
 
    if (
      sincronizacaoPlanosEmAndamento
    ) {
      return res
        .status(409)
        .json({
          success:
            false,
 
          error:
            'Já existe uma sincronização de planos em andamento.',
        });
    }
 
    try {
 
      if (!validarSyncSecret(req)) {
        return res
          .status(401)
          .json({
            success:
              false,
 
            error:
              'Não autorizado.',
          });
      }
 
      obterConfiguracaoSupabase();
 
      sincronizacaoPlanosEmAndamento =
        true;
 
      console.log(
        '=========================================='
      );
 
      console.log(
        '>>> INICIANDO SINCRONIZAÇÃO DOS PLANOS EFÍ'
      );
 
      console.log(
        '=========================================='
      );
 
      const planos =
        await buscarPlanosRecorrentesSupabase();
 
      const accessToken =
        await obterTokenCobranca();
 
      const resultados = [];
 
      let criados = 0;
      let reaproveitados = 0;
      let jaSincronizados = 0;
      let erros = 0;
 
      for (
        const plano of planos
      ) {
 
        const planoIdSupabase =
          plano.id;
 
        const nomePlano =
          String(
            plano.nome_plano ||
            'Plano'
          ).trim();
 
        const efiPlanIdAtual =
          plano.efi_plan_id
            ? String(
                plano.efi_plan_id
              ).trim()
            : '';
 
        // ------------------------------------------------------
        // Plano já sincronizado
        // ------------------------------------------------------
 
        if (efiPlanIdAtual) {
 
          jaSincronizados +=
            1;
 
          resultados.push({
            id:
              planoIdSupabase,
 
            nome_plano:
              nomePlano,
 
            status:
              'ja_sincronizado',
 
            efi_plan_id:
              efiPlanIdAtual,
          });
 
          continue;
        }
 
        try {
 
          await atualizarPlanoSupabase(
            planoIdSupabase,
            {
              efi_sync_status:
                'sincronizando',
 
              efi_sync_error:
                null,
            }
          );
 
          const nomePlanoEfi =
            montarNomePlanoEfi(
              plano
            );
 
          console.log(
            `>>> Sincronizando plano: ${nomePlano}`
          );
 
          let planoEfi =
            await localizarPlanoEfiPorNome(
              accessToken,
              nomePlanoEfi
            );
 
          let origem =
            'existente';
 
          if (!planoEfi) {
 
            planoEfi =
              await criarPlanoMensalEfi(
                accessToken,
                nomePlanoEfi
              );
 
            origem =
              'criado';
 
            criados +=
              1;
 
          } else {
 
            reaproveitados +=
              1;
          }
 
          const planIdEfi =
            planoEfi.plan_id;
 
          if (!planIdEfi) {
            throw new Error(
              'Plano localizado/criado sem plan_id válido.'
            );
          }
 
          const agoraIso =
            new Date()
              .toISOString();
 
          await atualizarPlanoSupabase(
            planoIdSupabase,
            {
              efi_plan_id:
                String(
                  planIdEfi
                ),
 
              recorrencia_ativa:
                true,
 
              efi_sync_status:
                'sincronizado',
 
              efi_sync_error:
                null,
 
              efi_sync_at:
                agoraIso,
            }
          );
 
          console.log(
            `>>> Plano sincronizado: ${nomePlano} -> Efí ${planIdEfi}`
          );
 
          resultados.push({
            id:
              planoIdSupabase,
 
            nome_plano:
              nomePlano,
 
            status:
              'sincronizado',
 
            origem:
              origem,
 
            efi_plan_id:
              String(
                planIdEfi
              ),
          });
 
        } catch (erroPlano) {
 
          erros += 1;
 
          const respostaEfi =
            erroPlano
              .response
              ?.data;
 
          let mensagemErro =
            respostaEfi
              ?.error_description ||
            respostaEfi
              ?.mensagem ||
            respostaEfi
              ?.message ||
            respostaEfi
              ?.error ||
            erroPlano.message ||
            'Erro desconhecido';
 
          if (
            typeof mensagemErro !==
            'string'
          ) {
            mensagemErro =
              JSON.stringify(
                mensagemErro
              );
          }
 
          console.error(
            `>>> ERRO no plano "${nomePlano}":`,
            sanitizarTextoSeguro(mensagemErro)
          );
 
          try {
 
            await atualizarPlanoSupabase(
              planoIdSupabase,
              {
                recorrencia_ativa:
                  false,
 
                efi_sync_status:
                  'erro',
 
                efi_sync_error:
                  mensagemErro.substring(
                    0,
                    2000
                  ),
 
                efi_sync_at:
                  new Date()
                    .toISOString(),
              }
            );
 
          } catch (
            erroAtualizacao
          ) {
 
            console.error(
              '>>> Também falhou ao registrar o erro no Supabase:',
              resumirErroSeguro(erroAtualizacao)
            );
          }
 
          resultados.push({
            id:
              planoIdSupabase,
 
            nome_plano:
              nomePlano,
 
            status:
              'erro',
 
            error:
              mensagemErro,
          });
        }
      }
 
      console.log(
        '=========================================='
      );
 
      console.log(
        '>>> SINCRONIZAÇÃO FINALIZADA'
      );
 
      console.log(
        `>>> Criados: ${criados}`
      );
 
      console.log(
        `>>> Reaproveitados: ${reaproveitados}`
      );
 
      console.log(
        `>>> Já sincronizados: ${jaSincronizados}`
      );
 
      console.log(
        `>>> Erros: ${erros}`
      );
 
      console.log(
        '=========================================='
      );
 
      return res.json({
        success:
          erros === 0,
 
        total:
          planos.length,
 
        criados:
          criados,
 
        reaproveitados:
          reaproveitados,
 
        ja_sincronizados:
          jaSincronizados,
 
        erros:
          erros,
 
        resultados:
          resultados,
      });
 
    } catch (error) {
 
      console.error(
        '=========================================='
      );
 
      console.error(
        'ERRO GERAL NA SINCRONIZAÇÃO DOS PLANOS'
      );
 
      console.error(
        '=========================================='
      );
 
      console.error(
        resumirErroSeguro(error)
      );
 
      return res
        .status(
          error.response
            ?.status ||
          500
        )
        .json({
          success:
            false,
 
          error:
            resumirErroSeguro(error),
        });
 
    } finally {
 
      sincronizacaoPlanosEmAndamento =
        false;
    }
  }
);
 
// ============================================================
// 1. PIX
// ============================================================
 
app.post(
  '/gerar-pix',
 
  async (req, res) => {
 
    try {
 
      const {
        valor,
        cpf,
        nome,
        descricao,
        usuario_id,
        origem_tipo,
        origem_id,
      } = req.body;
 
      if (!valor || !cpf) {
 
        return res
          .status(400)
          .json({
            error:
              'Valor e CPF são obrigatórios.',
          });
      }
 
      if (
        !process.env.EFI_PIX_KEY
      ) {
 
        return res
          .status(500)
          .json({
            error:
              'Variável EFI_PIX_KEY não configurada no Render.',
          });
      }
 
      const accessToken =
        await obterTokenPix();
 
      const cpfLimpo =
        String(cpf)
          .replace(/\D/g, '');
 
      const payloadCob = {
        calendario: {
          expiracao:
            3600,
        },
 
        valor: {
          original:
            Number(valor)
              .toFixed(2),
        },
 
        chave:
          process.env.EFI_PIX_KEY,
 
        devedor: {
          cpf:
            cpfLimpo,
 
          nome:
            nome ||
            'Cliente Ache Obra',
        },
      };
 
      const responseCob =
        await axios({
          method:
            'POST',
 
          url:
            EFI_PIX_COB_URL,
 
          headers: {
            Authorization:
              `Bearer ${accessToken}`,
 
            'Content-Type':
              'application/json',
          },
 
          data:
            payloadCob,
 
          httpsAgent,
 
          timeout:
            30000,
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
 
      if (
        !copiaECola &&
        locId
      ) {
 
        const responseQr =
          await axios({
            method:
              'GET',
 
            url:
              `https://pix.api.efipay.com.br/v2/loc/${locId}`,
 
            headers: {
              Authorization:
                `Bearer ${accessToken}`,
            },
 
            httpsAgent,
 
            timeout:
              30000,
          });
 
        copiaECola =
          responseQr.data
            .pixCopiaECola ||
          responseQr.data
            .pix_copia_e_cola;
      }
 
      let pagamentoAvulsoSalvo = null;
      let erroRegistroPagamentoAvulso = null;

      if (usuario_id && txid) {
        try {
          const valorNumerico = Number(valor);

          pagamentoAvulsoSalvo =
            await inserirPagamentoAvulsoSupabase({
              usuario_id: String(usuario_id),
              origem_tipo: origem_tipo ? String(origem_tipo) : null,
              origem_id: normalizarUuidOuNull(origem_id),
              tipo_pagamento: 'pix',
              valor: Number.isFinite(valorNumerico) ? valorNumerico : 0,
              efi_charge_id: null,
              pix_txid: String(txid),
              pix_e2e_id: null,
              status: 'aguardando_pagamento',
              data_pagamento: null,
              estorno_solicitado_em: null,
              estorno_concluido_em: null,
              motivo_cancelamento: null,
            });

          console.log(
            '>>> Cobrança Pix registrada em tab_pagamentos_avulsos:',
            pagamentoAvulsoSalvo?.id || 'ID não retornado',
            '| txid:',
            txid
          );
        } catch (erroRegistroPagamento) {
          erroRegistroPagamentoAvulso =
            erroRegistroPagamento.response?.data ||
            erroRegistroPagamento.message;

          console.error(
            '>>> Pix gerado, mas falhou ao registrar em tab_pagamentos_avulsos:',
            resumirErroSeguro(erroRegistroPagamentoAvulso)
          );
        }
      }

      return res.json({
        success: true,
        txid: txid,
        pix_copia_e_cola: copiaECola,
        pagamento_avulso_id:
          pagamentoAvulsoSalvo?.id || null,
        registro_pagamento_salvo:
          pagamentoAvulsoSalvo != null,
        erro_registro_pagamento:
          erroRegistroPagamentoAvulso,
      });
 
    } catch (error) {
 
      console.error(
        'Erro ao gerar Pix:',
        resumirErroSeguro(error)
      );
 
      return res
        .status(
          error.response
            ?.status ||
          500
        )
        .json({
          error:
            error.response
              ?.data
              ?.mensagem ||
            error.response
              ?.data
              ?.message ||
            error.response
              ?.data
              ?.error ||
            error.message,
        });
    }
  }
);
 
// ============================================================
// 1.1 CONSULTAR / CONFIRMAR PAGAMENTO PIX
// ============================================================

app.get(
  '/status-pix/:txid',

  async (req, res) => {
    try {
      const usuario =
        await obterUsuarioSupabaseDoBearer(req);

      if (!usuario?.id) {
        return res.status(401).json({
          success: false,
          error: 'Usuário não autenticado.',
        });
      }

      const txid =
        String(req.params?.txid || '').trim();

      if (!txid) {
        return res.status(400).json({
          success: false,
          error: 'txid é obrigatório.',
        });
      }

      const pagamento =
        await buscarPagamentoAvulsoPixPorTxid(
          txid,
          usuario.id
        );

      if (!pagamento) {
        return res.status(404).json({
          success: false,
          error:
            'Pagamento Pix não encontrado para este usuário.',
        });
      }

      const resultado =
        await sincronizarPagamentoPixPorTxid(
          txid,
          usuario.id
        );

      let trocaPlanoConcluida = null;
      let erroTrocaPlano = null;

      const pagamentoAtual =
        resultado.pagamento ||
        pagamento;

      const origemTipo =
        String(
          pagamentoAtual?.origem_tipo || ''
        )
          .trim()
          .toLowerCase();

      const planoIdAvulso =
        normalizarUuidOuNull(
          pagamentoAtual?.origem_id
        );

      if (
        resultado.pago &&
        origemTipo === 'plano_categoria' &&
        planoIdAvulso
      ) {
        try {
          await finalizarAtivacaoPlanoAvulsoPago({
            usuarioId:
              usuario.id,
            planoId:
              planoIdAvulso,
            dataPagamento:
              pagamentoAtual?.data_pagamento ||
              new Date().toISOString(),
            motivoTroca:
              `Troca para plano avulso ${planoIdAvulso} após confirmação do Pix ${txid}.`,
          });

          trocaPlanoConcluida = true;

        } catch (erroTroca) {
          trocaPlanoConcluida = false;
          erroTrocaPlano =
            resumirErroSeguro(erroTroca);

          console.error(
            '>>> Pix confirmado, mas a troca segura de plano avulso ainda não foi concluída:',
            erroTrocaPlano
          );
        }
      }

      const liberarPlano =
        resultado.pago &&
        trocaPlanoConcluida !== false;

      return res.json({
        success: true,
        pago: liberarPlano,
        pagamento_confirmado:
          resultado.pago,
        troca_plano:
          trocaPlanoConcluida,
        erro_troca_plano:
          erroTrocaPlano,
        status:
          liberarPlano
            ? 'pago'
            : (
                resultado.pago
                  ? 'pagamento_confirmado_aguardando_troca'
                  : 'aguardando_pagamento'
              ),
        status_efi: resultado.status_efi,
        txid: resultado.txid,
        e2e_id: resultado.e2e_id,
        pagamento: pagamentoAtual,
      });

    } catch (error) {
      console.error(
        '>>> ERRO AO CONSULTAR STATUS PIX:',
        resumirErroSeguro(error)
      );

      return res
        .status(error.response?.status || 500)
        .json({
          success: false,
          error:
            resumirErroSeguro(error),
        });
    }
  }
);


// ============================================================
// 2. COBRANÇA AVULSA COM CARTÃO
// ============================================================
 
app.post(
  '/cobrar-cartao',
 
  async (req, res) => {
 
    try {
 
      const {
        valor,
        email,
        nome,
        cpf,
        telefone,
        payment_token,
        descricao,
        parcelas,
        usuario_id,
        origem_tipo,
        origem_id,
      } = req.body;
 
      console.log(
        '=========================================='
      );
 
      console.log(
        '>>> Nova solicitação de cobrança por cartão.'
      );
 
      console.log(
        '=========================================='
      );
 
      // --------------------------------------------------------
      // VALIDAÇÕES
      // --------------------------------------------------------
 
      if (!valor) {
 
        return res
          .status(400)
          .json({
            error:
              'Valor é obrigatório.',
          });
      }
 
      if (!nome) {
 
        return res
          .status(400)
          .json({
            error:
              'Nome do titular é obrigatório.',
          });
      }
 
      if (!cpf) {
 
        return res
          .status(400)
          .json({
            error:
              'CPF do titular é obrigatório.',
          });
      }
 
      if (!email) {
 
        return res
          .status(400)
          .json({
            error:
              'E-mail do titular é obrigatório.',
          });
      }
 
      if (!payment_token) {
 
        return res
          .status(400)
          .json({
            error:
              'payment_token é obrigatório.',
          });
      }
 
      if (!telefone) {
 
        return res
          .status(400)
          .json({
            error:
              'Telefone do titular é obrigatório.',
          });
      }
 
      const valorNumerico =
        Number(valor);
 
      if (
        !Number.isFinite(
          valorNumerico
        ) ||
        valorNumerico <= 0
      ) {
 
        return res
          .status(400)
          .json({
            error:
              'Valor inválido.',
          });
      }
 
      const valorCentavos =
        Math.round(
          valorNumerico *
          100
        );
 
      const cpfLimpo =
        String(cpf)
          .replace(/\D/g, '');
 
      if (
        cpfLimpo.length !==
        11
      ) {
 
        return res
          .status(400)
          .json({
            error:
              'CPF inválido.',
          });
      }
 
      let telefoneLimpo =
        String(telefone)
          .replace(/\D/g, '');
 
      if (
        telefoneLimpo
          .startsWith('55') &&
        (
          telefoneLimpo.length ===
            12 ||
          telefoneLimpo.length ===
            13
        )
      ) {
 
        telefoneLimpo =
          telefoneLimpo
            .substring(2);
      }
 
      if (
        telefoneLimpo.length !==
          10 &&
        telefoneLimpo.length !==
          11
      ) {
 
        return res
          .status(400)
          .json({
            error:
              'Telefone inválido. Informe DDD + número, com 10 ou 11 dígitos.',
          });
      }
 
      const installments =
        Number(parcelas) > 0
          ? Number(parcelas)
          : 1;
 
      // --------------------------------------------------------
      // METADATA - CUSTOM_ID CORRIGIDO
      // --------------------------------------------------------
 
      const customId =
        montarCustomId({
          usuario_id,
          origem_tipo,
          origem_id,
          prefixo:
            'acheobra-pagamento',
        });
 
      console.log(
        '>>> Custom ID ref:',
        referenciaSegura(customId)
      );
 
      // --------------------------------------------------------
      // PAYLOAD OFICIAL DA COBRANÇA DE CARTÃO
      // --------------------------------------------------------
 
      const payload = {
        items: [
          {
            name:
              descricao ||
              'Pagamento Ache Obra',
 
            value:
              valorCentavos,
 
            amount:
              1,
          },
        ],
 
        metadata: {
          custom_id:
            customId,
        },
 
        payment: {
          credit_card: {
            customer: {
              name:
                String(nome)
                  .trim(),
 
              cpf:
                cpfLimpo,
 
              email:
                String(email)
                  .trim()
                  .toLowerCase(),
 
              phone_number:
                telefoneLimpo,
            },
 
            installments:
              installments,
 
            payment_token:
              payment_token,
          },
        },
      };
 
      const accessToken =
        await obterTokenCobranca();
 
      console.log(
        '>>> Enviando cobrança para API Cobranças Efí...'
      );
 
      const response =
        await axios({
          method:
            'POST',
 
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
 
          timeout:
            30000,
        });
 
      const dados =
        response.data;
 
      const chargeId =
        dados?.data
          ?.charge_id;
 
      let status =
        dados?.data
          ?.status;
 
      const refusal =
        dados?.data
          ?.refusal ||
        null;

      // A Efí pode responder "approved" antes de registrar "paid".
      // Aguarda a confirmação por alguns segundos para que o plano seja
      // ativado ANTES de o Flutter receber pagamento_confirmado=true.
      if (chargeId && !statusCobrancaCartaoPago(status)) {
        const confirmacaoImediata =
          await aguardarConfirmacaoCobrancaCartaoEfi(
            accessToken,
            chargeId,
            { statusInicial: status }
          );

        if (confirmacaoImediata?.status) {
          status = confirmacaoImediata.status;
        }
      }
 
      console.log(
        '>>> Cobrança processada pela Efí.'
      );
 
      console.log(
        '>>> Status:',
        status
      );
 
      console.log(
        '>>> Charge ID:',
        chargeId
      );
 
      if (refusal) {
 
        console.log(
          '>>> Motivo da recusa:',
          refusal.reason ||
          'não informado'
        );
 
        console.log(
          '>>> Pode tentar novamente:',
          refusal.retry
        );
      }
 
      // CONFIRMAÇÃO DEFINITIVA + HISTÓRICO DO CARTÃO AVULSO
      const statusNormalizado =
        String(status || '').trim().toLowerCase();

      const pagamentoConfirmado =
        statusNormalizado === 'paid' ||
        statusNormalizado === 'settled';

      const statusLocal =
        pagamentoConfirmado
          ? 'pago'
          : (
              statusNormalizado === 'refused' ||
              statusNormalizado === 'declined' ||
              statusNormalizado === 'canceled' ||
              statusNormalizado === 'cancelled'
                ? 'recusado'
                : 'aguardando_pagamento'
            );

      let pagamentoAvulsoSalvo = null;
      let erroRegistroPagamentoAvulso = null;

      if (usuario_id && chargeId) {
        try {
          const existente =
            await buscarPagamentoAvulsoCartaoPorChargeId(
              String(chargeId)
            );

          if (existente?.id) {
            pagamentoAvulsoSalvo =
              await atualizarPagamentoAvulsoPorId(
                existente.id,
                {
                  status: statusLocal,
                  data_pagamento:
                    pagamentoConfirmado
                      ? (
                          existente.data_pagamento ||
                          new Date().toISOString()
                        )
                      : null,
                }
              );
          } else {
            pagamentoAvulsoSalvo =
              await inserirPagamentoAvulsoSupabase({
                usuario_id: String(usuario_id),
                origem_tipo: origem_tipo ? String(origem_tipo) : null,
                origem_id: normalizarUuidOuNull(origem_id),
                tipo_pagamento: 'cartao',
                valor: valorNumerico,
                efi_charge_id: String(chargeId),
                pix_txid: null,
                pix_e2e_id: null,
                status: statusLocal,
                data_pagamento:
                  pagamentoConfirmado
                    ? new Date().toISOString()
                    : null,
                estorno_solicitado_em: null,
                estorno_concluido_em: null,
                motivo_cancelamento: null,
              });
          }

          console.log(
            '>>> Histórico cartão salvo:',
            pagamentoAvulsoSalvo?.id || 'ID não retornado',
            '| local:',
            statusLocal,
            '| Efí:',
            statusNormalizado || 'não informado'
          );
        } catch (erroRegistroPagamento) {
          erroRegistroPagamentoAvulso =
            erroRegistroPagamento.response?.data ||
            erroRegistroPagamento.message;

          console.error(
            '>>> Charge criada na Efí, mas falhou o histórico no Supabase:',
            resumirErroSeguro(erroRegistroPagamentoAvulso)
          );
        }
      } else {
        erroRegistroPagamentoAvulso =
          'usuario_id ou charge_id ausente.';
      }

 
      let trocaPlanoConcluida = null;
      let erroTrocaPlano = null;

      const origemTipoNormalizada =
        String(origem_tipo || '')
          .trim()
          .toLowerCase();

      const planoIdAvulso =
        normalizarUuidOuNull(origem_id);

      if (
        pagamentoConfirmado &&
        usuario_id &&
        origemTipoNormalizada === 'plano_categoria' &&
        planoIdAvulso
      ) {
        try {
          await finalizarAtivacaoPlanoAvulsoPago({
            usuarioId:
              String(usuario_id),
            planoId:
              planoIdAvulso,
            dataPagamento:
              pagamentoAvulsoSalvo?.data_pagamento ||
              new Date().toISOString(),
            motivoTroca:
              `Troca para plano avulso ${planoIdAvulso} após confirmação da cobrança ${String(chargeId)}.`,
          });

          trocaPlanoConcluida = true;

        } catch (erroTroca) {
          trocaPlanoConcluida = false;
          erroTrocaPlano =
            resumirErroSeguro(erroTroca);

          console.error(
            '>>> Cartão avulso pago, mas a troca segura de plano ainda não foi concluída:',
            erroTrocaPlano
          );
        }
      }

      const liberarPlano =
        pagamentoConfirmado &&
        trocaPlanoConcluida !== false;

      return res.json({
        success:
          true,
 
        approved:
          liberarPlano,

        pago:
          pagamentoConfirmado,

        pagamento_confirmado:
          pagamentoConfirmado,

        troca_plano:
          trocaPlanoConcluida,

        erro_troca_plano:
          erroTrocaPlano,
 
        charge_id:
          chargeId,
 
        
        pagamento_avulso_id:
          pagamentoAvulsoSalvo?.id ||
          null,

        registro_pagamento_salvo:
          pagamentoAvulsoSalvo != null,

        erro_registro_pagamento:
          erroRegistroPagamentoAvulso,

status:
          status,
 
        payment:
          dados?.data
            ?.payment,
 
        installments:
          dados?.data
            ?.installments,
 
        installment_value:
          dados?.data
            ?.installment_value,
 
        total:
          dados?.data
            ?.total,
 
        refusal:
          refusal,
 
        reason:
          refusal?.reason ||
          null,
 
        retry:
          refusal?.retry ??
          null,
 
        data:
          dados?.data,
      });
 
    } catch (error) {
 
      console.error(
        '=========================================='
      );
 
      console.error(
        'ERRO NA COBRANÇA COM CARTÃO'
      );
 
      console.error(
        '=========================================='
      );
 
      console.error(
        'HTTP:',
        error.response?.status
      );
 
      console.error(
        'Resposta Efí (segura):',
        resumirErroSeguro(error)
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
 
      const descricaoErro =
        respostaEfi
          ?.error_description;
 
      let mensagem =
        respostaEfi
          ?.mensagem ||
        respostaEfi
          ?.message ||
        respostaEfi
          ?.error ||
        error.message;
 
      if (
        typeof descricaoErro ===
        'string'
      ) {
 
        mensagem =
          descricaoErro;
 
      } else if (
        descricaoErro
      ) {
 
        mensagem =
          JSON.stringify(
            descricaoErro
          );
      }
 
      // --------------------------------------------------------
      // ERRO DE REGRA EFÍ: RECEBEDOR E PAGADOR/TITULAR
      // --------------------------------------------------------
      //
      // Em produção a Efí pode impedir uma cobrança quando identifica
      // que o recebedor da conta e a pessoa pagadora/titular envolvida
      // na transação são a mesma pessoa. Esse retorno NÃO representa
      // falha técnica do Render e não deve ser mascarado como HTTP 500
      // interno do Ache Obra.
      //
      // Importante: o backend não tenta contornar essa validação e não
      // altera CPF/nome/payment_token. Os dados do customer continuam
      // sendo exatamente os dados do titular enviados pelo Flutter.
      // --------------------------------------------------------

      const mensagemNormalizada =
        String(mensagem || '')
          .trim()
          .toLowerCase();

      const recebedorEhCliente =
        mensagemNormalizada.includes(
          'recebedor e cliente não podem ser a mesma pessoa'
        ) ||
        mensagemNormalizada.includes(
          'recebedor e cliente nao podem ser a mesma pessoa'
        );

      if (recebedorEhCliente) {
        console.warn(
          '>>> Cobrança recusada por regra da Efí: recebedor e pessoa pagadora/titular identificados como a mesma pessoa.'
        );

        return res
          .status(422)
          .json({
            success: false,
            approved: false,
            codigo: 'EFI_RECEBEDOR_IGUAL_CLIENTE',
            error:
              'A Efí não permite concluir esta cobrança porque identificou o recebedor e a pessoa pagadora/titular como a mesma pessoa. Use um cartão pertencente a outra pessoa, com o nome e CPF reais do titular do cartão.',
            efi: respostaEfi || null,
          });
      }

      return res
        .status(
          error.response
            ?.status ||
          500
        )
        .json({
          success:
            false,
 
          approved:
            false,
 
          error:
            mensagem,
 
          efi:
            respostaEfi ||
            null,
        });
    }
  }
);
 
// ============================================================
// 3. ASSINATURA RECORRENTE NO CARTÃO
// ============================================================
//
// Fluxo:
//
// Flutter gera payment_token
//   -> POST /cobrar-assinatura
//   -> backend usa o plan_id da Efí
//   -> POST /v1/plan/:id/subscription/one-step
//
// IMPORTANTE:
//
// O plan_id recebido aqui deve ser o ID DO PLANO NA EFÍ
// salvo em tab_planos.efi_plan_id.
// ============================================================
 
app.post(
  '/cobrar-assinatura',
 
  async (req, res) => {
 
    try {
 
      const {
        valor,
        email,
        nome,
        cpf,
        telefone,
        payment_token,
        descricao,
        plan_id,
        usuario_id,
        origem_tipo,
        origem_id,
      } = req.body;
 
      console.log(
        '=========================================='
      );
 
      console.log(
        '>>> Nova solicitação de assinatura recorrente.'
      );
 
      console.log(
        '=========================================='
      );
 
      // --------------------------------------------------------
      // VALIDAÇÕES
      // --------------------------------------------------------
 
      if (!plan_id) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'plan_id da Efí é obrigatório para criar a assinatura.',
          });
      }
 
      if (!valor) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'Valor da assinatura é obrigatório.',
          });
      }
 
      if (!nome) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'Nome do titular é obrigatório.',
          });
      }
 
      if (!cpf) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'CPF do titular é obrigatório.',
          });
      }
 
      if (!email) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'E-mail do titular é obrigatório.',
          });
      }
 
      if (!telefone) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'Telefone do titular é obrigatório.',
          });
      }
 
      if (!payment_token) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'payment_token é obrigatório.',
          });
      }
 
      const valorNumerico =
        Number(valor);
 
      if (
        !Number.isFinite(
          valorNumerico
        ) ||
        valorNumerico <= 0
      ) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'Valor da assinatura inválido.',
          });
      }
 
      const valorCentavos =
        Math.round(
          valorNumerico *
          100
        );
 
      const cpfLimpo =
        String(cpf)
          .replace(/\D/g, '');
 
      if (
        cpfLimpo.length !==
        11
      ) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'CPF inválido.',
          });
      }
 
      let telefoneLimpo =
        String(telefone)
          .replace(/\D/g, '');
 
      if (
        telefoneLimpo
          .startsWith('55') &&
        (
          telefoneLimpo.length ===
            12 ||
          telefoneLimpo.length ===
            13
        )
      ) {
 
        telefoneLimpo =
          telefoneLimpo
            .substring(2);
      }
 
      if (
        telefoneLimpo.length !==
          10 &&
        telefoneLimpo.length !==
          11
      ) {
 
        return res
          .status(400)
          .json({
            success:
              false,
 
            error:
              'Telefone inválido. Informe DDD + número.',
          });
      }
 
      const planIdEfi =
        String(plan_id)
          .trim();
 
      const accessToken =
        await obterTokenCobranca();
 
      // --------------------------------------------------------
      // METADATA - CUSTOM_ID CORRIGIDO
      // --------------------------------------------------------
 
      const customId =
        montarCustomId({
          usuario_id,
          origem_tipo,
          origem_id,
          prefixo:
            'acheobra-assinatura',
        });
 
      console.log(
        '>>> Custom ID da assinatura ref:',
        referenciaSegura(customId)
      );
 
      // --------------------------------------------------------
      // PAYLOAD DA ASSINATURA
      // --------------------------------------------------------
 
      const payload = {
        items: [
          {
            name:
              descricao ||
              'Plano recorrente Ache Obra',
 
            value:
              valorCentavos,
 
            amount:
              1,
          },
        ],
 
        metadata: {
          custom_id:
            customId,
 
          notification_url:
            EFI_NOTIFICATION_URL,
        },
 
        payment: {
          credit_card: {
            customer: {
              name:
                String(nome)
                  .trim(),
 
              cpf:
                cpfLimpo,
 
              email:
                String(email)
                  .trim()
                  .toLowerCase(),
 
              phone_number:
                telefoneLimpo,
            },
 
            payment_token:
              payment_token,
          },
        },
      };
 
      console.log(
        '>>> Criando assinatura na Efí.'
      );
 
      console.log(
        '>>> Plan ID Efí:',
        planIdEfi
      );
 
      console.log(
        '>>> Valor:',
        valorCentavos,
        'centavos'
      );
 
      const response =
        await axios({
          method:
            'POST',
 
          url:
            `${EFI_COBRANCA_API_URL}/plan/${encodeURIComponent(
              planIdEfi
            )}/subscription/one-step`,
 
          headers: {
            Authorization:
              `Bearer ${accessToken}`,
 
            'Content-Type':
              'application/json',
          },
 
          data:
            payload,
 
          httpsAgent,
 
          timeout:
            30000,
        });
 
      const dados =
        response.data;
 
      const dadosAssinatura =
        dados?.data ||
        {};
 
      const subscriptionId =
        dadosAssinatura
          .subscription_id;
 
      const status =
        dadosAssinatura
          .status;
 
      let charge =
        dadosAssinatura
          .charge ||
        null;
 
      console.log(
        '>>> Assinatura criada na Efí.'
      );
 
      console.log(
        '>>> Subscription ID:',
        subscriptionId
      );
 
      console.log(
        '>>> Status da assinatura:',
        status
      );
 
      if (
        charge?.status
      ) {
 
        console.log(
          '>>> Status da primeira cobrança:',
          charge.status
        );
      }
 
      const statusAssinaturaEfi =
        String(status || '').trim().toLowerCase();

      let statusPrimeiraCobranca =
        String(charge?.status || '').trim().toLowerCase();

      if (charge?.charge_id && !statusCobrancaCartaoPago(statusPrimeiraCobranca)) {
        const confirmacaoImediata =
          await aguardarConfirmacaoCobrancaCartaoEfi(
            accessToken,
            charge.charge_id,
            { statusInicial: statusPrimeiraCobranca }
          );

        if (confirmacaoImediata?.status) {
          statusPrimeiraCobranca = confirmacaoImediata.status;
          charge = {
            ...charge,
            ...(confirmacaoImediata.cobranca || {}),
            status: confirmacaoImediata.status,
          };
        }
      }

      const pagamentoConfirmado =
        statusPrimeiraCobranca === 'paid' ||
        statusPrimeiraCobranca === 'settled';

      // "active" sozinho não confirma pagamento.
      const assinaturaAtiva =
        statusAssinaturaEfi === 'active' &&
        pagamentoConfirmado;

 
      // --------------------------------------------------------
      // REGISTRA / ATUALIZA A ASSINATURA NO SUPABASE
      // --------------------------------------------------------
 
      let registroAssinaturaSalvo =
        false;

      let registroAssinatura =
        null;

      let registroPagamentoRecorrenteSalvo =
        false;

      let erroRegistroPagamentoRecorrente =
        null;
 
      let erroRegistroAssinatura =
        null;
 
      try {
        if (
          subscriptionId &&
          usuario_id &&
          origem_id
        ) {
          registroAssinatura =
            await inserirOuAtualizarAssinaturaSupabase({
            usuario_id:
              String(usuario_id),
 
            plano_id:
              String(origem_id),
 
            efi_subscription_id:
              String(subscriptionId),
 
            efi_plan_id:
              String(planIdEfi),
 
            efi_charge_id:
              charge?.charge_id
                ? String(
                    charge.charge_id
                  )
                : null,
 
            // Sempre grava primeiro como pendente. A promoção para
            // ativo ocorre somente após tratar com segurança eventual
            // assinatura vigente anterior do mesmo usuário.
            status_assinatura:
              'pagamento_pendente',
 
            ultimo_status_efi:
              charge?.status ||
              status ||
              null,
 
            valor_recorrente:
              valorNumerico,
 
            data_inicio:
              new Date().toISOString(),
 
            data_ultimo_pagamento:
              pagamentoConfirmado
                ? new Date().toISOString()
                : null,
 
            proxima_cobranca_em:
              normalizarDataIso(
                dadosAssinatura.next_execution
              ),
 
            data_inicio_inadimplencia:
              null,
 
            data_fim_carencia:
              null,
 
            cancelado_em:
              null,
 
            motivo_cancelamento:
              null,
          });
 
          registroAssinaturaSalvo =
            Boolean(registroAssinatura);
 
          console.log(
            '>>> Assinatura registrada em tab_assinaturas.'
          );

          // Se o webhook chegou antes da gravação do contrato,
          // completa agora as referências do histórico recorrente órfão.
          if (registroAssinaturaSalvo) {
            try {
              await vincularPagamentosRecorrentesOrfaosAssinatura(
                registroAssinatura
              );
            } catch (erroVinculoOrfaos) {
              console.error(
                '>>> Falha ao vincular pagamentos recorrentes órfãos após salvar a assinatura:',
                resumirErroSeguro(erroVinculoOrfaos)
              );
            }
          }

          // ----------------------------------------------------
          // HISTÓRICO FINANCEIRO DA PRIMEIRA COBRANÇA RECORRENTE
          // ----------------------------------------------------
          // A cobrança entra em tab_pagamentos_recorrentes assim
          // que possui charge_id, mesmo em waiting/pending.
          // ----------------------------------------------------

          if (charge?.charge_id) {
            try {
              const registroPagamento =
                await registrarHistoricoPagamentoRecorrente({
                  assinatura:
                    registroAssinatura,
                  usuarioId:
                    String(usuario_id),
                  planoId:
                    String(origem_id),
                  efiSubscriptionId:
                    String(subscriptionId),
                  efiPlanId:
                    String(planIdEfi),
                  chargeId:
                    String(charge.charge_id),
                  statusEfi:
                    charge?.status || status || null,
                  valor:
                    valorNumerico,
                  parcelas:
                    charge?.installments ||
                    charge?.parcel ||
                    null,
                  valorParcela:
                    Number.isFinite(Number(charge?.installment_value))
                      ? Number(charge.installment_value) / 100
                      : null,
                  metodoPagamento:
                    charge?.payment_method ||
                    'credit_card',
                  bandeiraCartao:
                    charge?.card_brand ||
                    charge?.payment?.credit_card?.brand ||
                    null,
                  dataCobranca:
                    charge?.created_at ||
                    new Date().toISOString(),
                  dataPagamento:
                    charge?.paid_at ||
                    null,
                  dataVencimento:
                    charge?.expire_at ||
                    null,
                  codigoRecusa:
                    charge?.refusal?.code ||
                    null,
                  motivoRecusa:
                    charge?.refusal?.message ||
                    charge?.refusal?.reason ||
                    null,
                  origemRegistro:
                    'criacao_assinatura',
                  tipoEvento:
                    'subscription_charge',
                });

              registroPagamentoRecorrenteSalvo =
                Boolean(registroPagamento);

            } catch (erroHistoricoRecorrente) {
              erroRegistroPagamentoRecorrente =
                erroHistoricoRecorrente.response?.data ||
                erroHistoricoRecorrente.message;

              console.error(
                '>>> Assinatura criada, mas falhou ao salvar a cobrança em tab_pagamentos_recorrentes:',
                resumirErroSeguro(erroHistoricoRecorrente)
              );

              // Segurança: se a Efí já confirmou o pagamento, não
              // deixamos o contrato local como ativo sem o histórico.
              if (pagamentoConfirmado) {
                try {
                  await atualizarAssinaturaPorSubscriptionId(
                    String(subscriptionId),
                    {
                      status_assinatura:
                        'pagamento_pendente',
                      data_ultimo_pagamento:
                        null,
                    }
                  );
                } catch (erroReversaoLocal) {
                  console.error(
                    '>>> Falha ao manter a assinatura pendente após erro no histórico recorrente:',
                    resumirErroSeguro(erroReversaoLocal)
                  );
                }
              }
            }
          }
 
        } else {
          erroRegistroAssinatura =
            'usuario_id, origem_id ou subscription_id ausente.';
 
          console.warn(
            '>>> Assinatura criada na Efí, mas não foi possível registrar em tab_assinaturas:',
            resumirErroSeguro(erroRegistroAssinatura)
          );
        }
 
      } catch (erroSupabase) {
        erroRegistroAssinatura =
          erroSupabase.response?.data ||
          erroSupabase.message;
 
        console.error(
          '>>> Assinatura foi criada na Efí, mas falhou ao salvar em tab_assinaturas:',
          resumirErroSeguro(erroRegistroAssinatura)
        );
      }
 
      // --------------------------------------------------------
      // PROMOÇÃO SEGURA PARA ATIVO APÓS CONFIRMAÇÃO FINANCEIRA
      // --------------------------------------------------------
      if (
        pagamentoConfirmado &&
        registroAssinaturaSalvo &&
        (
          !charge?.charge_id ||
          registroPagamentoRecorrenteSalvo
        )
      ) {
        try {
          const finalizacao =
            await finalizarAtivacaoAssinaturaPaga({
              assinaturaNova:
                registroAssinatura,
              dataPagamento:
                charge?.paid_at ||
                new Date().toISOString(),
              accessTokenInformado:
                accessToken,
              motivoTroca:
                `Troca automática para o plano ${String(origem_id || '')} após confirmação financeira.`,
            });

          registroAssinatura =
            finalizacao.assinatura_nova ||
            registroAssinatura;

        } catch (erroFinalizacaoAtivacao) {
          console.error(
            '>>> Pagamento recorrente confirmado, mas a ativação segura não pôde ser concluída:',
            resumirErroSeguro(erroFinalizacaoAtivacao)
          );

          return res
            .status(502)
            .json({
              success: false,
              approved: false,
              pago: false,
              pagamento_confirmado: true,
              pagamento_pendente: true,
              status: status || null,
              subscription_id: subscriptionId,
              charge: charge,
              registro_assinatura_salvo:
                registroAssinaturaSalvo,
              registro_pagamento_recorrente_salvo:
                charge?.charge_id
                  ? registroPagamentoRecorrenteSalvo
                  : null,
              error:
                'O pagamento foi confirmado, mas a ativação segura do novo plano ainda não pôde ser concluída. A assinatura anterior foi preservada.',
            });
        }
      }

      if (
        subscriptionId &&
        (
          !registroAssinaturaSalvo ||
          (
            charge?.charge_id &&
            !registroPagamentoRecorrenteSalvo
          )
        )
      ) {
        return res
          .status(502)
          .json({
            success: false,
            approved: false,
            pago: false,
            pagamento_confirmado: false,
            pagamento_pendente: true,
            status: status || null,
            subscription_id: subscriptionId,
            charge: charge,
            registro_assinatura_salvo:
              registroAssinaturaSalvo,
            registro_pagamento_recorrente_salvo:
              registroPagamentoRecorrenteSalvo,
            erro_registro_pagamento_recorrente:
              erroRegistroPagamentoRecorrente,
            error:
              !registroAssinaturaSalvo
                ? 'A assinatura foi criada na Efí, mas o contrato não pôde ser salvo em tab_assinaturas. O plano não foi liberado.'
                : 'A assinatura foi criada na Efí, mas a cobrança não pôde ser salva em tab_pagamentos_recorrentes. O plano não foi liberado.',
          });
      }

      return res
        .status(201)
        .json({
          success:
            true,
 
          approved:
            pagamentoConfirmado,
 
          pago:
            pagamentoConfirmado,
 
          status:
            status,
 
          subscription_id:
            subscriptionId,
 
          registro_assinatura_salvo:
            registroAssinaturaSalvo,

          registro_pagamento_recorrente_salvo:
            charge?.charge_id
              ? registroPagamentoRecorrenteSalvo
              : null,
 
          erro_registro_assinatura:
            erroRegistroAssinatura,

          erro_registro_pagamento_recorrente:
            erroRegistroPagamentoRecorrente,
 
          plan_id:
            dadosAssinatura
              .plan_id ||
            dadosAssinatura
              .plan
              ?.plan_id ||
            planIdEfi,
 
          charge:
            charge,
 
          next_execution:
            dadosAssinatura
              .next_execution ||
            null,
 
          next_expire_at:
            dadosAssinatura
              .next_expire_at ||
            null,
 
          occurrences:
            dadosAssinatura
              .occurrences ??
            null,
 
          data:
            dadosAssinatura,
        });
 
    } catch (error) {
 
      console.error(
        '=========================================='
      );
 
      console.error(
        'ERRO AO CRIAR ASSINATURA'
      );
 
      console.error(
        '=========================================='
      );
 
      console.error(
        'HTTP:',
        error.response?.status
      );
 
      console.error(
        'Resposta Efí (segura):',
        resumirErroSeguro(error)
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
 
      const descricaoErro =
        respostaEfi
          ?.error_description;
 
      let mensagem =
        respostaEfi
          ?.mensagem ||
        respostaEfi
          ?.message ||
        respostaEfi
          ?.error ||
        error.message;
 
      if (
        typeof descricaoErro ===
        'string'
      ) {
 
        mensagem =
          descricaoErro;
 
      } else if (
        descricaoErro
      ) {
 
        mensagem =
          JSON.stringify(
            descricaoErro
          );
      }
 
      return res
        .status(
          error.response
            ?.status ||
          500
        )
        .json({
          success:
            false,
 
          approved:
            false,
 
          error:
            mensagem,
 
          efi:
            respostaEfi ||
            null,
        });
    }
  }
);
 
 

// ============================================================
// 3-B. TROCA IMEDIATA DE PLANO RECORRENTE
// ============================================================
//
// Requer Authorization: Bearer <access_token do Supabase>.
//
// Regra do Ache Obra:
// - serve tanto para upgrade quanto para downgrade;
// - não há crédito proporcional do ciclo anterior;
// - a nova assinatura começa imediatamente;
// - a assinatura antiga é cancelada imediatamente;
// - o plano antigo permanece no histórico como cancelado;
// - a nova assinatura é registrada como a assinatura vigente.
//
// Segurança contra estado inconsistente:
// 1. autentica o usuário pelo Supabase;
// 2. busca a assinatura recorrente atual;
// 3. lê o novo plano diretamente de tab_planos;
// 4. cria e cobra a nova assinatura na Efí;
// 5. cancela a assinatura antiga na Efí;
// 6. se o cancelamento da antiga falhar, tenta cancelar a nova
//    como compensação e NÃO altera a assinatura antiga no Supabase;
// 7. somente depois atualiza os registros no Supabase.
//
// Body esperado:
// {
//   "plano_id": "UUID_DO_NOVO_PLANO_NO_SUPABASE",
//   "email": "...",
//   "nome": "...",
//   "cpf": "...",
//   "telefone": "...",
//   "payment_token": "...",
//   "descricao": "..." // opcional
// }
// ============================================================

app.post(
  '/trocar-assinatura',

  async (req, res) => {
    let novaSubscriptionId = null;
    let novaAssinaturaSalva = false;

    try {
      const usuario =
        await obterUsuarioSupabaseDoBearer(req);

      if (!usuario?.id) {
        return res
          .status(401)
          .json({
            success: false,
            error: 'Usuário não autenticado.',
          });
      }

      const {
        plano_id,
        email,
        nome,
        cpf,
        telefone,
        payment_token,
        descricao,
      } = req.body || {};

      const novoPlanoId =
        String(plano_id || '').trim();

      if (!novoPlanoId) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              'plano_id do novo plano no Supabase é obrigatório.',
          });
      }

      if (!nome || !cpf || !email || !telefone || !payment_token) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              'Nome, CPF, e-mail, telefone e payment_token são obrigatórios.',
          });
      }

      const assinaturaAtual =
        await buscarAssinaturaAtivaPorUsuario(
          usuario.id
        );

      if (!assinaturaAtual) {
        return res
          .status(409)
          .json({
            success: false,
            error:
              'Nenhuma assinatura recorrente atual foi encontrada. Para a primeira assinatura use /cobrar-assinatura.',
            usar_rota:
              '/cobrar-assinatura',
          });
      }

      const assinaturaAtualId =
        String(
          assinaturaAtual.efi_subscription_id || ''
        ).trim();

      if (!assinaturaAtualId) {
        return res
          .status(409)
          .json({
            success: false,
            error:
              'A assinatura atual não possui efi_subscription_id.',
          });
      }

      if (
        String(assinaturaAtual.plano_id || '').trim() ===
        novoPlanoId
      ) {
        return res
          .status(409)
          .json({
            success: false,
            error:
              'O plano escolhido já é o plano recorrente atual do usuário.',
          });
      }

      const novoPlano =
        await buscarPlanoRecorrentePorIdSupabase(
          novoPlanoId
        );

      if (!novoPlano) {
        return res
          .status(404)
          .json({
            success: false,
            error:
              'Novo plano não encontrado no Supabase.',
          });
      }

      const novoPlanIdEfi =
        String(
          novoPlano.efi_plan_id || ''
        ).trim();

      const novoValor =
        Number(
          novoPlano.valor_recorrente
        );

      if (!novoPlanIdEfi) {
        return res
          .status(409)
          .json({
            success: false,
            error:
              'O novo plano ainda não possui efi_plan_id sincronizado.',
          });
      }

      if (
        !Number.isFinite(novoValor) ||
        novoValor <= 0
      ) {
        return res
          .status(409)
          .json({
            success: false,
            error:
              'O novo plano não possui valor_recorrente válido.',
          });
      }

      if (
        novoPlano.recorrencia_ativa === false
      ) {
        return res
          .status(409)
          .json({
            success: false,
            error:
              'A recorrência do novo plano está desativada.',
          });
      }

      const cpfLimpo =
        String(cpf)
          .replace(/\D/g, '');

      if (cpfLimpo.length !== 11) {
        return res
          .status(400)
          .json({
            success: false,
            error: 'CPF inválido.',
          });
      }

      let telefoneLimpo =
        String(telefone)
          .replace(/\D/g, '');

      if (
        telefoneLimpo.startsWith('55') &&
        (
          telefoneLimpo.length === 12 ||
          telefoneLimpo.length === 13
        )
      ) {
        telefoneLimpo =
          telefoneLimpo.substring(2);
      }

      if (
        telefoneLimpo.length !== 10 &&
        telefoneLimpo.length !== 11
      ) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              'Telefone inválido. Informe DDD + número.',
          });
      }

      const valorCentavos =
        Math.round(novoValor * 100);

      const accessToken =
        await obterTokenCobranca();

      const customId =
        montarCustomId({
          usuario_id: usuario.id,
          origem_tipo: 'plano_categoria',
          origem_id: novoPlanoId,
          prefixo:
            'acheobra-troca-assinatura',
        });

      const payload = {
        items: [
          {
            name:
              descricao ||
              `Plano recorrente Ache Obra - ${novoPlano.nome_plano || 'Plano'}`,
            value:
              valorCentavos,
            amount:
              1,
          },
        ],

        metadata: {
          custom_id:
            customId,
          notification_url:
            EFI_NOTIFICATION_URL,
        },

        payment: {
          credit_card: {
            customer: {
              name:
                String(nome).trim(),
              cpf:
                cpfLimpo,
              email:
                String(email)
                  .trim()
                  .toLowerCase(),
              phone_number:
                telefoneLimpo,
            },
            payment_token:
              payment_token,
          },
        },
      };

      console.log(
        '=========================================='
      );
      console.log(
        `>>> TROCA DE PLANO RECORRENTE - usuário ref ${referenciaSegura(usuario.id)}`
      );
      console.log(
        `>>> Assinatura atual: ${assinaturaAtualId}`
      );
      console.log(
        `>>> Novo plano Supabase: ${novoPlanoId}`
      );
      console.log(
        `>>> Novo plan_id Efí: ${novoPlanIdEfi}`
      );

      // --------------------------------------------------------
      // 1. CRIA A NOVA ASSINATURA NA EFÍ
      // --------------------------------------------------------
      // Criamos primeiro para não deixar o usuário sem assinatura
      // caso o novo cartão/pagamento seja recusado.
      // --------------------------------------------------------

      const responseNova =
        await axios({
          method: 'POST',
          url:
            `${EFI_COBRANCA_API_URL}/plan/${encodeURIComponent(
              novoPlanIdEfi
            )}/subscription/one-step`,
          headers: {
            Authorization:
              `Bearer ${accessToken}`,
            'Content-Type':
              'application/json',
          },
          data:
            payload,
          httpsAgent,
          timeout:
            30000,
        });

      const novaAssinaturaEfi =
        responseNova.data?.data || {};

      novaSubscriptionId =
        novaAssinaturaEfi.subscription_id
          ? String(
              novaAssinaturaEfi.subscription_id
            )
          : null;

      const novoStatusEfi =
        String(
          novaAssinaturaEfi.status || ''
        )
          .trim()
          .toLowerCase();

      let novaCharge =
        novaAssinaturaEfi.charge || null;

      if (!novaSubscriptionId) {
        throw new Error(
          'A Efí criou a cobrança, mas não retornou subscription_id da nova assinatura.'
        );
      }

      let novoStatusCharge =
        String(novaCharge?.status || '').trim().toLowerCase();

      if (novaCharge?.charge_id && !statusCobrancaCartaoPago(novoStatusCharge)) {
        const confirmacaoImediata =
          await aguardarConfirmacaoCobrancaCartaoEfi(
            accessToken,
            novaCharge.charge_id,
            { statusInicial: novoStatusCharge }
          );

        if (confirmacaoImediata?.status) {
          novoStatusCharge = confirmacaoImediata.status;
          novaCharge = {
            ...novaCharge,
            ...(confirmacaoImediata.cobranca || {}),
            status: confirmacaoImediata.status,
          };
        }
      }

      const novoPagamentoConfirmado =
        novoStatusCharge === 'paid' ||
        novoStatusCharge === 'settled';

      const agoraNovaTentativa =
        new Date().toISOString();

      // Salva a tentativa imediatamente, mesmo aguardando.
      const registroPendenteNova =
        await inserirOuAtualizarAssinaturaSupabase({
          usuario_id: String(usuario.id),
          plano_id: novoPlanoId,
          efi_subscription_id: novaSubscriptionId,
          efi_plan_id: novoPlanIdEfi,
          efi_charge_id:
            novaCharge?.charge_id
              ? String(novaCharge.charge_id)
              : null,
          // Sempre grava primeiro como pendente. Se o pagamento já
          // vier confirmado, a antiga será cancelada antes da promoção.
          status_assinatura:
            'pagamento_pendente',
          ultimo_status_efi:
            novoStatusCharge ||
            novoStatusEfi ||
            null,
          valor_recorrente: novoValor,
          data_inicio: agoraNovaTentativa,
          data_ultimo_pagamento:
            novoPagamentoConfirmado
              ? agoraNovaTentativa
              : null,
          proxima_cobranca_em:
            normalizarDataIso(
              novaAssinaturaEfi.next_execution
            ),
          data_inicio_inadimplencia: null,
          data_fim_carencia: null,
          cancelado_em: null,
          motivo_cancelamento: null,
        });

      novaAssinaturaSalva =
        Boolean(registroPendenteNova);

      if (!novaAssinaturaSalva) {
        throw new Error(
          'A nova assinatura foi criada na Efí, mas não foi possível salvar o histórico no Supabase.'
        );
      }

      let registroPagamentoRecorrenteNova = null;

      if (novaCharge?.charge_id) {
        try {
          registroPagamentoRecorrenteNova =
            await registrarHistoricoPagamentoRecorrente({
              assinatura:
                registroPendenteNova,
              usuarioId:
                String(usuario.id),
              planoId:
                novoPlanoId,
              efiSubscriptionId:
                novaSubscriptionId,
              efiPlanId:
                novoPlanIdEfi,
              chargeId:
                String(novaCharge.charge_id),
              statusEfi:
                novoStatusCharge ||
                novoStatusEfi ||
                null,
              valor:
                novoValor,
              parcelas:
                novaCharge?.installments ||
                novaCharge?.parcel ||
                null,
              valorParcela:
                Number.isFinite(Number(novaCharge?.installment_value))
                  ? Number(novaCharge.installment_value) / 100
                  : null,
              metodoPagamento:
                novaCharge?.payment_method ||
                'credit_card',
              bandeiraCartao:
                novaCharge?.card_brand ||
                novaCharge?.payment?.credit_card?.brand ||
                null,
              dataCobranca:
                novaCharge?.created_at ||
                agoraNovaTentativa,
              dataPagamento:
                novaCharge?.paid_at ||
                null,
              dataVencimento:
                novaCharge?.expire_at ||
                null,
              codigoRecusa:
                novaCharge?.refusal?.code ||
                null,
              motivoRecusa:
                novaCharge?.refusal?.message ||
                novaCharge?.refusal?.reason ||
                null,
              origemRegistro:
                'troca_assinatura',
              tipoEvento:
                'subscription_charge',
            });

        } catch (erroHistoricoNova) {
          console.error(
            '>>> Falha ao salvar cobrança da nova assinatura em tab_pagamentos_recorrentes. A assinatura anterior será preservada:',
            resumirErroSeguro(erroHistoricoNova)
          );

          let novaCanceladaAposErroHistorico = false;

          try {
            await cancelarAssinaturaEfiPorId(
              accessToken,
              novaSubscriptionId
            );

            novaCanceladaAposErroHistorico = true;

            await atualizarAssinaturaPorSubscriptionId(
              novaSubscriptionId,
              {
                status_assinatura: 'cancelado',
                ultimo_status_efi: 'canceled',
                cancelado_em: new Date().toISOString(),
                motivo_cancelamento:
                  'Cancelamento compensatório: falha ao registrar histórico financeiro recorrente.',
              }
            );
          } catch (erroCompensacaoHistorico) {
            console.error(
              '>>> ATENÇÃO: falhou também o cancelamento compensatório da nova assinatura após erro no histórico:',
              resumirErroSeguro(erroCompensacaoHistorico)
            );
          }

          return res
            .status(502)
            .json({
              success: false,
              approved: false,
              pago: false,
              troca_plano: false,
              assinatura_anterior_preservada: true,
              nova_subscription_id:
                novaSubscriptionId,
              nova_cancelada_compensacao:
                novaCanceladaAposErroHistorico,
              registro_pagamento_recorrente_salvo:
                false,
              error:
                'A nova assinatura foi criada, mas não foi possível registrar sua cobrança recorrente no histórico. A troca não foi concluída.',
            });
        }
      }

      // Enquanto a primeira cobrança estiver aguardando, mantém o
      // plano recorrente anterior e NÃO informa sucesso ao Flutter.
      if (!novoPagamentoConfirmado) {
        return res
          .status(202)
          .json({
            success: true,
            approved: false,
            pago: false,
            pagamento_confirmado: false,
            pagamento_pendente: true,
            troca_plano: false,
            assinatura_anterior_preservada: true,
            plano_novo_id: novoPlanoId,
            nova_subscription_id: novaSubscriptionId,
            charge_id:
              novaCharge?.charge_id || null,
            status_nova_assinatura:
              novoStatusEfi || null,
            status_primeira_cobranca:
              novoStatusCharge || null,
            registro_assinatura_salvo: true,
            registro_pagamento_recorrente_salvo:
              novaCharge?.charge_id
                ? Boolean(registroPagamentoRecorrenteNova)
                : null,
            message:
              'Nova assinatura registrada como pendente. O plano anterior permanece ativo até a confirmação real do pagamento.',
          });
      }


      if (novoStatusEfi !== 'active') {
        // Se por algum motivo a API retornar assinatura não ativa,
        // não cancelamos a antiga.
        try {
          await cancelarAssinaturaEfiPorId(
            accessToken,
            novaSubscriptionId
          );
        } catch (erroCancelamentoNova) {
          console.error(
            '>>> Não foi possível cancelar a nova assinatura não ativa durante a compensação:',
            resumirErroSeguro(erroCancelamentoNova)
          );
        }

        return res
          .status(409)
          .json({
            success: false,
            error:
              'A nova assinatura não ficou ativa. A assinatura anterior foi preservada.',
            status_nova_assinatura:
              novoStatusEfi || null,
            nova_subscription_id:
              novaSubscriptionId,
          });
      }

      // --------------------------------------------------------
      // 2. CANCELA A ASSINATURA ANTIGA NA EFÍ
      // --------------------------------------------------------

      try {
        await cancelarAssinaturaEfiPorId(
          accessToken,
          assinaturaAtualId
        );
      } catch (erroCancelarAntiga) {
        console.error(
          '>>> Falha ao cancelar assinatura antiga. Tentando desfazer a nova assinatura:',
          resumirErroSeguro(erroCancelarAntiga)
        );

        let novaCanceladaNaCompensacao =
          false;

        try {
          await cancelarAssinaturaEfiPorId(
            accessToken,
            novaSubscriptionId
          );

          novaCanceladaNaCompensacao =
            true;
        } catch (erroCompensacao) {
          console.error(
            '>>> ATENÇÃO: também falhou o cancelamento compensatório da nova assinatura:',
            resumirErroSeguro(erroCompensacao)
          );
        }

        return res
          .status(502)
          .json({
            success: false,
            error:
              'Não foi possível cancelar a assinatura anterior na Efí. A troca não foi concluída.',
            assinatura_anterior_preservada:
              true,
            nova_subscription_id:
              novaSubscriptionId,
            nova_cancelada_compensacao:
              novaCanceladaNaCompensacao,
            requer_atencao_manual:
              !novaCanceladaNaCompensacao,
          });
      }

      const agora =
        new Date().toISOString();

      // --------------------------------------------------------
      // 3. MARCA A ANTIGA COMO CANCELADA NO SUPABASE
      // --------------------------------------------------------

      await atualizarAssinaturaPorSubscriptionId(
        assinaturaAtualId,
        {
          status_assinatura:
            'cancelado',
          ultimo_status_efi:
            'canceled',
          cancelado_em:
            agora,
          motivo_cancelamento:
            `Troca imediata para o plano ${novoPlano.nome_plano || novoPlanoId}.`,
          data_inicio_inadimplencia:
            null,
          data_fim_carencia:
            null,
        }
      );

      // --------------------------------------------------------
      // 4. REGISTRA A NOVA ASSINATURA NO SUPABASE
      // --------------------------------------------------------

      const registroNovaAssinatura =
        await inserirOuAtualizarAssinaturaSupabase({
          usuario_id:
            String(usuario.id),
          plano_id:
            novoPlanoId,
          efi_subscription_id:
            novaSubscriptionId,
          efi_plan_id:
            novoPlanIdEfi,
          efi_charge_id:
            novaCharge?.charge_id
              ? String(novaCharge.charge_id)
              : null,
          status_assinatura:
            'ativo',
          ultimo_status_efi:
            novaCharge?.status ||
            novoStatusEfi ||
            'active',
          valor_recorrente:
            novoValor,
          data_inicio:
            agora,
          data_ultimo_pagamento:
            (
              novaCharge?.status === 'paid' ||
              novaCharge?.status === 'settled'
            )
              ? agora
              : null,
          proxima_cobranca_em:
            normalizarDataIso(
              novaAssinaturaEfi.next_execution
            ),
          data_inicio_inadimplencia:
            null,
          data_fim_carencia:
            null,
          cancelado_em:
            null,
          motivo_cancelamento:
            null,
        });

      novaAssinaturaSalva =
        Boolean(registroNovaAssinatura);

      if (!registroNovaAssinatura) {
        throw new Error(
          'A assinatura anterior foi cancelada, mas a nova assinatura não pôde ser confirmada no Supabase.'
        );
      }

      await atualizarPlanoAtivoUsuarioSupabase({
        usuarioId:
          String(usuario.id),
        planoId:
          novoPlanoId,
        recorrente:
          true,
        dataAtivacao:
          agora,
      });

      console.log(
        `>>> Troca concluída: ${assinaturaAtualId} -> ${novaSubscriptionId}.`
      );
      console.log(
        '=========================================='
      );

      return res
        .status(201)
        .json({
          success: true,
          approved: true,
          pago: true,
          troca_plano: true,
          plano_anterior_id:
            assinaturaAtual.plano_id || null,
          plano_novo_id:
            novoPlanoId,
          plano_novo_nome:
            novoPlano.nome_plano || null,
          valor_recorrente:
            novoValor,
          assinatura_anterior: {
            subscription_id:
              assinaturaAtualId,
            status:
              'cancelado',
          },
          assinatura_nova: {
            subscription_id:
              novaSubscriptionId,
            status:
              novoStatusEfi,
            charge:
              novaCharge,
            next_execution:
              novaAssinaturaEfi.next_execution ||
              null,
          },
          registro_assinatura_salvo:
            novaAssinaturaSalva,
          registro_pagamento_recorrente_salvo:
            novaCharge?.charge_id
              ? Boolean(registroPagamentoRecorrenteNova)
              : null,
          data:
            novaAssinaturaEfi,
        });

    } catch (error) {
      console.error(
        '=========================================='
      );
      console.error(
        'ERRO AO TROCAR PLANO RECORRENTE'
      );
      console.error(
        resumirErroSeguro(error)
      );
      console.error(
        '=========================================='
      );

      const respostaEfi =
        error.response?.data;

      let mensagem =
        respostaEfi?.error_description ||
        respostaEfi?.mensagem ||
        respostaEfi?.message ||
        respostaEfi?.error ||
        error.message;

      if (typeof mensagem !== 'string') {
        mensagem =
          JSON.stringify(mensagem);
      }

      return res
        .status(
          error.response?.status ||
          500
        )
        .json({
          success: false,
          approved: false,
          troca_plano: false,
          error: mensagem,
          nova_subscription_id:
            novaSubscriptionId,
          nova_assinatura_salva:
            novaAssinaturaSalva,
          efi:
            respostaEfi || null,
        });
    }
  }
);


// ============================================================
// 4. WEBHOOK / NOTIFICAÇÕES DA EFÍ
// ============================================================
//
// A Efí envia somente um token para notification_url.
// O backend consulta GET /v1/notification/:token e processa
// todos os eventos recebidos.
// ============================================================
 
app.post(
  '/webhook/efi',
 
  async (req, res) => {
    const notificationToken =
      String(
        req.body?.notification ||
        req.body?.token ||
        req.query?.notification ||
        ''
      ).trim();
 
    if (!notificationToken) {
      console.warn(
        '>>> Webhook Efí recebido sem token.'
      );
 
      return res
        .status(400)
        .json({
          success: false,
          error:
            'Token de notificação não informado.',
        });
    }
 
    console.log(
      '=========================================='
    );
 
    console.log(
      '>>> WEBHOOK EFÍ RECEBIDO'
    );
 
    console.log(
      '>>> Referência segura da notificação:',
      referenciaSegura(notificationToken)
    );
 
    console.log(
      '=========================================='
    );
 
    try {
      const accessToken =
        await obterTokenCobranca();
 
      const eventos =
        await consultarNotificacaoEfi(
          accessToken,
          notificationToken
        );
 
      const resultados = [];
 
      for (const evento of eventos) {
        const resultado =
          await aplicarEventoNotificacaoEfi(
            evento,
            notificationToken
          );
 
        resultados.push(
          resultado
        );
      }
 
      await processarCarenciasVencidas();
 
      console.log(
        `>>> Webhook processado. Eventos: ${eventos.length}`
      );
 
      return res.json({
        success: true,
        eventos:
          eventos.length,
        resultados,
      });
 
    } catch (error) {
      console.error(
        '>>> ERRO NO WEBHOOK EFÍ:',
        resumirErroSeguro(error)
      );
 
      return res
        .status(
          error.response?.status ||
          500
        )
        .json({
          success: false,
          error:
            resumirErroSeguro(error),
        });
    }
  }
);
 
// ============================================================
// 4.1 DEVOLUÇÃO DE PAGAMENTO AVULSO PIX EM ATÉ 7 DIAS
// ============================================================

app.post(
  '/cancelar-pagamento-pix',

  async (req, res) => {
    console.log('==========================================');
    console.log('>>> SOLICITAÇÃO DE CANCELAMENTO PIX AVULSO');
    console.log('>>> Dados seguros da solicitação:', resumoEntradaSeguro(req));
    console.log('==========================================');

    try {
      const usuario =
        await obterUsuarioSupabaseDoBearer(req);

      if (!usuario?.id) {
        return res.status(401).json({
          success: false,
          error: 'Usuário não autenticado.',
        });
      }

      const pagamentoId =
        String(req.body?.pagamento_id || '').trim();

      const motivoCancelamento =
        String(
          req.body?.motivo_cancelamento ||
          'Cancelamento Pix solicitado pelo usuário dentro do prazo de 7 dias.'
        ).trim().substring(0, 1000);

      if (!pagamentoId) {
        return res.status(400).json({
          success: false,
          error: 'pagamento_id é obrigatório.',
        });
      }

      let pagamento =
        await buscarPagamentoAvulsoPixPorIdUsuario(
          pagamentoId,
          usuario.id
        );

      console.log(
        '>>> Pagamento Pix localizado:',
        pagamento?.id || 'não encontrado'
      );

      if (!pagamento) {
        return res.status(404).json({
          success: false,
          error:
            'Pagamento avulso Pix não encontrado para este usuário.',
        });
      }

      let statusLocal =
        String(pagamento.status || '')
          .trim()
          .toLowerCase();

      if (
        statusLocal === 'estornado' ||
        statusLocal === 'refunded'
      ) {
        return res.json({
          success: true,
          ja_estornado: true,
          status: 'estornado',
          pagamento_id: pagamento.id,
          txid: pagamento.pix_txid,
          e2e_id: pagamento.pix_e2e_id,
        });
      }

      if (
        !pagamento.pix_e2e_id ||
        statusLocal === 'aguardando_pagamento'
      ) {
        const sincronizacao =
          await sincronizarPagamentoPixPorTxid(
            pagamento.pix_txid,
            usuario.id
          );

        pagamento =
          sincronizacao.pagamento ||
          pagamento;

        statusLocal =
          String(pagamento.status || '')
            .trim()
            .toLowerCase();

        if (!sincronizacao.pago) {
          return res.status(409).json({
            success: false,
            error:
              'O Pix ainda não está confirmado pela Efí.',
            status_efi:
              sincronizacao.status_efi,
            txid:
              pagamento.pix_txid,
          });
        }
      }

      const dataPagamentoTexto =
        pagamento.data_pagamento ||
        pagamento.created_at;

      const dataPagamento =
        dataPagamentoTexto
          ? new Date(dataPagamentoTexto)
          : null;

      if (
        !dataPagamento ||
        Number.isNaN(dataPagamento.getTime())
      ) {
        return res.status(409).json({
          success: false,
          error:
            'A data do pagamento Pix não está disponível ou é inválida.',
        });
      }

      const limiteCancelamento =
        new Date(
          dataPagamento.getTime() +
          7 * 24 * 60 * 60 * 1000
        );

      if (Date.now() > limiteCancelamento.getTime()) {
        return res.status(409).json({
          success: false,
          prazo_expirado: true,
          error:
            'O prazo de 7 dias para solicitar a devolução deste Pix já expirou.',
          data_pagamento:
            dataPagamento.toISOString(),
          limite_cancelamento:
            limiteCancelamento.toISOString(),
        });
      }

      const e2eId =
        String(pagamento.pix_e2e_id || '').trim();

      const txid =
        String(pagamento.pix_txid || '').trim();

      if (!e2eId) {
        return res.status(409).json({
          success: false,
          error:
            'O pagamento Pix não possui e2eId para solicitar a devolução.',
          txid,
        });
      }

      const valor =
        Number(pagamento.valor);

      if (
        !Number.isFinite(valor) ||
        valor <= 0
      ) {
        return res.status(409).json({
          success: false,
          error:
            'O valor do pagamento Pix é inválido para devolução.',
        });
      }

      const devolucaoId =
        gerarIdDevolucaoPix(
          pagamento.id
        );

      const accessToken =
        await obterTokenPix();

      if (statusLocal === 'estorno_solicitado') {
        try {
          const consulta =
            await consultarDevolucaoPixEfi(
              accessToken,
              e2eId,
              devolucaoId
            );

          const statusDevolucao =
            String(
              consulta.data?.status || ''
            )
              .trim()
              .toUpperCase();

          if (statusDevolucao === 'DEVOLVIDO') {
            const atualizado =
              await atualizarPagamentoAvulsoPorId(
                pagamento.id,
                {
                  status: 'estornado',
                  estorno_concluido_em:
                    new Date().toISOString(),
                }
              );

            return res.json({
              success: true,
              ja_estornado: true,
              status: 'estornado',
              pagamento: atualizado,
              efi: consulta.data,
            });
          }

          return res.json({
            success: true,
            ja_solicitado: true,
            status: 'estorno_solicitado',
            mensagem:
              'A devolução Pix já foi solicitada e ainda está em processamento.',
            pagamento_id: pagamento.id,
            txid,
            e2e_id: e2eId,
            efi: consulta.data,
          });

        } catch (consultaError) {
          console.warn(
            '>>> Não foi possível consultar devolução Pix já solicitada:',
            resumirErroSeguro(consultaError)
          );
        }
      }

      let respostaDevolucao;

      try {
        respostaDevolucao =
          await solicitarDevolucaoPixEfi(
            accessToken,
            e2eId,
            devolucaoId,
            valor
          );
      } catch (devolucaoError) {
        const nomeErro =
          devolucaoError.response?.data?.nome;

        if (
          devolucaoError.response?.status === 409 ||
          nomeErro === 'devolucao_id_duplicado'
        ) {
          respostaDevolucao =
            await consultarDevolucaoPixEfi(
              accessToken,
              e2eId,
              devolucaoId
            );
        } else {
          throw devolucaoError;
        }
      }

      const statusDevolucao =
        String(
          respostaDevolucao.data?.status || ''
        )
          .trim()
          .toUpperCase();

      const agoraIso =
        new Date().toISOString();

      if (statusDevolucao === 'DEVOLVIDO') {
        const atualizado =
          await atualizarPagamentoAvulsoPorId(
            pagamento.id,
            {
              status: 'estornado',
              estorno_solicitado_em:
                pagamento.estorno_solicitado_em ||
                agoraIso,
              estorno_concluido_em:
                agoraIso,
              motivo_cancelamento:
                motivoCancelamento,
            }
          );

        return res.json({
          success: true,
          status: 'estornado',
          pagamento_id: pagamento.id,
          txid,
          e2e_id: e2eId,
          pagamento: atualizado,
          efi: respostaDevolucao.data,
        });
      }

      if (statusDevolucao === 'NAO_REALIZADO') {
        const atualizado =
          await atualizarPagamentoAvulsoPorId(
            pagamento.id,
            {
              status: 'estorno_falhou',
              estorno_solicitado_em:
                pagamento.estorno_solicitado_em ||
                agoraIso,
              motivo_cancelamento:
                motivoCancelamento,
            }
          );

        return res.status(409).json({
          success: false,
          status: 'estorno_falhou',
          error:
            respostaDevolucao.data?.motivo ||
            'A Efí não realizou a devolução Pix.',
          pagamento: atualizado,
          efi: respostaDevolucao.data,
        });
      }

      const atualizado =
        await atualizarPagamentoAvulsoPorId(
          pagamento.id,
          {
            status: 'estorno_solicitado',
            estorno_solicitado_em:
              pagamento.estorno_solicitado_em ||
              agoraIso,
            motivo_cancelamento:
              motivoCancelamento,
          }
        );

      console.log(
        '>>> Devolução Pix solicitada com sucesso.',
        '| pagamento:',
        pagamento.id,
        '| txid:',
        txid,
        '| e2eId:',
        e2eId,
        '| status:',
        statusDevolucao || 'não informado'
      );

      return res.json({
        success: true,
        status: 'estorno_solicitado',
        mensagem:
          'Solicitação de devolução Pix enviada à Efí. A devolução está em processamento.',
        pagamento_id: pagamento.id,
        txid,
        e2e_id: e2eId,
        devolucao_id: devolucaoId,
        pagamento: atualizado,
        efi: respostaDevolucao.data,
      });

    } catch (error) {
      console.error(
        '>>> ERRO AO DEVOLVER PAGAMENTO PIX:',
        resumirErroSeguro(error)
      );

      const respostaEfi =
        error.response?.data;

      let mensagem =
        respostaEfi?.mensagem ||
        respostaEfi?.message ||
        respostaEfi?.error ||
        respostaEfi?.nome ||
        error.message;

      if (typeof mensagem !== 'string') {
        mensagem = JSON.stringify(mensagem);
      }

      return res
        .status(error.response?.status || 500)
        .json({
          success: false,
          error: mensagem,
          efi:
            respostaEfi ||
            null,
        });
    }
  }
);


// ============================================================
// 5. ESTORNO DE PAGAMENTO AVULSO NO CARTÃO
// ============================================================

app.post(
  '/cancelar-pagamento-cartao',
  async (req, res) => {
    console.log('==========================================');
    console.log('>>> SOLICITAÇÃO DE CANCELAMENTO CARTÃO AVULSO');
    console.log('>>> Dados seguros da solicitação:', resumoEntradaSeguro(req));
    console.log('==========================================');

    try {
      const usuario = await obterUsuarioSupabaseDoBearer(req);
      if (!usuario?.id) {
        console.warn('>>> Cancelamento recusado: usuário não autenticado.');
        return res.status(401).json({ success: false, error: 'Usuário não autenticado.' });
      }
      console.log('>>> Usuário autenticado ref:', referenciaSegura(usuario.id));

      const pagamentoId = String(req.body?.pagamento_id || '').trim();
      const motivoCancelamento = String(
        req.body?.motivo_cancelamento || 'Cancelamento solicitado pelo usuário dentro do prazo de 7 dias.'
      ).trim().substring(0, 1000);

      if (!pagamentoId) {
        return res.status(400).json({ success: false, error: 'pagamento_id é obrigatório.' });
      }

      const pagamento = await buscarPagamentoAvulsoCartaoPorIdUsuario(pagamentoId, usuario.id);
      console.log('>>> Pagamento localizado:', pagamento?.id || 'não encontrado');
      if (!pagamento) {
        return res.status(404).json({ success: false, error: 'Pagamento avulso de cartão não encontrado para este usuário.' });
      }

      const statusLocal = String(pagamento.status || '').trim().toLowerCase();
      console.log('>>> Status local:', statusLocal || 'não informado');

      if (statusLocal === 'estornado' || statusLocal === 'refunded') {
        return res.json({ success: true, ja_estornado: true, status: 'estornado', pagamento_id: pagamento.id, charge_id: pagamento.efi_charge_id });
      }
      if (statusLocal === 'estorno_solicitado') {
        return res.json({ success: true, ja_solicitado: true, status: 'estorno_solicitado', pagamento_id: pagamento.id, charge_id: pagamento.efi_charge_id, mensagem: 'O estorno deste pagamento já foi enviado à Efí.' });
      }

      const dataPagamentoTexto = pagamento.data_pagamento || pagamento.created_at;
      const dataPagamento = dataPagamentoTexto ? new Date(dataPagamentoTexto) : null;
      if (!dataPagamento || Number.isNaN(dataPagamento.getTime())) {
        return res.status(409).json({ success: false, error: 'A data do pagamento não está disponível ou é inválida.' });
      }

      const agora = new Date();
      const limiteEstorno = new Date(dataPagamento.getTime() + 7 * 24 * 60 * 60 * 1000);
      if (agora > limiteEstorno) {
        return res.status(409).json({ success: false, prazo_expirado: true, error: 'O prazo de 7 dias para solicitar o cancelamento deste pagamento já expirou.', data_pagamento: dataPagamento.toISOString(), limite_cancelamento: limiteEstorno.toISOString() });
      }

      const chargeId = String(pagamento.efi_charge_id || '').trim();
      console.log('>>> Charge ID:', chargeId || 'ausente');
      if (!chargeId) {
        return res.status(409).json({ success: false, error: 'O pagamento não possui efi_charge_id para solicitar o estorno.' });
      }

      const accessToken = await obterTokenCobranca();
      const consultaCharge = await axios({
        method: 'GET',
        url: `${EFI_COBRANCA_API_URL}/charge/${encodeURIComponent(chargeId)}`,
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        httpsAgent,
        timeout: 30000,
      });
      const statusEfi = String(consultaCharge.data?.data?.status || '').trim().toLowerCase();
      console.log('>>> Status atual Efí:', statusEfi || 'desconhecido');

      if (statusEfi === 'refunded') {
        const atualizado = await atualizarPagamentoAvulsoPorId(pagamento.id, {
          status: 'estornado', estorno_concluido_em: new Date().toISOString(), motivo_cancelamento: motivoCancelamento,
        });
        return res.json({ success: true, ja_estornado: true, status: 'estornado', pagamento: atualizado });
      }

      // Se ainda estiver approved, registra a intenção. O webhook tentará o refund
      // automaticamente quando a Efí informar que a cobrança chegou a paid.
      if (statusEfi === 'approved') {
        const atualizado = await atualizarPagamentoAvulsoPorId(pagamento.id, {
          status: 'estorno_pendente',
          estorno_solicitado_em: pagamento.estorno_solicitado_em || new Date().toISOString(),
          motivo_cancelamento: motivoCancelamento,
        });
        console.log('>>> Estorno registrado como pendente; aguardando status paid na Efí.');
        return res.status(202).json({
          success: true,
          aguardando_estorno: true,
          status: 'estorno_pendente',
          status_efi: statusEfi,
          mensagem: 'Cancelamento registrado. A cobrança ainda está aprovada e o estorno será enviado automaticamente quando a Efí liberar o status paid.',
          pagamento_id: pagamento.id,
          charge_id: chargeId,
          data_pagamento: dataPagamento.toISOString(),
          limite_cancelamento: limiteEstorno.toISOString(),
          pagamento: atualizado,
        });
      }

      if (statusEfi !== 'paid') {
        return res.status(409).json({ success: false, error: `A cobrança não está em um status que permita registrar/enviar o estorno. Status atual na Efí: ${statusEfi || 'desconhecido'}.`, status_efi: statusEfi || null, charge_id: chargeId });
      }

      const respostaEstorno = await solicitarEstornoCartaoEfi(accessToken, chargeId);
      const pagamentoAtualizado = await atualizarPagamentoAvulsoPorId(pagamento.id, {
        status: 'estorno_solicitado',
        estorno_solicitado_em: pagamento.estorno_solicitado_em || new Date().toISOString(),
        motivo_cancelamento: motivoCancelamento,
      });
      console.log('>>> Refund enviado à Efí com sucesso.');

      return res.json({ success: true, status: 'estorno_solicitado', mensagem: 'Solicitação de estorno enviada à Efí. O reembolso está em processamento.', pagamento_id: pagamento.id, charge_id: chargeId, data_pagamento: dataPagamento.toISOString(), limite_cancelamento: limiteEstorno.toISOString(), pagamento: pagamentoAtualizado, efi: respostaEstorno.data });
    } catch (error) {
      console.error('>>> ERRO AO ESTORNAR PAGAMENTO AVULSO NO CARTÃO:', resumirErroSeguro(error));
      const respostaEfi = error.response?.data;
      let mensagem = respostaEfi?.error_description || respostaEfi?.mensagem || respostaEfi?.message || respostaEfi?.error || error.message;
      if (typeof mensagem !== 'string') mensagem = JSON.stringify(mensagem);
      return res.status(error.response?.status || 500).json({ success: false, error: mensagem, efi: respostaEfi || null });
    }
  }
);

// ============================================================
// 5. CANCELAMENTO DA ASSINATURA PELO USUÁRIO
// ============================================================
//
// Requer Authorization: Bearer <access_token do Supabase>
//
// O backend identifica o usuário autenticado, localiza sua
// assinatura ativa e cancela na Efí antes de atualizar o banco.
// ============================================================
 
app.post(
  '/cancelar-assinatura',
 
  async (req, res) => {
    try {
      const usuario =
        await obterUsuarioSupabaseDoBearer(
          req
        );
 
      if (!usuario?.id) {
        return res
          .status(401)
          .json({
            success: false,
            error:
              'Usuário não autenticado.',
          });
      }
 
      const assinatura =
        await buscarAssinaturaAtivaPorUsuario(
          usuario.id
        );
 
      if (!assinatura) {
        return res
          .status(404)
          .json({
            success: false,
            error:
              'Nenhuma assinatura ativa encontrada para este usuário.',
          });
      }
 
      const subscriptionId =
        assinatura
          .efi_subscription_id;
 
      if (!subscriptionId) {
        return res
          .status(409)
          .json({
            success: false,
            error:
              'A assinatura não possui efi_subscription_id.',
          });
      }
 
      const accessToken =
        await obterTokenCobranca();
 
      console.log(
        `>>> Cancelando assinatura Efí ${subscriptionId} do usuário ref ${referenciaSegura(usuario.id)}.`
      );
 
      await axios({
        method: 'PUT',
 
        url:
          `${EFI_COBRANCA_API_URL}/subscription/${encodeURIComponent(
            subscriptionId
          )}/cancel`,
 
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
 
          'Content-Type':
            'application/json',
        },
 
        httpsAgent,
 
        timeout:
          30000,
      });
 
      const agora =
        new Date().toISOString();
 
      await atualizarAssinaturaPorSubscriptionId(
        String(subscriptionId),
        {
          status_assinatura:
            'cancelado',
 
          ultimo_status_efi:
            'canceled',
 
          cancelado_em:
            agora,
 
          motivo_cancelamento:
            String(
              req.body?.motivo ||
              'Cancelado pelo usuário no aplicativo.'
            ).substring(0, 500),
 
          data_inicio_inadimplencia:
            null,
 
          data_fim_carencia:
            null,
        }
      );
 
      console.log(
        `>>> Assinatura ${subscriptionId} cancelada com sucesso.`
      );
 
      return res.json({
        success: true,
        status:
          'cancelado',
        efi_subscription_id:
          String(subscriptionId),
      });
 
    } catch (error) {
      console.error(
        '>>> ERRO AO CANCELAR ASSINATURA:',
        resumirErroSeguro(error)
      );
 
      const respostaEfi =
        error.response?.data;
 
      let mensagem =
        respostaEfi
          ?.error_description ||
        respostaEfi
          ?.message ||
        respostaEfi
          ?.error ||
        error.message;
 
      if (
        typeof mensagem !==
        'string'
      ) {
        mensagem =
          JSON.stringify(
            mensagem
          );
      }
 
      return res
        .status(
          error.response?.status ||
          500
        )
        .json({
          success: false,
          error:
            mensagem,
          efi:
            respostaEfi ||
            null,
        });
    }
  }
);
 
// ============================================================
// 6. PROCESSAR CARÊNCIAS VENCIDAS
// ============================================================
//
// Rota administrativa para execução manual, se necessário.
// Também existe um processamento automático de hora em hora.
// ============================================================
 
app.post(
  '/processar-inadimplencia',
 
  async (req, res) => {
    try {
      if (!validarSyncSecret(req)) {
        return res
          .status(401)
          .json({
            success: false,
            error:
              'Não autorizado.',
          });
      }
 
      const alteradas =
        await processarCarenciasVencidas();
 
      return res.json({
        success: true,
        assinaturas_inadimplentes:
          alteradas,
      });
 
    } catch (error) {
      return res
        .status(500)
        .json({
          success: false,
          error:
            error.message,
        });
    }
  }
);
 
 
// ============================================================
// 7. REGISTRAR ASSINATURA JÁ EXISTENTE NA EFÍ
// ============================================================
//
// Útil para migrar uma assinatura criada antes da existência
// da tabela tab_assinaturas.
//
// Proteção:
// X-Sync-Secret: <SYNC_PLANOS_SECRET>
//
// Body:
// {
//   "subscription_id": "108083",
//   "usuario_id": "UUID_DO_USUARIO",
//   "plano_id": "UUID_DO_PLANO_NO_SUPABASE"
// }
// ============================================================
 
app.post(
  '/registrar-assinatura-existente',
 
  async (req, res) => {
    try {
      if (!validarSyncSecret(req)) {
        return res
          .status(401)
          .json({
            success: false,
            error:
              'Não autorizado.',
          });
      }
 
      const subscriptionId =
        String(
          req.body?.subscription_id ||
          ''
        ).trim();
 
      const usuarioId =
        String(
          req.body?.usuario_id ||
          ''
        ).trim();
 
      const planoIdSupabase =
        String(
          req.body?.plano_id ||
          ''
        ).trim();
 
      if (
        !subscriptionId ||
        !usuarioId ||
        !planoIdSupabase
      ) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              'subscription_id, usuario_id e plano_id são obrigatórios.',
          });
      }
 
      const accessToken =
        await obterTokenCobranca();
 
      const assinaturaEfi =
        await consultarAssinaturaEfiPorId(
          accessToken,
          subscriptionId
        );
 
      // Vincula a URL de webhook também à assinatura antiga.
      await axios({
        method: 'PUT',
 
        url:
          `${EFI_COBRANCA_API_URL}/subscription/${encodeURIComponent(
            subscriptionId
          )}/metadata`,
 
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
 
          'Content-Type':
            'application/json',
        },
 
        data: {
          notification_url:
            EFI_NOTIFICATION_URL,
 
          custom_id:
            assinaturaEfi.custom_id ||
            `acheobra-assinatura-importada-${subscriptionId}`,
        },
 
        httpsAgent,
 
        timeout:
          30000,
      });
 
      const statusEfi =
        String(
          assinaturaEfi.status ||
          ''
        )
          .trim()
          .toLowerCase();
 
      const statusInterno =
        statusEfi === 'canceled' ||
        statusEfi === 'expired'
          ? 'cancelado'
          : 'ativo';
 
      const valorCentavos =
        Number(
          assinaturaEfi.value ||
          0
        );
 
      const registro =
        await inserirOuAtualizarAssinaturaSupabase({
          usuario_id:
            usuarioId,
 
          plano_id:
            planoIdSupabase,
 
          efi_subscription_id:
            subscriptionId,
 
          efi_plan_id:
            assinaturaEfi?.plan?.plan_id
              ? String(
                  assinaturaEfi.plan.plan_id
                )
              : null,
 
          efi_charge_id:
            null,
 
          status_assinatura:
            statusInterno,
 
          ultimo_status_efi:
            statusEfi ||
            null,
 
          valor_recorrente:
            Number.isFinite(
              valorCentavos
            )
              ? valorCentavos / 100
              : null,
 
          data_inicio:
            normalizarDataIso(
              assinaturaEfi.created_at
            ) ||
            new Date().toISOString(),
 
          data_ultimo_pagamento:
            null,
 
          proxima_cobranca_em:
            normalizarDataIso(
              assinaturaEfi.next_execution
            ),
 
          data_inicio_inadimplencia:
            null,
 
          data_fim_carencia:
            null,
 
          cancelado_em:
            statusInterno === 'cancelado'
              ? new Date().toISOString()
              : null,
 
          motivo_cancelamento:
            statusInterno === 'cancelado'
              ? 'Assinatura importada já cancelada/expirada na Efí.'
              : null,
        });
 
      let sincronizacaoHistorico = null;

      try {
        sincronizacaoHistorico =
          await sincronizarHistoricoPagamentosRecorrentesAssinatura(
            subscriptionId,
            accessToken
          );
      } catch (erroSincronizacaoHistorico) {
        console.error(
          '>>> Assinatura importada, mas houve erro ao sincronizar o histórico recorrente:',
          resumirErroSeguro(erroSincronizacaoHistorico)
        );

        return res
          .status(502)
          .json({
            success: false,
            assinatura:
              registro,
            historico_recorrente_sincronizado:
              false,
            error:
              'A assinatura foi registrada, mas o histórico de cobranças recorrentes não pôde ser sincronizado.',
          });
      }

      return res.json({
        success: true,
        assinatura:
          registro,
        historico_recorrente_sincronizado:
          true,
        sincronizacao_historico:
          sincronizacaoHistorico,
      });
 
    } catch (error) {
      console.error(
        '>>> ERRO AO REGISTRAR ASSINATURA EXISTENTE:',
        resumirErroSeguro(error)
      );
 
      return res
        .status(
          error.response?.status ||
          500
        )
        .json({
          success: false,
          error:
            resumirErroSeguro(error),
        });
    }
  }
);
 
// ============================================================
// SINCRONIZAÇÃO MANUAL DO HISTÓRICO RECORRENTE
// ============================================================
//
// POST /sincronizar-pagamentos-recorrentes/:subscriptionId
//
// Protegida por SYNC_PLANOS_SECRET.
// Lê GET /v1/subscription/:id na Efí e percorre o history,
// gravando/atualizando cada charge_id em
// tab_pagamentos_recorrentes.
//
// Útil para:
// - importar cobranças anteriores à criação da nova tabela;
// - recuperar eventos perdidos;
// - conciliar manualmente uma assinatura específica.
// ============================================================

app.post(
  '/sincronizar-pagamentos-recorrentes/:subscriptionId',

  async (req, res) => {
    try {
      if (!validarSyncSecret(req)) {
        return res
          .status(401)
          .json({
            success: false,
            error: 'Não autorizado.',
          });
      }

      const subscriptionId = String(
        req.params?.subscriptionId || ''
      ).trim();

      if (!subscriptionId) {
        return res
          .status(400)
          .json({
            success: false,
            error: 'subscriptionId é obrigatório.',
          });
      }

      const resultado =
        await sincronizarHistoricoPagamentosRecorrentesAssinatura(
          subscriptionId
        );

      return res.json({
        success: true,
        ...resultado,
      });

    } catch (error) {
      console.error(
        '>>> ERRO AO SINCRONIZAR PAGAMENTOS RECORRENTES:',
        resumirErroSeguro(error)
      );

      return res
        .status(
          error.response?.status ||
          500
        )
        .json({
          success: false,
          error:
            resumirErroSeguro(error),
        });
    }
  }
);

// ============================================================
// DIAGNÓSTICO SEGURO DE COBRANÇA EFÍ
// ============================================================
//
// GET /diagnostico-charge/:chargeId
//
// Segurança:
// - exige o mesmo SYNC_PLANOS_SECRET das rotas administrativas;
// - aceita X-Sync-Secret ou Authorization: Bearer <SYNC_PLANOS_SECRET>;
// - não devolve CPF, e-mail, telefone, cartão, CVV, payment_token,
//   token OAuth, Client Secret nem o payload bruto da Efí;
// - retorna somente informações técnicas úteis para diagnóstico.
//
// Exemplo:
// curl -H "X-Sync-Secret: SEU_SYNC_PLANOS_SECRET" \
//   https://efi-backend-1.onrender.com/diagnostico-charge/45019980
// ============================================================

function resumirCobrancaEfiParaDiagnostico(respostaEfi) {
  const raiz =
    respostaEfi?.data &&
    typeof respostaEfi.data === 'object'
      ? respostaEfi.data
      : (
          respostaEfi &&
          typeof respostaEfi === 'object'
            ? respostaEfi
            : {}
        );

  const charge =
    raiz?.charge &&
    typeof raiz.charge === 'object'
      ? raiz.charge
      : raiz;

  const payment =
    charge?.payment &&
    typeof charge.payment === 'object'
      ? charge.payment
      : {};

  const refusal =
    charge?.refusal &&
    typeof charge.refusal === 'object'
      ? charge.refusal
      : (
          payment?.refusal &&
          typeof payment.refusal === 'object'
            ? payment.refusal
            : {}
        );

  const historicoBruto =
    Array.isArray(charge?.history)
      ? charge.history
      : (
          Array.isArray(charge?.status_history)
            ? charge.status_history
            : (
                Array.isArray(charge?.events)
                  ? charge.events
                  : []
              )
        );

  const historico =
    historicoBruto
      .slice(-20)
      .map((item) => ({
        type:
          item?.type
            ? sanitizarTextoSeguro(item.type)
            : null,

        status:
          item?.status
            ? sanitizarTextoSeguro(
                typeof item.status === 'object'
                  ? (
                      item.status.current ||
                      item.status.new ||
                      JSON.stringify(item.status)
                    )
                  : item.status
              )
            : null,

        created_at:
          normalizarDataIso(
            item?.created_at ||
            item?.date ||
            item?.timestamp
          ),

        reason:
          item?.reason
            ? sanitizarTextoSeguro(item.reason)
            : null,

        message:
          item?.message
            ? sanitizarTextoSeguro(item.message)
            : null,
      }));

  return {
    charge_id:
      charge?.charge_id ??
      charge?.id ??
      null,

    status:
      charge?.status
        ? String(charge.status).trim().toLowerCase()
        : null,

    total_centavos:
      Number.isFinite(
        Number(
          charge?.total ??
          charge?.value
        )
      )
        ? Number(
            charge?.total ??
            charge?.value
          )
        : null,

    installments:
      charge?.installments ??
      payment?.installments ??
      null,

    installment_value:
      charge?.installment_value ??
      payment?.installment_value ??
      null,

    created_at:
      normalizarDataIso(
        charge?.created_at
      ),

    paid_at:
      normalizarDataIso(
        charge?.paid_at ||
        charge?.received_by_bank_at ||
        payment?.paid_at
      ),

    payment_method:
      payment?.method
        ? sanitizarTextoSeguro(payment.method)
        : (
            charge?.payment_method
              ? sanitizarTextoSeguro(charge.payment_method)
              : null
          ),

    card_brand:
      payment?.brand
        ? sanitizarTextoSeguro(payment.brand)
        : (
            payment?.card_brand
              ? sanitizarTextoSeguro(payment.card_brand)
              : null
          ),

    subscription_id:
      charge?.subscription_id ??
      charge?.identifiers?.subscription_id ??
      raiz?.subscription_id ??
      null,

    plan_id:
      charge?.plan_id ??
      charge?.plan?.plan_id ??
      raiz?.plan_id ??
      raiz?.plan?.plan_id ??
      null,

    refusal:
      Object.keys(refusal).length > 0
        ? {
            reason:
              refusal?.reason
                ? sanitizarTextoSeguro(refusal.reason)
                : null,

            retry:
              refusal?.retry ?? null,

            code:
              refusal?.code
                ? sanitizarTextoSeguro(refusal.code)
                : null,
          }
        : null,

    historico,
  };
}

app.get(
  '/diagnostico-charge/:chargeId',

  async (req, res) => {
    try {
      if (!validarSyncSecret(req)) {
        return res
          .status(401)
          .json({
            success: false,
            error: 'Não autorizado.',
          });
      }

      const chargeId =
        String(
          req.params.chargeId || ''
        ).trim();

      if (!/^\d+$/.test(chargeId)) {
        return res
          .status(400)
          .json({
            success: false,
            error: 'charge_id inválido.',
          });
      }

      console.log(
        '>>> DIAGNÓSTICO EFÍ - CONSULTANDO CHARGE:',
        chargeId
      );

      const accessToken =
        await obterTokenCobranca();

      const response =
        await axios({
          method: 'GET',

          url:
            `${EFI_COBRANCA_API_URL}/charge/${encodeURIComponent(
              chargeId
            )}`,

          headers: {
            Authorization:
              `Bearer ${accessToken}`,

            'Content-Type':
              'application/json',
          },

          httpsAgent,

          timeout:
            30000,
        });

      const diagnostico =
        resumirCobrancaEfiParaDiagnostico(
          response.data
        );

      console.log(
        '>>> DIAGNÓSTICO EFÍ CONCLUÍDO:',
        {
          charge_id:
            diagnostico.charge_id ||
            chargeId,

          status:
            diagnostico.status,

          subscription_id:
            diagnostico.subscription_id,

          refusal:
            diagnostico.refusal,
        }
      );

      return res.json({
        success: true,
        ambiente: 'producao',
        charge_id: chargeId,
        diagnostico,
      });

    } catch (error) {
      console.error(
        '>>> ERRO NO DIAGNÓSTICO DA CHARGE EFÍ:',
        resumirErroSeguro(error)
      );

      return res
        .status(
          error.response?.status ||
          500
        )
        .json({
          success: false,
          error:
            resumirErroSeguro(error),
        });
    }
  }
);

// ============================================================
// ROTA DE TESTE
// ============================================================
 
app.get(
  '/',
 
  (req, res) => {
 
    return res.json({
      success:
        true,
 
      message:
        'Backend Ache Obra / Efí funcionando.',
 
      ambiente:
        'producao',
 
      rotas: {
        pix:
          '/gerar-pix',

        status_pix:
          '/status-pix/:txid',

        cancelar_pagamento_pix:
          '/cancelar-pagamento-pix',
 
        cartao:
          '/cobrar-cartao',
 
        assinatura:
          '/cobrar-assinatura',

        trocar_assinatura:
          '/trocar-assinatura',

        diagnostico_charge:
          '/diagnostico-charge/:chargeId',
 
        sincronizar_planos_efi:
          '/sincronizar-planos-efi',
 
        webhook_efi:
          '/webhook/efi',
 
        cancelar_pagamento_cartao:
          '/cancelar-pagamento-cartao',
 
        cancelar_assinatura:
          '/cancelar-assinatura',
 
        processar_inadimplencia:
          '/processar-inadimplencia',
 
        registrar_assinatura_existente:
          '/registrar-assinatura-existente',

        sincronizar_pagamentos_recorrentes:
          '/sincronizar-pagamentos-recorrentes/:subscriptionId',
      },
    });
  }
);
 

// ============================================================
// PROCESSAMENTO AUTOMÁTICO DE ESTORNOS PENDENTES
// ============================================================
let processandoEstornosPendentes =
  false;

async function processarEstornosPendentes() {
  if (
    processandoEstornosPendentes
  ) {
    console.log(
      '>>> Verificação de estornos de cartão já está em andamento. Ignorando execução simultânea.'
    );

    return 0;
  }

  processandoEstornosPendentes =
    true;

  try {
    const { supabaseUrl } = obterConfiguracaoSupabase();
    const response =
      await requisicaoSupabaseInterna({
        method: 'GET',
        url: `${supabaseUrl}/rest/v1/tab_pagamentos_avulsos`,
        params: {
          select: 'id,efi_charge_id,status',
          tipo_pagamento: 'eq.cartao',
          status: 'eq.estorno_pendente',
          limit: 100,
        },
        timeout: 30000,
      });
    const pendentes = Array.isArray(response.data) ? response.data : [];
    for (const pagamento of pendentes) {
      if (!pagamento.efi_charge_id) continue;
      try { await processarEstornoPendentePorChargeId(String(pagamento.efi_charge_id)); }
      catch (error) { console.error(`>>> Falha ao reprocessar estorno pendente ${pagamento.id}:`, resumirErroSeguro(error)); }
    }
    return pendentes.length;
  } catch (error) {
    console.error('>>> Erro ao buscar/processar estornos pendentes:', resumirErroSeguro(error));
    return 0;

  } finally {
    processandoEstornosPendentes =
      false;
  }
}

// ============================================================
// PROCESSAMENTO AUTOMÁTICO DE DEVOLUÇÕES PIX PENDENTES
// ============================================================

let processandoDevolucoesPixPendentes =
  false;

async function processarDevolucoesPixPendentes() {
  if (
    processandoDevolucoesPixPendentes
  ) {
    console.log(
      '>>> Verificação de devoluções Pix já está em andamento. Ignorando execução simultânea.'
    );

    return 0;
  }

  processandoDevolucoesPixPendentes =
    true;

  try {
    const { supabaseUrl } =
      obterConfiguracaoSupabase();

    const response =
      await requisicaoSupabaseInterna({
        method: 'GET',
        url:
          `${supabaseUrl}/rest/v1/tab_pagamentos_avulsos`,
        params: {
          select: '*',
          tipo_pagamento: 'eq.pix',
          status: 'eq.estorno_solicitado',
          limit: 100,
        },
        timeout: 30000,
      });

    const pendentes =
      Array.isArray(response.data)
        ? response.data
        : [];

    for (const pagamento of pendentes) {
      try {
        const resultado =
          await processarDevolucaoPixPendente(
            pagamento
          );

        console.log(
          '>>> Reprocessamento devolução Pix:',
          pagamento.id,
          resultado?.status ||
          resultado?.motivo ||
          'sem alteração'
        );
      } catch (error) {
        console.error(
          `>>> Falha ao reprocessar devolução Pix ${pagamento.id}:`,
          resumirErroSeguro(error)
        );
      }
    }

    return pendentes.length;

  } catch (error) {
    console.error(
      '>>> Erro ao buscar/processar devoluções Pix pendentes:',
      resumirErroSeguro(error)
    );

    return 0;

  } finally {
    processandoDevolucoesPixPendentes =
      false;
  }
}


// ============================================================
// INICIAR SERVIDOR
// ============================================================
 
app.listen(
  PORT,
 
  () => {
 
    console.log(
      '=========================================='
    );
 
    console.log(
      `Servidor rodando na porta ${PORT}`
    );
 
    console.log(
      'Backend Ache Obra iniciado com sucesso.'
    );
 
    console.log(
      'Ambiente Efí: PRODUÇÃO'
    );
 
    console.log(
      '=========================================='
    );
  }
);
 
// ============================================================
// PROCESSAMENTO AUTOMÁTICO DE INADIMPLÊNCIA
// ============================================================
//
// A cada 1 hora, o backend transforma em "inadimplente"
// assinaturas que permaneceram em "pagamento_pendente"
// além dos 7 dias de carência.
// ============================================================
 
setTimeout(
  () => {
    processarCarenciasVencidas();
  },
  15000
);
 
setInterval(
  () => {
    processarCarenciasVencidas();
  },
  60 * 60 * 1000
);


// Reprocessa estornos pendentes 15s após subir e depois a cada 5 minutos.
setTimeout(() => { processarEstornosPendentes(); }, 15000);
setInterval(() => { processarEstornosPendentes(); }, 5 * 60 * 1000);


// Reprocessa devoluções Pix pendentes 20s após subir e depois a cada 5 minutos.
setTimeout(() => { processarDevolucoesPixPendentes(); }, 20000);
setInterval(() => { processarDevolucoesPixPendentes(); }, 5 * 60 * 1000);
