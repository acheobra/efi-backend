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

    // Mantido conforme sua configuração atual.
    // Em produção, o ideal é validar o certificado.
    rejectUnauthorized: false,
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

  const credentials =
    obterCredenciais();

  const response =
    await axios({
      method:
        'POST',

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
      method:
        'POST',

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
// SUPABASE - CONSULTAR PLANOS RECORRENTES
// ============================================================

async function buscarPlanosRecorrentesSupabase() {

  const {
    supabaseUrl,
  } = obterConfiguracaoSupabase();

  const response =
    await axios({
      method:
        'GET',

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
      method:
        'PATCH',

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
      method:
        'GET',

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
      method:
        'POST',

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

      // Valida as variáveis antes de começar.
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

          // ----------------------------------------------------
          // Primeiro procura na Efí para evitar duplicação
          // em caso de retry após falha anterior.
          // ----------------------------------------------------

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
            mensagemErro
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
              erroAtualizacao
                .response
                ?.data ||
              erroAtualizacao
                .message
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
        error.response?.data ||
        error.message
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
            error.response
              ?.data ||
            error.message,
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
              `https://pix-h.api.efipay.com.br/v2/loc/${locId}`,

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

      return res.json({
        success:
          true,

        txid:
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
      // Validações
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

      // Se vier com código do Brasil, remove o 55.
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
      // Metadata
      // --------------------------------------------------------

      const customIdParts = [
        'acheobra',

        usuario_id
          ? `user-${usuario_id}`
          : null,

        origem_tipo
          ? `tipo-${origem_tipo}`
          : null,

        origem_id
          ? `origem-${origem_id}`
          : null,
      ].filter(Boolean);

      const customId =
        customIdParts
          .join('|')
          .substring(
            0,
            255
          );

      // --------------------------------------------------------
      // Payload oficial da cobrança de cartão
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
            customId ||
            'pagamento-ache-obra',
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

      const status =
        dados?.data
          ?.status;

      const refusal =
        dados?.data
          ?.refusal ||
        null;

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

      const aprovado =
        status ===
          'approved' ||
        status ===
          'paid';

      return res.json({
        success:
          true,

        approved:
          aprovado,

        pago:
          aprovado,

        charge_id:
          chargeId,

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
      // Validações
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
      // Metadata
      // --------------------------------------------------------

      const customIdParts = [
        'acheobra',

        usuario_id
          ? `user-${usuario_id}`
          : null,

        origem_tipo
          ? `tipo-${origem_tipo}`
          : null,

        origem_id
          ? `origem-${origem_id}`
          : null,
      ].filter(Boolean);

      const customId =
        customIdParts
          .join('|')
          .substring(
            0,
            255
          );

      // --------------------------------------------------------
      // Payload da assinatura
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
            customId ||
            'assinatura-ache-obra',
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

      const charge =
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

      const assinaturaAtiva =
        status ===
        'active';

      return res
        .status(201)
        .json({
          success:
            true,

          approved:
            assinaturaAtiva,

          pago:
            assinaturaAtiva,

          status:
            status,

          subscription_id:
            subscriptionId,

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
        'homologacao',

      rotas: {
        pix:
          '/gerar-pix',

        cartao:
          '/cobrar-cartao',

        assinatura:
          '/cobrar-assinatura',

        sincronizar_planos_efi:
          '/sincronizar-planos-efi',
      },
    });
  }
);

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
      'Ambiente Efí: HOMOLOGAÇÃO'
    );

    console.log(
      '=========================================='
    );
  }
);