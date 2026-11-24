//! Fluxo de login automático via navegador controlado por CDP (`chromiumoxide`, RF16, RNF12, RNF13).
//!
//! Abstrai as verificações determinísticas (validação de domínio e iframes,
//! detecção de CAPTCHA/MFA por URL e HTML, normalização e casamento de `url_sucesso`,
//! criação segura do diretório de perfil persistente com permissão `0700` no Unix)
//! e executa o fluxo em um runtime Tokio local criado sob demanda.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::FrameId;
use chromiumoxide::cdp::js_protocol::runtime::EvaluateParams;
use chromiumoxide::element::Element;
use chromiumoxide::page::Page;
use futures::StreamExt;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::dominio::{self, DominioError};
use crate::navegador::{self, NavegadorError};

/// Tempo curto (em segundos) para verificar se o seletor de senha aparece antes de
/// concluir que a sessão já está ativa na página carregada.
const TIMEOUT_CURTO_SESSAO_ATIVA_SEGS: u64 = 3;

#[derive(Debug, Error)]
pub enum AutomacaoError {
    #[error(transparent)]
    Dominio(#[from] DominioError),

    #[error(transparent)]
    Navegador(#[from] NavegadorError),

    #[error("Falha ao preparar o diretório de perfil do navegador: {0}")]
    DiretorioPerfil(std::io::Error),

    #[error("Falha ao criar o runtime assíncrono de automação: {0}")]
    Runtime(std::io::Error),

    #[error("Falha ao iniciar ou controlar o navegador: {0}")]
    Cdp(String),
}

/// Parâmetros de entrada para o fluxo `executar_login`.
///
/// A implementação de `Debug` oculta a senha para evitar exposição acidental (RNF05).
pub struct ParametrosLogin {
    pub credencial_id: i64,
    pub url_login: String,
    pub dominio_principal: String,
    pub identificador: String,
    pub senha: Zeroizing<String>,
    pub seletor_usuario: Option<String>,
    pub seletor_senha: String,
    pub seletor_botao: Option<String>,
    pub url_sucesso: Option<String>,
    pub envio_automatico: bool,
    pub timeout_segundos: u64,
    pub navegador_padrao: String,
    /// Diretório base de dados do aplicativo (onde a pasta `perfis/credencial-<id>` será criada).
    pub diretorio_dados_app: PathBuf,
    /// Flag opcional de interrupção (Ctrl+C) compartilhada com a CLI.
    pub interrompido: Option<Arc<AtomicBool>>,
    /// Se `true`, aguarda o usuário fechar o navegador ou pressionar Enter/Ctrl+C ao final.
    pub aguardar_fechamento: bool,
}

impl fmt::Debug for ParametrosLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParametrosLogin")
            .field("credencial_id", &self.credencial_id)
            .field("url_login", &self.url_login)
            .field("dominio_principal", &self.dominio_principal)
            .field("identificador", &self.identificador)
            .field("senha", &"<protegida>")
            .field("seletor_usuario", &self.seletor_usuario)
            .field("seletor_senha", &self.seletor_senha)
            .field("seletor_botao", &self.seletor_botao)
            .field("url_sucesso", &self.url_sucesso)
            .field("envio_automatico", &self.envio_automatico)
            .field("timeout_segundos", &self.timeout_segundos)
            .field("navegador_padrao", &self.navegador_padrao)
            .field("diretorio_dados_app", &self.diretorio_dados_app)
            .field("aguardar_fechamento", &self.aguardar_fechamento)
            .finish()
    }
}

/// Status final da tentativa de login automático (mapeia para `ResultadoEvento` na auditoria).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusLogin {
    /// Login concluído com sucesso (ou sessão persistente já ativa).
    Sucesso,
    /// Intervenção manual necessária (CAPTCHA/MFA detectado, envio manual ou `url_sucesso` não confirmada).
    Parcial,
    /// Fluxo abortado por erro ou violação de segurança (ex: domínio não autorizado).
    Falha,
    /// Operação interrompida pelo usuário (Ctrl+C) antes da conclusão.
    Cancelado,
}

/// Resultado detalhado retornado por `executar_login`.
#[derive(Debug, Clone)]
pub struct ResultadoLogin {
    pub status: StatusLogin,
    /// Descrição clara (sem segredos) do desfecho da operação.
    pub motivo: String,
    /// Indica se uma sessão prévia já estava autenticada sem precisar digitar a senha.
    pub sessao_ja_ativa: bool,
    /// Caminho do diretório de perfil persistente utilizado.
    pub diretorio_perfil: PathBuf,
    /// Nome do navegador efetivamente utilizado.
    pub navegador: String,
}

/// Cria (se necessário) e retorna o diretório de perfil persistente para a credencial:
/// `<diretorio_dados_app>/perfis/credencial-<credencial_id>`.
///
/// Como o diretório de perfil armazena cookies e tokens de sessão, ele é tratado como
/// segredo e criado com permissão `0700` em sistemas Unix.
pub fn preparar_diretorio_perfil(
    diretorio_dados_app: &Path,
    credencial_id: i64,
) -> Result<PathBuf, AutomacaoError> {
    let dir_perfis = diretorio_dados_app.join("perfis");
    let dir_credencial = dir_perfis.join(format!("credencial-{credencial_id}"));

    std::fs::create_dir_all(&dir_credencial).map_err(AutomacaoError::DiretorioPerfil)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&dir_perfis, perm.clone())
            .map_err(AutomacaoError::DiretorioPerfil)?;
        std::fs::set_permissions(&dir_credencial, perm).map_err(AutomacaoError::DiretorioPerfil)?;
    }

    Ok(dir_credencial)
}

/// Normaliza uma URL para comparação de `url_sucesso`:
/// - Faz parse com `url::Url`;
/// - Remove fragmento (`#...`);
/// - Remove barra final redundante do caminho (exceto quando o caminho é apenas `"/"`).
pub fn normalizar_url_para_comparacao(raw: &str) -> Option<(String, String, Option<String>)> {
    let parsed = Url::parse(raw.trim()).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = parsed.host_str()?.to_ascii_lowercase();
    let port_part = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let origem = format!("{scheme}://{host}{port_part}");

    let mut path = parsed.path().to_string();
    while path.len() > 1 && path.ends_with('/') {
        path.pop();
    }

    let query = parsed.query().map(str::to_string);
    Some((origem, path, query))
}

/// Verifica se a `url_atual` bate com a `url_sucesso` esperada (igualdade ou prefixo
/// de caminho/query na mesma origem após normalização).
pub fn url_bate_com_sucesso(url_atual: &str, url_sucesso: &str) -> bool {
    let Some((orig_atual, path_atual, query_atual)) = normalizar_url_para_comparacao(url_atual)
    else {
        return false;
    };
    let Some((orig_esp, path_esp, query_esp)) = normalizar_url_para_comparacao(url_sucesso) else {
        return false;
    };

    if orig_atual != orig_esp {
        return false;
    }

    // Verifica se o path atual é igual ao esperado ou está abaixo dele em limite de segmento '/'
    let path_casa = if path_esp == "/" || path_atual == path_esp {
        true
    } else if let Some(resto) = path_atual.strip_prefix(&path_esp) {
        resto.starts_with('/')
    } else {
        false
    };

    if !path_casa {
        return false;
    }

    // Se a url_sucesso especificou query string, exige que a query atual comece com ela
    match (query_esp, query_atual) {
        (Some(q_esp), Some(q_atual)) => q_atual == q_esp || q_atual.starts_with(&q_esp),
        (Some(_), None) => false,
        (None, _) => true,
    }
}

/// Inspeciona a URL atual, as URLs dos frames/iframes e o HTML da página em busca de
/// sinais de CAPTCHA ou autenticação multifator (MFA / 2FA / OTP) (RNF13).
///
/// Quando detectado, retorna `Some(motivo)` descrevendo o mecanismo encontrado para que
/// o fluxo automático pare imediatamente e devolva o controle ao usuário.
pub fn detectar_captcha_ou_mfa(
    url_atual: &str,
    urls_frames: &[String],
    html_pagina: &str,
) -> Option<String> {
    let url_lower = url_atual.to_ascii_lowercase();
    let html_lower = html_pagina.to_ascii_lowercase();

    // 1. Verificar URLs de iframes conhecidos de CAPTCHA
    let padroes_frame_captcha = [
        ("recaptcha", "reCAPTCHA"),
        ("google.com/recaptcha", "Google reCAPTCHA"),
        ("recaptcha.net", "reCAPTCHA"),
        ("hcaptcha.com", "hCaptcha"),
        ("challenges.cloudflare.com", "Cloudflare Turnstile"),
        ("turnstile", "Cloudflare Turnstile"),
        ("arkoselabs.com", "Arkose Labs CAPTCHA"),
        ("funcaptcha", "FunCaptcha"),
    ];

    for frame_url in urls_frames {
        let f_lower = frame_url.to_ascii_lowercase();
        for (padrao, nome) in padroes_frame_captcha {
            if f_lower.contains(padrao) {
                return Some(format!("CAPTCHA detectado em frame ({nome})"));
            }
        }
    }

    // 2. Verificar elementos e widgets de CAPTCHA no HTML
    let padroes_html_captcha = [
        ("class=\"g-recaptcha\"", "reCAPTCHA"),
        ("class='g-recaptcha'", "reCAPTCHA"),
        ("data-sitekey=", "widget de CAPTCHA (data-sitekey)"),
        ("class=\"h-captcha\"", "hCaptcha"),
        ("class='h-captcha'", "hCaptcha"),
        ("class=\"cf-turnstile\"", "Cloudflare Turnstile"),
        ("class='cf-turnstile'", "Cloudflare Turnstile"),
        (
            "challenges.cloudflare.com/turnstile",
            "Cloudflare Turnstile",
        ),
        ("google.com/recaptcha/api", "Google reCAPTCHA"),
        ("hcaptcha.com/1/api.js", "hCaptcha"),
    ];

    for (padrao, nome) in padroes_html_captcha {
        if html_lower.contains(padrao) {
            return Some(format!("CAPTCHA detectado na página ({nome})"));
        }
    }

    // 3. Verificar indicadores de MFA / 2FA / OTP na URL ou no HTML
    let padroes_html_mfa = [
        (
            "autocomplete=\"one-time-code\"",
            "campo de código de uso único (one-time-code)",
        ),
        (
            "autocomplete='one-time-code'",
            "campo de código de uso único (one-time-code)",
        ),
        ("name=\"otp\"", "campo OTP"),
        ("name='otp'", "campo OTP"),
        ("name=\"totp\"", "campo TOTP"),
        ("name='totp'", "campo TOTP"),
        ("id=\"otp\"", "campo OTP"),
        ("id=\"totp\"", "campo TOTP"),
        ("name=\"two_factor\"", "campo de segundo fator (2FA)"),
        ("name=\"2fa\"", "campo de segundo fator (2FA)"),
        ("name=\"mfa_code\"", "campo de código MFA"),
        (
            "verifique que você é humano",
            "desafio de verificação humana",
        ),
        ("verify you are human", "desafio de verificação humana"),
        (
            "autenticação de dois fatores",
            "solicitação de autenticação de dois fatores (2FA)",
        ),
        (
            "two-factor authentication",
            "solicitação de autenticação de dois fatores (2FA)",
        ),
        (
            "digite o código de verificação",
            "solicitação de código de verificação (MFA)",
        ),
        (
            "enter the verification code",
            "solicitação de código de verificação (MFA)",
        ),
    ];

    for (padrao, nome) in padroes_html_mfa {
        if html_lower.contains(padrao) {
            return Some(format!("Desafio de segurança/MFA detectado ({nome})"));
        }
    }

    let padroes_url_desafio = [
        "/checkpoint/challenge",
        "/sessions/two-factor",
        "/mfa-challenge",
        "/2fa-challenge",
        "/captcha",
    ];
    for padrao in padroes_url_desafio {
        if url_lower.contains(padrao) {
            return Some(format!("Página de desafio/MFA detectada na URL ({padrao})"));
        }
    }

    None
}

/// Verifica se a flag de interrupção (Ctrl+C) foi acionada.
fn foi_interrompido(flag: &Option<Arc<AtomicBool>>) -> bool {
    flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst))
}

/// Executa o fluxo completo de login automático criando um runtime Tokio local.
pub fn executar_login(params: &ParametrosLogin) -> Result<ResultadoLogin, AutomacaoError> {
    // 1. Validar antecipadamente se a URL de login configurada é compatível com o dominio_principal
    dominio::validar_url_contra_dominio(&params.url_login, &params.dominio_principal)?;

    // 2. Localizar o executável do navegador antes de abrir o perfil
    let executavel = navegador::localizar_navegador(&params.navegador_padrao)?;

    // 3. Preparar o diretório de perfil persistente com permissão 0700 no Unix
    let diretorio_perfil =
        preparar_diretorio_perfil(&params.diretorio_dados_app, params.credencial_id)?;

    // 4. Criar runtime Tokio local (a CLI é síncrona)
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(AutomacaoError::Runtime)?;

    rt.block_on(executar_login_async(params, &executavel, diretorio_perfil))
}

async fn fechar_navegador_limpo(browser: &mut Browser) {
    // Todas as etapas têm timeout: se o navegador já morreu (ex.: o Ctrl+C do
    // terminal também chega ao processo do Chromium), o `close` via CDP nunca
    // recebe resposta e travaria o comando (e o `cofre shell`) para sempre.
    let _ = tokio::time::timeout(Duration::from_secs(3), browser.close()).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), browser.wait()).await;
    if let Ok(None) = browser.try_wait() {
        let _ = tokio::time::timeout(Duration::from_secs(3), browser.kill()).await;
    }
}

/// Escapa uma string como literal JavaScript seguro (`"..."`).
fn escapar_string_js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Coleta as URLs de todos os frames da página e identifica as URLs dos frames
/// (`document.location.href` do contexto do frame) que contêm qualquer um dos seletores informados.
async fn inspecionar_frames_e_seletores(
    page: &Page,
    seletores: &[&str],
) -> Result<(Vec<String>, Vec<String>), AutomacaoError> {
    let frames: Vec<FrameId> = page.frames().await.unwrap_or_default();
    let mut todas_urls_frames = Vec::new();
    let mut urls_frames_com_campos = Vec::new();

    for frame_id in frames {
        if let Ok(Some(f_url)) = page.frame_url(frame_id.clone()).await {
            if !f_url.is_empty() && f_url != "about:blank" {
                todas_urls_frames.push(f_url.clone());
            }
        }

        // Verifica no contexto de execução do frame se algum dos seletores existe e obtém document.location.href
        if let Ok(Some(ctx_id)) = page.frame_execution_context(frame_id).await {
            for seletor in seletores {
                let seletor_js = escapar_string_js(seletor);
                let expr = format!(
                    "(() => {{ const el = document.querySelector({seletor_js}); return el ? document.location.href : null; }})()"
                );
                let eval_params = EvaluateParams::builder()
                    .expression(expr)
                    .context_id(ctx_id)
                    .build()
                    .map_err(|e| AutomacaoError::Cdp(e.to_string()))?;

                if let Ok(res) = page.evaluate_expression(eval_params).await {
                    if let Ok(Some(loc)) = res.into_value::<Option<String>>() {
                        if !urls_frames_com_campos.contains(&loc) {
                            urls_frames_com_campos.push(loc);
                        }
                    }
                }
            }
        }
    }

    Ok((todas_urls_frames, urls_frames_com_campos))
}

/// Aguarda até `timeout` pelo aparecimento de um elemento que corresponda a `seletor`.
async fn aguardar_elemento(
    page: &Page,
    seletor: &str,
    timeout: Duration,
    interrompido: &Option<Arc<AtomicBool>>,
) -> Option<Element> {
    let fim = Instant::now() + timeout;
    loop {
        if foi_interrompido(interrompido) {
            return None;
        }
        if let Ok(el) = page.find_element(seletor).await {
            return Some(el);
        }
        if Instant::now() >= fim {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Limpa o valor atual de um campo de formulário e digita o texto via CDP.
///
/// Nunca inclui o valor digitado em mensagens de erro ou logs (RNF05).
async fn preencher_campo(el: &Element, valor: &str) -> Result<(), AutomacaoError> {
    // O foco é dado via JS, e não por clique: um clique de mouse vai para as
    // coordenadas do elemento, onde um iframe de outra origem sobreposto
    // (clickjacking) poderia receber o foco e, com ele, a digitação da senha.
    // Como `type_str` envia as teclas para o elemento focado da aba, confere-se
    // em seguida que o foco está exatamente neste elemento do documento validado.
    let focado = el
        .call_js_fn(
            "function() { this.focus(); if ('value' in this) { this.value = ''; } \
             return document.activeElement === this; }",
            false,
        )
        .await
        .ok()
        .and_then(|r| r.result.value)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !focado {
        return Err(AutomacaoError::Cdp(
            "Não foi possível focar o campo do formulário com segurança; preenchimento abortado"
                .into(),
        ));
    }
    el.type_str(valor).await.map_err(|_| {
        AutomacaoError::Cdp("Falha ao preencher campo do formulário via CDP".into())
    })?;
    Ok(())
}

/// Aguarda o usuário fechar a janela do navegador ou pressionar Enter / Ctrl+C no terminal.
/// Quando o usuário encerra pelo terminal (Enter ou Ctrl+C), o navegador é fechado de forma limpa.
async fn aguardar_usuario_ou_fechamento(
    browser: &mut Browser,
    interrompido: &Option<Arc<AtomicBool>>,
) {
    let (tx_enter, mut rx_enter) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
        let _ = tx_enter.send(());
    });

    let enter_recebido = loop {
        if foi_interrompido(interrompido) {
            fechar_navegador_limpo(browser).await;
            break false;
        }

        if rx_enter.try_recv().is_ok() {
            fechar_navegador_limpo(browser).await;
            break true;
        }

        match browser.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) => {}
            Err(_) => break false,
        }

        // Se todas as abas foram fechadas pelo usuário, encerra o processo do navegador
        if let Ok(paginas) = browser.pages().await {
            if paginas.is_empty() {
                fechar_navegador_limpo(browser).await;
                break false;
            }
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    };

    // A thread leitora continua bloqueada em `read_line` até chegar uma linha.
    // Se ela ficasse viva, no `cofre shell` engoliria o próximo comando digitado;
    // por isso, quando o encerramento não veio pelo Enter, espera-se por ele aqui.
    if !enter_recebido {
        println!("Navegador fechado. Pressione Enter para continuar.");
        let _ = rx_enter.await;
    }
}

async fn executar_login_async(
    params: &ParametrosLogin,
    executavel: &Path,
    diretorio_perfil: PathBuf,
) -> Result<ResultadoLogin, AutomacaoError> {
    let timeout_total = Duration::from_secs(params.timeout_segundos.max(1));

    // 1. Lançar navegador visível (with_head), user_data_dir persistente e porta 0 (--remote-debugging-port=0)
    let config = BrowserConfig::builder()
        .chrome_executable(executavel)
        .user_data_dir(&diretorio_perfil)
        .port(0)
        .with_head()
        .viewport(None)
        .launch_timeout(timeout_total)
        .request_timeout(timeout_total)
        .build()
        .map_err(AutomacaoError::Cdp)?;

    let (mut browser, mut handler) = Browser::launch(config)
        .await
        .map_err(|e| AutomacaoError::Cdp(e.to_string()))?;

    let handler_task =
        tokio::spawn(async move { while let Some(_evento) = handler.next().await {} });

    let desfecho = fluxo_pagina_login(&mut browser, params, timeout_total).await;

    let resultado = match desfecho {
        Ok((status, motivo, sessao_ja_ativa)) => {
            // Se falhou por domínio não autorizado ou foi cancelado, fecha imediatamente o navegador por segurança
            if matches!(status, StatusLogin::Falha | StatusLogin::Cancelado) {
                fechar_navegador_limpo(&mut browser).await;
            } else if params.aguardar_fechamento {
                println!("{motivo}");
                println!(
                    "ℹ️  O navegador continua aberto. Pressione Enter (ou Ctrl+C) no terminal, ou feche a janela, para encerrar."
                );
                aguardar_usuario_ou_fechamento(&mut browser, &params.interrompido).await;
            } else {
                fechar_navegador_limpo(&mut browser).await;
            }

            Ok(ResultadoLogin {
                status,
                motivo,
                sessao_ja_ativa,
                diretorio_perfil,
                navegador: params.navegador_padrao.clone(),
            })
        }
        Err(e) => {
            fechar_navegador_limpo(&mut browser).await;
            Err(e)
        }
    };

    handler_task.abort();
    resultado
}

async fn fluxo_pagina_login(
    browser: &mut Browser,
    params: &ParametrosLogin,
    timeout_total: Duration,
) -> Result<(StatusLogin, String, bool), AutomacaoError> {
    if foi_interrompido(&params.interrompido) {
        return Ok((
            StatusLogin::Cancelado,
            "Login automático cancelado pelo usuário".into(),
            false,
        ));
    }

    // 2. Abrir a URL e esperar carregar
    let page = tokio::time::timeout(timeout_total, browser.new_page(params.url_login.clone()))
        .await
        .map_err(|_| AutomacaoError::Cdp("Tempo esgotado ao abrir a página de login".into()))?
        .map_err(|e| AutomacaoError::Cdp(e.to_string()))?;

    let _ = tokio::time::timeout(Duration::from_secs(5), page.wait_for_navigation()).await;

    if foi_interrompido(&params.interrompido) {
        return Ok((
            StatusLogin::Cancelado,
            "Login automático cancelado pelo usuário".into(),
            false,
        ));
    }

    // 3. ANTES de preencher, validar o domínio da página principal e de todos os frames que contenham os campos
    let url_atual = page
        .url()
        .await
        .map_err(|e| AutomacaoError::Cdp(e.to_string()))?
        .unwrap_or_default();

    let mut seletores_ativos: Vec<&str> = vec![params.seletor_senha.as_str()];
    if let Some(ref s_usr) = params.seletor_usuario {
        seletores_ativos.push(s_usr.as_str());
    }
    if let Some(ref s_btn) = params.seletor_botao {
        seletores_ativos.push(s_btn.as_str());
    }

    let (todas_urls_frames, urls_frames_com_campos) =
        inspecionar_frames_e_seletores(&page, &seletores_ativos).await?;

    if let Err(e) = dominio::validar_pagina_e_frames(
        &url_atual,
        &urls_frames_com_campos,
        &params.dominio_principal,
    ) {
        return Ok((
            StatusLogin::Falha,
            format!("domínio não autorizado: {e}"),
            false,
        ));
    }

    // 4. Verificar se já está logado:
    // - URL atual já casa com url_sucesso; OU
    // - O seletor de senha não aparece até um timeout curto (e não há CAPTCHA/MFA bloqueando a tela)
    if let Some(ref url_suc) = params.url_sucesso {
        if url_bate_com_sucesso(&url_atual, url_suc) {
            return Ok((
                StatusLogin::Sucesso,
                "sessão já ativa (URL de sucesso já carregada)".into(),
                true,
            ));
        }
    }

    let timeout_curto =
        Duration::from_secs(TIMEOUT_CURTO_SESSAO_ATIVA_SEGS.min(params.timeout_segundos.max(1)));
    let el_senha_inicial = aguardar_elemento(
        &page,
        &params.seletor_senha,
        timeout_curto,
        &params.interrompido,
    )
    .await;

    // 5. Detectar CAPTCHA / MFA antes de concluir sessão ativa ou preencher
    let html_atual = page.content().await.unwrap_or_default();
    if let Some(motivo_desafio) =
        detectar_captcha_ou_mfa(&url_atual, &todas_urls_frames, &html_atual)
    {
        return Ok((
            StatusLogin::Parcial,
            format!(
                "{motivo_desafio} — automação interrompida para conclusão manual pelo usuário (RNF13)"
            ),
            false,
        ));
    }

    if el_senha_inicial.is_none() {
        // Verifica novamente a URL atual após a espera curta
        let url_pos_espera = page.url().await.ok().flatten().unwrap_or(url_atual.clone());
        if dominio::validar_url_contra_dominio(&url_pos_espera, &params.dominio_principal).is_err()
        {
            return Ok((
                StatusLogin::Falha,
                "domínio não autorizado após redirecionamento inicial".into(),
                false,
            ));
        }
        return Ok((
            StatusLogin::Sucesso,
            "sessão já ativa (campo de senha não exibido no domínio autorizado)".into(),
            true,
        ));
    }

    if foi_interrompido(&params.interrompido) {
        return Ok((
            StatusLogin::Cancelado,
            "Login automático cancelado pelo usuário".into(),
            false,
        ));
    }

    // 6. Preencher seletor_usuario (se configurado) e seletor_senha
    if let Some(ref sel_usuario) = params.seletor_usuario {
        let Some(el_usuario) =
            aguardar_elemento(&page, sel_usuario, timeout_total, &params.interrompido).await
        else {
            return Ok((
                StatusLogin::Falha,
                format!("Campo de usuário ('{sel_usuario}') não encontrado dentro do timeout"),
                false,
            ));
        };

        // Revalidar domínio antes de preencher o identificador
        let url_antes_usr = page.url().await.ok().flatten().unwrap_or_default();
        let (_, frames_usr) =
            inspecionar_frames_e_seletores(&page, &[sel_usuario.as_str()]).await?;
        if let Err(e) =
            dominio::validar_pagina_e_frames(&url_antes_usr, &frames_usr, &params.dominio_principal)
        {
            return Ok((
                StatusLogin::Falha,
                format!("domínio não autorizado antes de preencher usuário: {e}"),
                false,
            ));
        }

        preencher_campo(&el_usuario, &params.identificador).await?;
    }

    // Localizar (ou relocalizar) o campo de senha e REVALIDAR o domínio imediatamente antes de digitar a senha
    let Some(el_senha) = aguardar_elemento(
        &page,
        &params.seletor_senha,
        timeout_total,
        &params.interrompido,
    )
    .await
    else {
        return Ok((
            StatusLogin::Falha,
            "Campo de senha não encontrado dentro do timeout".into(),
            false,
        ));
    };

    let url_antes_senha = page.url().await.ok().flatten().unwrap_or_default();
    let (frames_atuais, frames_senha) =
        inspecionar_frames_e_seletores(&page, &[params.seletor_senha.as_str()]).await?;
    if let Err(e) =
        dominio::validar_pagina_e_frames(&url_antes_senha, &frames_senha, &params.dominio_principal)
    {
        return Ok((
            StatusLogin::Falha,
            format!("domínio não autorizado imediatamente antes de preencher a senha: {e}"),
            false,
        ));
    }

    // Verificar também se um CAPTCHA/MFA surgiu antes de digitar a senha
    let html_antes_senha = page.content().await.unwrap_or_default();
    if let Some(motivo_desafio) =
        detectar_captcha_ou_mfa(&url_antes_senha, &frames_atuais, &html_antes_senha)
    {
        return Ok((
            StatusLogin::Parcial,
            format!("{motivo_desafio} — automação interrompida antes do envio da senha (RNF13)"),
            false,
        ));
    }

    preencher_campo(&el_senha, params.senha.as_str()).await?;

    // 7. Clicar seletor_botao se envio_automatico; senão deixar para o usuário
    if !params.envio_automatico {
        return Ok((
            StatusLogin::Parcial,
            "Campos preenchidos (envio automático desabilitado; aguardando submissão manual pelo usuário)".into(),
            false,
        ));
    }

    if let Some(ref sel_botao) = params.seletor_botao {
        let Some(el_botao) =
            aguardar_elemento(&page, sel_botao, timeout_total, &params.interrompido).await
        else {
            return Ok((
                StatusLogin::Parcial,
                format!(
                    "Campos preenchidos, mas o botão de envio ('{sel_botao}') não foi encontrado"
                ),
                false,
            ));
        };
        el_botao
            .click()
            .await
            .map_err(|_| AutomacaoError::Cdp("Falha ao clicar no botão de login".into()))?;
    } else {
        // Quando envio_automatico=true mas seletor_botao não foi especificado, envia Enter no campo de senha
        el_senha
            .press_key("Enter")
            .await
            .map_err(|_| AutomacaoError::Cdp("Falha ao submeter formulário com Enter".into()))?;
    }

    // 8. Se url_sucesso definida, aguardar até timeout_segundos que a URL bata (ou que surja CAPTCHA/MFA)
    if let Some(ref url_suc) = params.url_sucesso {
        let fim = Instant::now() + timeout_total;
        loop {
            if foi_interrompido(&params.interrompido) {
                return Ok((
                    StatusLogin::Cancelado,
                    "Login automático cancelado pelo usuário enquanto aguardava confirmação".into(),
                    false,
                ));
            }

            let url_pos = page.url().await.ok().flatten().unwrap_or_default();
            if url_bate_com_sucesso(&url_pos, url_suc) {
                return Ok((
                    StatusLogin::Sucesso,
                    "Login automático concluído e confirmado pela URL de sucesso".into(),
                    false,
                ));
            }

            let (frames_pos, _) = inspecionar_frames_e_seletores(&page, &[]).await?;
            let html_pos = page.content().await.unwrap_or_default();
            if let Some(motivo_desafio) = detectar_captcha_ou_mfa(&url_pos, &frames_pos, &html_pos)
            {
                return Ok((
                    StatusLogin::Parcial,
                    format!(
                        "{motivo_desafio} após submissão — aguardando conclusão manual pelo usuário (RNF13)"
                    ),
                    false,
                ));
            }

            if Instant::now() >= fim {
                return Ok((
                    StatusLogin::Falha,
                    format!(
                        "Tempo esgotado ({}s) aguardando a URL de sucesso '{url_suc}'",
                        params.timeout_segundos
                    ),
                    false,
                ));
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    // Breve espera para verificar se surgiu CAPTCHA/MFA logo após o clique quando url_sucesso não foi definida
    tokio::time::sleep(Duration::from_millis(800)).await;
    let url_final = page.url().await.ok().flatten().unwrap_or_default();
    let (frames_finais, _) = inspecionar_frames_e_seletores(&page, &[]).await?;
    let html_final = page.content().await.unwrap_or_default();
    if let Some(motivo_desafio) = detectar_captcha_ou_mfa(&url_final, &frames_finais, &html_final) {
        return Ok((
            StatusLogin::Parcial,
            format!(
                "{motivo_desafio} após submissão — aguardando conclusão manual pelo usuário (RNF13)"
            ),
            false,
        ));
    }

    Ok((
        StatusLogin::Parcial,
        "Credenciais submetidas (sem url_sucesso configurada para confirmar a autenticação)".into(),
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalizar_e_casar_url_sucesso() {
        // Igualdade com e sem barra final / fragmento
        assert!(url_bate_com_sucesso(
            "https://www.netflix.com/browse/",
            "https://www.netflix.com/browse"
        ));
        assert!(url_bate_com_sucesso(
            "https://www.netflix.com/browse#profile",
            "https://www.netflix.com/browse/"
        ));

        // Prefixo em subcaminho legítimo
        assert!(url_bate_com_sucesso(
            "https://www.netflix.com/browse/genre/83",
            "https://www.netflix.com/browse"
        ));

        // Não deve casar se o caminho apenas compartilha prefixo de string sem '/'
        assert!(!url_bate_com_sucesso(
            "https://www.netflix.com/browser-unsupported",
            "https://www.netflix.com/browse"
        ));

        // Origem diferente não casa
        assert!(!url_bate_com_sucesso(
            "https://login.netflix.com/browse",
            "https://www.netflix.com/browse"
        ));
        assert!(!url_bate_com_sucesso(
            "http://www.netflix.com/browse",
            "https://www.netflix.com/browse"
        ));

        // Query string quando exigida na url_sucesso
        assert!(url_bate_com_sucesso(
            "https://app.exemplo.com/painel?logado=1&tab=home",
            "https://app.exemplo.com/painel?logado=1"
        ));
        assert!(!url_bate_com_sucesso(
            "https://app.exemplo.com/painel",
            "https://app.exemplo.com/painel?logado=1"
        ));
    }

    #[test]
    fn test_detectar_captcha_por_frames_e_html() {
        // Iframe do reCAPTCHA
        let motivo = detectar_captcha_ou_mfa(
            "https://exemplo.com/login",
            &["https://www.google.com/recaptcha/api2/anchor?k=123".to_string()],
            "<html><body><form></form></body></html>",
        )
        .expect("Deveria detectar reCAPTCHA no frame");
        assert!(motivo.contains("CAPTCHA"));

        // Iframe do hCaptcha
        let motivo = detectar_captcha_ou_mfa(
            "https://exemplo.com/login",
            &["https://newassets.hcaptcha.com/captcha/v1/abc".to_string()],
            "<html><body></body></html>",
        )
        .expect("Deveria detectar hCaptcha");
        assert!(motivo.contains("hCaptcha"));

        // Iframe do Cloudflare Turnstile
        let motivo = detectar_captcha_ou_mfa(
            "https://exemplo.com/login",
            &[
                "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile"
                    .to_string(),
            ],
            "<html><body></body></html>",
        )
        .expect("Deveria detectar Turnstile");
        assert!(motivo.contains("Turnstile"));

        // Div g-recaptcha ou cf-turnstile no HTML
        assert!(detectar_captcha_ou_mfa(
            "https://exemplo.com/login",
            &[],
            r#"<div class="cf-turnstile" data-sitekey="0x4AAA"></div>"#,
        )
        .is_some());
    }

    #[test]
    fn test_detectar_mfa_otp_e_pagina_limpa() {
        // Campo autocomplete="one-time-code"
        let motivo = detectar_captcha_ou_mfa(
            "https://exemplo.com/login",
            &[],
            r#"<input type="text" name="code" autocomplete="one-time-code" />"#,
        )
        .expect("Deveria detectar campo one-time-code");
        assert!(motivo.contains("one-time-code"));

        // Campo name="totp"
        assert!(detectar_captcha_ou_mfa(
            "https://exemplo.com/sessions/two-factor",
            &[],
            r#"<input id="app_totp" name="totp" />"#,
        )
        .is_some());

        // Texto comum de 2FA
        assert!(detectar_captcha_ou_mfa(
            "https://exemplo.com/auth",
            &[],
            "<html><body><h1>Autenticação de dois fatores</h1><p>Digite o código de verificação enviado</p></body></html>",
        )
        .is_some());

        // Página de login normal com usuário e senha NÃO deve acusar falso positivo
        assert!(detectar_captcha_ou_mfa(
            "https://exemplo.com/login",
            &["https://exemplo.com/static/frame.html".to_string()],
            r#"<html><body><form><input id="user" type="email"/><input id="pass" type="password"/><button type="submit">Entrar</button></form></body></html>"#,
        )
        .is_none());
    }

    #[test]
    fn test_preparar_diretorio_perfil_permissoes_e_debug_sem_segredo() {
        let base = std::env::temp_dir().join(format!("cofre-perfil-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        let dir_perfil = preparar_diretorio_perfil(&base, 42).unwrap();
        assert!(dir_perfil.is_dir());
        assert!(dir_perfil.ends_with("credencial-42"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let modo = std::fs::metadata(&dir_perfil).unwrap().permissions().mode() & 0o777;
            assert_eq!(modo, 0o700);
        }

        let params = ParametrosLogin {
            credencial_id: 42,
            url_login: "https://exemplo.com/login".into(),
            dominio_principal: "exemplo.com".into(),
            identificador: "alice".into(),
            senha: Zeroizing::new("SegredoSuperSecreto123!".into()),
            seletor_usuario: Some("#user".into()),
            seletor_senha: "#pass".into(),
            seletor_botao: Some("#btn".into()),
            url_sucesso: Some("https://exemplo.com/app".into()),
            envio_automatico: true,
            timeout_segundos: 10,
            navegador_padrao: "chromium".into(),
            diretorio_dados_app: base.clone(),
            interrompido: None,
            aguardar_fechamento: false,
        };

        let dbg = format!("{params:?}");
        assert!(!dbg.contains("SegredoSuperSecreto123!"));
        assert!(dbg.contains("<protegida>"));

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Teste de integração real com navegador (ignorado por padrão pois o ambiente de CI
    /// pode não ter Chromium instalado; executa se `COFRE_NAVEGADOR` estiver definido).
    #[test]
    #[ignore]
    fn test_executar_login_com_navegador_real_se_configurado() {
        if std::env::var(navegador::ENV_COFRE_NAVEGADOR).is_err() {
            return;
        }

        let base = std::env::temp_dir().join(format!("cofre-real-browser-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        let params = ParametrosLogin {
            credencial_id: 1,
            url_login: "http://127.0.0.1:9/login".into(),
            dominio_principal: "127.0.0.1".into(),
            identificador: "teste".into(),
            senha: Zeroizing::new("senha123".into()),
            seletor_usuario: Some("#user".into()),
            seletor_senha: "#pass".into(),
            seletor_botao: Some("#submit".into()),
            url_sucesso: None,
            envio_automatico: false,
            timeout_segundos: 5,
            navegador_padrao: "chromium".into(),
            diretorio_dados_app: base.clone(),
            interrompido: None,
            aguardar_fechamento: false,
        };

        // Deve tentar lançar o navegador configurado em COFRE_NAVEGADOR
        let _ = executar_login(&params);
        let _ = std::fs::remove_dir_all(&base);
    }
}
