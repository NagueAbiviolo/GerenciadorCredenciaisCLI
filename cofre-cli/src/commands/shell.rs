//! Comando `cofre shell` — Modo interativo (REPL) com bloqueio automático por inatividade (RNF07).
//!
//! Desbloqueia o cofre uma única vez na entrada e mantém a DEK em memória protegida
//! para executar vários subcomandos sem repetir o custo do Argon2id. Não utiliza
//! biblioteca de readline e não persiste histórico em arquivo (RNF05).

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;

use cofre_crypto::CryptoError;
use cofre_db::connection::DbError;
use cofre_db::Database;
use cofre_services::auditoria_service::{self, ResultadoEvento, TipoEvento};
use cofre_services::preferencia_service::{self, PADRAO_TIMEOUT_INATIVIDADE};
use cofre_services::vault_service::{self, VaultServiceError};

use super::sessao::{Contexto, SessaoAtiva};
use super::{sinal, unlock, Cli, Commands};

/// Número máximo de tentativas de senha mestre ao iniciar o shell.
pub const MAX_TENTATIVAS_SENHA: u8 = 3;

/// Prompt exibido no modo interativo.
const PROMPT: &str = "cofre> ";

/// Comandos internos exclusivos do modo `cofre shell`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComandoInterno {
    /// Encerra a sessão interativa (`sair`, `exit`, `quit`).
    Sair,
    /// Descarta imediatamente a sessão desbloqueada (`bloquear`).
    Bloquear,
    /// Exibe a ajuda dos comandos internos (`ajuda`).
    Ajuda,
}

/// Resultado da interpretação de uma linha digitada no shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComandoShell {
    /// Linha vazia ou contendo apenas espaços em branco.
    Vazio,
    /// Comando interno do shell (`sair`, `exit`, `quit`, `bloquear`, `ajuda`).
    Interno(ComandoInterno),
    /// Comando ou argumento recusado dentro do shell (`init`, `shell`, `--db-path`).
    Recusado(String),
    /// Subcomando normal da CLI pronto para o `clap` (prefixado com `"cofre"`).
    Subcomando(Vec<String>),
    /// Erro de sintaxe em aspas não fechadas ou escape inválido.
    ErroAspas,
}

/// Verifica se o tempo decorrido entre `ultima` e `agora` atingiu ou ultrapassou `timeout`.
pub fn expirou(ultima: Instant, agora: Instant, timeout: Duration) -> bool {
    agora.saturating_duration_since(ultima) >= timeout
}

/// Interpreta uma linha lida do prompt do shell, separando argumentos com `shlex`
/// e classificando comandos vazios, internos, recusados ou subcomandos da CLI.
pub fn interpretar_linha(linha: &str) -> ComandoShell {
    if linha.trim().is_empty() {
        return ComandoShell::Vazio;
    }

    let Some(tokens) = shlex::split(linha) else {
        return ComandoShell::ErroAspas;
    };

    if tokens.is_empty() {
        return ComandoShell::Vazio;
    }

    if tokens
        .iter()
        .any(|t| t == "--db-path" || t.starts_with("--db-path="))
    {
        return ComandoShell::Recusado(
            "Não é permitido alterar o banco de dados (--db-path) dentro do shell.".into(),
        );
    }

    let primeiro = tokens[0].as_str();
    match primeiro {
        "sair" | "exit" | "quit" => ComandoShell::Interno(ComandoInterno::Sair),
        "bloquear" => ComandoShell::Interno(ComandoInterno::Bloquear),
        "ajuda" => ComandoShell::Interno(ComandoInterno::Ajuda),
        "init" => ComandoShell::Recusado(
            "O comando 'init' não pode ser executado dentro do shell.".into(),
        ),
        "shell" => ComandoShell::Recusado(
            "O comando 'shell' não pode ser executado dentro de outro shell.".into(),
        ),
        _ => {
            let mut argv = Vec::with_capacity(tokens.len() + 1);
            argv.push("cofre".to_string());
            argv.extend(tokens);
            ComandoShell::Subcomando(argv)
        }
    }
}

/// Tenta bloquear a sessão caso esteja ociosa há pelo menos `timeout`.
///
/// Usa `try_lock` na sessão e verifica `executando_comando` para nunca bloquear
/// no meio de um comando em execução. Retorna `true` se a sessão foi descartada.
pub fn tentar_bloquear_por_inatividade(
    sessao: &Mutex<Option<SessaoAtiva>>,
    ultima_atividade: &Mutex<Instant>,
    executando_comando: &AtomicBool,
    agora: Instant,
    timeout: Duration,
) -> bool {
    if executando_comando.load(Ordering::SeqCst) {
        return false;
    }

    let Ok(mut guard) = sessao.try_lock() else {
        return false;
    };

    if guard.is_none() || executando_comando.load(Ordering::SeqCst) {
        return false;
    }

    let ultima = *ultima_atividade
        .lock()
        .expect("Mutex de última atividade corrompido");
    if expirou(ultima, agora, timeout) {
        if let Some(s) = guard.take() {
            auditoria_service::registrar(
                &s.db,
                s.usuario_id,
                TipoEvento::Bloqueio,
                ResultadoEvento::Sucesso,
                None,
                Some("Cofre bloqueado por inatividade no shell"),
            );
        }
        true
    } else {
        false
    }
}

/// Abre o banco e solicita a senha mestre com até `MAX_TENTATIVAS_SENHA` tentativas.
fn desbloquear_inicial(ctx: &Contexto) -> Result<()> {
    let db = Database::open(ctx.db_path()).context("Falha ao abrir o banco de dados")?;

    // Verifica se o cofre está inicializado antes de pedir a senha mestre.
    if let Err(e) = db.buscar_usuario_ativo() {
        return match e {
            DbError::NotFound => {
                Err(VaultServiceError::NotInitialized).context("Falha ao desbloquear o cofre")
            }
            outro => Err(VaultServiceError::Db(outro)).context("Falha ao desbloquear o cofre"),
        };
    }

    for tentativa in 1..=MAX_TENTATIVAS_SENHA {
        let senha = unlock::pedir_senha("Senha mestre:")?;
        match vault_service::unlock_vault(&db, senha.as_bytes()) {
            Ok((vault, usuario_id)) => {
                ctx.definir_sessao(SessaoAtiva {
                    db,
                    vault,
                    usuario_id,
                });
                return Ok(());
            }
            Err(VaultServiceError::Crypto(CryptoError::InvalidMasterPassword)) => {
                if tentativa < MAX_TENTATIVAS_SENHA {
                    eprintln!(
                        "❌ Senha mestre inválida (tentativa {tentativa}/{MAX_TENTATIVAS_SENHA})."
                    );
                } else {
                    anyhow::bail!(
                        "Falha ao desbloquear o cofre: senha mestre inválida após {MAX_TENTATIVAS_SENHA} tentativas."
                    );
                }
            }
            Err(e) => return Err(e).context("Falha ao desbloquear o cofre"),
        }
    }

    unreachable!()
}

/// Lê a preferência `timeout_inatividade` (em minutos) da sessão ativa, se houver,
/// e atualiza o valor atômico em segundos usado pela thread vigia.
fn atualizar_timeout_da_preferencia(ctx: &Contexto, timeout_segundos: &AtomicU64) {
    let sessao = ctx.sessao_compartilhada();
    let Ok(guard) = sessao.lock() else {
        return;
    };
    if let Some(s) = guard.as_ref() {
        let minutos = preferencia_service::timeout_inatividade(&s.db, s.usuario_id)
            .unwrap_or(PADRAO_TIMEOUT_INATIVIDADE);
        timeout_segundos.store(minutos.saturating_mul(60), Ordering::SeqCst);
    }
}

fn imprimir_ajuda() {
    println!("Comandos internos do shell:");
    println!("  ajuda              Exibe esta ajuda");
    println!("  bloquear           Bloqueia o cofre imediatamente (descarta a sessão da memória)");
    println!("  sair, exit, quit   Bloqueia o cofre e encerra o shell (ou Ctrl+D)");
    println!();
    println!("Os demais comandos são os subcomandos normais sem o prefixo 'cofre':");
    println!("  categoria <subcomando>    Gerenciar categorias (add, list, edit, delete)");
    println!("  servico <subcomando>      Gerenciar serviços e URLs (add, list, search, edit, delete, url)");
    println!("  credencial <subcomando>   Gerenciar credenciais, histórico, métodos e e-mails");
    println!("  dispositivo <subcomando>  Gerenciar dispositivos registrados (list)");
    println!("  preferencia <subcomando>  Gerenciar preferências (list, get, set, reset)");
    println!("  auditoria <subcomando>    Consultar eventos de auditoria (list)");
    println!("  senha-mestre              Alterar a senha mestre do cofre");
    println!("  --help ou <cmd> --help    Exibir ajuda detalhada dos subcomandos");
}

pub fn execute(ctx: &Contexto) -> Result<()> {
    // Registra o handler global de Ctrl+C para que Ctrl+C no prompt não mate o shell.
    let ctrl_c = sinal::preparar_ctrl_c()?;

    desbloquear_inicial(ctx)?;

    let timeout_segundos = Arc::new(AtomicU64::new(
        PADRAO_TIMEOUT_INATIVIDADE.saturating_mul(60),
    ));
    atualizar_timeout_da_preferencia(ctx, &timeout_segundos);

    let minutos_atuais = timeout_segundos.load(Ordering::SeqCst) / 60;
    println!(
        "🔓 Cofre desbloqueado. Digite 'ajuda' para ver os comandos ou 'sair' para encerrar (bloqueio por inatividade: {minutos_atuais} min)."
    );

    let ultima_atividade = Arc::new(Mutex::new(Instant::now()));
    let executando_comando = Arc::new(AtomicBool::new(false));
    let encerrar = Arc::new(AtomicBool::new(false));

    let sessao_vigia = ctx.sessao_compartilhada();
    let ultima_vigia = Arc::clone(&ultima_atividade);
    let executando_vigia = Arc::clone(&executando_comando);
    let timeout_vigia = Arc::clone(&timeout_segundos);
    let encerrar_vigia = Arc::clone(&encerrar);

    let vigia = std::thread::spawn(move || {
        while !encerrar_vigia.load(Ordering::SeqCst) {
            std::thread::park_timeout(Duration::from_secs(1));
            if encerrar_vigia.load(Ordering::SeqCst) {
                break;
            }
            let timeout = Duration::from_secs(timeout_vigia.load(Ordering::SeqCst));
            if tentar_bloquear_por_inatividade(
                &sessao_vigia,
                &ultima_vigia,
                &executando_vigia,
                Instant::now(),
                timeout,
            ) {
                println!(
                    "\n🔒 Cofre bloqueado por inatividade. O próximo comando pedirá a senha mestre."
                );
                print!("{PROMPT}");
                let _ = io::stdout().flush();
            }
        }
    });

    let stdin = io::stdin();
    let mut linha = String::new();

    loop {
        print!("{PROMPT}");
        let _ = io::stdout().flush();

        linha.clear();
        match stdin.read_line(&mut linha) {
            Ok(0) => {
                // Se Ctrl+C interrompeu a leitura em algum terminal, apenas avança a linha.
                if ctrl_c.swap(false, Ordering::SeqCst) {
                    println!();
                    continue;
                }
                // EOF (Ctrl+D)
                println!();
                break;
            }
            Ok(_) => {
                ctrl_c.store(false, Ordering::SeqCst);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                ctrl_c.store(false, Ordering::SeqCst);
                println!();
                continue;
            }
            Err(e) => {
                eprintln!("❌ Erro ao ler entrada: {e:#}");
                break;
            }
        }

        // Marca início de atividade ao receber a linha.
        executando_comando.store(true, Ordering::SeqCst);
        *ultima_atividade
            .lock()
            .expect("Mutex de última atividade corrompido") = Instant::now();

        let sair = match interpretar_linha(&linha) {
            ComandoShell::Vazio => false,
            ComandoShell::ErroAspas => {
                eprintln!("❌ Erro: Aspas não fechadas ou escape inválido na linha de comando.");
                false
            }
            ComandoShell::Interno(ComandoInterno::Sair) => true,
            ComandoShell::Interno(ComandoInterno::Bloquear) => {
                if ctx.bloquear(Some("Cofre bloqueado manualmente no shell")) {
                    println!("🔒 Cofre bloqueado. O próximo comando que exigir autenticação pedirá a senha mestre.");
                } else {
                    println!("🔒 O cofre já está bloqueado.");
                }
                false
            }
            ComandoShell::Interno(ComandoInterno::Ajuda) => {
                imprimir_ajuda();
                false
            }
            ComandoShell::Recusado(motivo) => {
                eprintln!("❌ Erro: {motivo}");
                false
            }
            ComandoShell::Subcomando(argv) => {
                match Cli::try_parse_from(&argv) {
                    Ok(cli) => {
                        if cli.db_path.is_some() {
                            eprintln!(
                                "❌ Erro: Não é permitido alterar o banco de dados (--db-path) dentro do shell."
                            );
                        } else {
                            match cli.command {
                                Commands::Init { .. } => {
                                    eprintln!(
                                        "❌ Erro: O comando 'init' não pode ser executado dentro do shell."
                                    );
                                }
                                Commands::Shell => {
                                    eprintln!(
                                        "❌ Erro: O comando 'shell' não pode ser executado dentro de outro shell."
                                    );
                                }
                                cmd => {
                                    if let Err(e) = super::executar_comando(ctx, cmd) {
                                        eprintln!("❌ Erro: {e:#}");
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = e.print();
                    }
                }
                false
            }
        };

        // Releitura da preferência de timeout após cada comando para refletir
        // alterações feitas com `preferencia set/reset` na própria sessão.
        atualizar_timeout_da_preferencia(ctx, &timeout_segundos);

        // Atualiza instante da última atividade ao término do comando.
        *ultima_atividade
            .lock()
            .expect("Mutex de última atividade corrompido") = Instant::now();
        executando_comando.store(false, Ordering::SeqCst);

        if sair {
            break;
        }
    }

    encerrar.store(true, Ordering::SeqCst);
    vigia.thread().unpark();
    let _ = vigia.join();

    ctx.bloquear(Some("Cofre bloqueado ao sair do shell"));
    println!("🔒 Cofre bloqueado.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cofre_crypto::kdf::KdfParams;
    use cofre_crypto::keys;

    fn sessao_ficticia() -> SessaoAtiva {
        let conn = cofre_db::rusqlite::Connection::open_in_memory().unwrap();
        let mut db = Database { conn };
        cofre_db::migrations::run(&mut db.conn).unwrap();

        let params = KdfParams {
            m_cost_kib: 8_192,
            t_cost: 1,
            p_cost: 1,
        };
        let init = keys::init_vault(b"senha-teste-123", &params).unwrap();
        let vault = keys::unlock_vault(
            b"senha-teste-123",
            &init.kek_salt,
            &init.verifier_salt,
            &init.verifier,
            &init.encrypted_dek,
            &init.dek_nonce,
            &init.kdf_params_json,
        )
        .unwrap();

        SessaoAtiva {
            db,
            vault,
            usuario_id: 1,
        }
    }

    #[test]
    fn test_expirou() {
        let base = Instant::now();
        let timeout = Duration::from_secs(300);

        assert!(!expirou(base, base, timeout));
        assert!(!expirou(base, base + Duration::from_secs(299), timeout));
        assert!(expirou(base, base + Duration::from_secs(300), timeout));
        assert!(expirou(base, base + Duration::from_secs(600), timeout));
    }

    #[test]
    fn test_interpretar_linha_vazia() {
        assert_eq!(interpretar_linha(""), ComandoShell::Vazio);
        assert_eq!(interpretar_linha("   \t\n "), ComandoShell::Vazio);
    }

    #[test]
    fn test_interpretar_linha_comandos_internos() {
        assert_eq!(
            interpretar_linha("sair"),
            ComandoShell::Interno(ComandoInterno::Sair)
        );
        assert_eq!(
            interpretar_linha("  exit "),
            ComandoShell::Interno(ComandoInterno::Sair)
        );
        assert_eq!(
            interpretar_linha("quit"),
            ComandoShell::Interno(ComandoInterno::Sair)
        );
        assert_eq!(
            interpretar_linha("bloquear"),
            ComandoShell::Interno(ComandoInterno::Bloquear)
        );
        assert_eq!(
            interpretar_linha("ajuda"),
            ComandoShell::Interno(ComandoInterno::Ajuda)
        );
    }

    #[test]
    fn test_interpretar_linha_comandos_recusados() {
        assert!(matches!(
            interpretar_linha("init --nome Alice"),
            ComandoShell::Recusado(_)
        ));
        assert!(matches!(
            interpretar_linha("shell"),
            ComandoShell::Recusado(_)
        ));
        assert!(matches!(
            interpretar_linha("credencial list --db-path /tmp/outro.db"),
            ComandoShell::Recusado(_)
        ));
        assert!(matches!(
            interpretar_linha("--db-path=/tmp/outro.db credencial list"),
            ComandoShell::Recusado(_)
        ));
    }

    #[test]
    fn test_interpretar_linha_subcomando_e_aspas() {
        assert_eq!(
            interpretar_linha(
                "credencial add --servico-id 1 --nome \"Netflix Pessoal\" -i a@b.com"
            ),
            ComandoShell::Subcomando(vec![
                "cofre".into(),
                "credencial".into(),
                "add".into(),
                "--servico-id".into(),
                "1".into(),
                "--nome".into(),
                "Netflix Pessoal".into(),
                "-i".into(),
                "a@b.com".into(),
            ])
        );

        assert_eq!(
            interpretar_linha("servico add --nome \"aspa sem fechar"),
            ComandoShell::ErroAspas
        );
    }

    #[test]
    fn test_tentar_bloquear_por_inatividade() {
        let base = Instant::now();
        let timeout = Duration::from_secs(60);
        let sessao = Mutex::new(Some(sessao_ficticia()));
        let ultima = Mutex::new(base);
        let executando = AtomicBool::new(false);

        // Antes do timeout: não bloqueia.
        assert!(!tentar_bloquear_por_inatividade(
            &sessao,
            &ultima,
            &executando,
            base + Duration::from_secs(30),
            timeout,
        ));
        assert!(sessao.lock().unwrap().is_some());

        // Se um comando estiver em execução, não bloqueia mesmo após o timeout.
        executando.store(true, Ordering::SeqCst);
        assert!(!tentar_bloquear_por_inatividade(
            &sessao,
            &ultima,
            &executando,
            base + Duration::from_secs(120),
            timeout,
        ));
        assert!(sessao.lock().unwrap().is_some());

        // Se o mutex da sessão estiver travado por `com_sessao`, `try_lock` falha e não bloqueia.
        executando.store(false, Ordering::SeqCst);
        {
            let _guard = sessao.lock().unwrap();
            assert!(!tentar_bloquear_por_inatividade(
                &sessao,
                &ultima,
                &executando,
                base + Duration::from_secs(120),
                timeout,
            ));
        }
        assert!(sessao.lock().unwrap().is_some());

        // Ocioso e com timeout expirado: bloqueia e descarta a sessão.
        assert!(tentar_bloquear_por_inatividade(
            &sessao,
            &ultima,
            &executando,
            base + Duration::from_secs(60),
            timeout,
        ));
        assert!(sessao.lock().unwrap().is_none());

        // Chamada subsequente com sessão já vazia retorna `false`.
        assert!(!tentar_bloquear_por_inatividade(
            &sessao,
            &ultima,
            &executando,
            base + Duration::from_secs(180),
            timeout,
        ));
    }
}
