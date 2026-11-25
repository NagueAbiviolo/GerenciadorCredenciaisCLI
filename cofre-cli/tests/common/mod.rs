//! Utilitários compartilhados pelos testes de integração do binário `cofre`.
//!
//! Garante que todos os comandos utilizem exclusivamente um banco SQLite em
//! diretório temporário (`tempfile::TempDir`), isolando os testes do ambiente
//! do usuário.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use tempfile::TempDir;

/// Senha mestre padrão utilizada nos cenários de teste (>= 8 caracteres).
pub const SENHA_PADRAO: &str = "SenhaMestre@2026!";

/// Timeout generoso para interações em PTY (45 segundos), evitando flakiness
/// devido ao custo de memória/CPU do Argon2id (256 MiB) em builds não otimizados.
#[cfg(unix)]
pub const TIMEOUT_PTY_MS: u64 = 45_000;

/// Ambiente isolado de um cofre temporário para testes de integração.
pub struct CofreTemp {
    pub dir: TempDir,
    pub db_path: PathBuf,
}

impl CofreTemp {
    /// Cria um novo diretório temporário com caminho de banco `cofre.db` (ainda não inicializado).
    pub fn novo() -> Self {
        let dir = TempDir::new().expect("Falha ao criar diretório temporário do teste");
        let db_path = dir.path().join("cofre.db");
        Self { dir, db_path }
    }

    /// Caminho do diretório padrão de backups (`<dir do db>/backups/`).
    pub fn dir_backups(&self) -> PathBuf {
        self.dir.path().join("backups")
    }

    /// Constrói um `assert_cmd::Command` para o binário `cofre` já configurado
    /// com `--db-path` apontando para o banco temporário.
    pub fn cmd(&self) -> Command {
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("cofre");
        cmd.arg("--db-path").arg(&self.db_path);
        cmd.env("NO_COLOR", "1");
        cmd
    }

    /// Inicia o binário `cofre` dentro de um pseudo-terminal (PTY) via `rexpect`,
    /// sempre passando `--db-path` para o arquivo temporário.
    #[cfg(unix)]
    pub fn spawn_pty(&self, args: &[&str]) -> rexpect::session::PtySession {
        spawn_pty_em(&self.db_path, args)
    }

    /// Inicializa o cofre via PTY (`cofre init --nome <nome>`) e valida o sucesso.
    #[cfg(unix)]
    pub fn inicializar(&self, nome: &str, senha: &str) {
        let mut pty = self.spawn_pty(&["init", "--nome", nome]);
        esperar_texto(&mut pty, "Defina a senha mestre:");
        pty.send_line(senha).expect("Falha ao enviar senha mestre");
        esperar_texto(&mut pty, "Confirme a senha:");
        pty.send_line(senha)
            .expect("Falha ao confirmar senha mestre");

        let (saida, codigo) = aguardar_saida(&mut pty);
        assert_eq!(
            codigo, 0,
            "Esperava código 0 no 'cofre init', mas obteve {codigo}. Saída:\n{saida}"
        );
        assert!(
            saida.contains("Cofre inicializado com sucesso!"),
            "Mensagem de sucesso ausente no 'cofre init'. Saída:\n{saida}"
        );
    }

    /// Executa um subcomando que solicita apenas `"Senha mestre:"` no início e
    /// retorna `(saida_completa_utf8, codigo_saida)`.
    #[cfg(unix)]
    pub fn executar_com_senha(&self, args: &[&str], senha_mestre: &str) -> (String, i32) {
        let mut pty = self.spawn_pty(args);
        let antes = esperar_texto(&mut pty, "Senha mestre:");
        pty.send_line(senha_mestre)
            .expect("Falha ao enviar senha mestre ao PTY");
        let (depois, codigo) = aguardar_saida(&mut pty);
        (format!("{antes}{depois}"), codigo)
    }
}

/// Inicia o binário `cofre` em PTY apontando para um `db_path` arbitrário.
///
/// Configura a largura do PTY para 240 colunas para evitar que o `comfy-table`
/// quebre palavras/nomes de arquivos em múltiplas linhas (por padrão um PTY novo
/// nasce com `ws_col = 0`).
#[cfg(unix)]
pub fn spawn_pty_em(db_path: &Path, args: &[&str]) -> rexpect::session::PtySession {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("cofre"));
    cmd.arg("--db-path").arg(db_path);
    cmd.args(args);
    cmd.env("NO_COLOR", "1");
    let pty = rexpect::session::spawn_command(cmd, Some(TIMEOUT_PTY_MS))
        .expect("Falha ao iniciar o binário 'cofre' em PTY");

    if let Ok(fd) = pty.process().get_file_handle() {
        let _ = std::process::Command::new("stty")
            .args(["cols", "240", "rows", "50"])
            .stdin(fd)
            .status();
    }

    pty
}

/// Converte texto UTF-8 para a representação interna byte-a-char usada pelo `NBReader` do `rexpect`.
#[cfg(unix)]
pub fn codificar_padrao_pty(texto_utf8: &str) -> String {
    texto_utf8.bytes().map(|b| b as char).collect()
}

/// Reconstrói uma `String` UTF-8 a partir do buffer byte-a-char retornado pelo `rexpect`.
#[cfg(unix)]
pub fn decodificar_saida_pty(bruto: &str) -> String {
    let bytes: Vec<u8> = bruto.chars().map(|c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Aguarda até que `esperado` apareça na saída do PTY e retorna o texto anterior já decodificado em UTF-8.
#[cfg(unix)]
pub fn esperar_texto(pty: &mut rexpect::session::PtySession, esperado: &str) -> String {
    let alvo = codificar_padrao_pty(esperado);
    match pty.exp_string(&alvo) {
        Ok(antes) => decodificar_saida_pty(&antes),
        Err(erro) => panic!("Falha ao aguardar '{esperado}' no PTY: {erro}"),
    }
}

/// Lê toda a saída restante até EOF e retorna `(saida_utf8, codigo_de_saida)`.
#[cfg(unix)]
pub fn aguardar_saida(pty: &mut rexpect::session::PtySession) -> (String, i32) {
    let restante = pty
        .exp_eof()
        .map(|s| decodificar_saida_pty(&s))
        .unwrap_or_default();

    let status = pty
        .process()
        .wait()
        .expect("Falha ao aguardar término do processo filho no PTY");

    let codigo = match status {
        rexpect::process::WaitStatus::Exited(_, code) => code,
        outro => panic!("Processo no PTY não terminou normalmente com código de saída: {outro:?}"),
    };

    (restante, codigo)
}
