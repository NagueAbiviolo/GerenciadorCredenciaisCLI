//! Contexto de execução e sessão compartilhada do cofre.
//!
//! No modo avulso, a sessão é criada sob demanda pelo comando que exige o cofre
//! desbloqueado e descartada ao término do processo. No modo `cofre shell`, a
//! sessão é aberta uma única vez e reaproveitada entre os comandos, podendo ser
//! descartada manualmente (`bloquear`) ou automaticamente por inatividade (RNF07).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use cofre_crypto::keys::UnlockedVault;
use cofre_db::Database;
use cofre_services::auditoria_service::{self, ResultadoEvento, TipoEvento};

use super::unlock;

/// Sessão de cofre desbloqueado, mantendo a conexão com o banco, a DEK em
/// memória protegida (`UnlockedVault`) e o ID do usuário ativo.
///
/// Tanto `Database` (`rusqlite::Connection`) quanto `UnlockedVault`
/// (`SecretBox<Vec<u8>>`) implementam `Send`, permitindo armazenar a sessão em
/// `Arc<Mutex<Option<SessaoAtiva>>>` e compartilhá-la com a thread vigia de
/// inatividade do `cofre shell`.
pub struct SessaoAtiva {
    pub db: Database,
    pub vault: UnlockedVault,
    pub usuario_id: i64,
}

/// Contexto compartilhado entre os comandos da CLI.
#[derive(Clone)]
pub struct Contexto {
    db_path: PathBuf,
    sessao: Arc<Mutex<Option<SessaoAtiva>>>,
}

impl Contexto {
    /// Cria um novo contexto sem sessão desbloqueada.
    pub fn novo(db_path: PathBuf) -> Self {
        Self {
            db_path,
            sessao: Arc::new(Mutex::new(None)),
        }
    }

    /// Retorna o caminho do banco de dados configurado neste contexto.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Retorna uma referência compartilhada para o mutex da sessão ativa.
    pub fn sessao_compartilhada(&self) -> Arc<Mutex<Option<SessaoAtiva>>> {
        Arc::clone(&self.sessao)
    }

    /// Armazena uma sessão já desbloqueada no contexto.
    pub fn definir_sessao(&self, sessao: SessaoAtiva) {
        let mut guard = self.sessao.lock().expect("Mutex da sessão corrompido");
        *guard = Some(sessao);
    }

    /// Descarta imediatamente a sessão ativa, se houver, zerando a DEK em memória.
    /// Registra um evento `BLOQUEIO` na auditoria caso `descricao` seja informada.
    /// Retorna `true` se havia uma sessão ativa que foi descartada.
    pub fn bloquear(&self, descricao: Option<&str>) -> bool {
        let mut guard = self.sessao.lock().expect("Mutex da sessão corrompido");
        if let Some(sessao) = guard.take() {
            if let Some(desc) = descricao {
                auditoria_service::registrar(
                    &sessao.db,
                    sessao.usuario_id,
                    TipoEvento::Bloqueio,
                    ResultadoEvento::Sucesso,
                    None,
                    Some(desc),
                );
            }
            true
        } else {
            false
        }
    }

    /// Executa `f` com referência à sessão desbloqueada, sem clonar segredos.
    ///
    /// Se já houver uma sessão ativa, reutiliza-a; caso contrário, solicita a
    /// senha mestre via `unlock::unlock` e armazena a sessão antes de executar `f`.
    /// O mutex permanece travado durante toda a execução de `f`, garantindo que a
    /// thread vigia nunca bloqueie o cofre no meio de um comando.
    pub fn com_sessao<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&SessaoAtiva) -> Result<T>,
    {
        let mut guard = self.sessao.lock().expect("Mutex da sessão corrompido");
        if guard.is_none() {
            let (db, vault, usuario_id) = unlock::unlock(&self.db_path)?;
            *guard = Some(SessaoAtiva {
                db,
                vault,
                usuario_id,
            });
        }
        let sessao = guard.as_ref().expect("Sessão recém-inicializada");
        f(sessao)
    }

    /// Executa `f` com acesso ao banco de dados sem exigir desbloqueio do cofre.
    ///
    /// Reutiliza a conexão da sessão ativa se ela existir; caso contrário, abre
    /// o banco a partir de `db_path`.
    pub fn com_banco<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Database) -> Result<T>,
    {
        let guard = self.sessao.lock().expect("Mutex da sessão corrompido");
        if let Some(sessao) = guard.as_ref() {
            f(&sessao.db)
        } else {
            let db = Database::open(&self.db_path).context("Falha ao abrir o banco de dados")?;
            f(&db)
        }
    }
}
