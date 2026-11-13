//! Utilitários compartilhados pelos testes dos serviços.

use cofre_crypto::kdf::KdfParams;

/// Banco temporário em arquivo, removido ao final do teste.
pub struct DbTemp(pub std::path::PathBuf);

impl DbTemp {
    pub fn new(nome: &str) -> Self {
        let path = std::env::temp_dir()
            .join(format!("cofre-teste-{nome}-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for DbTemp {
    fn drop(&mut self) {
        for sufixo in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sufixo}", self.0.display()));
        }
    }
}

/// Parâmetros leves de KDF: os padrões (256 MiB) deixam os testes muito lentos.
pub fn params_teste() -> KdfParams {
    KdfParams { m_cost_kib: 16_384, t_cost: 1, p_cost: 1 }
}
