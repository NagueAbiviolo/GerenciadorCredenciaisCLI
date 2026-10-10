//! Serviço do cofre: orquestra inicialização, desbloqueio e operações com credenciais.

use cofre_crypto::aead;
use cofre_crypto::keys::{self, UnlockedVault};
use cofre_crypto::kdf::KdfParams;
use cofre_db::Database;
use cofre_db::connection::DbError;
use cofre_db::models::NovaCredencial;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultServiceError {
    #[error("Erro de criptografia: {0}")]
    Crypto(#[from] cofre_crypto::CryptoError),

    #[error("Erro no banco de dados: {0}")]
    Db(#[from] DbError),

    #[error("Cofre já inicializado")]
    AlreadyInitialized,

    #[error("Cofre não inicializado. Execute 'cofre init' primeiro.")]
    NotInitialized,
}

/// Inicializa um novo cofre.
pub fn init_vault(db: &Database, nome: &str, password: &[u8]) -> Result<(), VaultServiceError> {
    // Verificar se já existe um usuário ativo
    if db.buscar_usuario_ativo().is_ok() {
        return Err(VaultServiceError::AlreadyInitialized);
    }

    let params = KdfParams::default();
    let vault_data = keys::init_vault(password, &params)?;

    db.criar_usuario(
        nome,
        &vault_data.verifier,
        &vault_data.kek_salt,
        &vault_data.kdf_params_json,
        &vault_data.encrypted_dek,
        &vault_data.dek_nonce,
        &vault_data.verifier_salt,
    )?;

    Ok(())
}

/// Desbloqueia o cofre e retorna a sessão com a DEK em memória protegida.
pub fn unlock_vault(db: &Database, password: &[u8]) -> Result<(UnlockedVault, i64), VaultServiceError> {
    let usuario = db.buscar_usuario_ativo().map_err(|e| match e {
        DbError::NotFound => VaultServiceError::NotInitialized,
        other => VaultServiceError::Db(other),
    })?;

    let vault = keys::unlock_vault(
        password,
        &usuario.salt_kdf,
        &usuario.verificador_salt,
        &usuario.verificador_mestre,
        &usuario.dek_criptografada,
        &usuario.dek_nonce,
        &usuario.parametros_kdf,
    )?;

    // Atualizar último acesso
    db.atualizar_ultimo_acesso(usuario.id)?;

    Ok((vault, usuario.id))
}

/// Adiciona uma nova credencial cifrada ao cofre.
pub fn adicionar_credencial(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
    servico_id: i64,
    nome_exibicao: &str,
    identificador: &str,
    senha_plaintext: &[u8],
    observacao: Option<&str>,
) -> Result<i64, VaultServiceError> {
    // A AAD precisa do ID real da linha, que só existe após o INSERT. Por isso a
    // credencial é inserida com campos cifrados vazios e atualizada em seguida,
    // tudo na mesma transação: nunca fica gravada uma linha sem segredo.
    let tx = db.conn.unchecked_transaction().map_err(DbError::from)?;

    let nova = NovaCredencial {
        usuario_id,
        servico_id,
        nome_exibicao: nome_exibicao.to_string(),
        identificador: identificador.to_string(),
        segredo_criptografado: Vec::new(),
        nonce: Vec::new(),
        observacao_criptografada: None,
        observacao_nonce: None,
        favorita: false,
    };
    let id = db.criar_credencial(&nova)?;

    let aad = aead::build_aad("credencial", "segredo_criptografado", id, usuario_id);
    let (nonce, segredo_criptografado) = vault.encrypt(senha_plaintext, &aad)?;

    let (obs_criptografada, obs_nonce) = match observacao {
        Some(obs) => {
            let aad_obs = aead::build_aad("credencial", "observacao_criptografada", id, usuario_id);
            let (n, c) = vault.encrypt(obs.as_bytes(), &aad_obs)?;
            (Some(c), Some(n))
        }
        None => (None, None),
    };

    db.definir_segredos_credencial(
        id,
        &segredo_criptografado,
        &nonce,
        obs_criptografada.as_deref(),
        obs_nonce.as_deref(),
    )?;

    tx.commit().map_err(DbError::from)?;
    Ok(id)
}

/// Descriptografa e retorna a senha de uma credencial.
pub fn revelar_senha(
    db: &Database,
    vault: &UnlockedVault,
    credencial_id: i64,
    usuario_id: i64,
) -> Result<Vec<u8>, VaultServiceError> {
    let cred = db.buscar_credencial(credencial_id)?;
    if cred.usuario_id != usuario_id {
        return Err(VaultServiceError::Db(DbError::NotFound));
    }

    let aad = aead::build_aad("credencial", "segredo_criptografado", cred.id, usuario_id);
    let plaintext = vault.decrypt(&cred.nonce, &cred.segredo_criptografado, &aad)?;

    // Atualizar último uso
    db.atualizar_ultimo_uso_credencial(credencial_id)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cofre_db::models::NovoServico;

    /// Banco temporário em arquivo, removido ao final do teste.
    struct DbTemp(std::path::PathBuf);

    impl DbTemp {
        fn new(nome: &str) -> Self {
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

    #[test]
    fn test_init_unlock_adicionar_e_revelar() {
        let tmp = DbTemp::new("roundtrip");
        let db = Database::open(&tmp.0).unwrap();
        init_vault(&db, "Teste", b"senha-mestre-forte").unwrap();

        assert!(unlock_vault(&db, b"senha-errada").is_err());
        let (vault, usuario_id) = unlock_vault(&db, b"senha-mestre-forte").unwrap();

        let servico_id = db
            .criar_servico(&NovoServico {
                categoria_id: None,
                nome: "GitHub".into(),
                dominio_principal: "github.com".into(),
                url_principal: None,
                descricao: None,
            })
            .unwrap();

        let a = adicionar_credencial(&db, &vault, usuario_id, servico_id, "A", "a@x.com", b"senha-a", None).unwrap();
        let b = adicionar_credencial(&db, &vault, usuario_id, servico_id, "B", "b@x.com", b"senha-b", None).unwrap();

        assert_eq!(revelar_senha(&db, &vault, a, usuario_id).unwrap(), b"senha-a");
        assert_eq!(revelar_senha(&db, &vault, b, usuario_id).unwrap(), b"senha-b");

        // Copiar o segredo cifrado de B para A deve ser detectado pela AAD.
        let cred_b = db.buscar_credencial(b).unwrap();
        db.definir_segredos_credencial(a, &cred_b.segredo_criptografado, &cred_b.nonce, None, None)
            .unwrap();
        assert!(revelar_senha(&db, &vault, a, usuario_id).is_err());
    }
}
