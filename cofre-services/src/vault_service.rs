//! Serviço do cofre: orquestra inicialização, desbloqueio e operações com credenciais.

use cofre_crypto::aead;
use cofre_crypto::keys::{self, UnlockedVault, VaultInit};
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
    // Cifrar a senha com AAD
    // Nota: usamos id=0 temporariamente; numa versão futura, poderíamos usar
    // uma abordagem de INSERT + UPDATE para usar o ID real.
    let aad = aead::build_aad("credencial", "segredo_criptografado", 0, usuario_id);
    let (nonce, segredo_criptografado) = vault.encrypt(senha_plaintext, &aad)?;

    // Cifrar observação se houver
    let (obs_criptografada, obs_nonce) = match observacao {
        Some(obs) => {
            let aad_obs = aead::build_aad("credencial", "observacao_criptografada", 0, usuario_id);
            let (n, c) = vault.encrypt(obs.as_bytes(), &aad_obs)?;
            (Some(c), Some(n))
        }
        None => (None, None),
    };

    let nova = NovaCredencial {
        usuario_id,
        servico_id,
        nome_exibicao: nome_exibicao.to_string(),
        identificador: identificador.to_string(),
        segredo_criptografado,
        nonce,
        observacao_criptografada: obs_criptografada,
        observacao_nonce: obs_nonce,
        favorita: false,
    };

    let id = db.criar_credencial(&nova)?;
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

    let aad = aead::build_aad("credencial", "segredo_criptografado", 0, usuario_id);
    let plaintext = vault.decrypt(&cred.nonce, &cred.segredo_criptografado, &aad)?;

    // Atualizar último uso
    db.atualizar_ultimo_uso_credencial(credencial_id)?;

    Ok(plaintext)
}
