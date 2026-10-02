use thiserror::Error;

/// Erros do módulo criptográfico.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Falha na derivação de chave (KDF): {0}")]
    KdfError(String),

    #[error("Falha na criptografia: {0}")]
    EncryptionError(String),

    #[error("Falha na descriptografia: {0}")]
    DecryptionError(String),

    #[error("Senha mestre inválida")]
    InvalidMasterPassword,

    #[error("Falha ao gerar dados aleatórios: {0}")]
    RandomError(String),

    #[error("Parâmetros KDF inválidos: {0}")]
    InvalidKdfParams(String),

    #[error("Serialização/deserialização: {0}")]
    SerdeError(#[from] serde_json::Error),
}
