//! Derivação de chaves com Argon2id.
//!
//! Implementa a geração de KEK a partir da senha mestre e a verificação
//! de senhas. Os parâmetros do KDF são serializáveis para armazenamento
//! no campo `parametros_kdf` da tabela `usuario`.

use argon2::{self, Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::CryptoError;

/// Tamanho do salt em bytes (128 bits).
const SALT_LEN: usize = 16;

/// Tamanho da chave derivada em bytes (256 bits).
const KEY_LEN: usize = 32;

/// Parâmetros do KDF serializáveis (armazenados como JSON no banco).
///
/// Calibrados para ~0.5–1s em hardware moderno:
/// - 256 MiB de memória
/// - 3 iterações
/// - 4 threads de paralelismo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Custo de memória em KiB (padrão: 262144 = 256 MiB).
    pub m_cost_kib: u32,
    /// Número de iterações (padrão: 3).
    pub t_cost: u32,
    /// Grau de paralelismo (padrão: 4).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 262_144, // 256 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// Resultado da derivação de chave para um novo usuário.
///
/// Contém o salt, a chave derivada (KEK) e o verificador mestre.
pub struct KdfOutput {
    /// Salt aleatório gerado (armazenar no campo `salt_kdf`).
    pub salt: Vec<u8>,
    /// Chave derivada de 256 bits (usar como KEK).
    /// Deve ser encapsulada em `secrecy::Secret` pelo chamador.
    pub derived_key: Vec<u8>,
    /// Verificador mestre: hash Argon2id(senha, salt_verificador).
    /// Usado para validar a senha mestre sem expor a KEK.
    pub verifier: Vec<u8>,
    /// Salt separado usado para gerar o verificador.
    pub verifier_salt: Vec<u8>,
}



/// Gera um salt aleatório criptograficamente seguro.
pub fn generate_salt() -> Result<Vec<u8>, CryptoError> {
    let mut salt = vec![0u8; SALT_LEN];
    rand::thread_rng()
        .try_fill_bytes(&mut salt)
        .map_err(|e| CryptoError::RandomError(e.to_string()))?;
    Ok(salt)
}

/// Constrói uma instância de Argon2 a partir dos parâmetros fornecidos.
fn build_argon2(params: &KdfParams) -> Result<(Argon2<'_>, Params), CryptoError> {
    let argon2_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params.clone());
    Ok((argon2, argon2_params))
}

/// Deriva uma chave (KEK) e um verificador a partir da senha mestre.
///
/// Esta função é usada durante a **criação** do cofre (`init`).
/// - Gera um salt aleatório para a KEK.
/// - Gera um salt separado para o verificador.
/// - Retorna ambos os salts, a KEK e o verificador.
pub fn derive_new(password: &[u8], params: &KdfParams) -> Result<KdfOutput, CryptoError> {
    let salt = generate_salt()?;
    let verifier_salt = generate_salt()?;

    let (argon2, _) = build_argon2(params)?;

    // Derivar KEK
    let mut derived_key = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(password, &salt, &mut derived_key)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    // Derivar verificador (com salt separado para não expor a KEK)
    let mut verifier = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(password, &verifier_salt, &mut verifier)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    Ok(KdfOutput {
        salt,
        derived_key,
        verifier,
        verifier_salt,
    })
}

/// Deriva a KEK a partir da senha mestre e do salt existente.
///
/// Usada durante o **desbloqueio** do cofre (`unlock`).
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Vec<u8>, CryptoError> {
    let (argon2, _) = build_argon2(params)?;
    let mut derived_key = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut derived_key)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;
    Ok(derived_key)
}

/// Verifica a senha mestre contra o verificador armazenado.
///
/// Retorna `Ok(())` se a senha estiver correta, ou
/// `Err(CryptoError::InvalidMasterPassword)` caso contrário.
pub fn verify_password(
    password: &[u8],
    verifier_salt: &[u8],
    expected_verifier: &[u8],
    params: &KdfParams,
) -> Result<(), CryptoError> {
    let (argon2, _) = build_argon2(params)?;
    let mut computed = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(password, verifier_salt, &mut computed)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;

    // O tamanho deve ser comparado antes do zeroize: em Vec<u8>, zeroize() também
    // trunca o vetor para len = 0.
    let same_len = computed.len() == expected_verifier.len();

    // Comparação em tempo constante
    let matches = computed
        .iter()
        .zip(expected_verifier.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));

    computed.zeroize();

    if same_len && matches == 0 {
        Ok(())
    } else {
        Err(CryptoError::InvalidMasterPassword)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_and_verify() {
        let params = KdfParams {
            m_cost_kib: 16_384, // 16 MiB para testes rápidos
            t_cost: 1,
            p_cost: 1,
        };

        let password = b"minha-senha-mestre-segura";
        let output = derive_new(password, &params).unwrap();

        // Verificação com senha correta deve passar
        assert!(verify_password(password, &output.verifier_salt, &output.verifier, &params).is_ok());

        // Verificação com senha errada deve falhar
        assert!(
            verify_password(b"senha-errada", &output.verifier_salt, &output.verifier, &params)
                .is_err()
        );
    }

    #[test]
    fn test_derive_key_deterministic() {
        let params = KdfParams {
            m_cost_kib: 16_384,
            t_cost: 1,
            p_cost: 1,
        };
        let password = b"test-password";
        let salt = generate_salt().unwrap();

        let key1 = derive_key(password, &salt, &params).unwrap();
        let key2 = derive_key(password, &salt, &params).unwrap();

        assert_eq!(key1, key2, "Mesma senha e salt devem produzir a mesma chave");
    }

    #[test]
    fn test_kdf_params_serialization() {
        let params = KdfParams::default();
        let json = serde_json::to_string(&params).unwrap();
        let deserialized: KdfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params.m_cost_kib, deserialized.m_cost_kib);
        assert_eq!(params.t_cost, deserialized.t_cost);
        assert_eq!(params.p_cost, deserialized.p_cost);
    }
}
