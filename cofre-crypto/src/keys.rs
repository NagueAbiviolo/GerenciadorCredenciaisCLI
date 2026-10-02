//! Gerenciamento da hierarquia de chaves KEK/DEK.
//!
//! - **KEK (Key Encryption Key):** Derivada da senha mestre via Argon2id.
//!   Usada exclusivamente para cifrar/decifrar a DEK.
//! - **DEK (Data Encryption Key):** Chave aleatória de 256 bits que cifra
//!   todos os dados sensíveis do cofre. Alterar a senha mestre recifra
//!   apenas a DEK, sem tocar nas credenciais.

use rand::RngCore;
use secrecy::{ExposeSecret, SecretVec};
use zeroize::Zeroize;

use crate::aead;
use crate::kdf::{self, KdfParams};
use crate::CryptoError;

/// Tamanho da DEK em bytes (256 bits).
const DEK_LEN: usize = 32;

/// Contém os dados necessários para persistir o cofre no banco de dados.
///
/// Resultado da inicialização de um novo cofre.
pub struct VaultInit {
    /// Salt da KEK (armazenar em `usuario.salt_kdf`).
    pub kek_salt: Vec<u8>,
    /// Verificador mestre (armazenar em `usuario.verificador_mestre`).
    pub verifier: Vec<u8>,
    /// Salt do verificador (armazenar junto com `verificador_mestre`).
    pub verifier_salt: Vec<u8>,
    /// DEK cifrada pela KEK (armazenar de forma segura).
    pub encrypted_dek: Vec<u8>,
    /// Nonce usado para cifrar a DEK.
    pub dek_nonce: Vec<u8>,
    /// Parâmetros KDF serializados como JSON (armazenar em `usuario.parametros_kdf`).
    pub kdf_params_json: String,
}

/// Sessão de cofre desbloqueado.
///
/// Mantém a DEK em memória protegida (`SecretVec`) durante a sessão.
/// A DEK é zeroizada automaticamente ao ser descartada.
pub struct UnlockedVault {
    /// DEK em memória protegida.
    dek: SecretVec<u8>,
}

impl UnlockedVault {
    /// Acessa a DEK para operações de criptografia.
    ///
    /// O chamador deve usar a referência imediatamente e não copiá-la.
    pub fn dek(&self) -> &[u8] {
        self.dek.expose_secret()
    }

    /// Cifra dados sensíveis usando a DEK e AAD.
    pub fn encrypt(&self, plaintext: &[u8], aad: &str) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        aead::encrypt(self.dek(), plaintext, aad)
    }

    /// Decifra dados usando a DEK e AAD.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        aead::decrypt(self.dek(), nonce, ciphertext, aad)
    }
}

/// Inicializa um novo cofre com uma senha mestre.
///
/// Gera a DEK aleatória, deriva a KEK da senha e cifra a DEK.
/// Retorna os dados necessários para persistir no banco.
pub fn init_vault(password: &[u8], params: &KdfParams) -> Result<VaultInit, CryptoError> {
    // 1. Gerar DEK aleatória
    let mut dek = vec![0u8; DEK_LEN];
    rand::thread_rng()
        .try_fill_bytes(&mut dek)
        .map_err(|e| CryptoError::RandomError(e.to_string()))?;

    // 2. Derivar KEK e verificador a partir da senha mestre
    let kdf_output = kdf::derive_new(password, params)?;

    // 3. Cifrar a DEK com a KEK
    let (dek_nonce, encrypted_dek) = aead::encrypt_dek(&kdf_output.derived_key, &dek)?;

    // 4. Serializar parâmetros KDF
    let kdf_params_json = serde_json::to_string(params)?;

    // Zeroizar a DEK em texto puro
    dek.zeroize();

    Ok(VaultInit {
        kek_salt: kdf_output.salt,
        verifier: kdf_output.verifier,
        verifier_salt: kdf_output.verifier_salt,
        encrypted_dek,
        dek_nonce,
        kdf_params_json,
    })
}

/// Desbloqueia o cofre verificando a senha mestre e recuperando a DEK.
///
/// # Parâmetros
/// - `password`: Senha mestre em bytes.
/// - `kek_salt`: Salt da KEK (de `usuario.salt_kdf`).
/// - `verifier_salt`: Salt do verificador.
/// - `expected_verifier`: Verificador armazenado (de `usuario.verificador_mestre`).
/// - `encrypted_dek`: DEK cifrada.
/// - `dek_nonce`: Nonce da DEK cifrada.
/// - `kdf_params_json`: Parâmetros KDF serializados.
pub fn unlock_vault(
    password: &[u8],
    kek_salt: &[u8],
    verifier_salt: &[u8],
    expected_verifier: &[u8],
    encrypted_dek: &[u8],
    dek_nonce: &[u8],
    kdf_params_json: &str,
) -> Result<UnlockedVault, CryptoError> {
    // 1. Deserializar parâmetros KDF
    let params: KdfParams = serde_json::from_str(kdf_params_json)?;

    // 2. Verificar a senha mestre
    kdf::verify_password(password, verifier_salt, expected_verifier, &params)?;

    // 3. Derivar KEK
    let mut kek = kdf::derive_key(password, kek_salt, &params)?;

    // 4. Decifrar a DEK
    let dek_bytes = aead::decrypt_dek(&kek, dek_nonce, encrypted_dek)?;

    // 5. Zeroizar a KEK (não precisamos mais dela)
    kek.zeroize();

    // 6. Encapsular a DEK em SecretVec
    let dek = SecretVec::new(dek_bytes);

    Ok(UnlockedVault { dek })
}

/// Altera a senha mestre sem recifrar as credenciais.
///
/// Apenas recifra a DEK com a nova KEK.
pub fn change_master_password(
    vault: &UnlockedVault,
    new_password: &[u8],
    params: &KdfParams,
) -> Result<VaultInit, CryptoError> {
    let dek_copy = vault.dek().to_vec();

    // Derivar nova KEK e verificador
    let kdf_output = kdf::derive_new(new_password, params)?;

    // Cifrar a DEK com a nova KEK
    let (dek_nonce, encrypted_dek) = aead::encrypt_dek(&kdf_output.derived_key, &dek_copy)?;

    let kdf_params_json = serde_json::to_string(params)?;

    Ok(VaultInit {
        kek_salt: kdf_output.salt,
        verifier: kdf_output.verifier,
        verifier_salt: kdf_output.verifier_salt,
        encrypted_dek,
        dek_nonce,
        kdf_params_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 16_384, // 16 MiB para testes rápidos
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn test_init_and_unlock() {
        let password = b"minha-senha-mestre-forte!";
        let params = test_params();

        // Inicializar cofre
        let vault_data = init_vault(password, &params).unwrap();

        // Desbloquear cofre
        let vault = unlock_vault(
            password,
            &vault_data.kek_salt,
            &vault_data.verifier_salt,
            &vault_data.verifier,
            &vault_data.encrypted_dek,
            &vault_data.dek_nonce,
            &vault_data.kdf_params_json,
        )
        .unwrap();

        // DEK deve ter 32 bytes
        assert_eq!(vault.dek().len(), 32);
    }

    #[test]
    fn test_wrong_password_rejected() {
        let password = b"senha-correta";
        let wrong = b"senha-errada";
        let params = test_params();

        let vault_data = init_vault(password, &params).unwrap();

        let result = unlock_vault(
            wrong,
            &vault_data.kek_salt,
            &vault_data.verifier_salt,
            &vault_data.verifier,
            &vault_data.encrypted_dek,
            &vault_data.dek_nonce,
            &vault_data.kdf_params_json,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_change_password_preserves_dek() {
        let old_pw = b"senha-antiga";
        let new_pw = b"senha-nova-mais-forte!";
        let params = test_params();

        // Inicializar com senha antiga
        let vault_data = init_vault(old_pw, &params).unwrap();
        let vault = unlock_vault(
            old_pw,
            &vault_data.kek_salt,
            &vault_data.verifier_salt,
            &vault_data.verifier,
            &vault_data.encrypted_dek,
            &vault_data.dek_nonce,
            &vault_data.kdf_params_json,
        )
        .unwrap();

        let original_dek = vault.dek().to_vec();

        // Alterar senha mestre
        let new_vault_data = change_master_password(&vault, new_pw, &params).unwrap();

        // Desbloquear com senha nova
        let new_vault = unlock_vault(
            new_pw,
            &new_vault_data.kek_salt,
            &new_vault_data.verifier_salt,
            &new_vault_data.verifier,
            &new_vault_data.encrypted_dek,
            &new_vault_data.dek_nonce,
            &new_vault_data.kdf_params_json,
        )
        .unwrap();

        // A DEK deve ser a mesma (credenciais não precisam ser recifradas)
        assert_eq!(new_vault.dek(), &original_dek[..]);

        // Senha antiga não deve mais funcionar
        let result = unlock_vault(
            old_pw,
            &new_vault_data.kek_salt,
            &new_vault_data.verifier_salt,
            &new_vault_data.verifier,
            &new_vault_data.encrypted_dek,
            &new_vault_data.dek_nonce,
            &new_vault_data.kdf_params_json,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_encrypt_decrypt() {
        let password = b"test-pw";
        let params = test_params();

        let vault_data = init_vault(password, &params).unwrap();
        let vault = unlock_vault(
            password,
            &vault_data.kek_salt,
            &vault_data.verifier_salt,
            &vault_data.verifier,
            &vault_data.encrypted_dek,
            &vault_data.dek_nonce,
            &vault_data.kdf_params_json,
        )
        .unwrap();

        let plaintext = b"senha-do-netflix";
        let aad = aead::build_aad("credencial", "segredo_criptografado", 1, 1);

        let (nonce, ciphertext) = vault.encrypt(plaintext, &aad).unwrap();
        let decrypted = vault.decrypt(&nonce, &ciphertext, &aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }
}
