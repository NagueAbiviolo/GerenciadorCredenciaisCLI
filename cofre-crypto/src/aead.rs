//! Criptografia autenticada com XChaCha20-Poly1305 e AAD.
//!
//! Todas as operações de cifrar/decifrar utilizam **Additional Authenticated Data (AAD)**
//! para vincular o texto cifrado ao seu contexto (tabela, coluna, ID, etc.), impedindo
//! que um atacante com acesso ao banco troque ciphertexts entre linhas/colunas.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

use crate::CryptoError;

/// Tamanho do nonce para XChaCha20-Poly1305: 24 bytes (192 bits).
const NONCE_LEN: usize = 24;

/// Gera um nonce aleatório de 24 bytes.
pub fn generate_nonce() -> Result<Vec<u8>, CryptoError> {
    let mut nonce = vec![0u8; NONCE_LEN];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CryptoError::RandomError(e.to_string()))?;
    Ok(nonce)
}

/// Constrói a string de AAD a partir dos componentes de contexto.
///
/// Formato: `tabela|coluna|id|usuario_id`
///
/// # Exemplo
/// ```
/// use cofre_crypto::aead::build_aad;
/// let aad = build_aad("credencial", "segredo_criptografado", 42, 1);
/// assert_eq!(aad, "credencial|segredo_criptografado|42|1");
/// ```
pub fn build_aad(table: &str, column: &str, record_id: i64, user_id: i64) -> String {
    format!("{table}|{column}|{record_id}|{user_id}")
}

/// Cifra dados com XChaCha20-Poly1305 usando AAD.
///
/// Retorna `(nonce, ciphertext)`. Ambos devem ser armazenados no banco.
///
/// # Parâmetros
/// - `key`: Chave de 256 bits (DEK).
/// - `plaintext`: Dados a serem cifrados.
/// - `aad`: Additional Authenticated Data — contexto que amarra o ciphertext ao registro.
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &str) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::EncryptionError(
            "Chave deve ter 32 bytes (256 bits)".into(),
        ));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    let nonce_bytes = generate_nonce()?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: aad.as_bytes(),
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    Ok((nonce_bytes, ciphertext))
}

/// Decifra dados com XChaCha20-Poly1305 usando AAD.
///
/// # Parâmetros
/// - `key`: Chave de 256 bits (DEK).
/// - `nonce`: Nonce de 24 bytes usado na cifragem.
/// - `ciphertext`: Dados cifrados.
/// - `aad`: Additional Authenticated Data — deve ser **exatamente** o mesmo usado na cifragem.
///
/// # Erros
/// Retorna `CryptoError::DecryptionError` se a chave, nonce ou AAD estiverem incorretos
/// (autenticação falha = dados foram adulterados ou o contexto não confere).
pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &str,
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::DecryptionError(
            "Chave deve ter 32 bytes (256 bits)".into(),
        ));
    }
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::DecryptionError(format!(
            "Nonce deve ter {NONCE_LEN} bytes, recebeu {}",
            nonce.len()
        )));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad: aad.as_bytes(),
    };

    let plaintext = cipher
        .decrypt(xnonce, payload)
        .map_err(|_| CryptoError::DecryptionError(
            "Falha na autenticação: chave, nonce ou AAD incorretos, ou dados adulterados".into(),
        ))?;

    // Nota: o chamador é responsável por zeroizar o Vec<u8> retornado após o uso.
    Ok(plaintext)
}

/// Cifra a DEK usando a KEK (sem AAD adicional, pois o contexto é fixo).
///
/// Usada internamente pela hierarquia de chaves.
pub fn encrypt_dek(kek: &[u8], dek: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    encrypt(kek, dek, "sistema|dek|0|0")
}

/// Decifra a DEK usando a KEK.
pub fn decrypt_dek(kek: &[u8], nonce: &[u8], encrypted_dek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    decrypt(kek, nonce, encrypted_dek, "sistema|dek|0|0")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"minha-senha-super-secreta";
        let aad = build_aad("credencial", "segredo_criptografado", 1, 1);

        let (nonce, ciphertext) = encrypt(&key, plaintext, &aad).unwrap();

        assert_ne!(&ciphertext[..], plaintext, "Ciphertext não deve ser igual ao plaintext");

        let decrypted = decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = test_key();
        let plaintext = b"dados-sensiveis";
        let aad_original = build_aad("credencial", "segredo_criptografado", 1, 1);
        let aad_errado = build_aad("credencial", "segredo_criptografado", 2, 1);

        let (nonce, ciphertext) = encrypt(&key, plaintext, &aad_original).unwrap();

        // Tentar decifrar com AAD diferente deve falhar (proteção contra swap de linhas)
        let result = decrypt(&key, &nonce, &ciphertext, &aad_errado);
        assert!(result.is_err(), "Descriptografia com AAD diferente deve falhar");
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = test_key();
        let wrong_key = vec![0x99u8; 32];
        let plaintext = b"dados-sensiveis";
        let aad = build_aad("credencial", "segredo_criptografado", 1, 1);

        let (nonce, ciphertext) = encrypt(&key, plaintext, &aad).unwrap();

        let result = decrypt(&wrong_key, &nonce, &ciphertext, &aad);
        assert!(result.is_err(), "Descriptografia com chave errada deve falhar");
    }

    #[test]
    fn test_dek_encrypt_decrypt() {
        let kek = test_key();
        let dek = vec![0xABu8; 32];

        let (nonce, encrypted_dek) = encrypt_dek(&kek, &dek).unwrap();
        let decrypted_dek = decrypt_dek(&kek, &nonce, &encrypted_dek).unwrap();

        assert_eq!(decrypted_dek, dek);
    }

    #[test]
    fn test_build_aad_format() {
        let aad = build_aad("credencial", "segredo_criptografado", 42, 1);
        assert_eq!(aad, "credencial|segredo_criptografado|42|1");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let plaintext = b"dados-sensiveis";
        let aad = build_aad("credencial", "segredo_criptografado", 1, 1);

        let (nonce, mut ciphertext) = encrypt(&key, plaintext, &aad).unwrap();

        // Adulterar um byte do ciphertext
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt(&key, &nonce, &ciphertext, &aad);
        assert!(result.is_err(), "Ciphertext adulterado deve falhar na autenticação");
    }
}
