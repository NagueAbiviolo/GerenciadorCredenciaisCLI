//! # cofre-crypto
//!
//! Módulo criptográfico do Gerenciador de Credenciais.
//!
//! Responsável por:
//! - Derivação de chaves (KDF) com Argon2id
//! - Hierarquia KEK/DEK
//! - Criptografia autenticada (AEAD) com XChaCha20-Poly1305 e AAD
//! - Proteção de segredos em memória (secrecy + zeroize)

pub mod aead;
pub mod error;
pub mod kdf;
pub mod keys;

pub use error::CryptoError;
