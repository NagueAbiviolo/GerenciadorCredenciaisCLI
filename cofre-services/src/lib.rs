//! # cofre-services
//!
//! Regras de negócio do Gerenciador de Credenciais.
//! Orquestra operações entre cofre-crypto e cofre-db.

pub mod auditoria_service;
pub mod autenticacao_service;
pub mod dispositivo_service;
pub mod preferencia_service;
pub mod servico_service;
pub mod vault_service;

#[cfg(test)]
pub(crate) mod testes;
