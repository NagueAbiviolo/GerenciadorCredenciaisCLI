//! # cofre-db
//!
//! Camada de acesso a dados do Gerenciador de Credenciais.
//!
//! Responsável por:
//! - Conexão e configuração do SQLite (WAL, foreign keys)
//! - Migrações de schema (refinery)
//! - Repositórios (CRUD) para cada tabela

pub mod connection;
pub mod migrations;
pub mod models;
pub mod repositories;

pub use connection::Database;
