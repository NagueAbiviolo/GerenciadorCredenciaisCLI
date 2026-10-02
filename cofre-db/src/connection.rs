//! Conexão e configuração do banco SQLite.

use std::path::Path;

use rusqlite::Connection;
use thiserror::Error;

use crate::migrations;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Erro no banco de dados: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Erro nas migrações: {0}")]
    Migration(String),

    #[error("Registro não encontrado")]
    NotFound,

    #[error("Violação de restrição: {0}")]
    ConstraintViolation(String),
}

/// Wrapper do banco de dados SQLite.
pub struct Database {
    pub conn: Connection,
}

impl Database {
    /// Abre (ou cria) o banco de dados no caminho especificado.
    ///
    /// Configura modo WAL, foreign keys e executa as migrações pendentes.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;

        // Configurações de segurança e performance
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA synchronous = NORMAL;",
        )?;

        let mut db = Self { conn };

        // Executar migrações
        migrations::run(&mut db.conn)
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(db)
    }

    /// Abre um banco em memória (para testes).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()?;

        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;

        let mut db = Self { conn };

        migrations::run(&mut db.conn)
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(db)
    }
}
