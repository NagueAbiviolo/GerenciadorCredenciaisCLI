//! Migrações do banco de dados.
//!
//! Utiliza refinery para versionamento do schema.
//! Cada arquivo SQL em `migrations/` é executado em ordem.

use rusqlite::Connection;

/// Migrações embarcadas no binário via refinery.
mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("migrations");
}

/// Executa todas as migrações pendentes.
pub fn run(conn: &mut Connection) -> Result<(), Box<dyn std::error::Error>> {
    embedded::migrations::runner().run(conn)?;
    Ok(())
}
