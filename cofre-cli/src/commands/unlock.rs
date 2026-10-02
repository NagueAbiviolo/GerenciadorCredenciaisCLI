//! Utilitário para desbloquear o cofre (usado por vários comandos).

use std::path::Path;
use anyhow::{Context, Result};
use inquire::Password;

use cofre_crypto::keys::UnlockedVault;
use cofre_db::Database;
use cofre_services::vault_service;

/// Abre o banco, solicita a senha mestre e desbloqueia o cofre.
///
/// Retorna a sessão desbloqueada, o banco e o ID do usuário.
pub fn unlock(db_path: &Path) -> Result<(Database, UnlockedVault, i64)> {
    let db = Database::open(db_path)
        .context("Falha ao abrir o banco de dados")?;

    let senha = Password::new("Senha mestre:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()
        .context("Falha ao ler a senha mestre")?;

    let (vault, usuario_id) = vault_service::unlock_vault(&db, senha.as_bytes())
        .context("Falha ao desbloquear o cofre")?;

    Ok((db, vault, usuario_id))
}
