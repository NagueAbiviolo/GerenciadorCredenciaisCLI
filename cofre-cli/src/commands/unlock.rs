//! Utilitários de senha e desbloqueio do cofre (usados por vários comandos).

use std::path::Path;
use anyhow::{Context, Result};
use inquire::Password;
use zeroize::Zeroizing;

use cofre_crypto::keys::UnlockedVault;
use cofre_db::Database;
use cofre_services::vault_service;

/// Tamanho mínimo da senha mestre.
pub const MIN_SENHA_MESTRE: usize = 8;

/// Pede uma senha existente (sem confirmação).
pub fn pedir_senha(mensagem: &str) -> Result<Zeroizing<String>> {
    Password::new(mensagem)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map(Zeroizing::new)
        .context("Falha ao ler a senha")
}

/// Pede uma senha nova, digitada duas vezes para confirmação.
pub fn pedir_senha_nova(mensagem: &str, ajuda: Option<&str>) -> Result<Zeroizing<String>> {
    let mut prompt = Password::new(mensagem)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Confirme a senha:")
        .with_custom_confirmation_error_message("As senhas não coincidem. Tente novamente.");
    if let Some(ajuda) = ajuda {
        prompt = prompt.with_help_message(ajuda);
    }
    let senha = prompt.prompt().map(Zeroizing::new).context("Falha ao ler a senha")?;
    if senha.is_empty() {
        anyhow::bail!("A senha não pode ser vazia.");
    }
    Ok(senha)
}

/// Pede uma nova senha mestre, validando o tamanho mínimo.
pub fn pedir_senha_mestre_nova(mensagem: &str) -> Result<Zeroizing<String>> {
    let senha = pedir_senha_nova(
        mensagem,
        Some("Esta senha será usada para desbloquear o cofre. NÃO pode ser recuperada!"),
    )?;
    if senha.chars().count() < MIN_SENHA_MESTRE {
        anyhow::bail!("A senha mestre deve ter pelo menos {MIN_SENHA_MESTRE} caracteres.");
    }
    Ok(senha)
}

/// Abre o banco, solicita a senha mestre e desbloqueia o cofre.
///
/// Retorna a sessão desbloqueada, o banco e o ID do usuário.
pub fn unlock(db_path: &Path) -> Result<(Database, UnlockedVault, i64)> {
    let db = Database::open(db_path)
        .context("Falha ao abrir o banco de dados")?;

    let senha = pedir_senha("Senha mestre:")?;

    let (vault, usuario_id) = vault_service::unlock_vault(&db, senha.as_bytes())
        .context("Falha ao desbloquear o cofre")?;

    Ok((db, vault, usuario_id))
}
