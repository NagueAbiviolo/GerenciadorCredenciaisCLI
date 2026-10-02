//! Comando `cofre init` — Inicializa um novo cofre.

use std::path::Path;
use anyhow::{Context, Result};
use inquire::Password;

use cofre_db::Database;
use cofre_services::vault_service;

pub fn execute(db_path: &Path, nome: &str) -> Result<()> {
    println!("🔐 Inicializando cofre para: {nome}");
    println!("   Banco: {}", db_path.display());

    // Solicitar senha mestre (oculta)
    let senha = Password::new("Defina a senha mestre:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .with_help_message("Esta senha será usada para desbloquear o cofre. NÃO pode ser recuperada!")
        .prompt()
        .context("Falha ao ler a senha mestre")?;

    let confirmacao = Password::new("Confirme a senha mestre:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()
        .context("Falha ao confirmar a senha mestre")?;

    if senha != confirmacao {
        anyhow::bail!("As senhas não coincidem. Tente novamente.");
    }

    if senha.len() < 8 {
        anyhow::bail!("A senha mestre deve ter pelo menos 8 caracteres.");
    }

    // Criar diretório pai se necessário
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let db = Database::open(db_path)
        .context("Falha ao abrir/criar o banco de dados")?;

    vault_service::init_vault(&db, nome, senha.as_bytes())
        .context("Falha ao inicializar o cofre")?;

    println!();
    println!("✅ Cofre inicializado com sucesso!");
    println!("   Proprietário: {nome}");
    println!("   Criptografia: XChaCha20-Poly1305 com Argon2id");
    println!();
    println!("⚠️  IMPORTANTE: Não há como recuperar a senha mestre.");
    println!("   Se esquecê-la, os dados serão perdidos permanentemente.");

    Ok(())
}
