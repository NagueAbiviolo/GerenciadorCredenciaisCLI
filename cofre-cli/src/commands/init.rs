//! Comando `cofre init` — Inicializa um novo cofre.

use std::path::Path;
use anyhow::{Context, Result};

use cofre_db::Database;
use cofre_services::vault_service;

use super::unlock::pedir_senha_mestre_nova;

pub fn execute(db_path: &Path, nome: &str) -> Result<()> {
    println!("🔐 Inicializando cofre para: {nome}");
    println!("   Banco: {}", db_path.display());

    let senha = pedir_senha_mestre_nova("Defina a senha mestre:")?;

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
