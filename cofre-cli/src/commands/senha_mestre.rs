//! Comando `cofre senha-mestre` — Altera a senha mestre do cofre.

use std::path::Path;
use anyhow::{Context, Result};

use cofre_services::vault_service;

use super::unlock::{self, pedir_senha_mestre_nova};

pub fn execute(db_path: &Path) -> Result<()> {
    println!("🔐 Alteração da senha mestre. Informe primeiro a senha atual.");
    let (db, vault, usuario_id) = unlock::unlock(db_path)?;

    let nova = pedir_senha_mestre_nova("Nova senha mestre:")?;

    vault_service::alterar_senha_mestre(&db, &vault, usuario_id, nova.as_bytes())
        .context("Falha ao alterar a senha mestre")?;

    println!("✅ Senha mestre alterada. As credenciais não precisaram ser recifradas.");
    Ok(())
}
