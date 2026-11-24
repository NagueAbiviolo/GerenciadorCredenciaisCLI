//! Comando `cofre senha-mestre` — Altera a senha mestre do cofre.

use anyhow::{Context, Result};

use cofre_services::vault_service;

use super::sessao::Contexto;
use super::unlock::{self, pedir_senha_mestre_nova};

pub fn execute(ctx: &Contexto) -> Result<()> {
    // A senha atual é sempre pedida, mesmo com o cofre já desbloqueado no
    // `cofre shell`: quem encontra um terminal aberto não pode trocar a senha.
    println!("🔐 Alteração da senha mestre. Informe primeiro a senha atual.");
    let (db, vault, usuario_id) = unlock::unlock(ctx.db_path())?;

    let nova = pedir_senha_mestre_nova("Nova senha mestre:")?;

    // `alterar_senha_mestre` só recifra a DEK com uma nova KEK. A DEK em si não
    // muda, então uma sessão ativa do `cofre shell` continua válida.
    vault_service::alterar_senha_mestre(&db, &vault, usuario_id, nova.as_bytes())
        .context("Falha ao alterar a senha mestre")?;

    println!("✅ Senha mestre alterada. As credenciais não precisaram ser recifradas.");
    Ok(())
}
