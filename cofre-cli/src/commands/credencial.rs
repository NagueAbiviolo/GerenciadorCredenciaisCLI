//! Comandos de gerenciamento de credenciais.

use std::path::Path;
use anyhow::{Context, Result};
use comfy_table::{Table, ContentArrangement};
use inquire::Password;
use zeroize::Zeroize;

use cofre_services::vault_service;

use super::CredencialCommands;
use super::unlock;

pub fn execute(db_path: &Path, cmd: CredencialCommands) -> Result<()> {
    match cmd {
        CredencialCommands::Add { servico_id, nome, identificador } => {
            // Desbloquear o cofre
            let (db, vault, usuario_id) = unlock::unlock(db_path)?;

            // Solicitar a senha da credencial
            let senha = Password::new("Senha da credencial:")
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .prompt()
                .context("Falha ao ler a senha")?;

            let id = vault_service::adicionar_credencial(
                &db,
                &vault,
                usuario_id,
                servico_id,
                &nome,
                &identificador,
                senha.as_bytes(),
                None, // observação (pode ser adicionada depois)
            )
            .context("Falha ao adicionar credencial")?;

            println!("✅ Credencial '{nome}' adicionada com ID {id}.");
        }

        CredencialCommands::List => {
            let (db, _vault, usuario_id) = unlock::unlock(db_path)?;

            let credenciais = db.listar_credenciais(usuario_id)
                .context("Falha ao listar credenciais")?;

            if credenciais.is_empty() {
                println!("Nenhuma credencial encontrada.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec!["ID", "Nome", "Identificador", "Serviço", "⭐", "Último uso"]);

            for c in &credenciais {
                let servico_nome = db.buscar_servico(c.servico_id)
                    .map(|s| s.nome)
                    .unwrap_or_else(|_| "?".into());

                table.add_row(vec![
                    c.id.to_string(),
                    c.nome_exibicao.clone(),
                    c.identificador.clone(),
                    servico_nome,
                    if c.favorita { "⭐" } else { "" }.into(),
                    c.ultimo_uso_em
                        .map(|d| d.format("%d/%m/%Y %H:%M").to_string())
                        .unwrap_or("-".into()),
                ]);
            }

            println!("{table}");
            println!("\nTotal: {} credencial(is)", credenciais.len());
        }

        CredencialCommands::Show { id, revelar } => {
            let (db, vault, usuario_id) = unlock::unlock(db_path)?;

            let cred = db.buscar_credencial(id)
                .context("Credencial não encontrada")?;

            let servico_nome = db.buscar_servico(cred.servico_id)
                .map(|s| s.nome)
                .unwrap_or_else(|_| "?".into());

            println!("┌─────────────────────────────────────────");
            println!("│ 📋 Credencial #{}", cred.id);
            println!("├─────────────────────────────────────────");
            println!("│ Nome:          {}", cred.nome_exibicao);
            println!("│ Identificador: {}", cred.identificador);
            println!("│ Serviço:       {servico_nome}");
            println!("│ Favorita:      {}", if cred.favorita { "⭐ Sim" } else { "Não" });
            println!("│ Criada em:     {}", cred.criada_em.format("%d/%m/%Y %H:%M"));
            println!("│ Última alt.:   {}", cred.alterada_em.format("%d/%m/%Y %H:%M"));
            println!("│ Último uso:    {}", cred.ultimo_uso_em
                .map(|d| d.format("%d/%m/%Y %H:%M").to_string())
                .unwrap_or("-".into()));

            if revelar {
                let mut senha_bytes = vault_service::revelar_senha(&db, &vault, id, usuario_id)
                    .context("Falha ao descriptografar a senha")?;

                let senha_str = String::from_utf8_lossy(&senha_bytes);
                println!("│ 🔑 Senha:      {senha_str}");

                // Zeroizar a senha da memória
                senha_bytes.zeroize();
            } else {
                println!("│ 🔒 Senha:      ******** (use --revelar para exibir)");
            }

            println!("└─────────────────────────────────────────");
        }

        CredencialCommands::Search { termo } => {
            let (db, _vault, usuario_id) = unlock::unlock(db_path)?;

            let credenciais = db.pesquisar_credenciais(usuario_id, &termo)
                .context("Falha ao pesquisar credenciais")?;

            if credenciais.is_empty() {
                println!("Nenhuma credencial encontrada para '{termo}'.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec!["ID", "Nome", "Identificador", "Serviço"]);

            for c in &credenciais {
                let servico_nome = db.buscar_servico(c.servico_id)
                    .map(|s| s.nome)
                    .unwrap_or_else(|_| "?".into());

                table.add_row(vec![
                    c.id.to_string(),
                    c.nome_exibicao.clone(),
                    c.identificador.clone(),
                    servico_nome,
                ]);
            }

            println!("{table}");
            println!("\n{} resultado(s) para '{termo}'", credenciais.len());
        }
    }

    Ok(())
}
