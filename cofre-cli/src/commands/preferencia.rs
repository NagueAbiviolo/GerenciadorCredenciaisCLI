//! Comandos de gerenciamento de preferências (`cofre preferencia ...`).

use anyhow::{Context, Result};
use comfy_table::{ContentArrangement, Table};

use cofre_services::preferencia_service;

use super::sessao::Contexto;
use super::PreferenciaCommands;

pub fn execute(ctx: &Contexto, cmd: PreferenciaCommands) -> Result<()> {
    ctx.com_sessao(|s| {
        match cmd {
            PreferenciaCommands::List => {
                let preferencias = preferencia_service::listar_efetivas(&s.db, s.usuario_id)
                    .context("Falha ao listar preferências")?;

                let mut table = Table::new();
                table.set_content_arrangement(ContentArrangement::Dynamic);
                table.set_header(vec!["Chave", "Valor", "Padrão?", "Descrição"]);

                for p in &preferencias {
                    table.add_row(vec![
                        p.chave.clone(),
                        p.valor.clone(),
                        if p.padrao { "Sim" } else { "Não" }.into(),
                        p.descricao.clone(),
                    ]);
                }

                println!("{table}");
                println!("\nTotal: {} preferência(s)", preferencias.len());
            }

            PreferenciaCommands::Get { chave } => {
                let p = preferencia_service::obter(&s.db, s.usuario_id, &chave)
                    .context("Falha ao obter preferência")?;
                println!(
                    "{} = {}{}",
                    p.chave,
                    p.valor,
                    if p.padrao { " (padrão)" } else { "" }
                );
            }

            PreferenciaCommands::Set { chave, valor } => {
                let p = preferencia_service::definir(&s.db, s.usuario_id, &chave, &valor)
                    .context("Falha ao definir preferência")?;
                println!("✅ Preferência '{}' definida como '{}'.", p.chave, p.valor);
            }

            PreferenciaCommands::Reset { chave } => {
                let p = preferencia_service::redefinir(&s.db, s.usuario_id, &chave)
                    .context("Falha ao redefinir preferência")?;
                println!(
                    "🔄 Preferência '{}' redefinida para o padrão ('{}').",
                    p.chave, p.valor
                );
            }
        }

        Ok(())
    })
}
