//! Comandos de gerenciamento de serviços.

use std::path::Path;
use anyhow::{Context, Result};
use comfy_table::{Table, ContentArrangement};

use cofre_db::Database;
use cofre_db::models::NovoServico;

use super::ServicoCommands;

pub fn execute(db_path: &Path, cmd: ServicoCommands) -> Result<()> {
    let db = Database::open(db_path)
        .context("Falha ao abrir o banco de dados")?;

    match cmd {
        ServicoCommands::Add { nome, dominio, categoria_id, url } => {
            let novo = NovoServico {
                categoria_id,
                nome: nome.clone(),
                dominio_principal: dominio,
                url_principal: url,
                descricao: None,
            };
            let id = db.criar_servico(&novo)
                .context("Falha ao criar serviço")?;
            println!("✅ Serviço '{nome}' criado com ID {id}.");
        }
        ServicoCommands::List { categoria_id } => {
            let servicos = db.listar_servicos(categoria_id)
                .context("Falha ao listar serviços")?;

            if servicos.is_empty() {
                println!("Nenhum serviço encontrado.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec!["ID", "Nome", "Domínio", "Categoria", "Criado em"]);

            for s in &servicos {
                table.add_row(vec![
                    s.id.to_string(),
                    s.nome.clone(),
                    s.dominio_principal.clone(),
                    s.categoria_id.map(|id| id.to_string()).unwrap_or("-".into()),
                    s.criado_em.format("%d/%m/%Y %H:%M").to_string(),
                ]);
            }

            println!("{table}");
            println!("\nTotal: {} serviço(s)", servicos.len());
        }
        ServicoCommands::Search { termo } => {
            let servicos = db.pesquisar_servicos(&termo)
                .context("Falha ao pesquisar serviços")?;

            if servicos.is_empty() {
                println!("Nenhum serviço encontrado para '{termo}'.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec!["ID", "Nome", "Domínio"]);

            for s in &servicos {
                table.add_row(vec![
                    s.id.to_string(),
                    s.nome.clone(),
                    s.dominio_principal.clone(),
                ]);
            }

            println!("{table}");
            println!("\n{} resultado(s) para '{termo}'", servicos.len());
        }
    }

    Ok(())
}
