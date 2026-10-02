//! Comandos de gerenciamento de categorias.

use std::path::Path;
use anyhow::{Context, Result};
use comfy_table::{Table, ContentArrangement};

use cofre_db::Database;
use cofre_db::models::NovaCategoria;

use super::CategoriaCommands;

pub fn execute(db_path: &Path, cmd: CategoriaCommands) -> Result<()> {
    let db = Database::open(db_path)
        .context("Falha ao abrir o banco de dados")?;

    match cmd {
        CategoriaCommands::Add { nome, descricao } => {
            let nova = NovaCategoria { nome: nome.clone(), descricao };
            let id = db.criar_categoria(&nova)
                .context("Falha ao criar categoria")?;
            println!("✅ Categoria '{nome}' criada com ID {id}.");
        }
        CategoriaCommands::List => {
            let categorias = db.listar_categorias()
                .context("Falha ao listar categorias")?;

            if categorias.is_empty() {
                println!("Nenhuma categoria encontrada.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec!["ID", "Nome", "Descrição", "Criada em"]);

            for cat in &categorias {
                table.add_row(vec![
                    cat.id.to_string(),
                    cat.nome.clone(),
                    cat.descricao.clone().unwrap_or_default(),
                    cat.criado_em.format("%d/%m/%Y %H:%M").to_string(),
                ]);
            }

            println!("{table}");
            println!("\nTotal: {} categoria(s)", categorias.len());
        }
    }

    Ok(())
}
