//! Comandos dos métodos de autenticação (`cofre credencial metodo ...`).

use std::path::Path;

use anyhow::{Context, Result};
use comfy_table::{ContentArrangement, Table};

use cofre_db::models::MetodoAutenticacao;
use cofre_services::autenticacao_service::{self, EdicaoMetodo};

use super::unlock;
use super::{confirmar, vazio_para_none, MetodoCommands};

/// Tabela de métodos, também usada em `credencial show`.
pub fn tabela_metodos(metodos: &[MetodoAutenticacao]) -> Table {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "ID",
        "Tipo",
        "Descrição",
        "Principal",
        "Habilitado",
        "Configurado em",
    ]);
    for m in metodos {
        table.add_row(vec![
            m.id.to_string(),
            m.tipo.clone(),
            m.descricao.clone().unwrap_or("-".into()),
            if m.principal { "✔" } else { "" }.into(),
            if m.habilitado { "Sim" } else { "Não" }.into(),
            m.configurado_em
                .map(|d| d.format("%d/%m/%Y %H:%M").to_string())
                .unwrap_or("-".into()),
        ]);
    }
    table
}

pub fn execute(db_path: &Path, cmd: MetodoCommands) -> Result<()> {
    // Sem argumentos de edição, falha antes de pedir a senha mestre.
    if let MetodoCommands::Edit {
        tipo: None,
        descricao: None,
        principal: None,
        habilitado: None,
        ..
    } = cmd
    {
        anyhow::bail!("Nada para alterar. Use --help para ver os campos editáveis.");
    }

    let (db, _vault, usuario_id) = unlock::unlock(db_path)?;

    match cmd {
        MetodoCommands::Add {
            credencial_id,
            tipo,
            descricao,
            principal,
        } => {
            let id = autenticacao_service::adicionar_metodo(
                &db,
                usuario_id,
                credencial_id,
                tipo.como_db(),
                descricao.as_deref(),
                principal,
            )
            .context("Falha ao adicionar método de autenticação")?;
            println!(
                "✅ Método {} adicionado à credencial #{credencial_id} com ID {id}.",
                tipo.como_db()
            );
        }

        MetodoCommands::List { credencial_id } => {
            let metodos = autenticacao_service::listar_metodos(&db, usuario_id, credencial_id)
                .context("Falha ao listar métodos de autenticação")?;
            if metodos.is_empty() {
                println!(
                    "Nenhum método de autenticação cadastrado para a credencial #{credencial_id}."
                );
                return Ok(());
            }
            println!("{}", tabela_metodos(&metodos));
            println!("\nTotal: {} método(s)", metodos.len());
        }

        MetodoCommands::Edit {
            id,
            tipo,
            descricao,
            principal,
            habilitado,
        } => {
            let descricao = descricao.map(vazio_para_none);
            let edicao = EdicaoMetodo {
                tipo: tipo.map(|t| t.como_db()),
                descricao: descricao.as_ref().map(|d| d.as_deref()),
                principal,
                habilitado,
            };
            autenticacao_service::editar_metodo(&db, usuario_id, id, &edicao)
                .context("Falha ao editar método de autenticação")?;
            println!("✅ Método #{id} atualizado.");
        }

        MetodoCommands::Delete { id, sim } => {
            let metodo = autenticacao_service::buscar_metodo(&db, usuario_id, id)
                .context("Método de autenticação não encontrado")?;
            let mensagem = format!(
                "Excluir o método {} da credencial #{}?",
                metodo.tipo, metodo.credencial_id
            );
            if !confirmar(&mensagem, sim)? {
                println!("Operação cancelada.");
                return Ok(());
            }
            autenticacao_service::excluir_metodo(&db, usuario_id, id)
                .context("Falha ao excluir método de autenticação")?;
            println!("🗑️  Método #{id} excluído.");
        }
    }
    Ok(())
}
