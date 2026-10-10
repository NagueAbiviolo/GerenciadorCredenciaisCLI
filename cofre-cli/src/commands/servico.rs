//! Comandos de gerenciamento de serviços.

use std::path::Path;
use anyhow::{Context, Result};
use comfy_table::{Table, ContentArrangement};

use cofre_db::Database;
use cofre_db::models::NovoServico;

use super::{confirmar, vazio_para_none, ServicoCommands};

pub fn execute(db_path: &Path, cmd: ServicoCommands) -> Result<()> {
    let db = Database::open(db_path)
        .context("Falha ao abrir o banco de dados")?;

    match cmd {
        ServicoCommands::Add { nome, dominio, categoria_id, url, descricao } => {
            let novo = NovoServico {
                categoria_id,
                nome: nome.clone(),
                dominio_principal: dominio,
                url_principal: url,
                descricao,
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
        ServicoCommands::Edit { id, nome, dominio, categoria_id, sem_categoria, url, descricao } => {
            if nome.is_none()
                && dominio.is_none()
                && categoria_id.is_none()
                && !sem_categoria
                && url.is_none()
                && descricao.is_none()
            {
                anyhow::bail!("Nada para alterar. Use --help para ver os campos editáveis.");
            }
            let atual = db.buscar_servico(id)
                .context("Serviço não encontrado")?;

            let dados = NovoServico {
                categoria_id: if sem_categoria { None } else { categoria_id.or(atual.categoria_id) },
                nome: nome.unwrap_or(atual.nome),
                dominio_principal: dominio.unwrap_or(atual.dominio_principal),
                url_principal: match url {
                    Some(u) => vazio_para_none(u),
                    None => atual.url_principal,
                },
                descricao: match descricao {
                    Some(d) => vazio_para_none(d),
                    None => atual.descricao,
                },
            };
            db.atualizar_servico(id, &dados)
                .context("Falha ao atualizar serviço")?;
            println!("✅ Serviço #{id} atualizado.");
        }
        ServicoCommands::Delete { id, sim } => {
            let servico = db.buscar_servico(id)
                .context("Serviço não encontrado")?;

            let credenciais = db.contar_credenciais_servico(id)?;
            if credenciais > 0 {
                anyhow::bail!(
                    "O serviço '{}' possui {credenciais} credencial(is) vinculada(s). \
                     Exclua-as antes de excluir o serviço.",
                    servico.nome
                );
            }

            if !confirmar(&format!("Excluir o serviço '{}'?", servico.nome), sim)? {
                println!("Operação cancelada.");
                return Ok(());
            }

            db.excluir_servico(id)
                .context("Falha ao excluir serviço")?;
            println!("🗑️  Serviço '{}' excluído.", servico.nome);
        }
    }

    Ok(())
}
