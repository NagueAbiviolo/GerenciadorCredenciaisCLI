//! Comandos de gerenciamento das URLs de um serviço (`cofre servico url ...`).

use anyhow::{Context, Result};
use comfy_table::{ContentArrangement, Table};

use cofre_db::Database;
use cofre_services::servico_service::{self, EdicaoUrl};

use super::{confirmar, vazio_para_none, UrlCommands};

pub fn execute(db: &Database, cmd: UrlCommands) -> Result<()> {
    match cmd {
        UrlCommands::Add { servico_id, url, tipo, descricao, padrao } => {
            let id = servico_service::adicionar_url(
                db,
                servico_id,
                &url,
                tipo.como_db(),
                descricao.as_deref(),
                padrao,
            )
            .context("Falha ao adicionar URL")?;
            let marcada = db.buscar_url_servico(id).map(|u| u.padrao).unwrap_or(false);
            println!(
                "✅ URL adicionada com ID {id}{}.",
                if marcada { " (padrão do serviço)" } else { "" }
            );
        }

        UrlCommands::List { servico_id } => {
            let urls = servico_service::listar_urls(db, servico_id)
                .with_context(|| format!("Falha ao listar as URLs do serviço #{servico_id}"))?;
            if urls.is_empty() {
                println!("Nenhuma URL cadastrada para o serviço #{servico_id}.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec!["ID", "Tipo", "URL", "Descrição", "Padrão", "Ativa"]);
            for u in &urls {
                table.add_row(vec![
                    u.id.to_string(),
                    u.tipo.clone(),
                    u.url.clone(),
                    u.descricao.clone().unwrap_or("-".into()),
                    if u.padrao { "✔" } else { "" }.into(),
                    if u.ativa { "Sim" } else { "Não" }.into(),
                ]);
            }
            println!("{table}");
            println!("\nTotal: {} URL(s)", urls.len());
        }

        UrlCommands::Edit { id, url, tipo, descricao, padrao, ativa } => {
            if url.is_none() && tipo.is_none() && descricao.is_none() && !padrao && ativa.is_none() {
                anyhow::bail!("Nada para alterar. Use --help para ver os campos editáveis.");
            }
            let descricao = descricao.map(vazio_para_none);
            let edicao = EdicaoUrl {
                url: url.as_deref(),
                tipo: tipo.map(|t| t.como_db()),
                descricao: descricao.as_ref().map(|d| d.as_deref()),
                ativa,
                padrao,
            };
            servico_service::editar_url(db, id, &edicao).context("Falha ao editar URL")?;
            println!("✅ URL #{id} atualizada.");
        }

        UrlCommands::Delete { id, sim } => {
            let url = db.buscar_url_servico(id).context("URL não encontrada")?;
            if !confirmar(&format!("Excluir a URL '{}'?", url.url), sim)? {
                println!("Operação cancelada.");
                return Ok(());
            }
            servico_service::excluir_url(db, id).context("Falha ao excluir URL")?;
            println!("🗑️  URL #{id} excluída.");
        }
    }
    Ok(())
}
