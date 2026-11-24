//! Comandos de consulta aos eventos de auditoria (`cofre auditoria ...`).

use anyhow::{Context, Result};
use chrono::NaiveDate;
use comfy_table::{ContentArrangement, Table};

use cofre_db::models::FiltroAuditoria;
use cofre_services::auditoria_service;

use super::sessao::Contexto;
use super::AuditoriaCommands;

pub fn execute(ctx: &Contexto, cmd: AuditoriaCommands) -> Result<()> {
    match cmd {
        AuditoriaCommands::List {
            tipo,
            credencial,
            desde,
            limite,
        } => {
            let data_desde = match desde.as_deref() {
                Some(texto) => Some(
                    NaiveDate::parse_from_str(texto.trim(), "%Y-%m-%d").with_context(|| {
                        format!("Data inválida '{texto}': use o formato AAAA-MM-DD")
                    })?,
                ),
                None => None,
            };

            let tipo_upper = tipo.map(|t| t.trim().to_ascii_uppercase());

            ctx.com_sessao(|s| {
                let filtro = FiltroAuditoria {
                    tipo_evento: tipo_upper.as_deref(),
                    credencial_id: credencial,
                    desde: data_desde,
                    limite: Some(limite as usize),
                };

                let eventos = auditoria_service::listar(&s.db, s.usuario_id, &filtro)
                    .context("Falha ao listar eventos de auditoria")?;

                if eventos.is_empty() {
                    println!("Nenhum evento de auditoria encontrado.");
                    return Ok(());
                }

                let mut table = Table::new();
                table.set_content_arrangement(ContentArrangement::Dynamic);
                table.set_header(vec![
                    "Data",
                    "Tipo",
                    "Resultado",
                    "Credencial",
                    "Dispositivo",
                    "Descrição",
                ]);

                for ev in &eventos {
                    table.add_row(vec![
                        ev.ocorrido_em.format("%d/%m/%Y %H:%M:%S").to_string(),
                        ev.tipo_evento.clone(),
                        ev.resultado.clone(),
                        ev.credencial_id
                            .map(|id| format!("#{id}"))
                            .unwrap_or_else(|| "-".into()),
                        ev.dispositivo_id
                            .map(|id| format!("#{id}"))
                            .unwrap_or_else(|| "-".into()),
                        ev.descricao.clone().unwrap_or_else(|| "-".into()),
                    ]);
                }

                println!("{table}");
                println!("\nTotal: {} evento(s)", eventos.len());
                Ok(())
            })
        }
    }
}
