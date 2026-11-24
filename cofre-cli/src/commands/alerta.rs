//! Comandos de gerenciamento de alertas de segurança (`cofre alerta ...`).

use anyhow::{Context, Result};
use comfy_table::{ContentArrangement, Table};

use cofre_db::models::{AlertaSeguranca, FiltroAlerta};
use cofre_db::Database;
use cofre_services::alerta_service;

use super::sessao::Contexto;
use super::{confirmar, AlertaCommands};

fn formatar_nivel(nivel: &str) -> String {
    match nivel {
        "CRITICO" => "🔴 CRITICO".into(),
        "ALTO" => "🟠 ALTO".into(),
        "MEDIO" => "🟡 MEDIO".into(),
        "BAIXO" => "⚪ BAIXO".into(),
        outro => outro.to_string(),
    }
}

fn formatar_credencial(db: &Database, usuario_id: i64, credencial_id: Option<i64>) -> String {
    match credencial_id {
        Some(id) => match cofre_services::vault_service::buscar_credencial(db, id, usuario_id) {
            Ok(cred) => format!("#{id} {}", cred.nome_exibicao),
            Err(_) => format!("#{id}"),
        },
        None => "-".into(),
    }
}

fn formatar_status(alerta: &AlertaSeguranca) -> String {
    if alerta.resolvido {
        match alerta.resolvido_em {
            Some(dt) => format!("Resolvido ({})", dt.format("%d/%m/%Y %H:%M")),
            None => "Resolvido".into(),
        }
    } else {
        "Aberto".into()
    }
}

pub fn execute(ctx: &Contexto, cmd: AlertaCommands) -> Result<()> {
    match cmd {
        AlertaCommands::Scan => ctx.com_sessao(|s| {
            let resumo = alerta_service::verificar(&s.db, &s.vault, s.usuario_id)
                .context("Falha ao verificar alertas de segurança")?;

            println!("🔍 Verificação de alertas de segurança concluída:");
            println!("   • Novos alertas:                {}", resumo.novos);
            println!("   • Alertas mantidos:             {}", resumo.mantidos);
            println!(
                "   • Resolvidos automaticamente:   {}",
                resumo.resolvidos_automaticamente
            );
            println!(
                "   • Total de alertas abertos:     {}",
                resumo.total_abertos
            );
            if resumo.total_abertos > 0 {
                println!("\nUse 'cofre alerta list' para consultar os alertas em aberto.");
            }
            Ok(())
        }),

        AlertaCommands::List { todos, tipo, nivel } => {
            let tipo_upper = tipo.map(|t| t.trim().to_ascii_uppercase());
            let nivel_upper = nivel.map(|n| n.trim().to_ascii_uppercase());

            ctx.com_sessao(|s| {
                let filtro = FiltroAlerta {
                    apenas_abertos: !todos,
                    tipo: tipo_upper.as_deref(),
                    nivel: nivel_upper.as_deref(),
                };

                let alertas = alerta_service::listar(&s.db, s.usuario_id, &filtro)
                    .context("Falha ao listar alertas de segurança")?;

                if alertas.is_empty() {
                    if todos {
                        println!("Nenhum alerta de segurança encontrado.");
                    } else {
                        println!("Nenhum alerta de segurança aberto encontrado.");
                    }
                    return Ok(());
                }

                let mut table = Table::new();
                table.set_content_arrangement(ContentArrangement::Dynamic);
                table.set_header(vec![
                    "ID",
                    "Nível",
                    "Tipo",
                    "Credencial",
                    "Título",
                    "Criado",
                    "Status",
                ]);

                for a in &alertas {
                    table.add_row(vec![
                        a.id.to_string(),
                        formatar_nivel(&a.nivel),
                        a.tipo.clone(),
                        formatar_credencial(&s.db, s.usuario_id, a.credencial_id),
                        format!("{}\n{}", a.titulo, a.mensagem),
                        a.criado_em.format("%d/%m/%Y %H:%M").to_string(),
                        formatar_status(a),
                    ]);
                }

                println!("{table}");
                println!(
                    "\nTotal: {} alerta(s){}",
                    alertas.len(),
                    if todos { "" } else { " aberto(s)" }
                );
                Ok(())
            })
        }

        AlertaCommands::Resolve { id } => ctx.com_sessao(|s| {
            let alerta = alerta_service::resolver(&s.db, s.usuario_id, id)
                .with_context(|| format!("Falha ao resolver o alerta #{id}"))?;
            println!("✅ Alerta #{id} ({}) marcado como resolvido.", alerta.tipo);
            Ok(())
        }),

        AlertaCommands::Delete { id, sim } => ctx.com_sessao(|s| {
            let alerta =
                s.db.buscar_alerta(id, s.usuario_id)
                    .with_context(|| format!("Alerta #{id} não encontrado"))?;

            let mensagem = format!(
                "Excluir o alerta #{id} ({} — '{}')?",
                alerta.tipo, alerta.titulo
            );
            if !confirmar(&mensagem, sim)? {
                println!("Operação cancelada.");
                return Ok(());
            }

            alerta_service::excluir(&s.db, s.usuario_id, id)
                .with_context(|| format!("Falha ao excluir o alerta #{id}"))?;
            println!("🗑️  Alerta #{id} excluído.");
            Ok(())
        }),
    }
}
