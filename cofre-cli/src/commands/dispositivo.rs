//! Comandos de gerenciamento de dispositivos (`cofre dispositivo ...`).

use std::path::Path;

use anyhow::{Context, Result};
use comfy_table::{ContentArrangement, Table};

use super::unlock;
use super::DispositivoCommands;

fn abreviar_fingerprint(fp: Option<&str>) -> String {
    match fp {
        Some(h) if h.len() > 16 => format!("{}…", &h[..16]),
        Some(h) => h.to_string(),
        None => "-".into(),
    }
}

pub fn execute(db_path: &Path, cmd: DispositivoCommands) -> Result<()> {
    let (db, _vault, usuario_id) = unlock::unlock(db_path)?;

    match cmd {
        DispositivoCommands::List => {
            let dispositivos = db
                .listar_dispositivos(usuario_id)
                .context("Falha ao listar dispositivos")?;

            if dispositivos.is_empty() {
                println!("Nenhum dispositivo encontrado.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec![
                "ID",
                "Nome",
                "Sistema Operacional",
                "Fingerprint",
                "Confiável",
                "Primeiro acesso",
                "Último acesso",
                "Ativo",
            ]);

            for d in &dispositivos {
                table.add_row(vec![
                    d.id.to_string(),
                    d.nome.clone(),
                    d.sistema_operacional.clone().unwrap_or_else(|| "-".into()),
                    abreviar_fingerprint(d.fingerprint_hash.as_deref()),
                    if d.confiavel { "Sim" } else { "Não" }.into(),
                    d.primeiro_acesso_em.format("%d/%m/%Y %H:%M").to_string(),
                    d.ultimo_acesso_em
                        .map(|dt| dt.format("%d/%m/%Y %H:%M").to_string())
                        .unwrap_or_else(|| "-".into()),
                    if d.ativo { "Sim" } else { "Não" }.into(),
                ]);
            }

            println!("{table}");
            println!("\nTotal: {} dispositivo(s)", dispositivos.len());
        }
    }

    Ok(())
}
