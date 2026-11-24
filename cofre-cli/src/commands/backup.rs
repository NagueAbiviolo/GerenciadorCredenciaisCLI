//! Comandos de gerenciamento de backups cifrados (`cofre backup ...`, RF14 / RNF10).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use comfy_table::{ContentArrangement, Table};
use zeroize::Zeroizing;

use cofre_services::backup_service::{self, OrigemRestauracao};

use super::sessao::Contexto;
use super::{confirmar, unlock, BackupCommands};

/// Determina o diretório padrão de backups (`<dir do db>/backups/`).
pub fn diretorio_backups_padrao(db_path: &Path) -> Result<PathBuf> {
    let dir_base = match db_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::env::current_dir().context("Falha ao obter o diretório atual")?,
    };
    Ok(dir_base.join("backups"))
}

/// Formata um tamanho em bytes para exibição legível (B, KiB, MiB, GiB).
pub fn formatar_tamanho(bytes: i64) -> String {
    let b = bytes.max(0) as f64;
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    if b < KIB {
        format!("{} B", bytes.max(0))
    } else if b < MIB {
        format!("{:.1} KiB", b / KIB)
    } else if b < GIB {
        format!("{:.1} MiB", b / MIB)
    } else {
        format!("{:.2} GiB", b / GIB)
    }
}

pub fn execute(ctx: &Contexto, cmd: BackupCommands) -> Result<()> {
    match cmd {
        BackupCommands::Create { destino } => {
            let dir_destino = match destino {
                Some(d) => d,
                None => diretorio_backups_padrao(ctx.db_path())?,
            };

            ctx.com_sessao(|s| {
                let bkp = backup_service::criar(&s.db, &s.vault, s.usuario_id, &dir_destino)
                    .context("Falha ao criar o backup cifrado")?;

                println!("✅ Backup cifrado criado com sucesso!");
                println!("   ID:       #{}", bkp.id);
                println!("   Arquivo:  {}", bkp.nome_arquivo);
                println!("   Caminho:  {}", bkp.caminho_arquivo);
                println!("   Tamanho:  {}", formatar_tamanho(bkp.tamanho_bytes));
                println!("   BLAKE3:   {}", bkp.hash_integridade);
                Ok(())
            })
        }

        BackupCommands::List => ctx.com_sessao(|s| {
            let backups = backup_service::listar(&s.db, s.usuario_id)
                .context("Falha ao listar os backups")?;

            if backups.is_empty() {
                println!("Nenhum backup registrado.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec![
                "ID",
                "Data",
                "Nome",
                "Tamanho",
                "Válido",
                "Última restauração",
                "Arquivo existe?",
            ]);

            for b in &backups {
                let existe = Path::new(&b.caminho_arquivo).exists();
                table.add_row(vec![
                    b.id.to_string(),
                    b.criado_em.format("%d/%m/%Y %H:%M:%S").to_string(),
                    b.nome_arquivo.clone(),
                    formatar_tamanho(b.tamanho_bytes),
                    if b.valido { "Sim" } else { "Não" }.into(),
                    b.ultima_restauracao_em
                        .map(|dt| dt.format("%d/%m/%Y %H:%M:%S").to_string())
                        .unwrap_or_else(|| "-".into()),
                    if existe { "Sim" } else { "Não" }.into(),
                ]);
            }

            println!("{table}");
            println!("\nTotal: {} backup(s)", backups.len());
            Ok(())
        }),

        BackupCommands::Verify { id } => ctx.com_sessao(|s| {
            let res = backup_service::verificar(&s.db, &s.vault, s.usuario_id, id)
                .with_context(|| format!("Falha ao verificar o backup #{id}"))?;

            if res.valido {
                println!(
                    "✅ Backup #{} ('{}') é VÁLIDO.",
                    res.backup.id, res.backup.nome_arquivo
                );
                println!("   Caminho:  {}", res.backup.caminho_arquivo);
                println!("   BLAKE3:   {}", res.backup.hash_integridade);
                println!("   Detalhe:  {}", res.detalhe);
                Ok(())
            } else {
                println!(
                    "❌ Backup #{} ('{}') é INVÁLIDO.",
                    res.backup.id, res.backup.nome_arquivo
                );
                println!("   Caminho:  {}", res.backup.caminho_arquivo);
                println!("   Motivo:   {}", res.detalhe);
                anyhow::bail!("Verificação de integridade/autenticidade do backup #{id} falhou");
            }
        }),

        BackupCommands::Restore { id, arquivo, sim } => {
            let descricao_alvo = match (id, arquivo.as_deref()) {
                (Some(bkp_id), None) => {
                    if !ctx.db_path().exists() {
                        anyhow::bail!(
                            "Cofre não encontrado em '{}'. Use 'cofre backup restore --arquivo <CAMINHO>' para restaurar a partir de um arquivo.",
                            ctx.db_path().display()
                        );
                    }
                    let bkp = ctx.com_banco(|db| {
                        let usuario = db
                            .buscar_usuario_ativo()
                            .context("Cofre não inicializado")?;
                        db.buscar_backup(bkp_id, usuario.id)
                            .with_context(|| format!("Backup #{bkp_id} não encontrado"))
                    })?;
                    format!("#{} ('{}')", bkp.id, bkp.nome_arquivo)
                }
                (None, Some(caminho)) => {
                    if !caminho.exists() {
                        anyhow::bail!("Arquivo de backup não encontrado: '{}'", caminho.display());
                    }
                    format!("'{}'", caminho.display())
                }
                _ => anyhow::bail!("Informe exatamente um entre <ID> ou --arquivo <CAMINHO>."),
            };

            let msg_confirmacao = if ctx.db_path().exists() {
                format!(
                    "Restaurar o backup {descricao_alvo}? O cofre atual ('{}') será substituído e uma cópia de segurança será mantida como '{}.antes-restauracao-AAAAMMDD-HHMMSS'.",
                    ctx.db_path().display(),
                    ctx.db_path().display()
                )
            } else {
                format!(
                    "Restaurar o backup {descricao_alvo} criando o cofre em '{}'?",
                    ctx.db_path().display()
                )
            };

            if !confirmar(&msg_confirmacao, sim)? {
                println!("Operação cancelada.");
                return Ok(());
            }

            // Descarta a sessão ativa e fecha toda conexão com o cofre.db ANTES da troca do arquivo.
            let vault_sessao = ctx.encerrar_sessao_para_restauracao(Some(
                "Cofre bloqueado antes da restauração de backup",
            ));

            let origem = match (id, arquivo.as_deref()) {
                (Some(bkp_id), None) => OrigemRestauracao::Id(bkp_id),
                (None, Some(caminho)) => OrigemRestauracao::Arquivo(caminho),
                _ => unreachable!(),
            };

            let resultado =
                backup_service::restaurar(ctx.db_path(), origem, vault_sessao.as_ref(), || {
                    unlock::pedir_senha("Senha mestre do backup:")
                        .map(|s| Zeroizing::new(s.as_bytes().to_vec()))
                        .map_err(|e| e.to_string())
                });

            // Garante descarte do vault anterior e estado bloqueado no contexto.
            drop(vault_sessao);
            ctx.bloquear(None);

            let res = resultado.context("Falha ao restaurar o backup")?;

            println!("✅ Backup restaurado com sucesso!");
            println!("   Origem:   {}", res.caminho_backup.display());
            println!("   Cofre:    {}", ctx.db_path().display());
            if let Some(copia) = res.copia_anterior {
                println!("   Anterior: {}", copia.display());
            }
            println!("ℹ️  A senha mestre agora é a que valia quando o backup foi criado.");
            Ok(())
        }

        BackupCommands::Delete {
            id,
            manter_arquivo,
            sim,
        } => ctx.com_sessao(|s| {
            let bkp =
                s.db.buscar_backup(id, s.usuario_id)
                    .with_context(|| format!("Backup #{id} não encontrado"))?;

            let msg = if manter_arquivo {
                format!(
                    "Remover o registro do backup #{} ('{}') mantendo o arquivo no disco?",
                    bkp.id, bkp.nome_arquivo
                )
            } else {
                format!(
                    "Excluir o backup #{} ('{}') e apagar o arquivo '{}' do disco?",
                    bkp.id, bkp.nome_arquivo, bkp.caminho_arquivo
                )
            };

            if !confirmar(&msg, sim)? {
                println!("Operação cancelada.");
                return Ok(());
            }

            backup_service::excluir(&s.db, s.usuario_id, id, manter_arquivo)
                .with_context(|| format!("Falha ao excluir o backup #{id}"))?;

            if manter_arquivo {
                println!(
                    "🗑️  Registro do backup #{} ('{}') removido (arquivo mantido em '{}').",
                    bkp.id, bkp.nome_arquivo, bkp.caminho_arquivo
                );
            } else {
                println!("🗑️  Backup #{} ('{}') excluído.", bkp.id, bkp.nome_arquivo);
            }
            Ok(())
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::Cli;
    use clap::Parser;

    #[test]
    fn test_formatar_tamanho() {
        assert_eq!(formatar_tamanho(0), "0 B");
        assert_eq!(formatar_tamanho(512), "512 B");
        assert_eq!(formatar_tamanho(2048), "2.0 KiB");
        assert_eq!(formatar_tamanho(1_572_864), "1.5 MiB");
    }

    #[test]
    fn test_clap_restore_exige_exatamente_id_ou_arquivo() {
        // Apenas ID: válido
        assert!(Cli::try_parse_from(["cofre", "backup", "restore", "1"]).is_ok());

        // Apenas --arquivo: válido
        assert!(
            Cli::try_parse_from(["cofre", "backup", "restore", "--arquivo", "/tmp/a.cbk"]).is_ok()
        );

        // Nenhum dos dois: inválido
        assert!(Cli::try_parse_from(["cofre", "backup", "restore"]).is_err());

        // Ambos ao mesmo tempo: inválido
        assert!(Cli::try_parse_from([
            "cofre",
            "backup",
            "restore",
            "1",
            "--arquivo",
            "/tmp/a.cbk"
        ])
        .is_err());
    }
}
