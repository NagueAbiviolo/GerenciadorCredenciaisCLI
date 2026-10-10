//! Comandos de gerenciamento de credenciais.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arboard::Clipboard;
use comfy_table::{Table, ContentArrangement};
use inquire::Text;
use zeroize::Zeroizing;

use cofre_db::Database;
use cofre_db::models::Credencial;
use cofre_services::vault_service::{self, EdicaoCredencial};

use super::unlock::{self, pedir_senha_nova};
use super::{confirmar, CredencialCommands};

fn nome_servico(db: &Database, servico_id: i64) -> String {
    db.buscar_servico(servico_id)
        .map(|s| s.nome)
        .unwrap_or_else(|_| "?".into())
}

fn pedir_observacao() -> Result<Zeroizing<String>> {
    Text::new("Observação:")
        .with_help_message("Armazenada cifrada no cofre.")
        .prompt()
        .map(Zeroizing::new)
        .context("Falha ao ler a observação")
}

fn imprimir_tabela(db: &Database, credenciais: &[Credencial]) {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["ID", "Nome", "Identificador", "Serviço", "⭐", "Último uso"]);

    for c in credenciais {
        table.add_row(vec![
            c.id.to_string(),
            c.nome_exibicao.clone(),
            c.identificador.clone(),
            nome_servico(db, c.servico_id),
            if c.favorita { "⭐" } else { "" }.into(),
            c.ultimo_uso_em
                .map(|d| d.format("%d/%m/%Y %H:%M").to_string())
                .unwrap_or("-".into()),
        ]);
    }

    println!("{table}");
}

/// Coloca o texto na área de transferência sem ir para o histórico/nuvem do Windows.
fn definir_clipboard(cb: &mut Clipboard, texto: &str) -> Result<()> {
    #[cfg(windows)]
    {
        use arboard::SetExtWindows;
        cb.set()
            .exclude_from_history()
            .exclude_from_cloud()
            .text(texto)
            .context("Falha ao copiar para a área de transferência")
    }
    #[cfg(not(windows))]
    {
        cb.set_text(texto)
            .context("Falha ao copiar para a área de transferência")
    }
}

/// Copia o texto, aguarda `segundos` (ou Ctrl+C) e limpa a área de transferência,
/// desde que ela ainda contenha o texto copiado.
fn copiar_temporariamente(texto: &str, segundos: u64) -> Result<()> {
    let mut cb = Clipboard::new().context("Falha ao acessar a área de transferência")?;

    // Com o handler, Ctrl+C antecipa a limpeza em vez de encerrar o processo
    // deixando a senha na área de transferência.
    let interrompido = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&interrompido);
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
        .context("Falha ao registrar o tratamento de Ctrl+C")?;

    definir_clipboard(&mut cb, texto)?;
    println!("📋 Senha copiada para a área de transferência.");

    let fim = Instant::now() + Duration::from_secs(segundos);
    while !interrompido.load(Ordering::SeqCst) {
        let agora = Instant::now();
        if agora >= fim {
            break;
        }
        let restante = (fim - agora).as_millis().div_ceil(1000);
        print!("\r⏳ Limpando em {restante:>3}s (Ctrl+C limpa agora) ");
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_millis(100));
    }
    println!();

    let atual = cb.get_text().ok().map(Zeroizing::new);
    if atual.as_deref().map(String::as_str) == Some(texto) {
        cb.clear().context("Falha ao limpar a área de transferência")?;
        println!("🧹 Área de transferência limpa.");
    } else {
        println!("ℹ️  O conteúdo da área de transferência mudou; nada foi apagado.");
    }
    Ok(())
}

pub fn execute(db_path: &Path, cmd: CredencialCommands) -> Result<()> {
    match cmd {
        CredencialCommands::Add { servico_id, nome, identificador, observacao } => {
            let (db, vault, usuario_id) = unlock::unlock(db_path)?;

            // Valida o serviço antes de pedir a senha da credencial.
            db.buscar_servico(servico_id)
                .with_context(|| format!("Serviço #{servico_id} não encontrado"))?;

            let senha = pedir_senha_nova("Senha da credencial:", None)?;
            let obs = if observacao { Some(pedir_observacao()?) } else { None };

            let id = vault_service::adicionar_credencial(
                &db,
                &vault,
                usuario_id,
                servico_id,
                &nome,
                &identificador,
                senha.as_bytes(),
                obs.as_deref().map(String::as_str),
            )
            .context("Falha ao adicionar credencial")?;

            println!("✅ Credencial '{nome}' adicionada com ID {id}.");
        }

        CredencialCommands::List { inativas } => {
            let (db, _vault, usuario_id) = unlock::unlock(db_path)?;

            let credenciais = db.listar_credenciais(usuario_id, !inativas)
                .context("Falha ao listar credenciais")?;

            if credenciais.is_empty() {
                println!("Nenhuma credencial {}encontrada.", if inativas { "inativa " } else { "" });
                return Ok(());
            }

            imprimir_tabela(&db, &credenciais);
            println!(
                "\nTotal: {} credencial(is){}",
                credenciais.len(),
                if inativas { " inativa(s)" } else { "" }
            );
        }

        CredencialCommands::Show { id, revelar } => {
            let (db, vault, usuario_id) = unlock::unlock(db_path)?;

            let cred = vault_service::buscar_credencial(&db, id, usuario_id)
                .context("Credencial não encontrada")?;

            println!("┌─────────────────────────────────────────");
            println!("│ 📋 Credencial #{}", cred.id);
            println!("├─────────────────────────────────────────");
            println!("│ Nome:          {}", cred.nome_exibicao);
            println!("│ Identificador: {}", cred.identificador);
            println!("│ Serviço:       {}", nome_servico(&db, cred.servico_id));
            println!("│ Favorita:      {}", if cred.favorita { "⭐ Sim" } else { "Não" });
            println!("│ Ativa:         {}", if cred.ativa { "Sim" } else { "Não" });
            println!("│ Criada em:     {}", cred.criada_em.format("%d/%m/%Y %H:%M"));
            println!("│ Última alt.:   {}", cred.alterada_em.format("%d/%m/%Y %H:%M"));
            println!("│ Último uso:    {}", cred.ultimo_uso_em
                .map(|d| d.format("%d/%m/%Y %H:%M").to_string())
                .unwrap_or("-".into()));

            let tem_observacao = cred.observacao_criptografada.is_some();
            if revelar {
                let senha = Zeroizing::new(
                    vault_service::revelar_senha(&db, &vault, id, usuario_id)
                        .context("Falha ao descriptografar a senha")?,
                );
                println!("│ 🔑 Senha:      {}", String::from_utf8_lossy(&senha));

                if let Some(obs) = vault_service::revelar_observacao(&vault, &cred)
                    .context("Falha ao descriptografar a observação")?
                {
                    let obs = Zeroizing::new(obs);
                    println!("│ 📝 Observação: {}", String::from_utf8_lossy(&obs));
                }
            } else {
                println!("│ 🔒 Senha:      ******** (use --revelar para exibir)");
                if tem_observacao {
                    println!("│ 📝 Observação: (oculta, use --revelar)");
                }
            }

            println!("└─────────────────────────────────────────");
        }

        CredencialCommands::Search { termo } => {
            let (db, _vault, usuario_id) = unlock::unlock(db_path)?;

            let credenciais = db.pesquisar_credenciais(usuario_id, &termo)
                .context("Falha ao pesquisar credenciais")?;

            if credenciais.is_empty() {
                println!("Nenhuma credencial encontrada para '{termo}'.");
                return Ok(());
            }

            imprimir_tabela(&db, &credenciais);
            println!("\n{} resultado(s) para '{termo}'", credenciais.len());
        }

        CredencialCommands::Copy { id, segundos } => {
            let (db, vault, usuario_id) = unlock::unlock(db_path)?;

            let senha = Zeroizing::new(
                vault_service::revelar_senha(&db, &vault, id, usuario_id)
                    .context("Falha ao descriptografar a senha")?,
            );
            let texto = std::str::from_utf8(&senha)
                .map_err(|_| anyhow::anyhow!("A senha armazenada não é um texto UTF-8 válido"))?;

            copiar_temporariamente(texto, segundos)?;
        }

        CredencialCommands::Edit {
            id,
            nome,
            identificador,
            favorita,
            senha,
            observacao,
            remover_observacao,
        } => {
            if nome.is_none()
                && identificador.is_none()
                && favorita.is_none()
                && !senha
                && !observacao
                && !remover_observacao
            {
                anyhow::bail!("Nada para alterar. Use --help para ver os campos editáveis.");
            }

            let (db, vault, usuario_id) = unlock::unlock(db_path)?;
            let cred = vault_service::buscar_credencial(&db, id, usuario_id)
                .context("Credencial não encontrada")?;
            println!("✏️  Editando '{}' (#{id})", cred.nome_exibicao);

            let nova_senha = if senha {
                Some(pedir_senha_nova("Nova senha da credencial:", None)?)
            } else {
                None
            };
            let nova_obs = if observacao { Some(pedir_observacao()?) } else { None };

            let edicao = EdicaoCredencial {
                nome_exibicao: nome.as_deref(),
                identificador: identificador.as_deref(),
                favorita,
                senha: nova_senha.as_ref().map(|s| s.as_bytes()),
                observacao: if remover_observacao {
                    Some(None)
                } else {
                    nova_obs.as_ref().map(|o| Some(o.as_str()))
                },
            };

            vault_service::editar_credencial(&db, &vault, usuario_id, id, &edicao)
                .context("Falha ao editar credencial")?;
            println!("✅ Credencial #{id} atualizada.");
        }

        CredencialCommands::Deactivate { id } => {
            let (db, _vault, usuario_id) = unlock::unlock(db_path)?;
            vault_service::definir_credencial_ativa(&db, usuario_id, id, false)
                .context("Falha ao desativar credencial")?;
            println!("⏸️  Credencial #{id} desativada. Use 'credencial activate {id}' para reativar.");
        }

        CredencialCommands::Activate { id } => {
            let (db, _vault, usuario_id) = unlock::unlock(db_path)?;
            vault_service::definir_credencial_ativa(&db, usuario_id, id, true)
                .context("Falha ao reativar credencial")?;
            println!("▶️  Credencial #{id} reativada.");
        }

        CredencialCommands::Delete { id, sim } => {
            let (db, _vault, usuario_id) = unlock::unlock(db_path)?;
            let cred = vault_service::buscar_credencial(&db, id, usuario_id)
                .context("Credencial não encontrada")?;

            let mensagem = format!(
                "Excluir DEFINITIVAMENTE a credencial '{}' ({})? Esta ação não pode ser desfeita.",
                cred.nome_exibicao, cred.identificador
            );
            if !confirmar(&mensagem, sim)? {
                println!("Operação cancelada.");
                return Ok(());
            }

            vault_service::excluir_credencial(&db, usuario_id, id)
                .context("Falha ao excluir credencial")?;
            println!("🗑️  Credencial '{}' excluída.", cred.nome_exibicao);
        }
    }

    Ok(())
}
