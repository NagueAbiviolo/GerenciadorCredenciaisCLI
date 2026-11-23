//! Comandos dos e-mails de recuperação (`cofre credencial email ...`).
//!
//! O endereço é sempre pedido em prompt (nunca como argumento), para não ficar
//! no histórico do shell, e é exibido mascarado salvo com `--revelar`.

use std::path::Path;

use anyhow::{Context, Result};
use comfy_table::{ContentArrangement, Table};
use inquire::Text;
use zeroize::Zeroizing;

use cofre_crypto::keys::UnlockedVault;
use cofre_db::models::EmailRecuperacao;
use cofre_services::autenticacao_service::{self, EdicaoEmail};

use super::unlock;
use super::{confirmar, EmailCommands};

fn pedir_email(mensagem: &str) -> Result<Zeroizing<String>> {
    Text::new(mensagem)
        .with_help_message("Armazenado cifrado no cofre.")
        .prompt()
        .map(Zeroizing::new)
        .context("Falha ao ler o e-mail")
}

/// Mascara um e-mail: "fulano@exemplo.com" → "f*****@exemplo.com".
pub fn mascarar_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, dominio)) => {
            let mut chars = local.chars();
            let primeiro = chars.next().map(String::from).unwrap_or_default();
            format!("{primeiro}{}@{dominio}", "*".repeat(chars.count().max(1)))
        }
        None => "***".into(),
    }
}

/// Tabela de e-mails, também usada em `credencial show`.
pub fn tabela_emails(
    vault: &UnlockedVault,
    usuario_id: i64,
    emails: &[EmailRecuperacao],
    revelar: bool,
) -> Result<Table> {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "ID",
        "E-mail",
        "Principal",
        "Verificado",
        "Ativo",
        "Criado em",
    ]);
    for e in emails {
        let texto = Zeroizing::new(
            autenticacao_service::revelar_email(vault, usuario_id, e)
                .with_context(|| format!("Falha ao descriptografar o e-mail #{}", e.id))?,
        );
        let texto = String::from_utf8_lossy(&texto);
        let exibido = if revelar {
            texto.to_string()
        } else {
            mascarar_email(&texto)
        };
        table.add_row(vec![
            e.id.to_string(),
            exibido,
            if e.principal { "✔" } else { "" }.into(),
            match (e.verificado, e.verificado_em) {
                (true, Some(d)) => format!("Sim ({})", d.format("%d/%m/%Y")),
                (true, None) => "Sim".into(),
                (false, _) => "Não".into(),
            },
            if e.ativo { "Sim" } else { "Não" }.into(),
            e.criado_em.format("%d/%m/%Y %H:%M").to_string(),
        ]);
    }
    Ok(table)
}

pub fn execute(db_path: &Path, cmd: EmailCommands) -> Result<()> {
    if let EmailCommands::Edit {
        email: false,
        principal: None,
        verificado: None,
        ativo: None,
        ..
    } = cmd
    {
        anyhow::bail!("Nada para alterar. Use --help para ver os campos editáveis.");
    }

    let (db, vault, usuario_id) = unlock::unlock(db_path)?;

    match cmd {
        EmailCommands::Add {
            credencial_id,
            principal,
            verificado,
        } => {
            // Valida a credencial antes de pedir o e-mail.
            cofre_services::vault_service::buscar_credencial(&db, credencial_id, usuario_id)
                .context("Credencial não encontrada")?;
            let email = pedir_email("E-mail de recuperação:")?;
            let id = autenticacao_service::adicionar_email(
                &db,
                &vault,
                usuario_id,
                credencial_id,
                &email,
                principal,
                verificado,
            )
            .context("Falha ao adicionar e-mail de recuperação")?;
            println!(
                "✅ E-mail de recuperação adicionado à credencial #{credencial_id} com ID {id}."
            );
        }

        EmailCommands::List {
            credencial_id,
            revelar,
        } => {
            let emails = autenticacao_service::listar_emails(&db, usuario_id, credencial_id)
                .context("Falha ao listar e-mails de recuperação")?;
            if emails.is_empty() {
                println!(
                    "Nenhum e-mail de recuperação cadastrado para a credencial #{credencial_id}."
                );
                return Ok(());
            }
            println!("{}", tabela_emails(&vault, usuario_id, &emails, revelar)?);
            println!("\nTotal: {} e-mail(s)", emails.len());
        }

        EmailCommands::Edit {
            id,
            email,
            principal,
            verificado,
            ativo,
        } => {
            autenticacao_service::buscar_email(&db, usuario_id, id)
                .context("E-mail de recuperação não encontrado")?;
            let novo = if email {
                Some(pedir_email("Novo e-mail de recuperação:")?)
            } else {
                None
            };
            let edicao = EdicaoEmail {
                email: novo.as_deref().map(String::as_str),
                principal,
                verificado,
                ativo,
            };
            autenticacao_service::editar_email(&db, &vault, usuario_id, id, &edicao)
                .context("Falha ao editar e-mail de recuperação")?;
            println!("✅ E-mail de recuperação #{id} atualizado.");
        }

        EmailCommands::Delete { id, sim } => {
            let registro = autenticacao_service::buscar_email(&db, usuario_id, id)
                .context("E-mail de recuperação não encontrado")?;
            let texto = Zeroizing::new(
                autenticacao_service::revelar_email(&vault, usuario_id, &registro)
                    .context("Falha ao descriptografar o e-mail")?,
            );
            let mensagem = format!(
                "Excluir o e-mail de recuperação {} da credencial #{}?",
                mascarar_email(&String::from_utf8_lossy(&texto)),
                registro.credencial_id
            );
            if !confirmar(&mensagem, sim)? {
                println!("Operação cancelada.");
                return Ok(());
            }
            autenticacao_service::excluir_email(&db, usuario_id, id)
                .context("Falha ao excluir e-mail de recuperação")?;
            println!("🗑️  E-mail de recuperação #{id} excluído.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::mascarar_email;

    #[test]
    fn test_mascarar_email() {
        assert_eq!(mascarar_email("fulano@exemplo.com"), "f*****@exemplo.com");
        assert_eq!(mascarar_email("a@x.com"), "a*@x.com");
        assert_eq!(mascarar_email("invalido"), "***");
    }
}
