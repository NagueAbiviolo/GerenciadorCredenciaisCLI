//! Métodos de autenticação e e-mails de recuperação vinculados a credenciais.
//!
//! Toda operação confere se a credencial pertence ao usuário. Os e-mails de
//! recuperação são cifrados com a DEK e AAD `email_recuperacao|email_criptografado|{id}|{usuario_id}`.

use cofre_crypto::aead;
use cofre_crypto::keys::UnlockedVault;
use cofre_db::connection::DbError;
use cofre_db::models::{EmailRecuperacao, MetodoAutenticacao, NovoMetodoAutenticacao};
use cofre_db::Database;

use crate::vault_service::{buscar_credencial, VaultServiceError};

/// Tipos aceitos pela coluna `metodo_autenticacao.tipo`.
pub const TIPOS_METODO: [&str; 7] = [
    "SENHA",
    "TOTP",
    "SMS",
    "EMAIL",
    "PASSKEY",
    "BIOMETRIA",
    "APLICATIVO",
];

/// Alterações possíveis em um método. Campos `None` não são alterados.
#[derive(Default)]
pub struct EdicaoMetodo<'a> {
    pub tipo: Option<&'a str>,
    /// `Some(None)` remove a descrição.
    pub descricao: Option<Option<&'a str>>,
    pub principal: Option<bool>,
    pub habilitado: Option<bool>,
}

/// Alterações possíveis em um e-mail de recuperação. Campos `None` não são alterados.
#[derive(Default)]
pub struct EdicaoEmail<'a> {
    pub email: Option<&'a str>,
    pub principal: Option<bool>,
    pub verificado: Option<bool>,
    pub ativo: Option<bool>,
}

fn validar_tipo_metodo(tipo: &str) -> Result<(), VaultServiceError> {
    if TIPOS_METODO.contains(&tipo) {
        Ok(())
    } else {
        Err(VaultServiceError::Invalido(format!(
            "tipo de método '{tipo}' (use um de: {})",
            TIPOS_METODO.join(", ")
        )))
    }
}

/// Validação simples de formato (não verifica se o endereço existe).
fn validar_email(email: &str) -> Result<(), VaultServiceError> {
    let valido = match email.split_once('@') {
        Some((local, dominio)) => {
            !local.is_empty()
                && dominio.contains('.')
                && !dominio.starts_with('.')
                && !dominio.ends_with('.')
                && !dominio.contains('@')
                && !email.chars().any(char::is_whitespace)
        }
        None => false,
    };
    if valido {
        Ok(())
    } else {
        Err(VaultServiceError::Invalido(
            "e-mail com formato inválido".into(),
        ))
    }
}

fn nao_encontrado() -> VaultServiceError {
    VaultServiceError::Db(DbError::NotFound)
}

// ------------------------------------------------------------------
// Métodos de autenticação
// ------------------------------------------------------------------

/// Busca um método garantindo que sua credencial pertence ao usuário.
pub fn buscar_metodo(
    db: &Database,
    usuario_id: i64,
    metodo_id: i64,
) -> Result<MetodoAutenticacao, VaultServiceError> {
    let metodo = db.buscar_metodo_autenticacao(metodo_id)?;
    buscar_credencial(db, metodo.credencial_id, usuario_id).map_err(|_| nao_encontrado())?;
    Ok(metodo)
}

/// Adiciona um método de autenticação à credencial.
pub fn adicionar_metodo(
    db: &Database,
    usuario_id: i64,
    credencial_id: i64,
    tipo: &str,
    descricao: Option<&str>,
    principal: bool,
) -> Result<i64, VaultServiceError> {
    validar_tipo_metodo(tipo)?;
    buscar_credencial(db, credencial_id, usuario_id)?;

    let tx = db.conn.unchecked_transaction()?;
    let id = db.criar_metodo_autenticacao(&NovoMetodoAutenticacao {
        credencial_id,
        tipo: tipo.to_string(),
        descricao: descricao.map(str::to_string),
        principal: false,
        habilitado: true,
    })?;
    if principal {
        db.definir_metodo_principal(credencial_id, id)?;
    }
    tx.commit()?;
    Ok(id)
}

/// Lista os métodos de uma credencial do usuário.
pub fn listar_metodos(
    db: &Database,
    usuario_id: i64,
    credencial_id: i64,
) -> Result<Vec<MetodoAutenticacao>, VaultServiceError> {
    buscar_credencial(db, credencial_id, usuario_id)?;
    Ok(db.listar_metodos_autenticacao(credencial_id)?)
}

/// Aplica as alterações a um método, em uma única transação.
pub fn editar_metodo(
    db: &Database,
    usuario_id: i64,
    metodo_id: i64,
    edicao: &EdicaoMetodo<'_>,
) -> Result<(), VaultServiceError> {
    let atual = buscar_metodo(db, usuario_id, metodo_id)?;
    let tipo = edicao.tipo.unwrap_or(&atual.tipo);
    validar_tipo_metodo(tipo)?;
    let descricao = match edicao.descricao {
        Some(d) => d,
        None => atual.descricao.as_deref(),
    };

    let tx = db.conn.unchecked_transaction()?;
    db.atualizar_metodo_autenticacao(
        metodo_id,
        tipo,
        descricao,
        edicao.principal.unwrap_or(atual.principal),
        edicao.habilitado.unwrap_or(atual.habilitado),
    )?;
    if edicao.principal == Some(true) {
        db.definir_metodo_principal(atual.credencial_id, metodo_id)?;
    }
    tx.commit()?;
    Ok(())
}

/// Exclui um método do usuário.
pub fn excluir_metodo(
    db: &Database,
    usuario_id: i64,
    metodo_id: i64,
) -> Result<MetodoAutenticacao, VaultServiceError> {
    let metodo = buscar_metodo(db, usuario_id, metodo_id)?;
    db.excluir_metodo_autenticacao(metodo_id)?;
    Ok(metodo)
}

// ------------------------------------------------------------------
// E-mails de recuperação
// ------------------------------------------------------------------

fn aad_email(email_id: i64, usuario_id: i64) -> String {
    aead::build_aad(
        "email_recuperacao",
        "email_criptografado",
        email_id,
        usuario_id,
    )
}

fn gravar_email(
    db: &Database,
    vault: &UnlockedVault,
    email_id: i64,
    usuario_id: i64,
    email: &str,
) -> Result<(), VaultServiceError> {
    let (nonce, cifrado) = vault.encrypt(email.as_bytes(), &aad_email(email_id, usuario_id))?;
    db.definir_email_recuperacao_cifrado(email_id, &cifrado, &nonce)?;
    Ok(())
}

/// Busca um e-mail garantindo que sua credencial pertence ao usuário.
pub fn buscar_email(
    db: &Database,
    usuario_id: i64,
    email_id: i64,
) -> Result<EmailRecuperacao, VaultServiceError> {
    let email = db.buscar_email_recuperacao(email_id)?;
    buscar_credencial(db, email.credencial_id, usuario_id).map_err(|_| nao_encontrado())?;
    Ok(email)
}

/// Adiciona um e-mail de recuperação cifrado à credencial.
pub fn adicionar_email(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
    credencial_id: i64,
    email: &str,
    principal: bool,
    verificado: bool,
) -> Result<i64, VaultServiceError> {
    let email = email.trim();
    validar_email(email)?;
    buscar_credencial(db, credencial_id, usuario_id)?;

    // Mesmo esquema das credenciais: a AAD precisa do ID, então a linha é criada
    // vazia e preenchida na mesma transação.
    let tx = db.conn.unchecked_transaction()?;
    let id = db.criar_email_recuperacao_vazio(credencial_id, verificado)?;
    gravar_email(db, vault, id, usuario_id, email)?;
    if principal {
        db.definir_email_recuperacao_principal(credencial_id, id, true)?;
    }
    tx.commit()?;
    Ok(id)
}

/// Lista os e-mails (cifrados) de uma credencial do usuário.
pub fn listar_emails(
    db: &Database,
    usuario_id: i64,
    credencial_id: i64,
) -> Result<Vec<EmailRecuperacao>, VaultServiceError> {
    buscar_credencial(db, credencial_id, usuario_id)?;
    Ok(db.listar_emails_recuperacao(credencial_id)?)
}

/// Descriptografa um e-mail de recuperação.
pub fn revelar_email(
    vault: &UnlockedVault,
    usuario_id: i64,
    email: &EmailRecuperacao,
) -> Result<Vec<u8>, VaultServiceError> {
    Ok(vault.decrypt(
        &email.nonce,
        &email.email_criptografado,
        &aad_email(email.id, usuario_id),
    )?)
}

/// Aplica as alterações a um e-mail de recuperação, em uma única transação.
pub fn editar_email(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
    email_id: i64,
    edicao: &EdicaoEmail<'_>,
) -> Result<(), VaultServiceError> {
    let atual = buscar_email(db, usuario_id, email_id)?;
    let novo_email = edicao.email.map(str::trim);
    if let Some(e) = novo_email {
        validar_email(e)?;
    }

    let tx = db.conn.unchecked_transaction()?;
    if let Some(e) = novo_email {
        gravar_email(db, vault, email_id, usuario_id, e)?;
        // Endereço novo: a verificação anterior não vale mais, salvo se informada.
        if edicao.verificado.is_none() && atual.verificado {
            db.definir_email_recuperacao_verificado(email_id, false)?;
        }
    }
    if let Some(v) = edicao.verificado {
        db.definir_email_recuperacao_verificado(email_id, v)?;
    }
    if let Some(p) = edicao.principal {
        db.definir_email_recuperacao_principal(atual.credencial_id, email_id, p)?;
    }
    if let Some(a) = edicao.ativo {
        db.definir_email_recuperacao_ativo(email_id, a)?;
    }
    tx.commit()?;
    Ok(())
}

/// Exclui um e-mail de recuperação do usuário.
pub fn excluir_email(
    db: &Database,
    usuario_id: i64,
    email_id: i64,
) -> Result<EmailRecuperacao, VaultServiceError> {
    let email = buscar_email(db, usuario_id, email_id)?;
    db.excluir_email_recuperacao(email_id)?;
    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testes::DbTemp;
    use crate::vault_service::{
        adicionar_credencial, excluir_credencial, tests::cofre_com_servico,
    };

    #[test]
    fn test_metodos_principal_unico() {
        let tmp = DbTemp::new("metodos");
        let (db, vault, u, s) = cofre_com_servico(&tmp);
        let c = adicionar_credencial(&db, &vault, u, s, "A", "a@x.com", b"s", None).unwrap();

        let senha = adicionar_metodo(&db, u, c, "SENHA", None, true).unwrap();
        let totp = adicionar_metodo(&db, u, c, "TOTP", Some("Aegis"), true).unwrap();
        let metodos = listar_metodos(&db, u, c).unwrap();
        assert_eq!(metodos.len(), 2);
        assert_eq!(metodos.iter().filter(|m| m.principal).count(), 1);
        assert_eq!(metodos[0].id, totp);
        assert!(metodos[0].configurado_em.is_some());

        editar_metodo(
            &db,
            u,
            senha,
            &EdicaoMetodo {
                principal: Some(true),
                habilitado: Some(false),
                descricao: Some(Some("antiga")),
                ..Default::default()
            },
        )
        .unwrap();
        let m = db.buscar_metodo_autenticacao(senha).unwrap();
        assert!(m.principal && !m.habilitado);
        assert_eq!(m.descricao.as_deref(), Some("antiga"));
        assert!(!db.buscar_metodo_autenticacao(totp).unwrap().principal);

        assert!(adicionar_metodo(&db, u, c, "FAX", None, false).is_err());
        assert!(adicionar_metodo(&db, u + 1, c, "SMS", None, false).is_err());
        assert!(excluir_metodo(&db, u + 1, totp).is_err());

        excluir_metodo(&db, u, totp).unwrap();
        assert_eq!(listar_metodos(&db, u, c).unwrap().len(), 1);
    }

    #[test]
    fn test_emails_cifrados_com_aad() {
        let tmp = DbTemp::new("emails");
        let (db, vault, u, s) = cofre_com_servico(&tmp);
        let c = adicionar_credencial(&db, &vault, u, s, "A", "a@x.com", b"s", None).unwrap();

        let a = adicionar_email(&db, &vault, u, c, " rec@exemplo.com ", true, true).unwrap();
        let b = adicionar_email(&db, &vault, u, c, "outro@exemplo.com", false, false).unwrap();

        let ea = db.buscar_email_recuperacao(a).unwrap();
        assert!(ea.principal && ea.verificado && ea.verificado_em.is_some());
        // O texto puro não aparece no banco.
        assert!(!ea.email_criptografado.windows(3).any(|w| w == b"rec"));
        assert_eq!(revelar_email(&vault, u, &ea).unwrap(), b"rec@exemplo.com");

        // Trocar o e-mail cifrado de linha é detectado pela AAD.
        let eb = db.buscar_email_recuperacao(b).unwrap();
        db.definir_email_recuperacao_cifrado(a, &eb.email_criptografado, &eb.nonce)
            .unwrap();
        let ea = db.buscar_email_recuperacao(a).unwrap();
        assert!(revelar_email(&vault, u, &ea).is_err());

        // Novo endereço zera a verificação; principal passa para B.
        editar_email(
            &db,
            &vault,
            u,
            a,
            &EdicaoEmail {
                email: Some("novo@exemplo.com"),
                ..Default::default()
            },
        )
        .unwrap();
        editar_email(
            &db,
            &vault,
            u,
            b,
            &EdicaoEmail {
                principal: Some(true),
                ativo: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
        let ea = db.buscar_email_recuperacao(a).unwrap();
        let eb = db.buscar_email_recuperacao(b).unwrap();
        assert_eq!(revelar_email(&vault, u, &ea).unwrap(), b"novo@exemplo.com");
        assert!(!ea.verificado && ea.verificado_em.is_none() && !ea.principal);
        assert!(eb.principal && !eb.ativo);

        for invalido in ["semarroba", "@x.com", "a@b", "a@.com", "a b@x.com"] {
            assert!(
                adicionar_email(&db, &vault, u, c, invalido, false, false).is_err(),
                "{invalido}"
            );
        }
        assert!(buscar_email(&db, u + 1, a).is_err());

        // Excluir a credencial remove os e-mails em cascata.
        excluir_credencial(&db, u, c).unwrap();
        assert!(matches!(
            db.buscar_email_recuperacao(b),
            Err(DbError::NotFound)
        ));
    }
}
