//! Regras das URLs vinculadas a serviços (`url_servico`).

use cofre_db::models::{NovaUrlServico, UrlServico};
use cofre_db::Database;

use crate::vault_service::VaultServiceError;

/// Tipos aceitos pela coluna `url_servico.tipo`.
pub const TIPOS_URL: [&str; 5] = ["PRINCIPAL", "LOGIN", "RECUPERACAO", "CADASTRO", "LOGOUT"];

/// Alterações possíveis em uma URL. Campos `None` não são alterados.
#[derive(Default)]
pub struct EdicaoUrl<'a> {
    pub url: Option<&'a str>,
    pub tipo: Option<&'a str>,
    /// `Some(None)` remove a descrição.
    pub descricao: Option<Option<&'a str>>,
    pub ativa: Option<bool>,
    /// `true` torna esta a URL padrão do serviço.
    pub padrao: bool,
}

fn validar_url(url: &str) -> Result<(), VaultServiceError> {
    let resto = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| {
            VaultServiceError::Invalido("a URL deve começar com http:// ou https://".into())
        })?;
    let host = resto.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || url.chars().any(char::is_whitespace) {
        return Err(VaultServiceError::Invalido(format!(
            "URL inválida: '{url}'"
        )));
    }
    Ok(())
}

fn validar_tipo(tipo: &str) -> Result<(), VaultServiceError> {
    if TIPOS_URL.contains(&tipo) {
        Ok(())
    } else {
        Err(VaultServiceError::Invalido(format!(
            "tipo de URL '{tipo}' (use um de: {})",
            TIPOS_URL.join(", ")
        )))
    }
}

/// Adiciona uma URL ao serviço. A primeira URL do serviço vira a padrão automaticamente.
pub fn adicionar_url(
    db: &Database,
    servico_id: i64,
    url: &str,
    tipo: &str,
    descricao: Option<&str>,
    padrao: bool,
) -> Result<i64, VaultServiceError> {
    let url = url.trim();
    validar_url(url)?;
    validar_tipo(tipo)?;
    db.buscar_servico(servico_id)?;

    let tx = db.conn.unchecked_transaction()?;
    let primeira = db.listar_urls_servico(servico_id)?.is_empty();
    let id = db.criar_url_servico(&NovaUrlServico {
        servico_id,
        url: url.to_string(),
        tipo: tipo.to_string(),
        descricao: descricao.map(str::to_string),
        padrao: false,
    })?;
    if padrao || primeira {
        db.definir_url_padrao(servico_id, id)?;
    }
    tx.commit()?;
    Ok(id)
}

/// Lista as URLs de um serviço existente.
pub fn listar_urls(db: &Database, servico_id: i64) -> Result<Vec<UrlServico>, VaultServiceError> {
    db.buscar_servico(servico_id)?;
    Ok(db.listar_urls_servico(servico_id)?)
}

/// Aplica as alterações a uma URL, em uma única transação.
pub fn editar_url(db: &Database, id: i64, edicao: &EdicaoUrl<'_>) -> Result<(), VaultServiceError> {
    let atual = db.buscar_url_servico(id)?;
    let url = edicao.url.map(str::trim).unwrap_or(&atual.url);
    let tipo = edicao.tipo.unwrap_or(&atual.tipo);
    validar_url(url)?;
    validar_tipo(tipo)?;
    let descricao = match edicao.descricao {
        Some(d) => d,
        None => atual.descricao.as_deref(),
    };

    let tx = db.conn.unchecked_transaction()?;
    db.atualizar_url_servico(
        id,
        url,
        tipo,
        descricao,
        edicao.ativa.unwrap_or(atual.ativa),
    )?;
    if edicao.padrao {
        db.definir_url_padrao(atual.servico_id, id)?;
    }
    tx.commit()?;
    Ok(())
}

/// Exclui uma URL, desde que nenhuma configuração de login dependa dela.
pub fn excluir_url(db: &Database, id: i64) -> Result<UrlServico, VaultServiceError> {
    let url = db.buscar_url_servico(id)?;
    let configuracoes = db.contar_configuracoes_login_url(id)?;
    if configuracoes > 0 {
        return Err(VaultServiceError::EmUso(format!(
            "A URL #{id} é usada por {configuracoes} configuração(ões) de login."
        )));
    }
    db.excluir_url_servico(id)?;
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cofre_db::models::NovoServico;

    fn db_com_servico(nome: &str) -> (crate::testes::DbTemp, Database, i64) {
        let tmp = crate::testes::DbTemp::new(nome);
        let db = Database::open(&tmp.0).unwrap();
        let servico_id = db
            .criar_servico(&NovoServico {
                categoria_id: None,
                nome: "GitHub".into(),
                dominio_principal: "github.com".into(),
                url_principal: None,
                descricao: None,
            })
            .unwrap();
        (tmp, db, servico_id)
    }

    #[test]
    fn test_urls_padrao_unica() {
        let (_tmp, db, s) = db_com_servico("urls");

        let a = adicionar_url(&db, s, "https://github.com/login", "LOGIN", None, false).unwrap();
        let b = adicionar_url(
            &db,
            s,
            "https://github.com/password_reset",
            "RECUPERACAO",
            None,
            false,
        )
        .unwrap();
        // A primeira vira padrão sozinha; a segunda não.
        assert!(db.buscar_url_servico(a).unwrap().padrao);
        assert!(!db.buscar_url_servico(b).unwrap().padrao);

        editar_url(
            &db,
            b,
            &EdicaoUrl {
                padrao: true,
                ..Default::default()
            },
        )
        .unwrap();
        let urls = listar_urls(&db, s).unwrap();
        assert_eq!(urls.iter().filter(|u| u.padrao).count(), 1);
        assert_eq!(urls[0].id, b);

        // URL duplicada no mesmo serviço é rejeitada pelo banco.
        assert!(adicionar_url(&db, s, "https://github.com/login", "LOGIN", None, false).is_err());

        excluir_url(&db, a).unwrap();
        assert_eq!(listar_urls(&db, s).unwrap().len(), 1);
    }

    #[test]
    fn test_url_validacao() {
        let (_tmp, db, s) = db_com_servico("urls-validacao");
        assert!(adicionar_url(&db, s, "github.com/login", "LOGIN", None, false).is_err());
        assert!(adicionar_url(&db, s, "https:///x", "LOGIN", None, false).is_err());
        assert!(adicionar_url(&db, s, "https://github.com", "QUALQUER", None, false).is_err());
        assert!(adicionar_url(&db, s + 99, "https://github.com", "LOGIN", None, false).is_err());
        assert!(adicionar_url(&db, s, "  https://github.com  ", "PRINCIPAL", None, false).is_ok());
    }
}
