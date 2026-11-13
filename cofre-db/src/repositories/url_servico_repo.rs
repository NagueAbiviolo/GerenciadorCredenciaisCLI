//! Repositório da tabela `url_servico`.

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::{NovaUrlServico, UrlServico};

const COLUNAS: &str = "id, servico_id, url, tipo, descricao, padrao, criado_em, ativa";

fn mapear_url(row: &Row<'_>) -> rusqlite::Result<UrlServico> {
    Ok(UrlServico {
        id: row.get(0)?,
        servico_id: row.get(1)?,
        url: row.get(2)?,
        tipo: row.get(3)?,
        descricao: row.get(4)?,
        padrao: row.get(5)?,
        criado_em: row.get(6)?,
        ativa: row.get(7)?,
    })
}

fn exigir_alteracao(alteradas: usize) -> Result<(), DbError> {
    if alteradas == 0 { Err(DbError::NotFound) } else { Ok(()) }
}

impl Database {
    /// Cria uma URL para um serviço. Não mexe nas outras URLs: para garantir uma
    /// única URL padrão, chame `definir_url_padrao` em seguida (na mesma transação).
    pub fn criar_url_servico(&self, nova: &NovaUrlServico) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO url_servico (servico_id, url, tipo, descricao, padrao)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![nova.servico_id, nova.url, nova.tipo, nova.descricao, nova.padrao],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Lista as URLs de um serviço (a padrão primeiro).
    pub fn listar_urls_servico(&self, servico_id: i64) -> Result<Vec<UrlServico>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS} FROM url_servico
             WHERE servico_id = ?1
             ORDER BY padrao DESC, tipo, url"
        ))?;
        let urls = stmt
            .query_map(params![servico_id], mapear_url)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(urls)
    }

    /// Busca uma URL pelo ID.
    pub fn buscar_url_servico(&self, id: i64) -> Result<UrlServico, DbError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUNAS} FROM url_servico WHERE id = ?1"),
                params![id],
                mapear_url,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })
    }

    /// Atualiza url, tipo, descrição e flag `ativa` de uma URL.
    pub fn atualizar_url_servico(
        &self,
        id: i64,
        url: &str,
        tipo: &str,
        descricao: Option<&str>,
        ativa: bool,
    ) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE url_servico SET url = ?2, tipo = ?3, descricao = ?4, ativa = ?5
             WHERE id = ?1",
            params![id, url, tipo, descricao, ativa],
        )?)
    }

    /// Torna `id` a única URL padrão do serviço (em um único comando, atômico).
    pub fn definir_url_padrao(&self, servico_id: i64, id: i64) -> Result<(), DbError> {
        let existe: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM url_servico WHERE id = ?1 AND servico_id = ?2)",
            params![id, servico_id],
            |row| row.get(0),
        )?;
        if !existe {
            return Err(DbError::NotFound);
        }
        self.conn.execute(
            "UPDATE url_servico SET padrao = (id = ?2) WHERE servico_id = ?1",
            params![servico_id, id],
        )?;
        Ok(())
    }

    /// Exclui uma URL.
    pub fn excluir_url_servico(&self, id: i64) -> Result<(), DbError> {
        exigir_alteracao(
            self.conn
                .execute("DELETE FROM url_servico WHERE id = ?1", params![id])?,
        )
    }

    /// Conta as configurações de login que usam esta URL (impedem a exclusão).
    pub fn contar_configuracoes_login_url(&self, id: i64) -> Result<i64, DbError> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM configuracao_login WHERE url_servico_id = ?1",
            params![id],
            |row| row.get(0),
        )?)
    }
}
