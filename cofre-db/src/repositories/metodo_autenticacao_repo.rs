//! Repositório da tabela `metodo_autenticacao`.

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::{MetodoAutenticacao, NovoMetodoAutenticacao};

const COLUNAS: &str = "id, credencial_id, tipo, descricao, principal, habilitado,
                       configurado_em, atualizado_em";

fn mapear_metodo(row: &Row<'_>) -> rusqlite::Result<MetodoAutenticacao> {
    Ok(MetodoAutenticacao {
        id: row.get(0)?,
        credencial_id: row.get(1)?,
        tipo: row.get(2)?,
        descricao: row.get(3)?,
        principal: row.get(4)?,
        habilitado: row.get(5)?,
        configurado_em: row.get(6)?,
        atualizado_em: row.get(7)?,
    })
}

fn exigir_alteracao(alteradas: usize) -> Result<(), DbError> {
    if alteradas == 0 { Err(DbError::NotFound) } else { Ok(()) }
}

impl Database {
    /// Cria um método de autenticação. `configurado_em` recebe o momento atual.
    ///
    /// Não mexe nos outros métodos: para garantir um único principal, chame
    /// `definir_metodo_principal` em seguida (na mesma transação).
    pub fn criar_metodo_autenticacao(&self, novo: &NovoMetodoAutenticacao) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO metodo_autenticacao
                 (credencial_id, tipo, descricao, principal, habilitado, configurado_em)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))",
            params![
                novo.credencial_id,
                novo.tipo,
                novo.descricao,
                novo.principal,
                novo.habilitado,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Lista os métodos de uma credencial (o principal primeiro).
    pub fn listar_metodos_autenticacao(
        &self,
        credencial_id: i64,
    ) -> Result<Vec<MetodoAutenticacao>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS} FROM metodo_autenticacao
             WHERE credencial_id = ?1
             ORDER BY principal DESC, id"
        ))?;
        let metodos = stmt
            .query_map(params![credencial_id], mapear_metodo)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(metodos)
    }

    /// Busca um método pelo ID.
    pub fn buscar_metodo_autenticacao(&self, id: i64) -> Result<MetodoAutenticacao, DbError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUNAS} FROM metodo_autenticacao WHERE id = ?1"),
                params![id],
                mapear_metodo,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })
    }

    /// Atualiza tipo, descrição e flags de um método.
    pub fn atualizar_metodo_autenticacao(
        &self,
        id: i64,
        tipo: &str,
        descricao: Option<&str>,
        principal: bool,
        habilitado: bool,
    ) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE metodo_autenticacao
             SET tipo = ?2, descricao = ?3, principal = ?4, habilitado = ?5,
                 atualizado_em = datetime('now')
             WHERE id = ?1",
            params![id, tipo, descricao, principal, habilitado],
        )?)
    }

    /// Torna `id` o único método principal da credencial (comando único, atômico).
    pub fn definir_metodo_principal(&self, credencial_id: i64, id: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE metodo_autenticacao
             SET principal = (id = ?2),
                 atualizado_em = CASE WHEN principal <> (id = ?2)
                                      THEN datetime('now') ELSE atualizado_em END
             WHERE credencial_id = ?1",
            params![credencial_id, id],
        )?;
        Ok(())
    }

    /// Exclui um método.
    pub fn excluir_metodo_autenticacao(&self, id: i64) -> Result<(), DbError> {
        exigir_alteracao(
            self.conn
                .execute("DELETE FROM metodo_autenticacao WHERE id = ?1", params![id])?,
        )
    }
}
