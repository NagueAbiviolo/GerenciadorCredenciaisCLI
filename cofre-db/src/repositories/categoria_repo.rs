//! Repositório da tabela `categoria`.

use rusqlite::params;

use crate::connection::{Database, DbError};
use crate::models::{Categoria, NovaCategoria};

impl Database {
    /// Cria uma nova categoria.
    pub fn criar_categoria(&self, nova: &NovaCategoria) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO categoria (nome, descricao) VALUES (?1, ?2)",
            params![nova.nome, nova.descricao],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Lista todas as categorias ativas.
    pub fn listar_categorias(&self) -> Result<Vec<Categoria>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, nome, descricao, criado_em, atualizado_em, ativa
             FROM categoria WHERE ativa = 1 ORDER BY nome",
        )?;

        let categorias = stmt
            .query_map([], |row| {
                Ok(Categoria {
                    id: row.get(0)?,
                    nome: row.get(1)?,
                    descricao: row.get(2)?,
                    criado_em: row.get(3)?,
                    atualizado_em: row.get(4)?,
                    ativa: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(categorias)
    }

    /// Busca uma categoria pelo ID.
    pub fn buscar_categoria(&self, id: i64) -> Result<Categoria, DbError> {
        self.conn
            .query_row(
                "SELECT id, nome, descricao, criado_em, atualizado_em, ativa
                 FROM categoria WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Categoria {
                        id: row.get(0)?,
                        nome: row.get(1)?,
                        descricao: row.get(2)?,
                        criado_em: row.get(3)?,
                        atualizado_em: row.get(4)?,
                        ativa: row.get(5)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })
    }

    /// Atualiza uma categoria.
    pub fn atualizar_categoria(&self, id: i64, nome: &str, descricao: Option<&str>) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE categoria SET nome = ?2, descricao = ?3, atualizado_em = datetime('now') WHERE id = ?1",
            params![id, nome, descricao],
        )?;
        Ok(())
    }

    /// Exclui (desativa) uma categoria.
    pub fn desativar_categoria(&self, id: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE categoria SET ativa = 0, atualizado_em = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }
}
