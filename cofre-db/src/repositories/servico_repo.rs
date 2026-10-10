//! Repositório da tabela `servico`.

use rusqlite::params;

use crate::connection::{Database, DbError};
use crate::models::{NovoServico, Servico};

impl Database {
    /// Cria um novo serviço.
    pub fn criar_servico(&self, novo: &NovoServico) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO servico (categoria_id, nome, dominio_principal, url_principal, descricao)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                novo.categoria_id,
                novo.nome,
                novo.dominio_principal,
                novo.url_principal,
                novo.descricao,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Lista todos os serviços ativos, opcionalmente filtrando por categoria.
    pub fn listar_servicos(&self, categoria_id: Option<i64>) -> Result<Vec<Servico>, DbError> {
        let (sql, params_vec): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match categoria_id {
            Some(cat_id) => (
                "SELECT id, categoria_id, nome, dominio_principal, url_principal,
                        descricao, criado_em, atualizado_em, ativo
                 FROM servico WHERE ativo = 1 AND categoria_id = ?1 ORDER BY nome",
                vec![Box::new(cat_id)],
            ),
            None => (
                "SELECT id, categoria_id, nome, dominio_principal, url_principal,
                        descricao, criado_em, atualizado_em, ativo
                 FROM servico WHERE ativo = 1 ORDER BY nome",
                vec![],
            ),
        };

        let mut stmt = self.conn.prepare(sql)?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let servicos = stmt
            .query_map(params_refs.as_slice(), |row| {
                Ok(Servico {
                    id: row.get(0)?,
                    categoria_id: row.get(1)?,
                    nome: row.get(2)?,
                    dominio_principal: row.get(3)?,
                    url_principal: row.get(4)?,
                    descricao: row.get(5)?,
                    criado_em: row.get(6)?,
                    atualizado_em: row.get(7)?,
                    ativo: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(servicos)
    }

    /// Busca um serviço pelo ID.
    pub fn buscar_servico(&self, id: i64) -> Result<Servico, DbError> {
        self.conn
            .query_row(
                "SELECT id, categoria_id, nome, dominio_principal, url_principal,
                        descricao, criado_em, atualizado_em, ativo
                 FROM servico WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Servico {
                        id: row.get(0)?,
                        categoria_id: row.get(1)?,
                        nome: row.get(2)?,
                        dominio_principal: row.get(3)?,
                        url_principal: row.get(4)?,
                        descricao: row.get(5)?,
                        criado_em: row.get(6)?,
                        atualizado_em: row.get(7)?,
                        ativo: row.get(8)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })
    }

    /// Pesquisa serviços por nome (busca parcial).
    pub fn pesquisar_servicos(&self, termo: &str) -> Result<Vec<Servico>, DbError> {
        let pattern = format!("%{termo}%");
        let mut stmt = self.conn.prepare(
            "SELECT id, categoria_id, nome, dominio_principal, url_principal,
                    descricao, criado_em, atualizado_em, ativo
             FROM servico WHERE ativo = 1 AND nome LIKE ?1 ORDER BY nome",
        )?;

        let servicos = stmt
            .query_map(params![pattern], |row| {
                Ok(Servico {
                    id: row.get(0)?,
                    categoria_id: row.get(1)?,
                    nome: row.get(2)?,
                    dominio_principal: row.get(3)?,
                    url_principal: row.get(4)?,
                    descricao: row.get(5)?,
                    criado_em: row.get(6)?,
                    atualizado_em: row.get(7)?,
                    ativo: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(servicos)
    }

    /// Atualiza os dados de um serviço.
    pub fn atualizar_servico(&self, id: i64, dados: &NovoServico) -> Result<(), DbError> {
        let alteradas = self.conn.execute(
            "UPDATE servico
             SET categoria_id = ?2, nome = ?3, dominio_principal = ?4, url_principal = ?5,
                 descricao = ?6, atualizado_em = datetime('now')
             WHERE id = ?1",
            params![
                id,
                dados.categoria_id,
                dados.nome,
                dados.dominio_principal,
                dados.url_principal,
                dados.descricao,
            ],
        )?;
        if alteradas == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    /// Exclui um serviço. Falha por chave estrangeira se ainda houver credenciais vinculadas.
    pub fn excluir_servico(&self, id: i64) -> Result<(), DbError> {
        let alteradas = self.conn.execute("DELETE FROM servico WHERE id = ?1", params![id])?;
        if alteradas == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    /// Conta as credenciais (ativas ou não) vinculadas a um serviço.
    pub fn contar_credenciais_servico(&self, id: i64) -> Result<i64, DbError> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM credencial WHERE servico_id = ?1",
            params![id],
            |row| row.get(0),
        )?)
    }
}
