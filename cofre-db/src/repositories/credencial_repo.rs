//! Repositório da tabela `credencial`.

use rusqlite::params;

use crate::connection::{Database, DbError};
use crate::models::{Credencial, NovaCredencial};

impl Database {
    /// Cria uma nova credencial (os dados sensíveis já devem estar cifrados).
    pub fn criar_credencial(&self, nova: &NovaCredencial) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO credencial (usuario_id, servico_id, nome_exibicao, identificador,
                                     segredo_criptografado, nonce,
                                     observacao_criptografada, observacao_nonce, favorita)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                nova.usuario_id,
                nova.servico_id,
                nova.nome_exibicao,
                nova.identificador,
                nova.segredo_criptografado,
                nova.nonce,
                nova.observacao_criptografada,
                nova.observacao_nonce,
                nova.favorita,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Lista todas as credenciais ativas de um usuário.
    pub fn listar_credenciais(&self, usuario_id: i64) -> Result<Vec<Credencial>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, usuario_id, servico_id, nome_exibicao, identificador,
                    segredo_criptografado, nonce, observacao_criptografada, observacao_nonce,
                    favorita, criada_em, alterada_em, ultimo_uso_em, ativa
             FROM credencial
             WHERE ativa = 1 AND usuario_id = ?1
             ORDER BY favorita DESC, nome_exibicao",
        )?;

        let credenciais = stmt
            .query_map(params![usuario_id], |row| {
                Ok(Credencial {
                    id: row.get(0)?,
                    usuario_id: row.get(1)?,
                    servico_id: row.get(2)?,
                    nome_exibicao: row.get(3)?,
                    identificador: row.get(4)?,
                    segredo_criptografado: row.get(5)?,
                    nonce: row.get(6)?,
                    observacao_criptografada: row.get(7)?,
                    observacao_nonce: row.get(8)?,
                    favorita: row.get(9)?,
                    criada_em: row.get(10)?,
                    alterada_em: row.get(11)?,
                    ultimo_uso_em: row.get(12)?,
                    ativa: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(credenciais)
    }

    /// Busca uma credencial pelo ID.
    pub fn buscar_credencial(&self, id: i64) -> Result<Credencial, DbError> {
        self.conn
            .query_row(
                "SELECT id, usuario_id, servico_id, nome_exibicao, identificador,
                        segredo_criptografado, nonce, observacao_criptografada, observacao_nonce,
                        favorita, criada_em, alterada_em, ultimo_uso_em, ativa
                 FROM credencial WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Credencial {
                        id: row.get(0)?,
                        usuario_id: row.get(1)?,
                        servico_id: row.get(2)?,
                        nome_exibicao: row.get(3)?,
                        identificador: row.get(4)?,
                        segredo_criptografado: row.get(5)?,
                        nonce: row.get(6)?,
                        observacao_criptografada: row.get(7)?,
                        observacao_nonce: row.get(8)?,
                        favorita: row.get(9)?,
                        criada_em: row.get(10)?,
                        alterada_em: row.get(11)?,
                        ultimo_uso_em: row.get(12)?,
                        ativa: row.get(13)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })
    }

    /// Pesquisa credenciais por nome de exibição ou identificador.
    pub fn pesquisar_credenciais(
        &self,
        usuario_id: i64,
        termo: &str,
    ) -> Result<Vec<Credencial>, DbError> {
        let pattern = format!("%{termo}%");
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.usuario_id, c.servico_id, c.nome_exibicao, c.identificador,
                    c.segredo_criptografado, c.nonce, c.observacao_criptografada,
                    c.observacao_nonce, c.favorita, c.criada_em, c.alterada_em,
                    c.ultimo_uso_em, c.ativa
             FROM credencial c
             LEFT JOIN servico s ON c.servico_id = s.id
             WHERE c.ativa = 1 AND c.usuario_id = ?1
               AND (c.nome_exibicao LIKE ?2 OR c.identificador LIKE ?2 OR s.nome LIKE ?2)
             ORDER BY c.favorita DESC, c.nome_exibicao",
        )?;

        let credenciais = stmt
            .query_map(params![usuario_id, pattern], |row| {
                Ok(Credencial {
                    id: row.get(0)?,
                    usuario_id: row.get(1)?,
                    servico_id: row.get(2)?,
                    nome_exibicao: row.get(3)?,
                    identificador: row.get(4)?,
                    segredo_criptografado: row.get(5)?,
                    nonce: row.get(6)?,
                    observacao_criptografada: row.get(7)?,
                    observacao_nonce: row.get(8)?,
                    favorita: row.get(9)?,
                    criada_em: row.get(10)?,
                    alterada_em: row.get(11)?,
                    ultimo_uso_em: row.get(12)?,
                    ativa: row.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(credenciais)
    }

    /// Grava os campos cifrados de uma credencial.
    ///
    /// Usado após o INSERT, quando o ID real já é conhecido e pode compor a AAD.
    pub fn definir_segredos_credencial(
        &self,
        id: i64,
        segredo_criptografado: &[u8],
        nonce: &[u8],
        observacao_criptografada: Option<&[u8]>,
        observacao_nonce: Option<&[u8]>,
    ) -> Result<(), DbError> {
        let alteradas = self.conn.execute(
            "UPDATE credencial
             SET segredo_criptografado = ?2, nonce = ?3,
                 observacao_criptografada = ?4, observacao_nonce = ?5
             WHERE id = ?1",
            params![id, segredo_criptografado, nonce, observacao_criptografada, observacao_nonce],
        )?;
        if alteradas == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    /// Atualiza o timestamp de último uso de uma credencial.
    pub fn atualizar_ultimo_uso_credencial(&self, id: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE credencial SET ultimo_uso_em = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Desativa uma credencial.
    pub fn desativar_credencial(&self, id: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE credencial SET ativa = 0, alterada_em = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }
}
