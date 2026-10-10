//! Repositório da tabela `credencial`.

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::{Credencial, NovaCredencial};

/// Colunas lidas por `mapear_credencial`, na mesma ordem.
const COLUNAS: &str = "c.id, c.usuario_id, c.servico_id, c.nome_exibicao, c.identificador,
                       c.segredo_criptografado, c.nonce, c.observacao_criptografada,
                       c.observacao_nonce, c.favorita, c.criada_em, c.alterada_em,
                       c.ultimo_uso_em, c.ativa";

fn mapear_credencial(row: &Row<'_>) -> rusqlite::Result<Credencial> {
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
}

/// Converte "nenhuma linha alterada" em `DbError::NotFound`.
fn exigir_alteracao(alteradas: usize) -> Result<(), DbError> {
    if alteradas == 0 {
        Err(DbError::NotFound)
    } else {
        Ok(())
    }
}

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

    /// Lista as credenciais de um usuário (ativas ou inativas, conforme `ativas`).
    pub fn listar_credenciais(&self, usuario_id: i64, ativas: bool) -> Result<Vec<Credencial>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS}
             FROM credencial c
             WHERE c.ativa = ?2 AND c.usuario_id = ?1
             ORDER BY c.favorita DESC, c.nome_exibicao"
        ))?;

        let credenciais = stmt
            .query_map(params![usuario_id, ativas], mapear_credencial)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(credenciais)
    }

    /// Busca uma credencial pelo ID.
    pub fn buscar_credencial(&self, id: i64) -> Result<Credencial, DbError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUNAS} FROM credencial c WHERE c.id = ?1"),
                params![id],
                mapear_credencial,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })
    }

    /// Pesquisa credenciais ativas por nome de exibição, identificador ou nome do serviço.
    pub fn pesquisar_credenciais(
        &self,
        usuario_id: i64,
        termo: &str,
    ) -> Result<Vec<Credencial>, DbError> {
        let pattern = format!("%{termo}%");
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS}
             FROM credencial c
             LEFT JOIN servico s ON c.servico_id = s.id
             WHERE c.ativa = 1 AND c.usuario_id = ?1
               AND (c.nome_exibicao LIKE ?2 OR c.identificador LIKE ?2 OR s.nome LIKE ?2)
             ORDER BY c.favorita DESC, c.nome_exibicao"
        ))?;

        let credenciais = stmt
            .query_map(params![usuario_id, pattern], mapear_credencial)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(credenciais)
    }

    /// Atualiza os dados não sensíveis de uma credencial.
    pub fn atualizar_dados_credencial(
        &self,
        id: i64,
        nome_exibicao: &str,
        identificador: &str,
        favorita: bool,
    ) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE credencial
             SET nome_exibicao = ?2, identificador = ?3, favorita = ?4,
                 alterada_em = datetime('now')
             WHERE id = ?1",
            params![id, nome_exibicao, identificador, favorita],
        )?)
    }

    /// Grava o segredo cifrado de uma credencial.
    pub fn definir_segredo_credencial(
        &self,
        id: i64,
        segredo_criptografado: &[u8],
        nonce: &[u8],
    ) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE credencial
             SET segredo_criptografado = ?2, nonce = ?3, alterada_em = datetime('now')
             WHERE id = ?1",
            params![id, segredo_criptografado, nonce],
        )?)
    }

    /// Grava (ou remove, com `None`) a observação cifrada de uma credencial.
    pub fn definir_observacao_credencial(
        &self,
        id: i64,
        observacao_criptografada: Option<&[u8]>,
        observacao_nonce: Option<&[u8]>,
    ) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE credencial
             SET observacao_criptografada = ?2, observacao_nonce = ?3,
                 alterada_em = datetime('now')
             WHERE id = ?1",
            params![id, observacao_criptografada, observacao_nonce],
        )?)
    }

    /// Atualiza o timestamp de último uso de uma credencial.
    pub fn atualizar_ultimo_uso_credencial(&self, id: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE credencial SET ultimo_uso_em = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Ativa ou desativa uma credencial.
    pub fn definir_credencial_ativa(&self, id: i64, ativa: bool) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE credencial SET ativa = ?2, alterada_em = datetime('now') WHERE id = ?1",
            params![id, ativa],
        )?)
    }

    /// Exclui definitivamente uma credencial (e, em cascata, seus dados dependentes).
    pub fn excluir_credencial(&self, id: i64) -> Result<(), DbError> {
        exigir_alteracao(
            self.conn
                .execute("DELETE FROM credencial WHERE id = ?1", params![id])?,
        )
    }
}
