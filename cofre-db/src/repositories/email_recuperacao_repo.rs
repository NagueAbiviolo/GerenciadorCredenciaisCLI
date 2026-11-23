//! Repositório da tabela `email_recuperacao`.
//!
//! O e-mail é guardado cifrado; a cifragem (com AAD) fica a cargo de `cofre-services`.

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::EmailRecuperacao;

const COLUNAS: &str = "id, credencial_id, email_criptografado, nonce, principal, verificado,
                       verificado_em, criado_em, ativo";

fn mapear_email(row: &Row<'_>) -> rusqlite::Result<EmailRecuperacao> {
    Ok(EmailRecuperacao {
        id: row.get(0)?,
        credencial_id: row.get(1)?,
        email_criptografado: row.get(2)?,
        nonce: row.get(3)?,
        principal: row.get(4)?,
        verificado: row.get(5)?,
        verificado_em: row.get(6)?,
        criado_em: row.get(7)?,
        ativo: row.get(8)?,
    })
}

fn exigir_alteracao(alteradas: usize) -> Result<(), DbError> {
    if alteradas == 0 {
        Err(DbError::NotFound)
    } else {
        Ok(())
    }
}

impl Database {
    /// Cria um e-mail de recuperação com o conteúdo cifrado vazio.
    ///
    /// A AAD depende do ID da linha, então o chamador deve, na mesma transação,
    /// gravar o e-mail cifrado com `definir_email_recuperacao_cifrado`.
    pub fn criar_email_recuperacao_vazio(
        &self,
        credencial_id: i64,
        verificado: bool,
    ) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO email_recuperacao
                 (credencial_id, email_criptografado, nonce, verificado, verificado_em)
             VALUES (?1, x'', x'', ?2, CASE WHEN ?2 THEN datetime('now') END)",
            params![credencial_id, verificado],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Grava o e-mail cifrado.
    pub fn definir_email_recuperacao_cifrado(
        &self,
        id: i64,
        email_criptografado: &[u8],
        nonce: &[u8],
    ) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE email_recuperacao SET email_criptografado = ?2, nonce = ?3 WHERE id = ?1",
            params![id, email_criptografado, nonce],
        )?)
    }

    /// Lista os e-mails de recuperação de uma credencial (o principal primeiro).
    pub fn listar_emails_recuperacao(
        &self,
        credencial_id: i64,
    ) -> Result<Vec<EmailRecuperacao>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS} FROM email_recuperacao
             WHERE credencial_id = ?1
             ORDER BY principal DESC, id"
        ))?;
        let emails = stmt
            .query_map(params![credencial_id], mapear_email)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(emails)
    }

    /// Busca um e-mail de recuperação pelo ID.
    pub fn buscar_email_recuperacao(&self, id: i64) -> Result<EmailRecuperacao, DbError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUNAS} FROM email_recuperacao WHERE id = ?1"),
                params![id],
                mapear_email,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })
    }

    /// Marca o e-mail como verificado (registrando a data) ou não verificado.
    pub fn definir_email_recuperacao_verificado(
        &self,
        id: i64,
        verificado: bool,
    ) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE email_recuperacao
             SET verificado = ?2,
                 verificado_em = CASE WHEN ?2 THEN datetime('now') END
             WHERE id = ?1",
            params![id, verificado],
        )?)
    }

    /// Ativa ou desativa um e-mail de recuperação.
    pub fn definir_email_recuperacao_ativo(&self, id: i64, ativo: bool) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE email_recuperacao SET ativo = ?2 WHERE id = ?1",
            params![id, ativo],
        )?)
    }

    /// Com `principal = true`, torna `id` o único e-mail principal da credencial
    /// (comando único, atômico). Com `false`, apenas desmarca `id`.
    pub fn definir_email_recuperacao_principal(
        &self,
        credencial_id: i64,
        id: i64,
        principal: bool,
    ) -> Result<(), DbError> {
        if principal {
            self.conn.execute(
                "UPDATE email_recuperacao SET principal = (id = ?2) WHERE credencial_id = ?1",
                params![credencial_id, id],
            )?;
            Ok(())
        } else {
            exigir_alteracao(self.conn.execute(
                "UPDATE email_recuperacao SET principal = 0 WHERE id = ?1 AND credencial_id = ?2",
                params![id, credencial_id],
            )?)
        }
    }

    /// Exclui um e-mail de recuperação.
    pub fn excluir_email_recuperacao(&self, id: i64) -> Result<(), DbError> {
        exigir_alteracao(
            self.conn
                .execute("DELETE FROM email_recuperacao WHERE id = ?1", params![id])?,
        )
    }
}
