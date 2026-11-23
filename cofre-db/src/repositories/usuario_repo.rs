//! Repositório da tabela `usuario`.

use rusqlite::params;

use crate::connection::{Database, DbError};
use crate::models::{DadosAutenticacao, NovoUsuario, Usuario};

impl Database {
    /// Cria um novo usuário (cofre).
    pub fn criar_usuario(&self, novo: &NovoUsuario) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO usuario (nome, verificador_mestre, salt_kdf, parametros_kdf,
                                  dek_criptografada, dek_nonce, verificador_salt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                novo.nome,
                novo.verificador_mestre,
                novo.salt_kdf,
                novo.parametros_kdf,
                novo.dek_criptografada,
                novo.dek_nonce,
                novo.verificador_salt,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Busca o usuário ativo (deve haver no máximo um na v1).
    pub fn buscar_usuario_ativo(&self) -> Result<Usuario, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, nome, verificador_mestre, salt_kdf, parametros_kdf,
                    criado_em, atualizado_em, ultimo_acesso_em, ativo,
                    dek_criptografada, dek_nonce, verificador_salt
             FROM usuario
             WHERE ativo = 1
             LIMIT 1",
        )?;

        let usuario = stmt
            .query_row([], |row| {
                Ok(Usuario {
                    id: row.get(0)?,
                    nome: row.get(1)?,
                    verificador_mestre: row.get(2)?,
                    salt_kdf: row.get(3)?,
                    parametros_kdf: row.get(4)?,
                    criado_em: row.get(5)?,
                    atualizado_em: row.get(6)?,
                    ultimo_acesso_em: row.get(7)?,
                    ativo: row.get(8)?,
                    dek_criptografada: row.get(9)?,
                    dek_nonce: row.get(10)?,
                    verificador_salt: row.get(11)?,
                })
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })?;

        Ok(usuario)
    }

    /// Atualiza o último acesso do usuário.
    pub fn atualizar_ultimo_acesso(&self, usuario_id: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE usuario SET ultimo_acesso_em = datetime('now') WHERE id = ?1",
            params![usuario_id],
        )?;
        Ok(())
    }

    /// Atualiza os dados de autenticação do usuário (troca de senha mestre).
    pub fn atualizar_autenticacao(
        &self,
        usuario_id: i64,
        dados: &DadosAutenticacao,
    ) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE usuario
             SET verificador_mestre = ?2, salt_kdf = ?3, parametros_kdf = ?4,
                 dek_criptografada = ?5, dek_nonce = ?6, verificador_salt = ?7,
                 atualizado_em = datetime('now')
             WHERE id = ?1",
            params![
                usuario_id,
                dados.verificador_mestre,
                dados.salt_kdf,
                dados.parametros_kdf,
                dados.dek_criptografada,
                dados.dek_nonce,
                dados.verificador_salt,
            ],
        )?;
        Ok(())
    }
}
