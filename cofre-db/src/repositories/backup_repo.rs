//! Repositório da tabela `backup` (RF14).

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::{Backup, NovoBackup};

const COLUNAS: &str = "id, usuario_id, nome_arquivo, caminho_arquivo, hash_integridade,
                       tamanho_bytes, versao_formato, criado_em, ultima_restauracao_em, valido";

fn mapear_backup(row: &Row<'_>) -> rusqlite::Result<Backup> {
    Ok(Backup {
        id: row.get(0)?,
        usuario_id: row.get(1)?,
        nome_arquivo: row.get(2)?,
        caminho_arquivo: row.get(3)?,
        hash_integridade: row.get(4)?,
        tamanho_bytes: row.get(5)?,
        versao_formato: row.get(6)?,
        criado_em: row.get(7)?,
        ultima_restauracao_em: row.get(8)?,
        valido: row.get(9)?,
    })
}

impl Database {
    /// Registra um novo backup e retorna o ID gerado.
    pub fn registrar_backup(&self, novo: &NovoBackup<'_>) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO backup
                 (usuario_id, nome_arquivo, caminho_arquivo, hash_integridade, tamanho_bytes, versao_formato)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                novo.usuario_id,
                novo.nome_arquivo,
                novo.caminho_arquivo,
                novo.hash_integridade,
                novo.tamanho_bytes,
                novo.versao_formato,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Busca um backup específico garantindo que pertence ao usuário informado.
    pub fn buscar_backup(&self, id: i64, usuario_id: i64) -> Result<Backup, DbError> {
        let resultado = self.conn.query_row(
            &format!("SELECT {COLUNAS} FROM backup WHERE id = ?1 AND usuario_id = ?2"),
            params![id, usuario_id],
            mapear_backup,
        );

        match resultado {
            Ok(b) => Ok(b),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(DbError::NotFound),
            Err(e) => Err(DbError::Sqlite(e)),
        }
    }

    /// Lista os backups de um usuário ordenados por `criado_em DESC, id DESC`.
    pub fn listar_backups(&self, usuario_id: i64) -> Result<Vec<Backup>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS} FROM backup
             WHERE usuario_id = ?1
             ORDER BY criado_em DESC, id DESC"
        ))?;

        let backups = stmt
            .query_map(params![usuario_id], mapear_backup)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(backups)
    }

    /// Atualiza o indicador `valido` (0/1) de um backup do usuário.
    pub fn marcar_backup_valido(
        &self,
        id: i64,
        usuario_id: i64,
        valido: bool,
    ) -> Result<(), DbError> {
        let alteradas = self.conn.execute(
            "UPDATE backup SET valido = ?3 WHERE id = ?1 AND usuario_id = ?2",
            params![id, usuario_id, valido],
        )?;
        if alteradas == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    /// Atualiza `ultima_restauracao_em` para o horário atual pelo ID do backup.
    pub fn marcar_backup_restaurado(&self, id: i64, usuario_id: i64) -> Result<(), DbError> {
        let alteradas = self.conn.execute(
            "UPDATE backup
             SET ultima_restauracao_em = datetime('now')
             WHERE id = ?1 AND usuario_id = ?2",
            params![id, usuario_id],
        )?;
        if alteradas == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    /// Atualiza `ultima_restauracao_em` nos registros do usuário cujo `caminho_arquivo`
    /// ou `hash_integridade` coincida com o backup restaurado.
    pub fn marcar_backup_restaurado_por_caminho_ou_hash(
        &self,
        usuario_id: i64,
        caminho_arquivo: &str,
        hash_integridade: &str,
    ) -> Result<usize, DbError> {
        let alteradas = self.conn.execute(
            "UPDATE backup
             SET ultima_restauracao_em = datetime('now')
             WHERE usuario_id = ?1 AND (caminho_arquivo = ?2 OR hash_integridade = ?3)",
            params![usuario_id, caminho_arquivo, hash_integridade],
        )?;
        Ok(alteradas)
    }

    /// Substitui todos os registros de backup do usuário pelos informados, mantendo
    /// os mesmos IDs.
    ///
    /// Usado na restauração: os backups são arquivos no disco, não conteúdo do
    /// cofre, então a lista do banco atual vale mais que a do banco restaurado
    /// (que nem conhece os backups feitos depois dele). Preservar o ID evita que
    /// `backup delete <id>` passe a apontar para outro arquivo após um restore.
    pub fn substituir_backups(&self, usuario_id: i64, backups: &[Backup]) -> Result<(), DbError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM backup WHERE usuario_id = ?1",
            params![usuario_id],
        )?;
        for b in backups {
            tx.execute(
                "INSERT INTO backup
                     (id, usuario_id, nome_arquivo, caminho_arquivo, hash_integridade,
                      tamanho_bytes, versao_formato, criado_em, ultima_restauracao_em, valido)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    b.id,
                    usuario_id,
                    b.nome_arquivo,
                    b.caminho_arquivo,
                    b.hash_integridade,
                    b.tamanho_bytes,
                    b.versao_formato,
                    b.criado_em,
                    b.ultima_restauracao_em,
                    b.valido,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Exclui o registro de um backup do usuário.
    pub fn excluir_backup(&self, id: i64, usuario_id: i64) -> Result<(), DbError> {
        let excluidas = self.conn.execute(
            "DELETE FROM backup WHERE id = ?1 AND usuario_id = ?2",
            params![id, usuario_id],
        )?;
        if excluidas == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NovoUsuario;

    fn preparar_db() -> (Database, i64) {
        let db = Database::open_in_memory().unwrap();
        let usuario_id = db
            .criar_usuario(&NovoUsuario {
                nome: "Alice",
                verificador_mestre: &[1],
                salt_kdf: &[2],
                parametros_kdf: "{}",
                dek_criptografada: &[3],
                dek_nonce: &[4],
                verificador_salt: &[5],
            })
            .unwrap();
        (db, usuario_id)
    }

    #[test]
    fn test_ciclo_completo_backup_repo() {
        let (db, u) = preparar_db();

        let id1 = db
            .registrar_backup(&NovoBackup {
                usuario_id: u,
                nome_arquivo: "cofre-backup-1.cbk",
                caminho_arquivo: "/tmp/cofre-backup-1.cbk",
                hash_integridade: "hash1",
                tamanho_bytes: 1024,
                versao_formato: "1",
            })
            .unwrap();

        let id2 = db
            .registrar_backup(&NovoBackup {
                usuario_id: u,
                nome_arquivo: "cofre-backup-2.cbk",
                caminho_arquivo: "/tmp/cofre-backup-2.cbk",
                hash_integridade: "hash2",
                tamanho_bytes: 2048,
                versao_formato: "1",
            })
            .unwrap();

        // Buscar por ID e usuário
        let b1 = db.buscar_backup(id1, u).unwrap();
        assert_eq!(b1.nome_arquivo, "cofre-backup-1.cbk");
        assert!(b1.valido);
        assert!(b1.ultima_restauracao_em.is_none());

        // Outro usuário não enxerga
        assert!(matches!(
            db.buscar_backup(id1, u + 99),
            Err(DbError::NotFound)
        ));

        // Listar (criado_em DESC, id DESC)
        let lista = db.listar_backups(u).unwrap();
        assert_eq!(lista.len(), 2);
        assert_eq!(lista[0].id, id2);
        assert_eq!(lista[1].id, id1);

        // Marcar válido = false e depois true
        db.marcar_backup_valido(id1, u, false).unwrap();
        assert!(!db.buscar_backup(id1, u).unwrap().valido);
        db.marcar_backup_valido(id1, u, true).unwrap();
        assert!(db.buscar_backup(id1, u).unwrap().valido);

        // Marcar restaurado
        db.marcar_backup_restaurado(id1, u).unwrap();
        assert!(db
            .buscar_backup(id1, u)
            .unwrap()
            .ultima_restauracao_em
            .is_some());

        // Marcar restaurado por caminho ou hash
        let alteradas = db
            .marcar_backup_restaurado_por_caminho_ou_hash(u, "/nao-existe", "hash2")
            .unwrap();
        assert_eq!(alteradas, 1);
        assert!(db
            .buscar_backup(id2, u)
            .unwrap()
            .ultima_restauracao_em
            .is_some());

        // Substituir backups mantendo os IDs de origem (fora de ordem de propósito)
        let b2 = db.buscar_backup(id2, u).unwrap();
        let mut b7 = b2.clone();
        b7.id = 7;
        b7.nome_arquivo = "cofre-backup-7.cbk".into();
        b7.caminho_arquivo = "/tmp/cofre-backup-7.cbk".into();
        b7.hash_integridade = "hash7".into();
        db.substituir_backups(u, &[b7.clone(), b2.clone()]).unwrap();
        assert_eq!(db.listar_backups(u).unwrap().len(), 2);
        assert_eq!(
            db.buscar_backup(7, u).unwrap().caminho_arquivo,
            b7.caminho_arquivo
        );
        assert_eq!(
            db.buscar_backup(id2, u).unwrap().caminho_arquivo,
            b2.caminho_arquivo
        );
        assert!(matches!(db.buscar_backup(id1, u), Err(DbError::NotFound)));
        db.substituir_backups(u, &[b2.clone(), b7.clone()]).unwrap();
        db.registrar_backup(&NovoBackup {
            usuario_id: u,
            nome_arquivo: "novo.cbk",
            caminho_arquivo: "/tmp/novo.cbk",
            hash_integridade: "hash-novo",
            tamanho_bytes: 1,
            versao_formato: "1",
        })
        .unwrap();
        assert_eq!(db.listar_backups(u).unwrap().len(), 3);

        // Excluir
        db.excluir_backup(7, u).unwrap();
        assert!(matches!(db.buscar_backup(7, u), Err(DbError::NotFound)));
        assert!(matches!(db.excluir_backup(7, u), Err(DbError::NotFound)));
    }
}
