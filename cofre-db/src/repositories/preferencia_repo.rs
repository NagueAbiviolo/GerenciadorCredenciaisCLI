//! Repositório da tabela `preferencia`.

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::{NovaPreferencia, Preferencia};

const COLUNAS: &str = "id, usuario_id, chave, valor, tipo_valor, descricao, atualizado_em";

fn mapear_preferencia(row: &Row<'_>) -> rusqlite::Result<Preferencia> {
    Ok(Preferencia {
        id: row.get(0)?,
        usuario_id: row.get(1)?,
        chave: row.get(2)?,
        valor: row.get(3)?,
        tipo_valor: row.get(4)?,
        descricao: row.get(5)?,
        atualizado_em: row.get(6)?,
    })
}

impl Database {
    /// Busca uma preferência do usuário pela chave.
    pub fn buscar_preferencia(
        &self,
        usuario_id: i64,
        chave: &str,
    ) -> Result<Option<Preferencia>, DbError> {
        let resultado = self.conn.query_row(
            &format!("SELECT {COLUNAS} FROM preferencia WHERE usuario_id = ?1 AND chave = ?2"),
            params![usuario_id, chave],
            mapear_preferencia,
        );

        match resultado {
            Ok(pref) => Ok(Some(pref)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DbError::Sqlite(e)),
        }
    }

    /// Lista todas as preferências salvas de um usuário, ordenadas pela chave.
    pub fn listar_preferencias(&self, usuario_id: i64) -> Result<Vec<Preferencia>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS} FROM preferencia
             WHERE usuario_id = ?1
             ORDER BY chave"
        ))?;

        let preferencias = stmt
            .query_map(params![usuario_id], mapear_preferencia)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(preferencias)
    }

    /// Define (insere ou atualiza via upsert) uma preferência do usuário.
    pub fn definir_preferencia(&self, nova: &NovaPreferencia<'_>) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO preferencia (usuario_id, chave, valor, tipo_valor, descricao)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(usuario_id, chave) DO UPDATE SET
                 valor = excluded.valor,
                 tipo_valor = excluded.tipo_valor,
                 descricao = excluded.descricao,
                 atualizado_em = datetime('now')",
            params![
                nova.usuario_id,
                nova.chave,
                nova.valor,
                nova.tipo_valor,
                nova.descricao,
            ],
        )?;
        Ok(())
    }

    /// Remove uma preferência do usuário. Retorna `true` se uma linha foi removida.
    pub fn remover_preferencia(&self, usuario_id: i64, chave: &str) -> Result<bool, DbError> {
        let alteradas = self.conn.execute(
            "DELETE FROM preferencia WHERE usuario_id = ?1 AND chave = ?2",
            params![usuario_id, chave],
        )?;
        Ok(alteradas > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NovoUsuario;

    fn criar_usuario_teste(db: &Database, nome: &str) -> i64 {
        db.criar_usuario(&NovoUsuario {
            nome,
            verificador_mestre: &[1, 2, 3],
            salt_kdf: &[4, 5, 6],
            parametros_kdf: "{}",
            dek_criptografada: &[7, 8, 9],
            dek_nonce: &[10, 11, 12],
            verificador_salt: &[13, 14, 15],
        })
        .unwrap()
    }

    #[test]
    fn test_buscar_definir_upsert_listar_e_remover_preferencias() {
        let db = Database::open_in_memory().unwrap();
        let u1 = criar_usuario_teste(&db, "Alice");
        let u2 = criar_usuario_teste(&db, "Bob");

        assert!(db
            .buscar_preferencia(u1, "tempo_clipboard")
            .unwrap()
            .is_none());
        assert!(db.listar_preferencias(u1).unwrap().is_empty());

        // Inserção inicial
        db.definir_preferencia(&NovaPreferencia {
            usuario_id: u1,
            chave: "tempo_clipboard",
            valor: "30",
            tipo_valor: "INTEGER",
            descricao: Some("Segundos até limpar a área de transferência"),
        })
        .unwrap();

        let p = db
            .buscar_preferencia(u1, "tempo_clipboard")
            .unwrap()
            .expect("preferência deveria existir");
        assert_eq!(p.usuario_id, u1);
        assert_eq!(p.chave, "tempo_clipboard");
        assert_eq!(p.valor, "30");
        assert_eq!(p.tipo_valor, "INTEGER");
        assert_eq!(
            p.descricao.as_deref(),
            Some("Segundos até limpar a área de transferência")
        );

        // Isolamento por usuário
        assert!(db
            .buscar_preferencia(u2, "tempo_clipboard")
            .unwrap()
            .is_none());

        // Upsert (atualiza valor e descrição sem duplicar)
        db.definir_preferencia(&NovaPreferencia {
            usuario_id: u1,
            chave: "tempo_clipboard",
            valor: "45",
            tipo_valor: "INTEGER",
            descricao: Some("Nova descrição"),
        })
        .unwrap();

        let p_atualizada = db
            .buscar_preferencia(u1, "tempo_clipboard")
            .unwrap()
            .unwrap();
        assert_eq!(p_atualizada.id, p.id);
        assert_eq!(p_atualizada.valor, "45");
        assert_eq!(p_atualizada.descricao.as_deref(), Some("Nova descrição"));

        // Segunda preferência para testar listagem ordenada por chave
        db.definir_preferencia(&NovaPreferencia {
            usuario_id: u1,
            chave: "navegador_padrao",
            valor: "brave",
            tipo_valor: "TEXT",
            descricao: None,
        })
        .unwrap();

        let lista = db.listar_preferencias(u1).unwrap();
        assert_eq!(lista.len(), 2);
        assert_eq!(lista[0].chave, "navegador_padrao");
        assert_eq!(lista[1].chave, "tempo_clipboard");

        // Remoção
        assert!(db.remover_preferencia(u1, "tempo_clipboard").unwrap());
        assert!(!db.remover_preferencia(u1, "tempo_clipboard").unwrap());
        assert!(db
            .buscar_preferencia(u1, "tempo_clipboard")
            .unwrap()
            .is_none());
        assert_eq!(db.listar_preferencias(u1).unwrap().len(), 1);
    }
}
