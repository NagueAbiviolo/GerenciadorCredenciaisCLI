//! Repositório da tabela `dispositivo`.

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::{Dispositivo, NovoDispositivo};

const COLUNAS: &str = "id, usuario_id, nome, sistema_operacional, fingerprint_hash,
                       confiavel, primeiro_acesso_em, ultimo_acesso_em, ativo";

fn mapear_dispositivo(row: &Row<'_>) -> rusqlite::Result<Dispositivo> {
    Ok(Dispositivo {
        id: row.get(0)?,
        usuario_id: row.get(1)?,
        nome: row.get(2)?,
        sistema_operacional: row.get(3)?,
        fingerprint_hash: row.get(4)?,
        confiavel: row.get(5)?,
        primeiro_acesso_em: row.get(6)?,
        ultimo_acesso_em: row.get(7)?,
        ativo: row.get(8)?,
    })
}

impl Database {
    /// Busca um dispositivo pelo seu hash de fingerprint.
    pub fn buscar_dispositivo_por_fingerprint(
        &self,
        fingerprint_hash: &str,
    ) -> Result<Option<Dispositivo>, DbError> {
        let resultado = self.conn.query_row(
            &format!("SELECT {COLUNAS} FROM dispositivo WHERE fingerprint_hash = ?1"),
            params![fingerprint_hash],
            mapear_dispositivo,
        );

        match resultado {
            Ok(disp) => Ok(Some(disp)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DbError::Sqlite(e)),
        }
    }

    /// Registra um novo dispositivo para o usuário.
    pub fn criar_dispositivo(&self, novo: &NovoDispositivo) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO dispositivo
                 (usuario_id, nome, sistema_operacional, fingerprint_hash, confiavel, ultimo_acesso_em)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))",
            params![
                novo.usuario_id,
                novo.nome,
                novo.sistema_operacional,
                novo.fingerprint_hash,
                novo.confiavel,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Atualiza a data/hora de último acesso de um dispositivo.
    pub fn atualizar_ultimo_acesso_dispositivo(&self, id: i64) -> Result<(), DbError> {
        let alteradas = self.conn.execute(
            "UPDATE dispositivo SET ultimo_acesso_em = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        if alteradas == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    /// Lista todos os dispositivos vinculados a um usuário.
    pub fn listar_dispositivos(&self, usuario_id: i64) -> Result<Vec<Dispositivo>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS} FROM dispositivo
             WHERE usuario_id = ?1
             ORDER BY confiavel DESC, id"
        ))?;

        let dispositivos = stmt
            .query_map(params![usuario_id], mapear_dispositivo)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(dispositivos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NovoUsuario;

    #[test]
    fn test_criar_buscar_atualizar_e_listar_dispositivos() {
        let db = Database::open_in_memory().unwrap();
        let usuario_id = db
            .criar_usuario(&NovoUsuario {
                nome: "Teste",
                verificador_mestre: &[1, 2, 3],
                salt_kdf: &[4, 5, 6],
                parametros_kdf: "{}",
                dek_criptografada: &[7, 8, 9],
                dek_nonce: &[10, 11, 12],
                verificador_salt: &[13, 14, 15],
            })
            .unwrap();

        assert!(db
            .buscar_dispositivo_por_fingerprint("fp-1")
            .unwrap()
            .is_none());

        let id1 = db
            .criar_dispositivo(&NovoDispositivo {
                usuario_id,
                nome: "notebook".into(),
                sistema_operacional: Some("linux".into()),
                fingerprint_hash: Some("fp-1".into()),
                confiavel: true,
            })
            .unwrap();

        let disp = db
            .buscar_dispositivo_por_fingerprint("fp-1")
            .unwrap()
            .expect("dispositivo deveria existir");
        assert_eq!(disp.id, id1);
        assert_eq!(disp.nome, "notebook");
        assert!(disp.confiavel);
        assert!(disp.ativo);

        db.atualizar_ultimo_acesso_dispositivo(id1).unwrap();

        let id2 = db
            .criar_dispositivo(&NovoDispositivo {
                usuario_id,
                nome: "desktop".into(),
                sistema_operacional: Some("windows".into()),
                fingerprint_hash: Some("fp-2".into()),
                confiavel: false,
            })
            .unwrap();

        let lista = db.listar_dispositivos(usuario_id).unwrap();
        assert_eq!(lista.len(), 2);
        assert_eq!(lista[0].id, id1);
        assert_eq!(lista[1].id, id2);
    }
}
