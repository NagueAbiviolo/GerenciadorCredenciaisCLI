//! Repositório da tabela `historico_credencial`.
//!
//! Registra alterações relevantes realizadas em uma credencial (RF10).

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::{HistoricoCredencial, NovoHistoricoCredencial};

const COLUNAS: &str = "id, credencial_id, tipo_alteracao, valor_anterior_criptografado,
                       nonce, motivo, alterado_em";

fn mapear_historico(row: &Row<'_>) -> rusqlite::Result<HistoricoCredencial> {
    Ok(HistoricoCredencial {
        id: row.get(0)?,
        credencial_id: row.get(1)?,
        tipo_alteracao: row.get(2)?,
        valor_anterior_criptografado: row.get(3)?,
        nonce: row.get(4)?,
        motivo: row.get(5)?,
        alterado_em: row.get(6)?,
    })
}

impl Database {
    /// Insere um novo registro no histórico da credencial e retorna o ID gerado.
    pub fn inserir_historico_credencial(
        &self,
        novo: &NovoHistoricoCredencial<'_>,
    ) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO historico_credencial
                 (credencial_id, tipo_alteracao, valor_anterior_criptografado, nonce, motivo)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                novo.credencial_id,
                novo.tipo_alteracao,
                novo.valor_anterior_criptografado,
                novo.nonce,
                novo.motivo,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Atualiza o valor anterior cifrado e o nonce de um registro de histórico pelo ID.
    pub fn atualizar_valor_historico_credencial(
        &self,
        id: i64,
        valor_anterior_criptografado: &[u8],
        nonce: &[u8],
    ) -> Result<(), DbError> {
        let alteradas = self.conn.execute(
            "UPDATE historico_credencial
             SET valor_anterior_criptografado = ?2, nonce = ?3
             WHERE id = ?1",
            params![id, valor_anterior_criptografado, nonce],
        )?;
        if alteradas == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    /// Lista o histórico de uma credencial ordenado por `alterado_em DESC, id DESC`.
    pub fn listar_historico_credencial(
        &self,
        credencial_id: i64,
    ) -> Result<Vec<HistoricoCredencial>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS} FROM historico_credencial
             WHERE credencial_id = ?1
             ORDER BY alterado_em DESC, id DESC"
        ))?;

        let itens = stmt
            .query_map(params![credencial_id], mapear_historico)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(itens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NovaCredencial, NovoServico, NovoUsuario};

    #[test]
    fn test_inserir_atualizar_e_listar_historico() {
        let db = Database::open_in_memory().unwrap();
        let u = db
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
        let s = db
            .criar_servico(&NovoServico {
                categoria_id: None,
                nome: "GitHub".into(),
                dominio_principal: "github.com".into(),
                url_principal: None,
                descricao: None,
            })
            .unwrap();
        let c = db
            .criar_credencial(&NovaCredencial {
                usuario_id: u,
                servico_id: s,
                nome_exibicao: "Conta".into(),
                identificador: "alice".into(),
                segredo_criptografado: vec![1],
                nonce: vec![2],
                observacao_criptografada: None,
                observacao_nonce: None,
                favorita: false,
            })
            .unwrap();

        let h1 = db
            .inserir_historico_credencial(&NovoHistoricoCredencial {
                credencial_id: c,
                tipo_alteracao: "SENHA",
                valor_anterior_criptografado: None,
                nonce: None,
                motivo: Some("Troca periódica"),
            })
            .unwrap();

        db.atualizar_valor_historico_credencial(h1, &[9, 9, 9], &[8, 8, 8])
            .unwrap();

        let h2 = db
            .inserir_historico_credencial(&NovoHistoricoCredencial {
                credencial_id: c,
                tipo_alteracao: "ATIVACAO",
                valor_anterior_criptografado: None,
                nonce: None,
                motivo: Some("Desativada"),
            })
            .unwrap();

        let lista = db.listar_historico_credencial(c).unwrap();
        assert_eq!(lista.len(), 2);
        assert_eq!(lista[0].id, h2);
        assert_eq!(lista[0].tipo_alteracao, "ATIVACAO");
        assert!(lista[0].valor_anterior_criptografado.is_none());

        assert_eq!(lista[1].id, h1);
        assert_eq!(lista[1].tipo_alteracao, "SENHA");
        assert_eq!(
            lista[1].valor_anterior_criptografado.as_deref(),
            Some(&[9, 9, 9][..])
        );
        assert_eq!(lista[1].nonce.as_deref(), Some(&[8, 8, 8][..]));
        assert_eq!(lista[1].motivo.as_deref(), Some("Troca periódica"));
    }
}
