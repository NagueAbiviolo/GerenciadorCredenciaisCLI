//! Repositório da tabela `sessao_navegador`.

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::{NovaSessaoNavegador, SessaoNavegador};

const COLUNAS: &str = "id, credencial_id, dispositivo_id, navegador, perfil_nome,
                       diretorio_perfil, iniciada_em, ultimo_uso_em, expira_em, ativa";

fn mapear_sessao(row: &Row<'_>) -> rusqlite::Result<SessaoNavegador> {
    Ok(SessaoNavegador {
        id: row.get(0)?,
        credencial_id: row.get(1)?,
        dispositivo_id: row.get(2)?,
        navegador: row.get(3)?,
        perfil_nome: row.get(4)?,
        diretorio_perfil: row.get(5)?,
        iniciada_em: row.get(6)?,
        ultimo_uso_em: row.get(7)?,
        expira_em: row.get(8)?,
        ativa: row.get(9)?,
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
    /// Registra uma nova sessão de navegador para uma credencial.
    pub fn criar_sessao_navegador(&self, nova: &NovaSessaoNavegador<'_>) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO sessao_navegador (
                 credencial_id, dispositivo_id, navegador, perfil_nome,
                 diretorio_perfil, ultimo_uso_em, ativa
             ) VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'), 1)",
            params![
                nova.credencial_id,
                nova.dispositivo_id,
                nova.navegador,
                nova.perfil_nome,
                nova.diretorio_perfil,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Lista as sessões de navegador vinculadas a uma credencial (ativas primeiro).
    pub fn listar_sessoes_navegador(
        &self,
        credencial_id: i64,
    ) -> Result<Vec<SessaoNavegador>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS} FROM sessao_navegador
             WHERE credencial_id = ?1
             ORDER BY ativa DESC, id DESC"
        ))?;
        let sessoes = stmt
            .query_map(params![credencial_id], mapear_sessao)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(sessoes)
    }

    /// Encerra uma sessão de navegador (`ativa = 0`) e atualiza `ultimo_uso_em`.
    pub fn encerrar_sessao_navegador(&self, id: i64) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE sessao_navegador
             SET ativa = 0, ultimo_uso_em = datetime('now')
             WHERE id = ?1",
            params![id],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NovaCredencial, NovoServico, NovoUsuario};

    fn preparar_banco() -> (Database, i64) {
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
        let servico_id = db
            .criar_servico(&NovoServico {
                categoria_id: None,
                nome: "GitHub".into(),
                dominio_principal: "github.com".into(),
                url_principal: None,
                descricao: None,
            })
            .unwrap();
        let credencial_id = db
            .criar_credencial(&NovaCredencial {
                usuario_id,
                servico_id,
                nome_exibicao: "GitHub Pessoal".into(),
                identificador: "user".into(),
                segredo_criptografado: vec![1, 2],
                nonce: vec![3, 4],
                observacao_criptografada: None,
                observacao_nonce: None,
                favorita: false,
            })
            .unwrap();
        (db, credencial_id)
    }

    #[test]
    fn test_inserir_listar_e_encerrar_sessao_navegador() {
        let (db, credencial_id) = preparar_banco();

        let id = db
            .criar_sessao_navegador(&NovaSessaoNavegador {
                credencial_id,
                dispositivo_id: None,
                navegador: "chromium",
                perfil_nome: Some("credencial-1"),
                diretorio_perfil: Some("/tmp/perfil-1"),
            })
            .unwrap();

        let lista = db.listar_sessoes_navegador(credencial_id).unwrap();
        assert_eq!(lista.len(), 1);
        assert_eq!(lista[0].id, id);
        assert_eq!(lista[0].navegador, "chromium");
        assert_eq!(lista[0].perfil_nome.as_deref(), Some("credencial-1"));
        assert_eq!(lista[0].diretorio_perfil.as_deref(), Some("/tmp/perfil-1"));
        assert!(lista[0].ativa);
        assert!(lista[0].ultimo_uso_em.is_some());

        db.encerrar_sessao_navegador(id).unwrap();

        let lista_apos = db.listar_sessoes_navegador(credencial_id).unwrap();
        assert_eq!(lista_apos.len(), 1);
        assert!(!lista_apos[0].ativa);

        // Encerrar ID inexistente retorna NotFound
        assert!(matches!(
            db.encerrar_sessao_navegador(id + 99),
            Err(DbError::NotFound)
        ));
    }
}
