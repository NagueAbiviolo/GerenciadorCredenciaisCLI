//! Repositório da tabela `alerta_seguranca` (RF12).
//!
//! A tabela `alerta_seguranca` não possui coluna `usuario_id`: alertas com
//! `credencial_id` pertencem ao dono da credencial (`JOIN credencial`), enquanto
//! alertas com `credencial_id IS NULL` são alertas gerais do cofre e pertencem
//! ao usuário ativo.

use rusqlite::{params, params_from_iter, types::Value, Row};

use crate::connection::{Database, DbError};
use crate::models::{AlertaSeguranca, FiltroAlerta, NovoAlerta};

const COLUNAS: &str = "a.id, a.credencial_id, a.tipo, a.nivel, a.titulo,
                       a.mensagem, a.criado_em, a.resolvido, a.resolvido_em";

fn mapear_alerta(row: &Row<'_>) -> rusqlite::Result<AlertaSeguranca> {
    Ok(AlertaSeguranca {
        id: row.get(0)?,
        credencial_id: row.get(1)?,
        tipo: row.get(2)?,
        nivel: row.get(3)?,
        titulo: row.get(4)?,
        mensagem: row.get(5)?,
        criado_em: row.get(6)?,
        resolvido: row.get(7)?,
        resolvido_em: row.get(8)?,
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
    /// Cria um novo alerta de segurança (inicialmente em aberto).
    pub fn criar_alerta(&self, novo: &NovoAlerta<'_>) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO alerta_seguranca (credencial_id, tipo, nivel, titulo, mensagem)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                novo.credencial_id,
                novo.tipo,
                novo.nivel,
                novo.titulo,
                novo.mensagem,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Busca um alerta de segurança pelo ID, garantindo que pertence ao usuário
    /// (ou é um alerta geral sem credencial associada).
    pub fn buscar_alerta(&self, id: i64, usuario_id: i64) -> Result<AlertaSeguranca, DbError> {
        self.conn
            .query_row(
                &format!(
                    "SELECT {COLUNAS}
                     FROM alerta_seguranca a
                     LEFT JOIN credencial c ON a.credencial_id = c.id
                     WHERE a.id = ?1 AND (a.credencial_id IS NULL OR c.usuario_id = ?2)"
                ),
                params![id, usuario_id],
                mapear_alerta,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })
    }

    /// Lista alertas de segurança do usuário (incluindo alertas gerais com `credencial_id IS NULL`)
    /// aplicando filtros opcionais e ordenando por:
    /// 1. abertos primeiro (`resolvido ASC`),
    /// 2. nível (`CRITICO > ALTO > MEDIO > BAIXO`),
    /// 3. `criado_em DESC, id DESC`.
    pub fn listar_alertas(
        &self,
        usuario_id: i64,
        filtro: &FiltroAlerta<'_>,
    ) -> Result<Vec<AlertaSeguranca>, DbError> {
        let mut sql = format!(
            "SELECT {COLUNAS}
             FROM alerta_seguranca a
             LEFT JOIN credencial c ON a.credencial_id = c.id
             WHERE (a.credencial_id IS NULL OR c.usuario_id = ?)"
        );
        let mut valores: Vec<Value> = vec![Value::Integer(usuario_id)];

        if filtro.apenas_abertos {
            sql.push_str(" AND a.resolvido = 0");
        }

        if let Some(tipo) = filtro.tipo {
            sql.push_str(" AND a.tipo = ?");
            valores.push(Value::Text(tipo.to_string()));
        }

        if let Some(nivel) = filtro.nivel {
            sql.push_str(" AND a.nivel = ?");
            valores.push(Value::Text(nivel.to_string()));
        }

        sql.push_str(
            " ORDER BY a.resolvido ASC,
                       CASE a.nivel
                           WHEN 'CRITICO' THEN 1
                           WHEN 'ALTO' THEN 2
                           WHEN 'MEDIO' THEN 3
                           WHEN 'BAIXO' THEN 4
                           ELSE 5
                       END ASC,
                       a.criado_em DESC,
                       a.id DESC",
        );

        let mut stmt = self.conn.prepare(&sql)?;
        let alertas = stmt
            .query_map(params_from_iter(valores), mapear_alerta)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(alertas)
    }

    /// Busca um alerta **aberto** (`resolvido = 0`) por `(tipo, credencial_id)` pertencente ao usuário.
    pub fn buscar_alerta_aberto(
        &self,
        usuario_id: i64,
        tipo: &str,
        credencial_id: Option<i64>,
    ) -> Result<Option<AlertaSeguranca>, DbError> {
        let res = match credencial_id {
            Some(cid) => self.conn.query_row(
                &format!(
                    "SELECT {COLUNAS}
                     FROM alerta_seguranca a
                     INNER JOIN credencial c ON a.credencial_id = c.id
                     WHERE a.resolvido = 0
                       AND a.tipo = ?1
                       AND a.credencial_id = ?2
                       AND c.usuario_id = ?3
                     ORDER BY a.criado_em DESC, a.id DESC
                     LIMIT 1"
                ),
                params![tipo, cid, usuario_id],
                mapear_alerta,
            ),
            None => self.conn.query_row(
                &format!(
                    "SELECT {COLUNAS}
                     FROM alerta_seguranca a
                     WHERE a.resolvido = 0
                       AND a.tipo = ?1
                       AND a.credencial_id IS NULL
                     ORDER BY a.criado_em DESC, a.id DESC
                     LIMIT 1"
                ),
                params![tipo],
                mapear_alerta,
            ),
        };

        match res {
            Ok(alerta) => Ok(Some(alerta)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(other) => Err(DbError::Sqlite(other)),
        }
    }

    /// Atualiza título, mensagem e nível de um alerta existente.
    pub fn atualizar_alerta(
        &self,
        id: i64,
        nivel: &str,
        titulo: &str,
        mensagem: &str,
    ) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE alerta_seguranca
             SET nivel = ?2, titulo = ?3, mensagem = ?4
             WHERE id = ?1",
            params![id, nivel, titulo, mensagem],
        )?)
    }

    /// Marca um alerta como resolvido (`resolvido = 1, resolvido_em = datetime('now')`).
    pub fn resolver_alerta(&self, id: i64) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE alerta_seguranca
             SET resolvido = 1,
                 resolvido_em = COALESCE(resolvido_em, datetime('now'))
             WHERE id = ?1",
            params![id],
        )?)
    }

    /// Exclui um alerta de segurança pelo ID.
    pub fn excluir_alerta(&self, id: i64) -> Result<(), DbError> {
        exigir_alteracao(
            self.conn
                .execute("DELETE FROM alerta_seguranca WHERE id = ?1", params![id])?,
        )
    }

    /// Exclui todos os alertas vinculados a uma credencial (necessário antes de excluir
    /// a credencial, pois `alerta_seguranca.credencial_id` não possui `ON DELETE`).
    pub fn excluir_alertas_credencial(&self, credencial_id: i64) -> Result<usize, DbError> {
        let removidos = self.conn.execute(
            "DELETE FROM alerta_seguranca WHERE credencial_id = ?1",
            params![credencial_id],
        )?;
        Ok(removidos)
    }

    /// Conta quantos alertas abertos (`resolvido = 0`) existem para o usuário
    /// (incluindo alertas gerais com `credencial_id IS NULL`).
    pub fn contar_alertas_abertos(&self, usuario_id: i64) -> Result<usize, DbError> {
        let total: i64 = self.conn.query_row(
            "SELECT COUNT(*)
             FROM alerta_seguranca a
             LEFT JOIN credencial c ON a.credencial_id = c.id
             WHERE a.resolvido = 0 AND (a.credencial_id IS NULL OR c.usuario_id = ?1)",
            params![usuario_id],
            |r| r.get(0),
        )?;
        Ok(usize::try_from(total).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NovaCredencial, NovoServico, NovoUsuario};

    fn preparar_db() -> (Database, i64, i64) {
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
        let servico_id = db
            .criar_servico(&NovoServico {
                categoria_id: None,
                nome: "GitHub".into(),
                dominio_principal: "github.com".into(),
                url_principal: None,
                descricao: None,
            })
            .unwrap();
        let cred_id = db
            .criar_credencial(&NovaCredencial {
                usuario_id,
                servico_id,
                nome_exibicao: "Conta".into(),
                identificador: "alice".into(),
                segredo_criptografado: vec![1, 2],
                nonce: vec![3, 4],
                observacao_criptografada: None,
                observacao_nonce: None,
                favorita: false,
            })
            .unwrap();
        (db, usuario_id, cred_id)
    }

    #[test]
    fn test_crud_filtros_ordenacao_e_contagem_alertas() {
        let (db, u, c) = preparar_db();

        let id_baixo = db
            .criar_alerta(&NovoAlerta {
                credencial_id: Some(c),
                tipo: "RECUPERACAO_DESATUALIZADA",
                nivel: "BAIXO",
                titulo: "Recuperação desatualizada",
                mensagem: "Sem e-mail",
            })
            .unwrap();

        let id_alto = db
            .criar_alerta(&NovoAlerta {
                credencial_id: Some(c),
                tipo: "SENHA_REUTILIZADA",
                nivel: "ALTO",
                titulo: "Senha reutilizada",
                mensagem: "Repetida",
            })
            .unwrap();

        let id_geral = db
            .criar_alerta(&NovoAlerta {
                credencial_id: None,
                tipo: "GERAL",
                nivel: "CRITICO",
                titulo: "Alerta geral",
                mensagem: "Geral",
            })
            .unwrap();

        assert_eq!(db.contar_alertas_abertos(u).unwrap(), 3);

        // Ordenação: CRITICO > ALTO > BAIXO
        let abertos = db
            .listar_alertas(
                u,
                &FiltroAlerta {
                    apenas_abertos: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            abertos.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![id_geral, id_alto, id_baixo]
        );

        // Buscar aberto por (tipo, credencial_id)
        let achado = db
            .buscar_alerta_aberto(u, "SENHA_REUTILIZADA", Some(c))
            .unwrap()
            .unwrap();
        assert_eq!(achado.id, id_alto);

        // Atualizar alerta
        db.atualizar_alerta(id_baixo, "MEDIO", "Novo título", "Nova mensagem")
            .unwrap();
        let atualizado = db.buscar_alerta(id_baixo, u).unwrap();
        assert_eq!(atualizado.nivel, "MEDIO");
        assert_eq!(atualizado.titulo, "Novo título");
        assert_eq!(atualizado.mensagem, "Nova mensagem");

        // Resolver alerta
        db.resolver_alerta(id_alto).unwrap();
        let resolvido = db.buscar_alerta(id_alto, u).unwrap();
        assert!(resolvido.resolvido);
        assert!(resolvido.resolvido_em.is_some());
        assert!(db
            .buscar_alerta_aberto(u, "SENHA_REUTILIZADA", Some(c))
            .unwrap()
            .is_none());
        assert_eq!(db.contar_alertas_abertos(u).unwrap(), 2);

        // Listar todos: abertos primeiro (CRITICO, MEDIO), depois resolvido (ALTO)
        let todos = db.listar_alertas(u, &FiltroAlerta::default()).unwrap();
        assert_eq!(
            todos.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![id_geral, id_baixo, id_alto]
        );

        // Outro usuário não vê alertas de credencial de `u`, mas vê alerta geral (credencial_id IS NULL)
        assert!(matches!(
            db.buscar_alerta(id_baixo, u + 99),
            Err(DbError::NotFound)
        ));
        assert!(db.buscar_alerta(id_geral, u + 99).is_ok());

        // Excluir alerta individual e por credencial
        db.excluir_alerta(id_geral).unwrap();
        assert_eq!(db.excluir_alertas_credencial(c).unwrap(), 2);
        assert!(db
            .listar_alertas(u, &FiltroAlerta::default())
            .unwrap()
            .is_empty());
    }
}
