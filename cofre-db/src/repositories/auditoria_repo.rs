//! Repositório da tabela `evento_auditoria`.
//!
//! Registra eventos relevantes sem armazenar segredos (RNF05/RNF11).

use rusqlite::{params, params_from_iter, types::Value, Row};

use crate::connection::{Database, DbError};
use crate::models::{EventoAuditoria, FiltroAuditoria, NovoEventoAuditoria};

const COLUNAS: &str = "id, usuario_id, credencial_id, dispositivo_id, tipo_evento,
                       resultado, descricao, ocorrido_em";

fn mapear_evento(row: &Row<'_>) -> rusqlite::Result<EventoAuditoria> {
    Ok(EventoAuditoria {
        id: row.get(0)?,
        usuario_id: row.get(1)?,
        credencial_id: row.get(2)?,
        dispositivo_id: row.get(3)?,
        tipo_evento: row.get(4)?,
        resultado: row.get(5)?,
        descricao: row.get(6)?,
        ocorrido_em: row.get(7)?,
    })
}

impl Database {
    /// Registra um novo evento de auditoria.
    pub fn registrar_evento_auditoria(
        &self,
        novo: &NovoEventoAuditoria<'_>,
    ) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO evento_auditoria
                 (usuario_id, credencial_id, dispositivo_id, tipo_evento, resultado, descricao)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                novo.usuario_id,
                novo.credencial_id,
                novo.dispositivo_id,
                novo.tipo_evento,
                novo.resultado,
                novo.descricao,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Lista eventos de auditoria do usuário aplicando filtros opcionais,
    /// ordenados por `ocorrido_em DESC, id DESC`.
    pub fn listar_eventos_auditoria(
        &self,
        usuario_id: i64,
        filtro: &FiltroAuditoria<'_>,
    ) -> Result<Vec<EventoAuditoria>, DbError> {
        let mut sql = format!("SELECT {COLUNAS} FROM evento_auditoria WHERE usuario_id = ?");
        let mut valores: Vec<Value> = vec![Value::Integer(usuario_id)];

        if let Some(tipo) = filtro.tipo_evento {
            sql.push_str(" AND tipo_evento = ?");
            valores.push(Value::Text(tipo.to_string()));
        }

        if let Some(cred_id) = filtro.credencial_id {
            sql.push_str(" AND credencial_id = ?");
            valores.push(Value::Integer(cred_id));
        }

        if let Some(desde) = filtro.desde {
            sql.push_str(" AND date(ocorrido_em) >= ?");
            valores.push(Value::Text(desde.format("%Y-%m-%d").to_string()));
        }

        sql.push_str(" ORDER BY ocorrido_em DESC, id DESC");

        if let Some(limite) = filtro.limite {
            sql.push_str(" LIMIT ?");
            valores.push(Value::Integer(limite as i64));
        }

        let mut stmt = self.conn.prepare(&sql)?;
        let eventos = stmt
            .query_map(params_from_iter(valores), mapear_evento)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(eventos)
    }

    /// Desvincula os eventos de auditoria de uma credencial (`credencial_id = NULL`),
    /// permitindo excluir a credencial sem violar a chave estrangeira e preservando o histórico de auditoria.
    pub fn desvincular_credencial_auditoria(&self, credencial_id: i64) -> Result<usize, DbError> {
        let alteradas = self.conn.execute(
            "UPDATE evento_auditoria SET credencial_id = NULL WHERE credencial_id = ?1",
            params![credencial_id],
        )?;
        Ok(alteradas)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NovaCredencial, NovoServico, NovoUsuario};
    use chrono::NaiveDate;

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
    fn test_registrar_listar_filtrar_e_desvincular_auditoria() {
        let (db, u, c) = preparar_db();

        let id1 = db
            .registrar_evento_auditoria(&NovoEventoAuditoria {
                usuario_id: u,
                credencial_id: Some(c),
                dispositivo_id: None,
                tipo_evento: "CRIACAO",
                resultado: "SUCESSO",
                descricao: Some("Credencial criada"),
            })
            .unwrap();

        let id2 = db
            .registrar_evento_auditoria(&NovoEventoAuditoria {
                usuario_id: u,
                credencial_id: Some(c),
                dispositivo_id: None,
                tipo_evento: "COPIA_SEGREDO",
                resultado: "SUCESSO",
                descricao: Some("Senha copiada"),
            })
            .unwrap();

        let id3 = db
            .registrar_evento_auditoria(&NovoEventoAuditoria {
                usuario_id: u,
                credencial_id: None,
                dispositivo_id: None,
                tipo_evento: "DESBLOQUEIO",
                resultado: "FALHA",
                descricao: Some("Senha inválida"),
            })
            .unwrap();

        // Ordenação: id DESC quando ocorrido_em é igual
        let todos = db
            .listar_eventos_auditoria(u, &FiltroAuditoria::default())
            .unwrap();
        assert_eq!(todos.len(), 3);
        assert_eq!(todos[0].id, id3);
        assert_eq!(todos[1].id, id2);
        assert_eq!(todos[2].id, id1);

        // Filtro por tipo
        let por_tipo = db
            .listar_eventos_auditoria(
                u,
                &FiltroAuditoria {
                    tipo_evento: Some("COPIA_SEGREDO"),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(por_tipo.len(), 1);
        assert_eq!(por_tipo[0].id, id2);

        // Filtro por credencial_id
        let por_cred = db
            .listar_eventos_auditoria(
                u,
                &FiltroAuditoria {
                    credencial_id: Some(c),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(por_cred.len(), 2);

        // Filtro por data (desde no futuro não retorna nada)
        let futuro = NaiveDate::from_ymd_opt(2099, 1, 1).unwrap();
        let por_data = db
            .listar_eventos_auditoria(
                u,
                &FiltroAuditoria {
                    desde: Some(futuro),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(por_data.is_empty());

        // Filtro por limite
        let limitados = db
            .listar_eventos_auditoria(
                u,
                &FiltroAuditoria {
                    limite: Some(2),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(limitados.len(), 2);

        // Desvincular credencial
        let desvinculados = db.desvincular_credencial_auditoria(c).unwrap();
        assert_eq!(desvinculados, 2);

        let apos = db
            .listar_eventos_auditoria(
                u,
                &FiltroAuditoria {
                    credencial_id: Some(c),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(apos.is_empty());
    }
}
