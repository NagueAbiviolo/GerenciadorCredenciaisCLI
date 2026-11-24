//! Repositório da tabela `configuracao_login`.

use rusqlite::{params, Row};

use crate::connection::{Database, DbError};
use crate::models::{ConfiguracaoLogin, NovaConfiguracaoLogin};

const COLUNAS: &str = "id, credencial_id, url_servico_id, seletor_usuario, seletor_senha,
                       seletor_botao, url_sucesso, envio_automatico, timeout_segundos,
                       ultima_validacao_em, criado_em, atualizado_em, ativa";

fn mapear_configuracao(row: &Row<'_>) -> rusqlite::Result<ConfiguracaoLogin> {
    Ok(ConfiguracaoLogin {
        id: row.get(0)?,
        credencial_id: row.get(1)?,
        url_servico_id: row.get(2)?,
        seletor_usuario: row.get(3)?,
        seletor_senha: row.get(4)?,
        seletor_botao: row.get(5)?,
        url_sucesso: row.get(6)?,
        envio_automatico: row.get(7)?,
        timeout_segundos: row.get(8)?,
        ultima_validacao_em: row.get(9)?,
        criado_em: row.get(10)?,
        atualizado_em: row.get(11)?,
        ativa: row.get(12)?,
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
    /// Insere uma nova configuração de login para uma credencial.
    pub fn criar_configuracao_login(&self, nova: &NovaConfiguracaoLogin) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO configuracao_login (
                 credencial_id, url_servico_id, seletor_usuario, seletor_senha,
                 seletor_botao, url_sucesso, envio_automatico, timeout_segundos, ativa
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                nova.credencial_id,
                nova.url_servico_id,
                nova.seletor_usuario,
                nova.seletor_senha,
                nova.seletor_botao,
                nova.url_sucesso,
                nova.envio_automatico,
                nova.timeout_segundos,
                nova.ativa,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Busca uma configuração de login pelo ID.
    pub fn buscar_configuracao_login(&self, id: i64) -> Result<ConfiguracaoLogin, DbError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUNAS} FROM configuracao_login WHERE id = ?1"),
                params![id],
                mapear_configuracao,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::NotFound,
                other => DbError::Sqlite(other),
            })
    }

    /// Lista as configurações de login vinculadas a uma credencial (ativas primeiro).
    pub fn listar_configuracoes_login(
        &self,
        credencial_id: i64,
    ) -> Result<Vec<ConfiguracaoLogin>, DbError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUNAS} FROM configuracao_login
             WHERE credencial_id = ?1
             ORDER BY ativa DESC, id"
        ))?;
        let configs = stmt
            .query_map(params![credencial_id], mapear_configuracao)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(configs)
    }

    /// Atualiza os campos de uma configuração de login.
    #[allow(clippy::too_many_arguments)]
    pub fn atualizar_configuracao_login(
        &self,
        id: i64,
        url_servico_id: i64,
        seletor_usuario: Option<&str>,
        seletor_senha: Option<&str>,
        seletor_botao: Option<&str>,
        url_sucesso: Option<&str>,
        envio_automatico: bool,
        timeout_segundos: i64,
        ativa: bool,
    ) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE configuracao_login
             SET url_servico_id = ?2,
                 seletor_usuario = ?3,
                 seletor_senha = ?4,
                 seletor_botao = ?5,
                 url_sucesso = ?6,
                 envio_automatico = ?7,
                 timeout_segundos = ?8,
                 ativa = ?9,
                 atualizado_em = datetime('now')
             WHERE id = ?1",
            params![
                id,
                url_servico_id,
                seletor_usuario,
                seletor_senha,
                seletor_botao,
                url_sucesso,
                envio_automatico,
                timeout_segundos,
                ativa,
            ],
        )?)
    }

    /// Marca `ultima_validacao_em` com o timestamp atual para uma configuração de login.
    pub fn marcar_validacao_configuracao_login(&self, id: i64) -> Result<(), DbError> {
        exigir_alteracao(self.conn.execute(
            "UPDATE configuracao_login
             SET ultima_validacao_em = datetime('now'),
                 atualizado_em = datetime('now')
             WHERE id = ?1",
            params![id],
        )?)
    }

    /// Exclui uma configuração de login pelo ID.
    pub fn excluir_configuracao_login(&self, id: i64) -> Result<(), DbError> {
        exigir_alteracao(
            self.conn
                .execute("DELETE FROM configuracao_login WHERE id = ?1", params![id])?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{NovaCredencial, NovaUrlServico, NovoServico, NovoUsuario};

    fn preparar_banco() -> (Database, i64, i64, i64) {
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
                nome: "Netflix".into(),
                dominio_principal: "netflix.com".into(),
                url_principal: None,
                descricao: None,
            })
            .unwrap();
        let url_id = db
            .criar_url_servico(&NovaUrlServico {
                servico_id,
                url: "https://www.netflix.com/login".into(),
                tipo: "LOGIN".into(),
                descricao: None,
                padrao: true,
            })
            .unwrap();
        let credencial_id = db
            .criar_credencial(&NovaCredencial {
                usuario_id,
                servico_id,
                nome_exibicao: "Netflix Pessoal".into(),
                identificador: "user@example.com".into(),
                segredo_criptografado: vec![1, 2],
                nonce: vec![3, 4],
                observacao_criptografada: None,
                observacao_nonce: None,
                favorita: false,
            })
            .unwrap();
        (db, servico_id, credencial_id, url_id)
    }

    #[test]
    fn test_crud_e_validacao_configuracao_login() {
        let (db, servico_id, credencial_id, url_id) = preparar_banco();

        let id = db
            .criar_configuracao_login(&NovaConfiguracaoLogin {
                credencial_id,
                url_servico_id: url_id,
                seletor_usuario: Some("#email".into()),
                seletor_senha: Some("#password".into()),
                seletor_botao: Some("button[type=submit]".into()),
                url_sucesso: Some("https://www.netflix.com/browse".into()),
                envio_automatico: true,
                timeout_segundos: 30,
                ativa: true,
            })
            .unwrap();

        let buscada = db.buscar_configuracao_login(id).unwrap();
        assert_eq!(buscada.credencial_id, credencial_id);
        assert_eq!(buscada.url_servico_id, url_id);
        assert_eq!(buscada.seletor_usuario.as_deref(), Some("#email"));
        assert_eq!(buscada.seletor_senha.as_deref(), Some("#password"));
        assert_eq!(
            buscada.seletor_botao.as_deref(),
            Some("button[type=submit]")
        );
        assert_eq!(
            buscada.url_sucesso.as_deref(),
            Some("https://www.netflix.com/browse")
        );
        assert!(buscada.envio_automatico);
        assert_eq!(buscada.timeout_segundos, 30);
        assert!(buscada.ativa);
        assert!(buscada.ultima_validacao_em.is_none());

        // Contagem de uso em url_servico_repo deve ser coerente
        assert_eq!(db.contar_configuracoes_login_url(url_id).unwrap(), 1);

        // Marcar validação
        db.marcar_validacao_configuracao_login(id).unwrap();
        let validada = db.buscar_configuracao_login(id).unwrap();
        assert!(validada.ultima_validacao_em.is_some());

        // Atualizar
        let url2_id = db
            .criar_url_servico(&NovaUrlServico {
                servico_id,
                url: "https://www.netflix.com/br/login".into(),
                tipo: "LOGIN".into(),
                descricao: None,
                padrao: false,
            })
            .unwrap();

        db.atualizar_configuracao_login(
            id,
            url2_id,
            None,
            Some("input[name=pass]"),
            None,
            None,
            false,
            45,
            false,
        )
        .unwrap();

        let atualizada = db.buscar_configuracao_login(id).unwrap();
        assert_eq!(atualizada.url_servico_id, url2_id);
        assert!(atualizada.seletor_usuario.is_none());
        assert_eq!(
            atualizada.seletor_senha.as_deref(),
            Some("input[name=pass]")
        );
        assert!(atualizada.seletor_botao.is_none());
        assert!(atualizada.url_sucesso.is_none());
        assert!(!atualizada.envio_automatico);
        assert_eq!(atualizada.timeout_segundos, 45);
        assert!(!atualizada.ativa);

        let lista = db.listar_configuracoes_login(credencial_id).unwrap();
        assert_eq!(lista.len(), 1);

        // Excluir
        db.excluir_configuracao_login(id).unwrap();
        assert!(matches!(
            db.buscar_configuracao_login(id),
            Err(DbError::NotFound)
        ));
        assert!(db
            .listar_configuracoes_login(credencial_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_cascade_ao_excluir_credencial() {
        let (db, _servico_id, credencial_id, url_id) = preparar_banco();
        let id = db
            .criar_configuracao_login(&NovaConfiguracaoLogin {
                credencial_id,
                url_servico_id: url_id,
                seletor_usuario: None,
                seletor_senha: Some("#pass".into()),
                seletor_botao: None,
                url_sucesso: None,
                envio_automatico: true,
                timeout_segundos: 30,
                ativa: true,
            })
            .unwrap();

        db.excluir_credencial(credencial_id).unwrap();
        assert!(matches!(
            db.buscar_configuracao_login(id),
            Err(DbError::NotFound)
        ));
    }
}
