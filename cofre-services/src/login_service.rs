//! Serviço de configuração e preparação de login automático (`configuracao_login`, `sessao_navegador`, RF06, RF07, RF16).
//!
//! Valida seletores, vínculo de URL com o serviço da credencial e timeouts;
//! prepara os dados de login mantendo a senha protegida em `Zeroizing<String>`
//! (sem `Debug` de segredos) e registra eventos de auditoria e sessões de navegador.

use std::fmt;

use cofre_crypto::keys::UnlockedVault;
use cofre_db::connection::DbError;
use cofre_db::models::{
    ConfiguracaoLogin, NovaConfiguracaoLogin, NovaSessaoNavegador, SessaoNavegador,
};
use cofre_db::Database;
use zeroize::Zeroizing;

use crate::auditoria_service::{self, ResultadoEvento, TipoEvento};
use crate::dispositivo_service;
use crate::preferencia_service;
use crate::vault_service::{self, buscar_credencial, VaultServiceError};

/// Timeout padrão (em segundos) para novas configurações de login.
pub const PADRAO_TIMEOUT_LOGIN: i64 = 30;

/// Dados de entrada para adicionar uma nova configuração de login automático.
pub struct DadosNovaConfiguracaoLogin<'a> {
    pub credencial_id: i64,
    pub url_servico_id: i64,
    pub seletor_usuario: Option<&'a str>,
    pub seletor_senha: Option<&'a str>,
    pub seletor_botao: Option<&'a str>,
    pub url_sucesso: Option<&'a str>,
    pub envio_automatico: bool,
    pub timeout_segundos: i64,
    pub ativa: bool,
}

/// Alterações possíveis em uma configuração de login. Campos `None` não são alterados.
#[derive(Default)]
pub struct EdicaoConfiguracaoLogin<'a> {
    pub url_servico_id: Option<i64>,
    /// `Some(None)` remove o seletor; `Some(Some(s))` define novo valor.
    pub seletor_usuario: Option<Option<&'a str>>,
    pub seletor_senha: Option<&'a str>,
    /// `Some(None)` remove o seletor; `Some(Some(s))` define novo valor.
    pub seletor_botao: Option<Option<&'a str>>,
    /// `Some(None)` remove a URL de sucesso; `Some(Some(s))` define novo valor.
    pub url_sucesso: Option<Option<&'a str>>,
    pub envio_automatico: Option<bool>,
    pub timeout_segundos: Option<i64>,
    pub ativa: Option<bool>,
}

/// Dados consolidados e validados para execução do login automático.
///
/// A senha é mantida em `Zeroizing<String>` para sobrescrita automática ao sair de escopo
/// e a implementação de `Debug` omite o segredo (RNF05).
pub struct DadosLoginPreparados {
    pub config: ConfiguracaoLogin,
    pub url_login: String,
    pub dominio_principal: String,
    pub identificador: String,
    pub senha: Zeroizing<String>,
    pub navegador_padrao: String,
}

impl fmt::Debug for DadosLoginPreparados {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DadosLoginPreparados")
            .field("config_id", &self.config.id)
            .field("credencial_id", &self.config.credencial_id)
            .field("url_login", &self.url_login)
            .field("dominio_principal", &self.dominio_principal)
            .field("identificador", &self.identificador)
            .field("senha", &"<protegida>")
            .field("navegador_padrao", &self.navegador_padrao)
            .finish()
    }
}

fn nao_encontrado() -> VaultServiceError {
    VaultServiceError::Db(DbError::NotFound)
}

fn validar_seletor_opcional(
    nome_campo: &str,
    valor: Option<&str>,
) -> Result<Option<String>, VaultServiceError> {
    match valor {
        Some(s) => {
            let limpo = s.trim();
            if limpo.is_empty() {
                return Err(VaultServiceError::Invalido(format!(
                    "{nome_campo} não pode ser vazio quando informado"
                )));
            }
            Ok(Some(limpo.to_string()))
        }
        None => Ok(None),
    }
}

fn validar_seletor_senha_obrigatorio(valor: Option<&str>) -> Result<String, VaultServiceError> {
    match valor {
        Some(s) => {
            let limpo = s.trim();
            if limpo.is_empty() {
                return Err(VaultServiceError::Invalido(
                    "seletor_senha é obrigatório e não pode ser vazio para login automático".into(),
                ));
            }
            Ok(limpo.to_string())
        }
        None => Err(VaultServiceError::Invalido(
            "seletor_senha é obrigatório para login automático".into(),
        )),
    }
}

fn validar_timeout(timeout_segundos: i64) -> Result<(), VaultServiceError> {
    if timeout_segundos <= 0 {
        return Err(VaultServiceError::Invalido(
            "timeout_segundos deve ser maior que zero".into(),
        ));
    }
    Ok(())
}

/// Busca uma configuração de login garantindo que sua credencial pertence ao usuário.
pub fn buscar_configuracao(
    db: &Database,
    usuario_id: i64,
    config_id: i64,
) -> Result<ConfiguracaoLogin, VaultServiceError> {
    let config = db.buscar_configuracao_login(config_id)?;
    buscar_credencial(db, config.credencial_id, usuario_id).map_err(|_| nao_encontrado())?;
    Ok(config)
}

/// Lista todas as configurações de login de uma credencial do usuário.
pub fn listar_configuracoes(
    db: &Database,
    usuario_id: i64,
    credencial_id: i64,
) -> Result<Vec<ConfiguracaoLogin>, VaultServiceError> {
    buscar_credencial(db, credencial_id, usuario_id)?;
    Ok(db.listar_configuracoes_login(credencial_id)?)
}

/// Adiciona uma nova configuração de login após validar credencial, URL do mesmo serviço,
/// seletores e timeout.
pub fn adicionar_configuracao(
    db: &Database,
    usuario_id: i64,
    dados: &DadosNovaConfiguracaoLogin<'_>,
) -> Result<i64, VaultServiceError> {
    validar_timeout(dados.timeout_segundos)?;
    let seletor_senha = validar_seletor_senha_obrigatorio(dados.seletor_senha)?;
    let seletor_usuario = validar_seletor_opcional("seletor_usuario", dados.seletor_usuario)?;
    let seletor_botao = validar_seletor_opcional("seletor_botao", dados.seletor_botao)?;
    let url_sucesso = validar_seletor_opcional("url_sucesso", dados.url_sucesso)?;

    let cred = buscar_credencial(db, dados.credencial_id, usuario_id)?;
    let url_servico = db.buscar_url_servico(dados.url_servico_id)?;
    if url_servico.servico_id != cred.servico_id {
        return Err(VaultServiceError::Invalido(format!(
            "a URL #{} pertence ao serviço #{}, mas a credencial #{} pertence ao serviço #{}",
            url_servico.id, url_servico.servico_id, cred.id, cred.servico_id
        )));
    }

    let id = db.criar_configuracao_login(&NovaConfiguracaoLogin {
        credencial_id: dados.credencial_id,
        url_servico_id: dados.url_servico_id,
        seletor_usuario,
        seletor_senha: Some(seletor_senha),
        seletor_botao,
        url_sucesso,
        envio_automatico: dados.envio_automatico,
        timeout_segundos: dados.timeout_segundos,
        ativa: dados.ativa,
    })?;

    let desc = format!("Configuração de login {id} criada");
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::Criacao,
        ResultadoEvento::Sucesso,
        Some(dados.credencial_id),
        Some(&desc),
    );

    Ok(id)
}

/// Atualiza uma configuração de login existente do usuário.
pub fn editar_configuracao(
    db: &Database,
    usuario_id: i64,
    config_id: i64,
    edicao: &EdicaoConfiguracaoLogin<'_>,
) -> Result<(), VaultServiceError> {
    let atual = buscar_configuracao(db, usuario_id, config_id)?;
    let cred = buscar_credencial(db, atual.credencial_id, usuario_id)?;

    let url_servico_id = edicao.url_servico_id.unwrap_or(atual.url_servico_id);
    let url_servico = db.buscar_url_servico(url_servico_id)?;
    if url_servico.servico_id != cred.servico_id {
        return Err(VaultServiceError::Invalido(format!(
            "a URL #{} pertence ao serviço #{}, mas a credencial #{} pertence ao serviço #{}",
            url_servico.id, url_servico.servico_id, cred.id, cred.servico_id
        )));
    }

    let seletor_usuario = match edicao.seletor_usuario {
        Some(novo) => validar_seletor_opcional("seletor_usuario", novo)?,
        None => atual.seletor_usuario.clone(),
    };

    let seletor_senha = match edicao.seletor_senha {
        Some(novo) => validar_seletor_senha_obrigatorio(Some(novo))?,
        None => validar_seletor_senha_obrigatorio(atual.seletor_senha.as_deref())?,
    };

    let seletor_botao = match edicao.seletor_botao {
        Some(novo) => validar_seletor_opcional("seletor_botao", novo)?,
        None => atual.seletor_botao.clone(),
    };

    let url_sucesso = match edicao.url_sucesso {
        Some(novo) => validar_seletor_opcional("url_sucesso", novo)?,
        None => atual.url_sucesso.clone(),
    };

    let envio_automatico = edicao.envio_automatico.unwrap_or(atual.envio_automatico);
    let timeout_segundos = edicao.timeout_segundos.unwrap_or(atual.timeout_segundos);
    validar_timeout(timeout_segundos)?;
    let ativa = edicao.ativa.unwrap_or(atual.ativa);

    db.atualizar_configuracao_login(
        config_id,
        url_servico_id,
        seletor_usuario.as_deref(),
        Some(&seletor_senha),
        seletor_botao.as_deref(),
        url_sucesso.as_deref(),
        envio_automatico,
        timeout_segundos,
        ativa,
    )?;

    let desc = format!("Configuração de login {config_id} editada");
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::Alteracao,
        ResultadoEvento::Sucesso,
        Some(atual.credencial_id),
        Some(&desc),
    );

    Ok(())
}

/// Exclui uma configuração de login do usuário.
pub fn excluir_configuracao(
    db: &Database,
    usuario_id: i64,
    config_id: i64,
) -> Result<ConfiguracaoLogin, VaultServiceError> {
    let config = buscar_configuracao(db, usuario_id, config_id)?;
    db.excluir_configuracao_login(config_id)?;

    let desc = format!("Configuração de login {config_id} excluída");
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::Exclusao,
        ResultadoEvento::Sucesso,
        Some(config.credencial_id),
        Some(&desc),
    );

    Ok(config)
}

/// Prepara todos os dados necessários para o login automático de uma credencial.
///
/// - Se `config_id` for informado, usa essa configuração (desde que pertença à credencial e esteja ativa).
/// - Se `config_id` for `None`, seleciona a primeira configuração ativa da credencial.
/// - Revela a senha mantendo-a em `Zeroizing<String>` e busca o navegador padrão do usuário.
pub fn preparar_dados_login(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
    credencial_id: i64,
    config_id: Option<i64>,
) -> Result<DadosLoginPreparados, VaultServiceError> {
    let cred = buscar_credencial(db, credencial_id, usuario_id)?;
    if !cred.ativa {
        return Err(VaultServiceError::Invalido(format!(
            "a credencial #{credencial_id} está desativada"
        )));
    }

    let config = match config_id {
        Some(id) => {
            let c = buscar_configuracao(db, usuario_id, id)?;
            if c.credencial_id != credencial_id {
                return Err(VaultServiceError::Invalido(format!(
                    "a configuração #{id} não pertence à credencial #{credencial_id}"
                )));
            }
            if !c.ativa {
                return Err(VaultServiceError::Invalido(format!(
                    "a configuração de login #{id} está desativada"
                )));
            }
            c
        }
        None => {
            let todas = db.listar_configuracoes_login(credencial_id)?;
            todas
                .into_iter()
                .find(|c| c.ativa)
                .ok_or_else(|| {
                    VaultServiceError::Invalido(format!(
                        "nenhuma configuração de login ativa encontrada para a credencial #{credencial_id}"
                    ))
                })?
        }
    };

    validar_seletor_senha_obrigatorio(config.seletor_senha.as_deref())?;
    validar_timeout(config.timeout_segundos)?;

    let url_servico = db.buscar_url_servico(config.url_servico_id)?;
    if url_servico.servico_id != cred.servico_id {
        return Err(VaultServiceError::Invalido(
            "a URL vinculada à configuração não pertence ao serviço da credencial".into(),
        ));
    }
    if !url_servico.ativa {
        return Err(VaultServiceError::Invalido(format!(
            "a URL #{} vinculada à configuração está desativada",
            url_servico.id
        )));
    }

    let servico = db.buscar_servico(cred.servico_id)?;
    let navegador_padrao = preferencia_service::navegador_padrao(db, usuario_id)?;

    let senha_bytes = Zeroizing::new(vault_service::revelar_senha(
        db,
        vault,
        credencial_id,
        usuario_id,
    )?);
    let senha_str = std::str::from_utf8(&senha_bytes)
        .map_err(|_| {
            VaultServiceError::Invalido("a senha armazenada não é um texto UTF-8 válido".into())
        })?
        .to_string();
    let senha = Zeroizing::new(senha_str);

    Ok(DadosLoginPreparados {
        config,
        url_login: url_servico.url,
        dominio_principal: servico.dominio_principal,
        identificador: cred.identificador,
        senha,
        navegador_padrao,
    })
}

/// Registra na auditoria o resultado de uma tentativa de login automático (`LOGIN_AUTOMATICO`)
/// e, se houver validação da configuração (`marcar_validacao = true`), atualiza `ultima_validacao_em`.
///
/// A descrição nunca deve conter senhas ou tokens (RNF05/RNF11).
pub fn registrar_resultado_login(
    db: &Database,
    usuario_id: i64,
    credencial_id: i64,
    config_id: i64,
    resultado: ResultadoEvento,
    descricao: &str,
    marcar_validacao: bool,
) {
    if marcar_validacao {
        if let Err(e) = db.marcar_validacao_configuracao_login(config_id) {
            tracing::warn!(
                config_id,
                "Não foi possível atualizar ultima_validacao_em da configuração de login: {e}"
            );
        }
    }

    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::LoginAutomatico,
        resultado,
        Some(credencial_id),
        Some(descricao),
    );
}

/// Registra uma nova sessão de navegador associada ao dispositivo local atual.
pub fn iniciar_sessao_navegador(
    db: &Database,
    usuario_id: i64,
    credencial_id: i64,
    navegador: &str,
    perfil_nome: Option<&str>,
    diretorio_perfil: Option<&str>,
) -> Result<i64, VaultServiceError> {
    buscar_credencial(db, credencial_id, usuario_id)?;
    let fp = dispositivo_service::fingerprint_dispositivo_atual();
    let dispositivo_id = db.buscar_dispositivo_por_fingerprint(fp)?.map(|d| d.id);

    Ok(db.criar_sessao_navegador(&NovaSessaoNavegador {
        credencial_id,
        dispositivo_id,
        navegador,
        perfil_nome,
        diretorio_perfil,
    })?)
}

/// Encerra uma sessão de navegador (`ativa = 0`).
pub fn encerrar_sessao_navegador(db: &Database, sessao_id: i64) -> Result<(), VaultServiceError> {
    Ok(db.encerrar_sessao_navegador(sessao_id)?)
}

/// Lista as sessões de navegador de uma credencial do usuário.
pub fn listar_sessoes_navegador(
    db: &Database,
    usuario_id: i64,
    credencial_id: i64,
) -> Result<Vec<SessaoNavegador>, VaultServiceError> {
    buscar_credencial(db, credencial_id, usuario_id)?;
    Ok(db.listar_sessoes_navegador(credencial_id)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::servico_service;
    use crate::testes::DbTemp;
    use crate::vault_service::{
        adicionar_credencial, tests::cofre_com_servico, DadosNovaCredencial,
    };
    use cofre_db::models::{FiltroAuditoria, NovoServico};

    #[test]
    fn test_crud_validacoes_e_preparacao_login() {
        let tmp = DbTemp::new("login-service");
        let (db, vault, usuario_id, servico_id) = cofre_com_servico(&tmp);

        let url_id = servico_service::adicionar_url(
            &db,
            servico_id,
            "https://github.com/login",
            "LOGIN",
            None,
            true,
        )
        .unwrap();

        let outro_servico_id = db
            .criar_servico(&NovoServico {
                categoria_id: None,
                nome: "Netflix".into(),
                dominio_principal: "netflix.com".into(),
                url_principal: None,
                descricao: None,
            })
            .unwrap();
        let url_outro_servico = servico_service::adicionar_url(
            &db,
            outro_servico_id,
            "https://www.netflix.com/login",
            "LOGIN",
            None,
            true,
        )
        .unwrap();

        let cred_id = adicionar_credencial(
            &db,
            &vault,
            &DadosNovaCredencial {
                usuario_id,
                servico_id,
                nome_exibicao: "GitHub Pessoal",
                identificador: "octocat",
                senha: b"senha-super-secreta",
                observacao: None,
            },
        )
        .unwrap();

        // Validações: URL de outro serviço deve falhar
        assert!(adicionar_configuracao(
            &db,
            usuario_id,
            &DadosNovaConfiguracaoLogin {
                credencial_id: cred_id,
                url_servico_id: url_outro_servico,
                seletor_usuario: Some("#login_field"),
                seletor_senha: Some("#password"),
                seletor_botao: Some("input[type=submit]"),
                url_sucesso: None,
                envio_automatico: true,
                timeout_segundos: 30,
                ativa: true,
            }
        )
        .is_err());

        // Validações: timeout <= 0 deve falhar
        assert!(adicionar_configuracao(
            &db,
            usuario_id,
            &DadosNovaConfiguracaoLogin {
                credencial_id: cred_id,
                url_servico_id: url_id,
                seletor_usuario: Some("#login_field"),
                seletor_senha: Some("#password"),
                seletor_botao: None,
                url_sucesso: None,
                envio_automatico: true,
                timeout_segundos: 0,
                ativa: true,
            }
        )
        .is_err());

        // Validações: seletor_senha ausente ou vazio deve falhar
        assert!(adicionar_configuracao(
            &db,
            usuario_id,
            &DadosNovaConfiguracaoLogin {
                credencial_id: cred_id,
                url_servico_id: url_id,
                seletor_usuario: Some("#login_field"),
                seletor_senha: None,
                seletor_botao: None,
                url_sucesso: None,
                envio_automatico: true,
                timeout_segundos: 30,
                ativa: true,
            }
        )
        .is_err());
        assert!(adicionar_configuracao(
            &db,
            usuario_id,
            &DadosNovaConfiguracaoLogin {
                credencial_id: cred_id,
                url_servico_id: url_id,
                seletor_usuario: Some("#login_field"),
                seletor_senha: Some("   "),
                seletor_botao: None,
                url_sucesso: None,
                envio_automatico: true,
                timeout_segundos: 30,
                ativa: true,
            }
        )
        .is_err());

        // Validações: seletor opcional vazio quando informado deve falhar
        assert!(adicionar_configuracao(
            &db,
            usuario_id,
            &DadosNovaConfiguracaoLogin {
                credencial_id: cred_id,
                url_servico_id: url_id,
                seletor_usuario: Some("  "),
                seletor_senha: Some("#password"),
                seletor_botao: None,
                url_sucesso: None,
                envio_automatico: true,
                timeout_segundos: 30,
                ativa: true,
            }
        )
        .is_err());

        // Criação válida
        let cfg_id = adicionar_configuracao(
            &db,
            usuario_id,
            &DadosNovaConfiguracaoLogin {
                credencial_id: cred_id,
                url_servico_id: url_id,
                seletor_usuario: Some(" #login_field "),
                seletor_senha: Some(" #password "),
                seletor_botao: Some(" input[type=submit] "),
                url_sucesso: Some(" https://github.com/ "),
                envio_automatico: true,
                timeout_segundos: 25,
                ativa: true,
            },
        )
        .unwrap();

        // Impede exclusão da URL em uso
        assert!(servico_service::excluir_url(&db, url_id).is_err());

        // Preparar dados de login
        let prep = preparar_dados_login(&db, &vault, usuario_id, cred_id, None).unwrap();
        assert_eq!(prep.config.id, cfg_id);
        assert_eq!(prep.url_login, "https://github.com/login");
        assert_eq!(prep.dominio_principal, "github.com");
        assert_eq!(prep.identificador, "octocat");
        assert_eq!(prep.senha.as_str(), "senha-super-secreta");
        assert_eq!(prep.navegador_padrao, "chromium");

        // Debug não deve vazar a senha
        let debug_str = format!("{prep:?}");
        assert!(!debug_str.contains("senha-super-secreta"));
        assert!(debug_str.contains("<protegida>"));

        // Registrar resultado de login automático e sessão
        let sessao_id = iniciar_sessao_navegador(
            &db,
            usuario_id,
            cred_id,
            &prep.navegador_padrao,
            Some("credencial-1"),
            Some("/tmp/perfis/cred-1"),
        )
        .unwrap();
        let sessoes = listar_sessoes_navegador(&db, usuario_id, cred_id).unwrap();
        assert_eq!(sessoes.len(), 1);
        assert!(sessoes[0].ativa);
        assert!(sessoes[0].dispositivo_id.is_some());

        encerrar_sessao_navegador(&db, sessao_id).unwrap();
        let sessoes_apos = listar_sessoes_navegador(&db, usuario_id, cred_id).unwrap();
        assert!(!sessoes_apos[0].ativa);

        registrar_resultado_login(
            &db,
            usuario_id,
            cred_id,
            cfg_id,
            ResultadoEvento::Sucesso,
            "Login automático concluído com sucesso",
            true,
        );

        let cfg_validada = buscar_configuracao(&db, usuario_id, cfg_id).unwrap();
        assert!(cfg_validada.ultima_validacao_em.is_some());

        let eventos_login = auditoria_service::listar(
            &db,
            usuario_id,
            &FiltroAuditoria {
                tipo_evento: Some("LOGIN_AUTOMATICO"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(eventos_login.len(), 1);
        assert_eq!(eventos_login[0].resultado, "SUCESSO");

        // Editar configuração
        editar_configuracao(
            &db,
            usuario_id,
            cfg_id,
            &EdicaoConfiguracaoLogin {
                seletor_botao: Some(None),
                envio_automatico: Some(false),
                timeout_segundos: Some(40),
                ..Default::default()
            },
        )
        .unwrap();
        let editada = buscar_configuracao(&db, usuario_id, cfg_id).unwrap();
        assert!(editada.seletor_botao.is_none());
        assert!(!editada.envio_automatico);
        assert_eq!(editada.timeout_segundos, 40);

        // Excluir configuração
        excluir_configuracao(&db, usuario_id, cfg_id).unwrap();
        assert!(listar_configuracoes(&db, usuario_id, cred_id)
            .unwrap()
            .is_empty());
    }
}
