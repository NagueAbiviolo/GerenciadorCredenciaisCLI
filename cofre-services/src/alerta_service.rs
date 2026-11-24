//! Serviço de alertas de segurança (`alerta_seguranca`, RF12).
//!
//! Analisa as credenciais ativas do usuário para detectar:
//! - `SENHA_REUTILIZADA` (`ALTO`): senhas iguais entre duas ou mais credenciais ativas
//!   (decifradas apenas em `Zeroizing<Vec<u8>>`, comparadas em memória e descartadas,
//!   sem persistir qualquer hash de senha).
//! - `SEM_2FA` (`MEDIO`): credencial ativa sem nenhum método de autenticação habilitado
//!   de tipo diferente de `SENHA` (`TOTP`, `SMS`, `EMAIL`, `PASSKEY`, `BIOMETRIA`, `APLICATIVO`).
//! - `RECUPERACAO_DESATUALIZADA` (`BAIXO`): credencial ativa sem e-mail de recuperação ativo,
//!   sem e-mail ativo verificado, ou cujo `verificado_em` mais recente ultrapassou a
//!   preferência `recuperacao_validade_dias`.
//!
//! **Regra de privacidade (RNF05/RNF11):** Títulos, mensagens de alerta e descrições de
//! auditoria citam credenciais exclusivamente por `#id nome_exibicao`. Nunca incluem
//! senha, observação, e-mail de recuperação ou `identificador`.

use std::collections::HashSet;

use chrono::{Duration, Utc};
use cofre_crypto::keys::UnlockedVault;
use cofre_db::models::{AlertaSeguranca, Credencial, FiltroAlerta, NovoAlerta};
use cofre_db::Database;
use zeroize::Zeroizing;

use crate::auditoria_service::{self, ResultadoEvento, TipoEvento};
use crate::preferencia_service;
use crate::vault_service::{aad_segredo, VaultServiceError};

/// Quantidade máxima de outras credenciais listadas nominalmente na mensagem de
/// `SENHA_REUTILIZADA` antes de resumir com `"e mais N"`.
const MAX_OUTRAS_CITADAS: usize = 5;

/// Tipos padronizados de alerta de segurança detectados automaticamente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TipoAlerta {
    SenhaReutilizada,
    Sem2fa,
    RecuperacaoDesatualizada,
}

impl TipoAlerta {
    /// Representação em MAIÚSCULAS persistida na coluna `alerta_seguranca.tipo`.
    pub fn as_str(self) -> &'static str {
        match self {
            TipoAlerta::SenhaReutilizada => "SENHA_REUTILIZADA",
            TipoAlerta::Sem2fa => "SEM_2FA",
            TipoAlerta::RecuperacaoDesatualizada => "RECUPERACAO_DESATUALIZADA",
        }
    }

    /// Todos os tipos gerenciados pela verificação automática (`verificar`).
    pub const TODOS: [TipoAlerta; 3] = [
        TipoAlerta::SenhaReutilizada,
        TipoAlerta::Sem2fa,
        TipoAlerta::RecuperacaoDesatualizada,
    ];
}

/// Nível de severidade de um alerta de segurança (conforme CHECK da tabela `alerta_seguranca`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NivelAlerta {
    Baixo,
    Medio,
    Alto,
    Critico,
}

impl NivelAlerta {
    /// Representação em MAIÚSCULAS persistida na coluna `alerta_seguranca.nivel`.
    pub fn as_str(self) -> &'static str {
        match self {
            NivelAlerta::Baixo => "BAIXO",
            NivelAlerta::Medio => "MEDIO",
            NivelAlerta::Alto => "ALTO",
            NivelAlerta::Critico => "CRITICO",
        }
    }
}

/// Resumo numérico retornado por [`verificar`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumoVerificacao {
    pub novos: usize,
    pub mantidos: usize,
    pub resolvidos_automaticamente: usize,
    pub total_abertos: usize,
}

/// Problema detectado durante a varredura de uma credencial ativa.
struct ProblemaDetectado {
    credencial_id: i64,
    tipo: TipoAlerta,
    nivel: NivelAlerta,
    titulo: String,
    mensagem: String,
}

fn formatar_outras_credenciais(outras: &[(i64, &str)]) -> String {
    let citadas: Vec<String> = outras
        .iter()
        .take(MAX_OUTRAS_CITADAS)
        .map(|(id, nome)| format!("#{id} {nome}"))
        .collect();
    let lista = citadas.join(", ");
    if outras.len() > MAX_OUTRAS_CITADAS {
        let restantes = outras.len() - MAX_OUTRAS_CITADAS;
        format!("{lista} e mais {restantes}")
    } else {
        lista
    }
}

/// Detecta reutilização de senhas entre as credenciais ativas.
///
/// As senhas são decifradas em `Zeroizing<Vec<u8>>`, comparadas apenas em memória e
/// descartadas ao final desta função.
fn detectar_senhas_reutilizadas(
    vault: &UnlockedVault,
    usuario_id: i64,
    credenciais: &[Credencial],
) -> Result<Vec<ProblemaDetectado>, VaultServiceError> {
    let mut ordenada: Vec<&Credencial> = credenciais.iter().collect();
    ordenada.sort_by_key(|c| c.id);

    let mut decifradas: Vec<(&Credencial, Zeroizing<Vec<u8>>)> = Vec::with_capacity(ordenada.len());
    for cred in ordenada {
        let senha = Zeroizing::new(vault.decrypt(
            &cred.nonce,
            &cred.segredo_criptografado,
            &aad_segredo(cred.id, usuario_id),
        )?);
        decifradas.push((cred, senha));
    }

    let mut problemas = Vec::new();
    for (i, (cred, senha)) in decifradas.iter().enumerate() {
        let mut outras: Vec<(i64, &str)> = Vec::new();
        for (j, (outro_cred, outra_senha)) in decifradas.iter().enumerate() {
            if i != j && senha.as_slice() == outra_senha.as_slice() {
                outras.push((outro_cred.id, outro_cred.nome_exibicao.as_str()));
            }
        }

        if !outras.is_empty() {
            let citacao = formatar_outras_credenciais(&outras);
            let mensagem = format!(
                "A credencial #{} {} compartilha a mesma senha com: {}. Recomenda-se definir uma senha única para cada conta.",
                cred.id, cred.nome_exibicao, citacao
            );
            problemas.push(ProblemaDetectado {
                credencial_id: cred.id,
                tipo: TipoAlerta::SenhaReutilizada,
                nivel: NivelAlerta::Alto,
                titulo: "Senha reutilizada em múltiplas credenciais".into(),
                mensagem,
            });
        }
    }

    Ok(problemas)
}

/// Detecta se a credencial não possui nenhum método de autenticação habilitado de tipo
/// diferente de `SENHA` (`TOTP`, `SMS`, `EMAIL`, `PASSKEY`, `BIOMETRIA`, `APLICATIVO`).
fn detectar_sem_2fa(
    db: &Database,
    cred: &Credencial,
) -> Result<Option<ProblemaDetectado>, VaultServiceError> {
    let metodos = db.listar_metodos_autenticacao(cred.id)?;
    let possui_2fa = metodos
        .iter()
        .any(|m| m.habilitado && !m.tipo.eq_ignore_ascii_case("SENHA"));

    if possui_2fa {
        Ok(None)
    } else {
        Ok(Some(ProblemaDetectado {
            credencial_id: cred.id,
            tipo: TipoAlerta::Sem2fa,
            nivel: NivelAlerta::Medio,
            titulo: "Conta sem autenticação em dois fatores (2FA)".into(),
            mensagem: format!(
                "A credencial #{} {} não possui nenhum método de segundo fator ou autenticação forte habilitado (TOTP, SMS, EMAIL, PASSKEY, BIOMETRIA ou APLICATIVO).",
                cred.id, cred.nome_exibicao
            ),
        }))
    }
}

/// Detecta problemas de e-mail de recuperação na credencial sem decifrar os endereços:
/// 1. Nenhum e-mail de recuperação ativo cadastrado.
/// 2. Há e-mails ativos, mas nenhum está marcado como verificado.
/// 3. O `verificado_em` mais recente entre os e-mails ativos verificados é mais antigo
///    que `validade_dias` (preferência `recuperacao_validade_dias`).
fn detectar_recuperacao_desatualizada(
    db: &Database,
    cred: &Credencial,
    validade_dias: u64,
) -> Result<Option<ProblemaDetectado>, VaultServiceError> {
    let emails = db.listar_emails_recuperacao(cred.id)?;
    let ativos: Vec<_> = emails.iter().filter(|e| e.ativo).collect();

    if ativos.is_empty() {
        return Ok(Some(ProblemaDetectado {
            credencial_id: cred.id,
            tipo: TipoAlerta::RecuperacaoDesatualizada,
            nivel: NivelAlerta::Baixo,
            titulo: "Credencial sem e-mail de recuperação ativo".into(),
            mensagem: format!(
                "A credencial #{} {} não possui nenhum e-mail de recuperação ativo cadastrado.",
                cred.id, cred.nome_exibicao
            ),
        }));
    }

    let verificados: Vec<_> = ativos.into_iter().filter(|e| e.verificado).collect();
    if verificados.is_empty() {
        return Ok(Some(ProblemaDetectado {
            credencial_id: cred.id,
            tipo: TipoAlerta::RecuperacaoDesatualizada,
            nivel: NivelAlerta::Baixo,
            titulo: "E-mail de recuperação não verificado".into(),
            mensagem: format!(
                "A credencial #{} {} possui e-mail(s) de recuperação ativo(s), mas nenhum foi marcado como verificado.",
                cred.id, cred.nome_exibicao
            ),
        }));
    }

    let mais_recente = verificados.iter().filter_map(|e| e.verificado_em).max();
    let agora = Utc::now().naive_utc();
    let dias_i64 = i64::try_from(validade_dias).unwrap_or(365);
    let limite = agora - Duration::days(dias_i64);

    match mais_recente {
        None => Ok(Some(ProblemaDetectado {
            credencial_id: cred.id,
            tipo: TipoAlerta::RecuperacaoDesatualizada,
            nivel: NivelAlerta::Baixo,
            titulo: "E-mail de recuperação sem data de verificação".into(),
            mensagem: format!(
                "A credencial #{} {} possui e-mail de recuperação marcado como verificado, mas sem data de verificação registrada.",
                cred.id, cred.nome_exibicao
            ),
        })),
        Some(data_verif) if data_verif < limite => {
            let dias_decorridos = (agora - data_verif).num_days();
            Ok(Some(ProblemaDetectado {
                credencial_id: cred.id,
                tipo: TipoAlerta::RecuperacaoDesatualizada,
                nivel: NivelAlerta::Baixo,
                titulo: "Verificação de e-mail de recuperação expirada".into(),
                mensagem: format!(
                    "A verificação mais recente do e-mail de recuperação da credencial #{} {} ocorreu há {} dia(s), ultrapassando a validade configurada de {} dias.",
                    cred.id, cred.nome_exibicao, dias_decorridos, validade_dias
                ),
            }))
        }
        Some(_) => Ok(None),
    }
}

/// Analisa todas as credenciais **ativas** do usuário e reconcilia de forma idempotente
/// os alertas abertos dos tipos `SENHA_REUTILIZADA`, `SEM_2FA` e `RECUPERACAO_DESATUALIZADA`.
///
/// - Para cada problema detectado: se já existe alerta aberto do mesmo `(tipo, credencial_id)`,
///   atualiza título, mensagem e nível (`mantidos`); caso contrário, cria um novo alerta (`novos`).
/// - Alertas abertos desses 3 tipos que não foram detectados na varredura atual (problema
///   corrigido ou credencial desativada) são marcados como resolvidos automaticamente.
/// - Toda a reconciliação ocorre dentro de uma única transação SQLite.
/// - Registra um evento `VERIFICACAO_ALERTAS` na auditoria com o resumo numérico.
pub fn verificar(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
) -> Result<ResumoVerificacao, VaultServiceError> {
    let credenciais_ativas = db.listar_credenciais(usuario_id, true)?;
    let validade_dias = preferencia_service::recuperacao_validade_dias(db, usuario_id)?;

    let mut problemas = detectar_senhas_reutilizadas(vault, usuario_id, &credenciais_ativas)?;

    let mut ordenada: Vec<&Credencial> = credenciais_ativas.iter().collect();
    ordenada.sort_by_key(|c| c.id);
    for cred in ordenada {
        if let Some(p) = detectar_sem_2fa(db, cred)? {
            problemas.push(p);
        }
        if let Some(p) = detectar_recuperacao_desatualizada(db, cred, validade_dias)? {
            problemas.push(p);
        }
    }

    let tx = db.conn.unchecked_transaction()?;

    let mut novos = 0usize;
    let mut mantidos = 0usize;
    let mut detectados: HashSet<(String, i64)> = HashSet::with_capacity(problemas.len());

    for p in &problemas {
        let tipo_str = p.tipo.as_str();
        let nivel_str = p.nivel.as_str();
        detectados.insert((tipo_str.to_string(), p.credencial_id));

        if let Some(existente) =
            db.buscar_alerta_aberto(usuario_id, tipo_str, Some(p.credencial_id))?
        {
            db.atualizar_alerta(existente.id, nivel_str, &p.titulo, &p.mensagem)?;
            mantidos += 1;
        } else {
            db.criar_alerta(&NovoAlerta {
                credencial_id: Some(p.credencial_id),
                tipo: tipo_str,
                nivel: nivel_str,
                titulo: &p.titulo,
                mensagem: &p.mensagem,
            })?;
            novos += 1;
        }
    }

    let tipos_gerenciados: HashSet<&'static str> =
        TipoAlerta::TODOS.iter().map(|t| t.as_str()).collect();
    let abertos_atuais = db.listar_alertas(
        usuario_id,
        &FiltroAlerta {
            apenas_abertos: true,
            ..Default::default()
        },
    )?;

    let mut resolvidos_automaticamente = 0usize;
    for alerta in abertos_atuais {
        if !tipos_gerenciados.contains(alerta.tipo.as_str()) {
            continue;
        }
        let ainda_presente = match alerta.credencial_id {
            Some(cid) => detectados.contains(&(alerta.tipo.clone(), cid)),
            None => false,
        };
        if !ainda_presente {
            db.resolver_alerta(alerta.id)?;
            resolvidos_automaticamente += 1;
        }
    }

    let total_abertos = db.contar_alertas_abertos(usuario_id)?;
    tx.commit()?;

    let desc = format!(
        "Verificação de alertas: {novos} novo(s), {mantidos} mantido(s), {resolvidos_automaticamente} resolvido(s) automaticamente, {total_abertos} aberto(s)"
    );
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::VerificacaoAlertas,
        ResultadoEvento::Sucesso,
        None,
        Some(&desc),
    );

    Ok(ResumoVerificacao {
        novos,
        mantidos,
        resolvidos_automaticamente,
        total_abertos,
    })
}

/// Lista os alertas de segurança do usuário aplicando os filtros informados.
pub fn listar(
    db: &Database,
    usuario_id: i64,
    filtro: &FiltroAlerta<'_>,
) -> Result<Vec<AlertaSeguranca>, VaultServiceError> {
    Ok(db.listar_alertas(usuario_id, filtro)?)
}

/// Marca manualmente um alerta de segurança como resolvido.
///
/// **Observação sobre reabertura:** Resolver manualmente um alerta descarta o registro
/// atual (`resolvido = 1`). Caso a condição que originou o alerta continue presente na
/// credencial ativa (por exemplo, a senha ainda estiver reutilizada ou a conta continuar
/// sem 2FA), a próxima execução de [`verificar`] (`cofre alerta scan`) detectará novamente
/// o problema e abrirá um **novo** alerta.
pub fn resolver(
    db: &Database,
    usuario_id: i64,
    alerta_id: i64,
) -> Result<AlertaSeguranca, VaultServiceError> {
    let alerta = db.buscar_alerta(alerta_id, usuario_id)?;
    db.resolver_alerta(alerta_id)?;
    let atualizado = db.buscar_alerta(alerta_id, usuario_id)?;

    let desc = format!(
        "Alerta #{alerta_id} ({}) marcado como resolvido",
        alerta.tipo
    );
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::Alteracao,
        ResultadoEvento::Sucesso,
        alerta.credencial_id,
        Some(&desc),
    );

    Ok(atualizado)
}

/// Exclui permanentemente um alerta de segurança do usuário.
pub fn excluir(
    db: &Database,
    usuario_id: i64,
    alerta_id: i64,
) -> Result<AlertaSeguranca, VaultServiceError> {
    let alerta = db.buscar_alerta(alerta_id, usuario_id)?;
    db.excluir_alerta(alerta_id)?;

    let desc = format!("Alerta #{alerta_id} ({}) excluído", alerta.tipo);
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::Exclusao,
        ResultadoEvento::Sucesso,
        alerta.credencial_id,
        Some(&desc),
    );

    Ok(alerta)
}

/// Conta quantos alertas de segurança estão abertos para o usuário.
pub fn contar_abertos(db: &Database, usuario_id: i64) -> Result<usize, VaultServiceError> {
    Ok(db.contar_alertas_abertos(usuario_id)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autenticacao_service;
    use crate::preferencia_service;
    use crate::testes::DbTemp;
    use crate::vault_service::{
        adicionar_credencial, definir_credencial_ativa, editar_credencial, excluir_credencial,
        tests::cofre_com_servico, DadosNovaCredencial, EdicaoCredencial,
    };
    use cofre_db::models::FiltroAuditoria;
    use cofre_db::rusqlite::params;

    #[test]
    fn test_reutilizacao_senha_e_resolucao_ao_trocar() {
        let tmp = DbTemp::new("alerta-reuso");
        let (db, vault, u, s) = cofre_com_servico(&tmp);

        let c1 = adicionar_credencial(
            &db,
            &vault,
            &DadosNovaCredencial {
                usuario_id: u,
                servico_id: s,
                nome_exibicao: "Conta Um",
                identificador: "id-secreto-1@exemplo.com",
                senha: b"SenhaCompartilhada!123",
                observacao: Some("obs-secreta-1"),
            },
        )
        .unwrap();
        let c2 = adicionar_credencial(
            &db,
            &vault,
            &DadosNovaCredencial {
                usuario_id: u,
                servico_id: s,
                nome_exibicao: "Conta Dois",
                identificador: "id-secreto-2@exemplo.com",
                senha: b"SenhaCompartilhada!123",
                observacao: None,
            },
        )
        .unwrap();
        let c3 = adicionar_credencial(
            &db,
            &vault,
            &DadosNovaCredencial {
                usuario_id: u,
                servico_id: s,
                nome_exibicao: "Conta Tres",
                identificador: "id-secreto-3@exemplo.com",
                senha: b"SenhaUnicaDiferente#999",
                observacao: None,
            },
        )
        .unwrap();

        let resumo = verificar(&db, &vault, u).unwrap();
        let alertas_reuso = listar(
            &db,
            u,
            &FiltroAlerta {
                apenas_abertos: true,
                tipo: Some("SENHA_REUTILIZADA"),
                nivel: None,
            },
        )
        .unwrap();

        // 3 credenciais, 2 com mesma senha -> exatamente 2 alertas de SENHA_REUTILIZADA
        assert_eq!(alertas_reuso.len(), 2);
        assert!(alertas_reuso.iter().all(|a| a.nivel == "ALTO"));
        assert!(alertas_reuso
            .iter()
            .any(|a| a.credencial_id == Some(c1)
                && a.mensagem.contains(&format!("#{c2} Conta Dois"))));
        assert!(alertas_reuso.iter().any(
            |a| a.credencial_id == Some(c2) && a.mensagem.contains(&format!("#{c1} Conta Um"))
        ));
        assert!(!alertas_reuso.iter().any(|a| a.credencial_id == Some(c3)));
        assert_eq!(resumo.novos, 8); // 2 reuso + 3 sem_2fa + 3 rec_desatualizada

        // Trocar a senha de c2 resolve automaticamente ambos os alertas de reutilização na próxima verificação
        editar_credencial(
            &db,
            &vault,
            u,
            c2,
            &EdicaoCredencial {
                senha: Some(b"NovaSenhaExclusiva$456"),
                ..Default::default()
            },
        )
        .unwrap();

        let resumo2 = verificar(&db, &vault, u).unwrap();
        assert_eq!(resumo2.resolvidos_automaticamente, 2);
        let alertas_reuso_apos = listar(
            &db,
            u,
            &FiltroAlerta {
                apenas_abertos: true,
                tipo: Some("SENHA_REUTILIZADA"),
                nivel: None,
            },
        )
        .unwrap();
        assert!(alertas_reuso_apos.is_empty());
    }

    #[test]
    fn test_sem_2fa_com_e_sem_totp() {
        let tmp = DbTemp::new("alerta-2fa");
        let (db, vault, u, s) = cofre_com_servico(&tmp);

        let c = adicionar_credencial(
            &db,
            &vault,
            &DadosNovaCredencial {
                usuario_id: u,
                servico_id: s,
                nome_exibicao: "GitHub Pessoal",
                identificador: "login-github",
                senha: b"s1",
                observacao: None,
            },
        )
        .unwrap();

        // Apenas método SENHA não conta como 2FA
        autenticacao_service::adicionar_metodo(&db, u, c, "SENHA", None, true).unwrap();
        verificar(&db, &vault, u).unwrap();

        let sem_2fa = listar(
            &db,
            u,
            &FiltroAlerta {
                apenas_abertos: true,
                tipo: Some("SEM_2FA"),
                nivel: None,
            },
        )
        .unwrap();
        assert_eq!(sem_2fa.len(), 1);
        assert_eq!(sem_2fa[0].nivel, "MEDIO");
        assert_eq!(sem_2fa[0].credencial_id, Some(c));

        // Adicionar TOTP habilitado resolve o alerta SEM_2FA na próxima verificação
        let totp_id =
            autenticacao_service::adicionar_metodo(&db, u, c, "TOTP", Some("Aegis"), false)
                .unwrap();
        verificar(&db, &vault, u).unwrap();

        let sem_2fa_apos = listar(
            &db,
            u,
            &FiltroAlerta {
                apenas_abertos: true,
                tipo: Some("SEM_2FA"),
                nivel: None,
            },
        )
        .unwrap();
        assert!(sem_2fa_apos.is_empty());

        // Se o TOTP for desabilitado, volta a alertar SEM_2FA
        autenticacao_service::editar_metodo(
            &db,
            u,
            totp_id,
            &autenticacao_service::EdicaoMetodo {
                habilitado: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
        verificar(&db, &vault, u).unwrap();
        let sem_2fa_reaberto = listar(
            &db,
            u,
            &FiltroAlerta {
                apenas_abertos: true,
                tipo: Some("SEM_2FA"),
                nivel: None,
            },
        )
        .unwrap();
        assert_eq!(sem_2fa_reaberto.len(), 1);
    }

    #[test]
    fn test_recuperacao_quatro_casos_e_preferencia() {
        let tmp = DbTemp::new("alerta-recuperacao");
        let (db, vault, u, s) = cofre_com_servico(&tmp);

        let c = adicionar_credencial(
            &db,
            &vault,
            &DadosNovaCredencial {
                usuario_id: u,
                servico_id: s,
                nome_exibicao: "Email Principal",
                identificador: "user-rec",
                senha: b"s1",
                observacao: None,
            },
        )
        .unwrap();

        // Caso 1: Sem e-mail de recuperação ativo
        verificar(&db, &vault, u).unwrap();
        let a1 = listar(
            &db,
            u,
            &FiltroAlerta {
                apenas_abertos: true,
                tipo: Some("RECUPERACAO_DESATUALIZADA"),
                nivel: None,
            },
        )
        .unwrap();
        assert_eq!(a1.len(), 1);
        assert_eq!(a1[0].nivel, "BAIXO");
        assert!(a1[0]
            .mensagem
            .contains("não possui nenhum e-mail de recuperação ativo"));

        // Caso 2: Com e-mail ativo mas não verificado
        let email_id = autenticacao_service::adicionar_email(
            &db,
            &vault,
            u,
            c,
            "recuperacao.secreta@exemplo.com",
            true,
            false,
        )
        .unwrap();
        verificar(&db, &vault, u).unwrap();
        let a2 = listar(
            &db,
            u,
            &FiltroAlerta {
                apenas_abertos: true,
                tipo: Some("RECUPERACAO_DESATUALIZADA"),
                nivel: None,
            },
        )
        .unwrap();
        assert_eq!(a2.len(), 1);
        assert_eq!(a2[0].id, a1[0].id); // atualizado in-place (mantido)
        assert!(a2[0]
            .mensagem
            .contains("nenhum foi marcado como verificado"));

        // Caso 3: E-mail verificado recente -> OK (resolve automaticamente)
        autenticacao_service::editar_email(
            &db,
            &vault,
            u,
            email_id,
            &autenticacao_service::EdicaoEmail {
                verificado: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        verificar(&db, &vault, u).unwrap();
        let a3 = listar(
            &db,
            u,
            &FiltroAlerta {
                apenas_abertos: true,
                tipo: Some("RECUPERACAO_DESATUALIZADA"),
                nivel: None,
            },
        )
        .unwrap();
        assert!(a3.is_empty());

        // Caso 4: verificado_em antigo (ex.: 100 dias atrás com preferência configurada em 60 dias)
        preferencia_service::definir(&db, u, "recuperacao_validade_dias", "60").unwrap();
        db.conn
            .execute(
                "UPDATE email_recuperacao SET verificado_em = datetime('now', '-100 days') WHERE id = ?1",
                params![email_id],
            )
            .unwrap();
        verificar(&db, &vault, u).unwrap();
        let a4 = listar(
            &db,
            u,
            &FiltroAlerta {
                apenas_abertos: true,
                tipo: Some("RECUPERACAO_DESATUALIZADA"),
                nivel: None,
            },
        )
        .unwrap();
        assert_eq!(a4.len(), 1);
        assert!(a4[0]
            .mensagem
            .contains("ultrapassando a validade configurada de 60 dias"));
    }

    #[test]
    fn test_idempotencia_desativacao_exclusao_e_privacidade() {
        let tmp = DbTemp::new("alerta-idempotencia-priv");
        let (db, vault, u, s) = cofre_com_servico(&tmp);

        let senha_secreta = "SuperSenhaUltraSecreta!98765";
        let id_secreto_1 = "cpf-111.222.333-44-secreto";
        let id_secreto_2 = "login-privado-xyz@dominio.com";
        let obs_secreta = "MinhaObservacaoSuperSecreta";
        let email_secreto = "meu.email.recuperacao.secreto@dominio.org";

        let c1 = adicionar_credencial(
            &db,
            &vault,
            &DadosNovaCredencial {
                usuario_id: u,
                servico_id: s,
                nome_exibicao: "Banco Alfa",
                identificador: id_secreto_1,
                senha: senha_secreta.as_bytes(),
                observacao: Some(obs_secreta),
            },
        )
        .unwrap();
        let c2 = adicionar_credencial(
            &db,
            &vault,
            &DadosNovaCredencial {
                usuario_id: u,
                servico_id: s,
                nome_exibicao: "Banco Beta",
                identificador: id_secreto_2,
                senha: senha_secreta.as_bytes(),
                observacao: Some(obs_secreta),
            },
        )
        .unwrap();

        autenticacao_service::adicionar_email(&db, &vault, u, c1, email_secreto, true, false)
            .unwrap();

        // 1ª verificação cria os alertas
        let r1 = verificar(&db, &vault, u).unwrap();
        assert_eq!(r1.novos, 6);
        assert_eq!(r1.mantidos, 0);
        assert_eq!(r1.resolvidos_automaticamente, 0);
        assert_eq!(r1.total_abertos, 6);

        // 2ª verificação seguida é idempotente: 0 novos, 6 mantidos
        let r2 = verificar(&db, &vault, u).unwrap();
        assert_eq!(r2.novos, 0);
        assert_eq!(r2.mantidos, 6);
        assert_eq!(r2.resolvidos_automaticamente, 0);
        assert_eq!(r2.total_abertos, 6);

        // Verifica privacidade: nenhum alerta ou evento de auditoria contém senha,
        // identificador, observação ou e-mail de recuperação
        let todos_alertas = listar(&db, u, &FiltroAlerta::default()).unwrap();
        for a in &todos_alertas {
            for proibido in [
                senha_secreta,
                id_secreto_1,
                id_secreto_2,
                obs_secreta,
                email_secreto,
            ] {
                assert!(!a.titulo.contains(proibido), "Título vazou: {proibido}");
                assert!(!a.mensagem.contains(proibido), "Mensagem vazou: {proibido}");
            }
        }
        let eventos = auditoria_service::listar(&db, u, &FiltroAuditoria::default()).unwrap();
        for ev in &eventos {
            if let Some(desc) = &ev.descricao {
                for proibido in [
                    senha_secreta,
                    id_secreto_1,
                    id_secreto_2,
                    obs_secreta,
                    email_secreto,
                ] {
                    assert!(!desc.contains(proibido), "Auditoria vazou: {proibido}");
                }
            }
        }

        // Resolver manualmente um alerta: se o problema persistir, o próximo scan reabre como novo
        let alerta_id = todos_alertas[0].id;
        resolver(&db, u, alerta_id).unwrap();
        assert_eq!(contar_abertos(&db, u).unwrap(), 5);

        let r3 = verificar(&db, &vault, u).unwrap();
        assert_eq!(r3.novos, 1);
        assert_eq!(r3.mantidos, 5);
        assert_eq!(r3.total_abertos, 6);

        // Desativar c2 resolve todos os alertas de c2 e também o SENHA_REUTILIZADA de c1
        definir_credencial_ativa(&db, u, c2, false, None).unwrap();
        let r4 = verificar(&db, &vault, u).unwrap();
        assert_eq!(r4.resolvidos_automaticamente, 4); // 3 de c2 + 1 reuso de c1
        assert_eq!(r4.total_abertos, 2); // c1 continua sem_2fa e recuperacao_desatualizada

        // Excluir credencial c1 (que tem alertas abertos e resolvidos) funciona sem violar FK
        excluir_credencial(&db, u, c1).unwrap();
        assert_eq!(contar_abertos(&db, u).unwrap(), 0);
    }
}
