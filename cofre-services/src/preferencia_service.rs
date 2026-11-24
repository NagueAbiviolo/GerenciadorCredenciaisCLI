//! Serviço de preferências do usuário (`preferencia`, RF15).
//!
//! Mantém um catálogo fixo de preferências conhecidas com tipo, faixa/valores
//! permitidos, valor padrão e descrição. Apenas chaves do catálogo são aceitas.

use cofre_db::models::NovaPreferencia;
use cofre_db::Database;

use crate::auditoria_service::{self, ResultadoEvento, TipoEvento};
use crate::vault_service::VaultServiceError;

/// Chave da preferência de tempo de limpeza da área de transferência (segundos).
pub const CHAVE_TEMPO_CLIPBOARD: &str = "tempo_clipboard";
/// Chave da preferência de timeout de inatividade no modo shell (minutos).
pub const CHAVE_TIMEOUT_INATIVIDADE: &str = "timeout_inatividade";
/// Chave da preferência de navegador padrão para sessões/automação.
pub const CHAVE_NAVEGADOR_PADRAO: &str = "navegador_padrao";
/// Chave da preferência que controla a retenção de valores anteriores cifrados no histórico.
pub const CHAVE_HISTORICO_RETER_VALORES: &str = "historico_reter_valores";

/// Valor padrão para `tempo_clipboard` (segundos).
pub const PADRAO_TEMPO_CLIPBOARD: u64 = 20;
/// Valor padrão para `timeout_inatividade` (minutos).
pub const PADRAO_TIMEOUT_INATIVIDADE: u64 = 5;
/// Valor padrão para `navegador_padrao`.
pub const PADRAO_NAVEGADOR_PADRAO: &str = "chromium";
/// Valor padrão para `historico_reter_valores`.
pub const PADRAO_HISTORICO_RETER_VALORES: bool = false;

/// Valores permitidos para `navegador_padrao`.
pub const NAVEGADORES_PERMITIDOS: &[&str] = &["chromium", "chrome", "edge", "brave"];

/// Regra de validação do valor de uma preferência do catálogo.
#[derive(Debug, Clone, Copy)]
pub enum RegraPreferencia {
    /// Número inteiro dentro de uma faixa inclusiva (`min..=max`).
    InteiroFaixa { min: u64, max: u64 },
    /// Texto pertencente a um conjunto fixo de opções.
    TextoOpcoes(&'static [&'static str]),
    /// Valor booleano (aceita `true`/`false`, `sim`/`nao`/`não`, `1`/`0`, normalizando para `"true"`/`"false"`).
    Booleano,
}

/// Especificação de uma preferência conhecida no catálogo.
#[derive(Debug, Clone, Copy)]
pub struct EspecificacaoPreferencia {
    pub chave: &'static str,
    pub tipo_valor: &'static str,
    pub valor_padrao: &'static str,
    pub descricao: &'static str,
    pub regra: RegraPreferencia,
    /// Indica se o valor da preferência é sensível/secreto.
    ///
    /// Nota (regra da tabela 3.15): caso alguma preferência secreta seja
    /// adicionada no futuro (`secreta: true`), seu valor deverá ser armazenado
    /// cifrado com a DEK do cofre. Atualmente nenhuma preferência do catálogo é
    /// secreta, portanto a cifragem não é necessária.
    pub secreta: bool,
}

/// Catálogo fixo das preferências reconhecidas pelo sistema.
pub const CATALOGO_PREFERENCIAS: &[EspecificacaoPreferencia] = &[
    EspecificacaoPreferencia {
        chave: CHAVE_TEMPO_CLIPBOARD,
        tipo_valor: "INTEGER",
        valor_padrao: "20",
        descricao: "Segundos até limpar a área de transferência",
        regra: RegraPreferencia::InteiroFaixa { min: 1, max: 600 },
        secreta: false,
    },
    EspecificacaoPreferencia {
        chave: CHAVE_TIMEOUT_INATIVIDADE,
        tipo_valor: "INTEGER",
        valor_padrao: "5",
        descricao: "Minutos sem interação até bloquear o cofre no modo shell",
        regra: RegraPreferencia::InteiroFaixa { min: 1, max: 240 },
        secreta: false,
    },
    EspecificacaoPreferencia {
        chave: CHAVE_NAVEGADOR_PADRAO,
        tipo_valor: "TEXT",
        valor_padrao: PADRAO_NAVEGADOR_PADRAO,
        descricao: "Navegador padrão para abertura e automação de sessões",
        regra: RegraPreferencia::TextoOpcoes(NAVEGADORES_PERMITIDOS),
        secreta: false,
    },
    EspecificacaoPreferencia {
        chave: CHAVE_HISTORICO_RETER_VALORES,
        tipo_valor: "BOOLEAN",
        valor_padrao: "false",
        descricao: "Guardar cifrados os valores anteriores no histórico de credenciais",
        regra: RegraPreferencia::Booleano,
        secreta: false,
    },
];

/// Preferência resolvida (com valor salvo no banco ou valor padrão do catálogo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferenciaEfetiva {
    pub chave: String,
    pub valor: String,
    pub tipo_valor: String,
    pub padrao: bool,
    pub descricao: String,
}

fn chaves_disponiveis() -> String {
    CATALOGO_PREFERENCIAS
        .iter()
        .map(|e| e.chave)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Busca a especificação de uma preferência no catálogo ou retorna erro claro.
pub fn buscar_especificacao(
    chave: &str,
) -> Result<&'static EspecificacaoPreferencia, VaultServiceError> {
    let chave_limpa = chave.trim();
    CATALOGO_PREFERENCIAS
        .iter()
        .find(|e| e.chave == chave_limpa)
        .ok_or_else(|| {
            VaultServiceError::Invalido(format!(
                "preferência desconhecida '{chave_limpa}' (chaves válidas: {})",
                chaves_disponiveis()
            ))
        })
}

/// Valida e normaliza o valor informado de acordo com a especificação da preferência.
fn validar_valor(
    espec: &EspecificacaoPreferencia,
    valor: &str,
) -> Result<String, VaultServiceError> {
    let limpo = valor.trim();
    match espec.regra {
        RegraPreferencia::InteiroFaixa { min, max } => {
            let numero: u64 = limpo.parse().map_err(|_| {
                VaultServiceError::Invalido(format!(
                    "valor '{limpo}' inválido para '{}': esperado número inteiro entre {min} e {max}",
                    espec.chave
                ))
            })?;
            if !(min..=max).contains(&numero) {
                return Err(VaultServiceError::Invalido(format!(
                    "valor {numero} fora da faixa permitida para '{}': deve estar entre {min} e {max}",
                    espec.chave
                )));
            }
            Ok(numero.to_string())
        }
        RegraPreferencia::TextoOpcoes(opcoes) => {
            let minusculo = limpo.to_ascii_lowercase();
            if opcoes.contains(&minusculo.as_str()) {
                Ok(minusculo)
            } else {
                Err(VaultServiceError::Invalido(format!(
                    "valor '{limpo}' inválido para '{}': valores permitidos: {}",
                    espec.chave,
                    opcoes.join(", ")
                )))
            }
        }
        RegraPreferencia::Booleano => {
            let minusculo = limpo.to_lowercase();
            match minusculo.as_str() {
                "true" | "sim" | "1" => Ok("true".to_string()),
                "false" | "nao" | "não" | "0" => Ok("false".to_string()),
                _ => Err(VaultServiceError::Invalido(format!(
                    "valor '{limpo}' inválido para '{}': esperado booleano (true/false, sim/nao, 1/0)",
                    espec.chave
                ))),
            }
        }
    }
}

/// Lista todas as preferências conhecidas com seus valores efetivos (salvos ou padrão).
pub fn listar_efetivas(
    db: &Database,
    usuario_id: i64,
) -> Result<Vec<PreferenciaEfetiva>, VaultServiceError> {
    let salvas = db.listar_preferencias(usuario_id)?;
    let mut resultado = Vec::with_capacity(CATALOGO_PREFERENCIAS.len());

    for espec in CATALOGO_PREFERENCIAS {
        if let Some(salva) = salvas.iter().find(|p| p.chave == espec.chave) {
            resultado.push(PreferenciaEfetiva {
                chave: espec.chave.to_string(),
                valor: salva.valor.clone(),
                tipo_valor: espec.tipo_valor.to_string(),
                padrao: false,
                descricao: salva
                    .descricao
                    .clone()
                    .unwrap_or_else(|| espec.descricao.to_string()),
            });
        } else {
            resultado.push(PreferenciaEfetiva {
                chave: espec.chave.to_string(),
                valor: espec.valor_padrao.to_string(),
                tipo_valor: espec.tipo_valor.to_string(),
                padrao: true,
                descricao: espec.descricao.to_string(),
            });
        }
    }

    Ok(resultado)
}

/// Obtém o valor efetivo de uma preferência conhecida (salvo ou padrão).
pub fn obter(
    db: &Database,
    usuario_id: i64,
    chave: &str,
) -> Result<PreferenciaEfetiva, VaultServiceError> {
    let espec = buscar_especificacao(chave)?;
    if let Some(salva) = db.buscar_preferencia(usuario_id, espec.chave)? {
        Ok(PreferenciaEfetiva {
            chave: espec.chave.to_string(),
            valor: salva.valor,
            tipo_valor: espec.tipo_valor.to_string(),
            padrao: false,
            descricao: salva
                .descricao
                .unwrap_or_else(|| espec.descricao.to_string()),
        })
    } else {
        Ok(PreferenciaEfetiva {
            chave: espec.chave.to_string(),
            valor: espec.valor_padrao.to_string(),
            tipo_valor: espec.tipo_valor.to_string(),
            padrao: true,
            descricao: espec.descricao.to_string(),
        })
    }
}

/// Define o valor de uma preferência conhecida após validar tipo, faixa ou valores permitidos.
pub fn definir(
    db: &Database,
    usuario_id: i64,
    chave: &str,
    valor: &str,
) -> Result<PreferenciaEfetiva, VaultServiceError> {
    let espec = buscar_especificacao(chave)?;
    debug_assert!(
        !espec.secreta,
        "Preferências secretas devem ser cifradas antes de persistir (tabela 3.15)"
    );
    let valor_validado = validar_valor(espec, valor)?;

    db.definir_preferencia(&NovaPreferencia {
        usuario_id,
        chave: espec.chave,
        valor: &valor_validado,
        tipo_valor: espec.tipo_valor,
        descricao: Some(espec.descricao),
    })?;

    let desc = format!(
        "Preferência '{}' definida como '{}'",
        espec.chave, valor_validado
    );
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::AlteracaoPreferencia,
        ResultadoEvento::Sucesso,
        None,
        Some(&desc),
    );

    Ok(PreferenciaEfetiva {
        chave: espec.chave.to_string(),
        valor: valor_validado,
        tipo_valor: espec.tipo_valor.to_string(),
        padrao: false,
        descricao: espec.descricao.to_string(),
    })
}

/// Redefine uma preferência conhecida para o padrão (removendo a linha personalizada do banco).
pub fn redefinir(
    db: &Database,
    usuario_id: i64,
    chave: &str,
) -> Result<PreferenciaEfetiva, VaultServiceError> {
    let espec = buscar_especificacao(chave)?;
    db.remover_preferencia(usuario_id, espec.chave)?;

    let desc = format!(
        "Preferência '{}' redefinida para o padrão ('{}')",
        espec.chave, espec.valor_padrao
    );
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::AlteracaoPreferencia,
        ResultadoEvento::Sucesso,
        None,
        Some(&desc),
    );

    Ok(PreferenciaEfetiva {
        chave: espec.chave.to_string(),
        valor: espec.valor_padrao.to_string(),
        tipo_valor: espec.tipo_valor.to_string(),
        padrao: true,
        descricao: espec.descricao.to_string(),
    })
}

/// Retorna o tempo (em segundos) até limpar a área de transferência (`tempo_clipboard`).
/// Cai no valor padrão (20s) se não houver valor salvo ou se o valor for inválido.
pub fn tempo_clipboard(db: &Database, usuario_id: i64) -> Result<u64, VaultServiceError> {
    let pref = obter(db, usuario_id, CHAVE_TEMPO_CLIPBOARD)?;
    Ok(pref.valor.parse::<u64>().unwrap_or(PADRAO_TEMPO_CLIPBOARD))
}

/// Retorna o timeout de inatividade (em minutos) para bloqueio no modo shell (`timeout_inatividade`).
/// Cai no valor padrão (5 min) se não houver valor salvo ou se o valor for inválido.
pub fn timeout_inatividade(db: &Database, usuario_id: i64) -> Result<u64, VaultServiceError> {
    let pref = obter(db, usuario_id, CHAVE_TIMEOUT_INATIVIDADE)?;
    Ok(pref
        .valor
        .parse::<u64>()
        .unwrap_or(PADRAO_TIMEOUT_INATIVIDADE))
}

/// Retorna o navegador padrão configurado (`navegador_padrao`).
/// Cai no valor padrão (`"chromium"`) se não houver valor salvo.
pub fn navegador_padrao(db: &Database, usuario_id: i64) -> Result<String, VaultServiceError> {
    let pref = obter(db, usuario_id, CHAVE_NAVEGADOR_PADRAO)?;
    Ok(pref.valor)
}

/// Retorna se os valores anteriores das credenciais devem ser retidos cifrados no histórico (`historico_reter_valores`).
/// Cai no valor padrão (`false`) se não houver valor salvo.
pub fn historico_reter_valores(db: &Database, usuario_id: i64) -> Result<bool, VaultServiceError> {
    let pref = obter(db, usuario_id, CHAVE_HISTORICO_RETER_VALORES)?;
    Ok(matches!(pref.valor.as_str(), "true" | "sim" | "1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testes::{params_teste, DbTemp};
    use crate::vault_service::{init_vault_com_params, unlock_vault};

    fn db_com_usuario(nome: &str) -> (DbTemp, Database, i64) {
        let tmp = DbTemp::new(nome);
        let db = Database::open(&tmp.0).unwrap();
        init_vault_com_params(&db, "Alice", b"senha-mestre-forte", &params_teste()).unwrap();
        let (_vault, usuario_id) = unlock_vault(&db, b"senha-mestre-forte").unwrap();
        (tmp, db, usuario_id)
    }

    #[test]
    fn test_padroes_e_listagem_efetiva() {
        let (_tmp, db, u) = db_com_usuario("pref-padroes");

        let lista = listar_efetivas(&db, u).unwrap();
        assert_eq!(lista.len(), 4);
        assert!(lista.iter().all(|p| p.padrao));

        assert_eq!(tempo_clipboard(&db, u).unwrap(), 20);
        assert_eq!(timeout_inatividade(&db, u).unwrap(), 5);
        assert_eq!(navegador_padrao(&db, u).unwrap(), "chromium");
        assert!(!historico_reter_valores(&db, u).unwrap());

        let p = obter(&db, u, "tempo_clipboard").unwrap();
        assert_eq!(p.valor, "20");
        assert!(p.padrao);
        assert_eq!(p.tipo_valor, "INTEGER");
    }

    #[test]
    fn test_definir_upsert_e_redefinir() {
        let (_tmp, db, u) = db_com_usuario("pref-upsert-reset");

        // Define tempo_clipboard
        let definida = definir(&db, u, "tempo_clipboard", "45").unwrap();
        assert_eq!(definida.valor, "45");
        assert!(!definida.padrao);
        assert_eq!(tempo_clipboard(&db, u).unwrap(), 45);

        // Verifica que foi persistido com tipo_valor e descricao no banco
        let no_banco = db
            .buscar_preferencia(u, "tempo_clipboard")
            .unwrap()
            .unwrap();
        assert_eq!(no_banco.valor, "45");
        assert_eq!(no_banco.tipo_valor, "INTEGER");
        assert_eq!(
            no_banco.descricao.as_deref(),
            Some("Segundos até limpar a área de transferência")
        );

        // Upsert para novo valor
        definir(&db, u, "tempo_clipboard", "120").unwrap();
        assert_eq!(tempo_clipboard(&db, u).unwrap(), 120);

        // Define timeout_inatividade, navegador_padrao e historico_reter_valores
        definir(&db, u, "timeout_inatividade", "15").unwrap();
        definir(&db, u, "navegador_padrao", "  Brave ").unwrap();
        definir(&db, u, "historico_reter_valores", "SIM").unwrap();
        assert_eq!(timeout_inatividade(&db, u).unwrap(), 15);
        assert_eq!(navegador_padrao(&db, u).unwrap(), "brave");
        assert!(historico_reter_valores(&db, u).unwrap());

        let efetivas = listar_efetivas(&db, u).unwrap();
        assert!(efetivas.iter().all(|p| !p.padrao));

        // Redefinir volta ao padrão e remove a linha do banco
        let redefinida = redefinir(&db, u, "tempo_clipboard").unwrap();
        assert!(redefinida.padrao);
        assert_eq!(redefinida.valor, "20");
        assert_eq!(tempo_clipboard(&db, u).unwrap(), 20);
        assert!(db
            .buscar_preferencia(u, "tempo_clipboard")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_validacao_chave_tipo_faixa_e_opcoes() {
        let (_tmp, db, u) = db_com_usuario("pref-validacao");

        // Chave desconhecida
        assert!(obter(&db, u, "chave_inexistente").is_err());
        assert!(definir(&db, u, "chave_inexistente", "10").is_err());
        assert!(redefinir(&db, u, "chave_inexistente").is_err());

        // tempo_clipboard: faixa 1..=600
        assert!(definir(&db, u, "tempo_clipboard", "0").is_err());
        assert!(definir(&db, u, "tempo_clipboard", "601").is_err());
        assert!(definir(&db, u, "tempo_clipboard", "-5").is_err());
        assert!(definir(&db, u, "tempo_clipboard", "abc").is_err());
        assert!(definir(&db, u, "tempo_clipboard", "1").is_ok());
        assert!(definir(&db, u, "tempo_clipboard", "600").is_ok());

        // timeout_inatividade: faixa 1..=240
        assert!(definir(&db, u, "timeout_inatividade", "0").is_err());
        assert!(definir(&db, u, "timeout_inatividade", "241").is_err());
        assert!(definir(&db, u, "timeout_inatividade", "texto").is_err());
        assert!(definir(&db, u, "timeout_inatividade", "1").is_ok());
        assert!(definir(&db, u, "timeout_inatividade", "240").is_ok());

        // navegador_padrao: chromium, chrome, edge, brave
        assert!(definir(&db, u, "navegador_padrao", "firefox").is_err());
        assert!(definir(&db, u, "navegador_padrao", "safari").is_err());
        assert!(definir(&db, u, "navegador_padrao", "").is_err());
        for nav in ["chromium", "chrome", "edge", "brave"] {
            assert!(definir(&db, u, "navegador_padrao", nav).is_ok());
        }

        // historico_reter_valores: booleano
        for verdadeiro in ["true", "TRUE", "sim", "SIM", "1"] {
            let p = definir(&db, u, "historico_reter_valores", verdadeiro).unwrap();
            assert_eq!(p.valor, "true");
            assert!(historico_reter_valores(&db, u).unwrap());
        }
        for falso in ["false", "FALSE", "nao", "não", "NÃO", "0"] {
            let p = definir(&db, u, "historico_reter_valores", falso).unwrap();
            assert_eq!(p.valor, "false");
            assert!(!historico_reter_valores(&db, u).unwrap());
        }
        assert!(definir(&db, u, "historico_reter_valores", "talvez").is_err());
        assert!(definir(&db, u, "historico_reter_valores", "2").is_err());
    }
}
