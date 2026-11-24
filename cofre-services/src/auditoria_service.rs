//! Serviço de auditoria (`evento_auditoria`, RF11 / RNF11).
//!
//! Registra eventos relevantes de segurança e utilização sem armazenar senhas,
//! observações, e-mails de recuperação, tokens ou conteúdo do clipboard (RNF05/RNF11).

use cofre_db::connection::DbError;
use cofre_db::models::{EventoAuditoria, FiltroAuditoria, NovoEventoAuditoria};
use cofre_db::Database;

use crate::dispositivo_service;
use crate::vault_service::VaultServiceError;

/// Limite máximo de caracteres da coluna `evento_auditoria.descricao`.
pub const MAX_DESCRICAO_AUDITORIA: usize = 500;

/// Tipos padronizados de eventos de auditoria.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoEvento {
    Inicializacao,
    Desbloqueio,
    Bloqueio,
    AlteracaoSenhaMestre,
    Criacao,
    Alteracao,
    Ativacao,
    Desativacao,
    Exclusao,
    CopiaSegredo,
    RevelacaoSegredo,
    AlteracaoPreferencia,
    RegistroDispositivo,
    Backup,
    Restauracao,
    VerificacaoAlertas,
    LoginAutomatico,
}

impl TipoEvento {
    /// Representação em MAIÚSCULAS persistida no banco.
    pub fn as_str(self) -> &'static str {
        match self {
            TipoEvento::Inicializacao => "INICIALIZACAO",
            TipoEvento::Desbloqueio => "DESBLOQUEIO",
            TipoEvento::Bloqueio => "BLOQUEIO",
            TipoEvento::AlteracaoSenhaMestre => "ALTERACAO_SENHA_MESTRE",
            TipoEvento::Criacao => "CRIACAO",
            TipoEvento::Alteracao => "ALTERACAO",
            TipoEvento::Ativacao => "ATIVACAO",
            TipoEvento::Desativacao => "DESATIVACAO",
            TipoEvento::Exclusao => "EXCLUSAO",
            TipoEvento::CopiaSegredo => "COPIA_SEGREDO",
            TipoEvento::RevelacaoSegredo => "REVELACAO_SEGREDO",
            TipoEvento::AlteracaoPreferencia => "ALTERACAO_PREFERENCIA",
            TipoEvento::RegistroDispositivo => "REGISTRO_DISPOSITIVO",
            TipoEvento::Backup => "BACKUP",
            TipoEvento::Restauracao => "RESTAURACAO",
            TipoEvento::VerificacaoAlertas => "VERIFICACAO_ALERTAS",
            TipoEvento::LoginAutomatico => "LOGIN_AUTOMATICO",
        }
    }
}

/// Resultado de um evento de auditoria (conforme CHECK da tabela `evento_auditoria`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultadoEvento {
    Sucesso,
    Falha,
    Cancelado,
    Parcial,
}

impl ResultadoEvento {
    /// Representação em MAIÚSCULAS persistida no banco.
    pub fn as_str(self) -> &'static str {
        match self {
            ResultadoEvento::Sucesso => "SUCESSO",
            ResultadoEvento::Falha => "FALHA",
            ResultadoEvento::Cancelado => "CANCELADO",
            ResultadoEvento::Parcial => "PARCIAL",
        }
    }
}

fn truncar_descricao(descricao: &str) -> String {
    descricao.chars().take(MAX_DESCRICAO_AUDITORIA).collect()
}

fn resolver_dispositivo_atual(db: &Database) -> Option<i64> {
    let fp = dispositivo_service::fingerprint_dispositivo_atual();
    db.buscar_dispositivo_por_fingerprint(fp)
        .ok()
        .flatten()
        .map(|d| d.id)
}

/// Registra um evento de auditoria retornando `Result` (útil para testes e verificação explícita).
///
/// - Preenche `dispositivo_id` automaticamente buscando o fingerprint da máquina atual (se encontrado).
/// - Trunca `descricao` em `MAX_DESCRICAO_AUDITORIA` (500) caracteres.
pub fn tentar_registrar(
    db: &Database,
    usuario_id: i64,
    tipo: TipoEvento,
    resultado: ResultadoEvento,
    credencial_id: Option<i64>,
    descricao: Option<&str>,
) -> Result<i64, DbError> {
    let dispositivo_id = resolver_dispositivo_atual(db);
    let desc_truncada = descricao.map(truncar_descricao);

    db.registrar_evento_auditoria(&NovoEventoAuditoria {
        usuario_id,
        credencial_id,
        dispositivo_id,
        tipo_evento: tipo.as_str(),
        resultado: resultado.as_str(),
        descricao: desc_truncada.as_deref(),
    })
}

/// Registra um evento de auditoria sem interromper a operação principal do usuário em caso de falha.
///
/// Caso ocorra erro ao gravar no banco, emite um `tracing::warn!` (sem segredos) e prossegue.
pub fn registrar(
    db: &Database,
    usuario_id: i64,
    tipo: TipoEvento,
    resultado: ResultadoEvento,
    credencial_id: Option<i64>,
    descricao: Option<&str>,
) {
    if let Err(e) = tentar_registrar(db, usuario_id, tipo, resultado, credencial_id, descricao) {
        tracing::warn!(
            tipo = tipo.as_str(),
            resultado = resultado.as_str(),
            "Não foi possível registrar evento de auditoria: {e}"
        );
    }
}

/// Lista os eventos de auditoria do usuário aplicando os filtros informados.
pub fn listar(
    db: &Database,
    usuario_id: i64,
    filtros: &FiltroAuditoria<'_>,
) -> Result<Vec<EventoAuditoria>, VaultServiceError> {
    Ok(db.listar_eventos_auditoria(usuario_id, filtros)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testes::{params_teste, DbTemp};
    use crate::vault_service::{init_vault_com_params, unlock_vault};

    #[test]
    fn test_registrar_truncamento_dispositivo_e_listagem() {
        let tmp = DbTemp::new("auditoria-service");
        let db = Database::open(&tmp.0).unwrap();

        init_vault_com_params(&db, "Alice", b"senha-mestre-forte", &params_teste()).unwrap();
        let (_vault, usuario_id) = unlock_vault(&db, b"senha-mestre-forte").unwrap();

        // O dispositivo atual foi registrado no init/unlock, então dispositivo_id deve ser preenchido.
        let texto_longo = "x".repeat(650);
        let id = tentar_registrar(
            &db,
            usuario_id,
            TipoEvento::Alteracao,
            ResultadoEvento::Sucesso,
            None,
            Some(&texto_longo),
        )
        .unwrap();

        let eventos = listar(&db, usuario_id, &FiltroAuditoria::default()).unwrap();
        let ev = eventos.iter().find(|e| e.id == id).unwrap();
        assert!(ev.dispositivo_id.is_some());
        assert_eq!(ev.tipo_evento, "ALTERACAO");
        assert_eq!(ev.resultado, "SUCESSO");
        assert_eq!(
            ev.descricao.as_deref().unwrap().chars().count(),
            MAX_DESCRICAO_AUDITORIA
        );

        // Filtro por tipo
        let filtrados = listar(
            &db,
            usuario_id,
            &FiltroAuditoria {
                tipo_evento: Some("INICIALIZACAO"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(filtrados.len(), 1);
        assert_eq!(filtrados[0].resultado, "SUCESSO");
    }
}
