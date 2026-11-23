//! Identificação e registro automático do dispositivo local.
//!
//! Calcula um fingerprint SHA-256 estável a partir dos metadados da máquina
//! (hostname, SO, arquitetura, usuário do SO e `/etc/machine-id` no Linux)
//! sem armazenar identificadores brutos de hardware no banco.

use sha2::{Digest, Sha256};

use cofre_db::connection::DbError;
use cofre_db::models::NovoDispositivo;
use cofre_db::Database;

/// Obtém o hostname da máquina atual.
pub fn obter_hostname() -> String {
    for caminho in ["/etc/hostname", "/proc/sys/kernel/hostname"] {
        if let Ok(conteudo) = std::fs::read_to_string(caminho) {
            let limpo = conteudo.trim();
            if !limpo.is_empty() {
                return truncar(limpo, 100);
            }
        }
    }

    for var in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(val) = std::env::var(var) {
            let limpo = val.trim();
            if !limpo.is_empty() {
                return truncar(limpo, 100);
            }
        }
    }

    "desconhecido".to_string()
}

/// Obtém a identificação do sistema operacional (`std::env::consts::OS` + versão se disponível).
pub fn obter_sistema_operacional() -> String {
    let os = std::env::consts::OS;

    if let Ok(os_release) = std::fs::read_to_string("/etc/os-release") {
        for linha in os_release.lines() {
            if let Some(valor) = linha.strip_prefix("PRETTY_NAME=") {
                let limpo = valor.trim().trim_matches('"').trim_matches('\'');
                if !limpo.is_empty() {
                    return truncar(&format!("{os} ({limpo})"), 100);
                }
            }
        }
    }

    if let Ok(kernel) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let limpo = kernel.trim();
        if !limpo.is_empty() {
            return truncar(&format!("{os} ({limpo})"), 100);
        }
    }

    os.to_string()
}

fn obter_usuario_so() -> String {
    for var in ["USER", "USERNAME", "LOGNAME"] {
        if let Ok(val) = std::env::var(var) {
            let limpo = val.trim();
            if !limpo.is_empty() {
                return limpo.to_string();
            }
        }
    }
    "desconhecido".to_string()
}

fn obter_machine_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            let limpo = id.trim();
            if !limpo.is_empty() {
                return Some(limpo.to_string());
            }
        }
    }
    None
}

fn truncar(texto: &str, max_chars: usize) -> String {
    texto.chars().take(max_chars).collect()
}

/// Calcula o hash SHA-256 em hexadecimal dos dados estáveis da máquina.
pub fn calcular_fingerprint_componentes(
    hostname: &str,
    os: &str,
    arch: &str,
    usuario_so: &str,
    machine_id: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(b"|");
    hasher.update(os.as_bytes());
    hasher.update(b"|");
    hasher.update(arch.as_bytes());
    hasher.update(b"|");
    hasher.update(usuario_so.as_bytes());
    if let Some(mid) = machine_id {
        if !mid.is_empty() {
            hasher.update(b"|");
            hasher.update(mid.as_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

/// Coleta os dados do dispositivo atual prontos para persistência.
pub fn coletar_dados_dispositivo(usuario_id: i64, confiavel: bool) -> NovoDispositivo {
    let nome = obter_hostname();
    let sistema_operacional = Some(obter_sistema_operacional());
    let usuario_so = obter_usuario_so();
    let machine_id = obter_machine_id();
    let fingerprint = calcular_fingerprint_componentes(
        &nome,
        std::env::consts::OS,
        std::env::consts::ARCH,
        &usuario_so,
        machine_id.as_deref(),
    );

    NovoDispositivo {
        usuario_id,
        nome,
        sistema_operacional,
        fingerprint_hash: Some(fingerprint),
        confiavel,
    }
}

/// Registra um novo dispositivo ou atualiza `ultimo_acesso_em` caso o fingerprint já exista.
pub fn registrar_ou_atualizar_dispositivo(
    db: &Database,
    novo: &NovoDispositivo,
) -> Result<i64, DbError> {
    if let Some(fp) = novo.fingerprint_hash.as_deref() {
        if let Some(existente) = db.buscar_dispositivo_por_fingerprint(fp)? {
            db.atualizar_ultimo_acesso_dispositivo(existente.id)?;
            return Ok(existente.id);
        }
    }
    db.criar_dispositivo(novo)
}

/// Coleta os dados da máquina atual e registra/atualiza o dispositivo no banco.
///
/// - Se o dispositivo ainda não existir, é criado com `confiavel = confiavel_se_novo`.
/// - Se já existir (mesmo `fingerprint_hash`), apenas atualiza `ultimo_acesso_em`.
pub fn registrar_dispositivo_atual(
    db: &Database,
    usuario_id: i64,
    confiavel_se_novo: bool,
) -> Result<i64, DbError> {
    let dados = coletar_dados_dispositivo(usuario_id, confiavel_se_novo);
    registrar_ou_atualizar_dispositivo(db, &dados)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testes::{params_teste, DbTemp};
    use crate::vault_service::{init_vault_com_params, unlock_vault};

    #[test]
    fn test_fingerprint_deterministico_e_formato_hex() {
        let fp1 =
            calcular_fingerprint_componentes("host-a", "linux", "x86_64", "alice", Some("id123"));
        let fp2 =
            calcular_fingerprint_componentes("host-a", "linux", "x86_64", "alice", Some("id123"));
        let fp3 =
            calcular_fingerprint_componentes("host-b", "linux", "x86_64", "alice", Some("id123"));

        assert_eq!(fp1.len(), 64);
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_registro_dispositivo_no_init_e_unlock() {
        let tmp = DbTemp::new("dispositivo-init-unlock");
        let db = Database::open(&tmp.0).unwrap();

        // 1. No init, o dispositivo atual deve ser registrado como confiável.
        init_vault_com_params(&db, "Alice", b"senha-mestre-forte", &params_teste()).unwrap();
        let usuario = db.buscar_usuario_ativo().unwrap();
        let lista = db.listar_dispositivos(usuario.id).unwrap();
        assert_eq!(lista.len(), 1);
        assert!(lista[0].confiavel);
        assert!(lista[0].fingerprint_hash.is_some());
        assert!(lista[0].ultimo_acesso_em.is_some());

        // 2. No unlock na mesma máquina, não duplica o dispositivo e preserva confiavel = true.
        let (_vault, usuario_id) = unlock_vault(&db, b"senha-mestre-forte").unwrap();
        let lista_apos_unlock = db.listar_dispositivos(usuario_id).unwrap();
        assert_eq!(lista_apos_unlock.len(), 1);
        assert!(lista_apos_unlock[0].confiavel);

        // 3. Um acesso vindo de outro dispositivo (fingerprint novo) registra com confiavel = false.
        let outro_fp =
            calcular_fingerprint_componentes("outro-pc", "windows", "x86_64", "alice", None);
        let novo_id = registrar_ou_atualizar_dispositivo(
            &db,
            &NovoDispositivo {
                usuario_id,
                nome: "outro-pc".into(),
                sistema_operacional: Some("windows".into()),
                fingerprint_hash: Some(outro_fp.clone()),
                confiavel: false,
            },
        )
        .unwrap();

        let buscado = db
            .buscar_dispositivo_por_fingerprint(&outro_fp)
            .unwrap()
            .unwrap();
        assert_eq!(buscado.id, novo_id);
        assert!(!buscado.confiavel);

        // 4. Novo acesso do segundo dispositivo apenas atualiza ultimo_acesso_em, mantendo 2 dispositivos.
        let id_atualizado = registrar_ou_atualizar_dispositivo(
            &db,
            &NovoDispositivo {
                usuario_id,
                nome: "outro-pc".into(),
                sistema_operacional: Some("windows".into()),
                fingerprint_hash: Some(outro_fp),
                confiavel: false,
            },
        )
        .unwrap();
        assert_eq!(id_atualizado, novo_id);
        assert_eq!(db.listar_dispositivos(usuario_id).unwrap().len(), 2);
    }
}
