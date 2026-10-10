//! Serviço do cofre: orquestra inicialização, desbloqueio e operações com credenciais.

use cofre_crypto::aead;
use cofre_crypto::keys::{self, UnlockedVault};
use cofre_crypto::kdf::KdfParams;
use cofre_db::Database;
use cofre_db::connection::DbError;
use cofre_db::models::{Credencial, NovaCredencial};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultServiceError {
    #[error("Erro de criptografia: {0}")]
    Crypto(#[from] cofre_crypto::CryptoError),

    #[error("Erro no banco de dados: {0}")]
    Db(#[from] DbError),

    #[error("Cofre já inicializado")]
    AlreadyInitialized,

    #[error("Cofre não inicializado. Execute 'cofre init' primeiro.")]
    NotInitialized,
}

impl From<cofre_db::rusqlite::Error> for VaultServiceError {
    fn from(e: cofre_db::rusqlite::Error) -> Self {
        VaultServiceError::Db(DbError::from(e))
    }
}

/// Alterações possíveis em uma credencial. Campos `None` não são alterados.
#[derive(Default)]
pub struct EdicaoCredencial<'a> {
    pub nome_exibicao: Option<&'a str>,
    pub identificador: Option<&'a str>,
    pub favorita: Option<bool>,
    pub senha: Option<&'a [u8]>,
    /// `Some(None)` remove a observação; `Some(Some(texto))` a substitui.
    pub observacao: Option<Option<&'a str>>,
}

/// Inicializa um novo cofre com os parâmetros de KDF padrão.
pub fn init_vault(db: &Database, nome: &str, password: &[u8]) -> Result<(), VaultServiceError> {
    init_vault_com_params(db, nome, password, &KdfParams::default())
}

/// Inicializa um novo cofre com parâmetros de KDF específicos.
pub fn init_vault_com_params(
    db: &Database,
    nome: &str,
    password: &[u8],
    params: &KdfParams,
) -> Result<(), VaultServiceError> {
    // Verificar se já existe um usuário ativo
    if db.buscar_usuario_ativo().is_ok() {
        return Err(VaultServiceError::AlreadyInitialized);
    }

    let vault_data = keys::init_vault(password, params)?;

    db.criar_usuario(
        nome,
        &vault_data.verifier,
        &vault_data.kek_salt,
        &vault_data.kdf_params_json,
        &vault_data.encrypted_dek,
        &vault_data.dek_nonce,
        &vault_data.verifier_salt,
    )?;

    Ok(())
}

/// Desbloqueia o cofre e retorna a sessão com a DEK em memória protegida.
pub fn unlock_vault(db: &Database, password: &[u8]) -> Result<(UnlockedVault, i64), VaultServiceError> {
    let usuario = db.buscar_usuario_ativo().map_err(|e| match e {
        DbError::NotFound => VaultServiceError::NotInitialized,
        other => VaultServiceError::Db(other),
    })?;

    let vault = keys::unlock_vault(
        password,
        &usuario.salt_kdf,
        &usuario.verificador_salt,
        &usuario.verificador_mestre,
        &usuario.dek_criptografada,
        &usuario.dek_nonce,
        &usuario.parametros_kdf,
    )?;

    // Atualizar último acesso
    db.atualizar_ultimo_acesso(usuario.id)?;

    Ok((vault, usuario.id))
}

/// Troca a senha mestre. Apenas a DEK é recifrada; as credenciais não mudam.
///
/// Mantém os parâmetros de KDF já gravados para o usuário.
pub fn alterar_senha_mestre(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
    nova_senha: &[u8],
) -> Result<(), VaultServiceError> {
    let usuario = db.buscar_usuario_ativo()?;
    if usuario.id != usuario_id {
        return Err(VaultServiceError::Db(DbError::NotFound));
    }
    let params: KdfParams = serde_json::from_str(&usuario.parametros_kdf)
        .map_err(cofre_crypto::CryptoError::from)?;

    let novos = keys::change_master_password(vault, nova_senha, &params)?;

    db.atualizar_autenticacao(
        usuario_id,
        &novos.verifier,
        &novos.kek_salt,
        &novos.kdf_params_json,
        &novos.encrypted_dek,
        &novos.dek_nonce,
        &novos.verifier_salt,
    )?;

    Ok(())
}

/// Busca uma credencial garantindo que ela pertence ao usuário.
pub fn buscar_credencial(
    db: &Database,
    credencial_id: i64,
    usuario_id: i64,
) -> Result<Credencial, VaultServiceError> {
    let cred = db.buscar_credencial(credencial_id)?;
    if cred.usuario_id != usuario_id {
        return Err(VaultServiceError::Db(DbError::NotFound));
    }
    Ok(cred)
}

fn aad_segredo(credencial_id: i64, usuario_id: i64) -> String {
    aead::build_aad("credencial", "segredo_criptografado", credencial_id, usuario_id)
}

fn aad_observacao(credencial_id: i64, usuario_id: i64) -> String {
    aead::build_aad("credencial", "observacao_criptografada", credencial_id, usuario_id)
}

/// Cifra e grava a senha de uma credencial existente.
fn gravar_senha(
    db: &Database,
    vault: &UnlockedVault,
    credencial_id: i64,
    usuario_id: i64,
    senha: &[u8],
) -> Result<(), VaultServiceError> {
    let (nonce, cifrado) = vault.encrypt(senha, &aad_segredo(credencial_id, usuario_id))?;
    db.definir_segredo_credencial(credencial_id, &cifrado, &nonce)?;
    Ok(())
}

/// Cifra e grava (ou remove) a observação de uma credencial existente.
fn gravar_observacao(
    db: &Database,
    vault: &UnlockedVault,
    credencial_id: i64,
    usuario_id: i64,
    observacao: Option<&str>,
) -> Result<(), VaultServiceError> {
    match observacao {
        Some(obs) => {
            let (nonce, cifrado) =
                vault.encrypt(obs.as_bytes(), &aad_observacao(credencial_id, usuario_id))?;
            db.definir_observacao_credencial(credencial_id, Some(&cifrado), Some(&nonce))?;
        }
        None => db.definir_observacao_credencial(credencial_id, None, None)?,
    }
    Ok(())
}

/// Adiciona uma nova credencial cifrada ao cofre.
#[allow(clippy::too_many_arguments)]
pub fn adicionar_credencial(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
    servico_id: i64,
    nome_exibicao: &str,
    identificador: &str,
    senha_plaintext: &[u8],
    observacao: Option<&str>,
) -> Result<i64, VaultServiceError> {
    // A AAD precisa do ID real da linha, que só existe após o INSERT. Por isso a
    // credencial é inserida com campos cifrados vazios e atualizada em seguida,
    // tudo na mesma transação: nunca fica gravada uma linha sem segredo.
    let tx = db.conn.unchecked_transaction()?;

    let nova = NovaCredencial {
        usuario_id,
        servico_id,
        nome_exibicao: nome_exibicao.to_string(),
        identificador: identificador.to_string(),
        segredo_criptografado: Vec::new(),
        nonce: Vec::new(),
        observacao_criptografada: None,
        observacao_nonce: None,
        favorita: false,
    };
    let id = db.criar_credencial(&nova)?;

    gravar_senha(db, vault, id, usuario_id, senha_plaintext)?;
    if observacao.is_some() {
        gravar_observacao(db, vault, id, usuario_id, observacao)?;
    }

    tx.commit()?;
    Ok(id)
}

/// Aplica as alterações informadas a uma credencial, em uma única transação.
pub fn editar_credencial(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
    credencial_id: i64,
    edicao: &EdicaoCredencial<'_>,
) -> Result<(), VaultServiceError> {
    let atual = buscar_credencial(db, credencial_id, usuario_id)?;
    let tx = db.conn.unchecked_transaction()?;

    if edicao.nome_exibicao.is_some() || edicao.identificador.is_some() || edicao.favorita.is_some() {
        db.atualizar_dados_credencial(
            credencial_id,
            edicao.nome_exibicao.unwrap_or(&atual.nome_exibicao),
            edicao.identificador.unwrap_or(&atual.identificador),
            edicao.favorita.unwrap_or(atual.favorita),
        )?;
    }
    if let Some(senha) = edicao.senha {
        gravar_senha(db, vault, credencial_id, usuario_id, senha)?;
    }
    if let Some(observacao) = edicao.observacao {
        gravar_observacao(db, vault, credencial_id, usuario_id, observacao)?;
    }

    tx.commit()?;
    Ok(())
}

/// Descriptografa e retorna a senha de uma credencial.
pub fn revelar_senha(
    db: &Database,
    vault: &UnlockedVault,
    credencial_id: i64,
    usuario_id: i64,
) -> Result<Vec<u8>, VaultServiceError> {
    let cred = buscar_credencial(db, credencial_id, usuario_id)?;
    let plaintext = vault.decrypt(
        &cred.nonce,
        &cred.segredo_criptografado,
        &aad_segredo(cred.id, usuario_id),
    )?;

    // Atualizar último uso
    db.atualizar_ultimo_uso_credencial(credencial_id)?;

    Ok(plaintext)
}

/// Descriptografa a observação de uma credencial, se houver.
pub fn revelar_observacao(
    vault: &UnlockedVault,
    cred: &Credencial,
) -> Result<Option<Vec<u8>>, VaultServiceError> {
    match (&cred.observacao_criptografada, &cred.observacao_nonce) {
        (Some(cifrado), Some(nonce)) => Ok(Some(vault.decrypt(
            nonce,
            cifrado,
            &aad_observacao(cred.id, cred.usuario_id),
        )?)),
        _ => Ok(None),
    }
}

/// Ativa ou desativa uma credencial do usuário.
pub fn definir_credencial_ativa(
    db: &Database,
    usuario_id: i64,
    credencial_id: i64,
    ativa: bool,
) -> Result<(), VaultServiceError> {
    buscar_credencial(db, credencial_id, usuario_id)?;
    db.definir_credencial_ativa(credencial_id, ativa)?;
    Ok(())
}

/// Exclui definitivamente uma credencial do usuário.
pub fn excluir_credencial(
    db: &Database,
    usuario_id: i64,
    credencial_id: i64,
) -> Result<(), VaultServiceError> {
    buscar_credencial(db, credencial_id, usuario_id)?;
    db.excluir_credencial(credencial_id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cofre_db::models::NovoServico;

    /// Banco temporário em arquivo, removido ao final do teste.
    struct DbTemp(std::path::PathBuf);

    impl DbTemp {
        fn new(nome: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("cofre-teste-{nome}-{}.db", std::process::id()));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
    }

    impl Drop for DbTemp {
        fn drop(&mut self) {
            for sufixo in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{sufixo}", self.0.display()));
            }
        }
    }

    /// Parâmetros leves de KDF: os padrões (256 MiB) deixam os testes muito lentos.
    fn params_teste() -> KdfParams {
        KdfParams { m_cost_kib: 16_384, t_cost: 1, p_cost: 1 }
    }

    /// Cria um cofre desbloqueado com um serviço cadastrado.
    fn cofre_com_servico(tmp: &DbTemp) -> (Database, UnlockedVault, i64, i64) {
        let db = Database::open(&tmp.0).unwrap();
        init_vault_com_params(&db, "Teste", b"senha-mestre-forte", &params_teste()).unwrap();
        let (vault, usuario_id) = unlock_vault(&db, b"senha-mestre-forte").unwrap();
        let servico_id = db
            .criar_servico(&NovoServico {
                categoria_id: None,
                nome: "GitHub".into(),
                dominio_principal: "github.com".into(),
                url_principal: None,
                descricao: None,
            })
            .unwrap();
        (db, vault, usuario_id, servico_id)
    }

    #[test]
    fn test_init_unlock_adicionar_e_revelar() {
        let tmp = DbTemp::new("roundtrip");
        let (db, vault, usuario_id, servico_id) = cofre_com_servico(&tmp);

        assert!(unlock_vault(&db, b"senha-errada").is_err());

        let a = adicionar_credencial(&db, &vault, usuario_id, servico_id, "A", "a@x.com", b"senha-a", Some("nota a")).unwrap();
        let b = adicionar_credencial(&db, &vault, usuario_id, servico_id, "B", "b@x.com", b"senha-b", None).unwrap();

        assert_eq!(revelar_senha(&db, &vault, a, usuario_id).unwrap(), b"senha-a");
        assert_eq!(revelar_senha(&db, &vault, b, usuario_id).unwrap(), b"senha-b");

        let cred_a = db.buscar_credencial(a).unwrap();
        assert_eq!(revelar_observacao(&vault, &cred_a).unwrap().unwrap(), b"nota a");
        let cred_b = db.buscar_credencial(b).unwrap();
        assert!(revelar_observacao(&vault, &cred_b).unwrap().is_none());

        // Copiar o segredo cifrado de B para A deve ser detectado pela AAD.
        db.definir_segredo_credencial(a, &cred_b.segredo_criptografado, &cred_b.nonce)
            .unwrap();
        assert!(revelar_senha(&db, &vault, a, usuario_id).is_err());
    }

    #[test]
    fn test_editar_credencial() {
        let tmp = DbTemp::new("editar");
        let (db, vault, usuario_id, servico_id) = cofre_com_servico(&tmp);
        let id = adicionar_credencial(&db, &vault, usuario_id, servico_id, "A", "a@x.com", b"antiga", Some("nota")).unwrap();

        // Só o nome muda; o resto é preservado.
        editar_credencial(&db, &vault, usuario_id, id, &EdicaoCredencial {
            nome_exibicao: Some("Novo nome"),
            ..Default::default()
        })
        .unwrap();
        let cred = db.buscar_credencial(id).unwrap();
        assert_eq!(cred.nome_exibicao, "Novo nome");
        assert_eq!(cred.identificador, "a@x.com");
        assert!(!cred.favorita);
        assert_eq!(revelar_senha(&db, &vault, id, usuario_id).unwrap(), b"antiga");

        editar_credencial(&db, &vault, usuario_id, id, &EdicaoCredencial {
            identificador: Some("b@x.com"),
            favorita: Some(true),
            senha: Some(b"nova"),
            observacao: Some(None),
            ..Default::default()
        })
        .unwrap();
        let cred = db.buscar_credencial(id).unwrap();
        assert_eq!(cred.identificador, "b@x.com");
        assert!(cred.favorita);
        assert_eq!(revelar_senha(&db, &vault, id, usuario_id).unwrap(), b"nova");
        assert!(revelar_observacao(&vault, &cred).unwrap().is_none());
    }

    #[test]
    fn test_desativar_reativar_e_excluir() {
        let tmp = DbTemp::new("ciclo");
        let (db, vault, usuario_id, servico_id) = cofre_com_servico(&tmp);
        let id = adicionar_credencial(&db, &vault, usuario_id, servico_id, "A", "a@x.com", b"s", None).unwrap();

        definir_credencial_ativa(&db, usuario_id, id, false).unwrap();
        assert!(db.listar_credenciais(usuario_id, true).unwrap().is_empty());
        assert_eq!(db.listar_credenciais(usuario_id, false).unwrap().len(), 1);

        definir_credencial_ativa(&db, usuario_id, id, true).unwrap();
        assert_eq!(db.listar_credenciais(usuario_id, true).unwrap().len(), 1);

        // Com credencial vinculada, o serviço não pode ser excluído.
        assert!(db.excluir_servico(servico_id).is_err());

        excluir_credencial(&db, usuario_id, id).unwrap();
        assert!(matches!(db.buscar_credencial(id), Err(DbError::NotFound)));
        db.excluir_servico(servico_id).unwrap();
    }

    #[test]
    fn test_outro_usuario_nao_acessa_credencial() {
        let tmp = DbTemp::new("dono");
        let (db, vault, usuario_id, servico_id) = cofre_com_servico(&tmp);
        let id = adicionar_credencial(&db, &vault, usuario_id, servico_id, "A", "a@x.com", b"s", None).unwrap();

        let outro = usuario_id + 1;
        assert!(revelar_senha(&db, &vault, id, outro).is_err());
        assert!(excluir_credencial(&db, outro, id).is_err());
        assert!(db.buscar_credencial(id).is_ok());
    }

    #[test]
    fn test_alterar_senha_mestre_preserva_credenciais() {
        let tmp = DbTemp::new("senha-mestre");
        let (db, vault, usuario_id, servico_id) = cofre_com_servico(&tmp);
        let id = adicionar_credencial(&db, &vault, usuario_id, servico_id, "A", "a@x.com", b"segredo", None).unwrap();

        alterar_senha_mestre(&db, &vault, usuario_id, b"nova-senha-mestre").unwrap();

        assert!(unlock_vault(&db, b"senha-mestre-forte").is_err());
        let (novo_vault, _) = unlock_vault(&db, b"nova-senha-mestre").unwrap();
        assert_eq!(revelar_senha(&db, &novo_vault, id, usuario_id).unwrap(), b"segredo");
    }
}
