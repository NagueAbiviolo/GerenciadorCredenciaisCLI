//! Serviço de backups cifrados do cofre (`backup`, RF14 / RNF10).
//!
//! Orquestra criação (`VACUUM INTO`), listagem, verificação de integridade/autenticidade,
//! restauração segura (por ID registrado ou por arquivo `.cbk` em recuperação de desastre)
//! e exclusão de backups.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Local;
use cofre_backup::{self, BackupError, MaterialDesbloqueio, VERSAO_FORMATO};
use cofre_crypto::keys::UnlockedVault;
use cofre_db::connection::DbError;
use cofre_db::models::{Backup, EventoAuditoria, NovoBackup};
use cofre_db::{rusqlite, Database};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::auditoria_service::{self, ResultadoEvento, TipoEvento};

/// Cabeçalho mágico de 16 bytes de qualquer arquivo SQLite 3 válido.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

#[derive(Debug, Error)]
pub enum BackupServiceError {
    #[error("Erro no formato/criptografia do backup: {0}")]
    Backup(#[from] BackupError),

    #[error("Erro de criptografia: {0}")]
    Crypto(#[from] cofre_crypto::CryptoError),

    #[error("Erro no banco de dados: {0}")]
    Db(#[from] DbError),

    #[error("Erro de entrada/saída: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cofre não inicializado. Execute 'cofre init' ou use 'cofre backup restore --arquivo <CAMINHO>'.")]
    CofreNaoInicializado,

    #[error("Arquivo de backup inválido: {0}")]
    BackupInvalido(String),

    #[error("Falha ao obter a senha mestre do backup: {0}")]
    Prompt(String),
}

impl From<rusqlite::Error> for BackupServiceError {
    fn from(e: rusqlite::Error) -> Self {
        BackupServiceError::Db(DbError::from(e))
    }
}

/// Guard RAII que garante a remoção de um arquivo temporário (e possíveis `-wal`/`-shm`)
/// em todos os caminhos de saída ou erro.
struct GuardArquivoTemp {
    caminho: PathBuf,
    ativo: bool,
}

impl GuardArquivoTemp {
    fn novo(caminho: PathBuf) -> Self {
        Self {
            caminho,
            ativo: true,
        }
    }

    fn caminho(&self) -> &Path {
        &self.caminho
    }

    /// Desativa a remoção automática após um `rename` bem-sucedido.
    fn desarmar(&mut self) {
        self.ativo = false;
    }
}

impl Drop for GuardArquivoTemp {
    fn drop(&mut self) {
        if self.ativo {
            remover_sqlite_e_auxiliares(&self.caminho);
        }
    }
}

/// Remove um arquivo SQLite e seus possíveis arquivos auxiliares `-wal` e `-shm`.
fn remover_sqlite_e_auxiliares(caminho: &Path) {
    let _ = fs::remove_file(caminho);
    for sufixo in ["-wal", "-shm"] {
        let aux = caminho_com_sufixo(caminho, sufixo);
        let _ = fs::remove_file(aux);
    }
}

fn caminho_com_sufixo(caminho: &Path, sufixo: &str) -> PathBuf {
    let mut os = caminho.as_os_str().to_os_string();
    os.push(sufixo);
    PathBuf::from(os)
}

/// Gera um sufixo hexadecimal aleatório de 16 caracteres usando CSPRNG.
fn sufixo_aleatorio_hex() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(16);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Aplica permissão `0600` (leitura e escrita apenas para o dono) em sistemas Unix.
fn aplicar_permissao_0600(caminho: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(caminho, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = caminho;
    }
    Ok(())
}

/// Grava bytes em um novo arquivo criando-o já com modo `0600` no Unix.
fn gravar_arquivo_0600(caminho: &Path, dados: &[u8]) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut arq = opts.open(caminho)?;
    arq.write_all(dados)?;
    arq.sync_all()?;
    Ok(())
}

/// Escolhe o caminho final `cofre-backup-AAAAMMDD-HHMMSS.cbk` dentro de `destino_dir`,
/// acrescentando `-1`, `-2`, ... caso o arquivo já exista para nunca sobrescrever.
fn escolher_caminho_backup(destino_dir: &Path) -> (String, PathBuf) {
    let carimbo = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let base = format!("cofre-backup-{carimbo}");

    let nome_inicial = format!("{base}.cbk");
    let caminho_inicial = destino_dir.join(&nome_inicial);
    if !caminho_inicial.exists() {
        return (nome_inicial, caminho_inicial);
    }

    let mut indice = 1u32;
    loop {
        let nome = format!("{base}-{indice}.cbk");
        let caminho = destino_dir.join(&nome);
        if !caminho.exists() {
            return (nome, caminho);
        }
        indice += 1;
    }
}

/// Escolhe um caminho `cofre.db.antes-restauracao-AAAAMMDD-HHMMSS` sem sobrescrever existentes.
fn escolher_caminho_antes_restauracao(db_path: &Path) -> PathBuf {
    let carimbo = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let base_sufixo = format!(".antes-restauracao-{carimbo}");
    let primeiro = caminho_com_sufixo(db_path, &base_sufixo);
    if !primeiro.exists() {
        return primeiro;
    }

    let mut indice = 1u32;
    loop {
        let sufixo = format!("{base_sufixo}-{indice}");
        let candidato = caminho_com_sufixo(db_path, &sufixo);
        if !candidato.exists() {
            return candidato;
        }
        indice += 1;
    }
}

fn caminho_absoluto_string(caminho: &Path) -> String {
    let abs = fs::canonicalize(caminho).unwrap_or_else(|_| {
        if caminho.is_absolute() {
            caminho.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|d| d.join(caminho))
                .unwrap_or_else(|_| caminho.to_path_buf())
        }
    });
    abs.to_string_lossy().into_owned()
}

/// Cria um novo backup cifrado do banco de dados em `destino_dir`.
///
/// 1. Extrai um snapshot consistente com `VACUUM INTO '<tmp>'` no próprio `destino_dir`.
/// 2. Restringe permissões do temporário para `0600`, lê seus bytes em buffer `Zeroizing` e remove o temporário.
/// 3. Cifra o conteúdo com a DEK e cabeçalho autenticado via AAD (`cofre_backup::montar_arquivo`).
/// 4. Grava o arquivo `.cbk` via temporário (`0600`) + `rename` sem sobrescrever backups existentes.
/// 5. Registra os metadados na tabela `backup` e o evento `BACKUP` na auditoria.
pub fn criar(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
    destino_dir: &Path,
) -> Result<Backup, BackupServiceError> {
    let usuario = db.buscar_usuario_ativo().map_err(|e| match e {
        DbError::NotFound => BackupServiceError::CofreNaoInicializado,
        outro => BackupServiceError::Db(outro),
    })?;
    if usuario.id != usuario_id {
        return Err(BackupServiceError::Db(DbError::NotFound));
    }

    fs::create_dir_all(destino_dir)?;

    // 1. Snapshot consistente com VACUUM INTO em arquivo temporário protegido por guard
    let nome_tmp_db = format!(".cofre-snapshot-{}.tmp", sufixo_aleatorio_hex());
    let guard_tmp_db = GuardArquivoTemp::novo(destino_dir.join(nome_tmp_db));
    let caminho_tmp_str = guard_tmp_db
        .caminho()
        .to_str()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Caminho do diretório de destino contém caracteres não UTF-8",
            )
        })?
        .to_string();

    db.conn
        .execute("VACUUM INTO ?1", rusqlite::params![caminho_tmp_str])?;
    aplicar_permissao_0600(guard_tmp_db.caminho())?;

    // 2. Ler bytes do snapshot em claro para buffer Zeroizing e apagar imediatamente o arquivo tmp
    let bytes_db = Zeroizing::new(fs::read(guard_tmp_db.caminho())?);
    drop(guard_tmp_db);

    // 3. Montar arquivo cifrado com cabeçalho contendo o material de desbloqueio
    let material = MaterialDesbloqueio::de_usuario(&usuario);
    let bytes_cbk = cofre_backup::montar_arquivo(vault, material, &bytes_db)?;
    drop(bytes_db);

    let hash = cofre_backup::hash_integridade(&bytes_cbk);
    let tamanho_bytes = i64::try_from(bytes_cbk.len()).unwrap_or(i64::MAX);

    // 4. Gravar em arquivo temporário 0600 e renomear para o nome final .cbk
    let (nome_arquivo, caminho_final) = escolher_caminho_backup(destino_dir);
    let nome_tmp_cbk = format!(".cofre-cbk-{}.tmp", sufixo_aleatorio_hex());
    let mut guard_tmp_cbk = GuardArquivoTemp::novo(destino_dir.join(nome_tmp_cbk));

    gravar_arquivo_0600(guard_tmp_cbk.caminho(), &bytes_cbk)?;
    fs::rename(guard_tmp_cbk.caminho(), &caminho_final)?;
    guard_tmp_cbk.desarmar();

    let caminho_absoluto = caminho_absoluto_string(&caminho_final);

    // 5. Registrar metadados no banco e evento na auditoria
    let id = db.registrar_backup(&NovoBackup {
        usuario_id,
        nome_arquivo: &nome_arquivo,
        caminho_arquivo: &caminho_absoluto,
        hash_integridade: &hash,
        tamanho_bytes,
        versao_formato: VERSAO_FORMATO,
    })?;

    let backup = db.buscar_backup(id, usuario_id)?;

    let desc = format!(
        "Backup #{id} criado: '{}' ({tamanho_bytes} bytes)",
        backup.nome_arquivo
    );
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::Backup,
        ResultadoEvento::Sucesso,
        None,
        Some(&desc),
    );

    Ok(backup)
}

/// Resultado detalhado da verificação de integridade e autenticidade de um backup.
#[derive(Debug, Clone)]
pub struct ResultadoVerificacao {
    pub backup: Backup,
    pub arquivo_existe: bool,
    pub hash_confere: bool,
    pub decifragem_ok: bool,
    pub sqlite_valido: bool,
    pub valido: bool,
    pub detalhe: String,
}

/// Verifica se os bytes decifrados correspondem a um banco SQLite 3 íntegro contendo
/// a tabela `usuario` com um usuário ativo.
fn validar_bytes_sqlite_em_tmp(dir_base: &Path, bytes_db: &[u8]) -> Result<(), BackupServiceError> {
    if bytes_db.len() < SQLITE_HEADER.len() || &bytes_db[..SQLITE_HEADER.len()] != SQLITE_HEADER {
        return Err(BackupServiceError::BackupInvalido(
            "Cabeçalho SQLite format 3 ausente ou inválido".into(),
        ));
    }

    let dir_tmp = if dir_base.is_dir() {
        dir_base.to_path_buf()
    } else {
        std::env::temp_dir()
    };

    let guard_tmp = GuardArquivoTemp::novo(
        dir_tmp.join(format!(".cofre-verify-{}.tmp", sufixo_aleatorio_hex())),
    );
    gravar_arquivo_0600(guard_tmp.caminho(), bytes_db)?;

    let conn = rusqlite::Connection::open(guard_tmp.caminho())?;
    let integridade: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if !integridade.eq_ignore_ascii_case("ok") {
        return Err(BackupServiceError::BackupInvalido(format!(
            "Falha no PRAGMA integrity_check: {integridade}"
        )));
    }

    let usuarios_ativos: i64 = conn
        .query_row("SELECT COUNT(*) FROM usuario WHERE ativo = 1", [], |r| {
            r.get(0)
        })
        .map_err(|_| {
            BackupServiceError::BackupInvalido(
                "Tabela 'usuario' ausente ou inválida no backup".into(),
            )
        })?;

    if usuarios_ativos < 1 {
        return Err(BackupServiceError::BackupInvalido(
            "Nenhum usuário ativo encontrado no banco do backup".into(),
        ));
    }

    drop(conn);
    drop(guard_tmp);
    Ok(())
}

/// Verifica um backup registrado:
/// 1. Confere se o arquivo existe no disco.
/// 2. Calcula o hash BLAKE3 e compara com `hash_integridade` registrado.
/// 3. Decifra com a DEK atual (ou com a DEK do cabeçalho se for a mesma) validando o AAD.
/// 4. Verifica o cabeçalho `"SQLite format 3\0"`, `PRAGMA integrity_check` e a tabela `usuario`.
/// 5. Atualiza a coluna `valido` (0/1) no banco e registra auditoria (`SUCESSO` ou `FALHA`).
pub fn verificar(
    db: &Database,
    vault: &UnlockedVault,
    usuario_id: i64,
    id: i64,
) -> Result<ResultadoVerificacao, BackupServiceError> {
    let mut backup = db.buscar_backup(id, usuario_id)?;
    let caminho = Path::new(&backup.caminho_arquivo);

    let mut arquivo_existe = false;
    let mut hash_confere = false;
    let mut decifragem_ok = false;
    let mut sqlite_valido = false;
    let detalhe: String;

    match fs::read(caminho) {
        Err(_) => {
            detalhe = "Arquivo de backup não encontrado ou ilegível".into();
        }
        Ok(bytes_arq) => {
            arquivo_existe = true;
            let hash_atual = cofre_backup::hash_integridade(&bytes_arq);
            if hash_atual != backup.hash_integridade {
                detalhe = "Hash BLAKE3 do arquivo não confere com o registrado".into();
            } else {
                hash_confere = true;
                match cofre_backup::decifrar(vault, &bytes_arq) {
                    Err(e) => {
                        detalhe = format!("Falha ao decifrar o backup com a DEK atual: {e}");
                    }
                    Ok(bytes_db) => {
                        decifragem_ok = true;
                        let dir_base = caminho.parent().unwrap_or_else(|| Path::new("."));
                        match validar_bytes_sqlite_em_tmp(dir_base, &bytes_db) {
                            Ok(()) => {
                                sqlite_valido = true;
                                detalhe = "Arquivo íntegro, autenticado e SQLite válido".into();
                            }
                            Err(e) => {
                                detalhe = format!("Banco SQLite decifrado inválido: {e}");
                            }
                        }
                    }
                }
            }
        }
    }

    let valido = arquivo_existe && hash_confere && decifragem_ok && sqlite_valido;
    db.marcar_backup_valido(id, usuario_id, valido)?;
    backup.valido = valido;

    let resultado_auditoria = if valido {
        ResultadoEvento::Sucesso
    } else {
        ResultadoEvento::Falha
    };
    let desc = format!(
        "Verificação do backup #{id} ('{}'): {detalhe}",
        backup.nome_arquivo
    );
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::Backup,
        resultado_auditoria,
        None,
        Some(&desc),
    );

    Ok(ResultadoVerificacao {
        backup,
        arquivo_existe,
        hash_confere,
        decifragem_ok,
        sqlite_valido,
        valido,
        detalhe,
    })
}

/// Lista todos os backups registrados do usuário (`criado_em DESC`).
pub fn listar(db: &Database, usuario_id: i64) -> Result<Vec<Backup>, BackupServiceError> {
    Ok(db.listar_backups(usuario_id)?)
}

/// Exclui o registro de um backup e, se `manter_arquivo` for `false`, apaga também o
/// arquivo `.cbk` do disco (caso exista). Registra o evento na auditoria.
pub fn excluir(
    db: &Database,
    usuario_id: i64,
    id: i64,
    manter_arquivo: bool,
) -> Result<Backup, BackupServiceError> {
    let backup = db.buscar_backup(id, usuario_id)?;

    if !manter_arquivo {
        let caminho = Path::new(&backup.caminho_arquivo);
        if caminho.exists() {
            fs::remove_file(caminho)?;
        }
    }

    db.excluir_backup(id, usuario_id)?;

    let desc = if manter_arquivo {
        format!(
            "Registro do backup #{id} ('{}') excluído (arquivo mantido no disco)",
            backup.nome_arquivo
        )
    } else {
        format!(
            "Backup #{id} ('{}') excluído do banco e do disco",
            backup.nome_arquivo
        )
    };
    auditoria_service::registrar(
        db,
        usuario_id,
        TipoEvento::Backup,
        ResultadoEvento::Sucesso,
        None,
        Some(&desc),
    );

    Ok(backup)
}

/// Origem do backup para restauração: por ID registrado no cofre atual ou por caminho de arquivo `.cbk`.
#[derive(Debug, Clone, Copy)]
pub enum OrigemRestauracao<'a> {
    Id(i64),
    Arquivo(&'a Path),
}

/// Resultado de uma operação de restauração concluída.
#[derive(Debug, Clone)]
pub struct ResultadoRestauracao {
    pub caminho_backup: PathBuf,
    pub hash_integridade: String,
    pub copia_anterior: Option<PathBuf>,
    pub usuario_id: i64,
}

/// O que precisa sobreviver à troca do banco numa restauração.
struct EstadoCofreAtual {
    usuario_id: i64,
    usuario_criado_em: chrono::NaiveDateTime,
    backups: Vec<Backup>,
    eventos: Vec<EventoAuditoria>,
}

/// Lê do banco atual os registros de backup e os eventos de auditoria.
/// Retorna `None` se o banco não tiver usuário ativo.
fn coletar_estado_atual(db: &Database) -> Result<Option<EstadoCofreAtual>, BackupServiceError> {
    let usuario = match db.buscar_usuario_ativo() {
        Ok(u) => u,
        Err(DbError::NotFound) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(EstadoCofreAtual {
        usuario_id: usuario.id,
        usuario_criado_em: usuario.criado_em,
        backups: db.listar_backups(usuario.id)?,
        eventos: db.listar_eventos_auditoria_apos(0)?,
    }))
}

/// Restaura o cofre a partir de um backup registrado (`OrigemRestauracao::Id`) ou de um
/// arquivo `.cbk` (`OrigemRestauracao::Arquivo`, inclusive quando `cofre.db` não existe).
///
/// **Importante:** Todas as conexões com `db_path` devem estar fechadas antes de chamar
/// esta função para permitir a substituição segura do arquivo (especialmente no Windows).
pub fn restaurar<F>(
    db_path: &Path,
    origem: OrigemRestauracao<'_>,
    vault_atual: Option<&UnlockedVault>,
    pedir_senha_backup: F,
) -> Result<ResultadoRestauracao, BackupServiceError>
where
    F: FnOnce() -> Result<Zeroizing<Vec<u8>>, String>,
{
    // 1. Se existir cofre.db atual, coletar o que deve sobreviver à restauração
    //    (registros de backup e eventos de auditoria), fechando a conexão ao final.
    let (caminho_backup, cofre_atual): (PathBuf, Option<EstadoCofreAtual>) = match origem {
        OrigemRestauracao::Id(id) => {
            if !db_path.exists() {
                return Err(BackupServiceError::CofreNaoInicializado);
            }
            let db_atual = Database::open(db_path)?;
            let usuario_atual = db_atual.buscar_usuario_ativo().map_err(|e| match e {
                DbError::NotFound => BackupServiceError::CofreNaoInicializado,
                outro => BackupServiceError::Db(outro),
            })?;
            let registro = db_atual.buscar_backup(id, usuario_atual.id)?;
            let estado = coletar_estado_atual(&db_atual)?;
            let _ = db_atual
                .conn
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            (PathBuf::from(&registro.caminho_arquivo), estado)
        }
        OrigemRestauracao::Arquivo(caminho) => {
            let mut estado = None;
            if db_path.exists() {
                if let Ok(db_atual) = Database::open(db_path) {
                    estado = coletar_estado_atual(&db_atual).ok().flatten();
                    let _ = db_atual
                        .conn
                        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
                }
            }
            (caminho.to_path_buf(), estado)
        }
    };

    // 2. Ler arquivo de backup e validar cabeçalho
    let bytes_arquivo = fs::read(&caminho_backup)?;
    let hash_arq = cofre_backup::hash_integridade(&bytes_arquivo);
    let cabecalho = cofre_backup::ler_cabecalho(&bytes_arquivo)?;

    // 3. Tentar decifrar com o vault da sessão atual (se houver); se falhar ou não houver,
    //    solicitar a senha mestre do backup e desbloquear a DEK pelo material do cabeçalho.
    let bytes_db: Zeroizing<Vec<u8>> =
        match vault_atual.and_then(|v| cofre_backup::decifrar(v, &bytes_arquivo).ok()) {
            Some(plain) => plain,
            None => {
                let senha = pedir_senha_backup().map_err(BackupServiceError::Prompt)?;
                let vault_backup = cabecalho.material.desbloquear(senha.as_slice())?;
                cofre_backup::decifrar(&vault_backup, &bytes_arquivo)?
            }
        };

    if bytes_db.len() < SQLITE_HEADER.len() || &bytes_db[..SQLITE_HEADER.len()] != SQLITE_HEADER {
        return Err(BackupServiceError::BackupInvalido(
            "Conteúdo decifrado não possui cabeçalho SQLite 3 válido".into(),
        ));
    }

    // 4. Gravar o banco decifrado em arquivo temporário ao lado do cofre.db
    let dir_db = db_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir_db)?;

    let nome_tmp = format!(".cofre-restore-{}.tmp", sufixo_aleatorio_hex());
    let mut guard_tmp = GuardArquivoTemp::novo(dir_db.join(nome_tmp));
    gravar_arquivo_0600(guard_tmp.caminho(), &bytes_db)?;
    drop(bytes_db);

    // 5. Validar o banco restaurado, preservar linhas de backups mais novos, marcar
    //    ultima_restauracao_em, registrar auditoria RESTAURACAO e consolidar o WAL no arquivo principal.
    let caminho_abs_backup = caminho_absoluto_string(&caminho_backup);
    let usuario_restaurado_id = {
        let db_tmp = Database::open(guard_tmp.caminho())?;

        let integridade: String = db_tmp
            .conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if !integridade.eq_ignore_ascii_case("ok") {
            return Err(BackupServiceError::BackupInvalido(format!(
                "Falha na verificação de integridade do SQLite: {integridade}"
            )));
        }

        let usuario = db_tmp.buscar_usuario_ativo().map_err(|_| {
            BackupServiceError::BackupInvalido("O backup não contém um usuário ativo válido".into())
        })?;

        // Mesmo cofre (mesmo usuário criado no mesmo instante): o banco restaurado é
        // um retrato antigo do atual. Os backups são arquivos no disco e a trilha de
        // auditoria não pode sumir com um restore, então ambos vêm do banco atual.
        if let Some(atual) = &cofre_atual {
            if atual.usuario_id == usuario.id && atual.usuario_criado_em == usuario.criado_em {
                let max_id = db_tmp.max_id_evento_auditoria()?;
                let novos: Vec<EventoAuditoria> = atual
                    .eventos
                    .iter()
                    .filter(|e| e.id > max_id)
                    .cloned()
                    .collect();
                db_tmp.importar_eventos_auditoria(&novos)?;
                db_tmp.substituir_backups(usuario.id, &atual.backups)?;
            }
        }

        let marcados = db_tmp.marcar_backup_restaurado_por_caminho_ou_hash(
            usuario.id,
            &caminho_abs_backup,
            &hash_arq,
        )?;
        if marcados == 0 {
            // Restauração por arquivo sem registro (ex.: recuperação de desastre):
            // passa a constar na lista para poder ser verificado e restaurado de novo.
            let nome_arquivo = caminho_backup
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("backup.cbk");
            db_tmp.registrar_backup(&NovoBackup {
                usuario_id: usuario.id,
                nome_arquivo,
                caminho_arquivo: &caminho_abs_backup,
                hash_integridade: &hash_arq,
                tamanho_bytes: i64::try_from(bytes_arquivo.len()).unwrap_or(i64::MAX),
                versao_formato: &cabecalho.versao_formato,
            })?;
            db_tmp.marcar_backup_restaurado_por_caminho_ou_hash(
                usuario.id,
                &caminho_abs_backup,
                &hash_arq,
            )?;
        }

        let nome_exibicao = caminho_backup
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&caminho_abs_backup);
        let desc = format!("Cofre restaurado a partir do backup '{nome_exibicao}'");
        auditoria_service::registrar(
            &db_tmp,
            usuario.id,
            TipoEvento::Restauracao,
            ResultadoEvento::Sucesso,
            None,
            Some(&desc),
        );

        // Consolida todas as alterações do WAL dentro do arquivo principal antes do rename
        db_tmp.conn.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
             PRAGMA journal_mode = DELETE;",
        )?;

        usuario.id
    };

    // Remove eventuais auxiliares -wal/-shm do temporário após fechar db_tmp
    for sufixo in ["-wal", "-shm"] {
        let _ = fs::remove_file(caminho_com_sufixo(guard_tmp.caminho(), sufixo));
    }

    // 6. Renomear cofre.db atual para cofre.db.antes-restauracao-AAAAMMDD-HHMMSS e substituir
    let copia_anterior = if db_path.exists() {
        let destino_copia = escolher_caminho_antes_restauracao(db_path);
        fs::rename(db_path, &destino_copia)?;
        Some(destino_copia)
    } else {
        None
    };

    // Remover -wal e -shm antigos do cofre.db
    for sufixo in ["-wal", "-shm"] {
        let _ = fs::remove_file(caminho_com_sufixo(db_path, sufixo));
    }

    if let Err(e) = fs::rename(guard_tmp.caminho(), db_path) {
        // Se falhar ao mover o novo banco, tenta restaurar o banco anterior
        if let Some(ref copia) = copia_anterior {
            let _ = fs::rename(copia, db_path);
        }
        return Err(BackupServiceError::Io(e));
    }
    guard_tmp.desarmar();

    Ok(ResultadoRestauracao {
        caminho_backup,
        hash_integridade: hash_arq,
        copia_anterior,
        usuario_id: usuario_restaurado_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditoria_service;
    use crate::testes::{params_teste, DbTemp};
    use crate::vault_service::{
        adicionar_credencial, alterar_senha_mestre, init_vault_com_params, revelar_senha,
        unlock_vault, DadosNovaCredencial,
    };
    use cofre_db::models::{FiltroAuditoria, NovoServico};

    /// Diretório temporário para arquivos de backup nos testes, removido no Drop.
    struct DirTemp(PathBuf);

    impl DirTemp {
        fn novo(nome: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "cofre-bkp-dir-{nome}-{}-{}",
                std::process::id(),
                sufixo_aleatorio_hex()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for DirTemp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn remover_copias_antes_restauracao(db_path: &Path) {
        if let Some(parent) = db_path.parent() {
            if let Some(prefixo) = db_path.file_name().and_then(|n| n.to_str()) {
                let alvo = format!("{prefixo}.antes-restauracao-");
                if let Ok(entries) = fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        if entry
                            .file_name()
                            .to_str()
                            .is_some_and(|n| n.starts_with(&alvo))
                        {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_criar_listar_verificar_e_adulterar() {
        let tmp_db = DbTemp::new("bkp-criar-verificar");
        let tmp_dir = DirTemp::novo("criar-verificar");

        let db = Database::open(&tmp_db.0).unwrap();
        init_vault_com_params(&db, "Alice", b"senha-mestre-forte", &params_teste()).unwrap();
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

        adicionar_credencial(
            &db,
            &vault,
            &DadosNovaCredencial {
                usuario_id,
                servico_id,
                nome_exibicao: "GitHub Pessoal",
                identificador: "alice",
                senha: b"segredo-123",
                observacao: None,
            },
        )
        .unwrap();

        // Criar backup
        let criado = criar(&db, &vault, usuario_id, &tmp_dir.0).unwrap();
        assert!(criado.valido);
        assert!(criado.tamanho_bytes > 0);
        assert_eq!(criado.versao_formato, "1");
        assert!(Path::new(&criado.caminho_arquivo).exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let modo = fs::metadata(&criado.caminho_arquivo)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(modo, 0o600);
        }

        // Listar
        let lista = listar(&db, usuario_id).unwrap();
        assert_eq!(lista.len(), 1);
        assert_eq!(lista[0].id, criado.id);

        // Verificar OK
        let res_ok = verificar(&db, &vault, usuario_id, criado.id).unwrap();
        assert!(res_ok.valido);
        assert!(res_ok.arquivo_existe);
        assert!(res_ok.hash_confere);
        assert!(res_ok.decifragem_ok);
        assert!(res_ok.sqlite_valido);
        assert!(db.buscar_backup(criado.id, usuario_id).unwrap().valido);

        // Adulterar 1 byte do arquivo -> verificar marca valido = false (0)
        let mut bytes = fs::read(&criado.caminho_arquivo).unwrap();
        let ultimo = bytes.len() - 1;
        bytes[ultimo] ^= 0x01;
        fs::write(&criado.caminho_arquivo, &bytes).unwrap();

        let res_falha = verificar(&db, &vault, usuario_id, criado.id).unwrap();
        assert!(!res_falha.valido);
        assert!(res_falha.arquivo_existe);
        assert!(!res_falha.hash_confere);
        assert!(!db.buscar_backup(criado.id, usuario_id).unwrap().valido);
    }

    #[test]
    fn test_restaurar_por_id_volta_dados_antigos_e_preserva_backups() {
        let tmp_db = DbTemp::new("bkp-restaurar-id");
        let tmp_dir = DirTemp::novo("restaurar-id");

        let (bkp1_id, bkp2_id, cred1_id, cred2_id) = {
            let db = Database::open(&tmp_db.0).unwrap();
            init_vault_com_params(&db, "Alice", b"senha-mestre-forte", &params_teste()).unwrap();
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

            let c1 = adicionar_credencial(
                &db,
                &vault,
                &DadosNovaCredencial {
                    usuario_id,
                    servico_id,
                    nome_exibicao: "Conta 1",
                    identificador: "alice1",
                    senha: b"senha-1",
                    observacao: None,
                },
            )
            .unwrap();

            // Cria o backup 1 (contém apenas Conta 1)
            let b1 = criar(&db, &vault, usuario_id, &tmp_dir.0).unwrap();

            // Adiciona uma segunda credencial DEPOIS do backup 1
            let c2 = adicionar_credencial(
                &db,
                &vault,
                &DadosNovaCredencial {
                    usuario_id,
                    servico_id,
                    nome_exibicao: "Conta 2",
                    identificador: "alice2",
                    senha: b"senha-2",
                    observacao: None,
                },
            )
            .unwrap();

            // Cria um segundo backup mais novo (para testar que o registro dele é preservado)
            let b2 = criar(&db, &vault, usuario_id, &tmp_dir.0).unwrap();

            (b1.id, b2.id, c1, c2)
        };

        // Restaurar o backup 1 por ID (com todas as conexões fechadas)
        let res = restaurar(&tmp_db.0, OrigemRestauracao::Id(bkp1_id), None, || {
            Ok(Zeroizing::new(b"senha-mestre-forte".to_vec()))
        })
        .unwrap();

        assert!(res.copia_anterior.as_ref().unwrap().exists());

        // Reabrir o cofre restaurado e verificar os dados
        let db_rest = Database::open(&tmp_db.0).unwrap();
        let (vault_rest, usuario_id) = unlock_vault(&db_rest, b"senha-mestre-forte").unwrap();

        // Credencial 1 existe e decifra; Credencial 2 (criada após o backup 1) sumiu
        assert_eq!(
            revelar_senha(&db_rest, &vault_rest, cred1_id, usuario_id).unwrap(),
            b"senha-1"
        );
        assert!(matches!(
            db_rest.buscar_credencial(cred2_id),
            Err(DbError::NotFound)
        ));

        // Os registros de backup (b1 e b2) foram preservados no banco restaurado e b1 tem ultima_restauracao_em
        let backups = listar(&db_rest, usuario_id).unwrap();
        assert_eq!(backups.len(), 2);
        let b1_rest = backups
            .iter()
            .find(|b| b.hash_integridade == res.hash_integridade)
            .unwrap();
        assert!(b1_rest.ultima_restauracao_em.is_some());
        let _ = bkp2_id;

        // Evento RESTAURACAO registrado na auditoria do banco restaurado
        let eventos = auditoria_service::listar(
            &db_rest,
            usuario_id,
            &FiltroAuditoria {
                tipo_evento: Some("RESTAURACAO"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(eventos.len(), 1);
        assert_eq!(eventos[0].resultado, "SUCESSO");

        remover_copias_antes_restauracao(&tmp_db.0);
    }

    #[test]
    fn test_restaurar_por_arquivo_sem_cofre_existente_e_apos_troca_de_senha() {
        let tmp_db_origem = DbTemp::new("bkp-desastre-origem");
        let tmp_db_destino = DbTemp::new("bkp-desastre-destino");
        let tmp_dir = DirTemp::novo("desastre");

        let (caminho_cbk, cred_id) = {
            let db = Database::open(&tmp_db_origem.0).unwrap();
            init_vault_com_params(&db, "Alice", b"senha-do-momento-do-backup", &params_teste())
                .unwrap();
            let (vault, usuario_id) = unlock_vault(&db, b"senha-do-momento-do-backup").unwrap();

            let servico_id = db
                .criar_servico(&NovoServico {
                    categoria_id: None,
                    nome: "GitHub".into(),
                    dominio_principal: "github.com".into(),
                    url_principal: None,
                    descricao: None,
                })
                .unwrap();

            let cid = adicionar_credencial(
                &db,
                &vault,
                &DadosNovaCredencial {
                    usuario_id,
                    servico_id,
                    nome_exibicao: "Conta Desastre",
                    identificador: "alice",
                    senha: b"segredo-recuperado",
                    observacao: None,
                },
            )
            .unwrap();

            let bkp = criar(&db, &vault, usuario_id, &tmp_dir.0).unwrap();

            // Troca a senha mestre do cofre original DEPOIS do backup:
            // o backup deve continuar restaurável com a senha vigente no momento do backup.
            alterar_senha_mestre(&db, &vault, usuario_id, b"senha-nova-posterior").unwrap();

            (PathBuf::from(bkp.caminho_arquivo), cid)
        };

        // Garante que o banco destino NÃO existe (recuperação de desastre pura)
        assert!(!tmp_db_destino.0.exists());

        // Senha errada falha e não cria cofre.db
        let falha = restaurar(
            &tmp_db_destino.0,
            OrigemRestauracao::Arquivo(&caminho_cbk),
            None,
            || Ok(Zeroizing::new(b"senha-incorreta".to_vec())),
        );
        assert!(falha.is_err());
        assert!(!tmp_db_destino.0.exists());

        // Senha correta do momento do backup restaura o cofre mesmo sem cofre.db prévio
        let res = restaurar(
            &tmp_db_destino.0,
            OrigemRestauracao::Arquivo(&caminho_cbk),
            None,
            || Ok(Zeroizing::new(b"senha-do-momento-do-backup".to_vec())),
        )
        .unwrap();
        assert!(res.copia_anterior.is_none());
        assert!(tmp_db_destino.0.exists());

        let db_rec = Database::open(&tmp_db_destino.0).unwrap();
        let (vault_rec, usuario_id) = unlock_vault(&db_rec, b"senha-do-momento-do-backup").unwrap();
        assert_eq!(
            revelar_senha(&db_rec, &vault_rec, cred_id, usuario_id).unwrap(),
            b"segredo-recuperado"
        );
    }

    #[test]
    fn test_excluir_remove_arquivo_e_linha() {
        let tmp_db = DbTemp::new("bkp-excluir");
        let tmp_dir = DirTemp::novo("excluir");

        let db = Database::open(&tmp_db.0).unwrap();
        init_vault_com_params(&db, "Alice", b"senha-mestre-forte", &params_teste()).unwrap();
        let (vault, usuario_id) = unlock_vault(&db, b"senha-mestre-forte").unwrap();

        let bkp = criar(&db, &vault, usuario_id, &tmp_dir.0).unwrap();
        let caminho = PathBuf::from(&bkp.caminho_arquivo);
        assert!(caminho.exists());

        excluir(&db, usuario_id, bkp.id, false).unwrap();
        assert!(!caminho.exists());
        assert!(listar(&db, usuario_id).unwrap().is_empty());
    }
}
