//! # cofre-backup
//!
//! Formato binário e criptografia autenticada dos backups do cofre (`.cbk`, RF14 / RNF10).
//!
//! ## Layout do arquivo
//!
//! ```text
//! +------------------+------------------+-----------------------+--------------------+------------------+--------------------+
//! | MAGIC (8 bytes)  | Versão (1 byte)  | Tam. cabeçalho (u32)  | Cabeçalho (JSON)   | Nonce (24 bytes) | Ciphertext + Tag   |
//! | b"COFREBKP"      | 1                | Little-Endian         | UTF-8              | XChaCha20        | XChaCha20-Poly1305 |
//! +------------------+------------------+-----------------------+--------------------+------------------+--------------------+
//! ```
//!
//! - O cabeçalho armazena o material criptográfico de desbloqueio da tabela `usuario`
//!   (`salt_kdf`, `parametros_kdf`, `verificador_mestre`, `verificador_salt`,
//!   `dek_criptografada`, `dek_nonce`), permitindo recuperar a DEK apenas com a
//!   senha mestre vigente no momento do backup (mesmo que o `cofre.db` original
//!   tenha sido perdido).
//! - A AAD do AEAD é `"backup|v1|" + blake3_hex(bytes_do_cabecalho)`, garantindo
//!   que qualquer adulteração no cabeçalho invalide a autenticação Poly1305.

use chrono::{NaiveDateTime, Utc};
use cofre_crypto::keys::{self, UnlockedVault};
use cofre_db::models::Usuario;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

/// Assinatura inicial de todo arquivo de backup do cofre (8 bytes).
pub const MAGIC: &[u8; 8] = b"COFREBKP";

/// Versão binária do envelope do arquivo de backup.
pub const VERSAO_BINARIA: u8 = 1;

/// Versão lógica do formato de backup persistida no cabeçalho e no banco.
pub const VERSAO_FORMATO: &str = "1";

/// Tamanho do nonce do XChaCha20-Poly1305 em bytes.
pub const NONCE_LEN: usize = 24;

/// Tamanho da tag de autenticação Poly1305 em bytes.
const TAG_LEN: usize = 16;

/// Tamanho do prefixo fixo antes do cabeçalho: 8 (MAGIC) + 1 (versão) + 4 (u32 LE).
const PREFIXO_FIXO_LEN: usize = 8 + 1 + 4;

/// Limite máximo aceito para o cabeçalho JSON (64 KiB) contra alocações excessivas.
const MAX_CABECALHO_LEN: usize = 64 * 1024;

/// Erros de leitura, validação, montagem ou criptografia de arquivos de backup.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("Erro de criptografia: {0}")]
    Crypto(#[from] cofre_crypto::CryptoError),

    #[error("Arquivo de backup inválido: assinatura (magic) não reconhecida")]
    MagicInvalido,

    #[error("Versão de arquivo de backup não suportada: {0}")]
    VersaoNaoSuportada(u8),

    #[error("Arquivo de backup truncado ou incompleto: {0}")]
    ArquivoTruncado(String),

    #[error("Cabeçalho do backup inválido: {0}")]
    CabecalhoInvalido(String),

    #[error(
        "Tamanho do banco decifrado ({obtido} bytes) difere do registrado no cabeçalho ({esperado} bytes)"
    )]
    TamanhoInconsistente { esperado: u64, obtido: usize },
}

/// Material criptográfico de desbloqueio do usuário armazenado em claro no cabeçalho.
///
/// Contém exatamente os mesmos campos públicos da tabela `usuario`, permitindo
/// derivar a KEK e recuperar a DEK apenas com a senha mestre vigente no momento do backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterialDesbloqueio {
    #[serde(with = "hex_bytes")]
    pub salt_kdf: Vec<u8>,
    pub parametros_kdf: String,
    #[serde(with = "hex_bytes")]
    pub verificador_mestre: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub verificador_salt: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub dek_criptografada: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub dek_nonce: Vec<u8>,
}

impl MaterialDesbloqueio {
    /// Extrai o material de desbloqueio a partir de um registro `Usuario`.
    pub fn de_usuario(usuario: &Usuario) -> Self {
        Self {
            salt_kdf: usuario.salt_kdf.clone(),
            parametros_kdf: usuario.parametros_kdf.clone(),
            verificador_mestre: usuario.verificador_mestre.clone(),
            verificador_salt: usuario.verificador_salt.clone(),
            dek_criptografada: usuario.dek_criptografada.clone(),
            dek_nonce: usuario.dek_nonce.clone(),
        }
    }

    /// Desbloqueia a DEK encapsulada neste material usando a senha mestre do backup.
    pub fn desbloquear(&self, senha: &[u8]) -> Result<UnlockedVault, BackupError> {
        let vault = keys::unlock_vault(
            senha,
            &self.salt_kdf,
            &self.verificador_salt,
            &self.verificador_mestre,
            &self.dek_criptografada,
            &self.dek_nonce,
            &self.parametros_kdf,
        )?;
        Ok(vault)
    }
}

/// Cabeçalho JSON do arquivo de backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cabecalho {
    pub versao_formato: String,
    pub criado_em: NaiveDateTime,
    pub material: MaterialDesbloqueio,
    pub tamanho_db_bytes: u64,
}

/// Calcula a string de AAD que vincula o ciphertext ao conteúdo exato do cabeçalho.
///
/// Formato: `"backup|v1|" + blake3_hex(bytes_do_cabecalho)`
pub fn calcular_aad(bytes_cabecalho: &[u8]) -> String {
    let hash_cabecalho = blake3::hash(bytes_cabecalho).to_hex();
    format!("backup|v1|{hash_cabecalho}")
}

/// Calcula o hash BLAKE3 em hexadecimal do arquivo de backup inteiro.
pub fn hash_integridade(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Monta o arquivo de backup cifrado a partir do cofre desbloqueado, do material de
/// desbloqueio do usuário e dos bytes do snapshot SQLite.
pub fn montar_arquivo(
    vault: &UnlockedVault,
    material: MaterialDesbloqueio,
    bytes_db: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let cabecalho = Cabecalho {
        versao_formato: VERSAO_FORMATO.to_string(),
        criado_em: Utc::now().naive_utc(),
        material,
        tamanho_db_bytes: bytes_db.len() as u64,
    };

    let bytes_cabecalho = serde_json::to_vec(&cabecalho)
        .map_err(|e| BackupError::CabecalhoInvalido(e.to_string()))?;

    if bytes_cabecalho.len() > MAX_CABECALHO_LEN {
        return Err(BackupError::CabecalhoInvalido(
            "cabeçalho excede o tamanho máximo permitido".into(),
        ));
    }

    let aad = calcular_aad(&bytes_cabecalho);
    let (nonce, ciphertext) = vault.encrypt(bytes_db, &aad)?;

    let tam_cab_u32 = u32::try_from(bytes_cabecalho.len())
        .map_err(|_| BackupError::CabecalhoInvalido("tamanho do cabeçalho excede u32".into()))?;

    let total = PREFIXO_FIXO_LEN + bytes_cabecalho.len() + nonce.len() + ciphertext.len();
    let mut saida = Vec::with_capacity(total);
    saida.extend_from_slice(MAGIC);
    saida.push(VERSAO_BINARIA);
    saida.extend_from_slice(&tam_cab_u32.to_le_bytes());
    saida.extend_from_slice(&bytes_cabecalho);
    saida.extend_from_slice(&nonce);
    saida.extend_from_slice(&ciphertext);

    Ok(saida)
}

/// Estrutura interna com as fatias validadas de um arquivo de backup.
struct PartesArquivo<'a> {
    cabecalho: Cabecalho,
    bytes_cabecalho: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

fn extrair_partes(bytes: &[u8]) -> Result<PartesArquivo<'_>, BackupError> {
    if bytes.len() < PREFIXO_FIXO_LEN {
        return Err(BackupError::ArquivoTruncado(format!(
            "esperado ao menos {PREFIXO_FIXO_LEN} bytes no prefixo, encontrado {}",
            bytes.len()
        )));
    }

    if &bytes[0..8] != MAGIC {
        return Err(BackupError::MagicInvalido);
    }

    let versao = bytes[8];
    if versao != VERSAO_BINARIA {
        return Err(BackupError::VersaoNaoSuportada(versao));
    }

    let tam_cab_bytes: [u8; 4] = bytes[9..13]
        .try_into()
        .map_err(|_| BackupError::ArquivoTruncado("tamanho do cabeçalho incompleto".into()))?;
    let tam_cab = u32::from_le_bytes(tam_cab_bytes) as usize;

    if tam_cab == 0 {
        return Err(BackupError::CabecalhoInvalido("cabeçalho vazio".into()));
    }
    if tam_cab > MAX_CABECALHO_LEN {
        return Err(BackupError::CabecalhoInvalido(format!(
            "tamanho do cabeçalho ({tam_cab} bytes) excede o limite de {MAX_CABECALHO_LEN} bytes"
        )));
    }

    let fim_cab = PREFIXO_FIXO_LEN
        .checked_add(tam_cab)
        .ok_or_else(|| BackupError::CabecalhoInvalido("overflow no tamanho do cabeçalho".into()))?;
    let min_total = fim_cab
        .checked_add(NONCE_LEN + TAG_LEN)
        .ok_or_else(|| BackupError::CabecalhoInvalido("overflow no tamanho do arquivo".into()))?;

    if bytes.len() < fim_cab {
        return Err(BackupError::ArquivoTruncado(format!(
            "cabeçalho declara {tam_cab} bytes, mas o arquivo termina antes (total: {} bytes)",
            bytes.len()
        )));
    }

    let bytes_cabecalho = &bytes[PREFIXO_FIXO_LEN..fim_cab];
    let cabecalho: Cabecalho = serde_json::from_slice(bytes_cabecalho)
        .map_err(|e| BackupError::CabecalhoInvalido(e.to_string()))?;

    if cabecalho.versao_formato != VERSAO_FORMATO {
        return Err(BackupError::CabecalhoInvalido(format!(
            "versão de formato '{}' incompatível (esperado '{VERSAO_FORMATO}')",
            cabecalho.versao_formato
        )));
    }

    if bytes.len() < min_total {
        return Err(BackupError::ArquivoTruncado(
            "nonce ou payload cifrado ausente/incompleto após o cabeçalho".into(),
        ));
    }

    let nonce = &bytes[fim_cab..fim_cab + NONCE_LEN];
    let ciphertext = &bytes[fim_cab + NONCE_LEN..];

    Ok(PartesArquivo {
        cabecalho,
        bytes_cabecalho,
        nonce,
        ciphertext,
    })
}

/// Lê e valida o cabeçalho de um arquivo de backup sem decifrar o payload.
pub fn ler_cabecalho(bytes: &[u8]) -> Result<Cabecalho, BackupError> {
    Ok(extrair_partes(bytes)?.cabecalho)
}

/// Valida o cabeçalho e decifra o conteúdo do banco SQLite com a DEK fornecida.
///
/// O buffer retornado é encapsulado em `Zeroizing<Vec<u8>>` para ser zerado da RAM ao sair de escopo.
pub fn decifrar(vault: &UnlockedVault, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    let partes = extrair_partes(bytes)?;
    let aad = calcular_aad(partes.bytes_cabecalho);
    let plaintext = Zeroizing::new(vault.decrypt(partes.nonce, partes.ciphertext, &aad)?);

    if plaintext.len() as u64 != partes.cabecalho.tamanho_db_bytes {
        return Err(BackupError::TamanhoInconsistente {
            esperado: partes.cabecalho.tamanho_db_bytes,
            obtido: plaintext.len(),
        });
    }

    Ok(plaintext)
}

/// Serialização e desserialização hexadecimal de `Vec<u8>` para o cabeçalho JSON.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            use std::fmt::Write;
            let _ = write!(&mut s, "{b:02x}");
        }
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if !s.len().is_multiple_of(2) {
            return Err(serde::de::Error::custom(
                "string hexadecimal com comprimento ímpar",
            ));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| serde::de::Error::custom(format!("hex inválido: {e}")))?;
            out.push(byte);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cofre_crypto::kdf::KdfParams;
    use cofre_crypto::keys::{init_vault, unlock_vault, VaultInit};

    fn params_teste() -> KdfParams {
        KdfParams {
            m_cost_kib: 8_192,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn criar_vault_e_material(senha: &[u8]) -> (UnlockedVault, MaterialDesbloqueio, VaultInit) {
        let init = init_vault(senha, &params_teste()).unwrap();
        let vault = unlock_vault(
            senha,
            &init.kek_salt,
            &init.verifier_salt,
            &init.verifier,
            &init.encrypted_dek,
            &init.dek_nonce,
            &init.kdf_params_json,
        )
        .unwrap();
        let material = MaterialDesbloqueio {
            salt_kdf: init.kek_salt.clone(),
            parametros_kdf: init.kdf_params_json.clone(),
            verificador_mestre: init.verifier.clone(),
            verificador_salt: init.verifier_salt.clone(),
            dek_criptografada: init.encrypted_dek.clone(),
            dek_nonce: init.dek_nonce.clone(),
        };
        (vault, material, init)
    }

    #[test]
    fn test_ida_e_volta_e_desbloqueio_pelo_cabecalho() {
        let senha = b"senha-mestre-do-backup";
        let (vault, material, _) = criar_vault_e_material(senha);
        let dados_db = b"SQLite format 3\0conteudo-simulado-do-banco";

        let arquivo = montar_arquivo(&vault, material.clone(), dados_db).unwrap();
        let hash = hash_integridade(&arquivo);
        assert_eq!(hash.len(), 64);

        let cab = ler_cabecalho(&arquivo).unwrap();
        assert_eq!(cab.versao_formato, "1");
        assert_eq!(cab.tamanho_db_bytes, dados_db.len() as u64);
        assert_eq!(cab.material, material);

        // Decifrar com o vault atual
        let decifrado = decifrar(&vault, &arquivo).unwrap();
        assert_eq!(decifrado.as_slice(), dados_db);

        // Desbloquear um novo vault apenas com o material do cabeçalho + senha mestre
        let vault_recuperado = cab.material.desbloquear(senha).unwrap();
        let decifrado_rec = decifrar(&vault_recuperado, &arquivo).unwrap();
        assert_eq!(decifrado_rec.as_slice(), dados_db);
    }

    #[test]
    fn test_cabecalho_adulterado_falha_na_decifragem() {
        let (vault, material, _) = criar_vault_e_material(b"senha-123");
        let mut arquivo = montar_arquivo(&vault, material, b"dados-do-banco").unwrap();

        // O cabeçalho JSON começa no byte 13; procura o dígito da versão ou altera um caractere válido no JSON
        let tam_cab = u32::from_le_bytes(arquivo[9..13].try_into().unwrap()) as usize;
        let json_str = std::str::from_utf8(&arquivo[13..13 + tam_cab]).unwrap();
        let pos_rel = json_str
            .find("\"parametros_kdf\"")
            .expect("campo parametros_kdf presente");
        // Adultera um byte dentro do cabeçalho mantendo ou não JSON válido:
        // trocamos um caractere de whitespace/conteúdo substituindo um dígito dentro de criado_em
        let pos_criado = json_str.find("\"criado_em\":\"").unwrap() + "\"criado_em\":\"".len();
        let idx = 13 + pos_criado;
        arquivo[idx] = if arquivo[idx] == b'2' { b'1' } else { b'2' };
        let _ = pos_rel;

        // O cabeçalho ainda pode ser lido como JSON válido, mas o AAD mudou e a decifragem DEVE falhar
        assert!(ler_cabecalho(&arquivo).is_ok());
        assert!(decifrar(&vault, &arquivo).is_err());
    }

    #[test]
    fn test_ciphertext_adulterado_falha() {
        let (vault, material, _) = criar_vault_e_material(b"senha-123");
        let mut arquivo = montar_arquivo(&vault, material, b"dados-do-banco").unwrap();

        let ultimo = arquivo.len() - 1;
        arquivo[ultimo] ^= 0xFF;

        assert!(decifrar(&vault, &arquivo).is_err());
    }

    #[test]
    fn test_dek_errada_falha() {
        let (vault1, material1, _) = criar_vault_e_material(b"senha-1");
        let (vault2, _, _) = criar_vault_e_material(b"senha-2");

        let arquivo = montar_arquivo(&vault1, material1, b"dados-secretos").unwrap();
        assert!(decifrar(&vault2, &arquivo).is_err());
    }

    #[test]
    fn test_arquivo_truncado_magic_ou_versao_errada_nao_entra_em_panico() {
        // Vazio e menor que o prefixo
        assert!(matches!(
            ler_cabecalho(&[]),
            Err(BackupError::ArquivoTruncado(_))
        ));
        assert!(matches!(
            ler_cabecalho(b"COFRE"),
            Err(BackupError::ArquivoTruncado(_))
        ));

        // Magic errado
        assert!(matches!(
            ler_cabecalho(b"INVALIDO\x01\x02\x00\x00\x00{}"),
            Err(BackupError::MagicInvalido)
        ));

        // Versão binária não suportada
        assert!(matches!(
            ler_cabecalho(b"COFREBKP\x02\x02\x00\x00\x00{}"),
            Err(BackupError::VersaoNaoSuportada(2))
        ));

        // Tamanho do cabeçalho zero
        assert!(matches!(
            ler_cabecalho(b"COFREBKP\x01\x00\x00\x00\x00"),
            Err(BackupError::CabecalhoInvalido(_))
        ));

        // Tamanho do cabeçalho gigante (u32::MAX)
        assert!(matches!(
            ler_cabecalho(b"COFREBKP\x01\xFF\xFF\xFF\xFFlixo"),
            Err(BackupError::CabecalhoInvalido(_))
        ));

        // Tamanho do cabeçalho maior que os bytes disponíveis
        assert!(matches!(
            ler_cabecalho(b"COFREBKP\x01\x64\x00\x00\x00curto"),
            Err(BackupError::ArquivoTruncado(_))
        ));

        // Cabeçalho com JSON inválido
        let mut lixo_json = Vec::new();
        lixo_json.extend_from_slice(MAGIC);
        lixo_json.push(VERSAO_BINARIA);
        lixo_json.extend_from_slice(&4u32.to_le_bytes());
        lixo_json.extend_from_slice(b"lixo");
        assert!(matches!(
            ler_cabecalho(&lixo_json),
            Err(BackupError::CabecalhoInvalido(_))
        ));

        // Arquivo válido truncado no meio do ciphertext
        let (vault, material, _) = criar_vault_e_material(b"senha-123");
        let arquivo = montar_arquivo(&vault, material, b"dados-do-banco").unwrap();
        let tam_cab = u32::from_le_bytes(arquivo[9..13].try_into().unwrap()) as usize;
        let truncado_sem_payload = &arquivo[..13 + tam_cab + 5];
        assert!(matches!(
            ler_cabecalho(truncado_sem_payload),
            Err(BackupError::ArquivoTruncado(_))
        ));
    }
}
