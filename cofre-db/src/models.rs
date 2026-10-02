//! Modelos de dados que representam as tabelas do banco.
//!
//! Structs Rust correspondentes às linhas das tabelas SQLite.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

/// Modelo da tabela `usuario`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usuario {
    pub id: i64,
    pub nome: String,
    pub verificador_mestre: Vec<u8>,
    pub salt_kdf: Vec<u8>,
    pub parametros_kdf: String,
    pub criado_em: NaiveDateTime,
    pub atualizado_em: NaiveDateTime,
    pub ultimo_acesso_em: Option<NaiveDateTime>,
    pub ativo: bool,
    pub dek_criptografada: Vec<u8>,
    pub dek_nonce: Vec<u8>,
    pub verificador_salt: Vec<u8>,
}

/// Modelo da tabela `categoria`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Categoria {
    pub id: i64,
    pub nome: String,
    pub descricao: Option<String>,
    pub criado_em: NaiveDateTime,
    pub atualizado_em: NaiveDateTime,
    pub ativa: bool,
}

/// Dados para criar uma nova categoria.
pub struct NovaCategoria {
    pub nome: String,
    pub descricao: Option<String>,
}

/// Modelo da tabela `servico`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Servico {
    pub id: i64,
    pub categoria_id: Option<i64>,
    pub nome: String,
    pub dominio_principal: String,
    pub url_principal: Option<String>,
    pub descricao: Option<String>,
    pub criado_em: NaiveDateTime,
    pub atualizado_em: NaiveDateTime,
    pub ativo: bool,
}

/// Dados para criar um novo serviço.
pub struct NovoServico {
    pub categoria_id: Option<i64>,
    pub nome: String,
    pub dominio_principal: String,
    pub url_principal: Option<String>,
    pub descricao: Option<String>,
}

/// Modelo da tabela `credencial`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credencial {
    pub id: i64,
    pub usuario_id: i64,
    pub servico_id: i64,
    pub nome_exibicao: String,
    pub identificador: String,
    pub segredo_criptografado: Vec<u8>,
    pub nonce: Vec<u8>,
    pub observacao_criptografada: Option<Vec<u8>>,
    pub observacao_nonce: Option<Vec<u8>>,
    pub favorita: bool,
    pub criada_em: NaiveDateTime,
    pub alterada_em: NaiveDateTime,
    pub ultimo_uso_em: Option<NaiveDateTime>,
    pub ativa: bool,
}

/// Dados para criar uma nova credencial (antes da cifragem).
pub struct NovaCredencial {
    pub usuario_id: i64,
    pub servico_id: i64,
    pub nome_exibicao: String,
    pub identificador: String,
    pub segredo_criptografado: Vec<u8>,
    pub nonce: Vec<u8>,
    pub observacao_criptografada: Option<Vec<u8>>,
    pub observacao_nonce: Option<Vec<u8>>,
    pub favorita: bool,
}

/// Modelo da tabela `url_servico`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlServico {
    pub id: i64,
    pub servico_id: i64,
    pub url: String,
    pub tipo: String,
    pub descricao: Option<String>,
    pub padrao: bool,
    pub criado_em: NaiveDateTime,
    pub ativa: bool,
}

/// Modelo da tabela `evento_auditoria`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventoAuditoria {
    pub id: i64,
    pub usuario_id: i64,
    pub credencial_id: Option<i64>,
    pub dispositivo_id: Option<i64>,
    pub tipo_evento: String,
    pub resultado: String,
    pub descricao: Option<String>,
    pub ocorrido_em: NaiveDateTime,
}

/// Modelo da tabela `dispositivo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispositivo {
    pub id: i64,
    pub usuario_id: i64,
    pub nome: String,
    pub sistema_operacional: Option<String>,
    pub fingerprint_hash: Option<String>,
    pub confiavel: bool,
    pub primeiro_acesso_em: NaiveDateTime,
    pub ultimo_acesso_em: Option<NaiveDateTime>,
    pub ativo: bool,
}

/// Modelo da tabela `preferencia`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preferencia {
    pub id: i64,
    pub usuario_id: i64,
    pub chave: String,
    pub valor: String,
    pub tipo_valor: String,
    pub descricao: Option<String>,
    pub atualizado_em: NaiveDateTime,
}
