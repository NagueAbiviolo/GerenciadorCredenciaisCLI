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

/// Dados para criar um novo usuário (cofre).
pub struct NovoUsuario<'a> {
    pub nome: &'a str,
    pub verificador_mestre: &'a [u8],
    pub salt_kdf: &'a [u8],
    pub parametros_kdf: &'a str,
    pub dek_criptografada: &'a [u8],
    pub dek_nonce: &'a [u8],
    pub verificador_salt: &'a [u8],
}

/// Dados criptográficos de autenticação do usuário (atualizados na troca de senha mestre).
pub struct DadosAutenticacao<'a> {
    pub verificador_mestre: &'a [u8],
    pub salt_kdf: &'a [u8],
    pub parametros_kdf: &'a str,
    pub dek_criptografada: &'a [u8],
    pub dek_nonce: &'a [u8],
    pub verificador_salt: &'a [u8],
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

/// Dados para criar (ou atualizar) uma URL de serviço.
pub struct NovaUrlServico {
    pub servico_id: i64,
    pub url: String,
    /// Um de: PRINCIPAL, LOGIN, RECUPERACAO, CADASTRO, LOGOUT.
    pub tipo: String,
    pub descricao: Option<String>,
    pub padrao: bool,
}

/// Modelo da tabela `metodo_autenticacao`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetodoAutenticacao {
    pub id: i64,
    pub credencial_id: i64,
    pub tipo: String,
    pub descricao: Option<String>,
    pub principal: bool,
    pub habilitado: bool,
    pub configurado_em: Option<NaiveDateTime>,
    pub atualizado_em: NaiveDateTime,
}

/// Dados para criar (ou atualizar) um método de autenticação.
pub struct NovoMetodoAutenticacao {
    pub credencial_id: i64,
    /// Um de: SENHA, TOTP, SMS, EMAIL, PASSKEY, BIOMETRIA, APLICATIVO.
    pub tipo: String,
    pub descricao: Option<String>,
    pub principal: bool,
    pub habilitado: bool,
}

/// Modelo da tabela `email_recuperacao` (o e-mail fica cifrado).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailRecuperacao {
    pub id: i64,
    pub credencial_id: i64,
    pub email_criptografado: Vec<u8>,
    pub nonce: Vec<u8>,
    pub principal: bool,
    pub verificado: bool,
    pub verificado_em: Option<NaiveDateTime>,
    pub criado_em: NaiveDateTime,
    pub ativo: bool,
}

/// Modelo da tabela `historico_credencial`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricoCredencial {
    pub id: i64,
    pub credencial_id: i64,
    pub tipo_alteracao: String,
    pub valor_anterior_criptografado: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub motivo: Option<String>,
    pub alterado_em: NaiveDateTime,
}

/// Dados para criar um novo registro em `historico_credencial`.
pub struct NovoHistoricoCredencial<'a> {
    pub credencial_id: i64,
    /// Um de: SENHA, IDENTIFICADOR, OBSERVACAO, ATIVACAO.
    pub tipo_alteracao: &'a str,
    pub valor_anterior_criptografado: Option<&'a [u8]>,
    pub nonce: Option<&'a [u8]>,
    pub motivo: Option<&'a str>,
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

/// Dados para registrar um novo evento na tabela `evento_auditoria`.
pub struct NovoEventoAuditoria<'a> {
    pub usuario_id: i64,
    pub credencial_id: Option<i64>,
    pub dispositivo_id: Option<i64>,
    pub tipo_evento: &'a str,
    pub resultado: &'a str,
    pub descricao: Option<&'a str>,
}

/// Filtros opcionais para listagem de eventos de auditoria.
#[derive(Debug, Clone, Default)]
pub struct FiltroAuditoria<'a> {
    pub tipo_evento: Option<&'a str>,
    pub credencial_id: Option<i64>,
    pub desde: Option<chrono::NaiveDate>,
    pub limite: Option<usize>,
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

/// Dados para registrar um novo dispositivo.
pub struct NovoDispositivo {
    pub usuario_id: i64,
    pub nome: String,
    pub sistema_operacional: Option<String>,
    pub fingerprint_hash: Option<String>,
    pub confiavel: bool,
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

/// Dados para inserir ou atualizar uma preferência do usuário.
pub struct NovaPreferencia<'a> {
    pub usuario_id: i64,
    pub chave: &'a str,
    pub valor: &'a str,
    pub tipo_valor: &'a str,
    pub descricao: Option<&'a str>,
}
