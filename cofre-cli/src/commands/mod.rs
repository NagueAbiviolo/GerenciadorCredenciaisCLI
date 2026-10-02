//! Definição dos comandos CLI com clap.

pub mod init;
pub mod unlock;
pub mod credencial;
pub mod categoria;
pub mod servico;

use clap::{Parser, Subcommand};
use anyhow::Result;
use std::path::PathBuf;
use directories::ProjectDirs;

/// Gerenciador Pessoal de Credenciais — CLI
#[derive(Parser)]
#[command(
    name = "cofre",
    version,
    about = "Gerenciador pessoal de credenciais via linha de comando",
    long_about = "Armazena e gerencia credenciais de forma segura usando criptografia \
                  autenticada (XChaCha20-Poly1305) e derivação de chaves com Argon2id."
)]
pub struct Cli {
    /// Caminho personalizado para o banco de dados.
    /// Se não informado, usa o diretório padrão do SO.
    #[arg(long, global = true)]
    pub db_path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Inicializar um novo cofre de credenciais.
    Init {
        /// Nome do proprietário do cofre.
        #[arg(short, long)]
        nome: String,
    },

    /// Gerenciar categorias.
    #[command(subcommand)]
    Categoria(CategoriaCommands),

    /// Gerenciar serviços.
    #[command(subcommand)]
    Servico(ServicoCommands),

    /// Gerenciar credenciais.
    #[command(subcommand)]
    Credencial(CredencialCommands),
}

#[derive(Subcommand)]
pub enum CategoriaCommands {
    /// Adicionar uma nova categoria.
    Add {
        /// Nome da categoria.
        #[arg(short, long)]
        nome: String,
        /// Descrição opcional.
        #[arg(short, long)]
        descricao: Option<String>,
    },
    /// Listar todas as categorias.
    List,
}

#[derive(Subcommand)]
pub enum ServicoCommands {
    /// Adicionar um novo serviço.
    Add {
        /// Nome do serviço (ex: Netflix, GitHub).
        #[arg(short, long)]
        nome: String,
        /// Domínio principal (ex: netflix.com).
        #[arg(short, long)]
        dominio: String,
        /// ID da categoria (opcional).
        #[arg(short, long)]
        categoria_id: Option<i64>,
        /// URL principal (opcional).
        #[arg(short, long)]
        url: Option<String>,
    },
    /// Listar todos os serviços.
    List {
        /// Filtrar por categoria.
        #[arg(short, long)]
        categoria_id: Option<i64>,
    },
    /// Pesquisar serviços por nome.
    Search {
        /// Termo de pesquisa.
        termo: String,
    },
}

#[derive(Subcommand)]
pub enum CredencialCommands {
    /// Adicionar uma nova credencial.
    Add {
        /// ID do serviço.
        #[arg(short, long)]
        servico_id: i64,
        /// Nome de exibição (ex: "Netflix pessoal").
        #[arg(short, long)]
        nome: String,
        /// Identificador (login, e-mail, CPF, etc.).
        #[arg(short, long)]
        identificador: String,
    },
    /// Listar todas as credenciais.
    List,
    /// Exibir detalhes de uma credencial (e opcionalmente revelar a senha).
    Show {
        /// ID da credencial.
        id: i64,
        /// Revelar a senha em texto puro.
        #[arg(short, long)]
        revelar: bool,
    },
    /// Pesquisar credenciais.
    Search {
        /// Termo de pesquisa.
        termo: String,
    },
}

/// Retorna o caminho padrão do banco de dados.
pub fn default_db_path() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "cofre", "cofre-credenciais")
        .ok_or_else(|| anyhow::anyhow!("Não foi possível determinar o diretório de dados"))?;

    let data_dir = proj_dirs.data_dir();
    std::fs::create_dir_all(data_dir)?;

    Ok(data_dir.join("cofre.db"))
}

/// Resolve o caminho do banco de dados.
fn resolve_db_path(custom: &Option<PathBuf>) -> Result<PathBuf> {
    match custom {
        Some(p) => Ok(p.clone()),
        None => default_db_path(),
    }
}

/// Executa o comando selecionado.
pub fn execute(cli: Cli) -> Result<()> {
    let db_path = resolve_db_path(&cli.db_path)?;

    match cli.command {
        Commands::Init { nome } => init::execute(&db_path, &nome),
        Commands::Categoria(cmd) => categoria::execute(&db_path, cmd),
        Commands::Servico(cmd) => servico::execute(&db_path, cmd),
        Commands::Credencial(cmd) => credencial::execute(&db_path, cmd),
    }
}
