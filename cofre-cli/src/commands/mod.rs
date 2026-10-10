//! Definição dos comandos CLI com clap.

pub mod init;
pub mod unlock;
pub mod credencial;
pub mod categoria;
pub mod servico;
pub mod senha_mestre;

use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use std::path::PathBuf;
use directories::ProjectDirs;
use inquire::Confirm;

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

    /// Alterar a senha mestre do cofre.
    SenhaMestre,

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
    /// Editar uma categoria.
    Edit {
        /// ID da categoria.
        id: i64,
        /// Novo nome.
        #[arg(short, long)]
        nome: Option<String>,
        /// Nova descrição (vazia remove a descrição).
        #[arg(short, long)]
        descricao: Option<String>,
    },
    /// Excluir uma categoria (os serviços dela ficam sem categoria).
    Delete {
        /// ID da categoria.
        id: i64,
        /// Não pedir confirmação.
        #[arg(short = 'y', long)]
        sim: bool,
    },
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
        /// Descrição (opcional).
        #[arg(long)]
        descricao: Option<String>,
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
    /// Editar um serviço.
    Edit {
        /// ID do serviço.
        id: i64,
        /// Novo nome.
        #[arg(short, long)]
        nome: Option<String>,
        /// Novo domínio principal.
        #[arg(short, long)]
        dominio: Option<String>,
        /// Nova categoria.
        #[arg(short, long, conflicts_with = "sem_categoria")]
        categoria_id: Option<i64>,
        /// Remover a categoria do serviço.
        #[arg(long)]
        sem_categoria: bool,
        /// Nova URL principal (vazia remove a URL).
        #[arg(short, long)]
        url: Option<String>,
        /// Nova descrição (vazia remove a descrição).
        #[arg(long)]
        descricao: Option<String>,
    },
    /// Excluir um serviço (só é permitido se não houver credenciais vinculadas).
    Delete {
        /// ID do serviço.
        id: i64,
        /// Não pedir confirmação.
        #[arg(short = 'y', long)]
        sim: bool,
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
        /// Solicitar uma observação privada (armazenada cifrada).
        #[arg(short, long)]
        observacao: bool,
    },
    /// Listar as credenciais.
    List {
        /// Listar as credenciais desativadas em vez das ativas.
        #[arg(long)]
        inativas: bool,
    },
    /// Exibir detalhes de uma credencial (e opcionalmente revelar a senha).
    Show {
        /// ID da credencial.
        id: i64,
        /// Revelar a senha e a observação em texto puro.
        #[arg(short, long)]
        revelar: bool,
    },
    /// Pesquisar credenciais.
    Search {
        /// Termo de pesquisa.
        termo: String,
    },
    /// Copiar a senha para a área de transferência, limpando-a após alguns segundos.
    Copy {
        /// ID da credencial.
        id: i64,
        /// Segundos até limpar a área de transferência.
        #[arg(short, long, default_value_t = 20, value_parser = clap::value_parser!(u64).range(1..=600))]
        segundos: u64,
    },
    /// Editar uma credencial.
    Edit {
        /// ID da credencial.
        id: i64,
        /// Novo nome de exibição.
        #[arg(short, long)]
        nome: Option<String>,
        /// Novo identificador.
        #[arg(short, long)]
        identificador: Option<String>,
        /// Marcar (true) ou desmarcar (false) como favorita.
        #[arg(short, long)]
        favorita: Option<bool>,
        /// Solicitar uma nova senha.
        #[arg(short, long)]
        senha: bool,
        /// Solicitar uma nova observação.
        #[arg(short, long, conflicts_with = "remover_observacao")]
        observacao: bool,
        /// Remover a observação.
        #[arg(long)]
        remover_observacao: bool,
    },
    /// Desativar uma credencial (fica oculta, mas não é apagada).
    Deactivate {
        /// ID da credencial.
        id: i64,
    },
    /// Reativar uma credencial desativada.
    Activate {
        /// ID da credencial.
        id: i64,
    },
    /// Excluir definitivamente uma credencial.
    Delete {
        /// ID da credencial.
        id: i64,
        /// Não pedir confirmação.
        #[arg(short = 'y', long)]
        sim: bool,
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

/// Pede confirmação antes de uma operação destrutiva. `sim` pula a pergunta.
pub fn confirmar(mensagem: &str, sim: bool) -> Result<bool> {
    if sim {
        return Ok(true);
    }
    Confirm::new(mensagem)
        .with_default(false)
        .prompt()
        .context("Falha ao ler a confirmação")
}

/// Converte texto vazio em `None` (usado para remover campos opcionais na edição).
pub fn vazio_para_none(valor: String) -> Option<String> {
    if valor.trim().is_empty() { None } else { Some(valor) }
}

/// Executa o comando selecionado.
pub fn execute(cli: Cli) -> Result<()> {
    let db_path = resolve_db_path(&cli.db_path)?;

    match cli.command {
        Commands::Init { nome } => init::execute(&db_path, &nome),
        Commands::SenhaMestre => senha_mestre::execute(&db_path),
        Commands::Categoria(cmd) => categoria::execute(&db_path, cmd),
        Commands::Servico(cmd) => servico::execute(&db_path, cmd),
        Commands::Credencial(cmd) => credencial::execute(&db_path, cmd),
    }
}
