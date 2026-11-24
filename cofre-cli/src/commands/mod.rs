//! Definição dos comandos CLI com clap.

pub mod auditoria;
pub mod backup;
pub mod categoria;
pub mod credencial;
pub mod dispositivo;
pub mod email;
pub mod init;
pub mod metodo;
pub mod preferencia;
pub mod senha_mestre;
pub mod servico;
pub mod sessao;
pub mod shell;
pub mod sinal;
pub mod unlock;
pub mod url;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use inquire::Confirm;
use std::path::PathBuf;

use self::sessao::Contexto;

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

    /// Gerenciar dispositivos registrados no cofre.
    #[command(subcommand)]
    Dispositivo(DispositivoCommands),

    /// Gerenciar preferências do usuário.
    #[command(subcommand)]
    Preferencia(PreferenciaCommands),

    /// Consultar eventos de auditoria do cofre.
    #[command(subcommand)]
    Auditoria(AuditoriaCommands),

    /// Gerenciar backups cifrados do cofre.
    #[command(subcommand)]
    Backup(BackupCommands),

    /// Iniciar modo interativo (shell) com sessão única e bloqueio por inatividade.
    Shell,
}

#[derive(Subcommand)]
pub enum BackupCommands {
    /// Criar um novo backup cifrado do cofre.
    Create {
        /// Diretório onde o arquivo .cbk será gravado (padrão: <dir do banco>/backups/).
        #[arg(short, long)]
        destino: Option<PathBuf>,
    },
    /// Listar os backups registrados no cofre.
    List,
    /// Verificar a integridade, autenticidade e validade SQLite de um backup.
    Verify {
        /// ID do backup registrado.
        id: i64,
    },
    /// Restaurar o cofre a partir de um backup registrado (ID) ou de um arquivo .cbk.
    Restore {
        /// ID do backup registrado no cofre atual.
        #[arg(required_unless_present = "arquivo", conflicts_with = "arquivo")]
        id: Option<i64>,
        /// Caminho de um arquivo de backup (.cbk) — funciona mesmo sem cofre inicializado.
        #[arg(short, long, required_unless_present = "id", conflicts_with = "id")]
        arquivo: Option<PathBuf>,
        /// Não pedir confirmação.
        #[arg(short = 'y', long)]
        sim: bool,
    },
    /// Excluir um backup registrado (e opcionalmente manter o arquivo .cbk no disco).
    Delete {
        /// ID do backup registrado.
        id: i64,
        /// Remover apenas o registro no banco, mantendo o arquivo .cbk no disco.
        #[arg(long)]
        manter_arquivo: bool,
        /// Não pedir confirmação.
        #[arg(short = 'y', long)]
        sim: bool,
    },
}

#[derive(Subcommand)]
pub enum AuditoriaCommands {
    /// Listar eventos de auditoria registrados no cofre.
    List {
        /// Filtrar por tipo de evento (ex: DESBLOQUEIO, COPIA_SEGREDO, ALTERACAO).
        #[arg(long)]
        tipo: Option<String>,
        /// Filtrar por ID da credencial.
        #[arg(long)]
        credencial: Option<i64>,
        /// Filtrar eventos a partir desta data (formato AAAA-MM-DD).
        #[arg(long)]
        desde: Option<String>,
        /// Número máximo de eventos exibidos (1..=1000).
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u64).range(1..=1000))]
        limite: u64,
    },
}

#[derive(Subcommand)]
pub enum PreferenciaCommands {
    /// Listar todas as preferências e seus valores efetivos.
    List,
    /// Obter o valor atual de uma preferência.
    Get {
        /// Chave da preferência (ex: tempo_clipboard, timeout_inatividade, navegador_padrao).
        chave: String,
    },
    /// Definir o valor de uma preferência.
    Set {
        /// Chave da preferência.
        chave: String,
        /// Novo valor da preferência.
        valor: String,
    },
    /// Redefinir uma preferência para o valor padrão.
    Reset {
        /// Chave da preferência.
        chave: String,
    },
}

#[derive(Subcommand)]
pub enum DispositivoCommands {
    /// Listar os dispositivos registrados no cofre.
    List,
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
    /// Gerenciar as URLs do serviço (login, recuperação, cadastro...).
    #[command(subcommand)]
    Url(UrlCommands),
}

/// Tipo de uma URL de serviço.
#[derive(Clone, Copy, ValueEnum)]
pub enum TipoUrl {
    Principal,
    Login,
    Recuperacao,
    Cadastro,
    Logout,
}

impl TipoUrl {
    pub fn como_db(self) -> &'static str {
        match self {
            TipoUrl::Principal => "PRINCIPAL",
            TipoUrl::Login => "LOGIN",
            TipoUrl::Recuperacao => "RECUPERACAO",
            TipoUrl::Cadastro => "CADASTRO",
            TipoUrl::Logout => "LOGOUT",
        }
    }
}

#[derive(Subcommand)]
pub enum UrlCommands {
    /// Adicionar uma URL a um serviço (a primeira vira a padrão).
    Add {
        /// ID do serviço.
        servico_id: i64,
        /// URL completa (ex: https://github.com/login).
        url: String,
        /// Tipo da URL.
        #[arg(short, long, value_enum, default_value_t = TipoUrl::Login)]
        tipo: TipoUrl,
        /// Descrição opcional.
        #[arg(short, long)]
        descricao: Option<String>,
        /// Tornar esta a URL padrão do serviço.
        #[arg(short, long)]
        padrao: bool,
    },
    /// Listar as URLs de um serviço.
    List {
        /// ID do serviço.
        servico_id: i64,
    },
    /// Editar uma URL.
    Edit {
        /// ID da URL.
        id: i64,
        /// Nova URL.
        #[arg(short, long)]
        url: Option<String>,
        /// Novo tipo.
        #[arg(short, long, value_enum)]
        tipo: Option<TipoUrl>,
        /// Nova descrição (vazia remove a descrição).
        #[arg(short, long)]
        descricao: Option<String>,
        /// Tornar esta a URL padrão do serviço.
        #[arg(short, long)]
        padrao: bool,
        /// Ativar (true) ou desativar (false) a URL.
        #[arg(short, long)]
        ativa: Option<bool>,
    },
    /// Excluir uma URL.
    Delete {
        /// ID da URL.
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
        /// Segundos até limpar a área de transferência (usa a preferência tempo_clipboard se omitido).
        #[arg(short, long, value_parser = clap::value_parser!(u64).range(1..=600))]
        segundos: Option<u64>,
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
        /// Motivo opcional da alteração (registrado no histórico da credencial).
        #[arg(short, long)]
        motivo: Option<String>,
    },
    /// Desativar uma credencial (fica oculta, mas não é apagada).
    Deactivate {
        /// ID da credencial.
        id: i64,
        /// Motivo opcional da desativação (registrado no histórico da credencial).
        #[arg(short, long)]
        motivo: Option<String>,
    },
    /// Reativar uma credencial desativada.
    Activate {
        /// ID da credencial.
        id: i64,
        /// Motivo opcional da reativação (registrado no histórico da credencial).
        #[arg(short, long)]
        motivo: Option<String>,
    },
    /// Excluir definitivamente uma credencial.
    Delete {
        /// ID da credencial.
        id: i64,
        /// Não pedir confirmação.
        #[arg(short = 'y', long)]
        sim: bool,
    },
    /// Exibir o histórico de alterações de uma credencial.
    Historico {
        /// ID da credencial.
        id: i64,
        /// Revelar valores anteriores guardados no histórico (pede confirmação).
        #[arg(short, long)]
        revelar: bool,
    },
    /// Gerenciar os métodos de autenticação da credencial (senha, TOTP, SMS...).
    #[command(subcommand)]
    Metodo(MetodoCommands),
    /// Gerenciar os e-mails de recuperação da credencial (armazenados cifrados).
    #[command(subcommand)]
    Email(EmailCommands),
}

/// Tipo de um método de autenticação.
#[derive(Clone, Copy, ValueEnum)]
pub enum TipoMetodo {
    Senha,
    Totp,
    Sms,
    Email,
    Passkey,
    Biometria,
    Aplicativo,
}

impl TipoMetodo {
    pub fn como_db(self) -> &'static str {
        match self {
            TipoMetodo::Senha => "SENHA",
            TipoMetodo::Totp => "TOTP",
            TipoMetodo::Sms => "SMS",
            TipoMetodo::Email => "EMAIL",
            TipoMetodo::Passkey => "PASSKEY",
            TipoMetodo::Biometria => "BIOMETRIA",
            TipoMetodo::Aplicativo => "APLICATIVO",
        }
    }
}

#[derive(Subcommand)]
pub enum MetodoCommands {
    /// Adicionar um método de autenticação a uma credencial.
    Add {
        /// ID da credencial.
        credencial_id: i64,
        /// Tipo do método.
        #[arg(short, long, value_enum)]
        tipo: TipoMetodo,
        /// Descrição opcional (ex: "Google Authenticator", "celular final 1234").
        #[arg(short, long)]
        descricao: Option<String>,
        /// Tornar este o método principal da credencial.
        #[arg(short, long)]
        principal: bool,
    },
    /// Listar os métodos de autenticação de uma credencial.
    List {
        /// ID da credencial.
        credencial_id: i64,
    },
    /// Editar um método de autenticação.
    Edit {
        /// ID do método.
        id: i64,
        /// Novo tipo.
        #[arg(short, long, value_enum)]
        tipo: Option<TipoMetodo>,
        /// Nova descrição (vazia remove a descrição).
        #[arg(short, long)]
        descricao: Option<String>,
        /// Marcar (true) ou desmarcar (false) como principal.
        #[arg(short, long)]
        principal: Option<bool>,
        /// Habilitar (true) ou desabilitar (false) o método.
        #[arg(long)]
        habilitado: Option<bool>,
    },
    /// Excluir um método de autenticação.
    Delete {
        /// ID do método.
        id: i64,
        /// Não pedir confirmação.
        #[arg(short = 'y', long)]
        sim: bool,
    },
}

#[derive(Subcommand)]
pub enum EmailCommands {
    /// Adicionar um e-mail de recuperação (o endereço é pedido em prompt).
    Add {
        /// ID da credencial.
        credencial_id: i64,
        /// Tornar este o e-mail principal da credencial.
        #[arg(short, long)]
        principal: bool,
        /// Marcar o e-mail como já verificado.
        #[arg(short, long)]
        verificado: bool,
    },
    /// Listar os e-mails de recuperação de uma credencial (mascarados por padrão).
    List {
        /// ID da credencial.
        credencial_id: i64,
        /// Exibir os endereços completos.
        #[arg(short, long)]
        revelar: bool,
    },
    /// Editar um e-mail de recuperação.
    Edit {
        /// ID do e-mail.
        id: i64,
        /// Pedir um novo endereço (a verificação anterior é desfeita).
        #[arg(short, long)]
        email: bool,
        /// Marcar (true) ou desmarcar (false) como principal.
        #[arg(short, long)]
        principal: Option<bool>,
        /// Marcar como verificado (true) ou não verificado (false).
        #[arg(short, long)]
        verificado: Option<bool>,
        /// Ativar (true) ou desativar (false) o e-mail.
        #[arg(short, long)]
        ativo: Option<bool>,
    },
    /// Excluir um e-mail de recuperação.
    Delete {
        /// ID do e-mail.
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
    if valor.trim().is_empty() {
        None
    } else {
        Some(valor)
    }
}

/// Executa o comando selecionado.
pub fn execute(cli: Cli) -> Result<()> {
    let db_path = resolve_db_path(&cli.db_path)?;
    let ctx = Contexto::novo(db_path);
    executar_comando(&ctx, cli.command)
}

/// Despacha um subcomando utilizando o contexto compartilhado.
pub fn executar_comando(ctx: &Contexto, command: Commands) -> Result<()> {
    match command {
        Commands::Init { nome } => init::execute(ctx, &nome),
        Commands::SenhaMestre => senha_mestre::execute(ctx),
        Commands::Categoria(cmd) => categoria::execute(ctx, cmd),
        Commands::Servico(cmd) => servico::execute(ctx, cmd),
        Commands::Credencial(cmd) => credencial::execute(ctx, cmd),
        Commands::Dispositivo(cmd) => dispositivo::execute(ctx, cmd),
        Commands::Preferencia(cmd) => preferencia::execute(ctx, cmd),
        Commands::Auditoria(cmd) => auditoria::execute(ctx, cmd),
        Commands::Backup(cmd) => backup::execute(ctx, cmd),
        Commands::Shell => shell::execute(ctx),
    }
}
