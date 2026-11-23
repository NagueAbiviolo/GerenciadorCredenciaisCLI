//! Gerenciador Pessoal de Credenciais — CLI
//!
//! Ponto de entrada do binário `cofre`.

mod commands;

use clap::Parser;
use commands::Cli;

fn main() {
    // Inicializar tracing para logs estruturados
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("cofre=info".parse().unwrap()),
        )
        .init();

    // Impedir a geração de core/crash dumps com segredos em memória
    cofre_crypto::protecao::desativar_core_dumps();

    let cli = Cli::parse();

    if let Err(e) = commands::execute(cli) {
        eprintln!("❌ Erro: {e:#}");
        std::process::exit(1);
    }
}
