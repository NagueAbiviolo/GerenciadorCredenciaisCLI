//! Comandos de login automático e configuração de login (`cofre login ...` e `cofre credencial login-config ...`).

use std::path::PathBuf;

use anyhow::{Context, Result};
use comfy_table::{ContentArrangement, Table};

use cofre_automacao::login::{self, ParametrosLogin, StatusLogin};
use cofre_db::models::ConfiguracaoLogin;
use cofre_db::Database;
use cofre_services::auditoria_service::ResultadoEvento;
use cofre_services::login_service::{self, DadosNovaConfiguracaoLogin, EdicaoConfiguracaoLogin};

use super::sessao::Contexto;
use super::{confirmar, sinal, vazio_para_none, LoginArgs, LoginConfigCommands, LoginSubcommands};

fn formatar_url(db: &Database, url_servico_id: i64) -> String {
    db.buscar_url_servico(url_servico_id)
        .map(|u| format!("#{} ({})", u.id, u.url))
        .unwrap_or_else(|_| format!("#{url_servico_id}"))
}

fn tabela_configuracoes(db: &Database, configs: &[ConfiguracaoLogin]) -> Table {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "ID",
        "URL",
        "Seletor Usuário",
        "Seletor Senha",
        "Seletor Botão",
        "Envio Auto",
        "Timeout",
        "Ativa",
        "Última Validação",
    ]);

    for c in configs {
        table.add_row(vec![
            c.id.to_string(),
            formatar_url(db, c.url_servico_id),
            c.seletor_usuario.clone().unwrap_or_else(|| "-".into()),
            c.seletor_senha.clone().unwrap_or_else(|| "-".into()),
            c.seletor_botao.clone().unwrap_or_else(|| "-".into()),
            if c.envio_automatico { "Sim" } else { "Não" }.into(),
            format!("{}s", c.timeout_segundos),
            if c.ativa { "Sim" } else { "Não" }.into(),
            c.ultima_validacao_em
                .map(|d| d.format("%d/%m/%Y %H:%M").to_string())
                .unwrap_or_else(|| "-".into()),
        ]);
    }

    table
}

fn diretorio_dados_app(ctx: &Contexto) -> PathBuf {
    ctx.db_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(std::env::temp_dir)
}

pub fn execute(ctx: &Contexto, args: LoginArgs) -> Result<()> {
    match (args.subcommand, args.credencial_id) {
        (Some(LoginSubcommands::Config(cmd)), _) => execute_config(ctx, cmd),
        (None, Some(credencial_id)) => executar_fluxo_login(ctx, credencial_id, args.config_id),
        (None, None) => {
            anyhow::bail!(
                "Informe o ID da credencial ('cofre login <credencial_id>') ou use 'cofre login config --help'."
            );
        }
    }
}

pub fn execute_config(ctx: &Contexto, cmd: LoginConfigCommands) -> Result<()> {
    if let LoginConfigCommands::Edit {
        url_id: None,
        seletor_usuario: None,
        seletor_senha: None,
        seletor_botao: None,
        url_sucesso: None,
        envio_automatico: false,
        sem_envio: false,
        timeout: None,
        ativa: None,
        ..
    } = cmd
    {
        anyhow::bail!("Nada para alterar. Use --help para ver os campos editáveis.");
    }

    ctx.com_sessao(|s| {
        match cmd {
            LoginConfigCommands::Add {
                credencial_id,
                url_id,
                seletor_usuario,
                seletor_senha,
                seletor_botao,
                url_sucesso,
                envio_automatico: _,
                sem_envio,
                timeout,
                ativa,
            } => {
                let envio_efetivo = !sem_envio;
                let id = login_service::adicionar_configuracao(
                    &s.db,
                    s.usuario_id,
                    &DadosNovaConfiguracaoLogin {
                        credencial_id,
                        url_servico_id: url_id,
                        seletor_usuario: seletor_usuario.as_deref(),
                        seletor_senha: Some(&seletor_senha),
                        seletor_botao: seletor_botao.as_deref(),
                        url_sucesso: url_sucesso.as_deref(),
                        envio_automatico: envio_efetivo,
                        timeout_segundos: timeout,
                        ativa,
                    },
                )
                .context("Falha ao adicionar configuração de login")?;

                println!(
                    "✅ Configuração de login adicionada para a credencial #{credencial_id} com ID {id}."
                );
            }

            LoginConfigCommands::List { credencial_id } => {
                let configs =
                    login_service::listar_configuracoes(&s.db, s.usuario_id, credencial_id)
                        .context("Falha ao listar configurações de login")?;
                if configs.is_empty() {
                    println!(
                        "Nenhuma configuração de login cadastrada para a credencial #{credencial_id}."
                    );
                    return Ok(());
                }
                println!("{}", tabela_configuracoes(&s.db, &configs));
                println!("\nTotal: {} configuração(ões)", configs.len());
            }

            LoginConfigCommands::Show { id } => {
                let c = login_service::buscar_configuracao(&s.db, s.usuario_id, id)
                    .context("Configuração de login não encontrada")?;

                println!("┌─────────────────────────────────────────");
                println!("│ 🌐 Configuração de Login #{}", c.id);
                println!("├─────────────────────────────────────────");
                println!("│ Credencial ID:    #{}", c.credencial_id);
                println!(
                    "│ URL do Serviço:   {}",
                    formatar_url(&s.db, c.url_servico_id)
                );
                println!(
                    "│ Seletor Usuário:  {}",
                    c.seletor_usuario.as_deref().unwrap_or("-")
                );
                println!(
                    "│ Seletor Senha:    {}",
                    c.seletor_senha.as_deref().unwrap_or("-")
                );
                println!(
                    "│ Seletor Botão:    {}",
                    c.seletor_botao.as_deref().unwrap_or("-")
                );
                println!(
                    "│ URL de Sucesso:   {}",
                    c.url_sucesso.as_deref().unwrap_or("-")
                );
                println!(
                    "│ Envio Automático: {}",
                    if c.envio_automatico { "Sim" } else { "Não" }
                );
                println!("│ Timeout:          {}s", c.timeout_segundos);
                println!(
                    "│ Ativa:            {}",
                    if c.ativa { "Sim" } else { "Não" }
                );
                println!(
                    "│ Última Validação: {}",
                    c.ultima_validacao_em
                        .map(|d| d.format("%d/%m/%Y %H:%M:%S").to_string())
                        .unwrap_or_else(|| "-".into())
                );
                println!(
                    "│ Criada em:        {}",
                    c.criado_em.format("%d/%m/%Y %H:%M:%S")
                );
                println!(
                    "│ Atualizada em:    {}",
                    c.atualizado_em.format("%d/%m/%Y %H:%M:%S")
                );
                println!("└─────────────────────────────────────────");
            }

            LoginConfigCommands::Edit {
                id,
                url_id,
                seletor_usuario,
                seletor_senha,
                seletor_botao,
                url_sucesso,
                envio_automatico,
                sem_envio,
                timeout,
                ativa,
            } => {
                let seletor_usuario = seletor_usuario.map(vazio_para_none);
                let seletor_botao = seletor_botao.map(vazio_para_none);
                let url_sucesso = url_sucesso.map(vazio_para_none);
                let envio_opt = if envio_automatico {
                    Some(true)
                } else if sem_envio {
                    Some(false)
                } else {
                    None
                };

                let edicao = EdicaoConfiguracaoLogin {
                    url_servico_id: url_id,
                    seletor_usuario: seletor_usuario.as_ref().map(|v| v.as_deref()),
                    seletor_senha: seletor_senha.as_deref(),
                    seletor_botao: seletor_botao.as_ref().map(|v| v.as_deref()),
                    url_sucesso: url_sucesso.as_ref().map(|v| v.as_deref()),
                    envio_automatico: envio_opt,
                    timeout_segundos: timeout,
                    ativa,
                };

                login_service::editar_configuracao(&s.db, s.usuario_id, id, &edicao)
                    .context("Falha ao editar configuração de login")?;
                println!("✅ Configuração de login #{id} atualizada.");
            }

            LoginConfigCommands::Delete { id, sim } => {
                let c = login_service::buscar_configuracao(&s.db, s.usuario_id, id)
                    .context("Configuração de login não encontrada")?;
                let msg = format!(
                    "Excluir a configuração de login #{id} da credencial #{}?",
                    c.credencial_id
                );
                if !confirmar(&msg, sim)? {
                    println!("Operação cancelada.");
                    return Ok(());
                }
                login_service::excluir_configuracao(&s.db, s.usuario_id, id)
                    .context("Falha ao excluir configuração de login")?;
                println!("🗑️  Configuração de login #{id} excluída.");
            }
        }
        Ok(())
    })
}

fn executar_fluxo_login(ctx: &Contexto, credencial_id: i64, config_id: Option<i64>) -> Result<()> {
    let interrompido = sinal::preparar_ctrl_c()?;
    let dir_dados = diretorio_dados_app(ctx);

    ctx.com_sessao(|s| {
        let prep = login_service::preparar_dados_login(
            &s.db,
            &s.vault,
            s.usuario_id,
            credencial_id,
            config_id,
        )
        .context("Falha ao preparar os dados para o login automático")?;

        let cfg_id = prep.config.id;
        let seletor_senha = prep
            .config
            .seletor_senha
            .clone()
            .unwrap_or_else(|| "input[type=password]".into());

        let perfil_dir = login::preparar_diretorio_perfil(&dir_dados, credencial_id)
            .context("Falha ao preparar o diretório de perfil do navegador")?;
        let perfil_nome = format!("credencial-{credencial_id}");
        let perfil_dir_str = perfil_dir.to_string_lossy().to_string();

        let sessao_id = login_service::iniciar_sessao_navegador(
            &s.db,
            s.usuario_id,
            credencial_id,
            &prep.navegador_padrao,
            Some(&perfil_nome),
            Some(&perfil_dir_str),
        )
        .context("Falha ao registrar sessão do navegador")?;

        println!(
            "🌐 Iniciando navegador '{}' para '{}' ({})...",
            prep.navegador_padrao, prep.url_login, prep.dominio_principal
        );

        let params = ParametrosLogin {
            credencial_id,
            url_login: prep.url_login.clone(),
            dominio_principal: prep.dominio_principal.clone(),
            identificador: prep.identificador.clone(),
            senha: prep.senha,
            seletor_usuario: prep.config.seletor_usuario.clone(),
            seletor_senha,
            seletor_botao: prep.config.seletor_botao.clone(),
            url_sucesso: prep.config.url_sucesso.clone(),
            envio_automatico: prep.config.envio_automatico,
            timeout_segundos: u64::try_from(prep.config.timeout_segundos).unwrap_or(30),
            navegador_padrao: prep.navegador_padrao.clone(),
            diretorio_dados_app: dir_dados,
            interrompido: Some(interrompido),
            aguardar_fechamento: true,
        };

        let resultado_exec = login::executar_login(&params);

        // Sempre encerra o registro da sessão do navegador ao término do comando
        let _ = login_service::encerrar_sessao_navegador(&s.db, sessao_id);

        match resultado_exec {
            Ok(res) => {
                let (res_auditoria, icone, validar) = match res.status {
                    StatusLogin::Sucesso => (ResultadoEvento::Sucesso, "✅", true),
                    StatusLogin::Parcial => (ResultadoEvento::Parcial, "⚠️ ", true),
                    StatusLogin::Falha => (ResultadoEvento::Falha, "❌", false),
                    StatusLogin::Cancelado => (ResultadoEvento::Cancelado, "🛑", false),
                };

                login_service::registrar_resultado_login(
                    &s.db,
                    s.usuario_id,
                    credencial_id,
                    cfg_id,
                    res_auditoria,
                    &res.motivo,
                    validar,
                );

                println!("{icone} Resultado do login automático: {}", res.motivo);
                if res.status == StatusLogin::Falha {
                    anyhow::bail!("Falha no login automático: {}", res.motivo);
                }
                Ok(())
            }
            Err(e) => {
                let desc = format!("Erro ao executar login automático: {e}");
                login_service::registrar_resultado_login(
                    &s.db,
                    s.usuario_id,
                    credencial_id,
                    cfg_id,
                    ResultadoEvento::Falha,
                    &desc,
                    false,
                );
                Err(anyhow::Error::new(e))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{Cli, Commands, CredencialCommands};
    use clap::Parser;

    #[test]
    fn test_cli_parse_login_e_login_config() {
        // 1. cofre login <credencial_id> [--config-id N]
        let cli = Cli::try_parse_from(["cofre", "login", "7", "--config-id", "2"]).unwrap();
        match cli.command {
            Commands::Login(args) => {
                assert!(args.subcommand.is_none());
                assert_eq!(args.credencial_id, Some(7));
                assert_eq!(args.config_id, Some(2));
            }
            _ => panic!("Esperava Commands::Login"),
        }

        // 2. cofre login config add ...
        let cli = Cli::try_parse_from([
            "cofre",
            "login",
            "config",
            "add",
            "--credencial-id",
            "3",
            "--url-id",
            "10",
            "--seletor-usuario",
            "#email",
            "--seletor-senha",
            "#pass",
            "--seletor-botao",
            "button[type=submit]",
            "--url-sucesso",
            "https://exemplo.com/home",
            "--sem-envio",
            "--timeout",
            "45",
            "--ativa=false",
        ])
        .unwrap();
        match cli.command {
            Commands::Login(args) => match args.subcommand {
                Some(LoginSubcommands::Config(LoginConfigCommands::Add {
                    credencial_id,
                    url_id,
                    seletor_usuario,
                    seletor_senha,
                    seletor_botao,
                    url_sucesso,
                    envio_automatico,
                    sem_envio,
                    timeout,
                    ativa,
                })) => {
                    assert_eq!(credencial_id, 3);
                    assert_eq!(url_id, 10);
                    assert_eq!(seletor_usuario.as_deref(), Some("#email"));
                    assert_eq!(seletor_senha, "#pass");
                    assert_eq!(seletor_botao.as_deref(), Some("button[type=submit]"));
                    assert_eq!(url_sucesso.as_deref(), Some("https://exemplo.com/home"));
                    assert!(!envio_automatico);
                    assert!(sem_envio);
                    assert_eq!(timeout, 45);
                    assert!(!ativa);
                }
                _ => panic!("Esperava LoginConfigCommands::Add"),
            },
            _ => panic!("Esperava Commands::Login"),
        }

        // 3. cofre credencial login-config list --credencial-id 3
        let cli = Cli::try_parse_from([
            "cofre",
            "credencial",
            "login-config",
            "list",
            "--credencial-id",
            "3",
        ])
        .unwrap();
        match cli.command {
            Commands::Credencial(CredencialCommands::LoginConfig(LoginConfigCommands::List {
                credencial_id,
            })) => {
                assert_eq!(credencial_id, 3);
            }
            _ => panic!("Esperava CredencialCommands::LoginConfig(List)"),
        }
    }
}
