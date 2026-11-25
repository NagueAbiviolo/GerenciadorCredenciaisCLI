//! Testes básicos da CLI: `--help`, `--version`, validação de argumentos,
//! inicialização do cofre (`init`), rejeição de senha incorreta e auditoria de desbloqueio.

mod common;

use common::CofreTemp;
use predicates::prelude::*;

#[test]
fn ajuda_exibe_descricao_e_subcomandos() {
    let cofre = CofreTemp::novo();

    // `--help` exibe `long_about` e todos os subcomandos principais
    cofre
        .cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Armazena e gerencia credenciais de forma segura",
        ))
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("categoria"))
        .stdout(predicate::str::contains("servico"))
        .stdout(predicate::str::contains("credencial"))
        .stdout(predicate::str::contains("auditoria"))
        .stdout(predicate::str::contains("alerta"))
        .stdout(predicate::str::contains("backup"))
        .stdout(predicate::str::contains("shell"));

    // `-h` exibe o resumo curto (`about`)
    cofre
        .cmd()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Gerenciador pessoal de credenciais via linha de comando",
        ));
}

#[test]
fn versao_exibe_nome_e_versao_do_pacote() {
    let cofre = CofreTemp::novo();

    cofre
        .cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(concat!(
            "cofre ",
            env!("CARGO_PKG_VERSION")
        )));
}

#[test]
fn erros_de_argumentos_e_validacao_imediata_falham() {
    let cofre = CofreTemp::novo();

    // Sem subcomando -> erro de uso do clap (código != 0)
    cofre.cmd().assert().failure();

    // `init` sem `--nome` -> erro de argumento obrigatório
    cofre.cmd().arg("init").assert().failure();

    // `backup restore` exige exatamente ID ou --arquivo (nem zero, nem ambos)
    cofre.cmd().args(["backup", "restore"]).assert().failure();
    cofre
        .cmd()
        .args(["backup", "restore", "1", "--arquivo", "teste.cbk"])
        .assert()
        .failure();

    // `credencial copy` sem ID e com `--segundos` fora da faixa 1..=600 -> erro do clap
    cofre.cmd().args(["credencial", "copy"]).assert().failure();
    cofre
        .cmd()
        .args(["credencial", "copy", "1", "--segundos", "0"])
        .assert()
        .failure();

    // `login` sem credencial_id nem subcomando `config` -> erro da aplicação (código 1)
    cofre
        .cmd()
        .arg("login")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("❌ Erro:"))
        .stderr(predicate::str::contains("Informe o ID da credencial"));

    // `credencial edit` sem campos para alterar falha imediatamente com código 1
    cofre
        .cmd()
        .args(["credencial", "edit", "1"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("❌ Erro: Nada para alterar"));
}

#[cfg(unix)]
#[test]
fn init_rejeita_senha_curta_menor_que_oito_caracteres() {
    use common::{aguardar_saida, esperar_texto};

    let cofre = CofreTemp::novo();
    let mut pty = cofre.spawn_pty(&["init", "--nome", "Usuária Teste"]);

    esperar_texto(&mut pty, "Defina a senha mestre:");
    pty.send_line("curta7!").unwrap();
    esperar_texto(&mut pty, "Confirme a senha:");
    pty.send_line("curta7!").unwrap();

    let (saida, codigo) = aguardar_saida(&mut pty);
    assert_eq!(
        codigo, 1,
        "Senha < 8 caracteres deve sair com código 1. Saída:\n{saida}"
    );
    assert!(
        saida.contains("❌ Erro:") && saida.contains("pelo menos 8 caracteres"),
        "Mensagem de erro de tamanho mínimo não encontrada. Saída:\n{saida}"
    );
    assert!(
        !cofre.db_path.exists(),
        "O banco não deve ser criado quando a senha mestre é rejeitada antes de abrir o cofre"
    );
}

#[cfg(unix)]
#[test]
fn init_rejeita_senhas_que_nao_coincidem() {
    use common::{aguardar_saida, esperar_texto};

    let cofre = CofreTemp::novo();
    let mut pty = cofre.spawn_pty(&["init", "--nome", "Usuária Teste"]);

    esperar_texto(&mut pty, "Defina a senha mestre:");
    pty.send_line("SenhaCorreta123!").unwrap();
    esperar_texto(&mut pty, "Confirme a senha:");
    pty.send_line("SenhaDiferente999!").unwrap();

    // O `inquire` exibe a mensagem de erro e volta a pedir a senha mestre.
    esperar_texto(&mut pty, "As senhas não coincidem. Tente novamente.");
    esperar_texto(&mut pty, "Defina a senha mestre:");

    // Cancela o prompt com Esc para encerrar o processo sem inicializar o cofre.
    pty.send("\x1b").unwrap();
    pty.flush().unwrap();

    let (saida, codigo) = aguardar_saida(&mut pty);
    assert_eq!(
        codigo, 1,
        "Cancelamento após confirmação divergente deve sair com código 1. Saída:\n{saida}"
    );
    assert!(
        saida.contains("❌ Erro:"),
        "Esperava mensagem de erro em stderr ao abortar init. Saída:\n{saida}"
    );
    assert!(
        !cofre.db_path.exists(),
        "O banco não deve existir após tentativa abortada de init"
    );
}

#[cfg(unix)]
#[test]
fn init_sucesso_duplicado_senha_errada_e_auditoria() {
    use common::{aguardar_saida, esperar_texto, SENHA_PADRAO};

    let cofre = CofreTemp::novo();

    // 1. Inicialização bem-sucedida
    cofre.inicializar("Maria Silva", SENHA_PADRAO);
    assert!(
        cofre.db_path.exists(),
        "O arquivo do banco deve ter sido criado"
    );

    // 2. Segundo `init` no mesmo banco deve falhar com código 1
    let mut pty_dup = cofre.spawn_pty(&["init", "--nome", "Outro Nome"]);
    esperar_texto(&mut pty_dup, "Defina a senha mestre:");
    pty_dup.send_line("OutraSenhaForte123!").unwrap();
    esperar_texto(&mut pty_dup, "Confirme a senha:");
    pty_dup.send_line("OutraSenhaForte123!").unwrap();

    let (saida_dup, codigo_dup) = aguardar_saida(&mut pty_dup);
    assert_eq!(
        codigo_dup, 1,
        "Init duplicado deve falhar com código 1. Saída:\n{saida_dup}"
    );
    assert!(
        saida_dup.contains("❌ Erro:") && saida_dup.contains("Cofre já inicializado"),
        "Esperava erro de cofre já inicializado. Saída:\n{saida_dup}"
    );

    // 3. Senha mestre incorreta deve falhar com código 1 e registrar DESBLOQUEIO com FALHA
    let (saida_errada, codigo_errada) =
        cofre.executar_com_senha(&["credencial", "list"], "SenhaIncorreta#000");
    assert_eq!(
        codigo_errada, 1,
        "Desbloqueio com senha errada deve sair com código 1. Saída:\n{saida_errada}"
    );
    assert!(
        saida_errada.contains("❌ Erro:") && saida_errada.contains("Falha ao desbloquear o cofre"),
        "Esperava mensagem de falha ao desbloquear. Saída:\n{saida_errada}"
    );

    // 4. Consulta à auditoria deve exibir INICIALIZACAO e DESBLOQUEIO (FALHA e SUCESSO)
    let (saida_aud, codigo_aud) = cofre.executar_com_senha(&["auditoria", "list"], SENHA_PADRAO);
    assert_eq!(codigo_aud, 0, "Falha em auditoria list:\n{saida_aud}");
    assert!(saida_aud.contains("INICIALIZACAO"));
    assert!(saida_aud.contains("DESBLOQUEIO"));
    assert!(saida_aud.contains("FALHA"));
    assert!(saida_aud.contains("SUCESSO"));
}
