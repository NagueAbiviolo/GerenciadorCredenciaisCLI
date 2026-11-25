//! Testes de integração do modo interativo (`cofre shell`).

mod common;

#[cfg(unix)]
#[test]
fn shell_desbloqueia_uma_vez_executa_comandos_bloqueia_e_sai() {
    use common::{aguardar_saida, esperar_texto, CofreTemp, SENHA_PADRAO};

    let cofre = CofreTemp::novo();
    cofre.inicializar("Carlos Shell", SENHA_PADRAO);

    let mut pty = cofre.spawn_pty(&["shell"]);

    // 1. Desbloqueia uma única vez ao entrar no shell
    esperar_texto(&mut pty, "Senha mestre:");
    pty.send_line(SENHA_PADRAO).unwrap();
    esperar_texto(&mut pty, "Cofre desbloqueado.");
    esperar_texto(&mut pty, "cofre> ");

    // 2. Executa múltiplos comandos reutilizando a sessão ativa (sem pedir Senha mestre:)
    pty.send_line("servico add --nome \"Servidor SSH\" --dominio \"ssh.exemplo.com\"")
        .unwrap();
    esperar_texto(&mut pty, "Serviço 'Servidor SSH' criado com ID 1.");
    esperar_texto(&mut pty, "cofre> ");

    pty.send_line("credencial add --servico-id 1 --nome \"Acesso Root\" --identificador \"root\"")
        .unwrap();
    // Nota: não pede "Senha mestre:", vai direto para "Senha da credencial:"
    esperar_texto(&mut pty, "Senha da credencial:");
    pty.send_line("ChaveRoot@9988!").unwrap();
    esperar_texto(&mut pty, "Confirme a senha:");
    pty.send_line("ChaveRoot@9988!").unwrap();
    esperar_texto(&mut pty, "Credencial 'Acesso Root' adicionada com ID 1.");
    esperar_texto(&mut pty, "cofre> ");

    pty.send_line("credencial show 1 --revelar").unwrap();
    esperar_texto(&mut pty, "ChaveRoot@9988!");
    esperar_texto(&mut pty, "cofre> ");

    pty.send_line("preferencia set tempo_clipboard 45").unwrap();
    esperar_texto(
        &mut pty,
        "Preferência 'tempo_clipboard' definida como '45'.",
    );
    esperar_texto(&mut pty, "cofre> ");

    // 3. Comandos proibidos dentro do shell devem ser recusados sem derrubar o REPL
    pty.send_line("init --nome Invalido").unwrap();
    esperar_texto(
        &mut pty,
        "O comando 'init' não pode ser executado dentro do shell.",
    );
    esperar_texto(&mut pty, "cofre> ");

    // 4. `bloquear` descarta a sessão em memória; o próximo comando que exige sessão pede a senha mestre
    pty.send_line("bloquear").unwrap();
    esperar_texto(&mut pty, "Cofre bloqueado.");
    esperar_texto(&mut pty, "cofre> ");

    pty.send_line("preferencia get tempo_clipboard").unwrap();
    esperar_texto(&mut pty, "Senha mestre:");
    pty.send_line(SENHA_PADRAO).unwrap();
    esperar_texto(&mut pty, "tempo_clipboard = 45");
    esperar_texto(&mut pty, "cofre> ");

    // 5. `sair` bloqueia o cofre e encerra o processo com código 0
    pty.send_line("sair").unwrap();
    let (saida_final, codigo) = aguardar_saida(&mut pty);
    assert_eq!(
        codigo, 0,
        "O comando 'sair' no shell deve encerrar com código 0. Saída:\n{saida_final}"
    );
    assert!(saida_final.contains("Cofre bloqueado."));
}
