//! Testes de integração de backups cifrados (`backup create`, `list`, `verify`, `restore`).

mod common;

#[cfg(unix)]
#[test]
fn backup_create_list_verify_restore_roundtrip() {
    use std::fs;

    use common::{aguardar_saida, esperar_texto, CofreTemp, SENHA_PADRAO};

    let cofre = CofreTemp::novo();
    cofre.inicializar("Ana Backup", SENHA_PADRAO);

    // Criar serviço sem exigir desbloqueio
    cofre
        .cmd()
        .args([
            "servico",
            "add",
            "--nome",
            "Email Pessoal",
            "--dominio",
            "proton.me",
        ])
        .assert()
        .success();

    let segredo_original = "SenhaProtonSuperSecreta!42";

    // Agrupamos criação de credencial, `backup create`, `backup list`, `backup verify`
    // e exclusão da credencial em uma sessão para evitar desbloqueios redundantes.
    let mut pty = cofre.spawn_pty(&["shell"]);
    esperar_texto(&mut pty, "Senha mestre:");
    pty.send_line(SENHA_PADRAO).unwrap();
    esperar_texto(&mut pty, "Cofre desbloqueado.");
    esperar_texto(&mut pty, "cofre> ");

    pty.send_line(
        "credencial add --servico-id 1 --nome \"Conta Proton\" --identificador \"ana@proton.me\"",
    )
    .unwrap();
    esperar_texto(&mut pty, "Senha da credencial:");
    pty.send_line(segredo_original).unwrap();
    esperar_texto(&mut pty, "Confirme a senha:");
    pty.send_line(segredo_original).unwrap();
    let saida_add = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_add.contains("Credencial 'Conta Proton' adicionada com ID 1."),
        "Falha ao criar credencial:\n{saida_add}"
    );

    // 1. `backup create` (no diretório padrão `<dir do db>/backups/`)
    pty.send_line("backup create").unwrap();
    let saida_create = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_create.contains("Backup cifrado criado com sucesso!")
            && saida_create.contains("ID:       #1"),
        "Falha no backup create:\n{saida_create}"
    );

    let dir_backups = cofre.dir_backups();
    assert!(
        dir_backups.is_dir(),
        "Diretório padrão de backups deveria existir em {}",
        dir_backups.display()
    );

    let arquivos_cbk: Vec<_> = fs::read_dir(&dir_backups)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("cbk"))
        .collect();
    assert_eq!(
        arquivos_cbk.len(),
        1,
        "Deveria haver exatamente 1 arquivo .cbk no diretório de backups"
    );

    // 2. `backup list`
    pty.send_line("backup list").unwrap();
    let saida_list = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_list.contains(".cbk") && saida_list.contains("Total: 1 backup(s)"),
        "Saída inesperada no backup list:\n{saida_list}"
    );

    // 3. `backup verify 1`
    pty.send_line("backup verify 1").unwrap();
    let saida_verify = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_verify.contains("Backup #1") && saida_verify.contains("é VÁLIDO."),
        "Saída inesperada no backup verify:\n{saida_verify}"
    );

    // 4. Excluir a credencial do cofre atual para simular perda de dados antes da restauração
    pty.send_line("credencial delete 1 -y").unwrap();
    let saida_del = esperar_texto(&mut pty, "cofre> ");
    assert!(saida_del.contains("Credencial 'Conta Proton' excluída."));

    pty.send_line("sair").unwrap();
    let (_, cod_shell) = aguardar_saida(&mut pty);
    assert_eq!(cod_shell, 0);

    // 5. Restaurar por ID via comando avulso (`cofre backup restore 1 -y`)
    let mut pty_restore = cofre.spawn_pty(&["backup", "restore", "1", "-y"]);
    esperar_texto(&mut pty_restore, "Senha mestre do backup:");
    pty_restore.send_line(SENHA_PADRAO).unwrap();

    let (saida_restore, cod_restore) = aguardar_saida(&mut pty_restore);
    assert_eq!(
        cod_restore, 0,
        "Falha no backup restore por ID:\n{saida_restore}"
    );
    assert!(saida_restore.contains("Backup restaurado com sucesso!"));

    // 6. Verificar via comando avulso `credencial show 1 --revelar` que a credencial voltou íntegra
    let (saida_show, cod_show) =
        cofre.executar_com_senha(&["credencial", "show", "1", "--revelar"], SENHA_PADRAO);
    assert_eq!(
        cod_show, 0,
        "Credencial #1 deveria existir após restauração:\n{saida_show}"
    );
    assert!(saida_show.contains("Conta Proton"));
    assert!(saida_show.contains(segredo_original));
}
