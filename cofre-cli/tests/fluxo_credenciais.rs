//! Testes de integração do fluxo de categorias, serviços, credenciais,
//! alertas de segurança (senha reutilizada) e eventos de auditoria.

mod common;

use common::CofreTemp;
use predicates::prelude::*;

#[test]
fn crud_categoria_e_servico_nao_interativo() {
    let cofre = CofreTemp::novo();

    // Criar categoria
    cofre
        .cmd()
        .args([
            "categoria",
            "add",
            "--nome",
            "Desenvolvimento",
            "--descricao",
            "Contas de código",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Categoria 'Desenvolvimento' criada com ID 1.",
        ));

    // Listar categorias
    cofre
        .cmd()
        .args(["categoria", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Desenvolvimento"))
        .stdout(predicate::str::contains("Contas de código"))
        .stdout(predicate::str::contains("Total: 1 categoria(s)"));

    // Editar categoria
    cofre
        .cmd()
        .args(["categoria", "edit", "1", "--nome", "Engenharia"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Categoria #1 atualizada."));

    // Criar serviço vinculado à categoria #1
    cofre
        .cmd()
        .args([
            "servico",
            "add",
            "--nome",
            "GitHub",
            "--dominio",
            "github.com",
            "--categoria-id",
            "1",
            "--url",
            "https://github.com",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Serviço 'GitHub' criado com ID 1.",
        ));

    // Listar e pesquisar serviços
    cofre
        .cmd()
        .args(["servico", "list", "--categoria-id", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GitHub"))
        .stdout(predicate::str::contains("github.com"))
        .stdout(predicate::str::contains("Total: 1 serviço(s)"));

    cofre
        .cmd()
        .args(["servico", "search", "Git"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 resultado(s) para 'Git'"));

    // Editar serviço
    cofre
        .cmd()
        .args(["servico", "edit", "1", "--dominio", "gist.github.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Serviço #1 atualizado."));

    // Excluir serviço e categoria com `-y`
    cofre
        .cmd()
        .args(["servico", "delete", "1", "-y"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Serviço 'GitHub' excluído."));

    cofre
        .cmd()
        .args(["categoria", "delete", "1", "-y"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Categoria 'Engenharia' excluída."));
}

#[cfg(unix)]
#[test]
fn fluxo_completo_credenciais_alerta_senha_reutilizada_e_auditoria() {
    use common::{aguardar_saida, esperar_texto, SENHA_PADRAO};

    let cofre = CofreTemp::novo();
    cofre.inicializar("João Dev", SENHA_PADRAO);

    // 1. Criar categoria e dois serviços (operações diretas no banco sem exigir Argon2id)
    cofre
        .cmd()
        .args(["categoria", "add", "--nome", "Trabalho"])
        .assert()
        .success();

    cofre
        .cmd()
        .args([
            "servico",
            "add",
            "--nome",
            "GitHub",
            "--dominio",
            "github.com",
            "--categoria-id",
            "1",
        ])
        .assert()
        .success();

    cofre
        .cmd()
        .args([
            "servico",
            "add",
            "--nome",
            "GitLab",
            "--dominio",
            "gitlab.com",
            "--categoria-id",
            "1",
        ])
        .assert()
        .success();

    let senha_compartilhada = "SegredoSuperForte#2026";
    let observacao_cred1 = "Token de recuperação no cofre físico";

    // 2. Adicionar credencial #1 com observação cifrada via comando avulso (testa desbloqueio + prompts)
    let mut pty_add1 = cofre.spawn_pty(&[
        "credencial",
        "add",
        "--servico-id",
        "1",
        "--nome",
        "GitHub Pessoal",
        "--identificador",
        "joao@exemplo.com",
        "--observacao",
    ]);
    esperar_texto(&mut pty_add1, "Senha mestre:");
    pty_add1.send_line(SENHA_PADRAO).unwrap();
    esperar_texto(&mut pty_add1, "Senha da credencial:");
    pty_add1.send_line(senha_compartilhada).unwrap();
    esperar_texto(&mut pty_add1, "Confirme a senha:");
    pty_add1.send_line(senha_compartilhada).unwrap();
    esperar_texto(&mut pty_add1, "Observação:");
    pty_add1.send_line(observacao_cred1).unwrap();

    let (saida_add1, cod_add1) = aguardar_saida(&mut pty_add1);
    assert_eq!(
        cod_add1, 0,
        "Falha ao adicionar credencial #1:\n{saida_add1}"
    );
    assert!(saida_add1.contains("Credencial 'GitHub Pessoal' adicionada com ID 1."));

    // 3. Agrupar as demais etapas (show --revelar, 2ª credencial, alerta, search, edit, delete -y,
    // list e auditoria) em uma sessão do `shell` para não repetir Argon2id (256 MiB) desnecessariamente.
    let mut pty = cofre.spawn_pty(&["shell"]);
    esperar_texto(&mut pty, "Senha mestre:");
    pty.send_line(SENHA_PADRAO).unwrap();
    esperar_texto(&mut pty, "Cofre desbloqueado.");
    esperar_texto(&mut pty, "cofre> ");

    // 3a. `credencial show 1 --revelar` exibe a senha e a observação exatas
    pty.send_line("credencial show 1 --revelar").unwrap();
    let saida_show = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_show.contains(senha_compartilhada),
        "A senha revelada deve aparecer na saída:\n{saida_show}"
    );
    assert!(
        saida_show.contains(observacao_cred1),
        "A observação revelada deve aparecer na saída:\n{saida_show}"
    );
    assert!(saida_show.contains("GitHub Pessoal"));

    // 3b. Adicionar credencial #2 reutilizando a mesma senha para acionar SENHA_REUTILIZADA
    pty.send_line(
        "credencial add --servico-id 2 --nome \"GitLab Pessoal\" --identificador \"joao@gitlab.exemplo.com\"",
    )
    .unwrap();
    esperar_texto(&mut pty, "Senha da credencial:");
    pty.send_line(senha_compartilhada).unwrap();
    esperar_texto(&mut pty, "Confirme a senha:");
    pty.send_line(senha_compartilhada).unwrap();
    let saida_add2 = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_add2.contains("Credencial 'GitLab Pessoal' adicionada com ID 2."),
        "Saída inesperada ao criar credencial #2:\n{saida_add2}"
    );

    // 3c. `alerta scan` e `alerta list --tipo SENHA_REUTILIZADA`
    pty.send_line("alerta scan").unwrap();
    let saida_scan = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_scan.contains("Verificação de alertas de segurança concluída:"),
        "Saída inesperada no alerta scan:\n{saida_scan}"
    );

    pty.send_line("alerta list --tipo SENHA_REUTILIZADA")
        .unwrap();
    let saida_alertas = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_alertas.contains("SENHA_REUTILIZADA")
            && saida_alertas.contains("GitHub Pessoal")
            && saida_alertas.contains("GitLab Pessoal"),
        "Alerta de senha reutilizada ausente ou incompleto:\n{saida_alertas}"
    );

    // 3d. `credencial search`
    pty.send_line("credencial search GitLab").unwrap();
    let saida_search = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_search.contains("GitLab Pessoal")
            && saida_search.contains("1 resultado(s) para 'GitLab'"),
        "Saída inesperada no credencial search:\n{saida_search}"
    );

    // 3e. `credencial edit` alterando nome, senha e motivo
    let nova_senha_cred2 = "SenhaUnicaGitLab!9876";
    pty.send_line(
        "credencial edit 2 --nome \"GitLab Corporativo\" --senha --motivo \"Eliminar reutilizacao\"",
    )
    .unwrap();
    esperar_texto(&mut pty, "Nova senha da credencial:");
    pty.send_line(nova_senha_cred2).unwrap();
    esperar_texto(&mut pty, "Confirme a senha:");
    pty.send_line(nova_senha_cred2).unwrap();
    let saida_edit = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_edit.contains("Credencial #2 atualizada."),
        "Saída inesperada no credencial edit:\n{saida_edit}"
    );

    // 3f. `credencial delete 2 -y` e `credencial list`
    pty.send_line("credencial delete 2 -y").unwrap();
    let saida_del = esperar_texto(&mut pty, "cofre> ");
    assert!(
        saida_del.contains("Credencial 'GitLab Corporativo' excluída."),
        "Saída inesperada no credencial delete -y:\n{saida_del}"
    );

    pty.send_line("credencial list").unwrap();
    let saida_list = esperar_texto(&mut pty, "cofre> ");
    assert!(saida_list.contains("GitHub Pessoal"));
    assert!(!saida_list.contains("GitLab Corporativo"));
    assert!(saida_list.contains("Total: 1 credencial(is)"));

    // 3g. `auditoria list` deve registrar os eventos executados
    pty.send_line("auditoria list").unwrap();
    let saida_aud = esperar_texto(&mut pty, "cofre> ");
    for evento_esperado in [
        "INICIALIZACAO",
        "DESBLOQUEIO",
        "CRIACAO",
        "REVELACAO_SEGREDO",
        "VERIFICACAO_ALERTAS",
        "ALTERACAO",
        "EXCLUSAO",
    ] {
        assert!(
            saida_aud.contains(evento_esperado),
            "Evento '{evento_esperado}' ausente na auditoria:\n{saida_aud}"
        );
    }

    pty.send_line("sair").unwrap();
    let (_, cod_shell) = aguardar_saida(&mut pty);
    assert_eq!(cod_shell, 0);
}
