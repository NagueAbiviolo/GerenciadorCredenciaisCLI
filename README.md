# 🔐 Cofre: gerenciador de credenciais via CLI

Gerenciador pessoal de credenciais em **Rust**, usado pela linha de comando, com armazenamento **local e criptografado**. Organiza contas, serviços, métodos de autenticação e dados de recuperação, e faz **login automático** no navegador.

## 🛡️ Segurança

- **Argon2id** para derivar a chave a partir da senha mestra
- **XChaCha20-Poly1305** (AEAD) para cifrar os dados, com hierarquia de chaves KEK/DEK
- **`secrecy` + `zeroize`**: segredos ficam encapsulados e a memória é zerada ao descartá-los
- A senha mestra é pedida em prompt oculto e nunca é passada como argumento de linha de comando
- SQLite em modo WAL com integridade referencial

## 🏗️ Arquitetura

Workspace Cargo dividido por responsabilidade:

| Crate | Responsabilidade |
|---|---|
| `cofre-cli` | Binário `cofre`: comandos (clap), prompts e saída formatada |
| `cofre-crypto` | KDF, chaves e criptografia autenticada |
| `cofre-db` | Conexão SQLite, modelos, repositórios e migrações |
| `cofre-services` | Regras de negócio do cofre |
| `cofre-automacao` | Login automático via Chromium (CDP) e validação de domínio (eTLD+1) |
| `cofre-backup` | Backup cifrado com verificação de integridade |

## ⌨️ Uso

```bash
cargo build --release

cofre init --nome "Seu Nome"
cofre shell                                             # modo interativo com bloqueio por inatividade
cofre senha-mestre
cofre categoria   add | list | edit | delete
cofre servico     add | list | search | edit | delete
cofre servico url add | list | edit | delete            # URLs de login, recuperação, cadastro...
cofre credencial  add | list | show | search | copy | edit | deactivate | activate | delete | historico
cofre credencial metodo add | list | edit | delete      # senha, TOTP, SMS, passkey...
cofre credencial email  add | list | edit | delete      # e-mails de recuperação (cifrados)
cofre preferencia list | get | set | reset              # tempo_clipboard, timeout_inatividade...
cofre auditoria   list                                  # eventos de auditoria do cofre
cofre alerta      scan | list | resolve | delete        # alertas de segurança (senha reutilizada, sem 2FA, recuperação)
cofre backup      create | list | verify | restore | delete
cofre login config add | list | show | edit | delete     # seletores, URL de sucesso, envio automático
cofre login <credencial_id> [--config-id <id>]          # abre o navegador e preenche o login
```

Os backups (`.cbk`) são cifrados com XChaCha20-Poly1305 (DEK) e trazem no cabeçalho autenticado por AAD o material criptográfico de desbloqueio e hash de integridade BLAKE3, podendo ser restaurados apenas com a senha mestre vigente no momento do backup (mesmo que o `cofre.db` tenha sido perdido).

Os e-mails de recuperação são cifrados com a DEK e pedidos em prompt (não vão para o histórico do shell). Na listagem aparecem mascarados, e `--revelar` mostra o endereço completo.

`cofre credencial copy <id>` copia a senha para a área de transferência e a limpa após 20 s (ajustável com `--segundos`; Ctrl+C limpa na hora). No Windows, o conteúdo não vai para o histórico nem para a sincronização em nuvem da área de transferência.

O login automático abre um navegador baseado em Chromium (Chromium, Chrome, Edge ou Brave; outro executável pode ser indicado com a variável `COFRE_NAVEGADOR`) e preenche usuário e senha nos seletores configurados. Antes de preencher, confere se o domínio da página bate com o do serviço pelo eTLD+1, para não entregar a senha a um site parecido. Se encontrar CAPTCHA ou MFA, ele para e passa o controle para você.

## 🧪 Testes

```bash
cargo test --workspace
```

Além dos testes unitários de cada crate, `cofre-cli/tests/` tem testes de integração que executam o binário `cofre` num cofre temporário: inicialização, CRUD de credenciais, auditoria, alertas, backup e restauração e o modo shell. Os prompts de senha rodam num pseudo-terminal (`rexpect`), então esses testes só executam em Linux e macOS.

## 📄 Documentação

- [Documento de requisitos](requisitos_gerenciador_credenciais.md)
- [Plano de implementação](plano_implementacao_rust.md)
- [Diagrama de caso de uso](<GerenciadorCredenciais Caso de Uso.png>)
- [Diagrama de classes](<GerenciadorCredenciais Diagrama de Classes.png>) ([fonte PlantUML](diagrama_classes.puml))

## Licença

[MIT](LICENSE)
