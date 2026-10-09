# 🔐 Cofre: gerenciador de credenciais via CLI

Gerenciador pessoal de credenciais em **Rust**, usado pela linha de comando, com armazenamento **local e criptografado**. Organiza contas, serviços, métodos de autenticação e dados de recuperação. Também está planejado o **login automático** no navegador.

> 🚧 Em desenvolvimento: já tem o núcleo criptográfico, o banco e os comandos básicos.

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
| `cofre-automacao` | Login automático via Chromium (CDP), *planejado* |
| `cofre-backup` | Backup cifrado com verificação de integridade, *planejado* |

## ⌨️ Uso

```bash
cargo build --release

cofre init --nome "Seu Nome"
cofre categoria add | list
cofre servico   add | list | search
cofre credencial add | list | show | search
```

## 📄 Documentação

- [Documento de requisitos](requisitos_gerenciador_credenciais.md)
- [Plano de implementação](plano_implementacao_rust.md)

## Licença

[MIT](LICENSE)
