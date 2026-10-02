# Plano de Implementação: Gerenciador Pessoal de Credenciais CLI (Rust)

Este documento detalha o plano de implementação passo a passo para o gerenciador de credenciais via linha de comando, baseado no [documento de requisitos](requisitos_gerenciador_credenciais.md) e nas decisões técnicas levantadas em análises anteriores. A linguagem escolhida é **Rust**, com foco em segurança, performance e robustez.

> **Contexto:** Em análise prévia (Claude Code, 25/09/2026), Rust ficou em **1º lugar** num ranking de segurança entre 8 linguagens para este projeto. O ponto fraco identificado é a automação web (sem Playwright oficial), mitigado pelo uso de `chromiumoxide` (CDP).

---

## 1. Stack Tecnológica

| Camada | Crate(s) | Justificativa |
|--------|----------|---------------|
| **CLI** | `clap` (feature `derive`) | Parseamento de comandos e subcomandos com validação em tempo de compilação. |
| **Prompt seguro** | `inquire` ou `dialoguer` | Captura de senhas ocultas (`Password`) e menus interativos. Senha **nunca** vem por argumento de linha de comando (RNF05). |
| **Terminal / tabelas** | `comfy-table` | Exibição formatada de credenciais, alertas e históricos. |
| **Banco de dados** | `rusqlite` + `refinery` | `rusqlite` oferece acesso direto e leve ao SQLite. `refinery` gerencia migrações de schema. Modo WAL e `PRAGMA foreign_keys=ON` obrigatórios. |
| **KDF** | `argon2` (RustCrypto) | Derivação de chaves com Argon2id. Parâmetros calibrados: ~256 MiB memória, 3 iterações, paralelismo 4, mirando 0,5–1s para desbloquear (RNF02). |
| **AEAD** | `chacha20poly1305` (XChaCha20-Poly1305) | Criptografia autenticada. Nonce de 192 bits elimina risco prático de colisão com nonces aleatórios (RNF04). |
| **Proteção em memória** | `secrecy` + `zeroize` | `secrecy::Secret<T>` encapsula chaves e senhas impedindo exposição acidental (ex: via `Debug`, `Display`). `zeroize` com `#[derive(Zeroize, ZeroizeOnDrop)]` sobrescreve a memória ao descartar. |
| **Bloqueio de memória** | `memsec` ou `region` | `mlock` nos buffers de chave para evitar que sejam paginados para swap/disco (RNF07). |
| **Automação web** | `chromiumoxide` | Controle do Chrome/Chromium via CDP. **Comunicação por pipe** (`--remote-debugging-pipe`), não por porta TCP — qualquer processo local poderia se conectar a uma porta aberta e ler a página com a senha preenchida. Limitação: suporta apenas navegadores Chromium. |
| **Automação web (alternativa)** | `thirtyfour` | WebDriver para Firefox via `geckodriver`. API mais verbosa, sem espera automática de elementos. |
| **Validação de domínio** | `url` + `psl` (Public Suffix List) | Validação por **eTLD+1** (não por prefixo de string). `netflix.com.evil.io` não passa como `netflix.com`. Verificar também a origem de **iframes** (RNF12). |
| **Clipboard** | `arboard` | Cópia de senhas com limpeza automática por timer. Marcar conteúdo para **não ir ao histórico** e à sincronização em nuvem do Windows. |
| **Hash de integridade** | `blake3` ou `sha2` | Verificação de integridade de backups. |
| **Erros** | `thiserror` (lib) + `anyhow` (binário) | Erros tipados nos módulos internos, ergonômicos no binário. **Nunca** incluir segredos em mensagens de erro. |
| **Geração aleatória** | `rand` + `getrandom` | Nonces, salts e DEK gerados com CSPRNG. |
| **Datas** | `chrono` | Manipulação de timestamps (`CURRENT_TIMESTAMP`). |
| **Logs** | `tracing` | Logs estruturados para auditoria. Filtrar qualquer campo sensível antes de emitir. |
| **Diretórios** | `directories` | Localizar pastas corretas de dados/config por SO (`%APPDATA%`, `~/.local/share/`). |
| **Auditoria de deps** | `cargo-deny`, `cargo-audit`, `cargo-vet` | Cada crate é código de terceiros rodando com acesso aos seus segredos. Manter dependências mínimas e auditadas. |

---

## 2. Arquitetura do Sistema

Workspace Cargo com crates separados para isolar responsabilidades:

```
cofre-credenciais/
├── Cargo.toml              # workspace
├── cofre-cli/              # Binário: clap, prompts, formatação de saída
├── cofre-crypto/           # Lib: KDF, KEK/DEK, AEAD com AAD, secrecy/zeroize
├── cofre-db/               # Lib: rusqlite, modelos, repositórios, migrations (refinery)
├── cofre-services/         # Lib: regras de negócio, auditoria, alertas, histórico
├── cofre-automacao/        # Lib: chromiumoxide/thirtyfour, validação eTLD+1, sessões
└── cofre-backup/           # Lib: exportação cifrada, verificação de integridade
```

### Princípios arquiteturais:
*   **`cofre-crypto` não depende de `cofre-db`** — é a camada mais interna e mais crítica.
*   **Segredos nunca saem de `cofre-crypto` em texto puro** exceto por tipos `secrecy::Secret<T>` que impedem exposição acidental.
*   **O binário (`cofre-cli`) orquestra** as chamadas entre os módulos.

---

## 3. Fases de Implementação

O projeto deve ser construído iterativamente, garantindo que segurança e banco de dados estejam sólidos antes das funcionalidades complexas.

### Fase 1: Fundação e Setup do Projeto
**Objetivo:** Estruturar o workspace, configurar CLI básica e preparar o banco de dados.

1.  Criar o workspace Cargo (`cargo new --name cofre-credenciais`).
2.  Criar os crates internos (`cofre-cli`, `cofre-crypto`, `cofre-db`, etc.).
3.  Configurar dependências iniciais no `Cargo.toml` de cada crate.
4.  Implementar o esqueleto CLI com `clap` (subcomandos: `init`, `unlock`, `credencial add|list|show|search`, `servico add|list`, `login`, `backup`, `config`).
5.  Configurar a conexão com o SQLite via `rusqlite` (modo WAL, `PRAGMA foreign_keys=ON`).
6.  Criar e executar as **migrações** com `refinery` (criar as 15 tabelas definidas nos requisitos).
7.  Configurar `cargo-deny` e `cargo-audit` no CI/workflow local.

### Fase 2: Módulo de Segurança (Criptografia)
**Objetivo:** Implementar o coração criptográfico do cofre (RNF01–RNF04).

1.  Implementar a derivação de chave (KDF) com **Argon2id**.
    *   Parâmetros padrão: **256 MiB memória, 3 iterações, paralelismo 4** (calibrar na máquina alvo para ~0,5–1s).
    *   Salvar parâmetros como JSON em `parametros_kdf`.
2.  Implementar a hierarquia de chaves **KEK/DEK** (RNF03):
    *   Senha mestre → Argon2id → **KEK**.
    *   KEK cifra/decifra a **DEK** (chave aleatória de 256 bits).
    *   DEK cifra/decifra todos os dados sensíveis.
    *   **Alterar a senha mestre recifra apenas a DEK**, sem tocar nas credenciais.
3.  Implementar rotinas de criptografia/descriptografia com **XChaCha20-Poly1305**.
    *   **Usar AAD (Additional Authenticated Data)** em toda operação AEAD: amarrar o texto cifrado ao seu contexto com uma string como `tabela|coluna|id|usuario_id`. Sem isso, um atacante com acesso ao banco poderia trocar o `segredo_criptografado` de uma linha pela de outra silenciosamente.
    *   Nonce de 192 bits gerado aleatoriamente (sem risco de colisão).
4.  Encapsular chaves em `secrecy::Secret<Vec<u8>>` e aplicar `#[derive(Zeroize, ZeroizeOnDrop)]`.
5.  Usar `mlock` (via `memsec`) nos buffers que guardam KEK e DEK em memória.
6.  **Desabilitar core/crash dumps** no processo (`setrlimit(RLIMIT_CORE, 0)` no Linux, equivalente no Windows) para evitar que chaves vazem em dumps.

### Fase 3: Gerenciamento de Usuário e Cofre
**Objetivo:** Permitir a inicialização e o desbloqueio do cofre.

1.  **Comando `init`**:
    *   Solicitar nova senha mestre via prompt seguro (oculto).
    *   Gerar salt aleatório, derivar KEK via Argon2id.
    *   Gerar DEK aleatória (256 bits), cifrar com KEK.
    *   Gerar verificador mestre (hash separado para validação sem expor a KEK).
    *   Salvar no banco (`usuario` com `verificador_mestre`, `salt_kdf`, `parametros_kdf`).
    *   Registrar o `dispositivo` atual automaticamente (fingerprint via hash).
2.  **Comando `unlock` / Modo shell interativo**:
    *   Solicitar senha mestre.
    *   Derivar KEK, validar contra o verificador.
    *   Descriptografar DEK e mantê-la em `Secret<Vec<u8>>` com `mlock` durante a sessão.
    *   **Timer de inatividade** (RNF07): zerar a DEK da memória após N minutos sem interação. Em modo shell interativo, o custo de startup é pago uma vez só.
    *   Atualizar `ultimo_acesso_em` no registro do usuário.

### Fase 4: CRUD de Credenciais e Serviços
**Objetivo:** Implementar as operações básicas (RF02 a RF05, RF08, RF09).

1.  Implementar gerenciamento de **Categorias** (`add`, `list`, `edit`, `delete`) e **Serviços** (`add`, `list`, `edit`, `delete`).
2.  Implementar gerenciamento de **Credenciais** (`add`, `list`, `show`, `search`, `edit`, `deactivate`, `delete`):
    *   No `add`, capturar senha via `inquire::Password`.
    *   Cifrar o segredo usando a DEK + AAD (contexto: `credencial|segredo_criptografado|{id}|{usuario_id}`) antes de inserir no banco.
    *   No `show`, descriptografar a senha e oferecer:
        *   Exibição breve no terminal (limpar após N segundos).
        *   Cópia para o clipboard via `arboard` com limpeza automática por timer (preferência `tempo_clipboard`). Marcar para excluir do histórico do Windows.
3.  Vincular URLs (`url_servico`) aos serviços.
4.  Implementar **Métodos de Autenticação** (`metodo_autenticacao`) e **E-mails de Recuperação** (`email_recuperacao`) — e-mails cifrados com DEK + AAD.

### Fase 5: Automação de Navegador (Login Automático)
**Objetivo:** Implementar o recurso de login automático (RF06, RF16 e Capítulo 5 dos Requisitos).

1.  Configurar a tabela `configuracao_login` para mapear os seletores CSS.
2.  Implementar o comando `login <credencial_id>`.
3.  Integrar `chromiumoxide` para:
    *   Lançar o navegador via **pipe** (`--remote-debugging-pipe`), **nunca por porta TCP** (`--remote-debugging-port`). Porta TCP permite que qualquer processo local se conecte e leia a página.
    *   Usar `user_data_dir` para perfil persistente (mapeia para `sessao_navegador.diretorio_perfil`). **Tratar o diretório do perfil como segredo** — guarda cookies de sessão (no Windows, protegidos por DPAPI, mas apenas amarrados ao usuário do SO, não à senha mestre).
    *   Abrir a URL cadastrada.
    *   **Validação de domínio por eTLD+1** (`url` + `psl`): antes de preencher qualquer campo, conferir que o domínio carregado (incluindo a **origem de iframes**) corresponde ao `dominio_principal` cadastrado no serviço.
    *   Preencher `seletor_usuario` e `seletor_senha`.
    *   Acionar `seletor_botao` se `envio_automatico` for verdadeiro.
    *   Verificar `url_sucesso` após submissão para confirmar autenticação.
4.  Detectar **CAPTCHA e MFA**: interromper o fluxo automático e devolver o controle ao usuário.
5.  Lidar com timeouts (`timeout_segundos`) e interrupções manuais.
6.  Registrar sessão em `sessao_navegador` e evento em `evento_auditoria`.

### Fase 6: Funcionalidades Avançadas e Auditoria
**Objetivo:** Implementar módulos auxiliares de segurança, histórico, backup e preferências (RF10–RF15).

1.  **Histórico de Credenciais** (RF10): Disparar inserções em `historico_credencial` em cada alteração relevante, cifrando valores antigos com AAD. A retenção de valores antigos é configurável (preferência).
2.  **Eventos de Auditoria** (RF11): Registrar em `evento_auditoria` cada ação importante (login automático, cópia de segredo, alteração, exclusão, backup). **Nunca** gravar senhas, tokens ou conteúdo do clipboard nos logs.
3.  **Alertas de Segurança** (RF12): Rotinas para detectar:
    *   Senhas reutilizadas (comparar ao descriptografar, ou usar hash cego dedicado).
    *   Credenciais sem 2FA (`SEM_2FA`).
    *   E-mails de recuperação desatualizados.
4.  **Backups** (RF14): Comando `backup create|list|verify|restore|delete`.
    *   Cópia do banco SQLite, cifrada com a DEK.
    *   Hash de integridade com `blake3`.
    *   Metadados em `backup` (caminho, tamanho, versão do formato).
5.  **Dispositivos** (RF13): Registrar `dispositivo` com fingerprint hash, SO, status de confiança.
6.  **Preferências** (RF15): Armazenar configurações em `preferencia` (ex: `tempo_clipboard`, `navegador_padrao`, `timeout_inatividade`). Preferências com informação secreta devem ser cifradas.

---

## 4. Considerações de Segurança

### Proteção em memória (vantagem do Rust)
*   `secrecy::Secret<T>` para encapsular DEK, KEK e senhas — impede `Debug`/`Display` acidentais.
*   `#[derive(Zeroize, ZeroizeOnDrop)]` para sobrescrita real da memória (Rust não tem GC que move objetos).
*   `mlock` via `memsec` para impedir que páginas com chaves vão para swap.
*   Desabilitar core/crash dumps no processo.

### AAD no AEAD (ponto crítico)
*   Todo dado cifrado deve incluir **Additional Authenticated Data** vinculando-o ao seu contexto (`tabela|coluna|id|usuario_id`).
*   Sem AAD, um atacante com acesso ao banco pode trocar o `segredo_criptografado` de uma credencial pela de outra — o ataque é silencioso e o sistema não detecta.

### Navegador e preenchimento automático
*   Navegador controlado por **pipe**, nunca por porta TCP.
*   Validação de domínio por **eTLD+1** (Public Suffix List), incluindo verificação da origem de iframes.
*   Diretório de perfil persistente tratado como segredo.
*   Interromper fluxo automático em CAPTCHA ou MFA não suportada.

### Clipboard
*   Limpar após o tempo configurado.
*   Marcar conteúdo para exclusão do histórico e sincronização em nuvem do Windows.

### SQL Injection
*   Uso de queries parametrizadas via `rusqlite` previne injeções de SQL.

### Gerenciamento de Erros
*   `thiserror` nos módulos internos, `anyhow` no binário.
*   **Nunca** incluir senhas, chaves ou tokens em mensagens de erro, pânico ou logs.

### Supply Chain
*   `cargo-deny`: bloquear licenças indesejadas e crates duplicados.
*   `cargo-audit`: verificar CVEs conhecidas.
*   `cargo-vet`: auditar crates de terceiros.
*   Manter o número de dependências no mínimo possível.

---

## 5. Cronograma Sugerido

| Semana | Entregas | Fase |
|--------|----------|------|
| **1** | Workspace Cargo, CLI com `clap`, SQLite + migrações das 15 tabelas, `cargo-deny`/`cargo-audit` | Fase 1 |
| **2** | Módulo criptográfico completo (Argon2id, XChaCha20-Poly1305 com AAD, KEK/DEK, secrecy/zeroize/mlock) | Fase 2 |
| **3** | Comandos `init` e `unlock`, modo shell interativo com timer de inatividade, registro de dispositivo | Fase 3 |
| **4** | CRUD completo (Categorias, Serviços, Credenciais, URLs, Métodos de Auth, E-mails de Recuperação), clipboard seguro | Fase 4 |
| **5** | Automação de navegador (`chromiumoxide` via pipe), validação eTLD+1, preenchimento assistido, detecção de CAPTCHA | Fase 5 |
| **6** | Histórico, Auditoria, Alertas de Segurança, Backups cifrados, Preferências | Fase 6 |
| **7** | Testes automatizados (unitários em crypto, integração em DB, e2e no CLI), documentação e refatoração | Polimento |
