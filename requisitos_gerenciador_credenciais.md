# Documento de Requisitos — Gerenciador Pessoal de Credenciais via CLI

> Requisitos funcionais por tabela e especificação detalhada dos campos · **Versão revisada**

## Sumário

- [1. Objetivo](#1-objetivo)
- [2. Requisitos Funcionais](#2-requisitos-funcionais)
- [3. Estrutura Detalhada do Banco de Dados](#3-estrutura-detalhada-do-banco-de-dados)
- [4. Relacionamentos Principais](#4-relacionamentos-principais)
- [5. Login Automático](#5-login-automático)
- [6. Observações de Segurança dos Dados](#6-observações-de-segurança-dos-dados)
- [7. Requisitos Não Funcionais](#7-requisitos-não-funcionais)

---

## 1. Objetivo

Desenvolver um gerenciador pessoal de credenciais, utilizado por linha de comando (CLI), capaz de organizar contas, serviços, métodos de autenticação, dados de recuperação e configurações de login automático. O sistema deve armazenar os dados localmente e permitir que o usuário associe uma credencial a uma URL para abrir o navegador e tentar autenticar a conta quando necessário.

---

## 2. Requisitos Funcionais

Os requisitos abaixo são organizados por tabela, com foco nas operações funcionais que o sistema deverá disponibilizar.

|  Código  | Tabela / Módulo        | Requisito funcional                                                                |
| :------: | ---------------------- | ---------------------------------------------------------------------------------- |
| **RF01** | `usuario`              | Permitir cadastrar, consultar, editar e desativar o usuário do cofre.              |
| **RF02** | `categoria`            | Permitir cadastrar, consultar, editar e excluir categorias.                        |
| **RF03** | `servico`              | Permitir cadastrar, consultar, editar e excluir serviços.                          |
| **RF04** | `credencial`           | Permitir cadastrar, consultar, editar, desativar, excluir e pesquisar credenciais. |
| **RF05** | `url_servico`          | Permitir cadastrar, consultar, editar e excluir URLs de serviços.                  |
| **RF06** | `configuracao_login`   | Permitir cadastrar, consultar, editar e excluir configurações de login automático. |
| **RF07** | `sessao_navegador`     | Permitir registrar, consultar, atualizar e remover sessões do navegador.           |
| **RF08** | `metodo_autenticacao`  | Permitir cadastrar, consultar, editar e excluir métodos de autenticação.           |
| **RF09** | `email_recuperacao`    | Permitir cadastrar, consultar, editar e excluir e-mails de recuperação.            |
| **RF10** | `historico_credencial` | Permitir registrar e consultar o histórico de alterações de credenciais.           |
| **RF11** | `evento_auditoria`     | Permitir registrar e consultar eventos de auditoria do sistema.                    |
| **RF12** | `alerta_seguranca`     | Permitir registrar, consultar, resolver e excluir alertas de segurança.            |
| **RF13** | `dispositivo`          | Permitir cadastrar, consultar, editar, revogar e excluir dispositivos.             |
| **RF14** | `backup`               | Permitir criar, listar, verificar, restaurar e excluir backups.                    |
| **RF15** | `preferencia`          | Permitir cadastrar, consultar, editar e excluir preferências do sistema.           |
| **RF16** | _login automático_     | Permitir realizar login automático pela CLI.                                       |

---

## 3. Estrutura Detalhada do Banco de Dados

A modelagem proposta contém **15 tabelas** e **136 campos**. Para cada campo são informados o tipo sugerido, a obrigatoriedade, chaves/relacionamentos, valor padrão e finalidade. Os tipos foram pensados para **SQLite com SQLAlchemy**.

**Convenções**

| Sigla                  | Significado                                        |
| ---------------------- | -------------------------------------------------- |
| PK                     | Chave primária                                     |
| FK                     | Chave estrangeira                                  |
| BLOB                   | Dado binário, especialmente conteúdo criptografado |
| NULL                   | Campo opcional                                     |
| CURRENT_TIMESTAMP      | Data e hora atual                                  |
| ✅ / — (coluna Obrig.) | Campo obrigatório / opcional                       |

### Visão geral das tabelas

|  #   | Tabela                                                     | Finalidade                                                                                                                  | Campos |
| :--: | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | :----: |
| 3.1  | [`usuario`](#31-tabela-usuario)                            | Armazena os dados do proprietário local do cofre e os parâmetros necessários para validar/desbloquear o cofre.              |   9    |
| 3.2  | [`categoria`](#32-tabela-categoria)                        | Organiza os serviços cadastrados em grupos compreensíveis para o usuário.                                                   |   6    |
| 3.3  | [`servico`](#33-tabela-servico)                            | Representa o site, aplicativo ou sistema no qual o usuário possui uma conta.                                                |   9    |
| 3.4  | [`credencial`](#34-tabela-credencial)                      | Armazena os dados de autenticação de uma conta vinculada a um serviço.                                                      |   14   |
| 3.5  | [`url_servico`](#35-tabela-url_servico)                    | Mantém as diferentes URLs relevantes de um serviço, como login, recuperação e página principal.                             |   8    |
| 3.6  | [`configuracao_login`](#36-tabela-configuracao_login)      | Armazena as informações necessárias para o navegador localizar os elementos da página e realizar o preenchimento assistido. |   13   |
| 3.7  | [`sessao_navegador`](#37-tabela-sessao_navegador)          | Registra metadados sobre sessões persistentes do navegador, permitindo reaproveitar uma autenticação existente.             |   10   |
| 3.8  | [`metodo_autenticacao`](#38-tabela-metodo_autenticacao)    | Registra os mecanismos de autenticação disponíveis para uma credencial.                                                     |   8    |
| 3.9  | [`email_recuperacao`](#39-tabela-email_recuperacao)        | Mantém os e-mails utilizados pelos serviços para recuperação de uma credencial.                                             |   9    |
| 3.10 | [`historico_credencial`](#310-tabela-historico_credencial) | Registra alterações relevantes realizadas em uma credencial para consulta histórica.                                        |   7    |
| 3.11 | [`evento_auditoria`](#311-tabela-evento_auditoria)         | Registra ações importantes realizadas no programa, sem registrar segredos.                                                  |   8    |
| 3.12 | [`alerta_seguranca`](#312-tabela-alerta_seguranca)         | Registra problemas ou recomendações de segurança detectados pelo sistema.                                                   |   9    |
| 3.13 | [`dispositivo`](#313-tabela-dispositivo)                   | Representa os computadores nos quais o cofre foi utilizado.                                                                 |   9    |
| 3.14 | [`backup`](#314-tabela-backup)                             | Registra metadados dos backups criptografados gerados pelo programa.                                                        |   10   |
| 3.15 | [`preferencia`](#315-tabela-preferencia)                   | Armazena opções de funcionamento configuráveis pelo usuário.                                                                |   7    |

### 3.1 Tabela usuario

Armazena os dados do proprietário local do cofre e os parâmetros necessários para validar/desbloquear o cofre.

| Campo                | Tipo        | Obrig. | Chave / relação    | Padrão              | Descrição / restrições                                                          |
| -------------------- | ----------- | :----: | ------------------ | ------------------- | ------------------------------------------------------------------------------- |
| `id`                 | `INTEGER`   |   ✅   | PK, AUTOINCREMENT  | —                   | Identificador interno do usuário.                                               |
| `nome`               | `TEXT(100)` |   ✅   | —                  | —                   | Nome do proprietário do cofre.                                                  |
| `verificador_mestre` | `BLOB`      |   ✅   | Dado criptográfico | —                   | Verificador derivado da senha mestre. A senha mestre em si nunca é armazenada.  |
| `salt_kdf`           | `BLOB`      |   ✅   | Dado criptográfico | —                   | Salt aleatório utilizado na derivação da chave com Argon2id.                    |
| `parametros_kdf`     | `TEXT`      |   ✅   | JSON/configuração  | —                   | Parâmetros usados na derivação de chave, como memória, iterações e paralelismo. |
| `criado_em`          | `DATETIME`  |   ✅   | —                  | `CURRENT_TIMESTAMP` | Data e hora de criação do perfil local.                                         |
| `atualizado_em`      | `DATETIME`  |   ✅   | —                  | `CURRENT_TIMESTAMP` | Data e hora da última alteração dos dados do usuário.                           |
| `ultimo_acesso_em`   | `DATETIME`  |   —    | —                  | `NULL`              | Data e hora do último desbloqueio bem-sucedido do cofre.                        |
| `ativo`              | `BOOLEAN`   |   ✅   | CHECK (0/1)        | `1`                 | Indica se o perfil está ativo.                                                  |

> **Regras adicionais:** para a primeira versão, o sistema pode possuir apenas um registro ativo nesta tabela.

### 3.2 Tabela categoria

Organiza os serviços cadastrados em grupos compreensíveis para o usuário.

| Campo           | Tipo        | Obrig. | Chave / relação   | Padrão              | Descrição / restrições                                            |
| --------------- | ----------- | :----: | ----------------- | ------------------- | ----------------------------------------------------------------- |
| `id`            | `INTEGER`   |   ✅   | PK, AUTOINCREMENT | —                   | Identificador da categoria.                                       |
| `nome`          | `TEXT(60)`  |   ✅   | UNIQUE            | —                   | Nome da categoria, por exemplo: Streaming, Bancos, Redes Sociais. |
| `descricao`     | `TEXT(255)` |   —    | —                 | `NULL`              | Descrição opcional da categoria.                                  |
| `criado_em`     | `DATETIME`  |   ✅   | —                 | `CURRENT_TIMESTAMP` | Data e hora do cadastro.                                          |
| `atualizado_em` | `DATETIME`  |   ✅   | —                 | `CURRENT_TIMESTAMP` | Data e hora da última alteração.                                  |
| `ativa`         | `BOOLEAN`   |   ✅   | CHECK (0/1)       | `1`                 | Permite desativar uma categoria sem excluir seu histórico.        |

> **Regras adicionais:** O nome deve ser único para evitar categorias duplicadas.

### 3.3 Tabela servico

Representa o site, aplicativo ou sistema no qual o usuário possui uma conta.

| Campo               | Tipo         | Obrig. | Chave / relação     | Padrão              | Descrição / restrições                                                                 |
| ------------------- | ------------ | :----: | ------------------- | ------------------- | -------------------------------------------------------------------------------------- |
| `id`                | `INTEGER`    |   ✅   | PK, AUTOINCREMENT   | —                   | Identificador do serviço.                                                              |
| `categoria_id`      | `INTEGER`    |   —    | FK → `categoria.id` | `NULL`              | Categoria à qual o serviço pertence.                                                   |
| `nome`              | `TEXT(100)`  |   ✅   | INDEX recomendado   | —                   | Nome do serviço, por exemplo: Netflix, GitHub, Gov.br.                                 |
| `dominio_principal` | `TEXT(255)`  |   ✅   | UNIQUE recomendado  | —                   | Domínio oficial usado para validação antes do preenchimento automático de credenciais. |
| `url_principal`     | `TEXT(2048)` |   —    | —                   | `NULL`              | URL principal do serviço.                                                              |
| `descricao`         | `TEXT(500)`  |   —    | —                   | `NULL`              | Observação geral sobre o serviço.                                                      |
| `criado_em`         | `DATETIME`   |   ✅   | —                   | `CURRENT_TIMESTAMP` | Data do cadastro.                                                                      |
| `atualizado_em`     | `DATETIME`   |   ✅   | —                   | `CURRENT_TIMESTAMP` | Data da última alteração.                                                              |
| `ativo`             | `BOOLEAN`    |   ✅   | CHECK (0/1)         | `1`                 | Indica se o serviço continua ativo no cofre.                                           |

> **Regras adicionais:** O domínio principal é usado como referência de segurança para impedir preenchimento automático em domínios não cadastrados.

### 3.4 Tabela credencial

Armazena os dados de autenticação de uma conta vinculada a um serviço.

| Campo                      | Tipo        | Obrig. | Chave / relação   | Padrão              | Descrição / restrições                                                       |
| -------------------------- | ----------- | :----: | ----------------- | ------------------- | ---------------------------------------------------------------------------- |
| `id`                       | `INTEGER`   |   ✅   | PK, AUTOINCREMENT | —                   | Identificador da credencial.                                                 |
| `usuario_id`               | `INTEGER`   |   ✅   | FK → `usuario.id` | —                   | Proprietário da credencial.                                                  |
| `servico_id`               | `INTEGER`   |   ✅   | FK → `servico.id` | —                   | Serviço ao qual a conta pertence.                                            |
| `nome_exibicao`            | `TEXT(100)` |   ✅   | —                 | —                   | Nome amigável da conta, como “Netflix pessoal”.                              |
| `identificador`            | `TEXT(320)` |   ✅   | —                 | —                   | Login, nome de usuário, e-mail, CPF ou outro identificador usado no serviço. |
| `segredo_criptografado`    | `BLOB`      |   ✅   | Conteúdo cifrado  | —                   | Senha ou segredo criptografado por algoritmo autenticado.                    |
| `nonce`                    | `BLOB`      |   ✅   | Criptografia      | —                   | Nonce/IV aleatório usado para criptografar o segredo.                        |
| `observacao_criptografada` | `BLOB`      |   —    | Conteúdo cifrado  | `NULL`              | Notas privadas opcionais sobre a conta.                                      |
| `observacao_nonce`         | `BLOB`      |   —    | Criptografia      | `NULL`              | Nonce/IV da observação, quando houver.                                       |
| `favorita`                 | `BOOLEAN`   |   ✅   | CHECK (0/1)       | `0`                 | Indica se a credencial está marcada como favorita.                           |
| `criada_em`                | `DATETIME`  |   ✅   | —                 | `CURRENT_TIMESTAMP` | Data do cadastro.                                                            |
| `alterada_em`              | `DATETIME`  |   ✅   | —                 | `CURRENT_TIMESTAMP` | Data da última alteração.                                                    |
| `ultimo_uso_em`            | `DATETIME`  |   —    | —                 | `NULL`              | Data do último uso ou abertura da credencial.                                |
| `ativa`                    | `BOOLEAN`   |   ✅   | CHECK (0/1)       | `1`                 | Indica se a credencial está ativa.                                           |

> **Regras adicionais:** O campo segredo_criptografado nunca deve armazenar senha em texto puro. Uma restrição UNIQUE(servico_id, identificador) pode ser aplicada se o projeto decidir impedir o cadastro duplicado da mesma conta no mesmo serviço.

### 3.5 Tabela url_servico

Mantém as diferentes URLs relevantes de um serviço, como login, recuperação e página principal.

| Campo        | Tipo         | Obrig. | Chave / relação   | Padrão              | Descrição / restrições                                            |
| ------------ | ------------ | :----: | ----------------- | ------------------- | ----------------------------------------------------------------- |
| `id`         | `INTEGER`    |   ✅   | PK, AUTOINCREMENT | —                   | Identificador da URL.                                             |
| `servico_id` | `INTEGER`    |   ✅   | FK → `servico.id` | —                   | Serviço proprietário da URL.                                      |
| `url`        | `TEXT(2048)` |   ✅   | —                 | —                   | Endereço completo.                                                |
| `tipo`       | `TEXT(20)`   |   ✅   | CHECK/ENUM lógico | `LOGIN`             | Classificação: PRINCIPAL, LOGIN, RECUPERACAO, CADASTRO ou LOGOUT. |
| `descricao`  | `TEXT(255)`  |   —    | —                 | `NULL`              | Descrição opcional da finalidade da URL.                          |
| `padrao`     | `BOOLEAN`    |   ✅   | CHECK (0/1)       | `0`                 | Indica se é a URL preferencial daquele tipo.                      |
| `criado_em`  | `DATETIME`   |   ✅   | —                 | `CURRENT_TIMESTAMP` | Data do cadastro.                                                 |
| `ativa`      | `BOOLEAN`    |   ✅   | CHECK (0/1)       | `1`                 | Indica se a URL ainda deve ser utilizada.                         |

> **Regras adicionais:** Recomenda-se UNIQUE(servico_id, url).

### 3.6 Tabela configuracao_login

Armazena as informações necessárias para o navegador localizar os elementos da página e realizar o preenchimento assistido.

| Campo                 | Tipo         | Obrig. | Chave / relação       | Padrão              | Descrição / restrições                                                                 |
| --------------------- | ------------ | :----: | --------------------- | ------------------- | -------------------------------------------------------------------------------------- |
| `id`                  | `INTEGER`    |   ✅   | PK, AUTOINCREMENT     | —                   | Identificador da configuração.                                                         |
| `credencial_id`       | `INTEGER`    |   ✅   | FK → `credencial.id`  | —                   | Credencial que será utilizada no login.                                                |
| `url_servico_id`      | `INTEGER`    |   ✅   | FK → `url_servico.id` | —                   | URL de login usada por esta configuração.                                              |
| `seletor_usuario`     | `TEXT(500)`  |   —    | Seletor CSS/locator   | `NULL`              | Seletor explícito do campo de usuário quando a detecção automática não for suficiente. |
| `seletor_senha`       | `TEXT(500)`  |   —    | Seletor CSS/locator   | `NULL`              | Seletor explícito do campo de senha.                                                   |
| `seletor_botao`       | `TEXT(500)`  |   —    | Seletor CSS/locator   | `NULL`              | Seletor do botão de autenticação.                                                      |
| `url_sucesso`         | `TEXT(2048)` |   —    | —                     | `NULL`              | URL ou padrão esperado após autenticação bem-sucedida.                                 |
| `envio_automatico`    | `BOOLEAN`    |   ✅   | CHECK (0/1)           | `1`                 | Define se o sistema pode enviar o formulário após preencher os campos.                 |
| `timeout_segundos`    | `INTEGER`    |   ✅   | CHECK > 0             | `30`                | Tempo máximo para aguardar elementos e navegação.                                      |
| `ultima_validacao_em` | `DATETIME`   |   —    | —                     | `NULL`              | Data em que a configuração foi testada pela última vez.                                |
| `criado_em`           | `DATETIME`   |   ✅   | —                     | `CURRENT_TIMESTAMP` | Data do cadastro.                                                                      |
| `atualizado_em`       | `DATETIME`   |   ✅   | —                     | `CURRENT_TIMESTAMP` | Data da última alteração.                                                              |
| `ativa`               | `BOOLEAN`    |   ✅   | CHECK (0/1)           | `1`                 | Indica se a automação está habilitada.                                                 |

> **Regras adicionais:** Antes de preencher qualquer segredo, o domínio carregado no navegador deve ser conferido com o domínio cadastrado no serviço. CAPTCHA e etapas adicionais não suportadas devem interromper o fluxo automático e devolver o controle ao usuário.

### 3.7 Tabela sessao_navegador

Registra metadados sobre sessões persistentes do navegador, permitindo reaproveitar uma autenticação existente.

| Campo              | Tipo         | Obrig. | Chave / relação       | Padrão              | Descrição / restrições                                  |
| ------------------ | ------------ | :----: | --------------------- | ------------------- | ------------------------------------------------------- |
| `id`               | `INTEGER`    |   ✅   | PK, AUTOINCREMENT     | —                   | Identificador da sessão.                                |
| `credencial_id`    | `INTEGER`    |   ✅   | FK → `credencial.id`  | —                   | Credencial associada à sessão.                          |
| `dispositivo_id`   | `INTEGER`    |   —    | FK → `dispositivo.id` | `NULL`              | Dispositivo no qual a sessão foi criada.                |
| `navegador`        | `TEXT(40)`   |   ✅   | —                     | —                   | Navegador utilizado, por exemplo Firefox ou Chromium.   |
| `perfil_nome`      | `TEXT(100)`  |   —    | —                     | `NULL`              | Nome lógico do perfil do navegador.                     |
| `diretorio_perfil` | `TEXT(1024)` |   —    | —                     | `NULL`              | Caminho do perfil persistente gerenciado pelo programa. |
| `iniciada_em`      | `DATETIME`   |   ✅   | —                     | `CURRENT_TIMESTAMP` | Data de criação do registro da sessão.                  |
| `ultimo_uso_em`    | `DATETIME`   |   —    | —                     | `NULL`              | Último uso conhecido da sessão.                         |
| `expira_em`        | `DATETIME`   |   —    | —                     | `NULL`              | Validade conhecida, quando disponível.                  |
| `ativa`            | `BOOLEAN`    |   ✅   | CHECK (0/1)           | `1`                 | Indica se a sessão ainda deve ser tentada.              |

> **Regras adicionais:** A tabela deve guardar metadados e referência ao perfil. Cookies e tokens de sessão não devem ser gravados em texto puro no banco.

### 3.8 Tabela metodo_autenticacao

Registra os mecanismos de autenticação disponíveis para uma credencial.

| Campo            | Tipo        | Obrig. | Chave / relação      | Padrão              | Descrição / restrições                                           |
| ---------------- | ----------- | :----: | -------------------- | ------------------- | ---------------------------------------------------------------- |
| `id`             | `INTEGER`   |   ✅   | PK, AUTOINCREMENT    | —                   | Identificador do método.                                         |
| `credencial_id`  | `INTEGER`   |   ✅   | FK → `credencial.id` | —                   | Credencial protegida pelo método.                                |
| `tipo`           | `TEXT(30)`  |   ✅   | CHECK/ENUM lógico    | `SENHA`             | Tipo: SENHA, TOTP, SMS, EMAIL, PASSKEY, BIOMETRIA ou APLICATIVO. |
| `descricao`      | `TEXT(255)` |   —    | —                    | `NULL`              | Informação de apoio, sem armazenar segredo em texto puro.        |
| `principal`      | `BOOLEAN`   |   ✅   | CHECK (0/1)          | `0`                 | Indica o método principal de autenticação.                       |
| `habilitado`     | `BOOLEAN`   |   ✅   | CHECK (0/1)          | `1`                 | Indica se o método está ativo.                                   |
| `configurado_em` | `DATETIME`  |   —    | —                    | `NULL`              | Data aproximada de configuração do método.                       |
| `atualizado_em`  | `DATETIME`  |   ✅   | —                    | `CURRENT_TIMESTAMP` | Data da última alteração.                                        |

> **Regras adicionais:** Uma credencial pode possuir vários métodos de autenticação.

### 3.9 Tabela email_recuperacao

Mantém os e-mails utilizados pelos serviços para recuperação de uma credencial.

| Campo                 | Tipo       | Obrig. | Chave / relação      | Padrão              | Descrição / restrições                                             |
| --------------------- | ---------- | :----: | -------------------- | ------------------- | ------------------------------------------------------------------ |
| `id`                  | `INTEGER`  |   ✅   | PK, AUTOINCREMENT    | —                   | Identificador do e-mail de recuperação.                            |
| `credencial_id`       | `INTEGER`  |   ✅   | FK → `credencial.id` | —                   | Credencial que utiliza o e-mail.                                   |
| `email_criptografado` | `BLOB`     |   ✅   | Conteúdo cifrado     | —                   | Endereço de e-mail criptografado.                                  |
| `nonce`               | `BLOB`     |   ✅   | Criptografia         | —                   | Nonce/IV da criptografia.                                          |
| `principal`           | `BOOLEAN`  |   ✅   | CHECK (0/1)          | `0`                 | Indica se é o principal e-mail de recuperação.                     |
| `verificado`          | `BOOLEAN`  |   ✅   | CHECK (0/1)          | `0`                 | Indica se o usuário confirmou que o endereço ainda está acessível. |
| `verificado_em`       | `DATETIME` |   —    | —                    | `NULL`              | Data da última confirmação.                                        |
| `criado_em`           | `DATETIME` |   ✅   | —                    | `CURRENT_TIMESTAMP` | Data do cadastro.                                                  |
| `ativo`               | `BOOLEAN`  |   ✅   | CHECK (0/1)          | `1`                 | Indica se ainda é utilizado.                                       |

### 3.10 Tabela historico_credencial

Registra alterações relevantes realizadas em uma credencial para consulta histórica.

| Campo                          | Tipo        | Obrig. | Chave / relação      | Padrão              | Descrição / restrições                                             |
| ------------------------------ | ----------- | :----: | -------------------- | ------------------- | ------------------------------------------------------------------ |
| `id`                           | `INTEGER`   |   ✅   | PK, AUTOINCREMENT    | —                   | Identificador do histórico.                                        |
| `credencial_id`                | `INTEGER`   |   ✅   | FK → `credencial.id` | —                   | Credencial alterada.                                               |
| `tipo_alteracao`               | `TEXT(40)`  |   ✅   | CHECK/ENUM lógico    | —                   | Exemplo: SENHA, IDENTIFICADOR, OBSERVACAO, ATIVACAO.               |
| `valor_anterior_criptografado` | `BLOB`      |   —    | Conteúdo cifrado     | `NULL`              | Valor anterior quando houver necessidade de recuperação histórica. |
| `nonce`                        | `BLOB`      |   —    | Criptografia         | `NULL`              | Nonce/IV do valor histórico criptografado.                         |
| `motivo`                       | `TEXT(255)` |   —    | —                    | `NULL`              | Motivo informado para a alteração.                                 |
| `alterado_em`                  | `DATETIME`  |   ✅   | —                    | `CURRENT_TIMESTAMP` | Data e hora da alteração.                                          |

> **Regras adicionais:** A retenção de valores antigos deve ser opcional e configurável, pois aumenta a quantidade de segredos armazenados no cofre.

### 3.11 Tabela evento_auditoria

Registra ações importantes realizadas no programa, sem registrar segredos.

| Campo            | Tipo        | Obrig. | Chave / relação       | Padrão              | Descrição / restrições                                                 |
| ---------------- | ----------- | :----: | --------------------- | ------------------- | ---------------------------------------------------------------------- |
| `id`             | `INTEGER`   |   ✅   | PK, AUTOINCREMENT     | —                   | Identificador do evento.                                               |
| `usuario_id`     | `INTEGER`   |   ✅   | FK → `usuario.id`     | —                   | Usuário responsável pelo evento.                                       |
| `credencial_id`  | `INTEGER`   |   —    | FK → `credencial.id`  | `NULL`              | Credencial relacionada, quando houver.                                 |
| `dispositivo_id` | `INTEGER`   |   —    | FK → `dispositivo.id` | `NULL`              | Dispositivo relacionado ao evento.                                     |
| `tipo_evento`    | `TEXT(50)`  |   ✅   | INDEX recomendado     | —                   | Exemplo: LOGIN_AUTOMATICO, COPIA_SEGREDO, ALTERACAO, EXCLUSAO, BACKUP. |
| `resultado`      | `TEXT(20)`  |   ✅   | CHECK/ENUM lógico     | `SUCESSO`           | Resultado: SUCESSO, FALHA, CANCELADO ou PARCIAL.                       |
| `descricao`      | `TEXT(500)` |   —    | —                     | `NULL`              | Detalhe do evento sem incluir senha, código, token ou segredo.         |
| `ocorrido_em`    | `DATETIME`  |   ✅   | INDEX recomendado     | `CURRENT_TIMESTAMP` | Data e hora do evento.                                                 |

> **Regras adicionais:** Logs de auditoria não devem armazenar dados secretos nem conteúdo completo do clipboard.

### 3.12 Tabela alerta_seguranca

Registra problemas ou recomendações de segurança detectados pelo sistema.

| Campo           | Tipo        | Obrig. | Chave / relação      | Padrão              | Descrição / restrições                                                               |
| --------------- | ----------- | :----: | -------------------- | ------------------- | ------------------------------------------------------------------------------------ |
| `id`            | `INTEGER`   |   ✅   | PK, AUTOINCREMENT    | —                   | Identificador do alerta.                                                             |
| `credencial_id` | `INTEGER`   |   —    | FK → `credencial.id` | `NULL`              | Credencial relacionada; pode ser nulo para alertas gerais.                           |
| `tipo`          | `TEXT(50)`  |   ✅   | INDEX recomendado    | —                   | Tipo do alerta, por exemplo SENHA_REUTILIZADA, SEM_2FA ou RECUPERACAO_DESATUALIZADA. |
| `nivel`         | `TEXT(10)`  |   ✅   | CHECK/ENUM lógico    | `BAIXO`             | Nível: BAIXO, MEDIO, ALTO ou CRITICO.                                                |
| `titulo`        | `TEXT(120)` |   ✅   | —                    | —                   | Título curto exibido ao usuário.                                                     |
| `mensagem`      | `TEXT(500)` |   ✅   | —                    | —                   | Explicação do problema ou recomendação.                                              |
| `criado_em`     | `DATETIME`  |   ✅   | —                    | `CURRENT_TIMESTAMP` | Data da criação do alerta.                                                           |
| `resolvido`     | `BOOLEAN`   |   ✅   | CHECK (0/1)          | `0`                 | Indica se o problema foi resolvido ou descartado.                                    |
| `resolvido_em`  | `DATETIME`  |   —    | —                    | `NULL`              | Data de resolução.                                                                   |

### 3.13 Tabela dispositivo

Representa os computadores nos quais o cofre foi utilizado.

| Campo                 | Tipo        | Obrig. | Chave / relação    | Padrão              | Descrição / restrições                                                              |
| --------------------- | ----------- | :----: | ------------------ | ------------------- | ----------------------------------------------------------------------------------- |
| `id`                  | `INTEGER`   |   ✅   | PK, AUTOINCREMENT  | —                   | Identificador do dispositivo.                                                       |
| `usuario_id`          | `INTEGER`   |   ✅   | FK → `usuario.id`  | —                   | Proprietário do dispositivo.                                                        |
| `nome`                | `TEXT(100)` |   ✅   | —                  | —                   | Nome amigável, como “Notebook pessoal”.                                             |
| `sistema_operacional` | `TEXT(100)` |   —    | —                  | `NULL`              | Sistema operacional e, opcionalmente, versão.                                       |
| `fingerprint_hash`    | `TEXT(128)` |   —    | UNIQUE recomendado | `NULL`              | Hash de um identificador local; evita armazenar identificadores brutos do hardware. |
| `confiavel`           | `BOOLEAN`   |   ✅   | CHECK (0/1)        | `0`                 | Indica se foi marcado como dispositivo confiável.                                   |
| `primeiro_acesso_em`  | `DATETIME`  |   ✅   | —                  | `CURRENT_TIMESTAMP` | Primeiro uso registrado.                                                            |
| `ultimo_acesso_em`    | `DATETIME`  |   —    | —                  | `NULL`              | Último uso registrado.                                                              |
| `ativo`               | `BOOLEAN`   |   ✅   | CHECK (0/1)        | `1`                 | Permite revogar o dispositivo sem excluir o histórico.                              |

### 3.14 Tabela backup

Registra metadados dos backups criptografados gerados pelo programa.

| Campo                   | Tipo         | Obrig. | Chave / relação   | Padrão              | Descrição / restrições                                      |
| ----------------------- | ------------ | :----: | ----------------- | ------------------- | ----------------------------------------------------------- |
| `id`                    | `INTEGER`    |   ✅   | PK, AUTOINCREMENT | —                   | Identificador do backup.                                    |
| `usuario_id`            | `INTEGER`    |   ✅   | FK → `usuario.id` | —                   | Usuário proprietário do backup.                             |
| `nome_arquivo`          | `TEXT(255)`  |   ✅   | —                 | —                   | Nome do arquivo de backup.                                  |
| `caminho_arquivo`       | `TEXT(1024)` |   ✅   | —                 | —                   | Local em que o backup foi gravado.                          |
| `hash_integridade`      | `TEXT(128)`  |   ✅   | —                 | —                   | Hash usado para detectar corrupção ou alteração do arquivo. |
| `tamanho_bytes`         | `INTEGER`    |   ✅   | CHECK >= 0        | `0`                 | Tamanho do arquivo.                                         |
| `versao_formato`        | `TEXT(20)`   |   ✅   | —                 | `1`                 | Versão do formato de backup para compatibilidade futura.    |
| `criado_em`             | `DATETIME`   |   ✅   | —                 | `CURRENT_TIMESTAMP` | Data de criação.                                            |
| `ultima_restauracao_em` | `DATETIME`   |   —    | —                 | `NULL`              | Última vez em que esse backup foi restaurado.               |
| `valido`                | `BOOLEAN`    |   ✅   | CHECK (0/1)       | `1`                 | Resultado da última verificação de integridade.             |

> **Regras adicionais:** O arquivo de backup deve ser criptografado; a tabela contém apenas seus metadados.

### 3.15 Tabela preferencia

Armazena opções de funcionamento configuráveis pelo usuário.

| Campo           | Tipo         | Obrig. | Chave / relação           | Padrão              | Descrição / restrições                                                 |
| --------------- | ------------ | :----: | ------------------------- | ------------------- | ---------------------------------------------------------------------- |
| `id`            | `INTEGER`    |   ✅   | PK, AUTOINCREMENT         | —                   | Identificador da preferência.                                          |
| `usuario_id`    | `INTEGER`    |   ✅   | FK → `usuario.id`         | —                   | Usuário ao qual a preferência pertence.                                |
| `chave`         | `TEXT(100)`  |   ✅   | UNIQUE(usuario_id, chave) | —                   | Nome interno da preferência, como tempo_clipboard ou navegador_padrao. |
| `valor`         | `TEXT(1000)` |   ✅   | —                         | —                   | Valor serializado da preferência.                                      |
| `tipo_valor`    | `TEXT(20)`   |   ✅   | CHECK/ENUM lógico         | `TEXT`              | Tipo esperado: TEXT, INTEGER, BOOLEAN, JSON.                           |
| `descricao`     | `TEXT(255)`  |   —    | —                         | `NULL`              | Descrição para facilitar manutenção.                                   |
| `atualizado_em` | `DATETIME`   |   ✅   | —                         | `CURRENT_TIMESTAMP` | Data da última alteração.                                              |

> **Regras adicionais:** Preferências que contenham informação secreta não devem ser armazenadas em texto puro nesta tabela.

---

## 4. Relacionamentos Principais

| Relacionamento                        | Cardinalidade | Descrição                                                              |
| ------------------------------------- | :-----------: | ---------------------------------------------------------------------- |
| `usuario` → `credencial`              |      1:N      | Um usuário pode possuir várias credenciais.                            |
| `categoria` → `servico`               |      1:N      | Uma categoria pode agrupar vários serviços.                            |
| `servico` → `credencial`              |      1:N      | Um serviço pode possuir várias contas/credenciais.                     |
| `servico` → `url_servico`             |      1:N      | Um serviço pode ter várias URLs.                                       |
| `credencial` → `configuracao_login`   |      1:N      | Uma credencial pode possuir uma ou mais configurações de login.        |
| `credencial` → `sessao_navegador`     |      1:N      | Uma conta pode possuir sessões em diferentes navegadores/dispositivos. |
| `credencial` → `metodo_autenticacao`  |      1:N      | Uma conta pode utilizar senha e métodos adicionais de autenticação.    |
| `credencial` → `email_recuperacao`    |      1:N      | Uma conta pode possuir mais de um e-mail de recuperação.               |
| `credencial` → `historico_credencial` |      1:N      | Cada alteração relevante pode gerar um item no histórico.              |
| `credencial` → `alerta_seguranca`     |      1:N      | Uma conta pode ter vários alertas ao longo do tempo.                   |
| `usuario` → `dispositivo`             |      1:N      | Um usuário pode utilizar o cofre em mais de um dispositivo.            |
| `usuario` → `backup`                  |      1:N      | Um usuário pode gerar vários backups.                                  |
| `usuario` → `preferencia`             |      1:N      | Um usuário possui diversas preferências.                               |

---

## 5. Login Automático

**Tabelas envolvidas:** `credencial`, `servico`, `url_servico`, `configuracao_login` e `sessao_navegador`.

**Fluxo:**

1. Abrir a URL cadastrada.
2. Verificar se já existe uma sessão válida.
3. Quando necessário, preencher os campos de autenticação.
4. **Antes de inserir a senha**, conferir se o domínio carregado corresponde ao domínio cadastrado.
5. CAPTCHA, autenticação adicional não suportada ou confirmação externa devem ser concluídos **manualmente** pelo usuário.

---

## 6. Observações de Segurança dos Dados

- A senha mestre não deve ser armazenada em texto puro.
- Senhas, e-mails de recuperação e instruções privadas devem ser criptografados antes de serem persistidos.
- Logs e eventos de auditoria não devem conter senhas, tokens ou códigos secretos.
- Backups devem permanecer criptografados e possuir verificação de integridade.
- Sessões do navegador devem guardar apenas referências/metadados seguros; cookies ou tokens não devem ser persistidos em texto puro no banco.

---

## 7. Requisitos Não Funcionais

Os requisitos não funcionais definem critérios de segurança, privacidade, integridade, desempenho, comportamento da automação e características de manutenção e portabilidade do gerenciador de credenciais.

### Segurança e criptografia

|  Código   | Requisito                  | Descrição                                                                                                                                                                                                                               |
| :-------: | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **RNF01** | Segurança do armazenamento | Todos os dados sensíveis armazenados pelo sistema devem permanecer protegidos por criptografia, não sendo permitido o armazenamento de senhas de contas em texto puro.                                                                  |
| **RNF02** | Proteção da senha mestra   | A senha mestra utilizada para desbloquear o cofre não deve ser armazenada diretamente no banco de dados. O sistema deve utilizar um mecanismo de derivação de chave baseado em Argon2id, com salt aleatório.                            |
| **RNF03** | Hierarquia de chaves       | O sistema deve utilizar uma chave de dados (DEK) para proteger os dados sensíveis e uma chave derivada da senha mestra (KEK) para proteger a DEK. A alteração da senha mestra não deve exigir a recriptografia de todas as credenciais. |
| **RNF04** | Criptografia autenticada   | Os dados sensíveis devem ser protegidos por um algoritmo de criptografia autenticada, como AES-GCM ou XChaCha20-Poly1305, garantindo confidencialidade e integridade.                                                                   |

### Exposição de dados e acesso

|  Código   | Requisito                    | Descrição                                                                                                                                                                        |
| :-------: | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **RNF05** | Não exposição de credenciais | Senhas, chaves criptográficas, tokens e demais informações sensíveis não devem ser exibidos em mensagens de erro, logs, histórico de comandos ou argumentos da linha de comando. |
| **RNF06** | Entrada segura de senhas     | Quando uma senha for solicitada pelo sistema, sua entrada deverá ser ocultada no terminal, evitando sua exposição visual durante a digitação.                                    |
| **RNF07** | Bloqueio automático          | O sistema deve possuir mecanismo de bloqueio automático do cofre após determinado período de inatividade, exigindo novamente a senha mestra para acesso aos dados protegidos.    |

### Privacidade, integridade e auditoria

|  Código   | Requisito             | Descrição                                                                                                                                                                                                 |
| :-------: | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **RNF08** | Privacidade           | O sistema deve funcionar localmente e não deve enviar credenciais, senhas, histórico ou demais dados pessoais para serviços externos sem uma ação explicitamente solicitada pelo usuário.                 |
| **RNF09** | Integridade dos dados | As operações de gravação, alteração e exclusão de dados devem preservar a integridade referencial do banco de dados, utilizando transações quando necessário.                                             |
| **RNF10** | Backup seguro         | Os backups do banco de dados devem permanecer protegidos por criptografia, não sendo permitido que uma cópia de segurança exponha as credenciais armazenadas.                                             |
| **RNF11** | Auditoria             | O sistema deve registrar eventos relevantes de segurança e utilização, como desbloqueios, bloqueios, alterações de senha e operações administrativas, sem registrar os segredos envolvidos nas operações. |

### Automação web

|  Código   | Requisito                                     | Descrição                                                                                                                                                                                                                                          |
| :-------: | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **RNF12** | Segurança da automação web                    | Antes de realizar uma tentativa de login automático, o sistema deve validar o domínio ou origem previamente associada à credencial, evitando o envio de informações para endereços não autorizados.                                                |
| **RNF13** | Interrupção diante de mecanismos de segurança | A automação de login não deve tentar contornar CAPTCHA, autenticação multifator, passkeys ou outros mecanismos de segurança. Quando esses mecanismos forem identificados, o processo deverá ser interrompido ou transferido para interação manual. |

### Desempenho, portabilidade e manutenção

|  Código   | Requisito                  | Descrição                                                                                                                                                                                                                                             |
| :-------: | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **RNF14** | Desempenho                 | As operações locais de consulta, cadastro, alteração e exclusão de credenciais devem apresentar tempo de resposta adequado para utilização interativa no terminal, considerando um volume de milhares de credenciais.                                 |
| **RNF15** | Portabilidade e manutenção | O sistema deve ser desenvolvido de forma modular e preferencialmente compatível com os principais sistemas operacionais de desktop, permitindo a manutenção e evolução independente dos módulos de banco de dados, criptografia, CLI e automação web. |

### Observação de integração dos RNFs ao modelo

> Os requisitos não funcionais passam a complementar os requisitos funcionais e a modelagem existente. Em especial, RNF02 e RNF03 estabelecem uma arquitetura criptográfica com Argon2id, KEK e DEK; na implementação, os campos atualmente destinados aos parâmetros de derivação e aos dados criptográficos deverão ser adequados para armazenar, de forma segura, os metadados necessários à hierarquia de chaves. Essa adequação é uma decisão de implementação e não altera, por si só, os requisitos funcionais definidos neste documento.
