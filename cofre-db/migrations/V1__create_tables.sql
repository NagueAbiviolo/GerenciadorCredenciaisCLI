-- Migração inicial: criação das 15 tabelas do Gerenciador de Credenciais.
-- Baseada no documento de requisitos v1.

-- ============================================================
-- 3.1 Tabela usuario
-- ============================================================
CREATE TABLE IF NOT EXISTS usuario (
    id                 INTEGER   PRIMARY KEY AUTOINCREMENT,
    nome               TEXT(100) NOT NULL,
    verificador_mestre BLOB      NOT NULL,
    salt_kdf           BLOB      NOT NULL,
    parametros_kdf     TEXT      NOT NULL,
    criado_em          DATETIME  NOT NULL DEFAULT (datetime('now')),
    atualizado_em      DATETIME  NOT NULL DEFAULT (datetime('now')),
    ultimo_acesso_em   DATETIME,
    ativo              BOOLEAN   NOT NULL DEFAULT 1 CHECK (ativo IN (0, 1)),
    -- Campos adicionais para a hierarquia KEK/DEK
    dek_criptografada  BLOB      NOT NULL,
    dek_nonce          BLOB      NOT NULL,
    verificador_salt   BLOB      NOT NULL
);

-- ============================================================
-- 3.2 Tabela categoria
-- ============================================================
CREATE TABLE IF NOT EXISTS categoria (
    id            INTEGER   PRIMARY KEY AUTOINCREMENT,
    nome          TEXT(60)  NOT NULL UNIQUE,
    descricao     TEXT(255),
    criado_em     DATETIME  NOT NULL DEFAULT (datetime('now')),
    atualizado_em DATETIME  NOT NULL DEFAULT (datetime('now')),
    ativa         BOOLEAN   NOT NULL DEFAULT 1 CHECK (ativa IN (0, 1))
);

-- ============================================================
-- 3.3 Tabela servico
-- ============================================================
CREATE TABLE IF NOT EXISTS servico (
    id                INTEGER    PRIMARY KEY AUTOINCREMENT,
    categoria_id      INTEGER    REFERENCES categoria(id) ON DELETE SET NULL,
    nome              TEXT(100)  NOT NULL,
    dominio_principal TEXT(255)  NOT NULL,
    url_principal     TEXT(2048),
    descricao         TEXT(500),
    criado_em         DATETIME   NOT NULL DEFAULT (datetime('now')),
    atualizado_em     DATETIME   NOT NULL DEFAULT (datetime('now')),
    ativo             BOOLEAN    NOT NULL DEFAULT 1 CHECK (ativo IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_servico_nome ON servico(nome);

-- ============================================================
-- 3.4 Tabela credencial
-- ============================================================
CREATE TABLE IF NOT EXISTS credencial (
    id                         INTEGER   PRIMARY KEY AUTOINCREMENT,
    usuario_id                 INTEGER   NOT NULL REFERENCES usuario(id),
    servico_id                 INTEGER   NOT NULL REFERENCES servico(id),
    nome_exibicao              TEXT(100) NOT NULL,
    identificador              TEXT(320) NOT NULL,
    segredo_criptografado      BLOB      NOT NULL,
    nonce                      BLOB      NOT NULL,
    observacao_criptografada   BLOB,
    observacao_nonce            BLOB,
    favorita                   BOOLEAN   NOT NULL DEFAULT 0 CHECK (favorita IN (0, 1)),
    criada_em                  DATETIME  NOT NULL DEFAULT (datetime('now')),
    alterada_em                DATETIME  NOT NULL DEFAULT (datetime('now')),
    ultimo_uso_em              DATETIME,
    ativa                      BOOLEAN   NOT NULL DEFAULT 1 CHECK (ativa IN (0, 1)),
    UNIQUE(servico_id, identificador)
);

-- ============================================================
-- 3.5 Tabela url_servico
-- ============================================================
CREATE TABLE IF NOT EXISTS url_servico (
    id          INTEGER    PRIMARY KEY AUTOINCREMENT,
    servico_id  INTEGER    NOT NULL REFERENCES servico(id) ON DELETE CASCADE,
    url         TEXT(2048) NOT NULL,
    tipo        TEXT(20)   NOT NULL DEFAULT 'LOGIN'
                CHECK (tipo IN ('PRINCIPAL', 'LOGIN', 'RECUPERACAO', 'CADASTRO', 'LOGOUT')),
    descricao   TEXT(255),
    padrao      BOOLEAN    NOT NULL DEFAULT 0 CHECK (padrao IN (0, 1)),
    criado_em   DATETIME   NOT NULL DEFAULT (datetime('now')),
    ativa       BOOLEAN    NOT NULL DEFAULT 1 CHECK (ativa IN (0, 1)),
    UNIQUE(servico_id, url)
);

-- ============================================================
-- 3.6 Tabela configuracao_login
-- ============================================================
CREATE TABLE IF NOT EXISTS configuracao_login (
    id                  INTEGER    PRIMARY KEY AUTOINCREMENT,
    credencial_id       INTEGER    NOT NULL REFERENCES credencial(id) ON DELETE CASCADE,
    url_servico_id      INTEGER    NOT NULL REFERENCES url_servico(id),
    seletor_usuario     TEXT(500),
    seletor_senha       TEXT(500),
    seletor_botao       TEXT(500),
    url_sucesso         TEXT(2048),
    envio_automatico    BOOLEAN    NOT NULL DEFAULT 1 CHECK (envio_automatico IN (0, 1)),
    timeout_segundos    INTEGER    NOT NULL DEFAULT 30 CHECK (timeout_segundos > 0),
    ultima_validacao_em DATETIME,
    criado_em           DATETIME   NOT NULL DEFAULT (datetime('now')),
    atualizado_em       DATETIME   NOT NULL DEFAULT (datetime('now')),
    ativa               BOOLEAN    NOT NULL DEFAULT 1 CHECK (ativa IN (0, 1))
);

-- ============================================================
-- 3.7 Tabela sessao_navegador
-- ============================================================
CREATE TABLE IF NOT EXISTS sessao_navegador (
    id               INTEGER    PRIMARY KEY AUTOINCREMENT,
    credencial_id    INTEGER    NOT NULL REFERENCES credencial(id) ON DELETE CASCADE,
    dispositivo_id   INTEGER    REFERENCES dispositivo(id),
    navegador        TEXT(40)   NOT NULL,
    perfil_nome      TEXT(100),
    diretorio_perfil TEXT(1024),
    iniciada_em      DATETIME   NOT NULL DEFAULT (datetime('now')),
    ultimo_uso_em    DATETIME,
    expira_em        DATETIME,
    ativa            BOOLEAN    NOT NULL DEFAULT 1 CHECK (ativa IN (0, 1))
);

-- ============================================================
-- 3.8 Tabela metodo_autenticacao
-- ============================================================
CREATE TABLE IF NOT EXISTS metodo_autenticacao (
    id             INTEGER   PRIMARY KEY AUTOINCREMENT,
    credencial_id  INTEGER   NOT NULL REFERENCES credencial(id) ON DELETE CASCADE,
    tipo           TEXT(30)  NOT NULL DEFAULT 'SENHA'
                   CHECK (tipo IN ('SENHA', 'TOTP', 'SMS', 'EMAIL', 'PASSKEY', 'BIOMETRIA', 'APLICATIVO')),
    descricao      TEXT(255),
    principal      BOOLEAN   NOT NULL DEFAULT 0 CHECK (principal IN (0, 1)),
    habilitado     BOOLEAN   NOT NULL DEFAULT 1 CHECK (habilitado IN (0, 1)),
    configurado_em DATETIME,
    atualizado_em  DATETIME  NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- 3.9 Tabela email_recuperacao
-- ============================================================
CREATE TABLE IF NOT EXISTS email_recuperacao (
    id                    INTEGER  PRIMARY KEY AUTOINCREMENT,
    credencial_id         INTEGER  NOT NULL REFERENCES credencial(id) ON DELETE CASCADE,
    email_criptografado   BLOB     NOT NULL,
    nonce                 BLOB     NOT NULL,
    principal             BOOLEAN  NOT NULL DEFAULT 0 CHECK (principal IN (0, 1)),
    verificado            BOOLEAN  NOT NULL DEFAULT 0 CHECK (verificado IN (0, 1)),
    verificado_em         DATETIME,
    criado_em             DATETIME NOT NULL DEFAULT (datetime('now')),
    ativo                 BOOLEAN  NOT NULL DEFAULT 1 CHECK (ativo IN (0, 1))
);

-- ============================================================
-- 3.10 Tabela historico_credencial
-- ============================================================
CREATE TABLE IF NOT EXISTS historico_credencial (
    id                             INTEGER   PRIMARY KEY AUTOINCREMENT,
    credencial_id                  INTEGER   NOT NULL REFERENCES credencial(id) ON DELETE CASCADE,
    tipo_alteracao                 TEXT(40)  NOT NULL
                                   CHECK (tipo_alteracao IN ('SENHA', 'IDENTIFICADOR', 'OBSERVACAO', 'ATIVACAO')),
    valor_anterior_criptografado   BLOB,
    nonce                          BLOB,
    motivo                         TEXT(255),
    alterado_em                    DATETIME  NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- 3.11 Tabela evento_auditoria
-- ============================================================
CREATE TABLE IF NOT EXISTS evento_auditoria (
    id              INTEGER   PRIMARY KEY AUTOINCREMENT,
    usuario_id      INTEGER   NOT NULL REFERENCES usuario(id),
    credencial_id   INTEGER   REFERENCES credencial(id),
    dispositivo_id  INTEGER   REFERENCES dispositivo(id),
    tipo_evento     TEXT(50)  NOT NULL,
    resultado       TEXT(20)  NOT NULL DEFAULT 'SUCESSO'
                    CHECK (resultado IN ('SUCESSO', 'FALHA', 'CANCELADO', 'PARCIAL')),
    descricao       TEXT(500),
    ocorrido_em     DATETIME  NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_evento_tipo ON evento_auditoria(tipo_evento);
CREATE INDEX IF NOT EXISTS idx_evento_data ON evento_auditoria(ocorrido_em);

-- ============================================================
-- 3.12 Tabela alerta_seguranca
-- ============================================================
CREATE TABLE IF NOT EXISTS alerta_seguranca (
    id              INTEGER   PRIMARY KEY AUTOINCREMENT,
    credencial_id   INTEGER   REFERENCES credencial(id),
    tipo            TEXT(50)  NOT NULL,
    nivel           TEXT(10)  NOT NULL DEFAULT 'BAIXO'
                    CHECK (nivel IN ('BAIXO', 'MEDIO', 'ALTO', 'CRITICO')),
    titulo          TEXT(120) NOT NULL,
    mensagem        TEXT(500) NOT NULL,
    criado_em       DATETIME  NOT NULL DEFAULT (datetime('now')),
    resolvido       BOOLEAN   NOT NULL DEFAULT 0 CHECK (resolvido IN (0, 1)),
    resolvido_em    DATETIME
);

CREATE INDEX IF NOT EXISTS idx_alerta_tipo ON alerta_seguranca(tipo);

-- ============================================================
-- 3.13 Tabela dispositivo
-- ============================================================
CREATE TABLE IF NOT EXISTS dispositivo (
    id                   INTEGER   PRIMARY KEY AUTOINCREMENT,
    usuario_id           INTEGER   NOT NULL REFERENCES usuario(id),
    nome                 TEXT(100) NOT NULL,
    sistema_operacional  TEXT(100),
    fingerprint_hash     TEXT(128) UNIQUE,
    confiavel            BOOLEAN   NOT NULL DEFAULT 0 CHECK (confiavel IN (0, 1)),
    primeiro_acesso_em   DATETIME  NOT NULL DEFAULT (datetime('now')),
    ultimo_acesso_em     DATETIME,
    ativo                BOOLEAN   NOT NULL DEFAULT 1 CHECK (ativo IN (0, 1))
);

-- ============================================================
-- 3.14 Tabela backup
-- ============================================================
CREATE TABLE IF NOT EXISTS backup (
    id                    INTEGER    PRIMARY KEY AUTOINCREMENT,
    usuario_id            INTEGER    NOT NULL REFERENCES usuario(id),
    nome_arquivo          TEXT(255)  NOT NULL,
    caminho_arquivo       TEXT(1024) NOT NULL,
    hash_integridade      TEXT(128)  NOT NULL,
    tamanho_bytes         INTEGER    NOT NULL DEFAULT 0 CHECK (tamanho_bytes >= 0),
    versao_formato        TEXT(20)   NOT NULL DEFAULT '1',
    criado_em             DATETIME   NOT NULL DEFAULT (datetime('now')),
    ultima_restauracao_em DATETIME,
    valido                BOOLEAN    NOT NULL DEFAULT 1 CHECK (valido IN (0, 1))
);

-- ============================================================
-- 3.15 Tabela preferencia
-- ============================================================
CREATE TABLE IF NOT EXISTS preferencia (
    id            INTEGER    PRIMARY KEY AUTOINCREMENT,
    usuario_id    INTEGER    NOT NULL REFERENCES usuario(id),
    chave         TEXT(100)  NOT NULL,
    valor         TEXT(1000) NOT NULL,
    tipo_valor    TEXT(20)   NOT NULL DEFAULT 'TEXT'
                  CHECK (tipo_valor IN ('TEXT', 'INTEGER', 'BOOLEAN', 'JSON')),
    descricao     TEXT(255),
    atualizado_em DATETIME   NOT NULL DEFAULT (datetime('now')),
    UNIQUE(usuario_id, chave)
);
