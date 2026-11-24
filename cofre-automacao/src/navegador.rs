//! Localização do executável do navegador no sistema operacional.
//!
//! Suporta os navegadores configuráveis na preferência `navegador_padrao`
//! (`chromium`, `chrome`, `edge`, `brave`) em Linux, Windows e macOS, além de
//! permitir sobreposição explícita pela variável de ambiente `COFRE_NAVEGADOR`.

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Nome da variável de ambiente que sobrepõe o caminho do executável do navegador.
pub const ENV_COFRE_NAVEGADOR: &str = "COFRE_NAVEGADOR";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NavegadorError {
    #[error("Navegador '{0}' não é suportado (use um de: chromium, chrome, edge, brave)")]
    TipoNaoSuportado(String),

    #[error("O caminho definido em {ENV_COFRE_NAVEGADOR} ('{0}') não existe ou não é um arquivo")]
    CaminhoEnvInvalido(String),

    #[error(
        "Executável do navegador '{navegador}' não encontrado no sistema. \
         Instale o navegador, altere a preferência 'navegador_padrao' ou defina a variável de ambiente {ENV_COFRE_NAVEGADOR} com o caminho completo do binário."
    )]
    NaoEncontrado { navegador: String },
}

/// Tipos de navegadores baseados em Chromium suportados pela automação CDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoNavegador {
    Chromium,
    Chrome,
    Edge,
    Brave,
}

impl TipoNavegador {
    /// Converte o nome salvo na preferência `navegador_padrao` para `TipoNavegador`.
    pub fn from_preferencia(valor: &str) -> Result<Self, NavegadorError> {
        match valor.trim().to_ascii_lowercase().as_str() {
            "chromium" => Ok(Self::Chromium),
            "chrome" => Ok(Self::Chrome),
            "edge" => Ok(Self::Edge),
            "brave" => Ok(Self::Brave),
            outro => Err(NavegadorError::TipoNaoSuportado(outro.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chromium => "chromium",
            Self::Chrome => "chrome",
            Self::Edge => "edge",
            Self::Brave => "brave",
        }
    }

    /// Nomes de binários procurados no `PATH` do sistema.
    pub fn candidatos_binario(self) -> &'static [&'static str] {
        match self {
            Self::Chromium => &["chromium", "chromium-browser", "chromium.exe"],
            Self::Chrome => &[
                "google-chrome",
                "google-chrome-stable",
                "chrome",
                "chrome-browser",
                "chrome.exe",
            ],
            Self::Edge => &[
                "microsoft-edge",
                "microsoft-edge-stable",
                "msedge",
                "msedge.exe",
            ],
            Self::Brave => &[
                "brave-browser",
                "brave-browser-stable",
                "brave",
                "brave.exe",
            ],
        }
    }
}

/// Gera a lista de caminhos candidatos conhecidos no sistema de arquivos para o navegador.
pub fn caminhos_candidatos_so(
    tipo: TipoNavegador,
    program_files: Option<&Path>,
    program_files_x86: Option<&Path>,
    local_app_data: Option<&Path>,
) -> Vec<PathBuf> {
    let mut caminhos = Vec::new();

    // Caminhos Linux / Unix
    match tipo {
        TipoNavegador::Chromium => {
            caminhos.extend([
                PathBuf::from("/usr/bin/chromium"),
                PathBuf::from("/usr/bin/chromium-browser"),
                PathBuf::from("/snap/bin/chromium"),
                PathBuf::from("/opt/chromium.org/chromium/chromium"),
            ]);
        }
        TipoNavegador::Chrome => {
            caminhos.extend([
                PathBuf::from("/usr/bin/google-chrome"),
                PathBuf::from("/usr/bin/google-chrome-stable"),
                PathBuf::from("/opt/google/chrome/google-chrome"),
                PathBuf::from("/opt/google/chrome/chrome"),
            ]);
        }
        TipoNavegador::Edge => {
            caminhos.extend([
                PathBuf::from("/usr/bin/microsoft-edge"),
                PathBuf::from("/usr/bin/microsoft-edge-stable"),
                PathBuf::from("/opt/microsoft/msedge/msedge"),
            ]);
        }
        TipoNavegador::Brave => {
            caminhos.extend([
                PathBuf::from("/usr/bin/brave-browser"),
                PathBuf::from("/usr/bin/brave"),
                PathBuf::from("/snap/bin/brave"),
                PathBuf::from("/opt/brave.com/brave/brave-browser"),
            ]);
        }
    }

    // Caminhos Windows (Program Files, Program Files (x86), LOCALAPPDATA)
    let sufixo_win = match tipo {
        TipoNavegador::Chromium => r"Chromium\Application\chrome.exe",
        TipoNavegador::Chrome => r"Google\Chrome\Application\chrome.exe",
        TipoNavegador::Edge => r"Microsoft\Edge\Application\msedge.exe",
        TipoNavegador::Brave => r"BraveSoftware\Brave-Browser\Application\brave.exe",
    };

    for base in [program_files, program_files_x86, local_app_data]
        .into_iter()
        .flatten()
    {
        caminhos.push(base.join(sufixo_win));
    }

    // Fallbacks Windows padrão caso as variáveis de ambiente não estejam definidas
    for fixo in [r"C:\Program Files", r"C:\Program Files (x86)"] {
        let candidato = PathBuf::from(fixo).join(sufixo_win);
        if !caminhos.contains(&candidato) {
            caminhos.push(candidato);
        }
    }

    // Caminhos macOS
    let caminho_mac = match tipo {
        TipoNavegador::Chromium => "/Applications/Chromium.app/Contents/MacOS/Chromium",
        TipoNavegador::Chrome => "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        TipoNavegador::Edge => "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        TipoNavegador::Brave => "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    };
    caminhos.push(PathBuf::from(caminho_mac));

    caminhos
}

/// Procura um binário em uma lista de diretórios do `PATH`.
fn procurar_no_path(nomes: &[&str], path_env: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let path_env = path_env?;
    for dir in std::env::split_paths(path_env) {
        for nome in nomes {
            let candidato = dir.join(nome);
            if candidato.is_file() {
                return Some(candidato);
            }
        }
    }
    None
}

/// Localiza o executável do navegador respeitando:
/// 1. Variável de ambiente `COFRE_NAVEGADOR` (se definida e não vazia).
/// 2. Binários correspondentes a `navegador_padrao` no `PATH`.
/// 3. Caminhos padrão de instalação no Linux, Windows (`ProgramFiles`, `ProgramFiles(x86)`, `LOCALAPPDATA`) e macOS.
pub fn localizar_navegador(navegador_padrao: &str) -> Result<PathBuf, NavegadorError> {
    let override_env = std::env::var(ENV_COFRE_NAVEGADOR).ok();
    localizar_navegador_com_env(
        navegador_padrao,
        override_env.as_deref(),
        std::env::var_os("PATH").as_deref(),
        std::env::var_os("ProgramFiles").as_deref().map(Path::new),
        std::env::var_os("ProgramFiles(x86)")
            .as_deref()
            .map(Path::new),
        std::env::var_os("LOCALAPPDATA").as_deref().map(Path::new),
    )
}

/// Versão parametrizada de [`localizar_navegador`] para facilitar testes determinísticos sem depender do ambiente global.
pub fn localizar_navegador_com_env(
    navegador_padrao: &str,
    cofre_navegador_env: Option<&str>,
    path_env: Option<&std::ffi::OsStr>,
    program_files: Option<&Path>,
    program_files_x86: Option<&Path>,
    local_app_data: Option<&Path>,
) -> Result<PathBuf, NavegadorError> {
    // Valida sempre a preferência primeiro, salvo se COFRE_NAVEGADOR estiver definido
    let tipo_res = TipoNavegador::from_preferencia(navegador_padrao);

    if let Some(caminho_override) = cofre_navegador_env {
        let limpo = caminho_override.trim();
        if !limpo.is_empty() {
            let p = PathBuf::from(limpo);
            if p.is_file() {
                return Ok(p);
            }
            return Err(NavegadorError::CaminhoEnvInvalido(limpo.to_string()));
        }
    }

    let tipo = tipo_res?;

    if let Some(encontrado) = procurar_no_path(tipo.candidatos_binario(), path_env) {
        return Ok(encontrado);
    }

    for candidato in caminhos_candidatos_so(tipo, program_files, program_files_x86, local_app_data)
    {
        if candidato.is_file() {
            return Ok(candidato);
        }
    }

    Err(NavegadorError::NaoEncontrado {
        navegador: tipo.as_str().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tipo_navegador() {
        assert_eq!(
            TipoNavegador::from_preferencia("chromium").unwrap(),
            TipoNavegador::Chromium
        );
        assert_eq!(
            TipoNavegador::from_preferencia(" CHROME ").unwrap(),
            TipoNavegador::Chrome
        );
        assert_eq!(
            TipoNavegador::from_preferencia("Edge").unwrap(),
            TipoNavegador::Edge
        );
        assert_eq!(
            TipoNavegador::from_preferencia("brave").unwrap(),
            TipoNavegador::Brave
        );
        assert!(matches!(
            TipoNavegador::from_preferencia("firefox"),
            Err(NavegadorError::TipoNaoSuportado(_))
        ));
    }

    #[test]
    fn test_override_cofre_navegador_e_busca_em_diretorios() {
        let dir_temp = std::env::temp_dir().join(format!("cofre-nav-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir_temp);
        std::fs::create_dir_all(&dir_temp).unwrap();

        let bin_falso = dir_temp.join("meu-navegador-custom");
        std::fs::write(&bin_falso, b"#!/bin/sh\n").unwrap();

        // 1. COFRE_NAVEGADOR válido sobrepõe a busca
        let res = localizar_navegador_com_env(
            "chromium",
            Some(bin_falso.to_str().unwrap()),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(res, bin_falso);

        // 2. COFRE_NAVEGADOR apontando para arquivo inexistente retorna erro claro
        let err = localizar_navegador_com_env(
            "chromium",
            Some("/caminho/que/nao/existe/chrome"),
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, NavegadorError::CaminhoEnvInvalido(_)));

        // 3. Busca via LOCALAPPDATA simulando estrutura do Windows para Brave
        let brave_win = dir_temp.join(r"BraveSoftware\Brave-Browser\Application\brave.exe");
        std::fs::create_dir_all(brave_win.parent().unwrap()).unwrap();
        std::fs::write(&brave_win, b"MZ").unwrap();

        let achado = localizar_navegador_com_env(
            "brave",
            None,
            Some(std::ffi::OsStr::new("")),
            None,
            None,
            Some(&dir_temp),
        )
        .unwrap();
        assert_eq!(achado, brave_win);

        // 4. Quando não há binário no PATH nem nos diretórios simulados (e se não existir instalado na máquina)
        let path_vazio = std::ffi::OsStr::new("/diretorio/vazio/inexistente");
        let res_edge =
            localizar_navegador_com_env("edge", None, Some(path_vazio), None, None, None);
        if res_edge.is_err() {
            assert!(matches!(
                res_edge,
                Err(NavegadorError::NaoEncontrado { .. })
            ));
        }

        let _ = std::fs::remove_dir_all(&dir_temp);
    }
}
