//! Validação de domínio e origem por eTLD+1 (Public Suffix List, RNF12).
//!
//! Garante que credenciais nunca sejam preenchidas em páginas ou iframes cuja
//! origem não pertença ao `dominio_principal` cadastrado no serviço.

use thiserror::Error;
use url::{Host, Url};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DominioError {
    #[error("URL inválida '{0}'")]
    UrlInvalida(String),

    #[error("Domínio principal inválido '{0}'")]
    DominioPrincipalInvalido(String),

    #[error("Esquema '{0}' não autorizado (exige https, ou http apenas em localhost/127.0.0.1)")]
    EsquemaNaoAutorizado(String),

    #[error("A URL não possui host válido")]
    SemHost,

    #[error("Domínio não autorizado: '{carregado}' não corresponde a '{esperado}'")]
    DominioNaoAutorizado { carregado: String, esperado: String },
}

/// Verifica se o host é loopback local permitido com esquema `http://` (útil em testes locais).
pub fn eh_host_local_http_permitido(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(ip) => ip.octets() == [127, 0, 0, 1],
        Host::Ipv6(_) => false,
    }
}

/// Extrai e normaliza o host a partir de um `dominio_principal` cadastrado no serviço.
///
/// Aceita tanto um domínio puro (`"netflix.com"`, `"127.0.0.1"`) quanto uma URL
/// (`"https://www.netflix.com"`).
fn extrair_host_esperado(dominio_principal: &str) -> Result<Host<String>, DominioError> {
    let limpo = dominio_principal.trim();
    if limpo.is_empty() || limpo.chars().any(char::is_whitespace) {
        return Err(DominioError::DominioPrincipalInvalido(
            dominio_principal.to_string(),
        ));
    }

    let url_candidata = if limpo.contains("://") {
        limpo.to_string()
    } else {
        format!("https://{limpo}")
    };

    let parsed = Url::parse(&url_candidata)
        .map_err(|_| DominioError::DominioPrincipalInvalido(dominio_principal.to_string()))?;

    // Se não tinha esquema explícito, não deve conter caminho, query ou credenciais embutidas
    if !limpo.contains("://")
        && (parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some())
    {
        return Err(DominioError::DominioPrincipalInvalido(
            dominio_principal.to_string(),
        ));
    }

    let host = parsed
        .host()
        .ok_or_else(|| DominioError::DominioPrincipalInvalido(dominio_principal.to_string()))?;

    Ok(match host {
        Host::Domain(d) => Host::Domain(d.trim_end_matches('.').to_ascii_lowercase()),
        Host::Ipv4(ip) => Host::Ipv4(ip),
        Host::Ipv6(ip) => Host::Ipv6(ip),
    })
}

/// Obtém o domínio registrável (eTLD+1) de um nome de domínio usando a Public Suffix List.
///
/// Para `"localhost"` (sem ponto, usado em testes locais), retorna `Some("localhost")`.
/// Para sufixos públicos puros (ex: `"com"`, `"co.uk"`, `"github.io"`), `psl::domain_str`
/// retorna `None` e a validação rejeita o domínio.
pub fn extrair_etld_mais_um(dominio: &str) -> Option<String> {
    let normalizado = dominio.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalizado.is_empty() {
        return None;
    }
    if normalizado == "localhost" {
        return Some("localhost".to_string());
    }
    let registravel = psl::domain_str(&normalizado)?;
    // Garante que o domínio tinha pelo menos um rótulo além do sufixo público
    let sufixo = psl::suffix_str(&normalizado)?;
    if registravel == sufixo {
        return None;
    }
    Some(registravel.to_ascii_lowercase())
}

/// Valida se a `url_carregada` (da página principal ou de um frame/iframe) é segura
/// e pertence ao mesmo `dominio_principal` do serviço (por eTLD+1 ou IP literal idêntico).
///
/// Regras:
/// - Exige esquema `https` (permite `http` apenas para `localhost` e `127.0.0.1`).
/// - IP literal só casa com o mesmo IP literal.
/// - Nomes de domínio são comparados pelo seu eTLD+1 via Public Suffix List (`psl`),
///   garantindo que `www.netflix.com` e `login.netflix.com` casem com `netflix.com`,
///   mas `netflix.com.evil.io` ou `evilnetflix.com` NÃO casem.
/// - Além do eTLD+1, se o `dominio_principal` cadastrado especificar um subdomínio
///   sob um sufixo privado/público (ex: `meuapp.github.io`), ambos terão o mesmo eTLD+1.
pub fn validar_url_contra_dominio(
    url_carregada: &str,
    dominio_principal: &str,
) -> Result<(), DominioError> {
    let esperado_host = extrair_host_esperado(dominio_principal)?;

    let parsed = Url::parse(url_carregada.trim())
        .map_err(|_| DominioError::UrlInvalida(url_carregada.to_string()))?;

    let host_carregado = parsed.host().ok_or(DominioError::SemHost)?;

    match parsed.scheme() {
        "https" => {}
        "http" if eh_host_local_http_permitido(&host_carregado) => {}
        outro => return Err(DominioError::EsquemaNaoAutorizado(outro.to_string())),
    }

    match (&host_carregado, &esperado_host) {
        (Host::Ipv4(ip_c), Host::Ipv4(ip_e)) => {
            if ip_c == ip_e {
                Ok(())
            } else {
                Err(DominioError::DominioNaoAutorizado {
                    carregado: ip_c.to_string(),
                    esperado: ip_e.to_string(),
                })
            }
        }
        (Host::Ipv6(ip_c), Host::Ipv6(ip_e)) => {
            if ip_c == ip_e {
                Ok(())
            } else {
                Err(DominioError::DominioNaoAutorizado {
                    carregado: ip_c.to_string(),
                    esperado: ip_e.to_string(),
                })
            }
        }
        (Host::Domain(dom_c), Host::Domain(dom_e)) => {
            let dom_c_norm = dom_c.trim_end_matches('.').to_ascii_lowercase();
            let Some(etld_esperado) = extrair_etld_mais_um(dom_e) else {
                return Err(DominioError::DominioPrincipalInvalido(
                    dominio_principal.to_string(),
                ));
            };
            let Some(etld_carregado) = extrair_etld_mais_um(&dom_c_norm) else {
                return Err(DominioError::DominioNaoAutorizado {
                    carregado: dom_c_norm,
                    esperado: etld_esperado,
                });
            };

            if etld_carregado == etld_esperado {
                Ok(())
            } else {
                Err(DominioError::DominioNaoAutorizado {
                    carregado: dom_c_norm,
                    esperado: etld_esperado,
                })
            }
        }
        _ => {
            let carregado_str = parsed.host_str().unwrap_or_default().to_string();
            let esperado_str = match esperado_host {
                Host::Domain(d) => d,
                Host::Ipv4(ip) => ip.to_string(),
                Host::Ipv6(ip) => ip.to_string(),
            };
            Err(DominioError::DominioNaoAutorizado {
                carregado: carregado_str,
                esperado: esperado_str,
            })
        }
    }
}

/// Retorna `true` se a `url_carregada` for autorizada para o `dominio_principal`.
pub fn url_autorizada(url_carregada: &str, dominio_principal: &str) -> bool {
    validar_url_contra_dominio(url_carregada, dominio_principal).is_ok()
}

/// Valida a URL da página principal e todas as URLs dos frames/iframes onde campos
/// sensíveis foram localizados.
///
/// Rejeita se a lista de frames estiver vazia ou se qualquer frame tiver URL inválida,
/// esquema não autorizado (`javascript:`, `data:`, `about:blank`, `http:` externo)
/// ou eTLD+1 divergente do `dominio_principal`.
pub fn validar_pagina_e_frames(
    url_pagina: &str,
    urls_frames_com_campos: &[String],
    dominio_principal: &str,
) -> Result<(), DominioError> {
    validar_url_contra_dominio(url_pagina, dominio_principal)?;
    for frame_url in urls_frames_com_campos {
        validar_url_contra_dominio(frame_url, dominio_principal)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subdominios_legitimos_casam_com_dominio_principal() {
        assert!(url_autorizada("https://netflix.com/login", "netflix.com"));
        assert!(url_autorizada(
            "https://www.netflix.com/br/login",
            "netflix.com"
        ));
        assert!(url_autorizada(
            "https://login.netflix.com/auth",
            "netflix.com"
        ));
        assert!(url_autorizada(
            "https://a.b.c.netflix.com:8443/path?x=1",
            "netflix.com"
        ));
        // Mesmo quando o serviço foi cadastrado com www ou URL completa
        assert!(url_autorizada(
            "https://login.netflix.com/auth",
            "www.netflix.com"
        ));
        assert!(url_autorizada(
            "https://login.netflix.com/auth",
            "https://www.netflix.com"
        ));
    }

    #[test]
    fn test_ataques_de_phishing_e_sufixo_falso_sao_rejeitados() {
        // O caso clássico exigido nos requisitos: netflix.com.evil.io NÃO casa com netflix.com
        assert!(!url_autorizada(
            "https://netflix.com.evil.io/login",
            "netflix.com"
        ));
        assert!(!url_autorizada(
            "https://www.netflix.com.evil.io/login",
            "netflix.com"
        ));
        assert!(!url_autorizada(
            "https://evil-netflix.com/login",
            "netflix.com"
        ));
        assert!(!url_autorizada("https://netflix.org/login", "netflix.com"));
        assert!(!url_autorizada(
            "https://netflix.com.br/login",
            "netflix.com"
        ));
        assert!(!url_autorizada(
            "https://evil.com/https://netflix.com",
            "netflix.com"
        ));
        assert!(!url_autorizada(
            "https://netflix.com@evil.com/login",
            "netflix.com"
        ));
    }

    #[test]
    fn test_tlds_compostos_e_psl_privado() {
        // .com.br e .gov.br
        assert!(url_autorizada(
            "https://acesso.gov.br/login",
            "sso.acesso.gov.br"
        ));
        assert!(!url_autorizada(
            "https://outro.gov.br/login",
            "acesso.gov.br"
        ));
        assert!(url_autorizada(
            "https://internetbanking.banco.com.br/auth",
            "banco.com.br"
        ));
        assert!(!url_autorizada(
            "https://banco.com.br.atacante.com.br/auth",
            "banco.com.br"
        ));

        // github.io está na PSL como sufixo público/privado: user1.github.io != user2.github.io
        assert!(url_autorizada(
            "https://app.meuusuario.github.io/login",
            "meuusuario.github.io"
        ));
        assert!(!url_autorizada(
            "https://outrousuario.github.io/login",
            "meuusuario.github.io"
        ));

        // Sufixo público puro como dominio_principal deve ser rejeitado
        assert!(matches!(
            validar_url_contra_dominio("https://qualquer.com", "com"),
            Err(DominioError::DominioPrincipalInvalido(_))
        ));
        assert!(matches!(
            validar_url_contra_dominio("https://qualquer.com.br", "com.br"),
            Err(DominioError::DominioPrincipalInvalido(_))
        ));
    }

    #[test]
    fn test_esquema_https_obrigatorio_exceto_localhost_e_127_0_0_1() {
        // HTTP em domínio externo é rejeitado
        assert!(matches!(
            validar_url_contra_dominio("http://www.netflix.com/login", "netflix.com"),
            Err(DominioError::EsquemaNaoAutorizado(_))
        ));
        assert!(matches!(
            validar_url_contra_dominio("ftp://www.netflix.com/login", "netflix.com"),
            Err(DominioError::EsquemaNaoAutorizado(_))
        ));
        assert!(matches!(
            validar_url_contra_dominio("javascript:alert(1)", "netflix.com"),
            Err(DominioError::SemHost)
        ));
        assert!(matches!(
            validar_url_contra_dominio("data:text/html,<h1>login</h1>", "netflix.com"),
            Err(DominioError::SemHost)
        ));
        assert!(matches!(
            validar_url_contra_dominio("about:blank", "netflix.com"),
            Err(DominioError::SemHost)
        ));

        // HTTP permitido apenas em localhost e 127.0.0.1
        assert!(url_autorizada("http://localhost:8080/login", "localhost"));
        assert!(url_autorizada("https://localhost:8443/login", "localhost"));
        assert!(url_autorizada("http://127.0.0.1:3000/login", "127.0.0.1"));
        assert!(url_autorizada("https://127.0.0.1:3000/login", "127.0.0.1"));

        // HTTP em outro IP privado/público NÃO é permitido
        assert!(matches!(
            validar_url_contra_dominio("http://192.168.1.10/login", "192.168.1.10"),
            Err(DominioError::EsquemaNaoAutorizado(_))
        ));
        assert!(url_autorizada(
            "https://192.168.1.10:8443/login",
            "192.168.1.10"
        ));
    }

    #[test]
    fn test_ip_literal_so_casa_com_ele_mesmo() {
        assert!(url_autorizada("http://127.0.0.1:8000/login", "127.0.0.1"));
        assert!(!url_autorizada("http://127.0.0.1:8000/login", "localhost"));
        assert!(!url_autorizada("http://localhost:8000/login", "127.0.0.1"));
        assert!(!url_autorizada(
            "https://192.168.1.10/login",
            "192.168.1.11"
        ));
        assert!(url_autorizada("https://[::1]:8443/login", "[::1]"));
        assert!(!url_autorizada("https://[::1]:8443/login", "[::2]"));
        assert!(!url_autorizada("https://127.0.0.1/login", "netflix.com"));
    }

    #[test]
    fn test_validar_pagina_e_frames_iframes_maliciosos() {
        // Página principal legítima + iframe de autenticação do mesmo domínio -> OK
        assert!(validar_pagina_e_frames(
            "https://www.netflix.com/login",
            &["https://auth.netflix.com/frame".to_string()],
            "netflix.com",
        )
        .is_ok());

        // Página principal legítima + iframe de terceiro contendo campo -> FALHA
        assert!(matches!(
            validar_pagina_e_frames(
                "https://www.netflix.com/login",
                &[
                    "https://www.netflix.com/login".to_string(),
                    "https://evil-tracker.io/phish-frame".to_string()
                ],
                "netflix.com",
            ),
            Err(DominioError::DominioNaoAutorizado { .. })
        ));

        // Iframe com about:blank ou data: contendo campo -> FALHA
        assert!(validar_pagina_e_frames(
            "https://www.netflix.com/login",
            &["about:blank".to_string()],
            "netflix.com",
        )
        .is_err());
    }
}
