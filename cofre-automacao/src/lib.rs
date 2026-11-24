//! # cofre-automacao
//!
//! Módulo de automação de navegador (Fase 5 — RF06, RF07, RF16, RNF12, RNF13).
//!
//! Implementa validação de domínio por eTLD+1 (`psl` + `url`), localização do
//! executável do navegador (`chromium`, `chrome`, `edge`, `brave` ou `COFRE_NAVEGADOR`),
//! detecção de CAPTCHA/MFA e preenchimento assistido via CDP (`chromiumoxide`).

pub mod dominio;
pub mod login;
pub mod navegador;
