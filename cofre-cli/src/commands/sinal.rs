//! Tratamento global de sinal Ctrl+C (SIGINT).
//!
//! Como `ctrlc::set_handler` só pode ser registrado uma única vez por processo,
//! este módulo inicializa o handler sob demanda via `OnceLock` e expõe uma flag
//! atômica reutilizável por `credencial copy` e pelo modo `cofre shell`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};

static CTRL_C_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Garante que o handler global de Ctrl+C está registrado, zera a flag de
/// interrupção pendente e retorna uma referência compartilhada para ela.
pub fn preparar_ctrl_c() -> Result<Arc<AtomicBool>> {
    if let Some(flag) = CTRL_C_FLAG.get() {
        flag.store(false, Ordering::SeqCst);
        return Ok(Arc::clone(flag));
    }

    let nova_flag = Arc::new(AtomicBool::new(false));
    let flag_handler = Arc::clone(&nova_flag);
    ctrlc::set_handler(move || {
        flag_handler.store(true, Ordering::SeqCst);
    })
    .context("Falha ao registrar o tratamento de Ctrl+C")?;

    let flag = CTRL_C_FLAG.get_or_init(|| nova_flag);
    flag.store(false, Ordering::SeqCst);
    Ok(Arc::clone(flag))
}
