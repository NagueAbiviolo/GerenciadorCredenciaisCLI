//! Proteções de memória e do processo contra vazamento de segredos.
//!
//! - `mlock` (`VirtualLock` no Windows) via crate `region` para impedir que
//!   páginas contendo chaves (KEK e DEK) sejam enviadas para o swap em disco.
//! - Desativação de core/crash dumps no processo para evitar que chaves em
//!   memória sejam gravadas em disco caso o processo sofra uma falha fatal.

/// Bloqueia um buffer na RAM (`mlock` / `VirtualLock`) para impedir que vá para o swap.
///
/// O bloqueio vale para **páginas inteiras**, não para o buffer: dois buffers
/// pequenos podem dividir a mesma página. Por isso a região **nunca é
/// desbloqueada**. Desbloquear a página da KEK temporária poderia liberar
/// também a página da DEK, e no Windows `VirtualUnlock` falha em páginas já
/// desbloqueadas. As páginas ficam travadas até o processo terminar, o que
/// custa poucos KiB.
///
/// Retorna `true` se o bloqueio funcionou. Se falhar (por exemplo, limite
/// `RLIMIT_MEMLOCK` baixo), registra um aviso e retorna `false`, sem impedir o uso do cofre.
pub fn trancar_memoria(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    match region::lock(buf.as_ptr(), buf.len()) {
        Ok(guard) => {
            // Intencional: não desbloquear (ver documentação acima).
            std::mem::forget(guard);
            true
        }
        Err(e) => {
            tracing::warn!("Não foi possível bloquear buffer de chave na RAM (mlock): {e}");
            false
        }
    }
}

/// Desativa a geração de core dumps / crash dumps para o processo atual.
///
/// - **Unix/Linux:** Define `RLIMIT_CORE = 0` via `setrlimit`.
/// - **Linux:** Define `PR_SET_DUMPABLE = 0` via `prctl` (também restringe `ptrace`).
/// - **Windows:** Define `SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX` via `SetErrorMode`.
///
/// Falhas são registradas como aviso (`tracing::warn!`) e não interrompem a execução.
pub fn desativar_core_dumps() {
    #[cfg(unix)]
    {
        let limite = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: chamada POSIX com ponteiro válido para struct rlimit inicializada.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limite) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("Não foi possível desativar core dumps (setrlimit RLIMIT_CORE): {err}");
        }
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE com argumento 0 desativa dumps e anexação ptrace não privilegiada.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("Não foi possível definir PR_SET_DUMPABLE=0 (prctl): {err}");
        }
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
        };
        // SAFETY: SetErrorMode apenas configura flags de erro do processo atual.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trancar_memoria_sem_destrancar() {
        // Dois buffers pequenos costumam dividir a mesma página; travar os dois
        // (e descartá-los) não pode entrar em pânico, nem com RLIMIT_MEMLOCK restrito.
        let a = vec![0x42u8; 32];
        let b = vec![0x24u8; 32];
        trancar_memoria(&a);
        trancar_memoria(&b);
        drop(a);
        drop(b);

        assert!(!trancar_memoria(&[]));
    }

    #[test]
    fn test_desativar_core_dumps() {
        desativar_core_dumps();

        #[cfg(unix)]
        {
            let mut limite = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limite) };
            assert_eq!(rc, 0);
            assert_eq!(limite.rlim_cur, 0);
        }

        #[cfg(target_os = "linux")]
        {
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
            assert_eq!(dumpable, 0);
        }
    }
}
