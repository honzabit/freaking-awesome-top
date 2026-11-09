//! macOS native data sources (FFI against libSystem, IOKit and CoreFoundation; no crates
//! beyond `libc`). OWNER: native-macos agent.
//!
//! * [`libproc`]: listening sockets and their owners, deleted-but-open files, files a process
//!   holds open for writing (replaces `lsof`).
//! * [`iokit`]: disk I/O counters, GPU utilization, battery (replaces `ioreg`, `pmset -g batt`).
//! * [`thermal`]: thermal pressure via the notify API (replaces `pmset -g therm`).
//! * [`cf`]: CoreFoundation handle and typed dictionary readers.
pub mod cf;
pub mod iokit;
pub mod libproc;

/// Thermal pressure from the `com.apple.system.thermalpressurelevel` notification state, which
/// thermalmonitord publishes for everyone (no root, no entitlement; the same signal behind
/// `NSProcessInfo.thermalState`). The token is registered once and kept for the process.
pub mod thermal {
    use std::ffi::c_int;
    use std::sync::OnceLock;

    const NOTIFY_STATUS_OK: u32 = 0;

    unsafe extern "C" {
        fn notify_register_check(name: *const std::ffi::c_char, token: *mut c_int) -> u32;
        fn notify_get_state(token: c_int, state: *mut u64) -> u32;
    }

    fn token() -> Option<c_int> {
        static TOKEN: OnceLock<Option<c_int>> = OnceLock::new();
        *TOKEN.get_or_init(|| {
            let mut t: c_int = 0;
            // SAFETY: NUL-terminated name, valid out-param.
            let rc = unsafe { notify_register_check(c"com.apple.system.thermalpressurelevel".as_ptr(), &mut t) };
            (rc == NOTIFY_STATUS_OK).then_some(t)
        })
    }

    /// Raw OSThermalPressureLevel (0 nominal, 1 moderate, 2 heavy, 3 trapping, 4 sleeping).
    pub fn pressure_level() -> Option<u64> {
        let t = token()?;
        let mut s = 0u64;
        // SAFETY: registered token, valid out-param.
        (unsafe { notify_get_state(t, &mut s) } == NOTIFY_STATUS_OK).then_some(s)
    }

    /// fat's thermal words, as NSProcessInfo maps the same levels.
    pub fn label(level: u64) -> &'static str {
        match level {
            0 => "nominal",
            1 => "fair",
            2 => "serious",
            _ => "critical",
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn levels() {
            assert_eq!(label(0), "nominal");
            assert_eq!(label(1), "fair");
            assert_eq!(label(2), "serious");
            assert_eq!(label(3), "critical");
            assert_eq!(label(4), "critical");
            let l = pressure_level().expect("notify state readable");
            assert!(l <= 4, "{l}");
        }
    }
}
