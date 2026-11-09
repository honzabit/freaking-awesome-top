//! Native OS bindings and the one shell-out fallback helper. OWNER: native-macos agent.
//!
//! macOS data comes from native APIs (libproc, IOKit, CoreFoundation, notify; see [`darwin`]).
//! The command-line tools they replaced (`lsof`, `ioreg`, `pmset`) are only run when a native
//! call fails, always through [`run_fallback`] (LC_ALL=C, hard timeout, child killed and reaped).
//!
//! Which source served each subsystem is recorded with [`note_source`]:
//! * `FAT_DEBUG_SOURCES=1` prints `fat: source <subsystem>=<source>` to stderr whenever the
//!   source of a subsystem is first known or changes.
//! * `FAT_FORCE_FALLBACK=1` skips the native calls and uses the command-line tools (parity
//!   checks, and an escape hatch should a native API misbehave on some macOS release).
#[cfg(target_os = "macos")]
pub mod darwin;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static SOURCES: Mutex<BTreeMap<&'static str, &'static str>> = Mutex::new(BTreeMap::new());

/// Record that `subsystem` ("ports", "gpu", ...) was just served by `source` ("libproc", "lsof", ...).
pub fn note_source(subsystem: &'static str, source: &'static str) {
    let Ok(mut m) = SOURCES.lock() else { return };
    if m.insert(subsystem, source) != Some(source) && std::env::var_os("FAT_DEBUG_SOURCES").is_some_and(|v| v != "0") {
        eprintln!("fat: source {subsystem}={source}");
    }
}

/// Every subsystem's last source, sorted by subsystem name.
#[allow(dead_code)]
pub fn sources() -> Vec<(&'static str, &'static str)> {
    SOURCES.lock().map(|m| m.iter().map(|(k, v)| (*k, *v)).collect()).unwrap_or_default()
}

/// `FAT_FORCE_FALLBACK=1`: use the command-line tools instead of the native APIs.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn force_fallback() -> bool {
    std::env::var_os("FAT_FORCE_FALLBACK").is_some_and(|v| v != "0")
}

/// Run a command we spawn ourselves with `LC_ALL=C` (stable number/date formats), stdin and
/// stderr closed, killing and reaping it after `timeout`. Returns stdout when it exited in
/// time, whatever its exit status (lsof exits 1 when a selector matched nothing; callers parse
/// the output and treat empty as nothing). None when it is missing or timed out.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn run_fallback(cmd: &str, args: &[&str], timeout: Duration) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    // Read on a helper thread so a full pipe cannot deadlock the deadline loop.
    let reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = stdout.read_to_end(&mut s);
        String::from_utf8_lossy(&s).into_owned()
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                // Timed out (or wait failed): kill our own child and reap it.
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return None;
            }
        }
    }
    reader.join().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_runs_with_c_locale_and_times_out() {
        let out = run_fallback("sh", &["-c", "echo $LC_ALL"], Duration::from_secs(5)).unwrap();
        assert_eq!(out.trim(), "C");
        // Non-zero exit still returns stdout.
        assert_eq!(run_fallback("sh", &["-c", "echo x; exit 1"], Duration::from_secs(5)).as_deref(), Some("x\n"));
        let t = Instant::now();
        assert_eq!(run_fallback("sleep", &["5"], Duration::from_millis(100)), None);
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        assert_eq!(run_fallback("/nonexistent/fat-no-such-tool", &[], Duration::from_secs(1)), None);
    }

    #[test]
    fn sources_are_recorded() {
        note_source("test-subsystem", "a");
        note_source("test-subsystem", "b");
        assert!(sources().contains(&("test-subsystem", "b")));
    }
}
