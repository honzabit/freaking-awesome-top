//! System stats: memory pressure, thermal, GPU (ioreg), battery, load. OWNER: collect-core agent.
//!
//! The slow sources (external `pmset` / `ioreg` commands) run in a background thread that keeps a
//! cached `Extras`; the sample path only reads that cache. Fast sources (sysctl) are read inline.

use std::process::Command;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::model::Gpu;

/// `ioreg` costs ~15ms CPU per run; 4s keeps the always-on recorder cheap.
pub const GPU_EVERY: Duration = Duration::from_secs(4);
pub const THERMAL_EVERY: Duration = Duration::from_secs(10);
pub const BATTERY_EVERY: Duration = Duration::from_secs(30);
/// Background polling pauses when nobody has sampled for this long.
const IDLE_AFTER: Duration = Duration::from_secs(15);

/// Values gathered from external commands, cached.
#[derive(Debug, Clone, PartialEq)]
pub struct Extras {
    pub thermal: String,
    pub gpus: Vec<Gpu>,
    pub battery_pct: Option<f32>,
    pub on_battery: Option<bool>,
}

impl Default for Extras {
    fn default() -> Self {
        Self { thermal: "unknown".into(), gpus: Vec::new(), battery_pct: None, on_battery: None }
    }
}

struct Shared {
    extras: Mutex<Extras>,
    last_read: Mutex<Instant>,
}

/// Handle to the background poller. Dropping it stops the thread (it holds only a Weak ref).
pub struct ExtrasCache {
    shared: Arc<Shared>,
}

impl ExtrasCache {
    pub fn start() -> Self {
        let shared = Arc::new(Shared {
            extras: Mutex::new(Extras::default()),
            last_read: Mutex::new(Instant::now()),
        });
        let weak = Arc::downgrade(&shared);
        // If the thread can't be spawned, values simply stay "unknown".
        let _ = thread::Builder::new().name("fat-sysextras".into()).spawn(move || poll_loop(weak));
        Self { shared }
    }

    pub fn get(&self) -> Extras {
        if let Ok(mut t) = self.shared.last_read.lock() {
            *t = Instant::now();
        }
        self.shared.extras.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

fn poll_loop(weak: Weak<Shared>) {
    let mut last_gpu: Option<Instant> = None;
    let mut last_therm: Option<Instant> = None;
    let mut last_batt: Option<Instant> = None;
    let due = |t: Option<Instant>, every: Duration| t.is_none_or(|t| t.elapsed() >= every);
    loop {
        let Some(shared) = weak.upgrade() else { return };
        let idle = shared.last_read.lock().map(|t| t.elapsed() > IDLE_AFTER).unwrap_or(false);
        if !idle {
            if due(last_gpu, GPU_EVERY) {
                last_gpu = Some(Instant::now());
                let g = gpus();
                if let Ok(mut e) = shared.extras.lock() {
                    e.gpus = g;
                }
            }
            if due(last_therm, THERMAL_EVERY) {
                last_therm = Some(Instant::now());
                let t = thermal();
                if let Ok(mut e) = shared.extras.lock() {
                    e.thermal = t;
                }
            }
            if due(last_batt, BATTERY_EVERY) {
                last_batt = Some(Instant::now());
                let (pct, on_batt) = battery();
                if let Ok(mut e) = shared.extras.lock() {
                    e.battery_pct = pct;
                    e.on_battery = on_batt;
                }
            }
        }
        drop(shared);
        thread::sleep(Duration::from_millis(250));
    }
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).stdin(std::process::Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------------------------------------
// Memory pressure (sysctl, inline)

/// "normal" | "warn" | "critical" | "unknown".
pub fn mem_pressure() -> String {
    pressure_label(sysctl_i32("kern.memorystatus_vm_pressure_level")).to_string()
}

pub fn pressure_label(level: Option<i32>) -> &'static str {
    match level {
        Some(1) => "normal",
        Some(2) => "warn",
        Some(4) => "critical",
        _ => "unknown",
    }
}

#[cfg(target_os = "macos")]
pub fn sysctl_i32(name: &str) -> Option<i32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: out buffer is a c_int with its size passed in `len`; no new value is set.
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == std::mem::size_of::<libc::c_int>()).then_some(val)
}

#[cfg(not(target_os = "macos"))]
pub fn sysctl_i32(_name: &str) -> Option<i32> {
    None
}

// ---------------------------------------------------------------------------------------------
// Thermal (pmset -g therm)

pub fn thermal() -> String {
    if !cfg!(target_os = "macos") {
        return "unknown".into();
    }
    run("pmset", &["-g", "therm"]).map(|s| parse_therm(&s).to_string()).unwrap_or_else(|| "unknown".into())
}

/// Parse `pmset -g therm`. Uses CPU_Speed_Limit when present, else thermal warning level, else
/// the "No thermal warning" note.
pub fn parse_therm(s: &str) -> &'static str {
    let mut speed: Option<u32> = None;
    let mut warn_level: Option<u32> = None;
    let mut no_warning = false;
    for line in s.lines() {
        let l = line.trim();
        if l.starts_with("CPU_Speed_Limit") {
            speed = l.split('=').nth(1).and_then(|v| v.trim().parse().ok());
        } else if l.contains("No thermal warning") {
            no_warning = true;
        } else if let Some(rest) = l.strip_prefix("Thermal warning level set to") {
            warn_level = rest.trim().trim_end_matches('.').parse().ok();
        }
    }
    if let Some(sp) = speed {
        return match sp {
            95.. => "nominal",
            75..=94 => "fair",
            45..=74 => "serious",
            _ => "critical",
        };
    }
    match warn_level {
        Some(0) => "nominal",
        Some(1..=2) => "fair",
        Some(3..=4) => "serious",
        Some(_) => "critical",
        None if no_warning => "nominal",
        None => "unknown",
    }
}

// ---------------------------------------------------------------------------------------------
// GPU (ioreg)

pub fn gpus() -> Vec<Gpu> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    run("ioreg", &["-r", "-d", "1", "-c", "IOAccelerator"]).map(|s| parse_ioreg_gpus(&s)).unwrap_or_default()
}

/// Parse `ioreg -r -d 1 -c IOAccelerator`. Each top-level entry starts with a line beginning "+-o".
pub fn parse_ioreg_gpus(s: &str) -> Vec<Gpu> {
    let mut out = Vec::new();
    let mut cur: Option<Gpu> = None;
    for line in s.lines() {
        let l = line.trim();
        if l.starts_with("+-o") {
            if let Some(g) = cur.take() {
                out.push(g);
            }
            // "+-o AGXAcceleratorG15X  <class ...>" -> fallback name
            let name = l.trim_start_matches("+-o").split_whitespace().next().unwrap_or("GPU");
            cur = Some(Gpu { name: name.to_string(), ..Default::default() });
            continue;
        }
        let Some(g) = cur.as_mut() else { continue };
        if l.starts_with("\"model\"") {
            if let Some(v) = l.split('=').nth(1) {
                let v = v.trim().trim_matches('"');
                // model may be `<"Apple M3 Max">` data in some versions
                let v = v.trim_start_matches("<\"").trim_end_matches("\">");
                if !v.is_empty() {
                    g.name = v.to_string();
                }
            }
        } else if l.starts_with("\"PerformanceStatistics\"") {
            if let Some(u) = dict_num(l, "Device Utilization %") {
                g.util = u as f32;
            }
            if let Some(m) = dict_num(l, "In use system memory") {
                g.mem_used = m;
            }
        }
    }
    if let Some(g) = cur {
        out.push(g);
    }
    out
}

/// Find `"key"=123` in an ioreg inline dictionary (exact key match, so "In use system memory"
/// doesn't match "In use system memory (driver)").
fn dict_num(s: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\"=");
    let idx = s.find(&pat)? + pat.len();
    let digits: String = s[idx..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

// ---------------------------------------------------------------------------------------------
// Battery (pmset -g batt)

pub fn battery() -> (Option<f32>, Option<bool>) {
    if !cfg!(target_os = "macos") {
        return (None, None);
    }
    run("pmset", &["-g", "batt"]).map(|s| parse_batt(&s)).unwrap_or((None, None))
}

/// Returns (percent, on_battery). Desktop Macs report no battery line -> percent None.
pub fn parse_batt(s: &str) -> (Option<f32>, Option<bool>) {
    let on_batt = if s.contains("'Battery Power'") {
        Some(true)
    } else if s.contains("'AC Power'") {
        Some(false)
    } else {
        None
    };
    let pct = s
        .lines()
        .filter(|l| l.contains("InternalBattery"))
        .find_map(|l| {
            let end = l.find('%')?;
            let start = l[..end].rfind(|c: char| !c.is_ascii_digit()).map(|i| i + 1).unwrap_or(0);
            l[start..end].parse::<f32>().ok()
        });
    // On a desktop (no battery) "on battery" is meaningless.
    let on_batt = if pct.is_some() { on_batt } else { None };
    (pct, on_batt)
}

// ---------------------------------------------------------------------------------------------
// Static info

/// (hostname, os version, cpu model) — computed once by the Collector.
pub fn static_info(sys: &sysinfo::System) -> (String, String, String) {
    let host = friendly_host(sysinfo::System::host_name());
    let os = sysinfo::System::long_os_version()
        .or_else(sysinfo::System::os_version)
        .unwrap_or_else(|| "unknown".into());
    let cpu = sys
        .cpus()
        .first()
        .map(|c| c.brand().trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    (host, os, cpu)
}

/// macOS often reports a DHCP-assigned hostname like "192.168.1.5"; prefer the Bonjour
/// LocalHostName ("Zamans-MacBook-Pro") in that case.
fn friendly_host(raw: Option<String>) -> String {
    let raw = raw.unwrap_or_default();
    let looks_bad = raw.is_empty() || raw.parse::<std::net::IpAddr>().is_ok() || raw == "localhost";
    #[cfg(target_os = "macos")]
    if looks_bad {
        if let Ok(o) = std::process::Command::new("/usr/sbin/scutil").args(["--get", "LocalHostName"]).output() {
            let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if o.status.success() && !name.is_empty() {
                return name;
            }
        }
    }
    if raw.is_empty() { "unknown".into() } else { raw }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IOREG: &str = r#"+-o AGXAcceleratorG15X  <class AGXAcceleratorG15X, id 0x1000003a1, registered>
    {
      "IOClass" = "AGXAcceleratorG15X"
      "PerformanceStatistics" = {"In use system memory (driver)"=0,"Alloc system memory"=6479560704,"Tiler Utilization %"=3,"Renderer Utilization %"=5,"Device Utilization %"=17,"In use system memory"=1112211456}
      "model" = "Apple M3 Max"
    }
"#;

    #[test]
    fn ioreg_parse() {
        let g = parse_ioreg_gpus(IOREG);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].name, "Apple M3 Max");
        assert_eq!(g[0].util, 17.0);
        assert_eq!(g[0].mem_used, 1112211456);
        assert!(parse_ioreg_gpus("").is_empty());
    }

    #[test]
    fn therm_parse() {
        assert_eq!(parse_therm("Note: No thermal warning level has been recorded\n"), "nominal");
        let s = "CPU Power notify\n\tCPU_Scheduler_Limit \t= 100\n\tCPU_Available_CPUs \t= 8\n\tCPU_Speed_Limit \t= 60\n";
        assert_eq!(parse_therm(s), "serious");
        assert_eq!(parse_therm("CPU_Speed_Limit = 100"), "nominal");
        assert_eq!(parse_therm("Thermal warning level set to 0."), "nominal");
        assert_eq!(parse_therm(""), "unknown");
    }

    #[test]
    fn batt_parse() {
        let ac = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=21954659)\t100%; charged; 0:00 remaining present: true\n";
        assert_eq!(parse_batt(ac), (Some(100.0), Some(false)));
        let b = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t57%; discharging; 3:10 remaining present: true\n";
        assert_eq!(parse_batt(b), (Some(57.0), Some(true)));
        assert_eq!(parse_batt("Now drawing from 'AC Power'\n"), (None, None));
    }

    #[test]
    fn pressure_labels() {
        assert_eq!(pressure_label(Some(1)), "normal");
        assert_eq!(pressure_label(Some(4)), "critical");
        assert_eq!(pressure_label(None), "unknown");
        #[cfg(target_os = "macos")]
        assert_ne!(mem_pressure(), "unknown");
    }
}
