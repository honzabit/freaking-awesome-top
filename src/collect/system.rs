//! System stats: memory pressure, thermal, GPU, battery, load. OWNER: collect-core agent.
//!
//! The slow sources run in a background thread that keeps a cached `Extras`; the sample path only
//! reads that cache. Fast sources are read inline.
//!
//! * macOS: `pmset` / `ioreg` (background), sysctl (inline).
//! * Linux: sysfs/procfs only (see `mod lx`): PSI `/proc/pressure`, `/proc/meminfo`,
//!   `/sys/class/thermal` + `/sys/class/hwmon`, `/sys/class/power_supply`, `/sys/class/drm` +
//!   DRM fdinfo, and `nvidia-smi` only when that binary exists (1s timeout). Every reader takes a
//!   root path so it is unit-tested against fixture trees; missing files degrade to None/"unknown".

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::model::{Gpu, Psi};

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
    /// Hottest sensor in °C (Linux thermal zones / hwmon; None on macOS). Refreshed with `thermal`.
    pub temp_c: Option<f32>,
}

impl Default for Extras {
    fn default() -> Self {
        Self { thermal: "unknown".into(), gpus: Vec::new(), battery_pct: None, on_battery: None, temp_c: None }
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
    #[cfg(target_os = "linux")]
    let mut gpu_sampler = lx::GpuSampler::default();
    loop {
        let Some(shared) = weak.upgrade() else { return };
        let idle = shared.last_read.lock().map(|t| t.elapsed() > IDLE_AFTER).unwrap_or(false);
        if !idle {
            if due(last_gpu, GPU_EVERY) {
                last_gpu = Some(Instant::now());
                #[cfg(target_os = "linux")]
                let g = {
                    let (g, per_pid) = gpu_sampler.sample();
                    if let Ok(mut m) = PROC_GPU.lock() {
                        *m = Some(per_pid);
                    }
                    g
                };
                #[cfg(not(target_os = "linux"))]
                let g = gpus();
                if let Ok(mut e) = shared.extras.lock() {
                    e.gpus = g;
                }
            }
            if due(last_therm, THERMAL_EVERY) {
                last_therm = Some(Instant::now());
                #[cfg(target_os = "linux")]
                let (t, temp) = {
                    let r = lx::read_thermal(std::path::Path::new("/sys/class"));
                    (r.level.to_string(), r.max_c)
                };
                #[cfg(not(target_os = "linux"))]
                let (t, temp) = (thermal(), None);
                if let Ok(mut e) = shared.extras.lock() {
                    e.thermal = t;
                    e.temp_c = temp;
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
/// Linux: from PSI memory stall (falls back to MemAvailable/MemTotal when PSI is absent).
pub fn mem_pressure() -> String {
    #[cfg(target_os = "linux")]
    let label = lx::mem_pressure_at(std::path::Path::new("/proc"));
    #[cfg(not(target_os = "linux"))]
    let label = pressure_label(sysctl_i32("kern.memorystatus_vm_pressure_level"));
    label.to_string()
}

/// Linux PSI (system-wide avg10). Three tiny procfs reads (~20µs), so it's read inline per sample.
/// None on macOS or kernels without CONFIG_PSI / booted with psi=0.
pub fn psi() -> Option<Psi> {
    #[cfg(target_os = "linux")]
    let p = lx::read_psi(std::path::Path::new("/proc/pressure"));
    #[cfg(not(target_os = "linux"))]
    let p = None;
    p
}

/// Hottest temperature sensor in °C. Linux: thermal zones + hwmon. macOS: None (no cheap source;
/// the background cache's `Extras::temp_c` is the per-sample value to use).
#[allow(dead_code)]
pub fn max_temp_c() -> Option<f32> {
    #[cfg(target_os = "linux")]
    let t = lx::read_thermal(std::path::Path::new("/sys/class")).max_c;
    #[cfg(not(target_os = "linux"))]
    let t = None;
    t
}

/// Per-process GPU utilization percent (pid -> 0..100), as last computed by the background poller
/// (every `GPU_EVERY`). Linux only: DRM fdinfo `drm-engine-*` deltas (kernel >= 5.19; amdgpu,
/// i915, xe, msm, panfrost, v3d...) plus `nvidia-smi pmon` SM% when NVIDIA is present. Only
/// processes whose /proc/<pid>/fd we may read are seen (own uid, or all with root/CAP_SYS_PTRACE).
/// Empty on macOS or when no ExtrasCache is running.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn proc_gpu() -> HashMap<u32, f32> {
    PROC_GPU.lock().ok().and_then(|m| m.clone()).unwrap_or_default()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
static PROC_GPU: Mutex<Option<HashMap<u32, f32>>> = Mutex::new(None);

#[cfg_attr(target_os = "linux", allow(dead_code))]
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
#[allow(dead_code)]
pub fn sysctl_i32(_name: &str) -> Option<i32> {
    None
}

// ---------------------------------------------------------------------------------------------
// Thermal (pmset -g therm)

#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn thermal() -> String {
    if cfg!(target_os = "linux") {
        return lx::read_thermal(std::path::Path::new("/sys/class")).level.to_string();
    }
    if !cfg!(target_os = "macos") {
        return "unknown".into();
    }
    run("pmset", &["-g", "therm"]).map(|s| parse_therm(&s).to_string()).unwrap_or_else(|| "unknown".into())
}

/// Parse `pmset -g therm`. Uses CPU_Speed_Limit when present, else thermal warning level, else
/// the "No thermal warning" note.
#[cfg_attr(target_os = "linux", allow(dead_code))]
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

#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn gpus() -> Vec<Gpu> {
    if cfg!(target_os = "linux") {
        return lx::GpuSampler::default().sample().0;
    }
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    run("ioreg", &["-r", "-d", "1", "-c", "IOAccelerator"]).map(|s| parse_ioreg_gpus(&s)).unwrap_or_default()
}

/// Parse `ioreg -r -d 1 -c IOAccelerator`. Each top-level entry starts with a line beginning "+-o".
#[cfg_attr(target_os = "linux", allow(dead_code))]
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
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn dict_num(s: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\"=");
    let idx = s.find(&pat)? + pat.len();
    let digits: String = s[idx..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

// ---------------------------------------------------------------------------------------------
// Battery (pmset -g batt)

pub fn battery() -> (Option<f32>, Option<bool>) {
    if cfg!(target_os = "linux") {
        return lx::read_battery(std::path::Path::new("/sys/class/power_supply"));
    }
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
    if cfg!(target_os = "linux") {
        let brand = sys.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_default();
        let os = lx::os_pretty(std::path::Path::new("/"))
            .or_else(sysinfo::System::long_os_version)
            .unwrap_or_else(|| "Linux".into());
        let cpu = lx::cpu_model(std::path::Path::new("/"), &brand, sys.cpus().len(), std::env::consts::ARCH);
        return (host, os, cpu);
    }
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
    #[cfg(not(target_os = "macos"))]
    let _ = looks_bad;
    #[cfg(target_os = "macos")]
    if looks_bad
        && let Ok(o) = std::process::Command::new("/usr/sbin/scutil").args(["--get", "LocalHostName"]).output()
    {
        let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if o.status.success() && !name.is_empty() {
            return name;
        }
    }
    if raw.is_empty() { "unknown".into() } else { raw }
}

// ---------------------------------------------------------------------------------------------
// Linux readers. Pure std::fs over a caller-supplied root so they compile (and are tested) on every
// platform; only the dispatchers above call them at runtime, and only on Linux.

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod lx {
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use crate::model::{Gpu, Psi};

    fn rd(p: &Path) -> Option<String> {
        fs::read_to_string(p).ok().map(|s| s.trim().to_string())
    }

    fn rd_num<T: std::str::FromStr>(p: &Path) -> Option<T> {
        rd(p)?.parse().ok()
    }

    /// Sorted entries of `dir` whose file name starts with `prefix`.
    fn entries(dir: &Path, prefix: &str) -> Vec<PathBuf> {
        let Ok(rd) = fs::read_dir(dir) else { return Vec::new() };
        let mut v: Vec<PathBuf> = rd
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
            .map(|e| e.path())
            .collect();
        v.sort();
        v
    }

    // ---- PSI ----------------------------------------------------------------------------------

    /// Parse one /proc/pressure/<res> file -> (some avg10, full avg10). Real content (6.x):
    /// ```text
    /// some avg10=1.53 avg60=0.87 avg300=0.40 total=3489715
    /// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
    /// ```
    /// /proc/pressure/cpu has only `some` before 5.13 (a zero `full` line after).
    pub fn parse_psi_file(s: &str) -> (Option<f32>, Option<f32>) {
        let mut some = None;
        let mut full = None;
        for line in s.lines() {
            let mut it = line.split_whitespace();
            let kind = it.next();
            let avg10 = it.find_map(|kv| kv.strip_prefix("avg10=")).and_then(|v| v.parse::<f32>().ok());
            match kind {
                Some("some") => some = avg10,
                Some("full") => full = avg10,
                _ => {}
            }
        }
        (some, full)
    }

    /// `dir` is normally /proc/pressure. None when no file is readable (no CONFIG_PSI, psi=0 —
    /// then reads fail with EOPNOTSUPP — or a container hiding it).
    pub fn read_psi(dir: &Path) -> Option<Psi> {
        let cpu = rd(&dir.join("cpu")).map(|s| parse_psi_file(&s));
        let mem = rd(&dir.join("memory")).map(|s| parse_psi_file(&s));
        let io = rd(&dir.join("io")).map(|s| parse_psi_file(&s));
        if cpu.is_none() && mem.is_none() && io.is_none() {
            return None;
        }
        let (cpu, mem, io) = (cpu.unwrap_or_default(), mem.unwrap_or_default(), io.unwrap_or_default());
        Some(Psi {
            cpu_some: cpu.0.unwrap_or(0.0),
            mem_some: mem.0.unwrap_or(0.0),
            mem_full: mem.1.unwrap_or(0.0),
            io_some: io.0.unwrap_or(0.0),
            io_full: io.1.unwrap_or(0.0),
        })
    }

    pub fn pressure_from_psi(p: &Psi) -> &'static str {
        if p.mem_full > 10.0 || p.mem_some > 40.0 {
            "critical"
        } else if p.mem_some > 10.0 {
            "warn"
        } else {
            "normal"
        }
    }

    /// (MemTotal, MemAvailable) in kB from /proc/meminfo.
    pub fn parse_meminfo(s: &str) -> (Option<u64>, Option<u64>) {
        let field = |name: &str| {
            s.lines()
                .find_map(|l| l.strip_prefix(name))
                .and_then(|r| r.trim_start_matches(':').split_whitespace().next()?.parse().ok())
        };
        (field("MemTotal:"), field("MemAvailable:"))
    }

    pub fn pressure_from_meminfo(total_kb: u64, avail_kb: u64) -> &'static str {
        if total_kb == 0 {
            return "unknown";
        }
        let frac = avail_kb as f64 / total_kb as f64;
        if frac < 0.05 {
            "critical"
        } else if frac < 0.15 {
            "warn"
        } else {
            "normal"
        }
    }

    /// `proc_root` is normally /proc. PSI memory first, MemAvailable/MemTotal fallback.
    pub fn mem_pressure_at(proc_root: &Path) -> &'static str {
        if let Some(p) = read_psi(&proc_root.join("pressure"))
            && rd(&proc_root.join("pressure/memory")).is_some()
        {
            return pressure_from_psi(&p);
        }
        match rd(&proc_root.join("meminfo")).map(|s| parse_meminfo(&s)) {
            Some((Some(t), Some(a))) => pressure_from_meminfo(t, a),
            _ => "unknown",
        }
    }

    // ---- Thermal ------------------------------------------------------------------------------

    #[derive(Debug, Clone, PartialEq)]
    pub struct Thermal {
        pub max_c: Option<f32>,
        /// "nominal" | "fair" | "serious" | "critical" | "unknown".
        pub level: &'static str,
    }

    /// Used when a sensor exposes no trip/max/crit (typical CPU Tjmax is ~100°C).
    const DEFAULT_PASSIVE_C: f32 = 95.0;
    const DEFAULT_CRIT_C: f32 = 105.0;

    fn valid_c(c: f32) -> bool {
        c > -40.0 && c < 200.0
    }

    fn milli(p: &Path) -> Option<f32> {
        let v: i64 = rd_num(p)?;
        let c = v as f32 / 1000.0;
        valid_c(c).then_some(c)
    }

    /// For a CPU package sensor (unknown trips default to Tjmax-like values): 0 nominal, 1 fair
    /// (>= passive: throttling has begun), 2 serious (halfway from passive to critical, at most
    /// passive + 10), 3 critical (>= critical). Below the passive trip is always nominal: a CPU
    /// at 80°C under a build is hot, not throttled.
    pub fn level_for(t: f32, passive: Option<f32>, crit: Option<f32>) -> u8 {
        let crit = crit.unwrap_or(DEFAULT_CRIT_C);
        let passive = passive.filter(|p| *p < crit).unwrap_or(DEFAULT_PASSIVE_C.min(crit));
        level_trips(t, Some(passive), None, Some(crit))
    }

    /// Level from real trip points only (no defaults): a missing passive/hot trip means that
    /// sensor can't say "throttling", only "critical" (if it has that trip).
    fn level_trips(t: f32, passive: Option<f32>, hot: Option<f32>, crit: Option<f32>) -> u8 {
        if crit.is_some_and(|c| t >= c) {
            return 3;
        }
        let Some(p) = passive.or(hot) else { return 0 };
        let serious = hot.filter(|h| *h > p).unwrap_or_else(|| match crit {
            Some(c) if c > p => (p + (c - p) / 2.0).min(p + 10.0),
            _ => p + 10.0,
        });
        if t >= serious {
            2
        } else if t >= p {
            1
        } else {
            0
        }
    }

    /// hwmon drivers that measure the CPU package/die (their _max/_crit are the CPU's own
    /// throttling points). Others (nvme, iwlwifi, amdgpu, acpi fan…) only feed `max_c`.
    const CPU_HWMON: [&str; 5] = ["coretemp", "k10temp", "zenpower", "cpu_thermal", "cpu-thermal"];

    const LEVELS: [&str; 4] = ["nominal", "fair", "serious", "critical"];

    /// `class` is normally /sys/class. `max_c` is the hottest sensor of any kind; `level` (the
    /// throttling state) only comes from CPU sources, each at its own real throttle points:
    /// * thermal/thermal_zone*/temp (m°C) with trip_point_N_{temp,type}; types are
    ///   active (fan steps, ignored) | passive (throttling starts) | hot | critical (shutdown).
    ///   e.g. x86_pkg_temp: temp=48000, trip_point_0_type=passive, trip_point_0_temp=95000;
    ///   acpitz: trip_point_0_type=critical, trip_point_0_temp=119000 (critical only).
    /// * hwmon/hwmon*/temp*_input with temp*_max (as passive) / temp*_crit of CPU drivers, e.g.
    ///   coretemp temp1_input=52000 temp1_max=100000 temp1_crit=100000; k10temp only
    ///   temp1_input (Tctl). An NVMe's temp1_max (~82°C) is the drive's, not a CPU throttle.
    ///   `drivetemp` (SATA disks via SMART) is skipped: reading it can be slow / wake disks.
    pub fn read_thermal(class: &Path) -> Thermal {
        let mut max_c: Option<f32> = None;
        let mut level = 0u8;
        let mut any = false;
        let mut see = |t: f32, lvl: u8| {
            any = true;
            max_c = Some(max_c.map_or(t, |m: f32| m.max(t)));
            level = level.max(lvl);
        };
        for z in entries(&class.join("thermal"), "thermal_zone") {
            let Some(t) = milli(&z.join("temp")) else { continue };
            if rd(&z.join("mode")).is_some_and(|m| m == "disabled") {
                continue;
            }
            let (mut passive, mut hot, mut crit): (Option<f32>, Option<f32>, Option<f32>) = (None, None, None);
            for i in 0..32 {
                let Some(ty) = rd(&z.join(format!("trip_point_{i}_type"))) else { break };
                let Some(tt) = milli(&z.join(format!("trip_point_{i}_temp"))).filter(|c| *c > 0.0) else { continue };
                let slot = match ty.as_str() {
                    "passive" => &mut passive,
                    "hot" => &mut hot,
                    "critical" => &mut crit,
                    _ => continue,
                };
                *slot = Some(slot.map_or(tt, |c: f32| c.min(tt)));
            }
            see(t, level_trips(t, passive, hot, crit));
        }
        for h in entries(&class.join("hwmon"), "hwmon") {
            let name = rd(&h.join("name")).unwrap_or_default();
            if name == "drivetemp" {
                continue;
            }
            let cpu = CPU_HWMON.contains(&name.as_str());
            let Ok(dir) = fs::read_dir(&h) else { continue };
            let mut inputs: Vec<String> = dir
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("temp") && n.ends_with("_input"))
                .collect();
            inputs.sort();
            for n in inputs {
                let base = n.trim_end_matches("_input");
                let Some(t) = milli(&h.join(&n)) else { continue };
                let max = milli(&h.join(format!("{base}_max"))).filter(|c| *c > 0.0);
                let crit = milli(&h.join(format!("{base}_crit"))).filter(|c| *c > 0.0);
                see(t, if cpu { level_for(t, max, crit) } else { 0 });
            }
        }
        Thermal { max_c, level: if any { LEVELS[level as usize] } else { "unknown" } }
    }

    // ---- Battery ------------------------------------------------------------------------------

    /// `dir` is normally /sys/class/power_supply. Returns (percent, on_battery) with macOS
    /// semantics: no system battery -> (None, None). Peripheral batteries (scope=Device: mice,
    /// headsets) are ignored. Real BAT0: type=Battery status=Discharging capacity=57
    /// energy_now=28860000 energy_full=50640000; AC adapter: type=Mains online=0.
    pub fn read_battery(dir: &Path) -> (Option<f32>, Option<bool>) {
        let mut bats: Vec<(f32, Option<f64>, String)> = Vec::new(); // (pct, full weight, status)
        let mut mains: Vec<bool> = Vec::new();
        for e in entries(dir, "") {
            let ty = rd(&e.join("type")).unwrap_or_default();
            match ty.as_str() {
                "Battery" => {
                    if rd(&e.join("scope")).is_some_and(|s| s == "Device") {
                        continue;
                    }
                    if rd(&e.join("present")).is_some_and(|s| s == "0") {
                        continue;
                    }
                    let now_full = |a: &str, b: &str| -> Option<(f64, f64)> {
                        let n: f64 = rd_num(&e.join(a))?;
                        let f: f64 = rd_num(&e.join(b))?;
                        (f > 0.0).then_some((n, f))
                    };
                    let nf = now_full("energy_now", "energy_full").or_else(|| now_full("charge_now", "charge_full"));
                    let pct = rd_num::<f32>(&e.join("capacity"))
                        .or_else(|| nf.map(|(n, f)| (n / f * 100.0) as f32))
                        .map(|p| p.clamp(0.0, 100.0));
                    let Some(pct) = pct else { continue };
                    bats.push((pct, nf.map(|x| x.1), rd(&e.join("status")).unwrap_or_default()));
                }
                "Mains" | "USB" | "USB_C" | "USB_PD" => {
                    if let Some(o) = rd(&e.join("online")) {
                        mains.push(o == "1");
                    }
                }
                _ => {}
            }
        }
        if bats.is_empty() {
            return (None, None);
        }
        let pct = if bats.iter().all(|b| b.1.is_some()) {
            let tot: f64 = bats.iter().map(|b| b.1.unwrap()).sum();
            (bats.iter().map(|b| b.0 as f64 * b.1.unwrap()).sum::<f64>() / tot) as f32
        } else {
            bats.iter().map(|b| b.0).sum::<f32>() / bats.len() as f32
        };
        let on_batt = if mains.iter().any(|o| *o) {
            Some(false)
        } else if bats.iter().any(|b| b.2 == "Discharging") {
            Some(true)
        } else if bats.iter().any(|b| matches!(b.2.as_str(), "Charging" | "Full" | "Not charging")) {
            Some(false)
        } else if !mains.is_empty() {
            Some(true)
        } else {
            None
        };
        (Some(pct), on_batt)
    }

    // ---- Static info --------------------------------------------------------------------------

    /// PRETTY_NAME from <root>/etc/os-release (or usr/lib/os-release).
    pub fn os_pretty(root: &Path) -> Option<String> {
        let s = rd(&root.join("etc/os-release")).or_else(|| rd(&root.join("usr/lib/os-release")))?;
        s.lines()
            .find_map(|l| l.strip_prefix("PRETTY_NAME="))
            .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|v| !v.is_empty())
    }

    fn arm_implementer(code: &str) -> Option<&'static str> {
        let v = u32::from_str_radix(code.trim().trim_start_matches("0x"), 16).ok()?;
        Some(match v {
            0x41 => "ARM",
            0x42 => "Broadcom",
            0x43 => "Cavium",
            0x46 => "Fujitsu",
            0x48 => "HiSilicon",
            0x4e => "NVIDIA",
            0x50 => "AppliedMicro",
            0x51 => "Qualcomm",
            0x53 => "Samsung",
            0x56 => "Marvell",
            0x61 => "Apple",
            0x69 => "Intel",
            0x6d => "Microsoft",
            0xc0 => "Ampere",
            _ => return None,
        })
    }

    /// CPU model: /proc/cpuinfo "model name" (x86, some ARM) -> sysinfo brand -> "Hardware"
    /// (32-bit ARM) -> device-tree model (Raspberry Pi etc.) -> "<implementer> <arch> (N cores)"
    /// -> "<arch> (N cores)". Never "unknown".
    pub fn cpu_model(root: &Path, brand: &str, cores: usize, arch: &str) -> String {
        let info = rd(&root.join("proc/cpuinfo")).unwrap_or_default();
        let field = |name: &str| {
            info.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                (k.trim() == name).then(|| v.trim().to_string()).filter(|v| !v.is_empty())
            })
        };
        let cores = if cores > 0 {
            cores
        } else {
            info.lines().filter(|l| l.split(':').next().is_some_and(|k| k.trim() == "processor")).count()
        };
        let generic = |b: &str| b.is_empty() || b.eq_ignore_ascii_case("unknown") || b.len() <= 3;
        if let Some(m) = field("model name").filter(|m| !generic(m)) {
            return m;
        }
        if !generic(brand) && brand.contains(' ') {
            return brand.to_string();
        }
        if let Some(h) = field("Hardware") {
            return h;
        }
        let dt = fs::read(root.join("sys/firmware/devicetree/base/model"))
            .ok()
            .map(|b| String::from_utf8_lossy(&b).trim_matches(char::from(0)).trim().to_string())
            .filter(|s| !s.is_empty());
        if let Some(m) = dt {
            return m;
        }
        let suffix = if cores > 0 { format!(" ({cores} cores)") } else { String::new() };
        if let Some(v) = field("CPU implementer").as_deref().and_then(arm_implementer) {
            return format!("{v} {arch}{suffix}");
        }
        if !generic(brand) {
            return format!("{brand} {arch}{suffix}");
        }
        format!("{arch}{suffix}")
    }

    // ---- GPU: sysfs DRM -----------------------------------------------------------------------

    #[derive(Debug, Clone, PartialEq)]
    pub struct DrmCard {
        pub name: String,
        pub driver: String,
        /// PCI slot ("0000:03:00.0") or platform device name ("fde60000.gpu"); matches drm-pdev.
        pub pdev: String,
        pub vendor: u32,
        pub busy: Option<f32>,
        pub vram_used: Option<u64>,
    }

    fn vendor_name(v: u32) -> &'static str {
        match v {
            0x1002 => "AMD",
            0x10de => "NVIDIA",
            0x8086 => "Intel",
            0x1af4 => "virtio",
            0x15ad => "VMware",
            0x1234 => "QEMU",
            0x5143 => "Qualcomm",
            0x1a03 => "ASPEED",
            0x102b => "Matrox",
            _ => "",
        }
    }

    /// Platform (non-PCI) drivers that are real GPUs (render engines), not display-only.
    const PLATFORM_GPUS: &[&str] = &["panfrost", "panthor", "lima", "msm", "v3d", "etnaviv", "asahi", "tegra", "pvr", "imagination"];

    fn hexnum(s: &str) -> Option<u32> {
        u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()
    }

    /// `drm` is normally /sys/class/drm. Lists card<N> GPUs (not connectors like card0-HDMI-A-1).
    /// amdgpu: device/gpu_busy_percent (e.g. "37"), device/mem_info_vram_used (bytes),
    /// sometimes device/product_name. Display-only PCI devices (class not 0x03xxxx) are skipped.
    pub fn read_drm_cards(drm: &Path) -> Vec<DrmCard> {
        let mut out = Vec::new();
        for c in entries(drm, "card") {
            let fname = c.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
            if !fname["card".len()..].chars().all(|ch| ch.is_ascii_digit()) || fname.len() == 4 {
                continue;
            }
            let dev = c.join("device");
            let uevent = rd(&dev.join("uevent")).unwrap_or_default();
            let ue = |k: &str| uevent.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')).map(str::to_string);
            let driver = ue("DRIVER")
                .or_else(|| fs::read_link(dev.join("driver")).ok()?.file_name().map(|f| f.to_string_lossy().into_owned()))
                .unwrap_or_default();
            let vendor = rd(&dev.join("vendor")).and_then(|v| hexnum(&v));
            let class = rd(&dev.join("class")).and_then(|v| hexnum(&v));
            match vendor {
                Some(_) => {
                    if class.is_some_and(|k| k >> 16 != 0x03) {
                        continue;
                    }
                }
                None if PLATFORM_GPUS.contains(&driver.as_str()) => {}
                None => continue, // simpledrm, vkms, display controllers
            }
            let pdev = ue("PCI_SLOT_NAME")
                .or_else(|| fs::canonicalize(&dev).ok()?.file_name().map(|f| f.to_string_lossy().into_owned()))
                .unwrap_or_default();
            let device_id = rd(&dev.join("device")).and_then(|v| hexnum(&v));
            let name = rd(&dev.join("product_name")).filter(|n| !n.is_empty()).unwrap_or_else(|| {
                let v = vendor.map(vendor_name).filter(|v| !v.is_empty());
                match (v, device_id) {
                    (Some(v), Some(d)) => format!("{v} GPU {d:04x} ({driver})"),
                    (Some(v), None) => format!("{v} GPU ({driver})"),
                    _ if !driver.is_empty() => format!("{driver} GPU"),
                    _ => "GPU".into(),
                }
            });
            out.push(DrmCard {
                name,
                driver,
                pdev,
                vendor: vendor.unwrap_or(0),
                busy: rd_num::<f32>(&dev.join("gpu_busy_percent")),
                vram_used: rd_num(&dev.join("mem_info_vram_used")),
            });
        }
        out
    }

    // ---- GPU: DRM fdinfo (per-client engine time, kernel >= 5.19) -----------------------------

    /// One DRM client as seen through /proc/<pid>/fdinfo/<fd>. Real amdgpu content:
    /// ```text
    /// drm-driver: amdgpu
    /// drm-client-id: 62
    /// drm-pdev: 0000:03:00.0
    /// drm-memory-vram: 190464 KiB
    /// drm-engine-gfx: 1523784738 ns
    /// drm-engine-compute: 0 ns
    /// ```
    /// i915 adds `drm-engine-capacity-video: 2`; xe reports `drm-cycles-rcs: N` with
    /// `drm-total-cycles-rcs: M` instead of ns.
    #[derive(Debug, Clone, Default, PartialEq)]
    pub struct DrmClient {
        pub driver: String,
        pub pdev: String,
        pub client_id: u64,
        /// engine -> busy ns
        pub engines: HashMap<String, u64>,
        pub capacity: HashMap<String, u64>,
        /// engine -> (cycles, total cycles)
        pub cycles: HashMap<String, (u64, u64)>,
    }

    pub fn parse_drm_fdinfo(s: &str) -> Option<DrmClient> {
        let mut c = DrmClient::default();
        let mut have_id = false;
        let mut cyc: HashMap<String, u64> = HashMap::new();
        let mut tot: HashMap<String, u64> = HashMap::new();
        for line in s.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            let (k, v) = (k.trim(), v.trim());
            let num = || v.split_whitespace().next().and_then(|n| n.parse::<u64>().ok());
            if k == "drm-driver" {
                c.driver = v.to_string();
            } else if k == "drm-pdev" {
                c.pdev = v.to_string();
            } else if k == "drm-client-id" {
                c.client_id = num()?;
                have_id = true;
            } else if let Some(e) = k.strip_prefix("drm-engine-capacity-") {
                c.capacity.insert(e.to_string(), num().unwrap_or(1).max(1));
            } else if let Some(e) = k.strip_prefix("drm-engine-") {
                if let Some(n) = num() {
                    c.engines.insert(e.to_string(), n);
                }
            } else if let Some(e) = k.strip_prefix("drm-total-cycles-") {
                if let Some(n) = num() {
                    tot.insert(e.to_string(), n);
                }
            } else if let Some(e) = k.strip_prefix("drm-cycles-")
                && let Some(n) = num()
            {
                cyc.insert(e.to_string(), n);
            }
        }
        for (e, n) in cyc {
            if let Some(t) = tot.get(&e) {
                c.cycles.insert(e, (n, *t));
            }
        }
        (have_id && !c.driver.is_empty()).then_some(c)
    }

    /// Walk `proc_root`/<pid>/fd, and for each fd that links into /dev/dri/ parse its fdinfo.
    /// Unreadable processes (other users without CAP_SYS_PTRACE) are silently skipped. A client
    /// shared by several fds of one pid is reported once.
    pub fn scan_drm_clients(proc_root: &Path) -> Vec<(u32, DrmClient)> {
        let mut out = Vec::new();
        let Ok(dir) = fs::read_dir(proc_root) else { return out };
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let Ok(fds) = fs::read_dir(e.path().join("fd")) else { continue };
            let mut seen: HashSet<(String, u64)> = HashSet::new();
            for fd in fds.flatten() {
                let Ok(target) = fs::read_link(fd.path()) else { continue };
                if !target.starts_with("/dev/dri/") {
                    continue;
                }
                let info = e.path().join("fdinfo").join(fd.file_name());
                let Some(c) = rd(&info).and_then(|s| parse_drm_fdinfo(&s)) else { continue };
                if seen.insert((c.pdev.clone(), c.client_id)) {
                    out.push((pid, c));
                }
            }
        }
        out
    }

    /// Per-engine busy fraction (0..1) between two samples of one client.
    fn engine_busy(prev: &DrmClient, cur: &DrmClient, dt_ns: f64) -> HashMap<String, f64> {
        let mut m = HashMap::new();
        if dt_ns <= 0.0 {
            return m;
        }
        for (e, n) in &cur.engines {
            let Some(p) = prev.engines.get(e) else { continue };
            let cap = *cur.capacity.get(e).unwrap_or(&1) as f64;
            let d = n.saturating_sub(*p) as f64;
            m.insert(e.clone(), (d / (dt_ns * cap)).min(1.0));
        }
        for (e, (c, t)) in &cur.cycles {
            let Some((pc, pt)) = prev.cycles.get(e) else { continue };
            let dt = t.saturating_sub(*pt) as f64;
            if dt > 0.0 {
                let cap = *cur.capacity.get(e).unwrap_or(&1) as f64;
                m.insert(e.clone(), (c.saturating_sub(*pc) as f64 / (dt * cap)).min(1.0));
            }
        }
        m
    }

    /// Utilization from two fdinfo scans `dt` apart -> (per pid %, per pdev %). A pid's value is
    /// its busiest engine (summed over its clients); a device's is its busiest engine summed over
    /// distinct clients (deduped by client id, since forked children share the fd).
    pub fn drm_util(
        prev: &[(u32, DrmClient)],
        cur: &[(u32, DrmClient)],
        dt: Duration,
    ) -> (HashMap<u32, f32>, HashMap<String, f32>) {
        let dt_ns = dt.as_nanos() as f64;
        let idx: HashMap<(u32, &str, u64), &DrmClient> =
            prev.iter().map(|(p, c)| ((*p, c.pdev.as_str(), c.client_id), c)).collect();
        let mut per_pid: HashMap<u32, HashMap<String, f64>> = HashMap::new();
        let mut per_dev: HashMap<String, HashMap<String, f64>> = HashMap::new();
        let mut dev_seen: HashSet<(String, u64)> = HashSet::new();
        for (pid, c) in cur {
            let Some(p) = idx.get(&(*pid, c.pdev.as_str(), c.client_id)) else { continue };
            let busy = engine_busy(p, c, dt_ns);
            let pe = per_pid.entry(*pid).or_default();
            for (e, b) in &busy {
                *pe.entry(e.clone()).or_default() += b;
            }
            let dev_key = if c.pdev.is_empty() { c.driver.clone() } else { c.pdev.clone() };
            if dev_seen.insert((dev_key.clone(), c.client_id)) {
                let de = per_dev.entry(dev_key).or_default();
                for (e, b) in busy {
                    *de.entry(e).or_default() += b;
                }
            }
        }
        let top = |m: HashMap<String, f64>| (m.into_values().fold(0.0, f64::max).min(1.0) * 100.0) as f32;
        (
            per_pid.into_iter().map(|(k, v)| (k, top(v))).filter(|(_, v)| *v > 0.0).collect(),
            per_dev.into_iter().map(|(k, v)| (k, top(v))).collect(),
        )
    }

    // ---- GPU: NVIDIA via nvidia-smi -----------------------------------------------------------

    /// `nvidia-smi --query-gpu=name,utilization.gpu,memory.used --format=csv,noheader,nounits`:
    /// `NVIDIA GeForce RTX 4090, 37, 2345` (memory in MiB; "[N/A]" possible).
    pub fn parse_nvidia_query(s: &str) -> Vec<Gpu> {
        s.lines()
            .filter_map(|l| {
                let mut it = l.rsplitn(3, ',');
                let mem = it.next()?.trim();
                let util = it.next()?.trim();
                let name = it.next()?.trim();
                if name.is_empty() {
                    return None;
                }
                Some(Gpu {
                    name: name.to_string(),
                    util: util.parse().unwrap_or(0.0),
                    mem_used: mem.parse::<u64>().map(|m| m * 1024 * 1024).unwrap_or(0),
                })
            })
            .collect()
    }

    /// `nvidia-smi pmon -c 1 -s u`:
    /// ```text
    /// # gpu         pid   type     sm    mem    enc    dec    jpg    ofa    command
    /// # Idx           #    C/G      %      %      %      %      %      %    name
    ///     0       2345     G     12      3      -      -      -      -    Xorg
    ///     0          -     -      -      -      -      -      -      -    -
    /// ```
    pub fn parse_nvidia_pmon(s: &str) -> HashMap<u32, f32> {
        let mut m: HashMap<u32, f32> = HashMap::new();
        for l in s.lines().filter(|l| !l.trim_start().starts_with('#')) {
            let t: Vec<&str> = l.split_whitespace().collect();
            let (Some(pid), Some(sm)) = (t.get(1).and_then(|p| p.parse::<u32>().ok()), t.get(3)) else { continue };
            let sm: f32 = sm.parse().unwrap_or(0.0);
            *m.entry(pid).or_default() += sm;
        }
        m.retain(|_, v| {
            *v = v.min(100.0);
            *v > 0.0
        });
        m
    }

    fn find_in_path(bin: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .chain(["/usr/bin", "/usr/local/bin", "/usr/local/nvidia/bin", "/opt/nvidia/bin"].map(PathBuf::from))
            .map(|d| d.join(bin))
            .find(|p| p.is_file())
    }

    /// Run a command we spawned ourselves, killing it after `timeout`.
    fn run_timeout(cmd: &Path, args: &[&str], timeout: Duration) -> Option<String> {
        use std::io::Read;
        use std::process::Stdio;
        let mut child = std::process::Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(st)) => {
                    let mut s = String::new();
                    child.stdout.take()?.read_to_string(&mut s).ok()?;
                    return st.success().then_some(s);
                }
                Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }

    // ---- GPU sampler (background thread state) ------------------------------------------------

    /// Holds the previous fdinfo scan so utilization can be computed from engine-time deltas.
    #[derive(Default)]
    pub struct GpuSampler {
        prev: Option<(Instant, Vec<(u32, DrmClient)>)>,
        nvidia: Option<Option<PathBuf>>,
    }

    impl GpuSampler {
        /// Device list (NVIDIA via nvidia-smi + DRM cards) and per-process GPU % (pid -> 0..100).
        pub fn sample(&mut self) -> (Vec<Gpu>, HashMap<u32, f32>) {
            let mut gpus = Vec::new();
            let mut per_pid: HashMap<u32, f32> = HashMap::new();
            let nv = self.nvidia.get_or_insert_with(|| find_in_path("nvidia-smi")).clone();
            if let Some(nv) = &nv {
                let t = Duration::from_secs(1);
                let q = ["--query-gpu=name,utilization.gpu,memory.used", "--format=csv,noheader,nounits"];
                if let Some(s) = run_timeout(nv, &q, t) {
                    gpus.extend(parse_nvidia_query(&s));
                }
                if let Some(s) = run_timeout(nv, &["pmon", "-c", "1", "-s", "u"], t) {
                    per_pid.extend(parse_nvidia_pmon(&s));
                }
            }
            let have_nv = !gpus.is_empty();
            let cards = read_drm_cards(Path::new("/sys/class/drm"));
            // fdinfo walks every fd of every process: only worth it when a render node exists.
            let dev_util = if Path::new("/dev/dri").is_dir() && !cards.is_empty() {
                let now = Instant::now();
                let cur = scan_drm_clients(Path::new("/proc"));
                let (pp, dev) = match &self.prev {
                    Some((t, prev)) => drm_util(prev, &cur, now - *t),
                    None => Default::default(),
                };
                self.prev = Some((now, cur));
                for (pid, u) in pp {
                    let e = per_pid.entry(pid).or_default();
                    *e = (*e + u).min(100.0);
                }
                dev
            } else {
                HashMap::new()
            };
            for c in cards {
                if have_nv && (c.vendor == 0x10de || c.driver == "nvidia") {
                    continue;
                }
                let util = c
                    .busy
                    .or_else(|| dev_util.get(&c.pdev).copied())
                    .or_else(|| dev_util.get(&c.driver).copied())
                    .unwrap_or(0.0);
                gpus.push(Gpu { name: c.name, util, mem_used: c.vram_used.unwrap_or(0) });
            }
            (gpus, per_pid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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

    // ---- Linux readers against fixture trees (run on every platform) ----------------------------

    use std::path::PathBuf;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(name: &str) -> Self {
            let d = std::env::temp_dir().join(format!("fat-sys-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Fixture(d)
        }
        fn put(&self, rel: &str, content: &str) -> &Self {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
            self
        }
        #[cfg(unix)]
        fn link(&self, rel: &str, target: &str) -> &Self {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, p).unwrap();
            self
        }
        fn p(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn psi_parse_and_pressure() {
        let f = Fixture::new("psi");
        f.put("proc/pressure/cpu", "some avg10=3.25 avg60=1.10 avg300=0.40 total=12345678\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
            .put("proc/pressure/memory", "some avg10=12.50 avg60=4.00 avg300=1.00 total=999\nfull avg10=2.00 avg60=1.00 avg300=0.30 total=500\n")
            .put("proc/pressure/io", "some avg10=0.81 avg60=0.33 avg300=0.10 total=4000\nfull avg10=0.50 avg60=0.20 avg300=0.05 total=2500\n");
        let p = lx::read_psi(&f.p("proc/pressure")).unwrap();
        assert_eq!(p, Psi { cpu_some: 3.25, mem_some: 12.5, mem_full: 2.0, io_some: 0.81, io_full: 0.5 });
        assert_eq!(lx::mem_pressure_at(&f.p("proc")), "warn");
        // Pre-5.13 cpu file: only "some".
        assert_eq!(lx::parse_psi_file("some avg10=0.10 avg60=0.00 avg300=0.00 total=1\n"), (Some(0.1), None));
        assert!(lx::read_psi(&f.p("nope")).is_none());

        let mk = |s, fu| Psi { mem_some: s, mem_full: fu, ..Default::default() };
        assert_eq!(lx::pressure_from_psi(&mk(0.0, 0.0)), "normal");
        assert_eq!(lx::pressure_from_psi(&mk(10.5, 0.0)), "warn");
        assert_eq!(lx::pressure_from_psi(&mk(41.0, 0.0)), "critical");
        assert_eq!(lx::pressure_from_psi(&mk(20.0, 10.5)), "critical");
    }

    #[test]
    fn meminfo_fallback() {
        let f = Fixture::new("meminfo");
        let mi = |avail: u64| {
            format!(
                "MemTotal:       16337068 kB\nMemFree:          912344 kB\nMemAvailable:   {avail:>8} kB\nBuffers:          302112 kB\nCached:          9071312 kB\nSwapCached:            0 kB\n"
            )
        };
        f.put("proc/meminfo", &mi(12_000_000));
        assert_eq!(lx::mem_pressure_at(&f.p("proc")), "normal"); // no PSI dir -> meminfo
        f.put("proc/meminfo", &mi(1_600_000));
        assert_eq!(lx::mem_pressure_at(&f.p("proc")), "warn");
        f.put("proc/meminfo", &mi(500_000));
        assert_eq!(lx::mem_pressure_at(&f.p("proc")), "critical");
        assert_eq!(lx::parse_meminfo("MemTotal: 100 kB\n"), (Some(100), None));
        assert_eq!(lx::mem_pressure_at(&f.p("missing")), "unknown");
    }

    #[test]
    fn thermal_zones_and_hwmon() {
        let f = Fixture::new("therm");
        assert_eq!(lx::read_thermal(&f.p("class")), lx::Thermal { max_c: None, level: "unknown" });
        // Laptop: acpitz (critical trip only) + x86_pkg_temp (passive 95) + coretemp hwmon.
        f.put("class/thermal/thermal_zone0/type", "acpitz\n")
            .put("class/thermal/thermal_zone0/temp", "27800\n")
            .put("class/thermal/thermal_zone0/trip_point_0_type", "critical\n")
            .put("class/thermal/thermal_zone0/trip_point_0_temp", "119000\n")
            .put("class/thermal/thermal_zone1/type", "x86_pkg_temp\n")
            .put("class/thermal/thermal_zone1/temp", "48000\n")
            .put("class/thermal/thermal_zone1/trip_point_0_type", "passive\n")
            .put("class/thermal/thermal_zone1/trip_point_0_temp", "95000\n")
            .put("class/thermal/thermal_zone1/trip_point_1_type", "critical\n")
            .put("class/thermal/thermal_zone1/trip_point_1_temp", "105000\n")
            .put("class/hwmon/hwmon2/name", "coretemp\n")
            .put("class/hwmon/hwmon2/temp1_label", "Package id 0\n")
            .put("class/hwmon/hwmon2/temp1_input", "52000\n")
            .put("class/hwmon/hwmon2/temp1_max", "100000\n")
            .put("class/hwmon/hwmon2/temp1_crit", "100000\n")
            .put("class/hwmon/hwmon2/temp2_input", "50000\n")
            .put("class/hwmon/hwmon3/name", "drivetemp\n")
            .put("class/hwmon/hwmon3/temp1_input", "99000\n"); // skipped
        let t = lx::read_thermal(&f.p("class"));
        assert_eq!(t, lx::Thermal { max_c: Some(52.0), level: "nominal" });
        f.put("class/thermal/thermal_zone1/temp", "80000\n"); // hot under a build, below the trip
        assert_eq!(lx::read_thermal(&f.p("class")).level, "nominal");
        f.put("class/hwmon/hwmon2/temp1_input", "90000\n"); // coretemp below its Tjmax-ish 95
        assert_eq!(lx::read_thermal(&f.p("class")).level, "nominal");
        f.put("class/hwmon/hwmon2/temp1_input", "52000\n");
        f.put("class/thermal/thermal_zone1/temp", "96000\n"); // passive trip 95 reached
        let t = lx::read_thermal(&f.p("class"));
        assert_eq!((t.max_c, t.level), (Some(96.0), "fair"));
        f.put("class/thermal/thermal_zone1/temp", "100500\n"); // halfway to critical 105
        assert_eq!(lx::read_thermal(&f.p("class")).level, "serious");
        f.put("class/thermal/thermal_zone1/temp", "60000\n");
        f.put("class/hwmon/hwmon2/temp1_input", "101000\n");
        assert_eq!(lx::read_thermal(&f.p("class")).level, "critical");
        // A hot NVMe (temp1_max 81.85) is a hot sensor, not CPU throttling.
        f.put("class/hwmon/hwmon2/temp1_input", "52000\n")
            .put("class/hwmon/hwmon4/name", "nvme\n")
            .put("class/hwmon/hwmon4/temp1_label", "Composite\n")
            .put("class/hwmon/hwmon4/temp1_input", "70850\n")
            .put("class/hwmon/hwmon4/temp1_max", "81850\n")
            .put("class/hwmon/hwmon4/temp1_crit", "84850\n");
        let t = lx::read_thermal(&f.p("class"));
        assert_eq!((t.max_c, t.level), (Some(70.85), "nominal"));
        f.put("class/hwmon/hwmon4/temp1_input", "86000\n");
        assert_eq!(lx::read_thermal(&f.p("class")).level, "nominal");
        // Bogus/unreadable sensors are ignored.
        let g = Fixture::new("therm2");
        g.put("class/hwmon/hwmon0/name", "k10temp\n")
            .put("class/hwmon/hwmon0/temp1_input", "61250\n")
            .put("class/hwmon/hwmon1/temp1_input", "-273000\n")
            .put("class/thermal/thermal_zone0/temp", "");
        assert_eq!(lx::read_thermal(&g.p("class")), lx::Thermal { max_c: Some(61.25), level: "nominal" });
        assert_eq!(lx::level_for(80.0, None, None), 0); // defaults: passive 95, crit 105
        assert_eq!(lx::level_for(76.0, Some(95.0), Some(100.0)), 0);
        assert_eq!(lx::level_for(95.0, None, None), 1);
        assert_eq!(lx::level_for(100.0, None, None), 2);
        assert_eq!(lx::level_for(85.0, None, Some(90.0)), 0); // crit 90 -> passive 90 capped: nominal
        assert_eq!(lx::level_for(90.0, None, Some(90.0)), 3);
    }

    #[test]
    fn battery_power_supply() {
        let f = Fixture::new("batt");
        assert_eq!(lx::read_battery(&f.p("ps")), (None, None));
        f.put("ps/AC/type", "Mains\n").put("ps/AC/online", "0\n");
        assert_eq!(lx::read_battery(&f.p("ps")), (None, None)); // desktop-like: no battery
        f.put("ps/BAT0/type", "Battery\n")
            .put("ps/BAT0/present", "1\n")
            .put("ps/BAT0/status", "Discharging\n")
            .put("ps/BAT0/capacity", "57\n")
            .put("ps/BAT0/energy_now", "28860000\n")
            .put("ps/BAT0/energy_full", "50640000\n")
            .put("ps/hidpp_battery_0/type", "Battery\n")
            .put("ps/hidpp_battery_0/scope", "Device\n")
            .put("ps/hidpp_battery_0/capacity", "5\n");
        assert_eq!(lx::read_battery(&f.p("ps")), (Some(57.0), Some(true)));
        f.put("ps/AC/online", "1\n").put("ps/BAT0/status", "Charging\n");
        assert_eq!(lx::read_battery(&f.p("ps")), (Some(57.0), Some(false)));
        // No capacity file: derive from charge_now/charge_full.
        let g = Fixture::new("batt2");
        g.put("ps/BAT1/type", "Battery\n")
            .put("ps/BAT1/status", "Full\n")
            .put("ps/BAT1/charge_now", "3000000\n")
            .put("ps/BAT1/charge_full", "4000000\n");
        assert_eq!(lx::read_battery(&g.p("ps")), (Some(75.0), Some(false)));
    }

    #[test]
    fn os_and_cpu_model() {
        let f = Fixture::new("static");
        f.put("etc/os-release", "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n");
        assert_eq!(lx::os_pretty(&f.0).as_deref(), Some("Ubuntu 24.04.1 LTS"));
        assert_eq!(lx::os_pretty(&f.p("none")), None);
        // x86
        f.put("proc/cpuinfo", "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz\n\nprocessor\t: 1\n");
        assert_eq!(lx::cpu_model(&f.0, "", 8, "x86_64"), "Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz");
        // aarch64 VM on Apple silicon (what OrbStack shows): no model name, no DT.
        f.put("proc/cpuinfo", "processor\t: 0\nBogoMIPS\t: 48.00\nFeatures\t: fp asimd evtstrm aes\nCPU implementer\t: 0x61\nCPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: 0x000\nCPU revision\t: 0\n\nprocessor\t: 1\nCPU implementer\t: 0x61\n");
        assert_eq!(lx::cpu_model(&f.0, "", 0, "aarch64"), "Apple aarch64 (2 cores)");
        // Raspberry Pi: device-tree model (NUL-terminated).
        f.put("sys/firmware/devicetree/base/model", "Raspberry Pi 4 Model B Rev 1.4\0");
        assert_eq!(lx::cpu_model(&f.0, "", 4, "aarch64"), "Raspberry Pi 4 Model B Rev 1.4");
        let g = Fixture::new("static2");
        assert_eq!(lx::cpu_model(&g.0, "", 14, "aarch64"), "aarch64 (14 cores)");
        assert_eq!(lx::cpu_model(&g.0, "Neoverse-N1", 4, "aarch64"), "Neoverse-N1 aarch64 (4 cores)");
    }

    #[test]
    fn drm_cards_sysfs() {
        let f = Fixture::new("drm");
        f.put("drm/card0/device/uevent", "DRIVER=amdgpu\nPCI_CLASS=30000\nPCI_ID=1002:73BF\nPCI_SLOT_NAME=0000:03:00.0\n")
            .put("drm/card0/device/vendor", "0x1002\n")
            .put("drm/card0/device/device", "0x73bf\n")
            .put("drm/card0/device/class", "0x030000\n")
            .put("drm/card0/device/gpu_busy_percent", "37\n")
            .put("drm/card0/device/mem_info_vram_used", "1073741824\n")
            .put("drm/card0-DP-1/status", "connected\n")
            .put("drm/card1/device/uevent", "DRIVER=i915\nPCI_SLOT_NAME=0000:00:02.0\n")
            .put("drm/card1/device/vendor", "0x8086\n")
            .put("drm/card1/device/device", "0x5917\n")
            .put("drm/card1/device/class", "0x030000\n")
            .put("drm/card2/device/uevent", "DRIVER=simple-framebuffer\n") // simpledrm: skipped
            .put("drm/card3/device/uevent", "DRIVER=panfrost\nOF_NAME=gpu\n")
            .put("drm/renderD128/dev", "226:128\n")
            .put("drm/version", "drm 1.1.0 20060810\n");
        let c = lx::read_drm_cards(&f.p("drm"));
        let names: Vec<&str> = c.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["AMD GPU 73bf (amdgpu)", "Intel GPU 5917 (i915)", "panfrost GPU"]);
        assert_eq!((c[0].busy, c[0].vram_used, c[0].pdev.as_str()), (Some(37.0), Some(1 << 30), "0000:03:00.0"));
        assert_eq!((c[1].busy, c[1].pdev.as_str()), (None, "0000:00:02.0"));
    }

    const AMD_FDINFO: &str = "pos:\t0\nflags:\t02100002\nmnt_id:\t26\nino:\t1037\ndrm-driver:\tamdgpu\ndrm-client-id:\t62\ndrm-pdev:\t0000:03:00.0\npasid:\t32780\ndrm-memory-vram:\t190464 KiB\ndrm-memory-gtt:\t2048 KiB\ndrm-memory-cpu:\t0 KiB\namd-memory-visible-vram:\t190464 KiB\ndrm-engine-gfx:\t1000000000 ns\ndrm-engine-compute:\t0 ns\ndrm-engine-dma:\t0 ns\n";

    #[test]
    fn drm_fdinfo_parse_and_util() {
        let c = lx::parse_drm_fdinfo(AMD_FDINFO).unwrap();
        assert_eq!((c.driver.as_str(), c.client_id, c.pdev.as_str()), ("amdgpu", 62, "0000:03:00.0"));
        assert_eq!(c.engines.get("gfx"), Some(&1_000_000_000));
        let i915 = "drm-driver:\ti915\ndrm-client-id:\t7\ndrm-pdev:\t0000:00:02.0\ndrm-engine-render:\t9288864723 ns\ndrm-engine-copy:\t0 ns\ndrm-engine-video:\t0 ns\ndrm-engine-capacity-video:\t2\n";
        let c = lx::parse_drm_fdinfo(i915).unwrap();
        assert_eq!((c.engines.len(), c.capacity.get("video")), (3, Some(&2)));
        let xe = "drm-driver:\txe\ndrm-client-id:\t3\ndrm-pdev:\t0000:00:02.0\ndrm-cycles-rcs:\t28257900\ndrm-total-cycles-rcs:\t7655183225\n";
        assert_eq!(lx::parse_drm_fdinfo(xe).unwrap().cycles.get("rcs"), Some(&(28257900, 7655183225)));
        assert!(lx::parse_drm_fdinfo("pos:\t0\nflags:\t02\n").is_none()); // not a DRM fd

        // gfx busy 0.5s over 1s -> 50%; xe 250/1000 cycles -> 25%.
        let prev = vec![(100, lx::parse_drm_fdinfo(AMD_FDINFO).unwrap()), (200, lx::parse_drm_fdinfo(xe).unwrap())];
        let mut a = prev[0].1.clone();
        a.engines.insert("gfx".into(), 1_500_000_000);
        let mut x = prev[1].1.clone();
        x.cycles.insert("rcs".into(), (28257900 + 250, 7655183225 + 1000));
        let (pp, dev) = lx::drm_util(&prev, &[(100, a), (200, x), (300, prev[0].1.clone())], Duration::from_secs(1));
        assert!((pp[&100] - 50.0).abs() < 0.01, "{pp:?}");
        assert!((pp[&200] - 25.0).abs() < 0.01);
        assert!(!pp.contains_key(&300)); // first sighting: no delta yet
        assert!((dev["0000:03:00.0"] - 50.0).abs() < 0.01);
    }

    #[cfg(unix)]
    #[test]
    fn drm_fdinfo_scan() {
        let f = Fixture::new("fdscan");
        f.link("proc/4242/fd/0", "/dev/null")
            .link("proc/4242/fd/5", "/dev/dri/renderD128")
            .link("proc/4242/fd/6", "/dev/dri/card0") // same client via second fd: deduped
            .put("proc/4242/fdinfo/0", "pos:\t0\nflags:\t02\n")
            .put("proc/4242/fdinfo/5", AMD_FDINFO)
            .put("proc/4242/fdinfo/6", AMD_FDINFO)
            .put("proc/self/stat", "x")
            .put("proc/meminfo", "x");
        let v = lx::scan_drm_clients(&f.p("proc"));
        assert_eq!(v.len(), 1);
        assert_eq!((v[0].0, v[0].1.client_id), (4242, 62));
    }

    #[test]
    fn nvidia_smi_parse() {
        let g = lx::parse_nvidia_query("NVIDIA GeForce RTX 4090, 37, 2345\nNVIDIA A100-SXM4-80GB, [N/A], 0\n");
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].name.as_str(), g[0].util, g[0].mem_used), ("NVIDIA GeForce RTX 4090", 37.0, 2345 * 1024 * 1024));
        assert_eq!(g[1].util, 0.0);
        let pmon = "# gpu         pid   type     sm    mem    enc    dec    jpg    ofa    command \n# Idx           #    C/G      %      %      %      %      %      %    name \n    0       2345     G     12      3      -      -      -      -    Xorg           \n    0       7777     C     55     20      -      -      -      -    python         \n    0          -     -      -      -      -      -      -      -    -              \n";
        let m = lx::parse_nvidia_pmon(pmon);
        assert_eq!(m.len(), 2);
        assert_eq!((m[&2345], m[&7777]), (12.0, 55.0));
    }

    /// The real-runtime paths never panic and are consistent with each other.
    #[test]
    fn runtime_smoke() {
        let _ = psi();
        let _ = max_temp_c();
        let _ = proc_gpu();
        let p = mem_pressure();
        assert!(["normal", "warn", "critical", "unknown"].contains(&p.as_str()));
        #[cfg(target_os = "linux")]
        {
            assert_ne!(p, "unknown"); // /proc/meminfo always exists
            let (_, os, cpu) = static_info(&sysinfo::System::new_with_specifics(
                sysinfo::RefreshKind::nothing().with_cpu(sysinfo::CpuRefreshKind::nothing()),
            ));
            assert_ne!(cpu, "unknown");
            assert_ne!(os, "unknown");
            let t0 = std::time::Instant::now();
            let r = (psi(), mem_pressure(), thermal(), max_temp_c(), gpus(), battery());
            eprintln!("linux runtime: {os} | {cpu} | {r:?} in {:?}", t0.elapsed());
            let mut s = lx::GpuSampler::default();
            let t0 = std::time::Instant::now();
            let _ = s.sample();
            let g = s.sample();
            eprintln!("gpu sampler x2: {g:?} in {:?}", t0.elapsed());
            let t0 = std::time::Instant::now();
            let n = lx::scan_drm_clients(std::path::Path::new("/proc")).len();
            eprintln!("fdinfo scan of /proc: {n} drm clients in {:?}", t0.elapsed());
        }
    }
}
