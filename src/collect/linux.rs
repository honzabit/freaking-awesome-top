//! Linux procfs/sysfs process reader. OWNER: linux-procs agent.
//!
//! Reads `/proc/<pid>/{stat,status,io,cmdline,cgroup,cwd,exe}` directly instead of going through
//! sysinfo: one pass, no third-refresh warm-up for cpu%, and fields sysinfo doesn't give us
//! (threads, nice, cgroup, container id). Everything takes a root path so the parsers are unit
//! tested against fixture trees (the OrbStack test kernel has no RAPL, for one).
//!
//! Permissions (unprivileged, default `hidepid=0`):
//!   * `stat`, `status`, `cmdline`, `cgroup` are world-readable -> cpu/mem/threads are known for
//!     every process, so `usage_unknown` is never set on Linux.
//!   * `io`, `cwd`, `exe` need same uid or CAP_SYS_PTRACE: other users' disk rates read 0 and
//!     their cwd/exe are empty. A denied `io` is remembered per process and not retried.
//!   * RAPL `energy_uj` is 0400 root since CVE-2020-8694; without it power is the cpu-time
//!     estimate (`power_source = "estimate"`).
//!
//! Cost: per process and sample we read `stat`, `status` and (if allowed) `io`; cmdline, exe,
//! cwd and cgroup are cached per (pid, starttime) and re-read after an exec (comm changed) or
//! every `STATIC_REFRESH` samples (staggered by pid).
//!
//! Compiled on Linux, and in tests everywhere (pure parsing + plain file reads), so the fixture
//! tests also run on macOS.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::procs::Counters;

/// Re-read cmdline/exe/cwd/cgroup of a live process this often (in samples).
const STATIC_REFRESH: u64 = 10;
/// PF_KTHREAD in /proc/<pid>/stat `flags` (field 9).
const PF_KTHREAD: u64 = 0x0020_0000;

/// Fields of `/proc/<pid>/stat` we use (see proc(5)).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Stat {
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub flags: u64,
    /// Clock ticks (utime+stime of the process, cutime+cstime of waited-for children).
    pub cpu_ticks: u64,
    pub child_cpu_ticks: u64,
    pub nice: i32,
    pub threads: u32,
    /// Clock ticks after boot.
    pub start_ticks: u64,
    pub vsize: u64,
    /// Resident pages.
    pub rss_pages: u64,
}

/// Parse `/proc/<pid>/stat`. `comm` may contain spaces and parentheses (`(a) b)`), so it spans
/// from the first '(' to the *last* ')'. Example (kernel 6.x):
/// `1821 (cat) R 1812 7 7 0 -1 4194304 80 0 0 0 0 0 0 0 20 0 1 0 25701343 8204288 564 ...`
pub fn parse_stat(s: &str) -> Option<Stat> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close < open {
        return None;
    }
    let comm = s[open + 1..close].to_string();
    // f[0] is field 3 (state); field N is f[N - 3].
    let f: Vec<&str> = s[close + 1..].split_ascii_whitespace().collect();
    if f.len() < 22 {
        return None;
    }
    let u = |i: usize| f[i].parse::<u64>().unwrap_or(0);
    Some(Stat {
        comm,
        state: f[0].chars().next().unwrap_or('?'),
        ppid: f[1].parse().unwrap_or(0),
        flags: u(6),
        cpu_ticks: u(11).saturating_add(u(12)),
        // cutime/cstime are signed in the kernel's printf but never negative in practice.
        child_cpu_ticks: f[13].parse::<i64>().unwrap_or(0).max(0) as u64 + f[14].parse::<i64>().unwrap_or(0).max(0) as u64,
        nice: f[16].parse().unwrap_or(0),
        threads: f[17].parse().unwrap_or(0),
        start_ticks: u(19),
        vsize: u(20),
        rss_pages: f[21].parse::<i64>().unwrap_or(0).max(0) as u64,
    })
}

/// Linux task state letter -> the model's single-char status (R, S, T, Z, I, U).
/// `D` (uninterruptible, usually disk) maps to "U" like macOS so "notable" checks stay uniform;
/// `t` (tracing stop) is "T"; `X` (dead) is "Z"; `W`/`P`/`K`/`W` and unknowns read as "S".
pub fn state_char(c: char) -> &'static str {
    match c {
        'R' => "R",
        'S' => "S",
        'D' => "U",
        'T' | 't' => "T",
        'Z' | 'X' | 'x' => "Z",
        'I' => "I",
        _ => "S",
    }
}

/// Effective uid and thread count from `/proc/<pid>/status`
/// (`Uid:\t1000\t1000\t1000\t1000` = real, effective, saved, fs).
pub fn parse_status(s: &str) -> (Option<u32>, Option<u32>) {
    let (uid, threads, _) = parse_status_rss(s);
    (uid, threads)
}

/// [`parse_status`] plus `VmRSS` in bytes. Since Linux 6.2 the mm RSS counters are per-CPU, and
/// the `rss` field of `/proc/<pid>/stat` is the unsynced approximation: a 100 kB `sleep` reads as
/// 0 pages there while status says `VmRSS: 100 kB`. So VmRSS is preferred when present
/// (kernel threads and zombies have no VmRSS line).
pub fn parse_status_rss(s: &str) -> (Option<u32>, Option<u32>, Option<u64>) {
    let mut uid = None;
    let mut threads = None;
    let mut rss = None;
    for line in s.lines() {
        if let Some(r) = line.strip_prefix("Uid:") {
            let mut it = r.split_ascii_whitespace();
            let real = it.next().and_then(|v| v.parse().ok());
            uid = it.next().and_then(|v| v.parse().ok()).or(real);
        } else if let Some(r) = line.strip_prefix("VmRSS:") {
            rss = r.split_ascii_whitespace().next().and_then(|v| v.parse::<u64>().ok()).map(|kb| kb * 1024);
        } else if let Some(r) = line.strip_prefix("Threads:") {
            // Threads comes after Uid and VmRSS.
            threads = r.trim().parse().ok();
            break;
        }
    }
    (uid, threads, rss)
}

/// `read_bytes` / `write_bytes` (actual storage I/O) from `/proc/<pid>/io`.
pub fn parse_io(s: &str) -> Option<(u64, u64)> {
    let mut rd = None;
    let mut wr = None;
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("read_bytes:") {
            rd = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("write_bytes:") {
            wr = v.trim().parse().ok();
        }
    }
    Some((rd?, wr?))
}

/// NUL-separated argv -> space-joined command line.
pub fn parse_cmdline(b: &[u8]) -> String {
    let b = b.strip_suffix(&[0]).unwrap_or(b);
    if b.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = b.split(|&c| c == 0).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
    parts.join(" ")
}

/// The cgroup path from `/proc/<pid>/cgroup`: the v2 `0::<path>` line, else (v1 hosts) the
/// `name=systemd` hierarchy, else the first line's path.
pub fn parse_cgroup(s: &str) -> String {
    let path_of = |l: &str| l.splitn(3, ':').nth(2).map(str::to_string);
    s.lines()
        .find(|l| l.starts_with("0::"))
        .and_then(path_of)
        .or_else(|| s.lines().find(|l| l.contains(":name=systemd:")).and_then(path_of))
        .or_else(|| s.lines().next().and_then(path_of))
        .unwrap_or_default()
}

/// Short (12 hex) container id from cgroup text (any number of lines). Recognizes
/// `/docker/<id>`, `/system.slice/docker-<id>.scope`, `cri-containerd-<id>.scope`,
/// `crio-<id>.scope`, `libpod-<id>.scope`, `/kubepods/.../<id>`, `/lxc.payload.../<id>`...: any
/// path component that is (after stripping a runtime prefix and `.scope`) 64 hex chars. The
/// innermost match wins. `crio-conmon-<id>` / `libpod-conmon-<id>` are monitors outside the
/// container and are ignored.
pub fn container_id(cgroup: &str) -> Option<String> {
    let mut found = None;
    for line in cgroup.lines() {
        let path = line.splitn(3, ':').nth(2).unwrap_or(line);
        for comp in path.split('/') {
            let c = comp.strip_suffix(".scope").unwrap_or(comp);
            if c.contains("conmon") {
                continue;
            }
            let id = c.rsplit(['-', ':']).next().unwrap_or(c);
            if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                found = Some(id[..12].to_ascii_lowercase());
            }
        }
    }
    found
}

/// `/proc/meminfo` values in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemInfo {
    pub total: u64,
    pub available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

impl MemInfo {
    /// MemTotal - MemAvailable (what `free` calls "used" since procps 3.3.10).
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }
    pub fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }
}

/// Parse `/proc/meminfo` (`MemTotal:       16424164 kB`). None without MemTotal/MemAvailable
/// (MemAvailable exists since 3.14).
pub fn parse_meminfo(s: &str) -> Option<MemInfo> {
    let mut m = MemInfo::default();
    let (mut have_total, mut have_avail) = (false, false);
    for line in s.lines() {
        let mut it = line.split_ascii_whitespace();
        let (Some(k), Some(v)) = (it.next(), it.next()) else { continue };
        let Ok(v) = v.parse::<u64>() else { continue };
        let v = v * if it.next() == Some("kB") { 1024 } else { 1 };
        match k {
            "MemTotal:" => (m.total, have_total) = (v, true),
            "MemAvailable:" => (m.available, have_avail) = (v, true),
            "SwapTotal:" => m.swap_total = v,
            "SwapFree:" => m.swap_free = v,
            _ => {}
        }
    }
    (have_total && have_avail).then_some(m)
}

pub fn meminfo(proc_root: &Path) -> Option<MemInfo> {
    parse_meminfo(&fs::read_to_string(proc_root.join("meminfo")).ok()?)
}

/// Boot time (epoch seconds) from the `btime` line of `/proc/stat`.
pub fn parse_btime(s: &str) -> Option<u64> {
    s.lines().find_map(|l| l.strip_prefix("btime ")).and_then(|v| v.trim().parse().ok())
}

pub fn clk_tck() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as u64 } else { 100 }
}

fn page_size() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 { v as u64 } else { 4096 }
}

/// One process as read from procfs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RawProc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmd: String,
    pub exe: String,
    pub cwd: String,
    pub uid: Option<u32>,
    /// Model status char.
    pub status: &'static str,
    pub nice: i32,
    pub threads: u32,
    pub mem: u64,
    pub virt: u64,
    /// Raw starttime ticks: the identity half of the (pid, start) delta key.
    pub start_ticks: u64,
    /// Epoch seconds.
    pub start_time: u64,
    pub counters: Counters,
    /// False when `/proc/<pid>/io` was not readable (disk counters are then 0, not idle).
    pub io_ok: bool,
    pub cgroup: String,
    pub container: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Static {
    comm: String,
    cmd: String,
    exe: String,
    cwd: String,
    cgroup: String,
    container: Option<String>,
    io_denied: bool,
    read_at: u64,
}

/// Stateful procfs reader (caches per-process static fields between samples).
pub struct ProcFs {
    root: PathBuf,
    clk_tck: u64,
    page: u64,
    btime: u64,
    buf: Vec<u8>,
    statics: HashMap<(u32, u64), Static>,
    generation: u64,
}

impl ProcFs {
    /// `root` is normally "/proc".
    pub fn new(root: &Path) -> Self {
        let btime = fs::read_to_string(root.join("stat")).ok().and_then(|s| parse_btime(&s)).unwrap_or(0);
        Self {
            root: root.to_path_buf(),
            clk_tck: clk_tck(),
            page: page_size(),
            btime,
            buf: Vec::with_capacity(4096),
            statics: HashMap::new(),
            generation: 0,
        }
    }

    #[cfg(test)]
    fn with_params(root: &Path, clk_tck: u64, page: u64) -> Self {
        Self { clk_tck, page, ..Self::new(root) }
    }

    fn ticks_to_ns(&self, t: u64) -> u64 {
        ((t as u128 * 1_000_000_000u128) / self.clk_tck as u128) as u64
    }

    /// Read a file into the shared buffer; false on any error.
    fn slurp(&mut self, p: &Path) -> bool {
        self.buf.clear();
        match fs::File::open(p) {
            Ok(mut f) => f.read_to_end(&mut self.buf).is_ok(),
            Err(_) => false,
        }
    }

    fn slurp_str(&mut self, p: &Path) -> Option<String> {
        self.slurp(p).then(|| String::from_utf8_lossy(&self.buf).into_owned())
    }

    /// All numeric entries of the proc root.
    pub fn pids(&self) -> Vec<u32> {
        let Ok(rd) = fs::read_dir(&self.root) else { return Vec::new() };
        rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok()).collect()
    }

    /// Read every process. Processes that vanish mid-read are skipped.
    pub fn scan(&mut self) -> Vec<RawProc> {
        self.generation += 1;
        let pids = self.pids();
        let mut out = Vec::with_capacity(pids.len());
        let mut seen = HashSet::with_capacity(pids.len());
        for pid in pids {
            if let Some(p) = self.read(pid) {
                seen.insert((p.pid, p.start_ticks));
                out.push(p);
            }
        }
        self.statics.retain(|k, _| seen.contains(k));
        out
    }

    /// Read one process (None if it doesn't exist / vanished).
    pub fn read(&mut self, pid: u32) -> Option<RawProc> {
        let dir = self.root.join(pid.to_string());
        let st = parse_stat(&self.slurp_str(&dir.join("stat"))?)?;
        let (uid, threads, rss) = match self.slurp_str(&dir.join("status")) {
            Some(s) => parse_status_rss(&s),
            None => (None, None, None),
        };
        let key = (pid, st.start_ticks);
        let generation = self.generation;
        let kthread = st.flags & PF_KTHREAD != 0;
        let stale = match self.statics.get(&key) {
            None => true,
            Some(s) => {
                s.comm != st.comm
                    || (s.cmd.is_empty() && !kthread && st.state != 'Z')
                    || (generation.wrapping_add(pid as u64).is_multiple_of(STATIC_REFRESH) && s.read_at != generation)
            }
        };
        if stale {
            let io_denied = self.statics.get(&key).is_some_and(|s| s.io_denied);
            let cmd = if self.slurp(&dir.join("cmdline")) { parse_cmdline(&self.buf) } else { String::new() };
            let link = |n: &str| fs::read_link(dir.join(n)).map(|p| p.display().to_string()).unwrap_or_default();
            let cgroup_text = self.slurp_str(&dir.join("cgroup")).unwrap_or_default();
            self.statics.insert(
                key,
                Static {
                    comm: st.comm.clone(),
                    cmd,
                    exe: link("exe"),
                    cwd: link("cwd"),
                    cgroup: parse_cgroup(&cgroup_text),
                    container: container_id(&cgroup_text),
                    io_denied,
                    read_at: generation,
                },
            );
        }
        let io_denied = self.statics.get(&key).is_some_and(|s| s.io_denied);
        let io = if io_denied { None } else { self.slurp_str(&dir.join("io")).and_then(|s| parse_io(&s)) };
        if io.is_none()
            && let Some(s) = self.statics.get_mut(&key)
        {
            // EACCES won't change for this process; ENOENT means it's exiting anyway.
            s.io_denied = true;
        }
        let s = self.statics.get(&key)?;
        let (disk_read, disk_write) = io.unwrap_or((0, 0));
        Some(RawProc {
            pid,
            ppid: st.ppid,
            name: display_name(&st.comm, &s.cmd),
            cmd: s.cmd.clone(),
            exe: s.exe.clone(),
            cwd: s.cwd.clone(),
            uid,
            status: state_char(st.state),
            nice: st.nice,
            threads: threads.unwrap_or(st.threads),
            mem: rss.unwrap_or(st.rss_pages * self.page),
            virt: st.vsize,
            start_ticks: st.start_ticks,
            start_time: self.btime + st.start_ticks / self.clk_tck,
            counters: Counters {
                energy_nj: 0,
                has_energy: false,
                cpu_ns: self.ticks_to_ns(st.cpu_ticks),
                child_cpu_ns: self.ticks_to_ns(st.child_cpu_ticks),
                disk_read,
                disk_write,
            },
            io_ok: io.is_some(),
            cgroup: s.cgroup.clone(),
            container: s.container.clone(),
        })
    }
}

/// `comm` is truncated to 15 bytes (TASK_COMM_LEN); when argv[0]'s basename extends it, show the
/// full name ("systemd-journal" -> "systemd-journald").
pub fn display_name(comm: &str, cmd: &str) -> String {
    if comm.len() == 15 {
        let argv0 = cmd.split(' ').next().unwrap_or("");
        let base = argv0.rsplit('/').next().unwrap_or(argv0);
        if base.len() > comm.len() && base.starts_with(comm) {
            return base.to_string();
        }
    }
    comm.to_string()
}

/// Counters for one pid read straight from procfs (used by `procs::counters` on Linux).
pub fn counters(proc_root: &Path, pid: u32) -> Option<Counters> {
    let dir = proc_root.join(pid.to_string());
    let st = parse_stat(&fs::read_to_string(dir.join("stat")).ok()?)?;
    let (r, w) = fs::read_to_string(dir.join("io")).ok().and_then(|s| parse_io(&s)).unwrap_or((0, 0));
    let tck = clk_tck() as u128;
    let ns = |t: u64| ((t as u128 * 1_000_000_000) / tck) as u64;
    Some(Counters {
        cpu_ns: ns(st.cpu_ticks),
        child_cpu_ns: ns(st.child_cpu_ticks),
        disk_read: r,
        disk_write: w,
        ..Default::default()
    })
}

/// Identity (ppid, euid, start epoch secs) for one pid.
#[allow(dead_code)] // reached via procs::{ident, threads}, which Linux sampling doesn't need
pub fn ident(proc_root: &Path, pid: u32) -> Option<super::procs::Ident> {
    let dir = proc_root.join(pid.to_string());
    let st = parse_stat(&fs::read_to_string(dir.join("stat")).ok()?)?;
    let (uid, _) = parse_status(&fs::read_to_string(dir.join("status")).ok()?);
    let btime = fs::read_to_string(proc_root.join("stat")).ok().and_then(|s| parse_btime(&s)).unwrap_or(0);
    Some(super::procs::Ident { ppid: st.ppid, uid: uid?, start_time: btime + st.start_ticks / clk_tck() })
}

#[allow(dead_code)] // reached via procs::{ident, threads}, which Linux sampling doesn't need
pub fn threads(proc_root: &Path, pid: u32) -> Option<u32> {
    let st = parse_stat(&fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?)?;
    Some(st.threads)
}

// ---------------------------------------------------------------------------------------------
// Package power: RAPL powercap (or hwmon energy counters)

#[derive(Debug, Clone)]
struct Zone {
    path: PathBuf,
    /// Counter wraps after this many µJ (0 = unknown).
    max_range: u64,
    last: Option<u64>,
}

/// Package energy meter. Sources, in order:
///   1. `/sys/class/powercap/intel-rapl:<N>/energy_uj` — top-level package zones only
///      (`intel-rapl:N:M` subzones are parts of the package and would double count). AMD Zen
///      also exposes its package counter under this name with the same driver. Top-level
///      zones are told apart by their `name`: `package-N` (one per socket, summed) and, on
///      Skylake+ laptops, `psys` (the whole platform, which already contains the package:
///      used alone, only when there is no package zone).
///   2. `/sys/class/powercap/intel-rapl-mmio:<N>` — same package via MMIO, only if (1) is absent.
///   3. `/sys/class/hwmon/hwmon*/energy*_input` (µJ) — e.g. the `amd_energy` driver
///      (`Esocket0` labels; `Ecore*` per-core inputs are skipped as they're part of the socket).
pub struct Rapl {
    zones: Vec<Zone>,
    pub source: &'static str,
}

fn read_u64(p: &Path) -> Option<u64> {
    fs::read_to_string(p).ok()?.trim().parse().ok()
}

impl Rapl {
    /// `root` is normally "/". Only zones whose counter is readable *now* are kept.
    pub fn discover(root: &Path) -> Self {
        let pc = root.join("sys/class/powercap");
        let names: Vec<String> = fs::read_dir(&pc)
            .map(|rd| rd.filter_map(|e| e.ok()?.file_name().into_string().ok()).collect())
            .unwrap_or_default();
        let pick = |prefix: &str| -> Vec<Zone> {
            let mut v: Vec<&String> = names
                .iter()
                .filter(|n| n.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())))
                .collect();
            v.sort();
            let (mut package, mut psys) = (Vec::new(), Vec::new());
            for n in v {
                let d = pc.join(n);
                let e = d.join("energy_uj");
                if read_u64(&e).is_none() {
                    continue;
                }
                let z = Zone { path: e, max_range: read_u64(&d.join("max_energy_range_uj")).unwrap_or(0), last: None };
                // `dram` etc. are subzones; a top-level zone is a package unless it says psys.
                match fs::read_to_string(d.join("name")).map(|s| s.trim().to_string()).unwrap_or_default().as_str() {
                    "psys" => psys.push(z),
                    _ => package.push(z),
                }
            }
            if package.is_empty() { psys } else { package }
        };
        let zones = pick("intel-rapl:");
        if !zones.is_empty() {
            return Self { zones, source: "rapl" };
        }
        let zones = pick("intel-rapl-mmio:");
        if !zones.is_empty() {
            return Self { zones, source: "rapl" };
        }
        let mut zones = Vec::new();
        let hw = root.join("sys/class/hwmon");
        let mut dirs: Vec<PathBuf> = fs::read_dir(&hw).map(|rd| rd.filter_map(|e| Some(e.ok()?.path())).collect()).unwrap_or_default();
        dirs.sort();
        for d in dirs {
            let mut files: Vec<String> = fs::read_dir(&d)
                .map(|rd| rd.filter_map(|e| e.ok()?.file_name().into_string().ok()).collect())
                .unwrap_or_default();
            files.sort();
            for f in files.iter().filter(|f| f.starts_with("energy") && f.ends_with("_input")) {
                let label = fs::read_to_string(d.join(f.replace("_input", "_label"))).unwrap_or_default();
                if label.trim().starts_with("Ecore") {
                    continue;
                }
                let p = d.join(f);
                if read_u64(&p).is_some() {
                    zones.push(Zone { path: p, max_range: 0, last: None });
                }
            }
        }
        let source = if zones.is_empty() { "" } else { "rapl" };
        Self { zones, source }
    }

    pub fn available(&self) -> bool {
        !self.zones.is_empty()
    }

    /// Energy (µJ) consumed since the previous call; None on the first call or if no zone could
    /// be read. Wraparound uses `max_energy_range_uj`; a decrease without a known range is
    /// skipped for that zone.
    pub fn delta_uj(&mut self) -> Option<u64> {
        let mut total = 0u64;
        let mut any = false;
        for z in &mut self.zones {
            let Some(cur) = read_u64(&z.path) else { continue };
            if let Some(prev) = z.last {
                if cur >= prev {
                    total += cur - prev;
                    any = true;
                } else if z.max_range > 0 && prev <= z.max_range {
                    total += z.max_range - prev + cur;
                    any = true;
                }
            }
            z.last = Some(cur);
        }
        any.then_some(total)
    }

    /// Package power in mW over `dt_s` seconds (None first call / dt 0).
    pub fn sample_mw(&mut self, dt_s: f64) -> Option<f64> {
        let d = self.delta_uj()?;
        (dt_s > 0.0).then(|| d as f64 / dt_s / 1000.0)
    }
}

/// Split `total_mw` across processes by their share of the machine's cpu *capacity*
/// (`cores` × 100%), not of the busy total: the package's idle and uncore draw stays
/// unattributed instead of landing on whichever process happens to be busiest. A process
/// using one of 8 cores fully gets 1/8 of package power; the parts never exceed the total.
pub fn apportion_capacity(total_mw: f64, cpu: &[f32], cores: usize) -> Vec<f32> {
    let cap = (cores.max(1) * 100) as f64;
    let sum: f64 = cpu.iter().map(|&c| c.max(0.0) as f64).sum();
    // cpu% can briefly exceed the capacity (sampling skew); then fall back to shares.
    let denom = cap.max(sum);
    if denom <= 0.0 {
        return vec![0.0; cpu.len()];
    }
    cpu.iter().map(|&c| (total_mw * c.max(0.0) as f64 / denom) as f32).collect()
}

/// Split `total_mw` across processes proportionally to their cpu%.
#[allow(dead_code)]
pub fn apportion(total_mw: f64, cpu: &[f32]) -> Vec<f32> {
    let sum: f64 = cpu.iter().map(|&c| c.max(0.0) as f64).sum();
    if sum <= 0.0 {
        return vec![0.0; cpu.len()];
    }
    cpu.iter().map(|&c| (total_mw * c.max(0.0) as f64 / sum) as f32).collect()
}

// ---------------------------------------------------------------------------------------------
// System-wide disk and network totals (world-readable, unlike other users' /proc/<pid>/io)

/// A whole physical disk (not a partition, nor a virtual device stacked on disks we already
/// count: loop, ram, zram, dm-*, md*). `blocks`: the names in /sys/block when readable
/// (partitions are not listed there); otherwise a name heuristic.
fn whole_disk(name: &str, blocks: Option<&HashSet<String>>) -> bool {
    const VIRTUAL: [&str; 7] = ["loop", "ram", "zram", "dm-", "md", "sr", "nbd"];
    if VIRTUAL.iter().any(|v| name.starts_with(v)) {
        return false;
    }
    if let Some(b) = blocks {
        return b.contains(name);
    }
    // nvme0n1 / mmcblk0 are disks, nvme0n1p1 / mmcblk0p1 partitions; sda / vdb / xvda disks,
    // sda1 partitions.
    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        return !name.rsplit_once('p').is_some_and(|(head, tail)| !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) && head.ends_with(|c: char| c.is_ascii_digit()));
    }
    !name.ends_with(|c: char| c.is_ascii_digit())
}

/// Total (read, written) bytes of whole disks from /proc/diskstats. Real line (6.x):
/// `259       0 nvme0n1 1123590 340987 75470062 210342 2265339 1270322 152637400 1871215 0 1106676 2149853 0 0 0 0 102340 68296`
/// (major minor name reads merged sectors_read ms writes merged sectors_written ...);
/// sectors are always 512 bytes.
pub fn parse_diskstats(s: &str, blocks: Option<&HashSet<String>>) -> (u64, u64) {
    let (mut r, mut w) = (0u64, 0u64);
    for l in s.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 10 || !whole_disk(f[2], blocks) {
            continue;
        }
        r = r.saturating_add(f[5].parse::<u64>().unwrap_or(0).saturating_mul(512));
        w = w.saturating_add(f[9].parse::<u64>().unwrap_or(0).saturating_mul(512));
    }
    (r, w)
}

/// Total (rx, tx) bytes of every interface but `lo` from /proc/net/dev (fat's own network
/// namespace). Real content:
/// ```text
/// Inter-|   Receive                                                |  Transmit
///  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
///     lo:  123456     789    0    0    0     0          0         0   123456     789    0    0    0     0       0          0
///   eth0: 98765432  65432    0    0    0     0          0         0  1234567   9876    0    0    0     0       0          0
/// ```
pub fn parse_net_dev(s: &str) -> (u64, u64) {
    let (mut rx, mut tx) = (0u64, 0u64);
    for l in s.lines() {
        let Some((name, rest)) = l.split_once(':') else { continue };
        if name.trim() == "lo" || name.contains('|') {
            continue;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if f.len() >= 9 {
            rx = rx.saturating_add(f[0]);
            tx = tx.saturating_add(f[8]);
        }
    }
    (rx, tx)
}

/// Rates of the system-wide counters between samples.
#[derive(Default)]
pub struct SysIo {
    prev: Option<([u64; 4], std::time::Instant)>,
}

impl SysIo {
    /// (disk_read, disk_write, net_rx, net_tx) bytes/s since the previous call; None on the
    /// first call or when the files are unreadable. `root` is normally "/".
    pub fn sample(&mut self, root: &Path) -> Option<[u64; 4]> {
        let blocks: Option<HashSet<String>> = fs::read_dir(root.join("sys/block"))
            .ok()
            .map(|rd| rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect())
            .filter(|b: &HashSet<String>| !b.is_empty());
        let disk = fs::read_to_string(root.join("proc/diskstats")).ok().map(|t| parse_diskstats(&t, blocks.as_ref()));
        let net = fs::read_to_string(root.join("proc/net/dev")).ok().map(|t| parse_net_dev(&t));
        let (Some((r, w)), Some((rx, tx))) = (disk, net) else {
            self.prev = None;
            return None;
        };
        let cur = [r, w, rx, tx];
        let now = std::time::Instant::now();
        let out = self.prev.and_then(|(p, t)| {
            let dt = now.duration_since(t).as_secs_f64();
            (dt > 0.0).then(|| {
                let mut o = [0u64; 4];
                for i in 0..4 {
                    o[i] = (cur[i].saturating_sub(p[i]) as f64 / dt) as u64;
                }
                o
            })
        });
        self.prev = Some((cur, now));
        out
    }
}

// ---------------------------------------------------------------------------------------------
// cgroup v2 limits on fat itself (a container started with --memory / --cpus)

/// The limits that bind the cgroup fat runs in, from its own cgroup up to the namespace root
/// (each level can limit; the tightest wins). `cg_root` is normally /sys/fs/cgroup and `own`
/// the unified path from /proc/self/cgroup (`/` in a container's private cgroup namespace).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CgView {
    /// Tightest memory.max on the path, and the cgroup that sets it.
    pub mem_max: Option<u64>,
    pub mem_dir: Option<PathBuf>,
    /// Tightest cpu.max as cores (quota / period), and the cgroup that sets it.
    pub cpu_quota: Option<f64>,
    pub cpu_dir: Option<PathBuf>,
    /// cpuset.cpus.effective of fat's own cgroup.
    pub cpus: Option<Vec<usize>>,
}

/// "0-3,8,10-11" -> [0,1,2,3,8,10,11].
pub fn parse_cpu_list(s: &str) -> Vec<usize> {
    let mut v = Vec::new();
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>())
                    && a <= b
                    && b - a < 4096
                {
                    v.extend(a..=b);
                }
            }
            None => v.extend(part.trim().parse::<usize>().ok()),
        }
    }
    v
}

pub fn cgroup_view(cg_root: &Path, own: &str) -> CgView {
    let mut view = CgView::default();
    let mut path = own.trim().trim_end_matches('/').to_string();
    let mut first = true;
    loop {
        let dir = cg_root.join(path.trim_start_matches('/'));
        // The real root has no limit files (and no cgroup.type); a namespace root does.
        if dir.join("cgroup.type").exists() || !path.is_empty() {
            if let Some(m) = fs::read_to_string(dir.join("memory.max")).ok().and_then(|t| t.trim().parse::<u64>().ok())
                && view.mem_max.is_none_or(|cur| m < cur)
            {
                view.mem_max = Some(m);
                view.mem_dir = Some(dir.clone());
            }
            if let Ok(t) = fs::read_to_string(dir.join("cpu.max")) {
                let mut it = t.split_whitespace();
                if let (Some(Ok(q)), Some(Ok(p))) = (it.next().map(str::parse::<f64>), it.next().map(str::parse::<f64>))
                    && p > 0.0
                    && view.cpu_quota.is_none_or(|cur| q / p < cur)
                {
                    view.cpu_quota = Some(q / p);
                    view.cpu_dir = Some(dir.clone());
                }
            }
            if first {
                view.cpus = fs::read_to_string(dir.join("cpuset.cpus.effective")).ok().map(|t| parse_cpu_list(&t)).filter(|v| !v.is_empty());
            }
        }
        first = false;
        if path.is_empty() {
            break;
        }
        path.truncate(path.rfind('/').unwrap_or(0));
    }
    view
}

/// Memory a cgroup really uses: memory.current minus inactive page cache (what `docker stats`
/// shows; the kernel reclaims inactive_file before it OOMs).
pub fn cg_mem_used(dir: &Path) -> Option<u64> {
    let cur: u64 = fs::read_to_string(dir.join("memory.current")).ok()?.trim().parse().ok()?;
    let inactive = fs::read_to_string(dir.join("memory.stat"))
        .ok()
        .and_then(|t| t.lines().find_map(|l| l.strip_prefix("inactive_file ").and_then(|v| v.trim().parse::<u64>().ok())))
        .unwrap_or(0);
    Some(cur.saturating_sub(inactive))
}

/// cgroup cpu.stat usage_usec.
pub fn cg_usage_usec(dir: &Path) -> Option<u64> {
    fs::read_to_string(dir.join("cpu.stat")).ok()?.lines().find_map(|l| l.strip_prefix("usage_usec ").and_then(|v| v.trim().parse().ok()))
}

/// The cgroup's own PSI ({cpu,memory,io}.pressure, same format as /proc/pressure/*).
pub fn cg_psi(dir: &Path) -> Option<crate::model::Psi> {
    use super::system::lx::parse_psi_file;
    let rd = |f: &str| fs::read_to_string(dir.join(f)).ok().map(|s| parse_psi_file(&s));
    let (cpu, mem, io) = (rd("cpu.pressure"), rd("memory.pressure"), rd("io.pressure"));
    if cpu.is_none() && mem.is_none() && io.is_none() {
        return None;
    }
    let (cpu, mem, io) = (cpu.unwrap_or_default(), mem.unwrap_or_default(), io.unwrap_or_default());
    Some(crate::model::Psi {
        cpu_some: cpu.0.unwrap_or(0.0),
        mem_some: mem.0.unwrap_or(0.0),
        mem_full: mem.1.unwrap_or(0.0),
        io_some: io.0.unwrap_or(0.0),
        io_full: io.1.unwrap_or(0.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh fixture dir under the temp dir.
    fn fixture(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fat-linux-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(root: &Path, rel: &str, content: &[u8]) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    // Real line from Debian bookworm, kernel 6.x (`cat /proc/self/stat`).
    const STAT_CAT: &str = "1821 (cat) R 1812 7 7 0 -1 4194304 80 0 0 0 3 2 1 4 20 0 1 0 25701343 8204288 564 18446744073709551615 187650985820160 187650985845404 281474264849824 0 0 0 0 0 0 0 0 0 17 12 0 0 0 0 0 187650985949792 187650985951432 187651630829568 281474264853797 281474264853817 281474264853817 281474264854507 0\n";

    #[test]
    fn stat_basic() {
        let s = parse_stat(STAT_CAT).unwrap();
        assert_eq!(s.comm, "cat");
        assert_eq!(s.state, 'R');
        assert_eq!(s.ppid, 1812);
        assert_eq!(s.cpu_ticks, 5);
        assert_eq!(s.child_cpu_ticks, 5);
        assert_eq!(s.nice, 0);
        assert_eq!(s.threads, 1);
        assert_eq!(s.start_ticks, 25701343);
        assert_eq!(s.vsize, 8204288);
        assert_eq!(s.rss_pages, 564);
    }

    #[test]
    fn stat_hostile_comm() {
        // comm with spaces and parens, negative nice, kthread flag.
        let line = "42 (a) b (c)) S 2 0 0 0 -1 2129984 0 0 0 0 7 9 0 0 39 19 3 0 100 0 0 18446744073709551615";
        let s = parse_stat(line).unwrap();
        assert_eq!(s.comm, "a) b (c)");
        assert_eq!(s.ppid, 2);
        assert_eq!(s.nice, 19);
        assert_eq!(s.threads, 3);
        assert_ne!(s.flags & PF_KTHREAD, 0);
        let neg = "7 (x) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 30 -10 1 0 5 0 0 0";
        assert_eq!(parse_stat(neg).unwrap().nice, -10);
        assert!(parse_stat("7 (x) S 1 2").is_none());
        assert!(parse_stat("garbage").is_none());
    }

    #[test]
    fn states() {
        assert_eq!(state_char('D'), "U");
        assert_eq!(state_char('t'), "T");
        assert_eq!(state_char('X'), "Z");
        assert_eq!(state_char('I'), "I");
        assert_eq!(state_char('W'), "S");
    }

    #[test]
    fn status_uid_threads() {
        let s = "Name:\tsudo\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t9\nPid:\t9\nPPid:\t1\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\nThreads:\t4\n";
        assert_eq!(parse_status(s), (Some(0), Some(4)));
        assert_eq!(parse_status(""), (None, None));
        // Real 7.x kernel: stat's rss field said 0 pages for this process.
        let st = "Name:\tsleep\nUid:\t0\t0\t0\t0\nVmSize:\t    2232 kB\nVmRSS:\t     100 kB\nRssAnon:\t      96 kB\nThreads:\t1\n";
        assert_eq!(parse_status_rss(st), (Some(0), Some(1), Some(100 * 1024)));
        assert_eq!(parse_status_rss("Uid:\t0\t0\t0\t0\nThreads:\t1\n").2, None);
    }

    #[test]
    fn io_and_cmdline() {
        let io = "rchar: 2075\nwchar: 0\nsyscr: 6\nsyscw: 0\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 0\n";
        assert_eq!(parse_io(io), Some((4096, 8192)));
        assert_eq!(parse_io("rchar: 1\n"), None);
        assert_eq!(parse_cmdline(b"node\0/usr/bin/vite\0--port\x003000\0"), "node /usr/bin/vite --port 3000");
        assert_eq!(parse_cmdline(b"nginx: worker process\0\0\0"), "nginx: worker process  ");
        assert_eq!(parse_cmdline(b""), "");
    }

    #[test]
    fn cgroup_and_container() {
        const D: &str = "1c5d10a36e643dfc79ca9514c31b8fb651d4c4b2741fb0bef58d591761db6384";
        assert_eq!(parse_cgroup("0::/init.scope\n"), "/init.scope");
        assert_eq!(parse_cgroup("12:memory:/x\n1:name=systemd:/user.slice\n"), "/user.slice");
        assert_eq!(parse_cgroup(""), "");
        let want = Some("1c5d10a36e64".to_string());
        for path in [
            format!("0::/docker/{D}\n"),
            format!("0::/system.slice/docker-{D}.scope\n"),
            format!("0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b.slice/cri-containerd-{D}.scope\n"),
            format!("0::/kubepods/besteffort/pod0f1e2d3c-1111-2222-3333-444455556666/{D}\n"),
            format!("0::/machine.slice/libpod-{D}.scope/container\n"),
            format!("0::/kubepods.slice/kubepods-pod1.slice/crio-{D}.scope\n"),
            format!("12:memory:/docker/{D}\n11:cpu:/docker/{D}\n"),
        ] {
            assert_eq!(container_id(&path), want, "{path}");
        }
        assert_eq!(container_id(&format!("0::/machine.slice/libpod-conmon-{D}.scope\n")), None);
        assert_eq!(container_id("0::/user.slice/user-1000.slice/session-3.scope\n"), None);
        assert_eq!(container_id("0::/\n"), None);
    }

    #[test]
    fn meminfo_used_is_total_minus_available() {
        let s = "MemTotal:       16424164 kB\nMemFree:        13796140 kB\nMemAvailable:   14785208 kB\nSwapTotal:      17472732 kB\nSwapFree:       17470732 kB\n";
        let m = parse_meminfo(s).unwrap();
        assert_eq!(m.total, 16424164 * 1024);
        assert_eq!(m.used(), (16424164 - 14785208) * 1024);
        assert_eq!(m.swap_used(), 2000 * 1024);
        assert!(parse_meminfo("MemTotal: 1 kB\n").is_none());
    }

    #[test]
    fn names() {
        assert_eq!(display_name("systemd-journal", "/usr/lib/systemd/systemd-journald"), "systemd-journald");
        assert_eq!(display_name("bash", "-bash"), "bash");
        assert_eq!(display_name("kworker/0:1-eve", ""), "kworker/0:1-eve");
    }

    /// A fake /proc with a process whose io is unreadable, a kernel thread and a container proc.
    #[test]
    fn procfs_fixture_scan() {
        let root = fixture("proc");
        put(&root, "stat", b"cpu  1 2 3 4\nbtime 1700000000\nprocesses 5\n");
        put(&root, "meminfo", b"MemTotal: 1000 kB\nMemAvailable: 250 kB\n");
        // pid 100: user process in a docker container, 2s cpu, started 50s after boot.
        put(&root, "100/stat", b"100 (python3 x) S 1 100 100 0 -1 4194560 0 0 0 0 150 50 10 0 20 5 3 0 5000 1048576 10 0\n");
        put(&root, "100/status", b"Name:\tpython3\nUid:\t1000\t1000\t1000\t1000\nThreads:\t3\n");
        put(&root, "100/io", b"read_bytes: 100\nwrite_bytes: 200\n");
        put(&root, "100/cmdline", b"python3\0-m\0http.server\0");
        put(&root, "100/cgroup", b"0::/system.slice/docker-1c5d10a36e643dfc79ca9514c31b8fb651d4c4b2741fb0bef58d591761db6384.scope\n");
        // pid 2: kthreadd, no io file (as if denied), empty cmdline.
        put(&root, "2/stat", b"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 2 0 0 0\n");
        put(&root, "2/status", b"Uid:\t0\t0\t0\t0\nThreads:\t1\n");
        put(&root, "2/cmdline", b"");
        put(&root, "2/cgroup", b"0::/\n");
        put(&root, "self/stat", b"ignored");
        let mut fs_ = ProcFs::with_params(&root, 100, 4096);
        let mut v = fs_.scan();
        v.sort_by_key(|p| p.pid);
        assert_eq!(v.len(), 2);
        let k = &v[0];
        assert_eq!((k.pid, k.ppid, k.name.as_str(), k.cmd.as_str()), (2, 0, "kthreadd", ""));
        assert!(!k.io_ok);
        assert_eq!(k.container, None);
        let p = &v[1];
        assert_eq!(p.name, "python3 x");
        assert_eq!(p.cmd, "python3 -m http.server");
        assert_eq!(p.uid, Some(1000));
        assert_eq!(p.threads, 3);
        assert_eq!(p.nice, 5);
        assert_eq!(p.status, "S");
        assert_eq!(p.mem, 10 * 4096);
        assert_eq!(p.virt, 1048576);
        assert_eq!(p.start_time, 1_700_000_000 + 50);
        assert_eq!(p.counters.cpu_ns, 2_000_000_000);
        assert_eq!(p.counters.child_cpu_ns, 100_000_000);
        assert_eq!((p.counters.disk_read, p.counters.disk_write), (100, 200));
        assert!(p.io_ok);
        assert_eq!(p.cgroup, "/system.slice/docker-1c5d10a36e643dfc79ca9514c31b8fb651d4c4b2741fb0bef58d591761db6384.scope");
        assert_eq!(p.container.as_deref(), Some("1c5d10a36e64"));
        assert_eq!(meminfo(&root).unwrap().used(), 750 * 1024);

        // exec: comm changes -> cmdline re-read even within the refresh window.
        put(&root, "100/stat", b"100 (node) R 1 100 100 0 -1 4194560 0 0 0 0 250 50 10 0 20 5 3 0 5000 1048576 10 0\n");
        put(&root, "100/cmdline", b"node\0server.js\0");
        let v = fs_.scan();
        let p = v.iter().find(|p| p.pid == 100).unwrap();
        assert_eq!(p.cmd, "node server.js");
        assert_eq!(p.status, "R");
        // pid gone -> dropped, cache pruned.
        fs::remove_dir_all(root.join("100")).unwrap();
        assert_eq!(fs_.scan().len(), 1);
        assert_eq!(fs_.statics.len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rapl_fixture_wrap_and_subzones() {
        let root = fixture("rapl");
        let pc = "sys/class/powercap";
        // Layout as on an Intel laptop (kernel 6.x): package + core/uncore subzones + psys.
        put(&root, &format!("{pc}/intel-rapl:0/name"), b"package-0\n");
        put(&root, &format!("{pc}/intel-rapl:0/energy_uj"), b"262143000000\n");
        put(&root, &format!("{pc}/intel-rapl:0/max_energy_range_uj"), b"262143328850\n");
        put(&root, &format!("{pc}/intel-rapl:0:0/name"), b"core\n");
        put(&root, &format!("{pc}/intel-rapl:0:0/energy_uj"), b"5\n");
        put(&root, &format!("{pc}/intel-rapl-mmio:0/energy_uj"), b"7\n");
        // psys (whole platform, includes the package) must not be added to package-0.
        put(&root, &format!("{pc}/intel-rapl:1/name"), b"psys\n");
        put(&root, &format!("{pc}/intel-rapl:1/energy_uj"), b"1000\n");
        let mut r = Rapl::discover(&root);
        assert!(r.available());
        assert_eq!(r.zones.len(), 1, "subzones, psys and mmio duplicate must be skipped");
        assert!(r.zones[0].path.to_string_lossy().contains("intel-rapl:0/"), "{:?}", r.zones);
        assert_eq!(r.sample_mw(1.0), None);
        // wrap: 328850 to the top, then 671150 more = 1_000_000 µJ in 2s = 500 mW.
        put(&root, &format!("{pc}/intel-rapl:0/energy_uj"), b"671150\n");
        let mw = r.sample_mw(2.0).unwrap();
        assert!((mw - 500.0).abs() < 1e-6, "{mw}");
        put(&root, &format!("{pc}/intel-rapl:0/energy_uj"), b"3671150\n");
        assert!((r.sample_mw(1.0).unwrap() - 3000.0).abs() < 1e-6);
        let _ = fs::remove_dir_all(&root);

        // psys alone (no package zone readable) -> used.
        let root = fixture("rapl-psys");
        put(&root, &format!("{pc}/intel-rapl:1/name"), b"psys\n");
        put(&root, &format!("{pc}/intel-rapl:1/energy_uj"), b"1000\n");
        let mut r = Rapl::discover(&root);
        assert_eq!(r.zones.len(), 1);
        assert_eq!(r.delta_uj(), None);
        put(&root, &format!("{pc}/intel-rapl:1/energy_uj"), b"9001000\n");
        assert_eq!(r.delta_uj(), Some(9_000_000));
        let _ = fs::remove_dir_all(&root);

        // Two sockets: both packages summed.
        let root = fixture("rapl-2s");
        for i in 0..2 {
            put(&root, &format!("{pc}/intel-rapl:{i}/name"), format!("package-{i}\n").as_bytes());
            put(&root, &format!("{pc}/intel-rapl:{i}/energy_uj"), b"100\n");
        }
        assert_eq!(Rapl::discover(&root).zones.len(), 2);
        let _ = fs::remove_dir_all(&root);

        // Only mmio present -> used.
        let root = fixture("rapl-mmio");
        put(&root, &format!("{pc}/intel-rapl-mmio:0/energy_uj"), b"7\n");
        assert!(Rapl::discover(&root).available());
        let _ = fs::remove_dir_all(&root);

        // amd_energy hwmon: socket counted, cores skipped.
        let root = fixture("amd");
        put(&root, "sys/class/hwmon/hwmon3/name", b"amd_energy\n");
        put(&root, "sys/class/hwmon/hwmon3/energy1_input", b"1000\n");
        put(&root, "sys/class/hwmon/hwmon3/energy1_label", b"Ecore000\n");
        put(&root, "sys/class/hwmon/hwmon3/energy65_input", b"2000\n");
        put(&root, "sys/class/hwmon/hwmon3/energy65_label", b"Esocket0\n");
        let mut r = Rapl::discover(&root);
        assert_eq!(r.zones.len(), 1);
        assert_eq!(r.delta_uj(), None);
        put(&root, "sys/class/hwmon/hwmon3/energy65_input", b"12000\n");
        assert_eq!(r.delta_uj(), Some(10000));
        let _ = fs::remove_dir_all(&root);

        // Nothing -> unavailable.
        let root = fixture("none");
        assert!(!Rapl::discover(&root).available());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn diskstats_whole_disks_only() {
        // Real 6.x lines: nvme disk + partitions, a loop device, dm on top of nvme0n1p3.
        let ds = "\
 259       0 nvme0n1 1123590 340987 75470062 210342 2265339 1270322 152637400 1871215 0 1106676 2149853 0 0 0 0 102340 68296
 259       1 nvme0n1p1 312 1201 18234 52 2 0 2 0 0 80 52 0 0 0 0 0 0
 259       3 nvme0n1p3 1122000 339000 75400000 210000 2265000 1270000 152600000 1870000 0 1100000 2140000 0 0 0 0 0 0
   7       0 loop0 54 0 2178 12 0 0 0 0 0 40 12 0 0 0 0 0 0
 253       0 dm-0 1460000 0 75000000 300000 3530000 0 152600000 4000000 0 1100000 4300000 0 0 0 0 0 0
   8       0 sda 100 0 200 1 10 0 40 2 0 3 3 0 0 0 0 0 0
   8       1 sda1 90 0 180 1 9 0 36 2 0 3 3 0 0 0 0 0 0
";
        let (r, w) = parse_diskstats(ds, None);
        assert_eq!(r, (75_470_062 + 200) * 512);
        assert_eq!(w, (152_637_400 + 40) * 512);
        let blocks: HashSet<String> = ["nvme0n1", "sda", "loop0", "dm-0"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_diskstats(ds, Some(&blocks)), (r, w));
        assert!(whole_disk("mmcblk0", None) && !whole_disk("mmcblk0p2", None));
        assert!(whole_disk("vda", None) && !whole_disk("vda1", None));
    }

    #[test]
    fn net_dev_skips_loopback() {
        let nd = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo:  123456     789    0    0    0     0          0         0   123456     789    0    0    0     0       0          0\n  eth0: 98765432  65432    0    0    0     0          0         0  1234567   9876    0    0    0     0       0          0\nwlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n";
        assert_eq!(parse_net_dev(nd), (98_765_432 + 1000, 1_234_567 + 2000));
    }

    #[test]
    fn sysio_rates_from_fixture() {
        let root = fixture("sysio");
        put(&root, "sys/block/vda/size", b"1\n");
        put(&root, "proc/diskstats", b" 254 0 vda 10 0 1000 0 10 0 2000 0 0 0 0\n 254 1 vda1 10 0 1000 0 10 0 2000 0 0 0 0\n");
        put(&root, "proc/net/dev", b"h|\nh|\n eth0: 100 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0\n");
        let mut s = SysIo::default();
        assert_eq!(s.sample(&root), None);
        std::thread::sleep(std::time::Duration::from_millis(50));
        put(&root, "proc/diskstats", b" 254 0 vda 10 0 3000 0 10 0 2000 0 0 0 0\n");
        put(&root, "proc/net/dev", b"h|\nh|\n eth0: 100100 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0\n");
        let r = s.sample(&root).unwrap();
        assert!(r[0] > 0 && r[1] == 0 && r[2] > 0 && r[3] == 0, "{r:?}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cgroup_view_tightest_limit() {
        // docker run --memory 256m --cpus 0.5 with --cgroupns=host: /docker/<id>.
        let root = fixture("cgview");
        put(&root, "cgroup.controllers", b"cpuset cpu io memory pids\n");
        put(&root, "docker/cgroup.type", b"domain\n");
        put(&root, "docker/memory.max", b"max\n");
        put(&root, "docker/cpu.max", b"max 100000\n");
        put(&root, "docker/abc/cgroup.type", b"domain\n");
        put(&root, "docker/abc/memory.max", b"268435456\n");
        put(&root, "docker/abc/cpu.max", b"50000 100000\n");
        put(&root, "docker/abc/cpuset.cpus.effective", b"0-3,8\n");
        put(&root, "docker/abc/memory.current", b"262144000\n");
        put(&root, "docker/abc/memory.stat", b"anon 200000000\nfile 60000000\nactive_file 10000000\ninactive_file 50000000\n");
        put(&root, "docker/abc/memory.pressure", b"some avg10=12.50 avg60=3.00 avg300=1.00 total=1\nfull avg10=2.00 avg60=0.00 avg300=0.00 total=1\n");
        let v = cgroup_view(&root, "/docker/abc");
        assert_eq!(v.mem_max, Some(268_435_456));
        assert_eq!(v.mem_dir, Some(root.join("docker/abc")));
        assert_eq!(v.cpu_quota, Some(0.5));
        assert_eq!(v.cpus, Some(vec![0, 1, 2, 3, 8]));
        assert_eq!(cg_mem_used(&root.join("docker/abc")), Some(212_144_000));
        let psi = cg_psi(&root.join("docker/abc")).unwrap();
        assert_eq!((psi.mem_some, psi.mem_full), (12.5, 2.0));
        // Unlimited cgroup: nothing. Private cgroupns ("/"): the namespace root's own files.
        assert_eq!(cgroup_view(&root, "/docker").mem_max, None);
        let ns = fixture("cgview-ns");
        put(&ns, "cgroup.type", b"domain\n");
        put(&ns, "memory.max", b"1073741824\n");
        put(&ns, "cpu.max", b"max 100000\n");
        let v = cgroup_view(&ns, "/");
        assert_eq!((v.mem_max, v.cpu_quota), (Some(1 << 30), None));
        assert_eq!(parse_cpu_list("0-1,4,6-7\n"), vec![0, 1, 4, 6, 7]);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&ns);
    }

    #[test]
    fn apportion_by_capacity_keeps_idle_unattributed() {
        // Idle 8-core laptop at 6 W: fat at 0.5% must not be "drawing" ~5.5 W.
        let v = apportion_capacity(6000.0, &[0.5, 0.03, 0.02], 8);
        assert!(v[0] < 5.0, "{v:?}");
        // Fully busy machine: the whole package is attributed.
        let v = apportion_capacity(40_000.0, &[400.0, 400.0], 8);
        assert_eq!(v, vec![20_000.0, 20_000.0]);
        // Never more than the total, even with skewed samples above capacity.
        let v = apportion_capacity(1000.0, &[150.0, 150.0], 2);
        assert!((v.iter().sum::<f32>() - 1000.0).abs() < 0.01, "{v:?}");
        assert_eq!(apportion_capacity(1000.0, &[0.0], 0), vec![0.0]);
    }

    #[test]
    fn apportion_by_cpu() {
        let v = apportion(1000.0, &[50.0, 150.0, 0.0]);
        assert_eq!(v, vec![250.0, 750.0, 0.0]);
        assert_eq!(apportion(1000.0, &[0.0, 0.0]), vec![0.0, 0.0]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_self() {
        let mut p = ProcFs::new(Path::new("/proc"));
        let me = p.read(std::process::id()).expect("self");
        assert!(me.threads >= 1);
        assert!(me.mem > 0);
        assert!(me.io_ok, "own io is readable");
        assert!(me.start_time > 1_000_000_000);
        assert!(me.uid.is_some());
        let c = counters(Path::new("/proc"), std::process::id()).unwrap();
        assert!(c.cpu_ns > 0 || me.counters.cpu_ns == 0);
    }
}
