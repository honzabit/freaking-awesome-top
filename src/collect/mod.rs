//! Local sampling. OWNER: collect-core agent (mod.rs, procs.rs, system.rs).
//!
//! Process table: macOS (and other non-Linux) goes through sysinfo plus the rusage calls in
//! `procs`; Linux reads procfs directly (`linux::ProcFs`) — cpu% from utime+stime deltas is live
//! on the second sample, and threads/nice/cgroup/container come for free. Linux power is RAPL
//! package energy apportioned by cpu share when readable (root), else the cpu-time estimate.
//! Compiled in tests on every OS so its fixture tests run on macOS too.
#[cfg(any(target_os = "linux", test))]
pub mod linux;
pub mod net;
pub mod ports;
pub mod procs;
pub mod system;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, Users};
#[cfg(not(target_os = "linux"))]
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use crate::model::{Proc, Snapshot, System, now_ms};

/// How often the uid -> name table may be reloaded when a lookup misses.
const USERS_REFRESH: Duration = Duration::from_secs(60);

/// Stateful sampler: CPU%, disk rates, energy and net need deltas between samples.
pub struct Collector {
    sys: sysinfo::System,
    users: Users,
    users_loaded: Instant,
    user_names: HashMap<u32, String>,
    deltas: procs::DeltaTracker,
    last_sample: Option<Instant>,
    net: net::NetSampler,
    extras: system::ExtrasCache,
    #[cfg(target_os = "linux")]
    procfs: linux::ProcFs,
    #[cfg(target_os = "linux")]
    rapl: linux::Rapl,
    #[cfg(target_os = "linux")]
    meminfo: Option<linux::MemInfo>,
    /// Latest RAPL package power (mW): the system total, measured, not a sum over processes.
    #[cfg(target_os = "linux")]
    rapl_mw: Option<f64>,
    /// System-wide disk/net rates from /proc/diskstats and /proc/net/dev.
    #[cfg(target_os = "linux")]
    sysio: linux::SysIo,
    #[cfg(target_os = "linux")]
    sysio_rates: Option<[u64; 4]>,
    /// fat's own cgroup limits (a container's --memory/--cpus), re-read every sample.
    #[cfg(target_os = "linux")]
    cg: linux::CgView,
    /// (usage_usec, when) of the cpu-limiting cgroup at the previous sample.
    #[cfg(target_os = "linux")]
    cg_cpu_prev: Option<(u64, Instant)>,
    #[cfg(target_os = "linux")]
    cg_cpu_pct: Option<f32>,
    hostname: String,
    os: String,
    cpu_model: String,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "linux"))]
fn proc_refresh_kind() -> ProcessRefreshKind {
    let kind = ProcessRefreshKind::nothing()
        .with_memory()
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cwd(UpdateKind::OnlyIfNotSet)
        .with_user(UpdateKind::OnlyIfNotSet);
    // On macOS cpu% and disk io come from our own proc_pid_rusage read: it's the same syscall
    // sysinfo would make, and sysinfo's macOS cpu% stays 0 until a process's *third* refresh.
    if cfg!(target_os = "macos") { kind } else { kind.with_cpu().with_disk_usage() }
}

/// User name for `uid` via getpwuid_r (thread-safe).
fn passwd_name(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: passwd is POD; getpwuid_r writes into `pw`/`buf` (sized as passed) and sets
    // `out` to &pw on success. pw_name points into buf, which outlives the read below.
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(uid as libc::uid_t, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out);
        if rc != 0 || out.is_null() || pw.pw_name.is_null() {
            return None;
        }
        let name = std::ffi::CStr::from_ptr(pw.pw_name).to_string_lossy().into_owned();
        (!name.is_empty()).then_some(name)
    }
}

impl Collector {
    pub fn new() -> Self {
        let sys = sysinfo::System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                .with_memory(MemoryRefreshKind::everything()),
        );
        let (hostname, os, cpu_model) = system::static_info(&sys);
        Self {
            sys,
            users: Users::new_with_refreshed_list(),
            users_loaded: Instant::now(),
            user_names: HashMap::new(),
            deltas: procs::DeltaTracker::new(),
            last_sample: None,
            net: net::NetSampler::start(),
            extras: system::ExtrasCache::start(),
            #[cfg(target_os = "linux")]
            procfs: linux::ProcFs::new(std::path::Path::new("/proc")),
            #[cfg(target_os = "linux")]
            rapl: linux::Rapl::discover(std::path::Path::new("/")),
            #[cfg(target_os = "linux")]
            meminfo: None,
            #[cfg(target_os = "linux")]
            rapl_mw: None,
            #[cfg(target_os = "linux")]
            sysio: linux::SysIo::default(),
            #[cfg(target_os = "linux")]
            sysio_rates: None,
            #[cfg(target_os = "linux")]
            cg: linux::CgView::default(),
            #[cfg(target_os = "linux")]
            cg_cpu_prev: None,
            #[cfg(target_os = "linux")]
            cg_cpu_pct: None,
            hostname,
            os,
            cpu_model,
        }
    }

    fn user_name(&mut self, uid: Option<u32>) -> String {
        let Some(uid) = uid else { return String::new() };
        if let Some(n) = self.user_names.get(&uid) {
            return n.clone();
        }
        let lookup = |users: &Users| {
            users.iter().find(|u| **u.id() == uid).map(|u| u.name().to_string())
        };
        let mut name = lookup(&self.users);
        if name.is_none() && self.users_loaded.elapsed() > USERS_REFRESH {
            self.users.refresh();
            self.users_loaded = Instant::now();
            name = lookup(&self.users);
        }
        // sysinfo's list skips system accounts (_windowserver, _mdnsresponder...); ask the
        // directory service directly before falling back to the numeric uid.
        let name = name.or_else(|| passwd_name(uid)).unwrap_or_else(|| uid.to_string());
        self.user_names.insert(uid, name.clone());
        name
    }

    /// Take one snapshot of the local machine (host = "local"). First call may have zero rates.
    pub fn sample(&mut self) -> Snapshot {
        let now = Instant::now();
        let dt = self.last_sample.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0);
        self.last_sample = Some(now);

        self.sys.refresh_cpu_usage();
        #[cfg(target_os = "linux")]
        let (list, power_source) = {
            self.meminfo = linux::meminfo(std::path::Path::new("/proc"));
            if self.meminfo.is_none() {
                self.sys.refresh_memory();
            }
            self.sysio_rates = self.sysio.sample(std::path::Path::new("/"));
            self.sample_cgroup();
            self.sample_procs_linux(dt)
        };
        #[cfg(not(target_os = "linux"))]
        let (list, power_source) = {
            self.sys.refresh_memory();
            self.sample_procs_sysinfo(dt)
        };

        let system = self.build_system(&list, power_source);
        let ports = ports::ports(&list);
        Snapshot {
            ts: now_ms(),
            host: "local".into(),
            system,
            procs: list,
            ports,
            containers: Vec::new(),
            ..Default::default()
        }
    }

    /// Linux process table straight from procfs. Returns (procs sorted by pid, power source).
    #[cfg(target_os = "linux")]
    fn sample_procs_linux(&mut self, dt: f64) -> (Vec<Proc>, &'static str) {
        let net = self.net.latest();
        let gpu = system::proc_gpu();
        let raw = self.procfs.scan();
        let mut alive = HashSet::with_capacity(raw.len());
        let mut list = Vec::with_capacity(raw.len());
        for r in raw {
            // Keyed by raw starttime ticks: finer than seconds, so a recycled pid never inherits.
            let rt = self.deltas.update(r.pid, r.start_ticks, r.counters, dt);
            alive.insert((r.pid, r.start_ticks));
            let user = self.user_name(r.uid);
            let (net_rx_bps, net_tx_bps) = net.get(&r.pid).copied().unwrap_or((0, 0));
            list.push(Proc {
                pid: r.pid,
                ppid: r.ppid,
                name: r.name,
                cmd: r.cmd,
                exe: r.exe,
                cwd: r.cwd,
                user,
                cpu: rt.cpu,
                mem: r.mem,
                virt: r.virt,
                // An unreadable io file (other user's process) leaves these 0; cpu/mem are still
                // real, so usage_unknown stays false.
                disk_read_bps: rt.disk_read_bps,
                disk_write_bps: rt.disk_write_bps,
                net_rx_bps,
                net_tx_bps,
                power_mw: rt.power_mw,
                gpu: gpu.get(&r.pid).copied(),
                threads: r.threads,
                start_time: r.start_time,
                status: r.status.to_string(),
                nice: r.nice,
                usage_unknown: false,
                cgroup: r.cgroup,
                container: r.container,
            });
        }
        self.deltas.retain(&alive);
        list.sort_by_key(|p| p.pid);
        if !self.rapl.available() {
            return (list, "estimate");
        }
        // Package power, split by share of cpu capacity (idle/uncore draw stays unattributed).
        // On the first sample (no delta yet) the per-process estimate values are all zero anyway.
        self.rapl_mw = self.rapl.sample_mw(dt);
        if let Some(total) = self.rapl_mw {
            let cpu: Vec<f32> = list.iter().map(|p| p.cpu).collect();
            let cores = self.sys.cpus().len();
            for (p, mw) in list.iter_mut().zip(linux::apportion_capacity(total, &cpu, cores)) {
                p.power_mw = mw;
            }
        }
        (list, self.rapl.source)
    }

    /// Re-read the limits of fat's own cgroup and the cpu use of the one that sets cpu.max.
    #[cfg(target_os = "linux")]
    fn sample_cgroup(&mut self) {
        let own = std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|t| t.lines().find_map(|l| l.strip_prefix("0::")).map(|p| p.trim().to_string()));
        self.cg = own.map(|o| linux::cgroup_view(std::path::Path::new("/sys/fs/cgroup"), &o)).unwrap_or_default();
        self.cg_cpu_pct = None;
        let usage = self.cg.cpu_dir.as_deref().and_then(linux::cg_usage_usec);
        let now = Instant::now();
        if let (Some(u), Some(q)) = (usage, self.cg.cpu_quota) {
            if let Some((pu, pt)) = self.cg_cpu_prev {
                let dt = now.duration_since(pt).as_secs_f64();
                if dt > 0.0 && q > 0.0 {
                    let cores_used = u.saturating_sub(pu) as f64 / 1e6 / dt;
                    self.cg_cpu_pct = Some((cores_used / q * 100.0).clamp(0.0, 100.0) as f32);
                }
            }
            self.cg_cpu_prev = Some((u, now));
        } else {
            self.cg_cpu_prev = None;
        }
    }

    /// sysinfo-based process table (macOS and other non-Linux). Returns (procs, power source).
    #[cfg(not(target_os = "linux"))]
    fn sample_procs_sysinfo(&mut self, dt: f64) -> (Vec<Proc>, &'static str) {
        self.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, proc_refresh_kind());

        let net = self.net.latest();
        let mut alive = HashSet::new();
        let mut list = Vec::with_capacity(self.sys.processes().len());
        let (mut any_energy, mut any_counters) = (false, false);

        // Collect the sysinfo view first (immutable borrow), then enrich.
        let raw: Vec<_> = self
            .sys
            .processes()
            .values()
            .map(|p| {
                let pid = p.pid().as_u32();
                let cmd = p
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ");
                let uid = p.user_id().map(|u| **u);
                let du = p.disk_usage();
                let base = Proc {
                    pid,
                    ppid: p.parent().map(|pp| pp.as_u32()).unwrap_or(0),
                    name: p.name().to_string_lossy().into_owned(),
                    cmd,
                    exe: p.exe().map(|e| e.display().to_string()).unwrap_or_default(),
                    cwd: p.cwd().map(|e| e.display().to_string()).unwrap_or_default(),
                    cpu: p.cpu_usage(),
                    mem: p.memory(),
                    virt: p.virtual_memory(),
                    start_time: p.start_time(),
                    status: procs::status_char(p.status()).to_string(),
                    threads: p.tasks().map(|t| t.len() as u32).unwrap_or(0),
                    ..Default::default()
                };
                (base, uid, du.read_bytes, du.written_bytes)
            })
            .collect();

        for (mut pr, mut uid, sys_rd, sys_wr) in raw {
            // sysinfo reads ppid/uid/start via PROC_PIDTBSDINFO, which fails for other users'
            // processes when unprivileged (it then reports ppid 0, no user, start 0). The short
            // bsd info + sysctl paths work for everyone, so fill the identity from those.
            if ((pr.ppid == 0 && pr.pid > 1) || uid.is_none() || pr.start_time == 0)
                && let Some(id) = procs::ident(pr.pid)
            {
                if pr.ppid == 0 {
                    pr.ppid = id.ppid;
                }
                if uid.is_none() {
                    uid = Some(id.uid);
                }
                if pr.start_time == 0 {
                    pr.start_time = id.start_time;
                }
            }
            pr.user = self.user_name(uid);
            if let Some(n) = procs::nice(pr.pid) {
                pr.nice = n;
            }
            if let Some(t) = procs::threads(pr.pid) {
                pr.threads = t;
            }
            alive.insert((pr.pid, pr.start_time));
            match procs::counters(pr.pid) {
                Some(c) => {
                    any_energy |= c.has_energy;
                    any_counters = true;
                    let r = self.deltas.update(pr.pid, pr.start_time, c, dt);
                    pr.cpu = r.cpu;
                    pr.power_mw = r.power_mw;
                    pr.disk_read_bps = r.disk_read_bps;
                    pr.disk_write_bps = r.disk_write_bps;
                }
                // On macOS cpu/power come only from rusage; without it (EPERM: another user's
                // process) the zeros mean "not measurable", which callers must not read as idle.
                None if cfg!(target_os = "macos") => pr.usage_unknown = true,
                None if dt > 0.0 => {
                    // sysinfo's disk_usage is "since last refresh".
                    pr.disk_read_bps = (sys_rd as f64 / dt) as u64;
                    pr.disk_write_bps = (sys_wr as f64 / dt) as u64;
                }
                None => {}
            }
            if let Some(&(rx, tx)) = net.get(&pr.pid) {
                pr.net_rx_bps = rx;
                pr.net_tx_bps = tx;
            }
            list.push(pr);
        }
        self.deltas.retain(&alive);
        list.sort_by_key(|p| p.pid);
        // macOS: "rusage" when the kernel's per-task energy counter (V6) is there, "estimate"
        // when only the V4 cpu-time fallback is.
        let source = match (any_counters, any_energy) {
            (_, true) => "rusage",
            (true, false) => "estimate",
            _ => "",
        };
        (list, source)
    }

    fn build_system(&self, list: &[Proc], power_source: &str) -> System {
        let extras = self.extras.get();
        let load = sysinfo::System::load_average();
        let per_core: Vec<f32> = self.sys.cpus().iter().map(|c| c.cpu_usage()).collect();
        let from_sysinfo =
            || (self.sys.total_memory(), self.sys.used_memory(), self.sys.total_swap(), self.sys.used_swap());
        // Linux: used = MemTotal - MemAvailable straight from /proc/meminfo.
        #[cfg(target_os = "linux")]
        let (mem_total, mem_used, swap_total, swap_used) = match self.meminfo {
            Some(m) => (m.total, m.used(), m.swap_total, m.swap_used()),
            None => from_sysinfo(),
        };
        #[cfg(not(target_os = "linux"))]
        let (mem_total, mem_used, swap_total, swap_used) = from_sysinfo();
        #[allow(unused_mut)]
        let mut cpu = self.sys.global_cpu_usage();
        #[allow(unused_mut)]
        let mut per_core = per_core;
        #[allow(unused_mut)]
        let mut mem_pressure = system::mem_pressure();
        #[allow(unused_mut)]
        let mut psi = system::psi();
        // Linux in a limited cgroup (a container with --memory / --cpus / --cpuset-cpus): its
        // limits are what this machine is, not the host's /proc/meminfo and cpu count.
        #[cfg(target_os = "linux")]
        let (mem_total, mem_used) = {
            let (mut total, mut used) = (mem_total, mem_used);
            let mut cg_psi = false;
            if let (Some(max), Some(dir)) = (self.cg.mem_max, self.cg.mem_dir.as_deref())
                && max < total
                && let Some(u) = linux::cg_mem_used(dir)
            {
                total = max;
                used = u.min(max);
                let cpsi = linux::cg_psi(dir);
                mem_pressure = match cpsi.filter(|_| dir.join("memory.pressure").exists()) {
                    Some(p) => system::lx::pressure_from_psi(&p).to_string(),
                    None => system::lx::pressure_from_meminfo(max / 1024, max.saturating_sub(used) / 1024).to_string(),
                };
                if cpsi.is_some() {
                    psi = cpsi;
                    cg_psi = true;
                }
            }
            if let Some(cpus) = self.cg.cpus.as_ref().filter(|c| c.len() < per_core.len() && c.iter().all(|&i| i < per_core.len())) {
                per_core = cpus.iter().map(|&i| per_core[i]).collect();
                cpu = per_core.iter().sum::<f32>() / per_core.len().max(1) as f32;
            }
            if self.cg.cpu_quota.is_some_and(|q| q < per_core.len() as f64) {
                // % of the cpu this cgroup may use (cpu.max), not of the host's cores.
                if let Some(p) = self.cg_cpu_pct {
                    cpu = p;
                }
                if !cg_psi {
                    psi = self.cg.cpu_dir.as_deref().and_then(linux::cg_psi).or(psi);
                }
            }
            (total, used)
        };
        #[cfg(target_os = "linux")]
        let rapl_mw = self.rapl_mw;
        #[cfg(not(target_os = "linux"))]
        let rapl_mw: Option<f64> = None;
        // Linux: totals from the world-readable system counters (an unprivileged user can't
        // read other users' /proc/<pid>/io, and ss -p sees only their own sockets).
        #[cfg(target_os = "linux")]
        let sysio = self.sysio_rates;
        #[cfg(not(target_os = "linux"))]
        let sysio: Option<[u64; 4]> = None;
        let sum = |f: fn(&Proc) -> u64| list.iter().map(f).sum::<u64>();
        let (disk_read_bps, disk_write_bps, net_rx_bps, net_tx_bps) = match sysio {
            Some([r, w, rx, tx]) => (r, w, rx, tx),
            None => (sum(|p| p.disk_read_bps), sum(|p| p.disk_write_bps), sum(|p| p.net_rx_bps), sum(|p| p.net_tx_bps)),
        };
        System {
            hostname: self.hostname.clone(),
            os: self.os.clone(),
            cpu_model: self.cpu_model.clone(),
            cores: per_core.len(),
            per_core,
            cpu,
            load: [load.one, load.five, load.fifteen],
            mem_total,
            mem_used,
            swap_total,
            swap_used,
            mem_pressure,
            thermal: extras.thermal,
            gpus: extras.gpus,
            power_mw: rapl_mw.map(|m| m as f32).unwrap_or_else(|| list.iter().map(|p| p.power_mw).sum()),
            net_rx_bps,
            net_tx_bps,
            disk_read_bps,
            disk_write_bps,
            uptime: sysinfo::System::uptime(),
            battery_pct: extras.battery_pct,
            on_battery: extras.on_battery,
            psi,
            temp_c: extras.temp_c,
            power_source: power_source.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_two_samples_sane() {
        let mut c = Collector::new();
        let t0 = Instant::now();
        let s1 = c.sample();
        let first = t0.elapsed();
        std::thread::sleep(Duration::from_millis(500));
        let mut times = Vec::new();
        let mut s2 = s1.clone();
        for _ in 0..5 {
            let t = Instant::now();
            s2 = c.sample();
            times.push(t.elapsed());
            std::thread::sleep(Duration::from_millis(200));
        }
        eprintln!(
            "procs={} first_sample={:?} steady={:?} power_total={:.0}mW thermal={} gpus={:?} pressure={} batt={:?}",
            s2.procs.len(),
            first,
            times,
            s2.system.power_mw,
            s2.system.thermal,
            s2.system.gpus,
            s2.system.mem_pressure,
            s2.system.battery_pct
        );
        let busiest = s2.procs.iter().map(|p| p.cpu).fold(0.0f32, f32::max);
        eprintln!("busiest proc cpu={busiest:.1}% system cpu={:.1}%", s2.system.cpu);
        let me = std::process::id();
        let p = s2.proc(me).expect("own pid present");
        assert!(p.mem > 0);
        assert!(p.threads >= 1);
        assert!(!p.user.is_empty());
        assert!(s2.system.mem_total > 0);
        assert!(s2.system.mem_used <= s2.system.mem_total);
        assert!(s2.system.cores > 0);
        assert_eq!(s2.system.per_core.len(), s2.system.cores);
        assert!(!s2.system.hostname.is_empty());
        assert!(s2.procs.len() > 10);
        assert_eq!(s2.host, "local");
        assert!(s2.system.power_mw >= 0.0);
    }

    #[test]
    fn two_samples_like_cli_have_cpu() {
        let mut c = Collector::new();
        let _ = c.sample();
        std::thread::sleep(Duration::from_millis(600));
        let s = c.sample();
        let busiest = s.procs.iter().map(|p| p.cpu).fold(0.0f32, f32::max);
        eprintln!("cli-like busiest={busiest} sys={}", s.system.cpu);
        assert!(busiest > 0.0, "per-process cpu must be live on the 2nd sample");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn other_users_processes_keep_identity() {
        let mut c = Collector::new();
        let s = c.sample();
        let launchd = s.proc(1).expect("launchd present");
        assert_eq!(launchd.user, "root");
        assert!(launchd.start_time > 0);
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            assert!(launchd.usage_unknown, "root process usage can't be measured unprivileged");
            // Root-owned daemons must not look orphaned (ppid 0) any more.
            let zero_ppid = s.procs.iter().filter(|p| p.pid > 1 && p.ppid == 0).count();
            assert!(zero_ppid <= 2, "{zero_ppid} processes with unknown parent (a racing exit may explain one or two)");
        }
        let me = s.proc(std::process::id()).unwrap();
        assert!(!me.usage_unknown);
        // System accounts resolve to names, not numeric uids.
        assert_eq!(passwd_name(0).as_deref(), Some("root"));
        if let Some(ws) = s.procs.iter().find(|p| p.name == "WindowServer") {
            assert!(ws.user.parse::<u32>().is_err(), "uid not resolved: {}", ws.user);
        }
    }

    #[test]
    fn collect_sees_stopped_child() {
        // Only touches a child we spawn ourselves.
        let mut child = std::process::Command::new("sleep").arg("300").spawn().expect("spawn sleep");
        let pid = child.id();
        // SAFETY: plain signal to our own child.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
        std::thread::sleep(Duration::from_millis(100));
        let mut c = Collector::new();
        let s = c.sample();
        let p = s.proc(pid).cloned();
        let _ = child.kill();
        let _ = child.wait();
        let p = p.expect("child present");
        assert_eq!(p.ppid, std::process::id());
        assert_eq!(p.name, "sleep");
        assert!(p.cmd.contains("300"));
        assert_eq!(p.status, "T");
        assert_eq!(p.nice, 0);
    }

    /// Linux: cpu% is live on the 2nd sample, threads/start/cgroup are filled, mem matches
    /// /proc/meminfo, and the power source is reported.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_procfs_sample() {
        let mut c = Collector::new();
        let _ = c.sample();
        // Keep this thread busy for 300ms so our own pid has measurable cpu.
        let t = Instant::now();
        while t.elapsed() < Duration::from_millis(300) {
            std::hint::black_box(0u64);
        }
        let s = c.sample();
        let me = s.proc(std::process::id()).expect("self");
        eprintln!("self: {me:?}\nsystem: power_source={} psi={:?} temp={:?}", s.system.power_source, s.system.psi, s.system.temp_c);
        assert!(me.cpu > 20.0, "own cpu {}", me.cpu);
        assert!(me.threads >= 1);
        assert!(me.start_time > 1_000_000_000);
        assert!(!me.user.is_empty());
        assert!(!me.cgroup.is_empty());
        assert!(!me.usage_unknown);
        assert!(me.power_mw > 0.0);
        assert!(matches!(s.system.power_source.as_str(), "rapl" | "estimate"));
        assert!(s.system.mem_used > 0 && s.system.mem_used <= s.system.mem_total);
        let mi = linux::meminfo(std::path::Path::new("/proc")).unwrap();
        assert_eq!(s.system.mem_total, mi.total);
        assert!(s.system.mem_used.abs_diff(mi.used()) < mi.total / 20);
        let init = s.proc(1).expect("pid 1");
        assert_eq!(init.ppid, 0);
        assert!(!init.user.is_empty());
        let total: f32 = s.procs.iter().map(|p| p.power_mw).sum();
        if s.system.power_source == "rapl" {
            // Measured package power; processes get their capacity share, never more.
            assert!(total <= s.system.power_mw + 1.0);
        } else {
            assert!((s.system.power_mw - total).abs() < 1.0);
        }
    }

    /// Linux perf: `FAT_BENCH_N` (default 1000) own `sleep` children, then time steady samples.
    /// Run with `cargo test --release linux_sample_bench -- --ignored --nocapture`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn linux_sample_bench() {
        let n: usize = std::env::var("FAT_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
        let mut kids: Vec<_> =
            (0..n).filter_map(|_| std::process::Command::new("sleep").arg("300").spawn().ok()).collect();
        let mut c = Collector::new();
        let t0 = Instant::now();
        let s = c.sample();
        let first = t0.elapsed();
        let mut times = Vec::new();
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(200));
            let t = Instant::now();
            let _ = c.sample();
            times.push(t.elapsed().as_secs_f64() * 1e3);
        }
        let mut scan = Vec::new();
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(200));
            let t = Instant::now();
            let _ = c.procfs.scan();
            scan.push(t.elapsed().as_secs_f64() * 1e3);
        }
        let t = Instant::now();
        let ports = ports::ports(&s.procs).len();
        let ports_ms = t.elapsed().as_secs_f64() * 1e3;
        eprintln!("procfs scan only ms={scan:.1?}; ports::ports {ports} in {ports_ms:.1}ms");
        for k in &mut kids {
            let _ = k.kill();
            let _ = k.wait();
        }
        times.sort_by(f64::total_cmp);
        eprintln!("procs={} first={first:?} steady_ms={times:.1?} median={:.1}ms", s.procs.len(), times[2]);
    }
}
