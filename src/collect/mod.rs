//! Local sampling. OWNER: collect-core agent (mod.rs, procs.rs, system.rs).
pub mod net;
pub mod ports;
pub mod procs;
pub mod system;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, UpdateKind,
    Users,
};

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
    hostname: String,
    os: String,
    cpu_model: String,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

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
        let name = name.unwrap_or_else(|| uid.to_string());
        self.user_names.insert(uid, name.clone());
        name
    }

    /// Take one snapshot of the local machine (host = "local"). First call may have zero rates.
    pub fn sample(&mut self) -> Snapshot {
        let now = Instant::now();
        let dt = self.last_sample.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0);
        self.last_sample = Some(now);

        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, proc_refresh_kind());

        let net = self.net.latest();
        let mut alive = HashSet::new();
        let mut list = Vec::with_capacity(self.sys.processes().len());

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

        for (mut pr, uid, sys_rd, sys_wr) in raw {
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
                    let r = self.deltas.update(pr.pid, pr.start_time, c, dt);
                    pr.cpu = r.cpu;
                    pr.power_mw = r.power_mw;
                    pr.disk_read_bps = r.disk_read_bps;
                    pr.disk_write_bps = r.disk_write_bps;
                }
                None if dt > 0.0 && !cfg!(target_os = "macos") => {
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

        let system = self.build_system(&list);
        let ports = ports::ports(&list);
        Snapshot {
            ts: now_ms(),
            host: "local".into(),
            system,
            procs: list,
            ports,
            containers: Vec::new(),
        }
    }

    fn build_system(&self, list: &[Proc]) -> System {
        let extras = self.extras.get();
        let load = sysinfo::System::load_average();
        let per_core: Vec<f32> = self.sys.cpus().iter().map(|c| c.cpu_usage()).collect();
        System {
            hostname: self.hostname.clone(),
            os: self.os.clone(),
            cpu_model: self.cpu_model.clone(),
            cores: per_core.len(),
            per_core,
            cpu: self.sys.global_cpu_usage(),
            load: [load.one, load.five, load.fifteen],
            mem_total: self.sys.total_memory(),
            mem_used: self.sys.used_memory(),
            swap_total: self.sys.total_swap(),
            swap_used: self.sys.used_swap(),
            mem_pressure: system::mem_pressure(),
            thermal: extras.thermal,
            gpus: extras.gpus,
            power_mw: list.iter().map(|p| p.power_mw).sum(),
            net_rx_bps: list.iter().map(|p| p.net_rx_bps).sum(),
            net_tx_bps: list.iter().map(|p| p.net_tx_bps).sum(),
            disk_read_bps: list.iter().map(|p| p.disk_read_bps).sum(),
            disk_write_bps: list.iter().map(|p| p.disk_write_bps).sum(),
            uptime: sysinfo::System::uptime(),
            battery_pct: extras.battery_pct,
            on_battery: extras.on_battery,
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
}
