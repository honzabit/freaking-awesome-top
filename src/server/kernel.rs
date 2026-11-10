//! Kernel health and the kernel event stream. OWNER: kernel agent.
//!
//! Sources (all optional; missing ones leave the field None/empty and add a Kernel.notes line):
//! /proc/stat (steal, iowait, irq, softirq, procs_blocked), /proc/pressure/*, /proc/vmstat
//! (oom_kill, pswpin/out), /proc/meminfo, /sys/devices/system/node/node*/meminfo, /proc/diskstats
//! (+ /sys/class/block/*/partition to drop partitions, /sys/block/*/device/ioerr_cnt),
//! /proc/sys/fs/file-nr, /proc/sys/net/netfilter/nf_conntrack_{count,max},
//! /proc/sys/net/ipv4/ip_local_port_range + /proc/net/{tcp,tcp6}, /proc/net/snmp + netstat
//! (RetransSegs, ListenOverflows, ListenDrops, TCPBacklogDrop), /proc/<pid>/{stat,wchan} for D
//! state, /proc/self/mountinfo, /sys/fs/ext4/*/errors_count, /proc/sys/kernel/tainted,
//! adjtimex(2) for clock sync, /proc/mdstat, and the kernel log: /dev/kmsg (non-blocking, needs
//! root or kernel.dmesg_restrict=0), else `journalctl -k` (needs journal read access), else a
//! "needs root" note.
//! Works on any kernel still in common use: parse defensively, absent columns -> 0/None.
//!
//! Cost (per sample): a handful of small procfs reads. The two that grow with the host are
//! bounded: /proc/net/tcp{,6} (grows with sockets) is rescanned at most every
//! `ServerCfg::unit_refresh_s` unless the last scan was already near the threshold, and the
//! kernel log fallback (`journalctl`) runs at most every `unit_refresh_s`.
//!
//! Events are edge-triggered (fire when a condition starts, re-arm when it clears to half the
//! threshold) and identical kernel-log events within one sample are collapsed with a `repeats`
//! count, so a flood of I/O errors costs one row, not thousands.
use super::{
    DStateProc, DiskStat, Event, EventKind, FsErrorStat, Kernel, MdArray, NumaNode, OomInfo, Pressure, ServerCfg,
    Severity, Unit,
};
use crate::model::{Proc, Ts, now_ms};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Stateful sampler: previous /proc/stat, diskstats, snmp and vmstat counters; D-state first
/// seen times; kmsg read position; mount rw/ro state seen at start.
pub struct KernelSampler {
    cfg: ServerCfg,
    pending: Vec<Event>,
    /// "/" in production; a fixture directory in tests (holds proc/... and sys/...).
    root: PathBuf,
    /// Read the live kernel log and clock (false for fixture roots).
    live: bool,
    last_at: Option<Instant>,
    prev_cpu: Option<[u64; 8]>,
    prev_disks: HashMap<String, DiskCounters>,
    prev_net: HashMap<String, u64>,
    prev_vm: Option<VmCounters>,
    /// (pid, starttime) -> first time seen in D state.
    dstate_first: HashMap<(u32, u64), Ts>,
    dstate_reported: HashSet<(u32, u64)>,
    /// mount id -> (mount point, was read-write when first seen).
    mounts: HashMap<u64, (String, bool)>,
    ro_remounts: Vec<String>,
    /// Device basename ("sda1", "dm-0") -> mount point, from the last mountinfo read.
    dev_mounts: HashMap<String, String>,
    /// Mount source -> kernel device name (symlinks like /dev/mapper/x resolved once).
    dev_names: HashMap<String, String>,
    ext4_errors: HashMap<String, u64>,
    taint: Option<u64>,
    ntp_synced: Option<bool>,
    md_degraded: HashSet<String>,
    /// Edge-trigger state: condition key -> active.
    active: HashSet<String>,
    eph_cache: Option<(Instant, Option<(u64, String)>)>,
    log: KernelLog,
    /// Last units seen (cgroup, name), longest cgroup first: maps memcgs and pids to units.
    unit_cgroups: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, Default)]
struct VmCounters {
    pswpin: u64,
    pswpout: u64,
    oom_kill: Option<u64>,
}

/// Where kernel log lines come from.
enum KernelLog {
    /// Not opened yet.
    Init,
    Kmsg {
        file: fs::File,
        last_seq: Option<u64>,
        asm: OomAssembler,
    },
    Journal {
        cursor: Option<String>,
        since_s: i64,
        last_run: Option<Instant>,
        asm: OomAssembler,
    },
    Off(String),
}

impl KernelSampler {
    pub fn new(cfg: &ServerCfg) -> KernelSampler {
        Self::with_root(cfg, Path::new("/"), true)
    }

    fn with_root(cfg: &ServerCfg, root: &Path, live: bool) -> KernelSampler {
        KernelSampler {
            cfg: cfg.clone(),
            pending: Vec::new(),
            root: root.to_path_buf(),
            live,
            last_at: None,
            prev_cpu: None,
            prev_disks: HashMap::new(),
            prev_net: HashMap::new(),
            prev_vm: None,
            dstate_first: HashMap::new(),
            dstate_reported: HashSet::new(),
            mounts: HashMap::new(),
            ro_remounts: Vec::new(),
            dev_mounts: HashMap::new(),
            dev_names: HashMap::new(),
            ext4_errors: HashMap::new(),
            taint: None,
            ntp_synced: None,
            md_degraded: HashSet::new(),
            active: HashSet::new(),
            eph_cache: None,
            log: if live && cfg.kmsg {
                KernelLog::Init
            } else {
                KernelLog::Off("kernel log disabled ([server] kmsg = false)".into())
            },
            unit_cgroups: Vec::new(),
        }
    }

    /// Kernel state over the interval since the previous call (first call: rates 0). `units`
    /// maps D-state pids to units. Queues events: oom_kill (kmsg, enriched with OomInfo; else
    /// vmstat delta with unknown victim), hung_task, kernel_warn, disk_error, ro_remount,
    /// disk_latency_spike (await > cfg.disk_await_warn_ms), exhaustion (fd/conntrack/ports >=
    /// cfg.exhaustion_warn), pressure_spike, clock_unsynced. None on non-Linux.
    pub fn sample(&mut self, procs: &[Proc], units: &[Unit]) -> Option<Kernel> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let now = Instant::now();
        let dt = self.last_at.map(|t| now.duration_since(t).as_secs_f64());
        self.last_at = Some(now);
        Some(self.sample_at(procs, units, now_ms(), dt))
    }

    /// Events detected since the last drain, oldest first.
    pub fn drain_events(&mut self) -> Vec<Event> {
        let mut v = std::mem::take(&mut self.pending);
        v.sort_by_key(|e| e.ts);
        v
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn read(&self, rel: &str) -> Option<String> {
        fs::read_to_string(self.p(rel)).ok()
    }

    /// Edge trigger: true when `key` goes from inactive to active.
    fn rise(&mut self, key: &str, on: bool, clear: bool) -> bool {
        if on {
            return self.active.insert(key.to_string());
        }
        if clear {
            self.active.remove(key);
        }
        false
    }

    fn unit_for_cgroup(&self, cg: &str) -> Option<String> {
        if cg.is_empty() {
            return None;
        }
        // The kernel log prints memcgs from the root cgroup namespace, so inside a container or
        // VM with its own namespace the unit's path is a suffix ("/<outer>/system.slice/x.scope").
        let hit = self.unit_cgroups.iter().find(|(c, _)| {
            !c.is_empty()
                && c != "/"
                && (cg == c
                    || cg.starts_with(&format!("{c}/"))
                    || cg.ends_with(c.as_str())
                    || cg.contains(&format!("{c}/")))
        });
        hit.map(|(_, n)| n.clone()).or_else(|| super::unit_of_cgroup(cg).map(|u| u.key))
    }

    /// The whole sample with an explicit clock (tests drive it with fixture roots).
    fn sample_at(&mut self, procs: &[Proc], units: &[Unit], now: Ts, dt: Option<f64>) -> Kernel {
        let mut k = Kernel::default();
        let dt = dt.filter(|d| *d > 0.0);
        let rate = |cur: u64, prev: u64| dt.map_or(0.0, |d| cur.saturating_sub(prev) as f64 / d) as f32;
        let mut units_cg: Vec<(String, String)> = units.iter().map(|u| (u.cgroup.clone(), u.name.clone())).collect();
        units_cg.sort_by_key(|(c, _)| std::cmp::Reverse(c.len()));
        self.unit_cgroups = units_cg;

        // CPU shares and run queue.
        match self.read("proc/stat").map(|s| parse_stat(&s)) {
            Some(st) => {
                if let Some(prev) = self.prev_cpu {
                    let d: Vec<u64> = st.cpu.iter().zip(prev.iter()).map(|(a, b)| a.saturating_sub(*b)).collect();
                    let total: u64 = d.iter().sum();
                    if total > 0 {
                        let pct = |i: usize| (d[i] as f64 * 100.0 / total as f64) as f32;
                        (k.iowait_pct, k.irq_pct, k.softirq_pct, k.steal_pct) = (pct(4), pct(5), pct(6), pct(7));
                    }
                }
                self.prev_cpu = Some(st.cpu);
                k.procs_running = st.procs_running;
                k.procs_blocked = st.procs_blocked;
            }
            None => k.notes.push("/proc/stat unreadable".into()),
        }

        // Pressure (some + full).
        k.pressure = self.read_pressure();
        if k.pressure.is_none() {
            k.notes.push(
                "no PSI: /proc/pressure unreadable (kernel < 4.20, CONFIG_PSI off, psi=0, or hidden in this container)"
                    .into(),
            );
        }

        if let Some(m) = self.read("proc/meminfo") {
            k.mem_available = meminfo_kb(&m, "MemAvailable").unwrap_or(0) * 1024;
        }

        // vmstat: swap rates, OOM kill counter.
        let vm = self.read("proc/vmstat").map(|s| parse_vmstat(&s)).unwrap_or_default();
        let prev_vm = self.prev_vm.replace(vm);
        if let Some(p) = prev_vm {
            k.swap_in_ps = rate(vm.pswpin, p.pswpin);
            k.swap_out_ps = rate(vm.pswpout, p.pswpout);
        }
        k.oom_kills_total = vm.oom_kill.unwrap_or(0);

        k.numa = self.read_numa();
        k.disks = self.read_disks(dt, now);

        // File handles.
        if let Some((used, max)) = self.read("proc/sys/fs/file-nr").and_then(|s| parse_file_nr(&s)) {
            k.fd_used = Some(used);
            k.fd_max = Some(max);
        }
        let num = |rel: &str| self.read(rel).and_then(|s| s.trim().parse::<u64>().ok());
        k.conntrack_used = num("proc/sys/net/netfilter/nf_conntrack_count");
        k.conntrack_max = num("proc/sys/net/netfilter/nf_conntrack_max");

        // Ephemeral ports.
        k.ephemeral_range = self.read("proc/sys/net/ipv4/ip_local_port_range").and_then(|s| parse_port_range(&s));
        let mut eph_dest = None;
        if let Some(range) = k.ephemeral_range
            && let Some((used, dest)) = self.ephemeral(range)
        {
            k.ephemeral_used = Some(used);
            eph_dest = (!dest.is_empty()).then_some(dest);
        }

        // TCP counters.
        let mut net = HashMap::new();
        for f in ["proc/net/snmp", "proc/net/netstat"] {
            if let Some(s) = self.read(f) {
                net.extend(parse_snmp(&s));
            }
        }
        if !self.prev_net.is_empty() {
            let r = |key: &str| rate(*net.get(key).unwrap_or(&0), *self.prev_net.get(key).unwrap_or(&0));
            k.tcp_retrans_ps = r("Tcp.RetransSegs");
            k.listen_overflows_ps = r("TcpExt.ListenOverflows");
            k.listen_drops_ps = r("TcpExt.ListenDrops") + r("TcpExt.TCPBacklogDrop");
        }
        self.prev_net = net;

        k.d_state = self.read_dstate(procs, k.procs_blocked, now, &mut k.notes);
        k.fs_errors = self.read_mounts_and_fs_errors(now);
        k.ro_remounts = self.ro_remounts.clone();

        if let Some(t) = self.read("proc/sys/kernel/tainted").and_then(|s| s.trim().parse::<u64>().ok()) {
            k.taint = t;
            k.taint_flags = decode_taint(t);
            if let Some(old) = self.taint {
                let new_bits = t & !old;
                // W (warning), D (oops), L (soft lockup), M (machine check), B (bad page).
                let serious = new_bits & ((1 << 9) | (1 << 7) | (1 << 14) | (1 << 4) | (1 << 5));
                if serious != 0 {
                    let sev =
                        if new_bits & ((1 << 7) | (1 << 4) | (1 << 5)) != 0 { Severity::Crit } else { Severity::Warn };
                    let mut e = event(
                        now,
                        EventKind::KernelWarn,
                        sev,
                        "kernel",
                        format!("kernel taint gained {} (now {})", decode_taint(new_bits), k.taint_flags),
                        "procfs",
                    );
                    e.value = Some(t as f64);
                    self.pending.push(e);
                }
            }
            self.taint = Some(t);
        }

        k.ntp_synced = if self.live { clock_synced() } else { self.read("ntp_synced").map(|s| s.trim() == "1") };
        if let Some(s) = k.ntp_synced {
            if !s && self.ntp_synced != Some(false) {
                self.pending.push(event(
                    now,
                    EventKind::ClockUnsynced,
                    Severity::Warn,
                    "host",
                    "system clock is not synchronised (kernel max error >= 16 s)".into(),
                    "procfs",
                ));
            }
            self.ntp_synced = Some(s);
        }

        if let Some(s) = self.read("proc/mdstat") {
            k.mdraid = parse_mdstat(&s);
            for a in &k.mdraid {
                if a.degraded && self.md_degraded.insert(a.name.clone()) {
                    let mut e = event(
                        now,
                        EventKind::DiskError,
                        Severity::Crit,
                        &format!("disk:{}", a.name),
                        format!("md array {} ({}) is degraded: {}", a.name, a.level, a.state),
                        "procfs",
                    );
                    e.value = a.sync_pct.map(f64::from);
                    self.pending.push(e);
                } else if !a.degraded {
                    self.md_degraded.remove(&a.name);
                }
            }
        }

        self.threshold_events(&k, now, eph_dest);
        self.read_kernel_log(&k, now, prev_vm, vm);
        if let KernelLog::Off(why) = &self.log
            && self.live
            && self.cfg.kmsg
        {
            k.notes.push(why.clone());
        }
        collapse(&mut self.pending);
        k
    }

    fn read_pressure(&self) -> Option<Pressure> {
        use crate::collect::system::lx::parse_psi_file;
        let rd = |f: &str| self.read(&format!("proc/pressure/{f}")).map(|s| parse_psi_file(&s));
        let (cpu, mem, io) = (rd("cpu"), rd("memory"), rd("io"));
        if cpu.is_none() && mem.is_none() && io.is_none() {
            return None;
        }
        let (c, m, i) = (cpu.unwrap_or_default(), mem.unwrap_or_default(), io.unwrap_or_default());
        Some(Pressure {
            cpu_some: c.0.unwrap_or(0.0),
            cpu_full: c.1.unwrap_or(0.0),
            mem_some: m.0.unwrap_or(0.0),
            mem_full: m.1.unwrap_or(0.0),
            io_some: i.0.unwrap_or(0.0),
            io_full: i.1.unwrap_or(0.0),
        })
    }

    fn read_numa(&self) -> Vec<NumaNode> {
        let Ok(rd) = fs::read_dir(self.p("sys/devices/system/node")) else { return Vec::new() };
        let mut v: Vec<NumaNode> = rd
            .flatten()
            .filter_map(|e| {
                let node: u32 = e.file_name().to_string_lossy().strip_prefix("node")?.parse().ok()?;
                let s = fs::read_to_string(e.path().join("meminfo")).ok()?;
                // "Node 0 MemTotal:  8000000 kB"
                let kb = |key: &str| {
                    s.lines().find_map(|l| {
                        l.split_once(key).and_then(|(_, r)| r.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
                    })
                };
                Some(NumaNode {
                    node,
                    mem_total: kb("MemTotal:").unwrap_or(0) * 1024,
                    mem_free: kb("MemFree:").unwrap_or(0) * 1024,
                })
            })
            .collect();
        v.sort_by_key(|n| n.node);
        v
    }

    fn read_disks(&mut self, dt: Option<f64>, now: Ts) -> Vec<DiskStat> {
        let Some(text) = self.read("proc/diskstats") else { return Vec::new() };
        let sysblock = self.p("sys/class/block");
        let have_sys = sysblock.is_dir();
        let cur: Vec<DiskCounters> = parse_diskstats(&text)
            .into_iter()
            .filter(|d| !(have_sys && sysblock.join(&d.name).join("partition").exists()))
            .collect();
        let mut out = Vec::with_capacity(cur.len());
        for d in &cur {
            let mut s = DiskStat { name: d.name.clone(), ..Default::default() };
            if let (Some(dt), Some(p)) = (dt, self.prev_disks.get(&d.name)) {
                let dd = |a: u64, b: u64| a.saturating_sub(b);
                let (r, w) = (dd(d.reads, p.reads), dd(d.writes, p.writes));
                let dt_ms = dt * 1000.0;
                s.r_iops = (r as f64 / dt) as f32;
                s.w_iops = (w as f64 / dt) as f32;
                s.r_bps = (dd(d.read_sectors, p.read_sectors) as f64 * 512.0 / dt) as u64;
                s.w_bps = (dd(d.write_sectors, p.write_sectors) as f64 * 512.0 / dt) as u64;
                s.r_await_ms = if r > 0 { dd(d.read_ms, p.read_ms) as f32 / r as f32 } else { 0.0 };
                s.w_await_ms = if w > 0 { dd(d.write_ms, p.write_ms) as f32 / w as f32 } else { 0.0 };
                s.util_pct = ((dd(d.io_ms, p.io_ms) as f64 / dt_ms) * 100.0).min(100.0) as f32;
                s.queue_depth = (dd(d.weighted_ms, p.weighted_ms) as f64 / dt_ms) as f32;
            }
            s.io_errors = fs::read_to_string(self.p(&format!("sys/block/{}/device/ioerr_cnt", d.name)))
                .ok()
                .and_then(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok());
            out.push(s);
        }
        let _ = now;
        self.prev_disks = cur.into_iter().map(|d| (d.name.clone(), d)).collect();
        out
    }

    /// (ports used, busiest destination) — rescanned at most every unit_refresh_s unless the
    /// previous scan was already above half the warning threshold.
    fn ephemeral(&mut self, range: (u16, u16)) -> Option<(u64, String)> {
        let span = (range.1 as u64).saturating_sub(range.0 as u64) + 1;
        if let Some((at, prev)) = &self.eph_cache {
            let near =
                prev.as_ref().is_some_and(|(u, _)| *u as f64 >= span as f64 * self.cfg.exhaustion_warn as f64 / 2.0);
            if !near && at.elapsed().as_secs() < self.cfg.unit_refresh_s {
                return prev.clone();
            }
        }
        let mut texts = Vec::new();
        for f in ["proc/net/tcp", "proc/net/tcp6"] {
            if let Some(s) = self.read(f) {
                texts.push(s);
            }
        }
        let res = (!texts.is_empty()).then(|| {
            let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
            ephemeral_usage(&refs, range)
        });
        self.eph_cache = Some((Instant::now(), res.clone()));
        res
    }

    fn read_dstate(&mut self, procs: &[Proc], blocked: u32, now: Ts, notes: &mut Vec<String>) -> Vec<DStateProc> {
        let mut seen = HashSet::new();
        let mut out: Vec<DStateProc> = Vec::new();
        let mut new_long = Vec::new();
        let mut wchan_hidden = false;
        // One task (main thread or worker thread) confirmed in D: track its episode by
        // (tid, starttime) so a recycled tid starts a new one; report it under its process.
        let mut task = |this: &mut Self,
                        p: &Proc,
                        dir: &str,
                        start: u64,
                        out: &mut Vec<DStateProc>,
                        new_long: &mut Vec<DStateProc>| {
            let tid: u32 = dir.rsplit('/').next().and_then(|t| t.parse().ok()).unwrap_or(p.pid);
            let key = (tid, start);
            seen.insert(key);
            let first = *this.dstate_first.entry(key).or_insert(now);
            let secs = ((now - first).max(0) / 1000) as u64;
            if secs < this.cfg.dstate_min_s {
                return;
            }
            let wchan = this.read(&format!("{dir}/wchan")).map(|s| s.trim().to_string()).unwrap_or_default();
            let wchan = if wchan.is_empty() || wchan == "0" {
                wchan_hidden = true;
                String::new()
            } else {
                wchan
            };
            let d = DStateProc {
                pid: p.pid,
                name: p.name.clone(),
                wchan,
                seconds: secs,
                unit: this.unit_for_cgroup(&p.cgroup),
            };
            // A process with several blocked threads is one row (its longest-blocked thread)
            // and one event.
            let fresh = this.dstate_reported.insert(key);
            if let Some(x) = out.iter_mut().find(|x| x.pid == p.pid) {
                if d.seconds > x.seconds {
                    *x = d;
                }
                return;
            }
            if fresh && !new_long.iter().any(|x: &DStateProc| x.pid == p.pid) {
                new_long.push(d.clone());
            }
            out.push(d);
        };
        // Proc.status maps Linux 'D' to "U"; confirm from /proc/<pid>/stat (also gives starttime
        // so a recycled pid starts a new episode).
        let mut found = 0u32;
        for p in procs.iter().filter(|p| p.status == "U" || p.status == "D") {
            let dir = format!("proc/{}", p.pid);
            let Some(st) = self.read(&format!("{dir}/stat")) else { continue };
            let Some((state, start)) = stat_state_start(&st) else { continue };
            if state != 'D' {
                continue;
            }
            found += 1;
            task(self, p, &dir, start, &mut out, &mut new_long);
        }
        // /proc/stat counts every blocked task, threads included, but /proc/<pid>/stat shows
        // only the main thread: a thread-pool server whose I/O threads are stuck while its main
        // thread sleeps would be invisible. When the kernel counts more blocked tasks than found,
        // walk the threads of multi-threaded processes, bounded by `dstate_max_thread_reads`.
        if blocked > found {
            let mut reads = 0usize;
            let max = self.cfg.dstate_max_thread_reads;
            let mut multi: Vec<&Proc> = procs.iter().filter(|p| p.threads > 1).collect();
            multi.sort_by_key(|p| std::cmp::Reverse(p.threads));
            'procs: for p in multi {
                let Ok(rd) = fs::read_dir(self.p(&format!("proc/{}/task", p.pid))) else { continue };
                for ent in rd.flatten() {
                    let Some(tid) = ent.file_name().to_str().and_then(|t| t.parse::<u32>().ok()) else { continue };
                    if tid == p.pid {
                        continue; // the main thread was checked above
                    }
                    if reads >= max || found >= blocked {
                        break 'procs;
                    }
                    reads += 1;
                    let dir = format!("proc/{}/task/{tid}", p.pid);
                    let Some(st) = self.read(&format!("{dir}/stat")) else { continue };
                    if let Some(('D', start)) = stat_state_start(&st) {
                        found += 1;
                        task(self, p, &dir, start, &mut out, &mut new_long);
                    }
                }
            }
            if reads >= max && found < blocked {
                notes.push(format!(
                    "{} blocked tasks, {found} found: thread scan stopped at server.dstate_max_thread_reads ({max})",
                    blocked
                ));
            }
        }
        self.dstate_first.retain(|k, _| seen.contains(k));
        self.dstate_reported.retain(|k| seen.contains(k));
        if wchan_hidden && unsafe { libc::geteuid() } != 0 {
            notes.push("needs root: wchan of other users' D-state processes".into());
        }
        out.sort_by(|a, b| b.seconds.cmp(&a.seconds).then(a.pid.cmp(&b.pid)));
        for d in new_long {
            let mut e = event(
                now,
                EventKind::HungTask,
                Severity::Warn,
                &format!("pid:{}", d.pid),
                format!(
                    "{} (pid {}) blocked in D state for {}s{}",
                    d.name,
                    d.pid,
                    d.seconds,
                    if d.wchan.is_empty() { String::new() } else { format!(" in {}", d.wchan) }
                ),
                "procfs",
            );
            e.pid = Some(d.pid);
            e.unit = d.unit.clone();
            e.value = Some(d.seconds as f64);
            if !d.wchan.is_empty() {
                e.extra.insert("wchan".into(), d.wchan.clone());
            }
            self.pending.push(e);
        }
        out
    }

    fn read_mounts_and_fs_errors(&mut self, now: Ts) -> Vec<FsErrorStat> {
        let mi = self.read("proc/self/mountinfo").map(|s| parse_mountinfo(&s)).unwrap_or_default();
        let mut seen = HashSet::new();
        // device basename -> (mount point, read-only)
        let mut dev_mount: HashMap<String, (String, bool)> = HashMap::new();
        for m in &mi {
            seen.insert(m.id);
            if let Some(dev) = m.source.strip_prefix("/dev/") {
                let live = self.live;
                let base = self
                    .dev_names
                    .entry(m.source.clone())
                    .or_insert_with(|| {
                        let real = if live {
                            fs::canonicalize(&m.source)
                                .ok()
                                .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
                        } else {
                            None
                        };
                        real.unwrap_or_else(|| dev.rsplit('/').next().unwrap_or(dev).to_string())
                    })
                    .clone();
                dev_mount.entry(base).or_insert((m.mount_point.clone(), m.read_only));
            }
            if VIRTUAL_FS.contains(&m.fstype.as_str()) {
                continue;
            }
            match self.mounts.get(&m.id) {
                None => {
                    self.mounts.insert(m.id, (m.mount_point.clone(), !m.read_only));
                }
                Some((mp, true)) if m.read_only => {
                    let mp = mp.clone();
                    self.mounts.insert(m.id, (mp.clone(), false));
                    if !self.ro_remounts.contains(&mp) {
                        self.ro_remounts.push(mp.clone());
                    }
                    let mut e = event(
                        now,
                        EventKind::RoRemount,
                        Severity::Crit,
                        &format!("mount:{mp}"),
                        format!("{mp} ({}, {}) went read-only", m.source, m.fstype),
                        "procfs",
                    );
                    e.extra.insert("device".into(), m.source.clone());
                    self.pending.push(e);
                }
                Some(_) => {}
            }
        }
        self.mounts.retain(|id, _| seen.contains(id));
        if self.dev_names.len() > 4 * mi.len().max(64) {
            self.dev_names.clear();
        }
        self.dev_mounts = dev_mount.iter().map(|(d, (m, _))| (d.clone(), m.clone())).collect();

        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(self.p("sys/fs/ext4")) {
            for e in rd.flatten() {
                let dev = e.file_name().to_string_lossy().into_owned();
                let Some(n) =
                    fs::read_to_string(e.path().join("errors_count")).ok().and_then(|s| s.trim().parse::<u64>().ok())
                else {
                    continue;
                };
                let (mount, ro) = dev_mount.get(&dev).cloned().map_or((None, false), |(m, r)| (Some(m), r));
                let prev = self.ext4_errors.insert(dev.clone(), n);
                if prev.is_some_and(|p| n > p) {
                    let mut ev = event(
                        now,
                        EventKind::DiskError,
                        Severity::Crit,
                        &format!("disk:{dev}"),
                        format!(
                            "ext4 on {dev}{} recorded {} new error(s) ({} total)",
                            mount.as_deref().map(|m| format!(" ({m})")).unwrap_or_default(),
                            n - prev.unwrap_or(0),
                            n
                        ),
                        "procfs",
                    );
                    ev.value = Some(n as f64);
                    self.pending.push(ev);
                }
                if n > 0 || ro {
                    out.push(FsErrorStat { device: dev, mount, errors: n, read_only: ro });
                }
            }
        }
        out.sort_by(|a, b| a.device.cmp(&b.device));
        out
    }

    fn threshold_events(&mut self, k: &Kernel, now: Ts, eph_dest: Option<String>) {
        let warn = self.cfg.exhaustion_warn.clamp(0.01, 1.0) as f64;
        let checks: [(&str, Option<u64>, Option<u64>, &str); 3] = [
            ("fd", k.fd_used, k.fd_max, "file handles"),
            ("conntrack", k.conntrack_used, k.conntrack_max, "conntrack entries"),
            (
                "ephemeral",
                k.ephemeral_used,
                k.ephemeral_range.map(|(a, b)| (b as u64).saturating_sub(a as u64) + 1),
                "ephemeral ports",
            ),
        ];
        for (key, used, max, what) in checks {
            let (Some(u), Some(m)) = (used, max) else { continue };
            if m == 0 {
                continue;
            }
            let r = u as f64 / m as f64;
            if self.rise(&format!("exh:{key}"), r >= warn, r < warn / 2.0) {
                let sev = if r >= 0.98 { Severity::Crit } else { Severity::Warn };
                let mut detail = format!("{what} at {:.0}% of the limit ({u} of {m})", r * 100.0);
                if key == "ephemeral"
                    && let Some(d) = &eph_dest
                {
                    detail.push_str(&format!("; busiest destination {d}"));
                }
                let mut e = event(now, EventKind::Exhaustion, sev, "kernel", detail, "procfs");
                e.value = Some(r * 100.0);
                e.extra.insert("resource".into(), key.into());
                self.pending.push(e);
            }
        }
        let lim = self.cfg.disk_await_warn_ms.max(0.001);
        for d in &k.disks {
            let a = d.r_await_ms.max(d.w_await_ms);
            let busy = d.r_iops + d.w_iops > 0.0;
            if self.rise(&format!("disk:{}", d.name), busy && a > lim, !busy || a < lim / 2.0) {
                let sev = if a > lim * 10.0 { Severity::Crit } else { Severity::Warn };
                let mut e = event(
                    now,
                    EventKind::DiskLatencySpike,
                    sev,
                    &format!("disk:{}", d.name),
                    format!(
                        "{} await r {:.0} ms / w {:.0} ms (util {:.0}%, queue {:.1}, {:.0} iops)",
                        d.name,
                        d.r_await_ms,
                        d.w_await_ms,
                        d.util_pct,
                        d.queue_depth,
                        d.r_iops + d.w_iops
                    ),
                    "procfs",
                );
                e.value = Some(a as f64);
                self.pending.push(e);
            }
        }
        if let Some(p) = k.pressure {
            let lim = self.cfg.pressure_full_warn.max(0.01);
            for (res, full) in [("cpu", p.cpu_full), ("memory", p.mem_full), ("io", p.io_full)] {
                if self.rise(&format!("psi:{res}"), full >= lim, full < lim / 2.0) {
                    let sev = if full >= lim * 4.0 { Severity::Crit } else { Severity::Warn };
                    let mut e = event(
                        now,
                        EventKind::PressureSpike,
                        sev,
                        "host",
                        format!(
                            "{res} pressure: all non-idle tasks stalled {full:.1}% of the last 10s (PSI full avg10)"
                        ),
                        "procfs",
                    );
                    e.value = Some(full as f64);
                    e.extra.insert("resource".into(), res.into());
                    self.pending.push(e);
                }
            }
        }
    }

    fn read_kernel_log(&mut self, _k: &Kernel, now: Ts, prev_vm: Option<VmCounters>, vm: VmCounters) {
        if matches!(self.log, KernelLog::Init) {
            self.log = open_kernel_log(now);
        }
        let mut raw: Vec<Event> = Vec::new();
        match &mut self.log {
            KernelLog::Kmsg { file, last_seq, asm } => {
                let boot = boot_ms();
                let mut lost = 0u64;
                read_kmsg_records(file, |rec| {
                    if let Some((seq, _)) = kmsg_seq(rec) {
                        if let Some(l) = *last_seq
                            && seq > l + 1
                        {
                            lost += seq - l - 1;
                        }
                        *last_seq = Some(seq);
                    }
                    raw.extend(asm.feed(rec, boot));
                });
                if lost > 0 {
                    raw.push(event(
                        now,
                        EventKind::Other,
                        Severity::Info,
                        "kernel",
                        format!("{lost} kernel log records were overwritten before fat read them"),
                        "kmsg",
                    ));
                }
            }
            KernelLog::Journal { cursor, since_s, last_run, asm } => {
                if last_run.is_none_or(|t| t.elapsed().as_secs() >= self.cfg.unit_refresh_s) {
                    *last_run = Some(Instant::now());
                    match journal_records(cursor.as_deref(), *since_s) {
                        Ok((recs, cur)) => {
                            if cur.is_some() {
                                *cursor = cur;
                            }
                            for (ts, rec) in recs {
                                raw.extend(asm.feed_at(&rec, ts));
                            }
                        }
                        Err(e) => self.log = KernelLog::Off(e),
                    }
                }
            }
            _ => {}
        }
        let kmsg_ooms = raw.iter().filter(|e| e.kind == EventKind::OomKill).count() as u64;
        for mut e in raw {
            if let Some(cg) = e.extra.get("memcg").cloned()
                && e.unit.is_none()
            {
                e.unit = self.unit_for_cgroup(&cg);
            }
            if e.kind == EventKind::RoRemount
                && let Some(dev) = e.subject.strip_prefix("disk:").map(str::to_string)
            {
                // Name the mount when we know it.
                let what = match self.dev_mounts.get(&dev) {
                    Some(mp) => {
                        e.subject = format!("mount:{mp}");
                        mp.clone()
                    }
                    None => dev,
                };
                if !self.ro_remounts.contains(&what) {
                    self.ro_remounts.push(what);
                }
            }
            self.pending.push(e);
        }
        // Without a readable kernel log, the vmstat counter still says *that* OOM kills
        // happened (victim unknown).
        let log_on = matches!(self.log, KernelLog::Kmsg { .. } | KernelLog::Journal { .. });
        if let (Some(p), Some(cur)) = (prev_vm.and_then(|p| p.oom_kill), vm.oom_kill) {
            let d = cur.saturating_sub(p);
            if d > 0 && !log_on && kmsg_ooms == 0 {
                let mut e = event(
                    now,
                    EventKind::OomKill,
                    Severity::Crit,
                    "host",
                    format!("{d} process(es) OOM-killed (victim unknown: kernel log needs root)"),
                    "procfs",
                );
                e.value = Some(d as f64);
                self.pending.push(e);
            }
        }
    }
}

/// Filesystems whose read-only state is not news.
const VIRTUAL_FS: &[&str] = &[
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "mqueue",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "configfs",
    "fusectl",
    "hugetlbfs",
    "autofs",
    "binfmt_misc",
    "rpc_pipefs",
    "nsfs",
    "efivarfs",
    "devtmpfs",
    "squashfs",
    "iso9660",
    "ramfs",
    "tmpfs",
    "overlay",
    "erofs",
    "nfsd",
];

fn event(ts: Ts, kind: EventKind, severity: Severity, subject: &str, detail: String, source: &str) -> Event {
    Event { ts, kind, severity, subject: subject.into(), detail, source: source.into(), ..Default::default() }
}

/// Merge identical (kind, subject, severity, detail-less-numbers) events of one sample into one
/// with a `repeats` count, keeping the first.
fn collapse(v: &mut Vec<Event>) {
    if v.len() < 2 {
        return;
    }
    let mut idx: HashMap<(EventKind, String, Severity, String), usize> = HashMap::new();
    let mut out: Vec<Event> = Vec::with_capacity(v.len());
    for e in v.drain(..) {
        if e.kind == EventKind::OomKill {
            out.push(e);
            continue;
        }
        let shape: String = e.detail.chars().filter(|c| !c.is_ascii_digit()).collect();
        let key = (e.kind, e.subject.clone(), e.severity, shape);
        match idx.get(&key) {
            Some(&i) => {
                let n: u64 = out[i].extra.get("repeats").and_then(|s| s.parse().ok()).unwrap_or(1);
                out[i].extra.insert("repeats".into(), (n + 1).to_string());
            }
            None => {
                idx.insert(key, out.len());
                out.push(e);
            }
        }
    }
    *v = out;
}

// ---------------------------------------------------------------------------------------------
// Kernel log
// ---------------------------------------------------------------------------------------------

fn open_kernel_log(now: Ts) -> KernelLog {
    if !cfg!(target_os = "linux") {
        return KernelLog::Off("kernel log: Linux only".into());
    }
    match open_kmsg() {
        Ok(mut f) => {
            use std::io::Seek;
            // Only new records; the backlog is imported separately via read_kmsg_since.
            let _ = f.seek(std::io::SeekFrom::End(0));
            KernelLog::Kmsg { file: f, last_seq: None, asm: OomAssembler::default() }
        }
        Err(_) if which("journalctl") => {
            KernelLog::Journal { cursor: None, since_s: now / 1000, last_run: None, asm: OomAssembler::default() }
        }
        Err(e) => KernelLog::Off(kmsg_error(&e)),
    }
}

/// Why /dev/kmsg could not be opened, in operator terms.
fn kmsg_error(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => {
            "kernel log unavailable: no /dev/kmsg here (typical in containers) and no readable journal".into()
        }
        _ => format!("{NEEDS_ROOT} ({e})"),
    }
}

const NEEDS_ROOT: &str = "kernel log unreadable: needs root, kernel.dmesg_restrict=0 or read access to the system journal (OOM victims, hung tasks and I/O errors come from it)";

fn which(prog: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(prog).is_file()))
}

fn open_kmsg() -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open("/dev/kmsg")
}

/// Read every available record (non-blocking). Each read() returns exactly one record.
fn read_kmsg_records(f: &mut fs::File, mut on: impl FnMut(&str)) {
    use std::io::Read;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => on(&String::from_utf8_lossy(&buf[..n])),
            // EPIPE: records were overwritten under us; the next read continues.
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Epoch ms of boot as the kernel log sees it (CLOCK_MONOTONIC, which kmsg timestamps follow).
fn boot_ms() -> Ts {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    // time_t / c_long are 32-bit on some targets.
    #[allow(clippy::unnecessary_cast)]
    let mono = t.tv_sec as i64 * 1000 + t.tv_nsec as i64 / 1_000_000;
    now_ms() - mono
}

/// (seq, ts_us) of a kmsg record.
fn kmsg_seq(rec: &str) -> Option<(u64, u64)> {
    let head = rec.split(';').next()?;
    let mut it = head.split(',');
    let _pri = it.next()?;
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// Joins the multi-line OOM report ("invoked oom-killer" .. "oom-kill:" .. "Killed process")
/// into one enriched event. Bounded: keeps only the three lines it needs.
#[derive(Default)]
struct OomAssembler {
    lines: Vec<String>,
    /// Victims already reported for the current report (memory.oom.group repeats the line).
    victims: Vec<u32>,
}

impl OomAssembler {
    fn feed(&mut self, rec: &str, boot_ms: Ts) -> Option<Event> {
        let (_, msg) = rec.split_once(';')?;
        let msg = msg.lines().next().unwrap_or("");
        let ts = kmsg_seq(rec).map_or(now_ms(), |(_, us)| boot_ms + (us / 1000) as i64);
        if kmsg_facility(rec) != Some(0) {
            return None;
        }
        self.track(msg);
        let e = parse_kmsg_record(rec, boot_ms)?;
        self.enrich(e, ts)
    }

    /// Journal records carry their own realtime timestamp.
    fn feed_at(&mut self, rec: &str, ts: Ts) -> Option<Event> {
        let (_, msg) = rec.split_once(';')?;
        self.track(msg);
        let level = rec.split(',').next()?.parse::<u8>().ok()? & 7;
        let e = classify(level, msg, ts)?;
        self.enrich(e, ts)
    }

    fn track(&mut self, msg: &str) {
        if msg.contains("invoked oom-killer") {
            self.lines.clear();
            self.victims.clear();
            self.lines.push(msg.to_string());
        } else if (msg.starts_with("oom-kill:") || is_legacy_oom_line(msg)) && self.lines.len() < 4 {
            self.lines.push(msg.to_string());
        }
    }

    fn enrich(&mut self, mut e: Event, ts: Ts) -> Option<Event> {
        e.ts = ts;
        if e.kind == EventKind::OomKill && e.source == "kmsg" {
            if let Some(pid) = e.pid {
                if self.victims.contains(&pid) {
                    return None;
                }
                self.victims.push(pid);
            }
            let killed = e.extra.remove("kmsg_line").unwrap_or_default();
            // The report's own oom-kill: line names the first victim; with memory.oom.group
            // further victims share its constraint, memcg and invoker but keep pid and rss.
            let mut info = parse_oom(&[killed.as_str()]).unwrap_or_default();
            let mut ctx = OomInfo::default();
            for l in &self.lines {
                fold_oom_line(&mut ctx, l);
            }
            // The killed line's own prefix ("Memory cgroup out of memory: ...") is the fallback
            // when the report carried no oom-kill: line (kernels before 4.19).
            if !ctx.constraint.is_empty() {
                info.constraint = ctx.constraint;
            }
            info.memcg = ctx.memcg;
            info.task_memcg = ctx.task_memcg;
            info.invoker = ctx.invoker;
            if info.victim_pid != 0 {
                apply_oom(&mut e, &info);
            }
        }
        Some(e)
    }
}

fn kmsg_facility(rec: &str) -> Option<u32> {
    rec.split(',').next()?.trim().parse::<u32>().ok().map(|p| p >> 3)
}

fn apply_oom(e: &mut Event, o: &OomInfo) {
    e.pid = Some(o.victim_pid);
    e.subject = format!("pid:{}", o.victim_pid);
    let rss = (o.anon_rss_kb + o.file_rss_kb + o.shmem_rss_kb) * 1024;
    e.value = Some(rss as f64);
    let scope = match o.constraint.as_str() {
        "CONSTRAINT_MEMCG" => {
            format!("cgroup {} hit its memory limit", if o.memcg.is_empty() { "?" } else { &o.memcg })
        }
        "CONSTRAINT_NONE" | "" => "host out of memory".to_string(),
        c => format!("{} ({c})", if o.memcg.is_empty() { "constrained OOM" } else { &o.memcg }),
    };
    e.detail = format!(
        "OOM killer killed {} (pid {}, rss {} MiB): {scope}{}",
        o.victim_name,
        o.victim_pid,
        rss / (1024 * 1024),
        o.invoker.as_deref().map(|i| format!("; triggered by {i}")).unwrap_or_default()
    );
    e.extra.insert("victim".into(), o.victim_name.clone());
    e.extra.insert("victim_pid".into(), o.victim_pid.to_string());
    if !o.constraint.is_empty() {
        e.extra.insert("constraint".into(), o.constraint.clone());
    }
    if !o.task_memcg.is_empty() {
        e.extra.insert("task_memcg".into(), o.task_memcg.clone());
    }
    if !o.memcg.is_empty() {
        e.extra.insert("memcg".into(), o.memcg.clone());
        if e.unit.is_none() {
            e.unit = super::unit_of_cgroup(&o.memcg).map(|u| u.key);
        }
    }
    e.extra.insert("anon_rss_kb".into(), o.anon_rss_kb.to_string());
    e.extra.insert("rss_kb".into(), (o.anon_rss_kb + o.file_rss_kb + o.shmem_rss_kb).to_string());
    if let Some(i) = &o.invoker {
        e.extra.insert("invoker".into(), i.clone());
    }
}

/// Kernel log events with ts >= `since` (None = whole ring buffer), for `what-happened` without
/// a recorder and for importing the backlog when the daemon starts. Err when /dev/kmsg is
/// unreadable (message says "needs root or kernel.dmesg_restrict=0"). Falls back to
/// `journalctl -k` when the journal is readable.
pub fn read_kmsg_since(since: Option<Ts>) -> anyhow::Result<Vec<Event>> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!("kernel log: Linux only");
    }
    let mut out = Vec::new();
    match open_kmsg() {
        Ok(mut f) => {
            let boot = boot_ms();
            let mut asm = OomAssembler::default();
            read_kmsg_records(&mut f, |rec| out.extend(asm.feed(rec, boot)));
        }
        Err(e) => {
            let since_s = since.unwrap_or(0) / 1000;
            let journal = if which("journalctl") { journal_records(None, since_s).ok() } else { None };
            let Some((recs, _)) = journal else {
                anyhow::bail!("{}", kmsg_error(&e));
            };
            let mut asm = OomAssembler::default();
            for (ts, rec) in recs {
                out.extend(asm.feed_at(&rec, ts));
            }
        }
    }
    if let Some(s) = since {
        out.retain(|e| e.ts >= s);
    }
    collapse(&mut out);
    out.sort_by_key(|e| e.ts);
    Ok(out)
}

/// `journalctl -k -o json` since a cursor (or epoch seconds) -> ("level,0,0,-;message" records
/// with realtime ms, new cursor). Err with a reason when the journal is not readable.
/// Journal records ("level,0,0,-;message" with realtime ms) and the cursor after the last one.
type JournalBatch = (Vec<(Ts, String)>, Option<String>);

fn journal_records(cursor: Option<&str>, since_s: i64) -> Result<JournalBatch, String> {
    let mut cmd = std::process::Command::new("journalctl");
    cmd.env("LC_ALL", "C").args(["-k", "-o", "json", "--no-pager", "-q"]);
    match cursor {
        Some(c) => cmd.arg(format!("--after-cursor={c}")),
        None => cmd.arg(format!("--since=@{since_s}")),
    };
    let out = run_with_timeout(cmd, std::time::Duration::from_secs(5))
        .map_err(|e| format!("kernel log via journalctl failed: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("insufficient permissions") || stderr.contains("No journal files were") {
        return Err(NEEDS_ROOT.into());
    }
    let mut recs = Vec::new();
    let mut last = None;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        if let Some(c) = s("__CURSOR") {
            last = Some(c);
        }
        let Some(msg) = s("MESSAGE") else { continue };
        let ts = s("__REALTIME_TIMESTAMP").and_then(|t| t.parse::<i64>().ok()).map_or(now_ms(), |us| us / 1000);
        let pri = s("PRIORITY").and_then(|p| p.parse::<u8>().ok()).unwrap_or(6);
        recs.push((ts, format!("{pri},0,0,-;{msg}")));
    }
    Ok((recs, last))
}

/// Run a command we spawn, killing it (our own child) if it outlives `limit`.
fn run_with_timeout(
    mut cmd: std::process::Command,
    limit: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    use std::process::Stdio;
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let (mut so, mut se) = (child.stdout.take(), child.stderr.take());
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = so.as_mut() {
            let _ = std::io::Read::read_to_end(s, &mut b);
        }
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = se.as_mut() {
            let _ = std::io::Read::read_to_end(s, &mut b);
        }
        b
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out"));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    Ok(std::process::Output {
        status,
        stdout: t_out.join().unwrap_or_default(),
        stderr: t_err.join().unwrap_or_default(),
    })
}

/// One /dev/kmsg record ("6,1234,5678901,-;message") -> event, if it is one we classify.
/// `boot_ms` = epoch ms of boot (the record's timestamp is µs since boot).
/// Records from userspace facilities (written to /dev/kmsg by init) are ignored.
pub fn parse_kmsg_record(record: &str, boot_ms: Ts) -> Option<Event> {
    let (head, msg) = record.split_once(';')?;
    let pri: u32 = head.split(',').next()?.trim().parse().ok()?;
    if pri >> 3 != 0 {
        return None;
    }
    let (_, us) = kmsg_seq(record)?;
    let msg = msg.lines().next().unwrap_or("").trim_end();
    classify((pri & 7) as u8, msg, boot_ms + (us / 1000) as i64)
}

fn kv_after<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let i = s.find(key)? + key.len();
    let rest = &s[i..];
    let end = rest.find([',', ' ', ')', ']', ':']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// "name[1234]:" or "[name:1234]" style pid extraction.
fn bracket_name_pid(s: &str) -> Option<(String, u32)> {
    let open = s.find('[')?;
    let close = open + s[open..].find(']')?;
    let name = s[..open].rsplit(' ').next().unwrap_or("").to_string();
    let pid = s[open + 1..close].parse().ok()?;
    Some((name, pid))
}

/// Device named in "(device sda1)" / "XFS (sdb1)" / "dev sda," / "[sdb]".
fn device_in(msg: &str) -> Option<String> {
    let pick = |s: &str| {
        s.trim_matches(|c: char| c == ',' || c == ')' || c == '(' || c == ':' || c == '[' || c == ']').to_string()
    };
    if let Some(d) = kv_after(msg, "(device ") {
        return Some(pick(d));
    }
    // "Buffer I/O error on device sdb1" (older kernels) before "on dev sdb1".
    if let Some(d) = kv_after(msg, "on device ") {
        return Some(pick(d));
    }
    if let Some(d) = kv_after(msg, "dev ") {
        return Some(pick(d));
    }
    // SCSI disk: "sd 2:0:0:0: [sdb] tag#0 FAILED Result: ..." names the block device in the
    // first bracket (the H:C:T:L address is not a device).
    if msg.starts_with("sd ")
        && let Some(open) = msg.find('[')
        && let Some(len) = msg[open + 1..].find(']')
    {
        let d = &msg[open + 1..open + 1 + len];
        if !d.is_empty() && d.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Some(d.to_string());
        }
    }
    for fs in ["EXT4-fs (", "XFS (", "EXT3-fs (", "BTRFS: device "] {
        if let Some(d) = kv_after(msg, fs) {
            return Some(pick(d));
        }
    }
    if let (Some(a), Some(b)) =
        (msg.find("] ["), msg.find("] [").and_then(|i| msg[i + 3..].find(']').map(|j| i + 3 + j)))
    {
        return Some(msg[a + 3..b].to_string());
    }
    None
}

/// Classify one kernel log message (level 0..7). Only known shapes become events; other
/// messages at level crit or worse become a generic kernel_warn.
fn classify(level: u8, msg: &str, ts: Ts) -> Option<Event> {
    let ev = |kind, sev, subject: &str, detail: String| {
        let mut e = event(ts, kind, sev, subject, detail, "kmsg");
        e.extra.insert("level".into(), level.to_string());
        e
    };
    let short: String = msg.chars().take(240).collect();

    // OOM: the final "Killed process" line (enriched by OomAssembler with the earlier lines).
    if msg.contains("Killed process ") && !msg.starts_with("oom_reaper") {
        let o = parse_oom(&[msg])?;
        let mut e = ev(EventKind::OomKill, Severity::Crit, &format!("pid:{}", o.victim_pid), String::new());
        apply_oom(&mut e, &o);
        e.extra.insert("kmsg_line".into(), msg.to_string());
        return Some(e);
    }
    if msg.contains("Out of memory and no killable processes") {
        return Some(ev(EventKind::OomKill, Severity::Crit, "host", short));
    }
    // Hung task: "INFO: task kworker/1:2:123 blocked for more than 120 seconds."
    if let Some(rest) = msg.split_once("INFO: task ").map(|(_, r)| r)
        && let Some((who, tail)) = rest.split_once(" blocked for more than ")
    {
        let (name, pid) =
            who.rsplit_once(':').map_or((who.to_string(), None), |(n, p)| (n.to_string(), p.parse::<u32>().ok()));
        let secs: f64 = tail.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let mut e = ev(
            EventKind::HungTask,
            Severity::Warn,
            &pid.map_or("kernel".into(), |p| format!("pid:{p}")),
            format!(
                "{name} (pid {}) blocked in D state for more than {secs:.0}s (kernel hung task detector)",
                pid.map_or("?".into(), |p| p.to_string())
            ),
        );
        e.pid = pid;
        e.value = Some(secs);
        return Some(e);
    }
    // Lockups and oopses.
    if msg.contains("soft lockup") || msg.contains("hard LOCKUP") {
        let mut e = ev(EventKind::KernelWarn, Severity::Crit, "kernel", short);
        if let Some((name, pid)) = msg.rfind('[').and_then(|i| {
            msg[i + 1..].trim_end_matches(']').rsplit_once(':').map(|(n, p)| (n.to_string(), p.parse::<u32>().ok()))
        }) {
            e.pid = pid;
            e.extra.insert("task".into(), name);
        }
        return Some(e);
    }
    if msg.contains("rcu_sched self-detected stall")
        || msg.contains("rcu_preempt self-detected stall")
        || msg.contains("detected stalls on CPUs")
    {
        return Some(ev(EventKind::KernelWarn, Severity::Warn, "kernel", short));
    }
    if msg.starts_with("BUG: ")
        || msg.starts_with("kernel BUG at")
        || msg.starts_with("Oops:")
        || msg.contains("Kernel panic")
        || msg.starts_with("general protection fault:")
    {
        return Some(ev(EventKind::KernelWarn, Severity::Crit, "kernel", short));
    }
    if msg.starts_with("WARNING: CPU:") || msg.starts_with("WARNING: at ") {
        return Some(ev(EventKind::KernelWarn, Severity::Warn, "kernel", short));
    }
    if msg.contains("page allocation failure:") {
        let mut e = ev(EventKind::KernelWarn, Severity::Warn, "kernel", short);
        e.extra.insert("task".into(), msg.split(':').next().unwrap_or("").trim().to_string());
        return Some(e);
    }
    if msg.contains("[Hardware Error]") || msg.starts_with("EDAC ") && msg.contains("error") {
        let sev = if msg.contains(" UE ") || msg.contains("Uncorrected") { Severity::Crit } else { Severity::Warn };
        return Some(ev(EventKind::KernelWarn, sev, "kernel", short));
    }
    if msg.contains("Marking clocksource") && msg.contains("unstable") {
        return Some(ev(EventKind::KernelWarn, Severity::Warn, "kernel", short));
    }
    // Process crashes: "nginx[1234]: segfault at 0 ip ..." / "traps: x[12] general protection ..."
    if msg.contains(": segfault at ")
        || msg.starts_with("traps: ")
        || msg.contains(" trap invalid opcode ")
        || msg.contains(" trap divide error ")
    {
        let body = msg.strip_prefix("traps: ").unwrap_or(msg);
        let mut e = ev(EventKind::KernelWarn, Severity::Warn, "kernel", short.clone());
        if let Some((name, pid)) = bracket_name_pid(body) {
            e.subject = format!("pid:{pid}");
            e.pid = Some(pid);
            e.detail = format!("{name} (pid {pid}) crashed: {short}");
            e.extra.insert("task".into(), name);
        }
        e.extra.insert("crash".into(), "1".into());
        return Some(e);
    }
    // Filesystems.
    if msg.contains("Remounting filesystem read-only")
        || msg.contains("forced readonly")
        || msg.contains("switching to read-only")
    {
        let dev = device_in(msg).unwrap_or_default();
        let mut e = ev(
            EventKind::RoRemount,
            Severity::Crit,
            &if dev.is_empty() { "kernel".into() } else { format!("disk:{dev}") },
            short,
        );
        e.extra.insert("device".into(), dev);
        return Some(e);
    }
    if msg.starts_with("EXT4-fs error")
        || msg.starts_with("EXT3-fs error")
        || msg.starts_with("BTRFS error")
        || msg.starts_with("BTRFS critical")
        || msg.starts_with("XFS (")
            && (msg.contains("error")
                || msg.contains("Corruption")
                || msg.contains("shut down")
                || msg.contains("force_shutdown"))
    {
        let dev = device_in(msg).unwrap_or_default();
        return Some(ev(EventKind::DiskError, Severity::Crit, &format!("disk:{dev}"), short));
    }
    if msg.starts_with("EXT4-fs warning") || msg.starts_with("BTRFS warning") {
        let dev = device_in(msg).unwrap_or_default();
        return Some(ev(EventKind::DiskError, Severity::Warn, &format!("disk:{dev}"), short));
    }
    // Block layer / drivers.
    if msg.contains("I/O error") || msg.contains("critical medium error") || msg.contains("critical target error") {
        let dev = device_in(msg).unwrap_or_default();
        let subj = if dev.is_empty() { "kernel".to_string() } else { format!("disk:{dev}") };
        return Some(ev(EventKind::DiskError, Severity::Crit, &subj, short));
    }
    if (msg.starts_with("nvme ")
        && (msg.contains("timeout") || msg.contains("controller is down") || msg.contains("resetting controller")))
        || (msg.starts_with("ata")
            && (msg.contains("failed command")
                || msg.contains("hard resetting link")
                || msg.contains("exception Emask")))
        || (msg.starts_with("sd ") && msg.contains("FAILED Result"))
    {
        let dev = msg.split_whitespace().nth(1).map(|s| s.trim_end_matches(':').to_string());
        let dev = device_in(msg).filter(|d| !d.contains(':')).or(dev).unwrap_or_default();
        let dev =
            if msg.starts_with("ata") { msg.split([':', ' ', '.']).next().unwrap_or("").to_string() } else { dev };
        return Some(ev(EventKind::DiskError, Severity::Warn, &format!("disk:{dev}"), short));
    }
    // Resource exhaustion reported by the kernel itself.
    let exh = |res: &str, sev| {
        let mut e = ev(EventKind::Exhaustion, sev, "kernel", short.clone());
        e.extra.insert("resource".into(), res.into());
        e
    };
    if msg.contains("nf_conntrack: table full") {
        return Some(exh("conntrack", Severity::Crit));
    }
    if msg.contains("file-max limit") && msg.contains("reached") {
        return Some(exh("fd", Severity::Crit));
    }
    if msg.contains("Possible SYN flooding on port") {
        let mut e = exh("syn_backlog", Severity::Warn);
        if let Some(p) = kv_after(msg, "on port ") {
            e.extra.insert("port".into(), p.trim_end_matches('.').to_string());
        }
        return Some(e);
    }
    if msg.contains("neighbor table overflow") || msg.contains("neighbour table overflow") {
        return Some(exh("neighbour", Severity::Warn));
    }
    if msg.contains("TCP: out of memory") || msg.contains("too many orphaned sockets") {
        return Some(exh("tcp_mem", Severity::Warn));
    }
    if let Some(cg) = msg.split_once("fork rejected by pids controller in ").map(|(_, c)| c.trim()) {
        let mut e = exh("pids", Severity::Warn);
        e.unit = super::unit_of_cgroup(cg).map(|u| u.key);
        e.extra.insert("memcg".into(), cg.to_string());
        if let Some(u) = &e.unit {
            e.subject = format!("unit:{u}");
        }
        return Some(e);
    }
    // NIC link state: "e1000e: eth0 NIC Link is Down", "mlx5_core ...: Link down".
    if msg.contains("NIC Link is Down")
        || msg.contains("Link is Down")
        || msg.ends_with(": Link down")
        || msg.contains("NIC Link is Up")
        || msg.contains("Link is Up")
    {
        let up = msg.contains("Up");
        let iface = msg
            .split_whitespace()
            .map(|w| w.trim_end_matches(':'))
            .take_while(|w| !w.eq_ignore_ascii_case("NIC") && !w.eq_ignore_ascii_case("link"))
            .last()
            .unwrap_or("")
            .to_string();
        let mut e = ev(
            EventKind::Other,
            if up { Severity::Info } else { Severity::Warn },
            "host",
            format!("network link {} {}", if iface.is_empty() { "?" } else { &iface }, if up { "up" } else { "down" }),
        );
        e.extra.insert("iface".into(), iface);
        e.extra.insert("raw".into(), short);
        return Some(e);
    }
    if level <= 2 {
        return Some(ev(EventKind::KernelWarn, Severity::Crit, "kernel", short));
    }
    None
}

/// OOM report lines of kernels before 4.19 that carry the constraint and memcg.
fn is_legacy_oom_line(msg: &str) -> bool {
    msg.starts_with("Task in ") || msg.contains("Memory cgroup out of memory") || msg.starts_with("Out of memory")
}

/// Fold the lines of one OOM report (from "invoked oom-killer" to "Killed process") into OomInfo.
pub fn parse_oom(lines: &[&str]) -> Option<OomInfo> {
    let mut o = OomInfo::default();
    let mut have = false;
    for l in lines {
        have |= fold_oom_line(&mut o, l);
    }
    have.then_some(o)
}

/// Fold one OOM report line into `o`; true when it named the victim. The "Killed process" line
/// wins over the oom-kill: line for the victim (it carries rss and oom_score_adj).
fn fold_oom_line(o: &mut OomInfo, l: &str) -> bool {
    if let Some((who, _)) = l.split_once(" invoked oom-killer") {
        o.invoker = Some(who.trim().to_string()).filter(|s| !s.is_empty());
        return false;
    }
    // Kernels before 4.19 (no oom-kill: line): "Task in /A killed as a result of limit of /B"
    // (printed only for a memory-cgroup OOM) and the "Memory cgroup out of memory:" /
    // "Out of memory:" prefix of the kill line say which limit was hit.
    if let Some(rest) = l.trim().strip_prefix("Task in ") {
        if let Some((task, limit)) = rest.split_once(" killed as a result of limit of ") {
            o.task_memcg = task.trim().to_string();
            if o.memcg.is_empty() {
                o.memcg = limit.trim().to_string();
            }
            if o.constraint.is_empty() {
                o.constraint = "CONSTRAINT_MEMCG".into();
            }
        }
        return false;
    }
    if o.constraint.is_empty() {
        if l.contains("Memory cgroup out of memory") {
            o.constraint = "CONSTRAINT_MEMCG".into();
        } else if l.contains("Out of memory:") || l.contains("Out of memory (oom_kill_allocating_task)") {
            o.constraint = "CONSTRAINT_NONE".into();
        }
    }
    if let Some(rest) = l.trim().strip_prefix("oom-kill:") {
        let (mut memcg, mut task_memcg, mut have) = (String::new(), String::new(), false);
        for kv in rest.split(',') {
            let Some((k, v)) = kv.split_once('=') else { continue };
            let v = v.trim();
            match k.trim() {
                "constraint" => o.constraint = v.to_string(),
                "oom_memcg" => memcg = v.to_string(),
                "task_memcg" => task_memcg = v.to_string(),
                "task" if o.victim_name.is_empty() => o.victim_name = v.to_string(),
                "pid" if o.victim_pid == 0 => {
                    if let Ok(p) = v.parse() {
                        o.victim_pid = p;
                        have = true;
                    }
                }
                _ => {}
            }
        }
        if !task_memcg.is_empty() {
            o.task_memcg = task_memcg.clone();
        }
        o.memcg = if memcg.is_empty() { task_memcg } else { memcg };
        return have;
    }
    let Some(i) = l.find("Killed process ") else { return false };
    let rest = &l[i + "Killed process ".len()..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    let Ok(pid) = rest[..end].parse::<u32>() else { return false };
    o.victim_pid = pid;
    let after = &rest[end..];
    if let Some(open) = after.find('(') {
        let tail = &after[open + 1..];
        let close = tail.find(") total-vm").or_else(|| tail.rfind(')')).unwrap_or(tail.len());
        o.victim_name = tail[..close].to_string();
    }
    let kb = |key: &str| kv_after(l, key).and_then(|v| v.trim_end_matches("kB").parse::<u64>().ok());
    o.anon_rss_kb = kb("anon-rss:").unwrap_or(0);
    o.file_rss_kb = kb("file-rss:").unwrap_or(0);
    o.shmem_rss_kb = kb("shmem-rss:").unwrap_or(0);
    if let Some(adj) =
        l.split("oom_score_adj:").nth(1).and_then(|s| s.split_whitespace().next()).and_then(|s| s.parse().ok())
    {
        o.oom_score_adj = adj;
    }
    true
}

// ---------------------------------------------------------------------------------------------
// procfs parsers (pure; tested on every platform)
// ---------------------------------------------------------------------------------------------

struct StatInfo {
    /// user nice system idle iowait irq softirq steal (guest is already inside user).
    cpu: [u64; 8],
    procs_running: u32,
    procs_blocked: u32,
}

fn parse_stat(s: &str) -> StatInfo {
    let mut st = StatInfo { cpu: [0; 8], procs_running: 0, procs_blocked: 0 };
    for l in s.lines() {
        let mut it = l.split_whitespace();
        match it.next() {
            Some("cpu") => {
                for (i, v) in it.take(8).enumerate() {
                    st.cpu[i] = v.parse().unwrap_or(0);
                }
            }
            Some("procs_running") => st.procs_running = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            Some("procs_blocked") => st.procs_blocked = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }
    st
}

fn meminfo_kb(s: &str, key: &str) -> Option<u64> {
    s.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(':')?.split_whitespace().next()?.parse().ok())
}

fn parse_vmstat(s: &str) -> VmCounters {
    let mut v = VmCounters::default();
    for l in s.lines() {
        let Some((k, n)) = l.split_once(' ') else { continue };
        let n: u64 = n.trim().parse().unwrap_or(0);
        match k {
            "pswpin" => v.pswpin = n,
            "pswpout" => v.pswpout = n,
            "oom_kill" => v.oom_kill = Some(n),
            _ => {}
        }
    }
    v
}

/// "allocated unused max" -> (in use, max).
fn parse_file_nr(s: &str) -> Option<(u64, u64)> {
    let v: Vec<u64> = s.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    (v.len() >= 3).then(|| (v[0].saturating_sub(v[1]), v[2]))
}

fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    let mut it = s.split_whitespace().filter_map(|x| x.parse::<u16>().ok());
    let (a, b) = (it.next()?, it.next()?);
    (a <= b).then_some((a, b))
}

/// /proc/net/snmp or netstat: header/value line pairs -> "Tcp.RetransSegs" -> n.
fn parse_snmp(s: &str) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    let lines: Vec<&str> = s.lines().collect();
    for pair in lines.chunks(2) {
        let [h, v] = pair else { continue };
        let (Some((hp, hk)), Some((vp, vv))) = (h.split_once(':'), v.split_once(':')) else { continue };
        if hp != vp {
            continue;
        }
        for (k, n) in hk.split_whitespace().zip(vv.split_whitespace()) {
            if let Ok(n) = n.parse::<i64>() {
                out.insert(format!("{hp}.{k}"), n.max(0) as u64);
            }
        }
    }
    out
}

/// TCP sockets in /proc/net/tcp{,6} texts -> (ports used, busiest remote endpoint): the larger
/// of distinct local ports inside `range` and the connections to the single busiest remote
/// endpoint from that range (each needs its own local port).
fn ephemeral_usage(texts: &[&str], range: (u16, u16)) -> (u64, String) {
    let mut ports = vec![false; 65536];
    let mut distinct = 0u64;
    // A connect() needs a local port unique per (local ip, remote ip, remote port).
    let mut per_dest: HashMap<(&str, &str), u64> = HashMap::new();
    for t in texts {
        for l in t.lines().skip(1) {
            let mut it = l.split_whitespace();
            let (Some(_), Some(local), Some(remote), Some(state)) = (it.next(), it.next(), it.next(), it.next()) else {
                continue;
            };
            let Some(port) = local.rsplit_once(':').and_then(|(_, p)| u16::from_str_radix(p, 16).ok()) else {
                continue;
            };
            if port < range.0 || port > range.1 || state == "0A" {
                continue;
            }
            if !ports[port as usize] {
                ports[port as usize] = true;
                distinct += 1;
            }
            if !remote.ends_with(":0000") {
                let lip = local.rsplit_once(':').map_or(local, |(ip, _)| ip);
                *per_dest.entry((lip, remote)).or_default() += 1;
            }
        }
    }
    let ((_, dest), n) = per_dest.into_iter().max_by_key(|(_, n)| *n).unwrap_or((("", ""), 0));
    if n > distinct {
        (n, decode_endpoint(dest))
    } else {
        (distinct, if n > 0 { decode_endpoint(dest) } else { String::new() })
    }
}

/// "0100007F:1F90" -> "127.0.0.1:8080" (IPv4); IPv6 is shown as hex words.
fn decode_endpoint(s: &str) -> String {
    let Some((ip, port)) = s.split_once(':') else { return s.into() };
    let port = u16::from_str_radix(port, 16).unwrap_or(0);
    if ip.len() == 8
        && let Ok(v) = u32::from_str_radix(ip, 16)
    {
        let b = v.to_le_bytes();
        return format!("{}.{}.{}.{}:{port}", b[0], b[1], b[2], b[3]);
    }
    if ip.len() == 32 {
        let mut bytes = [0u8; 16];
        for w in 0..4 {
            let Ok(v) = u32::from_str_radix(&ip[w * 8..w * 8 + 8], 16) else { return s.into() };
            bytes[w * 4..w * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        let a = std::net::Ipv6Addr::from(bytes);
        return match a.to_ipv4_mapped() {
            Some(v4) => format!("{v4}:{port}"),
            None => format!("[{a}]:{port}"),
        };
    }
    s.into()
}

/// /proc/<pid>/stat -> (state, starttime).
fn stat_state_start(s: &str) -> Option<(char, u64)> {
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some((f.first()?.chars().next()?, f.get(19)?.parse().ok()?))
}

struct MountRow {
    id: u64,
    mount_point: String,
    fstype: String,
    source: String,
    read_only: bool,
}

fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// /proc/self/mountinfo. Read-only when the mount *or* its superblock is ro (errors=remount-ro
/// flips only the superblock).
fn parse_mountinfo(s: &str) -> Vec<MountRow> {
    s.lines()
        .filter_map(|l| {
            let (pre, post) = l.split_once(" - ")?;
            let f: Vec<&str> = pre.split_whitespace().collect();
            let g: Vec<&str> = post.split_whitespace().collect();
            let ro = |opts: &str| opts.split(',').any(|o| o == "ro");
            Some(MountRow {
                id: f.first()?.parse().ok()?,
                mount_point: unescape_mount(f.get(4)?),
                read_only: ro(f.get(5)?) || g.get(2).is_some_and(|o| ro(o)),
                fstype: g.first()?.to_string(),
                source: unescape_mount(g.get(1).copied().unwrap_or("")),
            })
        })
        .collect()
}

/// Raw cumulative counters of one /proc/diskstats line.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiskCounters {
    pub name: String,
    pub reads: u64,
    pub read_sectors: u64,
    pub read_ms: u64,
    pub writes: u64,
    pub write_sectors: u64,
    pub write_ms: u64,
    pub in_flight: u64,
    pub io_ms: u64,
    pub weighted_ms: u64,
}

/// Partition by name shape (callers with /sys use `/sys/class/block/<n>/partition` too):
/// sda1, vdb2, xvda1, hdc3, nvme0n1p1, mmcblk0p2, md0p1, nbd0p1.
fn is_partition_name(n: &str) -> bool {
    let digits = n.len() - n.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 {
        return false;
    }
    let stem = &n[..n.len() - digits];
    if let Some(base) = stem.strip_suffix('p') {
        // nvme0n1p1, mmcblk0p1, md0p1, loop0p1: "p" follows a digit.
        return base.ends_with(|c: char| c.is_ascii_digit());
    }
    for pre in ["sd", "vd", "xvd", "hd"] {
        if let Some(letters) = stem.strip_prefix(pre) {
            return !letters.is_empty() && letters.bytes().all(|b| b.is_ascii_lowercase());
        }
    }
    false
}

/// Parse /proc/diskstats; skips partitions and ram/loop devices with no I/O.
pub fn parse_diskstats(text: &str) -> Vec<DiskCounters> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 14 {
                return None;
            }
            let n = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            let d = DiskCounters {
                name: f[2].to_string(),
                reads: n(3),
                read_sectors: n(5),
                read_ms: n(6),
                writes: n(7),
                write_sectors: n(9),
                write_ms: n(10),
                in_flight: n(11),
                io_ms: n(12),
                weighted_ms: n(13),
            };
            if is_partition_name(&d.name) {
                return None;
            }
            let idle_virtual = ["loop", "ram", "zram", "nbd", "sr", "fd"].iter().any(|p| d.name.starts_with(p))
                && d.reads + d.writes == 0;
            (!idle_virtual).then_some(d)
        })
        .collect()
}

/// Decode /proc/sys/kernel/tainted into its flag letters ("P", "O", "E", ...).
pub fn decode_taint(mask: u64) -> String {
    const LETTERS: &[u8] = b"PFSRMBUDAWCIOELKXTN";
    let mut s = String::new();
    for (i, c) in LETTERS.iter().enumerate() {
        if mask & (1 << i) != 0 {
            s.push(*c as char);
        }
    }
    if mask >> LETTERS.len() != 0 {
        s.push('?');
    }
    s
}

/// Parse /proc/mdstat.
pub fn parse_mdstat(text: &str) -> Vec<MdArray> {
    let mut out: Vec<MdArray> = Vec::new();
    for l in text.lines() {
        let t = l.trim();
        if let Some((name, rest)) = t.split_once(" : ") {
            if !name.starts_with("md") {
                continue;
            }
            let words: Vec<&str> = rest.split_whitespace().collect();
            let active = words.first() == Some(&"active");
            let level = words
                .iter()
                .skip(1)
                .find(|w| !w.starts_with('('))
                .filter(|w| w.starts_with("raid") || **w == "linear" || **w == "multipath")
                .map_or(String::new(), |w| w.to_string());
            let failed = words.iter().any(|w| w.ends_with("(F)"));
            out.push(MdArray {
                name: name.trim().into(),
                level,
                state: if active { "active".into() } else { words.first().unwrap_or(&"").to_string() },
                degraded: failed,
                sync_pct: None,
            });
            continue;
        }
        let Some(a) = out.last_mut() else { continue };
        // "[2/1] [U_]"
        if let Some(i) = t.rfind('[') {
            let tail = &t[i + 1..];
            if tail.ends_with(']')
                && tail.trim_end_matches(']').bytes().all(|b| b == b'U' || b == b'_')
                && tail.len() > 1
            {
                if tail.contains('_') {
                    a.degraded = true;
                }
                if let Some(j) = t[..i].rfind('[')
                    && let Some((want, have)) = t[j + 1..].split(']').next().and_then(|s| s.split_once('/'))
                    && let (Ok(w), Ok(h)) = (want.parse::<u32>(), have.parse::<u32>())
                    && h < w
                {
                    a.degraded = true;
                }
            }
        }
        for (op, st) in
            [("recovery", "recovering"), ("resync", "resyncing"), ("reshape", "reshaping"), ("check", "checking")]
        {
            if let Some(rest) = t.split_once(&format!("{op} =")).map(|(_, r)| r) {
                a.sync_pct = rest.trim().split('%').next().and_then(|p| p.trim().parse().ok());
                a.state = st.into();
            }
        }
        if a.degraded && a.state == "active" {
            a.state = "degraded".into();
        }
    }
    out
}

/// adjtimex(2) with modes=0 (read-only, no privilege needed). None off Linux.
#[allow(clippy::unnecessary_cast)]
fn clock_synced() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: zeroed timex with modes = 0 only reads the kernel clock state.
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::adjtimex(&mut tx) };
        if r < 0 {
            return None;
        }
        // Same rule as systemd's ntp_synced(): the kernel's maximum error estimate below 16 s
        // (NTP_PHASE_LIMIT). STA_UNSYNC alone is not used: time daemons and hypervisor clock
        // agents may leave it set just to keep the kernel from writing the RTC.
        Some((tx.maxerror as i64) < 16_000_000)
    }
    #[cfg(not(target_os = "linux"))]
    None
}

// ---------------------------------------------------------------------------------------------
// CLI / MCP report
// ---------------------------------------------------------------------------------------------

/// What `fat kernel` and the MCP `kernel` tool return.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct KernelReport {
    pub ts: Ts,
    /// None off Linux.
    pub kernel: Option<Kernel>,
    /// Processes currently in D state (any duration), for "load high but CPU idle".
    pub d_state_now: Vec<DStateProc>,
    /// Kernel log events since `since`, newest last (empty + a note when unreadable).
    pub events: Vec<Event>,
    pub notes: Vec<String>,
}

/// Two kernel samples `interval` apart (rates need an interval) plus kernel log events since
/// `since`. `procs`/`units` come from the caller's snapshot.
pub fn report(
    cfg: &ServerCfg,
    procs: &[Proc],
    units: &[Unit],
    interval: std::time::Duration,
    since: Ts,
    max_events: usize,
) -> KernelReport {
    let mut r = KernelReport { ts: now_ms(), ..Default::default() };
    if !cfg!(target_os = "linux") {
        r.notes.push("kernel health is Linux only".into());
        return r;
    }
    let mut c = cfg.clone();
    c.kmsg = false;
    let mut ks = KernelSampler::new(&c);
    let _ = ks.sample(procs, units);
    std::thread::sleep(interval);
    r.kernel = ks.sample(procs, units);
    for p in procs.iter().filter(|p| p.status == "U") {
        let Some((state, _)) =
            fs::read_to_string(format!("/proc/{}/stat", p.pid)).ok().as_deref().and_then(stat_state_start)
        else {
            continue;
        };
        if state == 'D' {
            let wchan =
                fs::read_to_string(format!("/proc/{}/wchan", p.pid)).map(|s| s.trim().to_string()).unwrap_or_default();
            r.d_state_now.push(DStateProc {
                pid: p.pid,
                name: p.name.clone(),
                wchan: if wchan == "0" { String::new() } else { wchan },
                seconds: 0,
                unit: ks.unit_for_cgroup(&p.cgroup),
            });
        }
    }
    let mut ev = ks.drain_events();
    if cfg.kmsg {
        match read_kmsg_since(Some(since)) {
            Ok(v) => ev.extend(v),
            Err(e) => r.notes.push(format!("{e:#}")),
        }
    }
    ev.sort_by_key(|e| e.ts);
    if ev.len() > max_events {
        ev.drain(..ev.len() - max_events);
    }
    r.events = ev;
    r
}

/// `fat kernel [--since D] [--json]`.
pub fn run_cli(cfg: &crate::config::Config, since: &str, json: bool, watch: bool) -> anyhow::Result<()> {
    if watch {
        return watch_events(cfg, json);
    }
    let secs = crate::budget::parse_duration(since)?;
    let procs = if cfg!(target_os = "linux") { crate::collect::Collector::new().sample().procs } else { Vec::new() };
    let r = report(&cfg.server, &procs, &[], std::time::Duration::from_secs(1), now_ms() - secs as i64 * 1000, 50);
    if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        print!("{}", render(&r));
    }
    Ok(())
}

/// `fat kernel --watch`: print kernel events as they happen (one line, or one JSON object per
/// line with --json) until interrupted. Samples at the configured interval.
fn watch_events(cfg: &crate::config::Config, json: bool) -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!("kernel events are Linux only");
    }
    let mut collector = crate::collect::Collector::new();
    let mut ks = KernelSampler::new(&cfg.server);
    let every = std::time::Duration::from_millis(cfg.interval_ms.max(250));
    let mut noted = false;
    loop {
        let procs = collector.sample().procs;
        let k = ks.sample(&procs, &[]);
        if !noted {
            noted = true;
            for n in k.iter().flat_map(|k| &k.notes) {
                eprintln!("note: {n}");
            }
            eprintln!("watching kernel events (Ctrl-C to stop)");
        }
        for e in ks.drain_events() {
            if json {
                println!("{}", serde_json::to_string(&e)?);
            } else {
                println!("{}", event_line(&e));
            }
        }
        std::thread::sleep(every);
    }
}

fn event_line(e: &Event) -> String {
    let t = chrono::DateTime::from_timestamp_millis(e.ts)
        .map(|d| d.with_timezone(&chrono::Local).format("%m-%d %H:%M:%S").to_string())
        .unwrap_or_default();
    let rep = e.extra.get("repeats").map(|n| format!(" (x{n})")).unwrap_or_default();
    let unit = e.unit.as_deref().map(|u| format!(" [{u}]")).unwrap_or_default();
    format!("{t}  {:<4} {:<18} {}{unit}{rep}", e.severity.as_str(), e.kind.as_str(), e.detail)
}

/// Human rendering of a report.
pub fn render(r: &KernelReport) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let Some(k) = &r.kernel else {
        for n in &r.notes {
            let _ = writeln!(s, "{n}");
        }
        return s;
    };
    let _ = writeln!(
        s,
        "CPU      steal {:.1}%  iowait {:.1}%  irq {:.1}%  softirq {:.1}%   running {}  blocked (D) {}",
        k.steal_pct, k.iowait_pct, k.irq_pct, k.softirq_pct, k.procs_running, k.procs_blocked
    );
    if let Some(p) = k.pressure {
        let _ = writeln!(
            s,
            "PSI      cpu {:.1}/{:.1}  mem {:.1}/{:.1}  io {:.1}/{:.1}   (some/full avg10 %)",
            p.cpu_some, p.cpu_full, p.mem_some, p.mem_full, p.io_some, p.io_full
        );
    }
    let _ = writeln!(
        s,
        "Memory   available {}  swap in/out {:.0}/{:.0} pages/s  OOM kills since boot {}",
        human(k.mem_available),
        k.swap_in_ps,
        k.swap_out_ps,
        k.oom_kills_total
    );
    for n in &k.numa {
        let _ = writeln!(s, "  node{}  {} free of {}", n.node, human(n.mem_free), human(n.mem_total));
    }
    let lim = |u: Option<u64>, m: Option<u64>| match (u, m) {
        (Some(u), Some(m)) if m > 0 && m < u64::MAX / 2 => format!("{u}/{m} ({:.0}%)", u as f64 * 100.0 / m as f64),
        (Some(u), _) => format!("{u}"),
        _ => "n/a".into(),
    };
    let eph_max = k.ephemeral_range.map(|(a, b)| (b as u64).saturating_sub(a as u64) + 1);
    let _ = writeln!(
        s,
        "Limits   fds {}  conntrack {}  ephemeral ports {}",
        lim(k.fd_used, k.fd_max),
        lim(k.conntrack_used, k.conntrack_max),
        lim(k.ephemeral_used, eph_max)
    );
    let _ = writeln!(
        s,
        "TCP      retrans {:.1}/s  listen overflows {:.1}/s  drops {:.1}/s",
        k.tcp_retrans_ps, k.listen_overflows_ps, k.listen_drops_ps
    );
    if !k.disks.is_empty() {
        let _ = writeln!(
            s,
            "Disks    {:<10} {:>6} {:>8} {:>8} {:>6} {:>8} {:>8} {:>10} {:>10}",
            "device", "util%", "r_await", "w_await", "queue", "r_iops", "w_iops", "read/s", "write/s"
        );
        for d in &k.disks {
            let _ = writeln!(
                s,
                "         {:<10} {:>6.1} {:>8.1} {:>8.1} {:>6.2} {:>8.0} {:>8.0} {:>10} {:>10}{}",
                d.name,
                d.util_pct,
                d.r_await_ms,
                d.w_await_ms,
                d.queue_depth,
                d.r_iops,
                d.w_iops,
                human(d.r_bps),
                human(d.w_bps),
                d.io_errors.filter(|e| *e > 0).map(|e| format!("  io errors {e}")).unwrap_or_default()
            );
        }
    }
    if !r.d_state_now.is_empty() {
        let _ = writeln!(s, "D state  {} process(es) now:", r.d_state_now.len());
        for d in r.d_state_now.iter().take(15) {
            let _ =
                writeln!(s, "         {:>7} {:<20} {:<24} {}", d.pid, d.name, d.wchan, d.unit.as_deref().unwrap_or(""));
        }
    }
    for m in &k.mdraid {
        let _ = writeln!(
            s,
            "RAID     {} {} {}{}",
            m.name,
            m.level,
            m.state,
            m.sync_pct.map(|p| format!(" {p:.1}%")).unwrap_or_default()
        );
    }
    for f in &k.fs_errors {
        let _ = writeln!(
            s,
            "FS       {} {} errors {}{}",
            f.device,
            f.mount.as_deref().unwrap_or(""),
            f.errors,
            if f.read_only { " (read-only)" } else { "" }
        );
    }
    for m in &k.ro_remounts {
        let _ = writeln!(s, "RO       {m} went read-only");
    }
    let _ = writeln!(
        s,
        "Kernel   tainted {}  clock {}",
        if k.taint == 0 { "no".to_string() } else { format!("{} ({})", k.taint_flags, k.taint) },
        match k.ntp_synced {
            Some(true) => "synchronised",
            Some(false) => "NOT synchronised",
            None => "unknown",
        }
    );
    if !r.events.is_empty() {
        let _ = writeln!(s, "\nKernel events ({}):", r.events.len());
        for e in &r.events {
            let _ = writeln!(s, "  {}", event_line(e));
        }
    }
    for n in k.notes.iter().chain(&r.notes) {
        let _ = writeln!(s, "note: {n}");
    }
    s
}

fn human(b: u64) -> String {
    let f = b as f64;
    match b {
        0..1024 => format!("{b} B"),
        1024..1_048_576 => format!("{:.1} KiB", f / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.1} MiB", f / 1_048_576.0),
        _ => format!("{:.1} GiB", f / 1_073_741_824.0),
    }
}

#[cfg(test)]
mod tests;
