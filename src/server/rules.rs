//! Server doctor rules (findings over units, kernel and recent events). OWNER: doctor-incident.
//! Hooked into crate::blame::diagnose by the same agent with one guarded call:
//! `if !snap.units.is_empty() || snap.kernel.is_some() { out.extend(server::rules::diagnose_server(snap, hist)) }`
//! so desktop behaviour is unchanged. Findings use the existing model::Finding; `action` stays
//! None for unit-level problems (fat never restarts services): the next steps are read-only
//! commands written into the detail for a human or agent to run.
//!
//! Thresholds come from [`ServerCfg`] where an operator may reasonably disagree (exhaustion,
//! disk await, flapping); the rest are named constants below with the reason for each.
use super::incident::{exhaustion_list, human_bytes, human_dur, unit_next_steps};
use super::{Event, EventKind, Kernel, ServerCfg, Severity, Unit, UnitKind};
use crate::history::History;
use crate::model::{Finding, Snapshot, System, Ts};
use std::collections::{BTreeMap, HashSet};

/// cpu.max throttling share of an interval (%) worth a finding: below this, throttling is the
/// quota doing its job on short bursts.
const THROTTLE_WARN_PCT: f32 = 25.0;
/// Unit PSI memory "full" avg10 (%) worth a finding: every task in the cgroup stalled at once
/// this share of the time.
const UNIT_MEM_FULL_WARN: f32 = 10.0;
/// Load per core with idle CPU that means work is stuck, not busy.
const LOAD_PER_CORE: f64 = 1.5;
/// Busy CPU share below which high load is "CPU idle".
const IDLE_CPU_PCT: f32 = 50.0;
/// iowait / steal shares (% of all CPU time) worth a finding.
const IOWAIT_WARN: f32 = 20.0;
const STEAL_WARN: f32 = 10.0;
/// Swap pages/s in+out that is thrashing rather than background swap-out (~4 MB/s at 4 KiB).
const SWAP_THRASH_PPS: f32 = 1000.0;
/// Failed units listed individually before they are grouped into one finding.
const MAX_UNIT_FINDINGS: usize = 5;
/// Events older than this do not produce findings.
const EVENT_HORIZON_MS: i64 = 24 * 3_600_000;
/// Events read from the recorder for findings (newest kept).
const MAX_RULE_EVENTS: usize = 5_000;

fn cfg() -> ServerCfg {
    static CFG: std::sync::OnceLock<ServerCfg> = std::sync::OnceLock::new();
    CFG.get_or_init(|| crate::config::Config::load().server).clone()
}

fn finding(sev: Severity, title: String, detail: String, pids: Vec<u32>) -> Finding {
    Finding { severity: sev.as_str().into(), title, detail, pids, action: None }
}

fn sev_rank(s: &str) -> Severity {
    Severity::parse(s)
}

/// Fill `snap` with units, kernel health and events for the doctor when the server profile is
/// active (no-op otherwise, or when already filled). One sampler per process: the first call
/// takes a short baseline so rates are real; later calls measure since the previous call.
pub fn fill_for_doctor(cfg: &ServerCfg, snap: &mut Snapshot) {
    if super::Profile::detect(cfg) != super::Profile::Server || !snap.units.is_empty() || snap.kernel.is_some() {
        return;
    }
    static SAMPLER: std::sync::Mutex<Option<super::ServerSampler>> = std::sync::Mutex::new(None);
    let mut g = SAMPLER.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_none() {
        let mut sm = super::ServerSampler::new(cfg);
        let mut warm = snap.clone();
        sm.fill(&mut warm);
        std::thread::sleep(std::time::Duration::from_millis(500));
        *g = Some(sm);
    }
    if let Some(sm) = g.as_mut()
        && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sm.fill(snap))).is_err()
    {
        *g = None;
    }
}

/// All server findings for one snapshot: unit rules + kernel rules + diagnose_events
/// (recent events from `hist` when present, else snap.events), de-duplicated, worst first.
pub fn diagnose_server(snap: &Snapshot, hist: Option<&History>) -> Vec<Finding> {
    let now = if snap.ts > 0 { snap.ts } else { crate::model::now_ms() };
    let recorded = hist.and_then(|h| h.events(now - EVENT_HORIZON_MS, now, &[], MAX_RULE_EVENTS).ok());
    diagnose_server_with(snap, recorded.as_deref(), &cfg())
}

/// [`diagnose_server`] with explicit recorded events and config (tests, fleet).
pub fn diagnose_server_with(snap: &Snapshot, recorded: Option<&[Event]>, cfg: &ServerCfg) -> Vec<Finding> {
    let now = if snap.ts > 0 { snap.ts } else { crate::model::now_ms() };
    let mut out = units_with(&snap.units, cfg);
    if let Some(k) = &snap.kernel {
        let mut kf = kernel_with(k, &snap.system, cfg);
        // The desktop PSI rule already reports system memory/io stalls from System.psi.
        if snap.system.psi.is_some() {
            kf.retain(|f| !f.title.starts_with("Memory stalls"));
        }
        out.extend(kf);
    }
    let mut events: Vec<Event> = recorded.map(<[Event]>::to_vec).unwrap_or_default();
    for e in &snap.events {
        if !events.iter().any(|x| x.ts / 1000 == e.ts / 1000 && x.kind == e.kind && x.subject == e.subject) {
            events.push(e.clone());
        }
    }
    let mut ef = diagnose_events(&events, now);
    // Unit findings already cover a unit that is failed/flapping right now.
    let covered: HashSet<String> =
        snap.units.iter().filter(|u| u.is_failed() || u.flapping).map(|u| u.name.clone()).collect();
    ef.retain(|f| !covered.iter().any(|n| f.title.starts_with(&format!("{n} ")) && f.title.contains("restart")));
    out.extend(ef);
    let mut seen = HashSet::new();
    out.retain(|f| seen.insert(f.title.clone()));
    out.sort_by_key(|f| std::cmp::Reverse(sev_rank(&f.severity)));
    out
}

fn steps(u: &Unit) -> String {
    let v = unit_next_steps(&u.name, u.kind, u.container.as_ref(), u.since.map(|t| t - 60_000));
    format!(" Next: {}.", v.iter().map(|s| format!("`{s}`")).collect::<Vec<_>>().join(", "))
}

fn kind_word(u: &Unit) -> &'static str {
    match u.kind {
        UnitKind::Systemd => "unit",
        UnitKind::Container => "container",
        UnitKind::Pod => "pod",
        UnitKind::Cgroup => "cgroup",
    }
}

fn since_text(u: &Unit, now: Ts) -> String {
    u.since.map(|t| format!(" for {}", human_dur(now - t))).unwrap_or_default()
}

fn units_with(units: &[Unit], cfg: &ServerCfg) -> Vec<Finding> {
    let now = crate::model::now_ms();
    let mut out = Vec::new();
    // Failed.
    let failed: Vec<&Unit> = units.iter().filter(|u| u.is_failed()).collect();
    for u in failed.iter().take(MAX_UNIT_FINDINGS) {
        let mut why = Vec::new();
        if !u.result.is_empty() && u.result != "success" {
            why.push(u.result.clone());
        }
        if let Some(c) = u.exit_code.filter(|c| *c != 0) {
            why.push(format!("status {c}"));
        }
        let reason = if why.is_empty() { String::new() } else { format!(" ({})", why.join(", ")) };
        let mut detail = format!("{} {} is failed{}{reason}", kind_word(u), u.name, since_text(u, now));
        if u.restarts > 0 {
            detail.push_str(&format!(" after {} restarts", u.restarts));
        }
        detail.push('.');
        detail.push_str(&match u.result.as_str() {
            "oom-kill" => {
                " It was killed for exceeding its memory limit: check MemoryMax/--memory against its real need."
                    .to_string()
            }
            "core-dump" | "signal" => " It crashed; `coredumpctl list` shows core dumps.".to_string(),
            "start-limit-hit" => " systemd gave up after too many restarts in a row.".to_string(),
            "timeout" => " It did not start or stop within its timeout.".to_string(),
            _ => String::new(),
        });
        if !u.description.is_empty() {
            detail.push_str(&format!(" ({})", u.description));
        }
        detail.push_str(&steps(u));
        if u.kind == UnitKind::Systemd {
            if crate::blame::is_protected_server_name(u.name.trim_end_matches(".service")) {
                detail.push_str(" It is a database/system service: find out why before restarting it.");
            } else {
                detail.push_str(&format!(
                    " After fixing the cause: `systemctl reset-failed {0} && systemctl restart {0}`.",
                    u.name
                ));
            }
        }
        let sev = if u.kind == UnitKind::Cgroup { Severity::Warn } else { Severity::Crit };
        out.push(finding(sev, format!("{} failed{reason}", u.name), detail, u.main_pid.into_iter().collect()));
    }
    if failed.len() > MAX_UNIT_FINDINGS {
        let rest: Vec<&str> = failed[MAX_UNIT_FINDINGS..].iter().map(|u| u.name.as_str()).collect();
        out.push(finding(
            Severity::Crit,
            format!("{} more failed units", rest.len()),
            format!(
                "Also failed: {}. `systemctl --failed` lists systemd ones.",
                rest.iter().take(20).copied().collect::<Vec<_>>().join(", ")
            ),
            vec![],
        ));
    }
    for u in units.iter().filter(|u| !u.is_failed()) {
        // Restart loops.
        if u.flapping || u.recent_restarts >= cfg.flap_restarts {
            let mut detail = format!(
                "{} {} restarted {} times in the last {} ({} in total){}.",
                kind_word(u),
                u.name,
                u.recent_restarts,
                human_dur(cfg.flap_window_s as i64 * 1000),
                u.restarts,
                if u.result.is_empty() || u.result == "success" {
                    String::new()
                } else {
                    format!("; last result {}", u.result)
                }
            );
            if let Some(c) = u.exit_code.filter(|c| *c != 0) {
                detail.push_str(&format!(" Last exit status {c}."));
            }
            detail.push_str(
                " A restart loop hides the real error: the first lines of each start in its log say why it dies.",
            );
            detail.push_str(&steps(u));
            out.push(finding(
                Severity::Warn,
                format!("{} is in a restart loop", u.name),
                detail,
                u.main_pid.into_iter().collect(),
            ));
        }
        // Memory limit.
        if let Some(l) = u.mem_limit.filter(|l| *l > 0) {
            let r = u.mem as f64 / l as f64;
            if r >= cfg.exhaustion_warn as f64 {
                out.push(finding(
                    if r >= 0.98 { Severity::Crit } else { Severity::Warn },
                    format!("{} at {:.0}% of its memory limit", u.name, r * 100.0),
                    format!(
                        "{} uses {} of its {} limit (memory.max). Past the limit the kernel reclaims hard and then OOM-kills inside it{}.{}",
                        u.name,
                        human_bytes(u.mem),
                        human_bytes(l),
                        if u.oom_kills > 0 { format!("; it has been OOM-killed {} times since it started", u.oom_kills) } else { String::new() },
                        steps(u)
                    ),
                    u.main_pid.into_iter().collect(),
                ));
            }
        }
        if u.oom_kills > 0 && u.mem_limit.is_none_or(|l| (u.mem as f64 / l.max(1) as f64) < cfg.exhaustion_warn as f64)
        {
            out.push(finding(
                Severity::Info,
                format!("{} has had {} OOM kill{}", u.name, u.oom_kills, if u.oom_kills == 1 { "" } else { "s" }),
                format!(
                    "The kernel killed a process inside {} {} time{} for exceeding memory (memory.events oom_kill, cumulative). `fat what-happened` explains the last one.{}",
                    u.name,
                    u.oom_kills,
                    if u.oom_kills == 1 { "" } else { "s" },
                    steps(u)
                ),
                u.main_pid.into_iter().collect(),
            ));
        }
        // CPU throttling.
        if u.cpu_throttled_pct >= THROTTLE_WARN_PCT {
            let quota = u.cpu_quota.map(|q| format!("{q:.1} cores")).unwrap_or_else(|| "its cpu.max".into());
            let at_quota = u.cpu_quota.is_some_and(|q| u.cpu >= q * 80.0);
            out.push(finding(
                Severity::Warn,
                format!("{} throttled {:.0}% of the time", u.name, u.cpu_throttled_pct),
                format!(
                    "{} hit its CPU quota ({quota}) in {:.0}% of scheduler periods while using {:.0}% CPU: requests to it slow down. {}{}",
                    u.name,
                    u.cpu_throttled_pct,
                    u.cpu,
                    if at_quota {
                        "It needs more CPU than the quota allows: raise CPUQuota= / --cpus / limits.cpu, or reduce its work."
                    } else {
                        "It is under quota on average but bursts past it: many threads in short bursts (GC, thread pools) trip a tight cpu.max."
                    },
                    steps(u)
                ),
                u.main_pid.into_iter().collect(),
            ));
        }
        // Unit memory stalls.
        if let Some(p) = u.psi.filter(|p| p.mem_full >= UNIT_MEM_FULL_WARN) {
            out.push(finding(
                Severity::Warn,
                format!("{} stalls on memory {:.0}% of the time", u.name, p.mem_full),
                format!(
                    "Every task in {} was stalled on memory reclaim {:.0}% of the last 10 s (PSI full){}: it is too close to its limit or the host is short.{}",
                    u.name,
                    p.mem_full,
                    u.mem_limit.map(|l| format!("; {} of {} limit", human_bytes(u.mem), human_bytes(l))).unwrap_or_default(),
                    steps(u)
                ),
                u.main_pid.into_iter().collect(),
            ));
        }
        if let Some(h) = u.container.as_ref().and_then(|c| c.health.as_deref()).filter(|h| *h == "unhealthy") {
            out.push(finding(
                Severity::Warn,
                format!("{} is {h}", u.name),
                format!("The runtime's health check for container {} fails.{}", u.name, steps(u)),
                u.main_pid.into_iter().collect(),
            ));
        }
    }
    out
}

/// Load high but CPU idle (D state, iowait, steal), disk latency, fd/conntrack/port exhaustion,
/// ro remounts, fs errors, degraded md arrays, clock unsynced, swap thrash, kernel taint changes.
fn kernel_with(k: &Kernel, sys: &System, cfg: &ServerCfg) -> Vec<Finding> {
    let mut out = Vec::new();
    let slow: Vec<_> = k.disks.iter().filter(|d| d.r_await_ms.max(d.w_await_ms) >= cfg.disk_await_warn_ms).collect();
    // Load high but CPU idle.
    let cores = sys.cores.max(1) as f64;
    if sys.load[0] / cores >= LOAD_PER_CORE && sys.cpu < IDLE_CPU_PCT {
        let mut why = Vec::new();
        let blocked = k.procs_blocked.max(k.d_state.len() as u32);
        if blocked > 0 {
            why.push(format!("{blocked} processes blocked in uninterruptible I/O (D state)"));
        }
        if k.iowait_pct >= 5.0 {
            why.push(format!("iowait {:.0}%", k.iowait_pct));
        }
        if k.steal_pct >= 5.0 {
            why.push(format!("hypervisor steal {:.0}%", k.steal_pct));
        }
        if let Some(d) = slow.first() {
            why.push(format!("{} await {:.0} ms", d.name, d.r_await_ms.max(d.w_await_ms)));
        }
        let ds: Vec<String> = k
            .d_state
            .iter()
            .take(6)
            .map(|d| {
                format!(
                    "{} (pid {}{}{})",
                    d.name,
                    d.pid,
                    if d.wchan.is_empty() { String::new() } else { format!(", in {}", d.wchan) },
                    d.unit.as_ref().map(|u| format!(", {u}")).unwrap_or_default()
                )
            })
            .collect();
        let mut detail = format!(
            "Load {:.1} on {} cores while CPU is only {:.0}% busy: the load is tasks waiting, not computing{}.",
            sys.load[0],
            sys.cores,
            sys.cpu,
            if why.is_empty() { String::new() } else { format!(" ({})", why.join(", ")) }
        );
        if !ds.is_empty() {
            detail.push_str(&format!(" Waiting: {}.", ds.join(", ")));
        }
        detail.push_str(" Usual causes: a slow or failing disk, a hung network/NFS/FUSE mount, or a starved VM. `fat what-happened` shows when it started and who did the I/O.");
        out.push(finding(
            if sys.load[0] / cores >= 4.0 { Severity::Crit } else { Severity::Warn },
            format!("Load {:.1} with idle CPU", sys.load[0]),
            detail,
            k.d_state.iter().map(|d| d.pid).collect(),
        ));
    }
    if k.steal_pct >= STEAL_WARN {
        out.push(finding(
            Severity::Warn,
            format!("CPU steal {:.0}%", k.steal_pct),
            format!(
                "The hypervisor withheld {:.0}% of CPU time from this VM (a busy neighbour on the host, an exhausted burst credit, or an oversubscribed host). Nothing inside the VM can fix it: move or resize the VM, or ask the platform.",
                k.steal_pct
            ),
            vec![],
        ));
    }
    if k.iowait_pct >= IOWAIT_WARN && slow.is_empty() {
        out.push(finding(
            Severity::Warn,
            format!("iowait {:.0}%", k.iowait_pct),
            format!("CPUs spent {:.0}% of the time idle waiting for I/O. `iostat -x 1 5` shows which device; `pidstat -d 1 5` which process.", k.iowait_pct),
            vec![],
        ));
    }
    for d in slow.iter().take(MAX_UNIT_FINDINGS) {
        let aw = d.r_await_ms.max(d.w_await_ms);
        out.push(finding(
            if aw >= cfg.disk_await_warn_ms * 5.0 { Severity::Crit } else { Severity::Warn },
            format!("{} I/O latency {:.0} ms", d.name, aw),
            format!(
                "{} requests take {:.0} ms to read / {:.0} ms to write (queue {:.1}, util {:.0}%, {:.0} r/s {:.0} w/s); above {:.0} ms everything touching it stalls. `fat what-happened` names the unit whose I/O rose; `iostat -x 1 5 {}` watches it live.",
                d.name, d.r_await_ms, d.w_await_ms, d.queue_depth, d.util_pct, d.r_iops, d.w_iops, cfg.disk_await_warn_ms, d.name
            ),
            vec![],
        ));
    }
    // Exhaustion.
    for (what, used, max) in exhaustion_list(k) {
        let r = used as f64 / max.max(1) as f64;
        if r < cfg.exhaustion_warn as f64 {
            continue;
        }
        let (effect, cmd) = match what {
            "file descriptors" => (
                "opening files and sockets fails with \"Too many open files\"",
                "cat /proc/sys/fs/file-nr; then count /proc/<pid>/fd for the top services",
            ),
            "conntrack entries" => (
                "new connections are dropped (\"nf_conntrack: table full\")",
                "conntrack -S; sysctl net.netfilter.nf_conntrack_max",
            ),
            _ => (
                "outgoing connections fail with \"Cannot assign requested address\"",
                "ss -s; ss -tan state time-wait | wc -l",
            ),
        };
        out.push(finding(
            if r >= 0.95 { Severity::Crit } else { Severity::Warn },
            format!("{what} {:.0}% used", r * 100.0),
            format!("{used} of {max} {what} in use. At the limit {effect}. Find the holder: `{cmd}`."),
            vec![],
        ));
    }
    if k.listen_overflows_ps >= 1.0 || k.listen_drops_ps >= 1.0 {
        out.push(finding(
            Severity::Warn,
            format!("Accept queues overflowing ({:.0}/s dropped)", k.listen_drops_ps.max(k.listen_overflows_ps)),
            "A listening service is not accepting connections as fast as they arrive (busy or blocked workers, or a backlog too small): clients see timeouts. `ss -ltn` shows Recv-Q vs backlog per port.".into(),
            vec![],
        ));
    }
    // Memory stalls (when System.psi is absent) and swap thrash.
    if let Some(p) = k.pressure.filter(|p| p.mem_full >= 5.0) {
        out.push(finding(
            if p.mem_full >= 20.0 { Severity::Crit } else { Severity::Warn },
            "Memory stalls: the system is thrashing".into(),
            format!("PSI memory {:.0}% some / {:.0}% full: every task was stalled on memory reclaim {:.0}% of the time. {} available.", p.mem_some, p.mem_full, p.mem_full, human_bytes(k.mem_available)),
            vec![],
        ));
    }
    if k.swap_in_ps + k.swap_out_ps >= SWAP_THRASH_PPS {
        out.push(finding(
            Severity::Warn,
            format!("Swap thrashing ({:.0} pages/s)", k.swap_in_ps + k.swap_out_ps),
            format!(
                "The kernel is swapping {:.0} pages/s in and {:.0} out: the working set does not fit in RAM ({} available). The biggest memory users are in `fat services` / `fat doctor`.",
                k.swap_in_ps,
                k.swap_out_ps,
                human_bytes(k.mem_available)
            ),
            vec![],
        ));
    }
    // Storage integrity.
    for m in &k.ro_remounts {
        out.push(finding(
            Severity::Crit,
            format!("{m} is read-only"),
            format!("{m} was remounted read-only, usually after a filesystem or disk error: every write to it fails. `journalctl -k | grep -iE 'remount|error'` shows why; back up, then fsck it unmounted."),
            vec![],
        ));
    }
    for f in k.fs_errors.iter().filter(|f| f.errors > 0) {
        out.push(finding(
            Severity::Crit,
            format!("Filesystem errors on {}", f.mount.clone().unwrap_or_else(|| f.device.clone())),
            format!(
                "{} has recorded {} filesystem error{}{}. Check `journalctl -k` for the first one and plan an fsck.",
                f.device,
                f.errors,
                if f.errors == 1 { "" } else { "s" },
                if f.read_only { " and is read-only" } else { "" }
            ),
            vec![],
        ));
    }
    for d in k.disks.iter().filter(|d| d.io_errors.is_some_and(|e| e > 0)) {
        out.push(finding(
            Severity::Crit,
            format!("I/O errors on {}", d.name),
            format!(
                "{} reports {} I/O errors. `smartctl -a /dev/{}` (root) shows the drive's health.",
                d.name,
                d.io_errors.unwrap_or(0),
                d.name
            ),
            vec![],
        ));
    }
    for md in &k.mdraid {
        if md.degraded {
            out.push(finding(
                Severity::Crit,
                format!("RAID {} degraded", md.name),
                format!(
                    "{} ({}) is {}: one more disk failure loses data. `cat /proc/mdstat`; `mdadm --detail /dev/{}`.",
                    md.name, md.level, md.state, md.name
                ),
                vec![],
            ));
        } else if let Some(p) = md.sync_pct {
            out.push(finding(
                Severity::Info,
                format!("RAID {} {} {:.0}%", md.name, md.state, p),
                format!("{} is {} ({p:.0}% done); I/O is slower until it finishes.", md.name, md.state),
                vec![],
            ));
        }
    }
    if k.ntp_synced == Some(false) {
        out.push(finding(
            Severity::Warn,
            "Clock not synchronised".into(),
            "The kernel says the system clock is unsynchronised: TLS, logs, cron and distributed systems misbehave as it drifts. `timedatectl status` (or `chronyc tracking`).".into(),
            vec![],
        ));
    }
    if k.taint != 0 {
        out.push(finding(
            Severity::Info,
            format!("Kernel tainted ({})", if k.taint_flags.is_empty() { k.taint.to_string() } else { k.taint_flags.clone() }),
            format!(
                "/proc/sys/kernel/tainted = {} ({}): out-of-tree/proprietary modules, or an earlier warning or oops. A W or D flag means the kernel already hit a problem: check `journalctl -k`.",
                k.taint, k.taint_flags
            ),
            vec![],
        ));
    }
    out
}

/// Findings from recent events (OOM kills in the last 24h, restart storms, hung tasks).
pub fn diagnose_events(events: &[Event], now: Ts) -> Vec<Finding> {
    let recent: Vec<&Event> =
        events.iter().filter(|e| e.ts <= now + 60_000 && now - e.ts <= EVENT_HORIZON_MS).collect();
    let mut out = Vec::new();
    let ago = |t: Ts| format!("{} ago", human_dur(now - t));
    // OOM kills, grouped.
    let ooms: Vec<&&Event> = recent.iter().filter(|e| e.kind == EventKind::OomKill).collect();
    if let Some(last) = ooms.iter().max_by_key(|e| e.ts) {
        let mut victims: BTreeMap<String, usize> = BTreeMap::new();
        for e in &ooms {
            let v = e.extra.get("victim").cloned().or_else(|| e.unit.clone()).unwrap_or_else(|| e.subject.clone());
            *victims.entry(v).or_default() += 1;
        }
        let list = victims
            .iter()
            .map(|(v, n)| if *n > 1 { format!("{v} x{n}") } else { v.clone() })
            .collect::<Vec<_>>()
            .join(", ");
        out.push(finding(
            if now - last.ts <= 3_600_000 { Severity::Crit } else { Severity::Warn },
            format!("{} OOM kill{} in 24h", ooms.len(), if ooms.len() == 1 { "" } else { "s" }),
            format!("The kernel OOM killer ended: {list}. Last: {} ({}). `fat what-happened --at {}` shows who held the memory then.", last.detail, ago(last.ts), last.ts / 1000),
            ooms.iter().filter_map(|e| e.pid).collect(),
        ));
    }
    // Restarts per unit.
    let mut restarts: BTreeMap<String, (usize, Ts)> = BTreeMap::new();
    for e in recent.iter().filter(|e| e.kind == EventKind::UnitRestart) {
        let n = e.unit.clone().unwrap_or_else(|| e.subject.clone());
        let r = restarts.entry(n).or_insert((0, 0));
        // One event may stand for several restarts (coalesced while a unit flaps).
        r.0 += e.value.map_or(1, |v| (v as usize).max(1));
        r.1 = r.1.max(e.ts);
    }
    for (n, (c, last)) in restarts.iter().filter(|(_, (c, _))| *c >= 3) {
        out.push(finding(
            Severity::Warn,
            format!("{n} restarted {c} times in 24h"),
            format!("{n} restarted {c} times in the last 24 h (last {}). Each restart drops in-flight work; its log says why it exits.", ago(*last)),
            vec![],
        ));
    }
    // Kernel trouble.
    let groups: [(EventKind, Severity, &str, &str); 5] = [
        (
            EventKind::HungTask,
            Severity::Warn,
            "hung task",
            "tasks stuck in the kernel in D state (usually storage or a stuck mount)",
        ),
        (EventKind::DiskError, Severity::Crit, "disk/filesystem error", "the kernel logged I/O or filesystem errors"),
        (EventKind::RoRemount, Severity::Crit, "read-only remount", "a filesystem went read-only after errors"),
        (
            EventKind::KernelWarn,
            Severity::Info,
            "kernel warning",
            "WARN/BUG/soft lockup/segfault lines in the kernel log",
        ),
        (EventKind::ClockUnsynced, Severity::Warn, "clock unsync", "the system clock lost synchronisation"),
    ];
    for (kind, sev, word, what) in groups {
        let ev: Vec<&&Event> = recent.iter().filter(|e| e.kind == kind).collect();
        let Some(last) = ev.iter().max_by_key(|e| e.ts) else { continue };
        // The kernel sampler grades each line (a TRIM/discard warning is not a media error);
        // the finding is as severe as the worst event, never more than this kind's ceiling,
        // except kernel warnings, whose worst lines (oops, lockups) are crit on their own.
        let worst = ev.iter().map(|e| e.severity).max().unwrap_or(sev);
        let sev = if kind == EventKind::KernelWarn { worst } else { worst.min(sev) };
        let subjects: HashSet<&str> = ev.iter().map(|e| e.subject.as_str()).collect();
        let mut subj: Vec<&str> = subjects.into_iter().collect();
        subj.sort();
        out.push(finding(
            sev,
            format!("{} {word}{} in 24h", ev.len(), if ev.len() == 1 { "" } else { "s" }),
            format!(
                "{what}: {} ({}). Last: {}. `fat events --kind {}` lists them.",
                subj.join(", "),
                ago(last.ts),
                last.detail,
                kind.as_str().replace('_', "-")
            ),
            ev.iter().filter_map(|e| e.pid).collect(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{DStateProc, DiskStat, FsErrorStat, MdArray, Pressure};

    const GB: u64 = 1 << 30;

    fn u(name: &str) -> Unit {
        Unit {
            name: name.into(),
            kind: UnitKind::Systemd,
            state: "active".into(),
            main_pid: Some(10),
            ..Default::default()
        }
    }

    #[test]
    fn unit_rules() {
        let cfg = ServerCfg::default();
        let mut f = u("api.service");
        f.state = "failed".into();
        f.result = "exit-code".into();
        f.exit_code = Some(2);
        let mut db = u("postgresql.service");
        db.state = "failed".into();
        db.result = "oom-kill".into();
        let mut flap = u("worker.service");
        flap.recent_restarts = 5;
        flap.flapping = true;
        let mut lim = u("cache.service");
        lim.mem = 950 << 20;
        lim.mem_limit = Some(1 << 30);
        let mut thr = u("batch.service");
        thr.cpu_throttled_pct = 70.0;
        thr.cpu_quota = Some(1.0);
        thr.cpu = 99.0;
        let mut stall = u("jvm.service");
        stall.psi = Some(Pressure { mem_full: 30.0, ..Default::default() });
        let fs = units_with(&[f, db, flap, lim, thr, stall, u("ok.service")], &cfg);
        let t: Vec<&str> = fs.iter().map(|f| f.title.as_str()).collect();
        assert!(t.contains(&"api.service failed (exit-code, status 2)"), "{t:?}");
        let api = fs.iter().find(|f| f.title.starts_with("api.service")).unwrap();
        assert_eq!(api.severity, "crit");
        assert!(
            api.detail.contains("journalctl -u api.service") && api.detail.contains("systemctl restart api.service"),
            "{}",
            api.detail
        );
        assert_eq!(api.action, None, "fat never restarts units");
        let pg = fs.iter().find(|f| f.title.starts_with("postgresql.service")).unwrap();
        assert!(!pg.detail.contains("systemctl restart") && pg.detail.contains("find out why"), "{}", pg.detail);
        assert!(pg.detail.contains("exceeding its memory limit"));
        assert!(t.contains(&"worker.service is in a restart loop"));
        assert!(t.iter().any(|x| x.starts_with("cache.service at 93%")), "{t:?}");
        assert!(t.contains(&"batch.service throttled 70% of the time"));
        assert!(fs.iter().any(|f| f.title.starts_with("batch.service") && f.detail.contains("needs more CPU")));
        assert!(t.contains(&"jvm.service stalls on memory 30% of the time"));
        assert!(!t.iter().any(|x| x.starts_with("ok.service")));
        // Many failures are grouped.
        let many: Vec<Unit> = (0..9).map(|i| Unit { state: "failed".into(), ..u(&format!("u{i}.service")) }).collect();
        let fs = units_with(&many, &cfg);
        assert_eq!(fs.len(), MAX_UNIT_FINDINGS + 1);
        assert!(fs.last().unwrap().title.starts_with("4 more failed"));
        // Containers get their runtime's commands.
        let mut c = u("web");
        c.kind = UnitKind::Container;
        c.state = "failed".into();
        c.container = Some(crate::server::ContainerMeta { runtime: "podman".into(), ..Default::default() });
        let fs = units_with(&[c], &cfg);
        assert!(fs[0].detail.contains("podman logs"), "{}", fs[0].detail);
    }

    #[test]
    fn kernel_rules() {
        let cfg = ServerCfg::default();
        let sys = System { cores: 4, cpu: 10.0, load: [12.0, 8.0, 4.0], ..Default::default() };
        let k = Kernel {
            iowait_pct: 30.0,
            steal_pct: 15.0,
            procs_blocked: 9,
            d_state: vec![DStateProc {
                pid: 7,
                name: "tar".into(),
                wchan: "io_schedule".into(),
                seconds: 30,
                unit: Some("backup.service".into()),
            }],
            disks: vec![
                DiskStat {
                    name: "sda".into(),
                    w_await_ms: 250.0,
                    queue_depth: 30.0,
                    util_pct: 100.0,
                    ..Default::default()
                },
                DiskStat { name: "sdb".into(), io_errors: Some(3), ..Default::default() },
            ],
            fd_used: Some(96_000),
            fd_max: Some(100_000),
            conntrack_used: Some(10),
            conntrack_max: Some(100),
            ephemeral_used: Some(25_000),
            ephemeral_range: Some((32768, 60999)),
            ro_remounts: vec!["/data".into()],
            fs_errors: vec![FsErrorStat {
                device: "sdc1".into(),
                mount: Some("/srv".into()),
                errors: 2,
                read_only: false,
            }],
            mdraid: vec![MdArray {
                name: "md0".into(),
                level: "raid1".into(),
                state: "degraded".into(),
                degraded: true,
                sync_pct: None,
            }],
            ntp_synced: Some(false),
            taint: 4097,
            taint_flags: "PO".into(),
            swap_in_ps: 900.0,
            swap_out_ps: 300.0,
            listen_drops_ps: 5.0,
            pressure: Some(Pressure { mem_full: 25.0, ..Default::default() }),
            ..Default::default()
        };
        let fs = kernel_with(&k, &sys, &cfg);
        let t: Vec<&str> = fs.iter().map(|f| f.title.as_str()).collect();
        let load = fs.iter().find(|f| f.title.starts_with("Load 12.0 with idle CPU")).expect("load idle");
        assert_eq!(load.severity, "warn");
        assert!(
            load.detail.contains("tar (pid 7, in io_schedule, backup.service)")
                && load.detail.contains("sda await 250 ms"),
            "{}",
            load.detail
        );
        for want in [
            "CPU steal 15%",
            "sda I/O latency 250 ms",
            "file descriptors 96% used",
            "ephemeral ports 89% used",
            "/data is read-only",
            "Filesystem errors on /srv",
            "I/O errors on sdb",
            "RAID md0 degraded",
            "Clock not synchronised",
            "Kernel tainted (PO)",
            "Swap thrashing (1200 pages/s)",
            "Memory stalls: the system is thrashing",
        ] {
            assert!(t.contains(&want), "missing {want}: {t:?}");
        }
        assert!(!t.iter().any(|x| x.starts_with("conntrack")), "10% is fine");
        assert!(!t.iter().any(|x| x.starts_with("iowait")), "slow disk already explains iowait");
        assert_eq!(fs.iter().find(|f| f.title.starts_with("file descriptors")).unwrap().severity, "crit");
        // Quiet kernel: nothing.
        let quiet =
            kernel_with(&Kernel::default(), &System { cores: 4, load: [0.5, 0.5, 0.5], ..Default::default() }, &cfg);
        assert!(quiet.is_empty(), "{quiet:?}");
        // Thresholds are config.
        let lax = ServerCfg { disk_await_warn_ms: 500.0, exhaustion_warn: 0.99, ..Default::default() };
        let t2: Vec<String> = kernel_with(&k, &sys, &lax).into_iter().map(|f| f.title).collect();
        assert!(!t2.iter().any(|x| x.starts_with("sda I/O") || x.starts_with("file descriptors")), "{t2:?}");
    }

    #[test]
    fn event_rules_and_server_merge() {
        let now = 1_800_000_000_000;
        let ev = |ago_s: i64, kind, unit: Option<&str>, extra: &[(&str, &str)]| Event {
            ts: now - ago_s * 1000,
            kind,
            subject: unit.map(|u| format!("unit:{u}")).unwrap_or_else(|| "kernel".into()),
            unit: unit.map(str::to_string),
            detail: format!("{kind:?}"),
            extra: extra.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        };
        let events = vec![
            ev(600, EventKind::OomKill, None, &[("victim", "java")]),
            ev(7200, EventKind::OomKill, None, &[("victim", "java")]),
            ev(90_000, EventKind::OomKill, None, &[("victim", "old")]),
            ev(100, EventKind::UnitRestart, Some("api.service"), &[]),
            ev(200, EventKind::UnitRestart, Some("api.service"), &[]),
            ev(300, EventKind::UnitRestart, Some("api.service"), &[]),
            ev(50, EventKind::HungTask, None, &[]),
        ];
        let fs = diagnose_events(&events, now);
        let oom = fs.iter().find(|f| f.title == "2 OOM kills in 24h").expect("oom");
        assert_eq!(oom.severity, "crit");
        assert!(oom.detail.contains("java x2"), "{}", oom.detail);
        assert!(fs.iter().any(|f| f.title == "api.service restarted 3 times in 24h"));
        assert!(fs.iter().any(|f| f.title == "1 hung task in 24h"));

        // Kernel-trouble findings are as severe as their worst event, capped by the kind.
        let graded = |sev: Severity| {
            let mut e = ev(40, EventKind::DiskError, None, &[]);
            e.severity = sev;
            diagnose_events(&[e], now)
                .into_iter()
                .find(|f| f.title == "1 disk/filesystem error in 24h")
                .expect("disk error")
                .severity
        };
        assert_eq!(graded(Severity::Warn), "warn", "a discard warning is not a media error");
        assert_eq!(graded(Severity::Crit), "crit");

        // Merge: a unit flapping right now suppresses the event-based restart finding.
        let mut flap = u("api.service");
        flap.flapping = true;
        flap.recent_restarts = 3;
        let snap = Snapshot {
            ts: now,
            units: vec![flap],
            kernel: Some(Kernel::default()),
            system: System { cores: 2, ..Default::default() },
            ..Default::default()
        };
        let all = diagnose_server_with(&snap, Some(&events), &ServerCfg::default());
        assert!(all.iter().any(|f| f.title == "api.service is in a restart loop"));
        assert!(!all.iter().any(|f| f.title == "api.service restarted 3 times in 24h"), "{all:?}");
        assert_eq!(all[0].severity, "crit");
        let _ = GB;
    }

    #[test]
    fn servers_protect_databases_and_plumbing() {
        use crate::blame::is_protected_server_name as prot;
        for n in [
            "postgres",
            "postgresql@16-main.service",
            "mysql.service",
            "mysqld",
            "redis-server",
            "mongod",
            "clickhouse-server",
            "ssh.service",
            "systemd-journald",
            "dbus.service",
            "kubelet.service",
        ] {
            assert!(prot(n), "{n}");
        }
        for n in ["api.service", "node", "backup.service", "nginx"] {
            assert!(!prot(n), "{n}");
        }
        let p = |pid: u32, ppid: u32, name: &str, cmd: &str, cpu: f32| crate::model::Proc {
            pid,
            ppid,
            name: name.into(),
            cmd: cmd.into(),
            user: "root".into(),
            cpu,
            ..Default::default()
        };
        let snap = Snapshot {
            system: System { os: "Linux 6.1".into(), cores: 4, load: [1.0; 3], ..Default::default() },
            procs: vec![
                p(1, 0, "systemd", "/sbin/init", 0.0),
                p(50, 1, "postgres", "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql", 390.0),
                p(60, 1, "sshd", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", 0.0),
                p(61, 60, "sshd", "sshd: alice@pts/0", 0.0),
                p(70, 1, "systemd-journald", "/usr/lib/systemd/systemd-journald", 0.0),
            ],
            ..Default::default()
        };
        let g = crate::blame::hub_gate(&snap, 50).expect("database is gated");
        assert!(g.hard && g.note.contains("database") && g.note.contains("investigate"), "{g:?}");
        assert!(crate::blame::hub_gate(&snap, 60).is_some_and(|g| g.hard), "sshd listener");
        assert!(crate::blame::hub_gate(&snap, 61).is_none_or(|g| !g.hard), "an ssh session is not the daemon");
        assert!(crate::blame::hub_gate(&snap, 70).is_some_and(|g| g.hard));
        for f in crate::blame::diagnose(&snap, None) {
            let a = f.action.unwrap_or_default();
            assert!(!a.contains(" 50") && !a.contains(" 60") && !a.contains(" 70"), "{} -> {a}", f.title);
        }
        let e = crate::blame::explain(&snap, 50, None);
        assert!(e.suggestions.iter().any(|s| s.contains("investigate the workload")), "{:?}", e.suggestions);
    }

    #[test]
    fn desktop_snapshots_get_no_server_findings() {
        let s = Snapshot { system: System { cores: 8, ..Default::default() }, ..Default::default() };
        let before = crate::blame::diagnose(&s, None);
        assert!(before.iter().all(|f| !f.title.contains("restart loop")));
        assert!(diagnose_server_with(&s, None, &ServerCfg::default()).is_empty());
    }
}
