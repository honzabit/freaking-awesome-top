//! `fat run --cpu 200 --mem 2G --time 10m -- cmd`: supervise a process tree under a budget. OWNER: actions agent.
//!
//! The job runs in its own process group, which is handed the terminal while it runs (so
//! interactive commands work) and taken back while a budget pause is in force (so Ctrl-C
//! reaches fat, which then interrupts *and* continues the frozen job). CPU is measured
//! from kernel cpu-time counters, including children that came and went between polls,
//! and enforcement reaches descendants that left the process group.
//!
//! On Linux the tree is read straight from procfs (child CPU of reaped children from
//! /proc/<pid>/stat cutime/cstime), and when cgroup v2 can be delegated to us the kernel
//! enforces cpu (cpu.max) and memory (memory.max) itself; see [`cgroup`]. Polling stays on for
//! reporting, the time and process-count budgets, and as the fallback.
use crate::model::Budget;
use anyhow::{anyhow, bail, Context};
use std::collections::{HashMap, HashSet};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
#[cfg(not(target_os = "linux"))]
use sysinfo::{ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System};

const POLL: Duration = Duration::from_millis(500);
/// How often the leader is checked for exit/stop between usage samples.
const WAIT_SLICE: Duration = Duration::from_millis(50);
const KILL_GRACE: Duration = Duration::from_secs(3);
/// Consecutive over-budget CPU samples before it counts (filters one-off spikes).
const CPU_STRIKES: u32 = 2;

/// Split "1.5g" into (1.5, "g").
fn split_num(s: &str) -> anyhow::Result<(f64, String)> {
    let s = s.trim();
    let end = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
    let (num, unit) = s.split_at(end);
    if num.is_empty() {
        bail!("expected a number in {s:?}");
    }
    let n: f64 = num.parse().with_context(|| format!("bad number {num:?}"))?;
    Ok((n, unit.trim().to_ascii_lowercase()))
}

/// Parse "2G", "512M", "1.5g" -> bytes.
pub fn parse_bytes(s: &str) -> anyhow::Result<u64> {
    let (n, unit) = split_num(s)?;
    let unit = unit.trim_end_matches("ib").trim_end_matches('b');
    let mult: u64 = match unit {
        "" => 1,
        "k" => 1 << 10,
        "m" => 1 << 20,
        "g" => 1 << 30,
        "t" => 1 << 40,
        other => bail!("unknown size unit {other:?} in {s:?} (use k, M, G, T)"),
    };
    Ok((n * mult as f64).round() as u64)
}

/// Parse "90s", "10m", "2h", "30" -> seconds. Also accepts "1d" and "1h30m".
pub fn parse_duration(s: &str) -> anyhow::Result<u64> {
    let mut rest = s.trim();
    if rest.is_empty() {
        bail!("empty duration");
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
        let (num, tail) = rest.split_at(end);
        let n: f64 = num.parse().map_err(|_| anyhow!("bad duration {s:?}"))?;
        let uend = tail.find(|c: char| c.is_ascii_digit() || c == '.').unwrap_or(tail.len());
        let (unit, next) = tail.split_at(uend);
        let mult = match unit.trim().to_ascii_lowercase().as_str() {
            "" | "s" | "sec" | "secs" => 1.0,
            "m" | "min" | "mins" => 60.0,
            "h" | "hr" | "hrs" => 3600.0,
            "d" | "day" | "days" => 86400.0,
            u => bail!("unknown duration unit {u:?} in {s:?} (use s, m, h, d)"),
        };
        total += n * mult;
        rest = next;
    }
    Ok(total.round() as u64)
}

pub(crate) fn fmt_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b}B") } else { format!("{v:.1}{}", U[i]) }
}

fn fmt_secs(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 60.0 { format!("{s:.1}s") } else { format!("{}m{:02}s", s as u64 / 60, s as u64 % 60) }
}

/// Process group the SIGINT/SIGTERM handler forwards to (0 = none).
static CHILD_PGID: AtomicI32 = AtomicI32::new(0);
/// Last signal forwarded by the handler (0 = none), so the main loop can follow up.
static FORWARDED: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_signal(sig: libc::c_int) {
    let pg = CHILD_PGID.load(Ordering::SeqCst);
    if pg > 1 {
        // SAFETY: kill(2) is async-signal-safe; negative pid targets only our child's group.
        // A paused (stopped) group would keep INT/TERM pending forever, so continue it too.
        unsafe {
            libc::kill(-pg, sig);
            libc::kill(-pg, libc::SIGCONT);
        }
    }
    FORWARDED.store(sig, Ordering::SeqCst);
}

fn signal_group(pgid: i32, sig: i32) {
    if pgid > 1 {
        // SAFETY: pgid is the group of a child we spawned with process_group(0).
        unsafe {
            libc::kill(-pgid, sig);
        }
    }
}

fn pgid_of(pid: u32) -> Option<i32> {
    // SAFETY: getpgid has no memory preconditions.
    let g = unsafe { libc::getpgid(pid as libc::pid_t) };
    (g > 0).then_some(g)
}

// ---------------------------------------------------------------- terminal handoff

/// While supervising, the job's process group owns the terminal (like a shell's foreground
/// job), so reads and tty mode changes work instead of stopping it with SIGTTIN/SIGTTOU.
/// fat takes the terminal back while the job is paused (so Ctrl-C reaches fat) and on exit.
struct Tty {
    fd: libc::c_int,
    /// Opened /dev/tty (closed on drop) when stdin isn't the terminal.
    owned: bool,
    fat_pgrp: libc::pid_t,
    old_ttou: libc::sighandler_t,
}

impl Tty {
    /// Only when fat itself is the terminal's foreground job; otherwise there's nothing to hand over.
    fn acquire() -> Option<Tty> {
        // SAFETY: isatty/tcgetpgrp/getpgrp/open take no pointers we don't own.
        unsafe {
            let (fd, owned) = if libc::isatty(0) == 1 {
                (0, false)
            } else {
                let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
                if fd < 0 {
                    return None;
                }
                (fd, true)
            };
            let fat_pgrp = libc::getpgrp();
            if libc::tcgetpgrp(fd) != fat_pgrp {
                if owned {
                    libc::close(fd);
                }
                return None;
            }
            // fat calls tcsetpgrp while in the background (to take the tty back); that raises
            // SIGTTOU unless ignored. Set after spawn, so the child keeps the default.
            let old_ttou = libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            Some(Tty { fd, owned, fat_pgrp, old_ttou })
        }
    }

    fn give(&self, pgid: i32) {
        // SAFETY: plain ioctl wrapper on a terminal fd we hold.
        unsafe {
            libc::tcsetpgrp(self.fd, pgid);
        }
    }

    fn reclaim(&self) {
        // SAFETY: as above; SIGTTOU is ignored so this can't stop fat.
        unsafe {
            libc::tcsetpgrp(self.fd, self.fat_pgrp);
        }
    }
}

impl Drop for Tty {
    fn drop(&mut self) {
        self.reclaim();
        // SAFETY: restoring the disposition returned by signal(); closing our own fd.
        unsafe {
            libc::signal(libc::SIGTTOU, self.old_ttou);
            if self.owned {
                libc::close(self.fd);
            }
        }
    }
}

// ---------------------------------------------------------------- accounting

#[derive(Debug, Default, Clone, PartialEq)]
struct Usage {
    cpu: f32,
    mem: u64,
    procs: usize,
    /// Every tracked member is stopped (the whole job is frozen).
    stopped: bool,
}

/// One tracked process of the job.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Member {
    start: u64,
    ppid: u32,
}

/// CPU consumed by a process tree from kernel cpu-time counters, including processes that
/// lived and died between two polls: their time shows up in the reaping parent's
/// child-rusage. Children we already counted while alive are credited back so their time
/// isn't counted twice when the parent reaps them.
#[derive(Default)]
struct CpuMeter {
    /// (own_ns, child_ns, ppid) at the previous sample, by (pid, start).
    prev: HashMap<(u32, u64), (u64, u64, u32)>,
}

impl CpuMeter {
    /// Nanoseconds of CPU consumed since the previous call. `cur` maps (pid, start) ->
    /// (own_ns, child_ns, ppid) for members with readable counters.
    fn consumed(&mut self, cur: HashMap<(u32, u64), (u64, u64, u32)>) -> u64 {
        let mut credit: HashMap<u32, u64> = HashMap::new();
        for (k, &(own, child, ppid)) in &self.prev {
            if !cur.contains_key(k) {
                *credit.entry(ppid).or_default() += own + child;
            }
        }
        let mut total = 0u64;
        for (&(pid, start), &(own, child, _)) in &cur {
            let (p_own, p_child) = self.prev.get(&(pid, start)).map(|&(o, c, _)| (o, c)).unwrap_or((0, 0));
            total += own.saturating_sub(p_own);
            let reaped = child.saturating_sub(p_child);
            total += reaped.saturating_sub(credit.get(&pid).copied().unwrap_or(0));
        }
        self.prev = cur;
        total
    }
}

/// One process as one poll saw it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Row {
    ppid: Option<u32>,
    /// Epoch seconds.
    start: u64,
    zombie: bool,
    stopped: bool,
    /// Resident bytes.
    mem: u64,
    /// Sampler's own CPU% estimate, used only when no kernel counters are readable.
    cpu_usage: f32,
    /// (own_ns, reaped_children_ns) when the sampler already read them; None = ask
    /// `collect::procs::counters`.
    ctr: Option<(u64, u64)>,
}

type Table = HashMap<u32, Row>;

/// Reads the whole process table once per poll.
struct Sampler {
    #[cfg(not(target_os = "linux"))]
    sys: System,
}

#[cfg(not(target_os = "linux"))]
impl Sampler {
    fn new() -> Sampler {
        Sampler { sys: System::new() }
    }

    fn table(&mut self) -> Table {
        let refresh = ProcessRefreshKind::nothing().with_cpu().with_memory();
        self.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
        self.sys
            .processes()
            .iter()
            .map(|(pid, p)| {
                let row = Row {
                    ppid: p.parent().map(|x| x.as_u32()),
                    start: p.start_time(),
                    zombie: p.status() == ProcessStatus::Zombie,
                    stopped: p.status() == ProcessStatus::Stop,
                    mem: p.memory(),
                    cpu_usage: p.cpu_usage(),
                    ctr: None,
                };
                (pid.as_u32(), row)
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
impl Sampler {
    fn new() -> Sampler {
        Sampler {}
    }

    /// One pass over /proc/<pid>/stat: ppid, state, rss, start time and cpu (own + reaped
    /// children, the same accounting macOS gets from rusage). ~1000 procs in a few ms.
    fn table(&mut self) -> Table {
        table_at(std::path::Path::new("/proc"))
    }
}

#[cfg(target_os = "linux")]
fn table_at(proc_root: &std::path::Path) -> Table {
    use crate::actions::procfs;
    let mut t = Table::new();
    let Ok(rd) = std::fs::read_dir(proc_root) else { return t };
    let page = procfs::page_size();
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let Some(st) = procfs::read_stat(proc_root, pid) else { continue };
        let row = Row {
            ppid: (st.ppid != 0).then_some(st.ppid),
            start: procfs::start_epoch_at(proc_root, &st),
            zombie: matches!(st.state, 'Z' | 'X' | 'x'),
            stopped: st.state == 'T',
            mem: st.rss_pages * page,
            cpu_usage: 0.0,
            ctr: Some((procfs::ticks_to_ns(st.utime + st.stime), procfs::ticks_to_ns(st.cutime + st.cstime))),
        };
        t.insert(pid, row);
    }
    t
}

/// The job's process tree across polls. Descendants are found by ppid, and members seen
/// before stay tracked (by pid + start time) after their parent dies and they are
/// re-parented to launchd, so a daemonizing child can't slip out of the budget.
struct Tracker {
    root: u32,
    pgid: i32,
    members: HashMap<u32, Member>,
    meter: CpuMeter,
    last: Option<Instant>,
}

impl Tracker {
    fn new(root: u32, pgid: i32) -> Tracker {
        Tracker { root, pgid, members: HashMap::new(), meter: CpuMeter::default(), last: None }
    }

    /// `extra`: pids known to belong to the job regardless of ancestry (its cgroup's members).
    fn sample(&mut self, table: &Table, extra: &[u32]) -> Usage {
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for (&pid, r) in table {
            if let Some(pp) = r.ppid {
                children.entry(pp).or_default().push(pid);
            }
        }
        let alive = |pid: u32| table.get(&pid).filter(|r| !r.zombie);

        let mut next: HashMap<u32, Member> = HashMap::new();
        // Previously known members that still exist as the same incarnation.
        for (&pid, m) in &self.members {
            if let Some(p) = alive(pid)
                && p.start.abs_diff(m.start) <= 1
            {
                next.insert(pid, Member { start: p.start, ppid: p.ppid.unwrap_or(0) });
            }
        }
        let mut stack: Vec<u32> = vec![self.root];
        stack.extend(next.keys().copied());
        stack.extend(extra);
        let mut seen = HashSet::new();
        while let Some(pid) = stack.pop() {
            if !seen.insert(pid) {
                continue;
            }
            let Some(p) = alive(pid) else { continue };
            next.entry(pid).or_insert(Member { start: p.start, ppid: p.ppid.unwrap_or(0) });
            if let Some(c) = children.get(&pid) {
                stack.extend(c);
            }
        }
        self.members = next;

        let now = Instant::now();
        let dt = self.last.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0);
        self.last = Some(now);

        let mut u = Usage { procs: self.members.len(), stopped: !self.members.is_empty(), ..Default::default() };
        let mut counters = HashMap::new();
        let mut fallback_cpu = 0f32;
        for (&pid, m) in &self.members {
            let Some(p) = table.get(&pid) else { continue };
            u.mem += p.mem;
            u.stopped &= p.stopped;
            match p.ctr.or_else(|| crate::collect::procs::counters(pid).map(|c| (c.cpu_ns, c.child_cpu_ns))) {
                Some((own, child)) => {
                    counters.insert((pid, m.start), (own, child, m.ppid));
                }
                None => fallback_cpu += p.cpu_usage,
            }
        }
        let ns = self.meter.consumed(counters);
        u.cpu = fallback_cpu + if dt > 0.0 { (ns as f64 / 1e9 / dt * 100.0) as f32 } else { 0.0 };
        u
    }

    /// Members that left the job's process group (setsid, `set -m`, daemonizing tools):
    /// `kill(-pgid)` doesn't reach them, so they're signalled one by one.
    fn escaped(&self) -> Vec<(u32, u64)> {
        let mut v: Vec<(u32, u64)> = self
            .members
            .iter()
            .filter(|&(&pid, _)| pid != self.root && pgid_of(pid).is_some_and(|g| g != self.pgid))
            .map(|(&pid, m)| (pid, m.start))
            .collect();
        v.sort_unstable();
        v
    }

    /// Signal the job: its process group plus every escaped member (each re-verified by start
    /// time right before the signal, so a recycled pid is never hit). Returns escaped count.
    fn signal(&self, sig: i32) -> usize {
        signal_group(self.pgid, sig);
        let mut n = 0;
        for (pid, start) in self.escaped() {
            let same = crate::actions::live_proc(pid).is_some_and(|l| l.start_time == 0 || l.start_time.abs_diff(start) <= 1);
            if same {
                // SAFETY: positive pid of a verified descendant of the child we spawned.
                unsafe {
                    libc::kill(pid as libc::pid_t, sig);
                }
                n += 1;
            }
        }
        n
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Cpu,
    Mem,
    Time,
    Procs,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Cpu => "cpu",
            Kind::Mem => "mem",
            Kind::Time => "time",
            Kind::Procs => "procs",
        }
    }
}

/// Pure budget check. `cpu_strikes` tracks consecutive CPU overages.
fn violations(b: &Budget, u: &Usage, elapsed: Duration, cpu_strikes: &mut u32) -> Vec<(Kind, String)> {
    let mut v = Vec::new();
    if let Some(lim) = b.cpu {
        if u.cpu > lim {
            *cpu_strikes += 1;
            if *cpu_strikes >= CPU_STRIKES {
                v.push((Kind::Cpu, format!("cpu {:.0}% > budget {:.0}%", u.cpu, lim)));
            }
        } else {
            *cpu_strikes = 0;
        }
    }
    if let Some(lim) = b.mem
        && u.mem > lim {
            v.push((Kind::Mem, format!("mem {} > budget {}", fmt_bytes(u.mem), fmt_bytes(lim))));
        }
    if let Some(lim) = b.time
        && elapsed.as_secs_f64() > lim as f64 {
            v.push((Kind::Time, format!("wall time {} > budget {lim}s", fmt_secs(elapsed))));
        }
    if let Some(lim) = b.procs
        && u.procs > lim {
            v.push((Kind::Procs, format!("{} processes > budget {lim}", u.procs)));
        }
    v
}

/// What happened to the leader, from waitpid(WUNTRACED | WCONTINUED).
enum Wait {
    Running,
    Exited(ExitStatus),
    Stopped(i32),
    Continued,
}

fn wait_leader(pid: u32) -> anyhow::Result<Wait> {
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid on our own child with a valid status out-pointer.
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED) };
    if r == 0 {
        return Ok(Wait::Running);
    }
    if r < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            return Ok(Wait::Running);
        }
        return Err(anyhow!("waitpid({pid}): {e}"));
    }
    Ok(if libc::WIFSTOPPED(status) {
        Wait::Stopped(libc::WSTOPSIG(status))
    } else if libc::WIFCONTINUED(status) {
        Wait::Continued
    } else {
        Wait::Exited(ExitStatus::from_raw(status))
    })
}

fn sig_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGTTIN => "SIGTTIN",
        libc::SIGTTOU => "SIGTTOU",
        libc::SIGTSTP => "SIGTSTP",
        libc::SIGSTOP => "SIGSTOP",
        _ => "a stop signal",
    }
}

/// Outcome of a supervised run.
#[derive(Debug, Clone, PartialEq)]
struct Report {
    code: i32,
    fired: Vec<Kind>,
    peak: Usage,
    /// Kernel enforcement results (Linux cgroup v2; zero/None when polling).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    kernel: KernelStats,
}

/// What the kernel did to the job (cgroup v2 counters at exit).
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct KernelStats {
    /// "cgroup" / "systemd --user" / "systemd" when a cgroup held the job; None = polling only.
    via: Option<&'static str>,
    cpu_enforced: bool,
    mem_enforced: bool,
    /// cpu.stat nr_throttled / throttled_usec.
    throttled: u64,
    throttled_usec: u64,
    /// memory.events oom_kill.
    oom_kills: u64,
    /// memory.peak (or the highest memory.current seen), page cache included.
    mem_peak: u64,
    /// The cgroup directory, and whether it is gone after the run (root mode removes its own).
    dir: Option<std::path::PathBuf>,
    removed: bool,
}

/// How `fat run` enforces a budget. Linux: `FAT_BUDGET_MODE=poll|cgroup` forces one (auto
/// otherwise: cgroup v2 when we can get one, polling when not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum Mode {
    Auto,
    Poll,
    Cgroup,
}

#[cfg(target_os = "linux")]
fn mode_from_env() -> anyhow::Result<Mode> {
    match std::env::var("FAT_BUDGET_MODE").unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(Mode::Auto),
        "poll" | "polling" => Ok(Mode::Poll),
        "cgroup" | "kernel" => Ok(Mode::Cgroup),
        other => bail!("unknown FAT_BUDGET_MODE {other:?} (use poll, cgroup or auto)"),
    }
}

#[cfg(not(target_os = "linux"))]
fn mode_from_env() -> anyhow::Result<Mode> {
    Ok(Mode::Auto)
}

/// Run cmd, enforce budget on its whole tree, print violations to stderr. Returns child's exit code.
pub fn run(cmd: &[String], budget: &Budget) -> anyhow::Result<i32> {
    supervise(cmd, budget, mode_from_env()?).map(|r| r.code)
}

fn supervise(cmd: &[String], budget: &Budget, enforce: Mode) -> anyhow::Result<Report> {
    let (prog, args) = cmd.split_first().ok_or_else(|| anyhow!("no command given"))?;
    let mode = match budget.on_violation.trim().to_ascii_lowercase().as_str() {
        "" | "warn" => "warn",
        "pause" | "stop" => "pause",
        "kill" | "term" => "kill",
        other => bail!("unknown --on-violation {other:?} (use pause, kill or warn)"),
    };

    let mut kernel = Kernel::prepare(budget, mode, enforce)?;
    let start = Instant::now();
    let child = kernel.command(prog, args)?.spawn().with_context(|| format!("failed to start {prog:?}"))?;
    let pid = child.id();
    // We reap the child ourselves with waitpid(WUNTRACED) to see job-control stops.
    drop(child);
    kernel.attach(pid, budget);
    let pgid = pid as i32;
    CHILD_PGID.store(pgid, Ordering::SeqCst);
    FORWARDED.store(0, Ordering::SeqCst);

    let tty = Tty::acquire();
    if let Some(t) = &tty {
        t.give(pgid);
        // If it already read the tty before the handoff it is stopped by SIGTTIN; wake it.
        signal_group(pgid, libc::SIGCONT);
    }

    // Forward TERM (and Ctrl-C while fat holds the terminal) to the job.
    // SAFETY: installing a handler that only calls the async-signal-safe kill(2) and an atomic store.
    let (old_int, old_term) = unsafe {
        let h = forward_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        (libc::signal(libc::SIGINT, h), libc::signal(libc::SIGTERM, h))
    };

    let mut sampler = Sampler::new();
    let mut tracker = Tracker::new(pid, pgid);
    tracker.sample(&sampler.table(), &kernel.members());
    let mut cpu_ref = Usage::default();
    kernel.sample(&mut cpu_ref);
    let limits = kernel.effective(budget);

    let mut peak = Usage::default();
    let mut fired: Vec<Kind> = Vec::new();
    let mut cpu_strikes = 0u32;
    let mut kill_deadline: Option<Instant> = None;
    let mut killed_hard = false;
    let mut paused_by_us = false;
    // After the user interrupts, don't re-pause: they asked the job to stop.
    let mut interrupted = false;
    let mut warned_stop = false;
    let mut next_sample = Instant::now() + POLL;

    let status = loop {
        match wait_leader(pid)? {
            Wait::Exited(st) => {
                kernel.tick();
                break st;
            }
            Wait::Running => {}
            Wait::Continued => {
                if paused_by_us {
                    // Someone ran `kill -CONT -pgid` / `fat resume`: follow through.
                    paused_by_us = false;
                    tracker.signal(libc::SIGCONT);
                    eprintln!("fat run: resumed");
                }
                if let Some(t) = &tty {
                    t.give(pgid);
                }
            }
            Wait::Stopped(_) if paused_by_us => {}
            Wait::Stopped(sig) => match &tty {
                Some(t) if sig == libc::SIGTTIN || sig == libc::SIGTTOU => {
                    t.give(pgid);
                    signal_group(pgid, libc::SIGCONT);
                }
                Some(t) => {
                    // Ctrl-Z (or an external STOP): behave like a shell job and suspend fat
                    // too, so the user's shell regains control; continue the job on `fg`.
                    t.reclaim();
                    // SAFETY: stopping ourselves with the default SIGTSTP action.
                    unsafe {
                        libc::kill(libc::getpid(), libc::SIGTSTP);
                    }
                    t.give(pgid);
                    tracker.signal(libc::SIGCONT);
                }
                None => {
                    if !warned_stop {
                        warned_stop = true;
                        let what = if sig == libc::SIGTTIN || sig == libc::SIGTTOU {
                            "it wants the terminal, but fat run doesn't control one (stdin is not a tty)"
                        } else {
                            "it was suspended"
                        };
                        eprintln!(
                            "fat run: {prog} (pid {pid}) is stopped by {}: {what}. Continue it with `kill -CONT -{pgid}`, or stop it with `kill {}`",
                            sig_name(sig),
                            std::process::id()
                        );
                    }
                }
            },
        }

        let fwd = FORWARDED.swap(0, Ordering::SeqCst);
        if fwd != 0 {
            interrupted = true;
            paused_by_us = false;
            // The handler covered the group; escaped members need it from here.
            tracker.signal(fwd);
            tracker.signal(libc::SIGCONT);
            if let Some(t) = &tty {
                t.give(pgid);
            }
        }

        kernel.tick();
        std::thread::sleep(WAIT_SLICE);
        if Instant::now() < next_sample {
            continue;
        }
        next_sample = Instant::now() + POLL;
        let mut u = tracker.sample(&sampler.table(), &kernel.members());
        if let Some(n) = kernel.sample(&mut u) {
            let lim = budget.mem.map(fmt_bytes).unwrap_or_default();
            eprintln!("fat run: budget exceeded: mem > budget {lim}; the kernel OOM-killed inside the job ({n} oom_kill event(s), memory.max)");
            if !fired.contains(&Kind::Mem) {
                fired.push(Kind::Mem);
            }
        }
        peak.cpu = peak.cpu.max(u.cpu);
        peak.mem = peak.mem.max(u.mem);
        peak.procs = peak.procs.max(u.procs);

        if let Some(dl) = kill_deadline {
            if !killed_hard && Instant::now() >= dl {
                eprintln!("fat run: still alive after {}s, sending SIGKILL to group {pgid}", KILL_GRACE.as_secs());
                tracker.signal(libc::SIGKILL);
                kernel.kill_all();
                killed_hard = true;
            }
            continue;
        }

        for (kind, why) in violations(&limits, &u, start.elapsed(), &mut cpu_strikes) {
            let first = !fired.contains(&kind);
            // A wall-clock budget is a deadline: pausing would only hold the job forever,
            // so `--time` always stops the job unless the policy is warn-only.
            let mode = if kind == Kind::Time && mode == "pause" { "kill" } else { mode };
            let mode = if mode == "pause" && interrupted { "warn" } else { mode };
            match mode {
                "warn" => {
                    if first {
                        eprintln!("fat run: budget exceeded: {why} (warn only)");
                    }
                }
                "pause" => {
                    // Resource budgets re-pause if the user resumes and it recurs. Only skip
                    // when the *whole* job is frozen, not just the leader.
                    if u.stopped && paused_by_us {
                        continue;
                    }
                    if let Some(t) = &tty {
                        t.reclaim(); // so Ctrl-C reaches fat while the job is frozen
                    }
                    let escaped = tracker.signal(libc::SIGSTOP);
                    let already = std::mem::replace(&mut paused_by_us, true);
                    if already {
                        continue; // a straggler was still running; it's frozen now too
                    }
                    let also = if escaped > 0 { format!(" and {escaped} process(es) that left it") } else { String::new() };
                    eprintln!(
                        "fat run: budget exceeded: {why}; paused process group {pgid}{also}. Resume with `kill -CONT -{pgid}` or `fat resume {pid}`; stop it with Ctrl-C here or `kill {}`",
                        std::process::id()
                    );
                }
                _ => {
                    eprintln!("fat run: budget exceeded: {why}; sending SIGTERM to group {pgid}");
                    tracker.signal(libc::SIGTERM);
                    // A stopped group can't handle TERM until continued.
                    tracker.signal(libc::SIGCONT);
                    kill_deadline = Some(Instant::now() + KILL_GRACE);
                }
            }
            if first {
                fired.push(kind);
            }
            if kill_deadline.is_some() {
                break;
            }
        }
    };

    CHILD_PGID.store(0, Ordering::SeqCst);
    // SAFETY: restoring the previous dispositions returned by signal().
    unsafe {
        libc::signal(libc::SIGINT, old_int);
        libc::signal(libc::SIGTERM, old_term);
    }
    drop(tty); // terminal back to fat's group
    if kill_deadline.is_some() {
        // Leader is gone; make sure stragglers (in the group or escaped) go too.
        tracker.sample(&sampler.table(), &kernel.members());
        tracker.signal(libc::SIGKILL);
        kernel.kill_all();
    }
    // An OOM kill can end the job between two polls (or before the first one).
    if status.signal() == Some(libc::SIGKILL) && !killed_hard {
        kernel.sigkilled();
    }
    if let Some(n) = kernel.sample(&mut Usage::default()) {
        let lim = budget.mem.map(fmt_bytes).unwrap_or_default();
        eprintln!("fat run: budget exceeded: mem > budget {lim}; the kernel OOM-killed inside the job ({n} oom_kill event(s), memory.max)");
        if !fired.contains(&Kind::Mem) {
            fired.push(Kind::Mem);
        }
    }
    let (kstats, ksummary) = kernel.finish();

    let code = match (status.code(), status.signal()) {
        (Some(c), _) => c,
        (None, Some(s)) => 128 + s,
        _ => 1,
    };
    let vio = if fired.is_empty() {
        "none".to_string()
    } else {
        fired.iter().map(|k| k.label()).collect::<Vec<_>>().join(",")
    };
    eprintln!(
        "fat run: exit {code} | wall {} | peak cpu {:.0}% | peak mem {} | peak procs {} | violations: {vio}{ksummary}",
        fmt_secs(start.elapsed()),
        peak.cpu,
        fmt_bytes(peak.mem),
        peak.procs
    );
    Ok(Report { code, fired, peak, kernel: kstats })
}

// ---------------------------------------------------------------- kernel enforcement

/// Kernel-side enforcement for a job. Only Linux has one (cgroup v2); elsewhere every hook is a
/// no-op and `fat run` polls exactly as it always has.
#[cfg(not(target_os = "linux"))]
struct Kernel;

#[cfg(not(target_os = "linux"))]
impl Kernel {
    fn prepare(_b: &Budget, _policy: &str, _mode: Mode) -> anyhow::Result<Kernel> {
        Ok(Kernel)
    }
    fn command(&self, prog: &str, args: &[String]) -> anyhow::Result<Command> {
        let mut c = Command::new(prog);
        c.args(args).process_group(0);
        Ok(c)
    }
    fn attach(&mut self, _pid: u32, _b: &Budget) {}
    fn members(&self) -> Vec<u32> {
        Vec::new()
    }
    fn sample(&mut self, _u: &mut Usage) -> Option<u64> {
        None
    }
    fn effective(&self, b: &Budget) -> Budget {
        b.clone()
    }
    fn kill_all(&mut self) {}
    fn tick(&mut self) {}
    fn sigkilled(&mut self) {}
    fn finish(&mut self) -> (KernelStats, String) {
        (KernelStats::default(), String::new())
    }
}

/// Linux: the job runs in its own cgroup v2 when we can get one, and the kernel enforces cpu
/// (cpu.max: the job is throttled, never over budget) and memory (memory.max: the kernel
/// reclaims, then OOM-kills inside the job only). Ways to get a cgroup, in order:
/// 1. root (or a writable cgroup root): /sys/fs/cgroup/fat.slice/run-<fatpid>-<n>, the child
///    moving itself in from `pre_exec` so not a single instruction of the job runs outside it;
/// 2. a systemd scope (`systemd-run --user --scope -p CPUQuota=.. -p MemoryMax=..`, or the
///    system manager when root), which is how an unprivileged user gets a delegated cgroup;
/// 3. none: polling enforces everything, as on macOS.
///
/// Polling always runs too: it reports (with exact cgroup cpu/memory numbers when in one), and
/// enforces the wall-time and process-count budgets and whatever the kernel couldn't take.
#[cfg(target_os = "linux")]
struct Kernel {
    job: Option<cgroup::Job>,
    /// Why there is no cgroup (shown in the "enforcing via polling" line).
    why_not: String,
    /// Any budget at all, i.e. whether to announce the mechanism.
    announce: bool,
}

#[cfg(target_os = "linux")]
impl Kernel {
    fn prepare(b: &Budget, policy: &str, mode: Mode) -> anyhow::Result<Kernel> {
        let announce = b.cpu.is_some() || b.mem.is_some() || b.time.is_some() || b.procs.is_some();
        let wants_cgroup = b.cpu.is_some() || b.mem.is_some();
        let (job, why_not) = match mode {
            Mode::Poll => (None, "FAT_BUDGET_MODE=poll".to_string()),
            Mode::Auto if !wants_cgroup => (None, String::new()),
            _ => {
                let want = cgroup::Want {
                    cpu_pct: b.cpu,
                    mem: b.mem,
                    // warn means "tell me", not "stop me": measure in a cgroup, don't limit.
                    limits: policy != "warn",
                    oom_group: policy == "kill",
                };
                match cgroup::Job::create(want) {
                    Ok(j) => (Some(j), String::new()),
                    Err(e) if mode == Mode::Cgroup => bail!("cgroup v2 enforcement unavailable: {e}"),
                    Err(e) => (None, format!("cgroup v2 unavailable: {e}")),
                }
            }
        };
        Ok(Kernel { job, why_not, announce })
    }

    fn command(&self, prog: &str, args: &[String]) -> anyhow::Result<Command> {
        match &self.job {
            Some(j) => j.command(prog, args),
            None => {
                let mut c = Command::new(prog);
                c.args(args).process_group(0);
                Ok(c)
            }
        }
    }

    fn attach(&mut self, pid: u32, b: &Budget) {
        if let Some(j) = &mut self.job
            && let Err(e) = j.attach(pid)
        {
            self.why_not = format!("cgroup v2 setup failed: {e}");
            self.job = None; // dropping removes the directory we made
        }
        if !self.announce {
            return;
        }
        let pct = |p: f32| format!("{p:.0}%");
        match &self.job {
            Some(j) => {
                let mut kern = Vec::new();
                let mut poll = Vec::new();
                if let Some(c) = b.cpu {
                    if j.cpu_enforced { kern.push(format!("cpu {} (cpu.max {})", pct(c), cgroup::cpu_max(c))) } else { poll.push("cpu") }
                }
                if let Some(m) = b.mem {
                    if j.mem_enforced { kern.push(format!("mem {} (memory.max)", fmt_bytes(m))) } else { poll.push("mem") }
                }
                if b.time.is_some() {
                    poll.push("time");
                }
                if b.procs.is_some() {
                    poll.push("procs");
                }
                let poll = if poll.is_empty() { String::new() } else { format!("; polling: {}", poll.join(", ")) };
                if kern.is_empty() {
                    let why = if j.want.limits { "the cpu/memory controllers aren't delegated here" } else { "warn only, no kernel limits" };
                    eprintln!("fat run: measuring via cgroup v2 ({}, {why}){poll}", j.describe());
                } else {
                    eprintln!("fat run: enforcing via cgroup v2 (kernel, {}): {}{poll}", j.describe(), kern.join(", "));
                }
            }
            None => {
                let why = if self.why_not.is_empty() { String::new() } else { format!(" ({})", self.why_not) };
                eprintln!("fat run: enforcing via polling every {}ms{why}", POLL.as_millis());
            }
        }
    }

    fn members(&self) -> Vec<u32> {
        self.job.as_ref().map(|j| j.members()).unwrap_or_default()
    }

    /// Exact cpu from the cgroup's own counter; returns newly seen OOM kills.
    fn sample(&mut self, u: &mut Usage) -> Option<u64> {
        self.job.as_mut()?.sample(u)
    }

    /// The budget polling still enforces: minus what the kernel holds.
    fn effective(&self, b: &Budget) -> Budget {
        let mut e = b.clone();
        if let Some(j) = &self.job {
            if j.cpu_enforced {
                e.cpu = None; // throttled, so it can't be "over"
            }
            if j.mem_enforced {
                e.mem = None; // the kernel reclaims or OOM-kills at memory.max
            }
        }
        e
    }

    fn kill_all(&mut self) {
        if let Some(j) = &mut self.job {
            j.kill_all();
        }
    }

    fn tick(&mut self) {
        if let Some(j) = &mut self.job {
            j.tick();
        }
    }

    fn sigkilled(&mut self) {
        if let Some(j) = &mut self.job {
            j.sigkilled();
        }
    }

    fn finish(&mut self) -> (KernelStats, String) {
        let Some(j) = self.job.as_mut() else { return (KernelStats::default(), String::new()) };
        let st = j.finish();
        let mut parts = Vec::new();
        if st.cpu_enforced {
            parts.push(format!("cpu throttled {}x ({:.1}s)", st.throttled, st.throttled_usec as f64 / 1e6));
        }
        if st.mem_enforced || st.oom_kills > 0 {
            parts.push(format!("oom kills {}", st.oom_kills));
        }
        if st.mem_peak > 0 {
            parts.push(format!("cgroup mem peak {} (incl. page cache)", fmt_bytes(st.mem_peak)));
        }
        if let Some(d) = st.dir.as_ref().filter(|_| !st.removed && j.owns_dir()) {
            parts.push(format!("{} still has processes; left in place", d.display()));
        }
        let s = if parts.is_empty() { String::new() } else { format!(" | kernel: {}", parts.join(", ")) };
        (st, s)
    }
}

/// cgroup v2 plumbing for `fat run` (Linux).
#[cfg(target_os = "linux")]
mod cgroup {
    use super::{KernelStats, Usage};
    use anyhow::anyhow;
    use std::collections::HashSet;
    use std::fs;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    pub const ROOT: &str = "/sys/fs/cgroup";
    /// cpu.max period. 100ms is the kernel default and what systemd's CPUQuota= uses.
    pub const PERIOD_US: u64 = 100_000;
    const SLICE: &str = "fat.slice";
    static SEQ: AtomicU32 = AtomicU32::new(0);

    #[derive(Debug, Clone, Default)]
    pub struct Want {
        pub cpu_pct: Option<f32>,
        pub mem: Option<u64>,
        /// Write cpu.max / memory.max (false: accounting only).
        pub limits: bool,
        /// memory.oom.group=1: an OOM kills the whole job, not just its biggest process.
        pub oom_group: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Via {
        /// A directory we created and remove.
        Root,
        /// A transient scope; systemd removes it when the job is gone.
        Systemd { user: bool },
    }

    pub struct Job {
        pub via: Via,
        pub want: Want,
        pub dir: Option<PathBuf>,
        unit: String,
        /// Root mode: cgroup.procs, opened before fork; the child writes "0" (= itself) to it.
        procs_fd: Option<OwnedFd>,
        pub cpu_enforced: bool,
        pub mem_enforced: bool,
        prev: Option<(u64, Instant)>,
        /// Latest counters, cached because a systemd scope's directory disappears the moment
        /// the job's last process exits (before we can read it in finish()).
        nr_throttled: u64,
        throttled_usec: u64,
        oom_total: u64,
        /// oom_kill events already reported.
        oom_seen: u64,
        /// Systemd: the parent slice's hierarchical oom_kill at attach, to still count an OOM
        /// kill that ended the job (and its scope) between two reads.
        parent_oom_base: Option<u64>,
        mem_peak: u64,
        cleaned: bool,
        /// cgroup.kill was written: members are on their way out.
        killed: bool,
    }

    /// "quota period" for cpu.max: percent of one core per 100ms period, e.g. 200% →
    /// "200000 100000". The kernel's minimum quota is 1ms.
    pub fn cpu_max(pct: f32) -> String {
        let quota = ((pct.max(0.0) as f64 / 100.0) * PERIOD_US as f64).round().max(1000.0) as u64;
        format!("{quota} {PERIOD_US}")
    }

    /// `key value` lines (cpu.stat, memory.events, memory.stat), e.g. cpu.stat on 6.x:
    /// `usage_usec 1527370\nuser_usec 1203981\nsystem_usec 323389\nnr_periods 31\nnr_throttled 25\nthrottled_usec 2041893`
    pub fn kv(text: &str, key: &str) -> Option<u64> {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(' ')?;
            (k == key).then(|| v.trim().parse().ok()).flatten()
        })
    }

    /// The unified-hierarchy path from /proc/<pid>/cgroup (`0::/user.slice/.../x.scope`).
    pub fn unified_path(proc_cgroup: &str) -> Option<&str> {
        proc_cgroup.lines().find_map(|l| l.strip_prefix("0::")).map(str::trim)
    }

    /// Space-separated controller lists (cgroup.controllers, cgroup.subtree_control).
    pub fn controllers(dir: &Path, file: &str) -> HashSet<String> {
        fs::read_to_string(dir.join(file)).unwrap_or_default().split_whitespace().map(str::to_string).collect()
    }

    /// The limit file holds a number, not "max" (and for cpu.max, the quota we asked for).
    pub fn limit_in_force(dir: &Path, file: &str) -> bool {
        fs::read_to_string(dir.join(file)).map(|s| !s.trim().is_empty() && !s.trim().starts_with("max")).unwrap_or(false)
    }

    /// Enable `wanted` controllers for `dir`'s children (each separately: one missing
    /// controller must not block the others). Errors only if a wanted one stays off.
    pub fn enable(dir: &Path, wanted: &[&str]) -> Result<(), String> {
        let avail = controllers(dir, "cgroup.controllers");
        let on = controllers(dir, "cgroup.subtree_control");
        let mut errs = Vec::new();
        for c in wanted {
            if on.contains(*c) {
                continue;
            }
            if !avail.contains(*c) {
                errs.push(format!("{c} controller not available in {}", dir.display()));
                continue;
            }
            if let Err(e) = fs::write(dir.join("cgroup.subtree_control"), format!("+{c}")) {
                errs.push(format!("enabling {c} in {}: {e}", dir.display()));
            }
        }
        if errs.is_empty() { Ok(()) } else { Err(errs.join("; ")) }
    }

    fn is_root() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    fn in_path(prog: &str) -> bool {
        let exec_ok = |p: &Path| {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
        };
        if prog.contains('/') {
            return exec_ok(Path::new(prog));
        }
        std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| exec_ok(&d.join(prog))))
    }

    /// Remove leftover run-<pid>-<n> dirs of fat processes that no longer exist (a fat that was
    /// SIGKILLed can't clean up). rmdir only succeeds on empty cgroups, so this never disturbs a job.
    fn gc(slice: &Path) {
        let Ok(rd) = fs::read_dir(slice) else { return };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(owner) = name.strip_prefix("run-").and_then(|r| r.split('-').next()).and_then(|p| p.parse::<u32>().ok()) else {
                continue;
            };
            if !Path::new(&format!("/proc/{owner}")).exists() {
                let _ = fs::remove_dir(e.path());
            }
        }
    }

    impl Job {
        pub fn create(want: Want) -> anyhow::Result<Job> {
            let root = Path::new(ROOT);
            if !root.join("cgroup.controllers").exists() {
                return Err(anyhow!("no cgroup v2 hierarchy at {ROOT}"));
            }
            let mut errs = Vec::new();
            match Job::create_dir(root, want.clone()) {
                Ok(j) => return Ok(j),
                Err(e) => errs.push(e),
            }
            match Job::systemd(want) {
                Ok(j) => return Ok(j),
                Err(e) => errs.push(e),
            }
            Err(anyhow!(errs.join("; ")))
        }

        /// Option 1: our own directory under <root>/fat.slice (needs write access to the
        /// cgroup root, i.e. root with the host's cgroup namespace).
        pub fn create_dir(root: &Path, want: Want) -> Result<Job, String> {
            // SAFETY: access(2) on a NUL-terminated path we own.
            let writable = {
                let p = std::ffi::CString::new(root.join("cgroup.subtree_control").as_os_str().as_encoded_bytes()).unwrap_or_default();
                unsafe { libc::access(p.as_ptr(), libc::W_OK) == 0 }
            };
            if !writable {
                return Err(if is_root() { format!("{ROOT} is read-only here") } else { "not root".to_string() });
            }
            let mut ctrls: Vec<&str> = Vec::new();
            if want.cpu_pct.is_some() {
                ctrls.push("cpu");
            }
            if want.mem.is_some() {
                ctrls.push("memory");
            }
            enable(root, &ctrls)?;
            let slice = root.join(SLICE);
            match fs::create_dir(&slice) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("mkdir {}: {e}", slice.display())),
            }
            enable(&slice, &ctrls)?;
            gc(&slice);
            let dir = slice.join(format!("run-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
            let _ = fs::remove_dir(&dir);
            fs::create_dir(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
            let mut job = Job {
                via: Via::Root,
                want,
                dir: Some(dir.clone()),
                unit: String::new(),
                procs_fd: None,
                cpu_enforced: false,
                mem_enforced: false,
                prev: None,
                nr_throttled: 0,
                throttled_usec: 0,
                oom_total: 0,
                oom_seen: 0,
                parent_oom_base: None,
                mem_peak: 0,
                cleaned: false,
                killed: false,
            };
            if job.want.limits {
                if let Some(p) = job.want.cpu_pct {
                    fs::write(dir.join("cpu.max"), cpu_max(p)).map_err(|e| format!("cpu.max: {e}"))?;
                }
                if let Some(m) = job.want.mem {
                    fs::write(dir.join("memory.max"), m.to_string()).map_err(|e| format!("memory.max: {e}"))?;
                    // Without this the job would page out to swap instead of meeting the limit.
                    let _ = fs::write(dir.join("memory.swap.max"), "0");
                    if job.want.oom_group {
                        let _ = fs::write(dir.join("memory.oom.group"), "1");
                    }
                }
            }
            let f = fs::OpenOptions::new().write(true).open(dir.join("cgroup.procs")).map_err(|e| format!("open cgroup.procs: {e}"))?;
            job.procs_fd = Some(f.into());
            job.read_enforced();
            Ok(job)
        }

        /// Option 2: a transient systemd scope, from the user manager (or the system one as root).
        fn systemd(want: Want) -> Result<Job, String> {
            let user = !is_root();
            if !in_path("systemd-run") {
                return Err("systemd-run not found".into());
            }
            if user {
                let rt = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
                let reachable = rt.as_ref().is_some_and(|d| d.join("bus").exists() || d.join("systemd/private").exists())
                    || std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
                if !reachable {
                    return Err("no systemd --user session (no $XDG_RUNTIME_DIR/bus; try `loginctl enable-linger`)".into());
                }
            } else if !Path::new("/run/systemd/system").exists() {
                return Err("systemd is not the init system".into());
            }
            // Probe once: the user manager can be absent even when the socket is there.
            let mut probe = Command::new("systemd-run");
            if user {
                probe.arg("--user");
            }
            probe.args(["--scope", "--quiet", "--collect", "--", "true"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            let mut child = probe.spawn().map_err(|e| format!("systemd-run: {e}"))?;
            let deadline = Instant::now() + Duration::from_secs(3);
            let ok = loop {
                match child.try_wait() {
                    Ok(Some(st)) => break st.success(),
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                    _ => {
                        let _ = child.kill(); // our own probe
                        let _ = child.wait();
                        break false;
                    }
                }
            };
            if !ok {
                let who = if user { "systemd --user" } else { "systemd" };
                return Err(format!("{who} would not start a scope"));
            }
            let unit = format!("fat-run-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
            Ok(Job {
                via: Via::Systemd { user },
                want,
                dir: None,
                unit,
                procs_fd: None,
                cpu_enforced: false,
                mem_enforced: false,
                prev: None,
                nr_throttled: 0,
                throttled_usec: 0,
                oom_total: 0,
                oom_seen: 0,
                parent_oom_base: None,
                mem_peak: 0,
                cleaned: false,
                killed: false,
            })
        }

        pub fn owns_dir(&self) -> bool {
            self.via == Via::Root
        }

        pub fn describe(&self) -> String {
            match self.via {
                Via::Root => self.dir.as_ref().map(|d| d.display().to_string()).unwrap_or_default(),
                Via::Systemd { user: true } => format!("systemd --user scope {}", self.unit),
                Via::Systemd { user: false } => format!("systemd scope {}", self.unit),
            }
        }

        pub fn command(&self, prog: &str, args: &[String]) -> anyhow::Result<Command> {
            match self.via {
                Via::Root => {
                    let mut c = Command::new(prog);
                    c.args(args).process_group(0);
                    if let Some(fd) = self.procs_fd.as_ref().map(|f| f.as_raw_fd()) {
                        // SAFETY: the closure only calls write(2), which is async-signal-safe,
                        // on an fd inherited from the parent (closed again by O_CLOEXEC at exec).
                        // A failure is detected by attach() in the parent, so it is ignored here.
                        unsafe {
                            c.pre_exec(move || {
                                libc::write(fd, b"0".as_ptr() as *const libc::c_void, 1);
                                Ok(())
                            });
                        }
                    }
                    Ok(c)
                }
                Via::Systemd { user } => {
                    // systemd-run execs the command itself, so a missing one would only show
                    // up as systemd-run's exit status; catch it like a direct spawn would.
                    if !in_path(prog) {
                        return Err(anyhow!("failed to start {prog:?}: No such file or directory"));
                    }
                    let mut c = Command::new("systemd-run");
                    if user {
                        c.arg("--user");
                    }
                    c.args(["--scope", "--quiet", "--collect", "--unit", &self.unit, "-p", "CPUAccounting=yes", "-p", "MemoryAccounting=yes"]);
                    if self.want.limits {
                        if let Some(p) = self.want.cpu_pct {
                            c.args(["-p", &format!("CPUQuota={}%", (p.max(1.0)).round() as u64)]);
                        }
                        if let Some(m) = self.want.mem {
                            c.args(["-p", &format!("MemoryMax={m}"), "-p", "MemorySwapMax=0"]);
                        }
                    }
                    c.arg("--").arg(prog).args(args).process_group(0);
                    Ok(c)
                }
            }
        }

        /// After spawn: confirm the job is in its cgroup (root mode), or find the scope's
        /// directory once systemd has moved it (systemd-run execs the command after that).
        pub fn attach(&mut self, pid: u32) -> Result<(), String> {
            match self.via {
                Via::Root => {
                    self.procs_fd = None;
                    let dir = self.dir.clone().ok_or("no cgroup dir")?;
                    if !self.contains(pid) {
                        // pre_exec's write failed (e.g. a seccomp or LSM rule); try from here.
                        fs::write(dir.join("cgroup.procs"), pid.to_string()).map_err(|e| format!("moving pid {pid}: {e}"))?;
                    }
                    Ok(())
                }
                Via::Systemd { .. } => {
                    let want = format!("/{}.scope", self.unit);
                    let deadline = Instant::now() + Duration::from_secs(5);
                    loop {
                        let cg = fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|_| "the job exited before systemd placed it".to_string())?;
                        if let Some(p) = unified_path(&cg).filter(|p| p.ends_with(&want)) {
                            let dir = Path::new(ROOT).join(p.trim_start_matches('/'));
                            if !dir.exists() {
                                return Err(format!("scope cgroup {} not visible in this cgroup namespace", dir.display()));
                            }
                            self.parent_oom_base = dir.parent().and_then(|p| fs::read_to_string(p.join("memory.events")).ok()).and_then(|t| kv(&t, "oom_kill"));
                            self.dir = Some(dir);
                            if self.want.limits && self.want.oom_group {
                                let _ = fs::write(self.dir.as_ref().unwrap().join("memory.oom.group"), "1");
                            }
                            self.read_enforced();
                            return Ok(());
                        }
                        let zombie = crate::actions::procfs::read_stat(Path::new("/proc"), pid).is_none_or(|s| s.state == 'Z');
                        if zombie || Instant::now() > deadline {
                            return Err(format!("systemd did not place the job in {}.scope", self.unit));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        }

        fn contains(&self, pid: u32) -> bool {
            self.members().contains(&pid)
        }

        /// What the kernel actually holds: limit files that are set, not what we asked for.
        fn read_enforced(&mut self) {
            let Some(d) = &self.dir else { return };
            self.cpu_enforced = self.want.limits && self.want.cpu_pct.is_some() && limit_in_force(d, "cpu.max");
            self.mem_enforced = self.want.limits && self.want.mem.is_some() && limit_in_force(d, "memory.max");
        }

        pub fn members(&self) -> Vec<u32> {
            let Some(d) = &self.dir else { return Vec::new() };
            fs::read_to_string(d.join("cgroup.procs")).unwrap_or_default().lines().filter_map(|l| l.trim().parse().ok()).collect()
        }

        fn read(&self, file: &str) -> String {
            self.dir.as_ref().and_then(|d| fs::read_to_string(d.join(file)).ok()).unwrap_or_default()
        }

        /// Refresh the cached counters (cheap: three small reads). Called every wait slice so
        /// the numbers survive a scope that vanishes with the job.
        pub fn tick(&mut self) {
            if self.dir.is_none() {
                return;
            }
            let cpu = self.read("cpu.stat");
            if let Some(n) = kv(&cpu, "nr_throttled") {
                self.nr_throttled = self.nr_throttled.max(n);
            }
            if let Some(n) = kv(&cpu, "throttled_usec") {
                self.throttled_usec = self.throttled_usec.max(n);
            }
            if let Some(n) = kv(&self.read("memory.events"), "oom_kill") {
                self.oom_total = self.oom_total.max(n);
            }
            let cur = self.read("memory.peak").trim().parse::<u64>().ok().or_else(|| self.read("memory.current").trim().parse::<u64>().ok());
            self.mem_peak = self.mem_peak.max(cur.unwrap_or(0));
        }

        /// The job ended with a SIGKILL fat didn't send and its scope is already gone: count the
        /// OOM kills its parent slice saw meanwhile (hierarchical memory.events), which is the
        /// kernel's memory.max OOM kill unless a sibling unit OOMed at the same moment.
        pub fn sigkilled(&mut self) {
            let Some(d) = self.dir.clone() else { return };
            if d.exists() || !self.mem_enforced || self.oom_total > 0 {
                return;
            }
            if let Some(base) = self.parent_oom_base
                && let Some(now) = d.parent().and_then(|p| fs::read_to_string(p.join("memory.events")).ok()).and_then(|t| kv(&t, "oom_kill"))
            {
                self.oom_total = now.saturating_sub(base).min(1);
            }
        }

        /// Replace the polled cpu with the cgroup's exact usage_usec rate; track memory peak.
        /// Returns the number of OOM kills since the last call, if any.
        pub fn sample(&mut self, u: &mut Usage) -> Option<u64> {
            self.dir.as_ref()?;
            let now = Instant::now();
            if let Some(usage) = kv(&self.read("cpu.stat"), "usage_usec") {
                if let Some((prev, t)) = self.prev {
                    let dt = now.duration_since(t).as_secs_f64();
                    if dt > 0.0 {
                        u.cpu = (usage.saturating_sub(prev) as f64 / 1e6 / dt * 100.0) as f32;
                    }
                }
                self.prev = Some((usage, now));
            }
            self.tick();
            let new = self.oom_total.saturating_sub(self.oom_seen);
            self.oom_seen = self.oom_total;
            (new > 0).then_some(new)
        }

        /// cgroup.kill (Linux 5.14+): SIGKILL every member, including any that escaped the
        /// process group and the tracker.
        pub fn kill_all(&mut self) {
            if let Some(d) = &self.dir {
                let _ = fs::write(d.join("cgroup.kill"), "1");
                self.killed = true;
            }
        }

        fn populated(&self) -> bool {
            kv(&self.read("cgroup.events"), "populated").is_some_and(|v| v != 0)
        }

        pub fn finish(&mut self) -> KernelStats {
            self.tick();
            let mut st = KernelStats {
                via: Some(match self.via {
                    Via::Root => "cgroup",
                    Via::Systemd { user: true } => "systemd --user",
                    Via::Systemd { user: false } => "systemd",
                }),
                cpu_enforced: self.cpu_enforced,
                mem_enforced: self.mem_enforced,
                throttled: self.nr_throttled,
                throttled_usec: self.throttled_usec,
                oom_kills: self.oom_total,
                mem_peak: self.mem_peak,
                dir: self.dir.clone(),
                removed: false,
            };
            st.removed = self.cleanup();
            st
        }

        /// Remove our directory once it's empty (members killed by us take a moment to exit).
        /// Systemd scopes are removed by systemd. Returns true when the directory is gone.
        fn cleanup(&mut self) -> bool {
            let Some(d) = self.dir.clone() else { return true };
            if self.via != Via::Root {
                return false;
            }
            if self.cleaned {
                return !d.exists();
            }
            self.cleaned = true;
            // Killed members take a moment to exit; a job that leaves a daemon running keeps
            // its cgroup (populated) and we leave it for that daemon.
            for _ in 0..40 {
                if fs::remove_dir(&d).is_ok() || !d.exists() {
                    return true;
                }
                if self.populated() && !self.members().is_empty() && self.killed {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                if self.populated() && !self.members().is_empty() {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            false
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            if self.via == Via::Root && !self.cleaned
                && let Some(d) = &self.dir
            {
                let _ = fs::remove_dir(d);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(parse_bytes("123").unwrap(), 123);
        assert_eq!(parse_bytes("100k").unwrap(), 102_400);
        assert_eq!(parse_bytes("512M").unwrap(), 512 << 20);
        assert_eq!(parse_bytes("2G").unwrap(), 2 << 30);
        assert_eq!(parse_bytes("1.5g").unwrap(), 3 << 29);
        assert_eq!(parse_bytes("2GB").unwrap(), 2 << 30);
        assert_eq!(parse_bytes("1GiB").unwrap(), 1 << 30);
        assert!(parse_bytes("lots").is_err());
        assert!(parse_bytes("5x").is_err());
        assert!(parse_bytes("").is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30").unwrap(), 30);
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("10m").unwrap(), 600);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert_eq!(parse_duration("1h30m").unwrap(), 5400);
        assert_eq!(parse_duration("1.5m").unwrap(), 90);
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5y").is_err());
    }

    #[test]
    fn violation_logic() {
        let b = Budget { cpu: Some(50.0), mem: Some(1000), time: Some(5), procs: Some(2), on_violation: "warn".into() };
        let mut strikes = 0;
        let hot = Usage { cpu: 99.0, mem: 10, procs: 1, stopped: false };
        assert!(violations(&b, &hot, Duration::from_secs(1), &mut strikes).is_empty());
        let v = violations(&b, &hot, Duration::from_secs(1), &mut strikes);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, Kind::Cpu);
        let big = Usage { cpu: 0.0, mem: 5000, procs: 3, stopped: false };
        let kinds: Vec<Kind> = violations(&b, &big, Duration::from_secs(6), &mut strikes).into_iter().map(|x| x.0).collect();
        assert_eq!(kinds, vec![Kind::Mem, Kind::Time, Kind::Procs]);
        assert_eq!(strikes, 0);
    }

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exit_codes() {
        let b = Budget::default();
        assert_eq!(run(&sv(&["true"]), &b).unwrap(), 0);
        assert_eq!(run(&sv(&["sh", "-c", "exit 7"]), &b).unwrap(), 7);
        assert_eq!(run(&sv(&["sh", "-c", "kill -TERM $$"]), &b).unwrap(), 128 + libc::SIGTERM);
        assert!(run(&sv(&["/nonexistent/definitely-not-here"]), &b).is_err());
    }

    #[test]
    fn cpu_budget_kills() {
        let b = Budget { cpu: Some(50.0), on_violation: "kill".into(), ..Default::default() };
        let t = Instant::now();
        let code = supervise(&sv(&["sh", "-c", "yes > /dev/null"]), &b, Mode::Poll).unwrap().code;
        assert_ne!(code, 0);
        assert!(t.elapsed() < Duration::from_secs(10), "took {:?}", t.elapsed());
    }

    #[test]
    fn time_budget_kills() {
        let b = Budget { time: Some(1), on_violation: "kill".into(), ..Default::default() };
        let t = Instant::now();
        let code = supervise(&sv(&["sleep", "30"]), &b, Mode::Poll).unwrap().code;
        assert_eq!(code, 128 + libc::SIGTERM);
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    fn have_perl() -> bool {
        Command::new("perl").arg("-e1").status().map(|s| s.success()).unwrap_or(false)
    }

    /// perl-base (minimal Debian/Ubuntu) lacks Time::HiRes.
    fn have_perl_hires() -> bool {
        Command::new("perl").args(["-MTime::HiRes", "-e1"]).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
    }

    #[test]
    fn cpu_meter_counts_reaped_children_once() {
        let mut m = CpuMeter::default();
        let ms = 1_000_000u64;
        // root (pid 10) and a child (pid 11) alive.
        m.consumed(HashMap::from([((10, 1), (0, 0, 1)), ((11, 2), (0, 0, 10))]));
        // child used 300ms; a short-lived child (never seen) used 200ms and was reaped by root.
        let d = m.consumed(HashMap::from([((10, 1), (10 * ms, 200 * ms, 1)), ((11, 2), (300 * ms, 0, 10))]));
        assert_eq!(d, 510 * ms);
        // child 11 exits after another 100ms; root reaps it: child time grows by 400ms total,
        // of which 300ms was already counted while it was alive.
        let d = m.consumed(HashMap::from([((10, 1), (10 * ms, 600 * ms, 1))]));
        assert_eq!(d, 100 * ms, "only the unseen tail of the reaped child counts");
    }

    #[test]
    fn cpu_budget_sees_short_lived_children() {
        if !have_perl_hires() {
            return;
        }
        // Sequential ~0.4s busy children: each lives about one poll, so per-process sampling
        // used to read them as 0% CPU.
        let script = "for i in 1 2 3 4 5 6 7 8; do perl -MTime::HiRes=time -e '$t=time; 1 while time-$t<0.4'; done";
        let b = Budget { cpu: Some(50.0), on_violation: "warn".into(), ..Default::default() };
        let r = supervise(&sv(&["sh", "-c", script]), &b, Mode::Poll).unwrap();
        assert_eq!(r.code, 0);
        assert!(r.fired.contains(&Kind::Cpu), "short-lived children escaped the cpu budget: {r:?}");
        assert!(r.peak.cpu > 60.0, "{r:?}");
    }

    #[test]
    fn kill_reaches_descendants_that_left_the_group() {
        let dir = std::env::temp_dir().join(format!("fat-budget-escape-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let pidfile = dir.join("yes.pid");
        let _ = std::fs::remove_file(&pidfile);
        // `set -m` puts the background job in its own process group; `kill -pgid` misses it.
        let script = format!("set -m; yes > /dev/null & echo $! > {}; sleep 30", pidfile.display());
        let b = Budget { cpu: Some(50.0), on_violation: "kill".into(), ..Default::default() };
        let t = Instant::now();
        let r = supervise(&sv(&["sh", "-c", &script]), &b, Mode::Poll).unwrap();
        assert!(t.elapsed() < Duration::from_secs(15));
        assert!(r.fired.contains(&Kind::Cpu), "{r:?}");
        let esc: u32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let mut gone = false;
        for _ in 0..40 {
            if crate::actions::live_proc(esc).is_none() {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !gone {
            // Clean up the process our own test spawned before failing.
            unsafe { libc::kill(esc as libc::pid_t, libc::SIGKILL) };
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(gone, "escaped `yes` (pid {esc}) survived the kill");
    }

    #[test]
    fn mem_budget_kills() {
        if !have_perl() {
            return;
        }
        let b = Budget { mem: Some(parse_bytes("50M").unwrap()), on_violation: "kill".into(), ..Default::default() };
        let t = Instant::now();
        // ~200MB string held, then sleep.
        let code = supervise(&sv(&["perl", "-e", "$x = 'a' x (200*1024*1024); sleep 30"]), &b, Mode::Poll).unwrap().code;
        assert_ne!(code, 0);
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    // ---- Linux: procfs sampling and cgroup v2 enforcement

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_table_reads_procfs() {
        use crate::actions::procfs;
        let root = std::env::temp_dir().join(format!("fat-budget-procfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("stat"), "cpu  1 2 3 4\nbtime 1762650000\n").unwrap();
        let tck = procfs::clk_tck();
        let w = |pid: u32, line: String| {
            std::fs::create_dir_all(root.join(pid.to_string())).unwrap();
            std::fs::write(root.join(pid.to_string()).join("stat"), line).unwrap();
        };
        // sh (pid 50) that has reaped children worth 120+30 ticks; one live child; one zombie.
        w(50, format!("50 (sh) S 1 50 50 0 -1 4194304 1 0 0 0 4 1 120 30 20 0 1 0 {} 2000000 300 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n", 10 * tck));
        w(51, format!("51 (perl) R 50 50 50 0 -1 4194304 1 0 0 0 40 2 0 0 20 0 1 0 {} 9000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n", 11 * tck));
        w(52, format!("52 (perl) Z 50 50 50 0 -1 4227084 0 0 0 0 7 0 0 0 20 0 1 0 {} 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n", 11 * tck));
        std::fs::create_dir_all(root.join("self")).unwrap(); // non-numeric entries are skipped
        let t = table_at(&root);
        assert_eq!(t.len(), 3);
        let sh = t[&50];
        assert_eq!(sh.ppid, Some(1));
        assert_eq!(sh.start, 1_762_650_010);
        assert_eq!(sh.ctr, Some((procfs::ticks_to_ns(5), procfs::ticks_to_ns(150))));
        assert_eq!(sh.mem, 300 * procfs::page_size());
        assert!(t[&52].zombie && !t[&51].zombie);
        // The tracker sees sh + perl (zombie excluded) and their cpu.
        let mut tr = Tracker::new(50, 50);
        let u = tr.sample(&t, &[]);
        assert_eq!(u.procs, 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_table_of_live_proc_is_fast_and_sane() {
        let mut s = Sampler::new();
        let t0 = Instant::now();
        let t = s.table();
        let took = t0.elapsed();
        eprintln!("procfs table: {} procs in {took:?}", t.len());
        let me = t.get(&std::process::id()).expect("our own row");
        assert!(me.mem > 0 && me.ctr.is_some(), "{me:?}");
        assert_eq!(me.start, crate::actions::live_proc(std::process::id()).unwrap().start_time);
        assert!(took < Duration::from_millis(500), "{took:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_file_formats() {
        assert_eq!(cgroup::cpu_max(200.0), "200000 100000");
        assert_eq!(cgroup::cpu_max(150.0), "150000 100000");
        assert_eq!(cgroup::cpu_max(0.2), "1000 100000", "kernel minimum quota is 1ms");
        // cpu.stat from a throttled job (Linux 6.8).
        let cpu = "usage_usec 1527370\nuser_usec 1203981\nsystem_usec 323389\ncore_sched.force_idle_usec 0\nnr_periods 31\nnr_throttled 25\nthrottled_usec 2041893\nnr_bursts 0\nburst_usec 0\n";
        assert_eq!(cgroup::kv(cpu, "usage_usec"), Some(1_527_370));
        assert_eq!(cgroup::kv(cpu, "nr_throttled"), Some(25));
        assert_eq!(cgroup::kv(cpu, "throttled_usec"), Some(2_041_893));
        assert_eq!(cgroup::kv(cpu, "nope"), None);
        let ev = "low 0\nhigh 0\nmax 1543\noom 3\noom_kill 3\noom_group_kill 0\n";
        assert_eq!(cgroup::kv(ev, "oom_kill"), Some(3));
        assert_eq!(cgroup::kv(ev, "oom"), Some(3));
        assert_eq!(cgroup::kv("populated 1\nfrozen 0\n", "populated"), Some(1));
        let pc = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/fat-run-77-0.scope\n";
        assert_eq!(cgroup::unified_path(pc), Some("/user.slice/user-1000.slice/user@1000.service/app.slice/fat-run-77-0.scope"));
        // A hybrid (v1 + v2) host lists v1 hierarchies first.
        assert_eq!(cgroup::unified_path("12:pids:/user.slice\n1:name=systemd:/x\n0::/x.scope\n"), Some("/x.scope"));
        assert_eq!(cgroup::unified_path("4:memory:/docker/abc\n"), None);
    }

    /// Run under a forced cgroup; None (test skipped) where cgroups can't be delegated to us.
    #[cfg(target_os = "linux")]
    fn cgroup_run(cmd: &[&str], b: &Budget) -> Option<Report> {
        match supervise(&sv(cmd), b, Mode::Cgroup) {
            Ok(r) => Some(r),
            Err(e) if e.to_string().contains("cgroup v2 enforcement unavailable") => {
                eprintln!("skipping: {e}");
                None
            }
            Err(e) => panic!("{e:#}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_throttles_cpu_instead_of_violating() {
        let b = Budget { cpu: Some(50.0), time: Some(2), on_violation: "kill".into(), ..Default::default() };
        let t = Instant::now();
        let Some(r) = cgroup_run(&["sh", "-c", "yes > /dev/null"], &b) else { return };
        assert!(t.elapsed() < Duration::from_secs(10));
        assert!(r.kernel.via.is_some(), "{r:?}");
        if !r.kernel.cpu_enforced {
            eprintln!("skipping: cpu controller not delegated ({r:?})");
            return;
        }
        assert_eq!(r.fired, vec![Kind::Time], "cpu is throttled, never a violation: {r:?}");
        assert_eq!(r.code, 128 + libc::SIGTERM);
        assert!(r.kernel.throttled > 0, "{r:?}");
        assert!(r.peak.cpu < 80.0, "kernel quota is 50%: {r:?}");
        if r.kernel.via == Some("cgroup") {
            assert!(r.kernel.removed, "cgroup dir must be removed: {r:?}");
            assert!(!r.kernel.dir.as_ref().unwrap().exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_memory_max_oom_kills() {
        if !have_perl() {
            return;
        }
        let b = Budget { mem: Some(parse_bytes("64M").unwrap()), time: Some(20), on_violation: "kill".into(), ..Default::default() };
        let t = Instant::now();
        let Some(r) = cgroup_run(&["perl", "-e", "$x = 'a' x (400*1024*1024); sleep 30"], &b) else { return };
        if !r.kernel.mem_enforced {
            eprintln!("skipping: memory controller not delegated ({r:?})");
            return;
        }
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        assert_eq!(r.code, 128 + libc::SIGKILL, "{r:?}");
        assert!(r.kernel.oom_kills >= 1, "{r:?}");
        assert!(r.fired.contains(&Kind::Mem), "{r:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_warn_measures_without_limits() {
        // warn = accounting only: the cgroup measures exact cpu, nothing is throttled.
        let b = Budget { cpu: Some(30.0), time: Some(2), on_violation: "warn".into(), ..Default::default() };
        let Some(r) = cgroup_run(&["sh", "-c", "yes > /dev/null & sleep 1.6; kill $!"], &b) else { return };
        assert!(!r.kernel.cpu_enforced && r.kernel.throttled == 0, "{r:?}");
        assert!(r.fired.contains(&Kind::Cpu), "{r:?}");
        assert!(r.peak.cpu > 60.0, "{r:?}");
        assert_eq!(r.code, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_kill_reaches_escaped_daemons() {
        // A double-forked, setsid'd child leaves both the process group and the ppid chain;
        // it's still in the cgroup, so a time-budget kill (cgroup.kill) takes it too.
        let dir = std::env::temp_dir().join(format!("fat-budget-cg-escape-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let pidfile = dir.join("daemon.pid");
        let _ = std::fs::remove_file(&pidfile);
        let script = format!("setsid sh -c 'sleep 300 & echo $! > {}' ; sleep 300", pidfile.display());
        let b = Budget { cpu: Some(400.0), time: Some(1), on_violation: "kill".into(), ..Default::default() };
        let Some(r) = cgroup_run(&["sh", "-c", &script], &b) else { return };
        assert!(r.fired.contains(&Kind::Time), "{r:?}");
        let esc: u32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let mut gone = false;
        for _ in 0..40 {
            if crate::actions::live_proc(esc).is_none() {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !gone {
            unsafe { libc::kill(esc as libc::pid_t, libc::SIGKILL) }; // our own test's sleep
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(gone, "daemonized sleep (pid {esc}) survived");
    }
}
