//! `fat run --cpu 200 --mem 2G --time 10m -- cmd`: supervise a process tree under a budget. OWNER: actions agent.
//!
//! The job runs in its own process group, which is handed the terminal while it runs (so
//! interactive commands work) and taken back while a budget pause is in force (so Ctrl-C
//! reaches fat, which then interrupts *and* continues the frozen job). CPU is measured
//! from kernel cpu-time counters, including children that came and went between polls,
//! and enforcement reaches descendants that left the process group.
use crate::model::Budget;
use anyhow::{anyhow, bail, Context};
use std::collections::{HashMap, HashSet};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System};

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

    fn sample(&mut self, sys: &System) -> Usage {
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for (pid, p) in sys.processes() {
            if let Some(pp) = p.parent() {
                children.entry(pp.as_u32()).or_default().push(pid.as_u32());
            }
        }
        let alive = |pid: u32| sys.process(Pid::from_u32(pid)).filter(|p| p.status() != ProcessStatus::Zombie);

        let mut next: HashMap<u32, Member> = HashMap::new();
        // Previously known members that still exist as the same incarnation.
        for (&pid, m) in &self.members {
            if let Some(p) = alive(pid)
                && p.start_time().abs_diff(m.start) <= 1
            {
                next.insert(pid, Member { start: p.start_time(), ppid: p.parent().map(|x| x.as_u32()).unwrap_or(0) });
            }
        }
        let mut stack: Vec<u32> = vec![self.root];
        stack.extend(next.keys().copied());
        let mut seen = HashSet::new();
        while let Some(pid) = stack.pop() {
            if !seen.insert(pid) {
                continue;
            }
            let Some(p) = alive(pid) else { continue };
            next.entry(pid)
                .or_insert(Member { start: p.start_time(), ppid: p.parent().map(|x| x.as_u32()).unwrap_or(0) });
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
            let Some(p) = sys.process(Pid::from_u32(pid)) else { continue };
            u.mem += p.memory();
            u.stopped &= p.status() == ProcessStatus::Stop;
            match crate::collect::procs::counters(pid) {
                Some(c) => {
                    counters.insert((pid, m.start), (c.cpu_ns, c.child_cpu_ns, m.ppid));
                }
                None => fallback_cpu += p.cpu_usage(),
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
}

/// Run cmd, enforce budget on its whole tree, print violations to stderr. Returns child's exit code.
pub fn run(cmd: &[String], budget: &Budget) -> anyhow::Result<i32> {
    supervise(cmd, budget).map(|r| r.code)
}

fn supervise(cmd: &[String], budget: &Budget) -> anyhow::Result<Report> {
    let (prog, args) = cmd.split_first().ok_or_else(|| anyhow!("no command given"))?;
    let mode = match budget.on_violation.trim().to_ascii_lowercase().as_str() {
        "" | "warn" => "warn",
        "pause" | "stop" => "pause",
        "kill" | "term" => "kill",
        other => bail!("unknown --on-violation {other:?} (use pause, kill or warn)"),
    };

    let start = Instant::now();
    let child = Command::new(prog)
        .args(args)
        .process_group(0)
        .spawn()
        .with_context(|| format!("failed to start {prog:?}"))?;
    let pid = child.id();
    // We reap the child ourselves with waitpid(WUNTRACED) to see job-control stops.
    drop(child);
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

    let refresh = ProcessRefreshKind::nothing().with_cpu().with_memory();
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
    let mut tracker = Tracker::new(pid, pgid);
    tracker.sample(&sys);

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
            Wait::Exited(st) => break st,
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

        std::thread::sleep(WAIT_SLICE);
        if Instant::now() < next_sample {
            continue;
        }
        next_sample = Instant::now() + POLL;
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
        let u = tracker.sample(&sys);
        peak.cpu = peak.cpu.max(u.cpu);
        peak.mem = peak.mem.max(u.mem);
        peak.procs = peak.procs.max(u.procs);

        if let Some(dl) = kill_deadline {
            if !killed_hard && Instant::now() >= dl {
                eprintln!("fat run: still alive after {}s, sending SIGKILL to group {pgid}", KILL_GRACE.as_secs());
                tracker.signal(libc::SIGKILL);
                killed_hard = true;
            }
            continue;
        }

        for (kind, why) in violations(budget, &u, start.elapsed(), &mut cpu_strikes) {
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
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
        tracker.sample(&sys);
        tracker.signal(libc::SIGKILL);
    }

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
        "fat run: exit {code} | wall {} | peak cpu {:.0}% | peak mem {} | peak procs {} | violations: {vio}",
        fmt_secs(start.elapsed()),
        peak.cpu,
        fmt_bytes(peak.mem),
        peak.procs
    );
    Ok(Report { code, fired, peak })
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
        let code = run(&sv(&["sh", "-c", "yes > /dev/null"]), &b).unwrap();
        assert_ne!(code, 0);
        assert!(t.elapsed() < Duration::from_secs(10), "took {:?}", t.elapsed());
    }

    #[test]
    fn time_budget_kills() {
        let b = Budget { time: Some(1), on_violation: "kill".into(), ..Default::default() };
        let t = Instant::now();
        let code = run(&sv(&["sleep", "30"]), &b).unwrap();
        assert_eq!(code, 128 + libc::SIGTERM);
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    fn have_perl() -> bool {
        Command::new("perl").arg("-e1").status().map(|s| s.success()).unwrap_or(false)
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
        if !have_perl() {
            return;
        }
        // Sequential ~0.4s busy children: each lives about one poll, so per-process sampling
        // used to read them as 0% CPU.
        let script = "for i in 1 2 3 4 5 6 7 8; do perl -MTime::HiRes=time -e '$t=time; 1 while time-$t<0.4'; done";
        let b = Budget { cpu: Some(50.0), on_violation: "warn".into(), ..Default::default() };
        let r = supervise(&sv(&["sh", "-c", script]), &b).unwrap();
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
        let r = supervise(&sv(&["sh", "-c", &script]), &b).unwrap();
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
        let have_perl = Command::new("perl").arg("-e1").status().map(|s| s.success()).unwrap_or(false);
        if !have_perl {
            return;
        }
        let b = Budget { mem: Some(parse_bytes("50M").unwrap()), on_violation: "kill".into(), ..Default::default() };
        let t = Instant::now();
        // ~200MB string held, then sleep.
        let code = run(&sv(&["perl", "-e", "$x = 'a' x (200*1024*1024); sleep 30"]), &b).unwrap();
        assert_ne!(code, 0);
        assert!(t.elapsed() < Duration::from_secs(10));
    }
}
