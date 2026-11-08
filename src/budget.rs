//! `fat run --cpu 200 --mem 2G --time 10m -- cmd`: supervise a process tree under a budget. OWNER: actions agent.
use crate::model::Budget;
use anyhow::{anyhow, bail, Context};
use std::collections::{HashMap, HashSet};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System};

const POLL: Duration = Duration::from_millis(500);
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

extern "C" fn forward_signal(sig: libc::c_int) {
    let pg = CHILD_PGID.load(Ordering::SeqCst);
    if pg > 1 {
        // SAFETY: kill(2) is async-signal-safe; negative pid targets only our child's group.
        unsafe {
            libc::kill(-pg, sig);
        }
    }
}

fn signal_group(pgid: i32, sig: i32) {
    if pgid > 1 {
        // SAFETY: pgid is the group of a child we spawned with process_group(0).
        unsafe {
            libc::kill(-pgid, sig);
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct Usage {
    cpu: f32,
    mem: u64,
    procs: usize,
    stopped: bool,
}

/// Sum usage over `root` and all its descendants via ppid traversal.
fn tree_usage(sys: &System, root: u32) -> Usage {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, p) in sys.processes() {
        if let Some(pp) = p.parent() {
            children.entry(pp.as_u32()).or_default().push(pid.as_u32());
        }
    }
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    let mut u = Usage::default();
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) {
            continue;
        }
        let Some(p) = sys.process(Pid::from_u32(pid)) else { continue };
        if p.status() == ProcessStatus::Zombie {
            continue;
        }
        if pid == root {
            u.stopped = p.status() == ProcessStatus::Stop;
        }
        u.cpu += p.cpu_usage();
        u.mem += p.memory();
        u.procs += 1;
        if let Some(c) = children.get(&pid) {
            stack.extend(c);
        }
    }
    u
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

/// Run cmd, enforce budget on its whole tree, print violations to stderr. Returns child's exit code.
pub fn run(cmd: &[String], budget: &Budget) -> anyhow::Result<i32> {
    let (prog, args) = cmd.split_first().ok_or_else(|| anyhow!("no command given"))?;
    let mode = match budget.on_violation.trim().to_ascii_lowercase().as_str() {
        "" | "warn" => "warn",
        "pause" | "stop" => "pause",
        "kill" | "term" => "kill",
        other => bail!("unknown --on-violation {other:?} (use pause, kill or warn)"),
    };

    let start = Instant::now();
    let mut child = Command::new(prog)
        .args(args)
        .process_group(0)
        .spawn()
        .with_context(|| format!("failed to start {prog:?}"))?;
    let pid = child.id();
    let pgid = pid as i32;
    CHILD_PGID.store(pgid, Ordering::SeqCst);

    // Forward Ctrl-C / TERM to the child's group (it is not in the terminal's foreground group).
    // SAFETY: installing a handler that only calls the async-signal-safe kill(2).
    let (old_int, old_term) = unsafe {
        let h = forward_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        (libc::signal(libc::SIGINT, h), libc::signal(libc::SIGTERM, h))
    };

    let refresh = ProcessRefreshKind::nothing().with_cpu().with_memory();
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);

    let mut peak = Usage::default();
    let mut fired: Vec<Kind> = Vec::new();
    let mut cpu_strikes = 0u32;
    let mut kill_deadline: Option<Instant> = None;
    let mut killed_hard = false;

    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        std::thread::sleep(POLL);
        if let Some(st) = child.try_wait()? {
            break st;
        }
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
        let u = tree_usage(&sys, pid);
        peak.cpu = peak.cpu.max(u.cpu);
        peak.mem = peak.mem.max(u.mem);
        peak.procs = peak.procs.max(u.procs);

        if let Some(dl) = kill_deadline {
            if !killed_hard && Instant::now() >= dl {
                eprintln!("fat run: still alive after {}s, sending SIGKILL to group {pgid}", KILL_GRACE.as_secs());
                signal_group(pgid, libc::SIGKILL);
                killed_hard = true;
            }
            continue;
        }

        for (kind, why) in violations(budget, &u, start.elapsed(), &mut cpu_strikes) {
            let first = !fired.contains(&kind);
            // A wall-clock budget is a deadline: pausing would only hold the job forever,
            // so `--time` always stops the job unless the policy is warn-only.
            let mode = if kind == Kind::Time && mode == "pause" { "kill" } else { mode };
            match mode {
                "warn" => {
                    if first {
                        eprintln!("fat run: budget exceeded: {why} (warn only)");
                    }
                }
                "pause" => {
                    // Resource budgets re-pause if the user resumes and it recurs.
                    if u.stopped {
                        continue;
                    }
                    signal_group(pgid, libc::SIGSTOP);
                    eprintln!(
                        "fat run: budget exceeded: {why}; paused process group {pgid}. Resume with `kill -CONT -{pgid}` (or `fat resume {pid}` for the leader), or stop it with `kill -TERM -{pgid}`"
                    );
                    reset_cpu_baseline(&mut sys);
                }
                _ => {
                    eprintln!("fat run: budget exceeded: {why}; sending SIGTERM to group {pgid}");
                    signal_group(pgid, libc::SIGTERM);
                    // A stopped group can't handle TERM until continued.
                    signal_group(pgid, libc::SIGCONT);
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
    if kill_deadline.is_some() {
        // Leader is gone; make sure stragglers in the group go too.
        signal_group(pgid, libc::SIGKILL);
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
    Ok(code)
}

/// After pausing, CPU readings for the next sample are stale; a refresh resets the baseline.
fn reset_cpu_baseline(sys: &mut System) {
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_cpu());
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
