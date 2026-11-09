//! fat — Fucking Awesome Top. A process monitor for humans and agents.
//! OWNER: integration (lead). Subcommands are thin wrappers over modules.

mod actions;
mod ask;
mod blame;
mod budget;
mod collect;
mod config;
mod fleet;
mod fs;
mod history;
mod mcp;
mod model;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use model::{ActionKind, Budget, Snapshot};

#[derive(Parser)]
#[command(name = "fat", version, about = "Fucking Awesome Top — what is my machine doing, why, and for whom?")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// One snapshot of this machine (procs, ports, system).
    Snapshot {
        #[arg(long)]
        json: bool,
        /// Max processes to print in text mode.
        #[arg(long, default_value_t = 25)]
        top: usize,
    },
    /// What's listening, who owns it, is it orphaned.
    Ports {
        #[arg(long)]
        json: bool,
    },
    /// Blame chain for a pid: why is it running and what is it costing.
    Why {
        pid: u32,
        #[arg(long)]
        json: bool,
    },
    /// Diagnose the whole machine.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Ask in plain language ("why is this machine slow?").
    Ask { question: Vec<String> },
    /// Run the always-on flight recorder (foreground).
    Record,
    /// Query the recorder: timeline, spikes, or a past snapshot.
    History {
        /// How far back, e.g. 10m, 2h, 1d.
        #[arg(long, default_value = "1h")]
        since: String,
        /// Show the snapshot nearest to N ago (e.g. 5m) instead of a timeline.
        #[arg(long)]
        at: Option<String>,
        #[arg(long)]
        spikes: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run a command under a resource budget.
    ///
    /// On Linux, --cpu and --mem are enforced by the kernel through a cgroup v2 when one can be
    /// had (root, or a systemd user scope); otherwise, and on macOS, by polling every 500ms.
    /// FAT_BUDGET_MODE=auto|cgroup|poll overrides the choice.
    Run {
        /// Max CPU percent across the tree (100 = 1 core).
        #[arg(long)]
        cpu: Option<f32>,
        /// Max memory, e.g. 2G, 512M.
        #[arg(long)]
        mem: Option<String>,
        /// Max wall time, e.g. 10m.
        #[arg(long)]
        time: Option<String>,
        /// Max processes in tree.
        #[arg(long)]
        procs: Option<usize>,
        /// pause | kill | warn. A --time overrun always stops the job (unless warn).
        #[arg(long, default_value = "pause")]
        on_violation: String,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Pause a process (SIGSTOP). Undoable.
    Pause { pid: u32 },
    /// Resume a paused process (SIGCONT).
    Resume { pid: u32 },
    /// Change priority. Undoable.
    Renice { pid: u32, nice: i32 },
    /// Terminate (TERM). With --tree, the whole subtree. --force sends KILL.
    Kill {
        pid: u32,
        #[arg(long)]
        tree: bool,
        #[arg(long)]
        force: bool,
    },
    /// Undo the last undoable action (or a specific id).
    Undo { id: Option<u64> },
    /// Show the action journal.
    Log {
        #[arg(long)]
        json: bool,
    },
    /// Containers and remote hosts.
    Fleet {
        #[arg(long)]
        json: bool,
    },
    /// Disk usage: what eats storage, and what is filling it right now. Read-only.
    ///
    /// `fat fs [PATH]` lists the children of PATH (default "/") by size from the cached
    /// background scan, scanning if needed. `--growth` answers "what grew in the last 10
    /// minutes", `--volumes` lists filesystems, `--largest N` the N biggest entries below PATH.
    Fs(FsArgs),
    /// Serve the MCP protocol on stdio (for agents).
    Mcp,
}

/// Two samples 600ms apart (rates need an interval). Containers, when wanted and enabled,
/// are fetched concurrently because `docker stats` alone can take ~2s.
fn sample_with(containers: bool) -> Snapshot {
    let want = containers && config::Config::load().containers;
    let fetch = want.then(|| std::thread::spawn(fleet::containers));
    let mut c = collect::Collector::new();
    let _ = c.sample();
    std::thread::sleep(std::time::Duration::from_millis(600));
    let mut s = c.sample();
    if let Some(h) = fetch {
        s.containers = h.join().unwrap_or_default();
    }
    s
}

fn sample() -> Snapshot {
    sample_with(false)
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn fmt_bytes(b: u64) -> String {
    let f = b as f64;
    match b {
        0..=1023 => format!("{b}B"),
        1024..=1_048_575 => format!("{:.1}K", f / 1024.0),
        1_048_576..=1_073_741_823 => format!("{:.1}M", f / 1_048_576.0),
        _ => format!("{:.2}G", f / 1_073_741_824.0),
    }
}

fn print_action(r: &model::ActionRecord) {
    let mark = if r.ok { "ok" } else { "FAILED" };
    println!("[{}] #{} {:?} {} ({}) — {}", mark, r.id, r.kind, r.pid, r.name, r.message);
    if r.undoable && r.ok && !r.undone && r.id != 0 {
        println!("    undo with: fat undo {}", r.id);
    }
}

fn ago_ms(s: &str) -> Result<i64> {
    Ok(budget::parse_duration(s)? as i64 * 1000)
}

#[derive(clap::Args, Debug, PartialEq)]
struct FsArgs {
    /// Directory to inspect (absolute or relative). Default "/". With --growth: only growth below it.
    path: Option<String>,
    /// Levels of subdirectories to print.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=6))]
    depth: u8,
    /// Wait up to this long (e.g. 30, 2m) for the scan of PATH to complete.
    #[arg(long)]
    wait: Option<String>,
    /// Max entries per directory.
    #[arg(long, default_value_t = 25)]
    top: usize,
    /// What grew recently (paths, writers, deleted-but-open files) instead of sizes.
    #[arg(long, conflicts_with_all = ["volumes", "largest"])]
    growth: bool,
    /// Growth window, e.g. 10m, 1h, 24h.
    #[arg(long, default_value = "10m", requires = "growth")]
    since: String,
    /// Only growth below this directory.
    #[arg(long, requires = "growth")]
    under: Option<String>,
    /// Mounted volumes: capacity, fill rate, ETA to full, I/O.
    #[arg(long, conflicts_with = "largest")]
    volumes: bool,
    /// The N largest files/directories below PATH.
    #[arg(long, value_name = "N")]
    largest: Option<usize>,
    #[arg(long)]
    json: bool,
}

/// Absolute, slash-trimmed form of a user-supplied path (lexical: no symlink resolution).
fn abs_path(p: Option<&str>) -> String {
    let p = p.map(str::trim).filter(|p| !p.is_empty()).unwrap_or("/");
    let expanded = match p.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => dirs::home_dir().map(|h| format!("{}{rest}", h.display())).unwrap_or_else(|| p.to_string()),
        _ => p.to_string(),
    };
    let abs = std::path::absolute(&expanded).map(|a| a.display().to_string()).unwrap_or(expanded);
    let mut parts: Vec<&str> = Vec::new();
    for c in abs.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

fn hb(b: u64) -> String {
    tui::widgets::fmt_bytes(b)
}

/// Aligned table of a listing's children (recursing through `list` up to `depth`).
fn fmt_listing(l: &fs::Listing, depth: u8, top: usize, now: model::Ts, list: &mut dyn FnMut(&str) -> Option<fs::Listing>) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let p = &l.progress;
    let mut status = Vec::new();
    status.push(format!("{} files", l.dir.files));
    if l.dir.partial {
        let pct = p.fraction.filter(|_| p.running).map(|f| format!(" {:.0}%", f * 100.0)).unwrap_or_default();
        status.push(format!("still scanning{pct}: sizes are lower bounds"));
    } else if p.running {
        // A finished tree being re-checked for changes: the numbers are complete.
        status.push("re-checking in the background".to_string());
    }
    let at = if l.dir.scanned_at > 0 { l.dir.scanned_at } else { p.completed_at };
    if at > 0 {
        status.push(format!("as of {}", tui::widgets::fmt_ago((now - at) / 1000)));
    }
    let _ = writeln!(out, "{}  {}  ({})", l.dir.path, hb(l.dir.size), status.join(" · "));
    if let Some(k) = blame::explain_path(&l.dir.path) {
        let _ = writeln!(out, "  💡 {k}");
    }
    let _ = writeln!(out, "{:>8} {:>4}  {:<12} {:>7} {:>8}  NAME", "SIZE", "%", "", "FILES", "NEWEST");
    let mut notes = Vec::new();
    fmt_children(&mut out, l, depth, top, 0, now, list, &mut notes);
    if l.children.iter().any(|c| c.denied > 0) || l.dir.denied > 0 {
        let _ = writeln!(out, "{}", locked_legend());
    }
    for (name, k) in notes {
        let _ = writeln!(out, "  💡 {name}: {k}");
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn fmt_children(
    out: &mut String,
    l: &fs::Listing,
    depth: u8,
    top: usize,
    level: usize,
    now: model::Ts,
    list: &mut dyn FnMut(&str) -> Option<fs::Listing>,
    notes: &mut Vec<(String, String)>,
) {
    use std::fmt::Write;
    let parent = l.dir.size.max(1);
    let indent = "  ".repeat(level);
    for c in l.children.iter().take(top) {
        let ratio = c.size as f64 / parent as f64;
        let mut name = format!("{indent}{}{}", c.name, if c.is_dir { "/" } else { "" });
        if c.mount_point {
            let alias = c.path.strip_prefix("/System/Volumes/Data").filter(|r| cfg!(target_os = "macos") && fs::volumes::firmlinks().iter().any(|f| f == r));
            match alias.map(|r| r.trim_start_matches('/')) {
                // macOS firmlink: the same directory as /<name>, counted there.
                Some(r) => name.push_str(&format!("  ↪ = /{r} (firmlink, counted there)")),
                None => name.push_str("  ⛁ mount (not counted)"),
            }
        } else if c.denied > 0 {
            name.push_str(" 🔒");
        }
        if c.partial {
            name.push_str(" …");
        }
        let size = if c.mount_point && c.size == 0 {
            "-".to_string()
        } else if c.denied > 0 && c.size == 0 {
            "?".to_string()
        } else {
            hb(c.size)
        };
        let _ = writeln!(
            out,
            "{size:>8} {:>3.0}%  {:<12} {:>7} {:>8}  {name}",
            ratio * 100.0,
            tui::widgets::bar(ratio, 12),
            c.files,
            tui::widgets::fmt_mtime_age(c.newest_mtime, now),
        );
        if let Some(k) = blame::explain_path(&c.path).filter(|k| !k.starts_with("inside ")) {
            notes.push((c.name.clone(), k));
        }
        if depth > 1 && c.is_dir && !c.mount_point && c.size > 0
            && let Some(sub) = list(&c.path)
        {
            fmt_children(out, &sub, depth - 1, top, level + 1, now, list, notes);
        }
    }
    if l.children.len() > top {
        let rest = &l.children[top..];
        let _ = writeln!(out, "{:>8} {:>4}  {:<12} {:>7} {:>8}  {indent}… {} more", hb(rest.iter().map(|c| c.size).sum()), "", "", "", "", rest.len());
    }
    let (files, bytes) = mcp::unlisted(l);
    if !l.dir.partial && files > 0 && bytes > 0 {
        // Loose files the index does not keep by name: so the rows add up to the directory.
        let ratio = bytes as f64 / parent as f64;
        let _ = writeln!(
            out,
            "{:>8} {:>3.0}%  {:<12} {:>7} {:>8}  {indent}({} other file{} not listed by name)",
            hb(bytes),
            ratio * 100.0,
            tui::widgets::bar(ratio, 12),
            files,
            "",
            files,
            if files == 1 { "" } else { "s" },
        );
    }
}

/// What 🔒 means, and what to do about it, on this OS.
fn locked_legend() -> &'static str {
    if cfg!(target_os = "macos") {
        "🔒 = not read (macOS privacy or permissions): not counted. Pass the dir itself (`fat fs DIR`) to read it, or grant your terminal Full Disk Access."
    } else {
        "🔒 = could not be read (permission denied): not counted. Run fat as the directory's owner, or as root."
    }
}

fn fmt_growth(g: &fs::Growth, window_ms: i64, now: model::Ts) -> String {
    use std::fmt::Write;
    use tui::widgets::{evidence_tags, fmt_delta, fmt_window};
    let mut out = String::new();
    let _ = writeln!(out, "What grew in the last {}:", fmt_window(window_ms));
    for (m, d) in &g.volumes {
        let _ = writeln!(out, "  volume {m}: {}", fmt_delta(*d));
    }
    if g.growers.is_empty() {
        let _ = writeln!(out, "  nothing grew noticeably");
    } else {
        let _ = writeln!(out, "{:>9} {:>8} {:>9}  {:<24} PATH", "Δ", "SIZE", "WRITE/s", "EVIDENCE");
        for x in g.growers.iter().filter(|x| x.delta != 0 || !x.writers.is_empty()) {
            let rate: u64 = x.writers.iter().map(|w| w.2).sum();
            let mut who = String::new();
            if let Some((pid, name, _)) = x.writers.iter().max_by_key(|w| w.2) {
                who = format!("  ← {name} ({pid})");
                if x.writers.len() > 1 {
                    who.push_str(&format!(" +{}", x.writers.len() - 1));
                }
            }
            let _ = writeln!(
                out,
                "{:>9} {:>8} {:>9}  {:<24} {}{}{who}",
                fmt_delta(x.delta),
                hb(x.size),
                if rate > 0 { format!("{}/s", hb(rate)) } else { "-".into() },
                evidence_tags(&x.evidence),
                x.path,
                if x.is_dir { "/" } else { "" },
            );
        }
    }
    let quiet = g.growers.iter().filter(|x| x.delta == 0 && x.writers.is_empty()).count();
    if quiet > 0 {
        let n = quiet;
        let _ = writeln!(out, "  … {n} more paths touched with no net size change (--json lists them)");
    }
    if !g.deleted_open.is_empty() {
        let _ = writeln!(out, "Deleted but still open (space returns when the holder closes them or restarts):");
        const SHOW: usize = 8;
        for (pid, name, path, b) in g.deleted_open.iter().take(SHOW) {
            let _ = writeln!(out, "{:>9}  {path}  held by {name} ({pid})", hb(*b));
        }
        if g.deleted_open.len() > SHOW {
            let rest = &g.deleted_open[SHOW..];
            let _ = writeln!(out, "{:>9}  … {} more (--json lists them)", hb(rest.iter().map(|d| d.3).sum()), rest.len());
        }
    }
    if !g.writers.is_empty() {
        let _ = writeln!(out, "Top writers:");
        for (pid, name, b) in &g.writers {
            let _ = writeln!(out, "{:>9}  {name} ({pid})   fat why {pid}", hb(*b));
        }
    }
    for n in &g.notes {
        let _ = writeln!(out, "note: {n}");
    }
    if g.to > 0 && now > 0 {
        let _ = writeln!(out, "(window {} → {}, evidence: fsevents/watch exact · open-files attributed · scan-diff coarse · mtime≤ upper bound)", fmt_hms(g.from), fmt_hms(g.to));
    }
    out
}

fn fmt_hms(ts: model::Ts) -> String {
    tui::widgets::fmt_clock(ts)
}

fn fmt_volumes(vols: &[fs::Volume]) -> String {
    use std::fmt::Write;
    use tui::widgets::{fmt_eta, fmt_fill, volume_ratio};
    let mut out = String::new();
    let w = vols.iter().map(|v| v.mount.chars().count()).max().unwrap_or(5).clamp(5, 40);
    let _ = writeln!(out, "{:<w$} {:>17} {:>4}  {:<12} {:>8} {:>12}  {:<12} {:<22} TYPE", "MOUNT", "USED/TOTAL", "USE", "", "AVAIL", "FILL/10m", "ETA", "IO r/w");
    for v in vols {
        let r = volume_ratio(v);
        let io = if v.read_bps + v.write_bps > 0 { format!("{}/s {}/s", hb(v.read_bps), hb(v.write_bps)) } else { "-".into() };
        let mut ty = v.fstype.clone();
        if v.read_only {
            ty.push_str(" ro");
        }
        if v.remote {
            ty.push_str(if v.fstype == "apfs" || v.fstype == "hfs" { " external" } else { " network" });
        }
        if v.primary {
            ty.push_str(" primary");
        }
        if let Some(p) = v.purgeable.filter(|p| *p > 0) {
            ty.push_str(&format!(" purgeable {}", hb(p)));
        }
        let _ = writeln!(
            out,
            "{:<w$} {:>17} {:>3.0}%  {:<12} {:>8} {:>12}  {:<12} {:<22} {ty}",
            v.mount,
            format!("{}/{}", hb(v.used), hb(v.total)),
            r * 100.0,
            tui::widgets::bar(r, 12),
            hb(v.avail),
            fmt_fill(v.fill_bps, 600_000).map(|f| f.trim_end_matches("/10m").to_string()).unwrap_or_else(|| "-".into()),
            v.eta_full_s.map(fmt_eta).unwrap_or_else(|| "-".into()),
            io,
        );
        if !v.note.is_empty() {
            let _ = writeln!(out, "{:<w$}   note: {}", "", v.note);
        }
    }
    out
}

/// Storage facts for `fat doctor` (one volume sample; deleted-but-open files). Empty on failure.
fn fs_facts(h: Option<&history::History>) -> blame::FsFacts {
    let guard = |f: &mut dyn FnMut()| std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_ok();
    let mut facts = blame::FsFacts::default();
    guard(&mut || {
        let mut v = fs::volumes::Volumes::new();
        if let Some(h) = h {
            h.seed_volumes(&mut v, model::now_ms());
        }
        facts.volumes = v.sample();
    });
    guard(&mut || facts.deleted_open = fs::volumes::deleted_open());
    facts
}

fn run_fs(a: FsArgs, cfg: &config::Config) -> Result<()> {
    let now = model::now_ms();
    if a.volumes {
        let mut v = fs::volumes::Volumes::new();
        // FILL/10m and the ETA come from recorded volume use (`fat record` or a TUI); two
        // samples a second apart are too close for a rate.
        if let Ok(h) = history::History::open(cfg.history_path.as_deref()) {
            h.seed_volumes(&mut v, now);
        }
        let _ = v.sample();
        // The disk I/O poller needs two readings (~0.9 s apart) for a rate.
        std::thread::sleep(std::time::Duration::from_millis(1300));
        let vols = v.sample();
        if a.json {
            return print_json(&vols);
        }
        print!("{}", fmt_volumes(&vols));
        return Ok(());
    }
    if a.growth {
        let window_ms = ago_ms(&a.since)?;
        if window_ms <= 0 {
            anyhow::bail!("--since must be positive");
        }
        // `fat fs PATH --growth` means growth under PATH (same as --under PATH).
        let under = match (a.under.as_deref(), a.path.as_deref()) {
            (Some(u), Some(p)) if abs_path(Some(u)) != abs_path(Some(p)) => {
                anyhow::bail!("give the directory once: either PATH or --under (got {p} and {u})")
            }
            (Some(u), _) | (None, Some(u)) => Some(abs_path(Some(u))),
            (None, None) => None,
        };
        let mut t = fs::growth::Tracker::new();
        // Collector samples give per-process write rates for attribution.
        // Three samples ~0.8 s apart, so a bursty writer is caught writing at least once.
        let mut c = collect::Collector::new();
        t.observe(&c.sample());
        for _ in 0..2 {
            std::thread::sleep(std::time::Duration::from_millis(800));
            t.observe(&c.sample());
        }
        let h = history::History::open(cfg.history_path.as_deref()).ok();
        let sc = fs::scan::Scanner::new();
        let g = t.report(window_ms, under.as_deref(), h.as_ref(), Some(&sc));
        if a.json {
            return print_json(&g);
        }
        print!("{}", fmt_growth(&g, window_ms, now));
        return Ok(());
    }
    let path = abs_path(a.path.as_deref());
    let wait_ms = a.wait.as_deref().map(budget::parse_duration).transpose()?.map(|s| s * 1000);
    if let Some(p) = mcp::path_problem(&path) {
        anyhow::bail!("{p}");
    }
    let sc = fs::scan::Scanner::new();
    // Typing a path is explicit intent: protected or mounted dirs may be read.
    sc.ensure(&path, true);
    if let Some(n) = a.largest {
        let mut v = sc.largest(&path, n);
        if v.is_empty() || wait_ms.is_some() {
            let _ = sc.scan_blocking(&path, wait_ms.unwrap_or(15_000));
            v = sc.largest(&path, n);
        }
        if a.json {
            return print_json(&v);
        }
        if v.is_empty() {
            println!("nothing measured under {path} yet");
        }
        for e in &v {
            println!("{:>8}  {}{}", hb(e.size), e.path, if e.is_dir { "/" } else { "" });
        }
        return Ok(());
    }
    let l = match wait_ms {
        Some(w) => sc.scan_blocking(&path, w),
        None => mcp::list_expanded(&sc, &path, 10_000).or_else(|| sc.scan_blocking(&path, 10_000)),
    };
    let Some(l) = l else {
        anyhow::bail!("nothing measured under {path} yet: the scan is still running (try --wait 2m)");
    };
    if l.dir.denied > 0 && l.dir.files == 0 && l.children.is_empty() {
        anyhow::bail!("{path}: could not be read ({})", mcp::unreadable_hint());
    }
    let mut lookup = |p: &str| mcp::list_expanded(&sc, p, 3000);
    if a.json {
        let mut v = mcp::listing_json(&l, a.depth as usize, a.top.max(1), &mut lookup);
        v["progress"] = serde_json::to_value(&l.progress)?;
        return print_json(&v);
    }
    print!("{}", fmt_listing(&l, a.depth, a.top.max(1), now, &mut lookup));
    Ok(())
}

fn main() -> Result<()> {
    // Behave like a normal Unix tool when piped into `head` etc.: die quietly on EPIPE
    // instead of panicking in println!.
    // SAFETY: setting a signal disposition to SIG_DFL at startup, before any threads exist.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    let cfg = config::Config::load();
    match cli.cmd {
        None => tui::run(cfg)?,
        Some(Cmd::Snapshot { json, top }) => {
            let s = sample_with(json);
            if json {
                print_json(&s)?;
            } else {
                let sys = &s.system;
                println!(
                    "{}  cpu {:.0}%  mem {}/{} ({})  thermal {}  power {:.1}W  load {:.2} {:.2} {:.2}",
                    sys.hostname,
                    sys.cpu,
                    fmt_bytes(sys.mem_used),
                    fmt_bytes(sys.mem_total),
                    sys.mem_pressure,
                    sys.thermal,
                    sys.power_mw / 1000.0,
                    sys.load[0],
                    sys.load[1],
                    sys.load[2]
                );
                // Linux-only extras; absent (and not printed) on macOS.
                let mut extra = Vec::new();
                if let Some(p) = &sys.psi {
                    extra.push(format!("psi some cpu {:.1} mem {:.1} io {:.1}", p.cpu_some, p.mem_some, p.io_some));
                }
                if let Some(t) = sys.temp_c {
                    extra.push(format!("temp {t:.0}°C"));
                }
                if !extra.is_empty() {
                    println!("{}", extra.join("  "));
                }
                let mut procs = s.procs.clone();
                procs.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
                println!("{:>7} {:>6} {:>8} {:>7}  NAME", "PID", "CPU%", "MEM", "POWER");
                for p in procs.iter().take(top) {
                    println!("{:>7} {:>6.1} {:>8} {:>6.0}mW  {}", p.pid, p.cpu, fmt_bytes(p.mem), p.power_mw, p.name);
                }
            }
        }
        Some(Cmd::Ports { json }) => {
            let s = sample();
            if json {
                print_json(&s.ports)?;
            } else {
                println!("{:<4} {:<22} {:>7}  {:<18} NOTE", "PROTO", "ADDR", "PID", "PROCESS");
                for p in &s.ports {
                    let orphan = if p.orphan { " ⚠ orphan" } else { "" };
                    println!(
                        "{:<4} {:<22} {:>7}  {:<18} {}{}",
                        format!("{:?}", p.proto).to_lowercase(),
                        format!("{}:{}", p.addr, p.port),
                        p.pid,
                        p.process,
                        p.note,
                        orphan
                    );
                }
            }
        }
        Some(Cmd::Why { pid, json }) => {
            let s = sample_with(true);
            let h = history::History::open(cfg.history_path.as_deref()).ok();
            let e = blame::explain(&s, pid, h.as_ref());
            if json {
                print_json(&e)?;
            } else {
                println!("{}", e.headline);
                for (i, step) in e.chain.iter().enumerate() {
                    println!("  {}{}", "  ".repeat(i), if i == 0 { step.clone() } else { format!("↳ {step}") });
                }
                for ev in &e.evidence {
                    println!("  • {ev}");
                }
                for sg in &e.suggestions {
                    println!("  → {sg}");
                }
            }
        }
        Some(Cmd::Doctor { json }) => {
            let mut s = sample();
            // Container names for container findings, fetched only when something runs in one.
            if cfg.containers && s.procs.iter().any(|p| p.container.is_some()) {
                s.containers = fleet::containers();
            }
            let h = history::History::open(cfg.history_path.as_deref()).ok();
            let f = blame::diagnose_with_fs(&s, h.as_ref(), &fs_facts(h.as_ref()));
            if json {
                print_json(&f)?;
            } else if f.is_empty() {
                println!("All good. Nothing unusual.");
            } else {
                for x in &f {
                    println!("[{}] {}\n    {}", x.severity, x.title, x.detail);
                    if let Some(a) = &x.action {
                        println!("    → {a}");
                    }
                }
            }
        }
        Some(Cmd::Ask { question }) => {
            let q = question.join(" ");
            let s = sample_with(true);
            let h = history::History::open(cfg.history_path.as_deref()).ok();
            let f = blame::diagnose(&s, h.as_ref());
            println!("{}", ask::ask(&q, &s, &f, &cfg.ask));
        }
        Some(Cmd::Record) => history::record_forever(&cfg)?,
        Some(Cmd::History { since, at, spikes, json }) => {
            let h = history::History::open(cfg.history_path.as_deref())?;
            let now = model::now_ms();
            if let Some(at) = at {
                match h.at(now - ago_ms(&at)?)? {
                    Some(s) if json => print_json(&s)?,
                    Some(mut s) => {
                        println!(
                            "snapshot @ {}  cpu {:.0}%  mem {}  power {:.1}W",
                            chrono::DateTime::from_timestamp_millis(s.ts)
                                .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
                                .unwrap_or_default(),
                            s.system.cpu,
                            fmt_bytes(s.system.mem_used),
                            s.system.power_mw / 1000.0
                        );
                        s.procs.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
                        for p in s.procs.iter().take(15) {
                            println!("{:>7} {:>6.1}% {:>8}  {}", p.pid, p.cpu, fmt_bytes(p.mem), p.name);
                        }
                    }
                    None => println!("no history at that time — is `fat record` running?"),
                }
            } else {
                let from = now - ago_ms(&since)?;
                let pts = if spikes { h.spikes(from, now)? } else { h.timeline(from, now, 60)? };
                if json {
                    print_json(&pts)?;
                } else if pts.is_empty() {
                    println!("no history in range — start the recorder with `fat record`");
                } else {
                    for p in &pts {
                        let t = chrono::DateTime::from_timestamp_millis(p.ts)
                            .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
                            .unwrap_or_default();
                        println!(
                            "{t}  cpu {:>5.1}%  mem {:>8}  power {:>5.1}W  top {} ({:.0}%)",
                            p.cpu,
                            fmt_bytes(p.mem_used),
                            p.power_mw / 1000.0,
                            p.top_name,
                            p.top_cpu
                        );
                    }
                }
            }
        }
        Some(Cmd::Run { cpu, mem, time, procs, on_violation, cmd }) => {
            let b = Budget {
                cpu,
                mem: mem.as_deref().map(budget::parse_bytes).transpose()?,
                time: time.as_deref().map(budget::parse_duration).transpose()?,
                procs,
                on_violation,
            };
            let code = budget::run(&cmd, &b)?;
            std::process::exit(code);
        }
        Some(Cmd::Pause { pid }) => {
            let s = sample();
            print_action(&actions::Actions::open().apply(ActionKind::Pause, pid, None, &s));
        }
        Some(Cmd::Resume { pid }) => {
            let s = sample();
            print_action(&actions::Actions::open().apply(ActionKind::Resume, pid, None, &s));
        }
        Some(Cmd::Renice { pid, nice }) => {
            let s = sample();
            print_action(&actions::Actions::open().apply(ActionKind::Renice, pid, Some(nice), &s));
        }
        Some(Cmd::Kill { pid, tree, force }) => {
            let s = sample();
            let kind = if tree { ActionKind::KillTree } else if force { ActionKind::Kill } else { ActionKind::Term };
            print_action(&actions::Actions::open().apply(kind, pid, None, &s));
        }
        Some(Cmd::Undo { id }) => {
            let mut a = actions::Actions::open();
            match id {
                Some(id) => print_action(&a.undo(id)),
                None => match a.undo_last() {
                    Some(r) => print_action(&r),
                    None => println!("nothing to undo"),
                },
            }
        }
        Some(Cmd::Log { json }) => {
            let l = actions::Actions::open().log();
            if json {
                print_json(&l)?;
            } else {
                for r in &l {
                    let undone = if r.undone { " (undone)" } else { "" };
                    print!("{}  ", chrono::DateTime::from_timestamp_millis(r.ts).map(|d| d.with_timezone(&chrono::Local).format("%m-%d %H:%M:%S").to_string()).unwrap_or_default());
                    print_action(r);
                    if !undone.is_empty() {
                        println!("    {undone}");
                    }
                }
            }
        }
        Some(Cmd::Fleet { json }) => {
            let mut out: Vec<serde_json::Value> = Vec::new();
            let cs = fleet::containers();
            for h in &cfg.hosts {
                match fleet::remote(h) {
                    Ok(s) => out.push(serde_json::json!({"host": h.name, "ok": true, "cpu": s.system.cpu, "mem_used": s.system.mem_used, "mem_total": s.system.mem_total, "procs": s.procs.len(), "ports": s.ports.len()})),
                    Err(e) => out.push(serde_json::json!({"host": h.name, "ok": false, "error": e.to_string()})),
                }
            }
            if json {
                print_json(&serde_json::json!({"containers": cs, "hosts": out}))?;
            } else {
                println!("containers: {}", cs.len());
                for c in &cs {
                    println!("  {:<24} {:<28} {:>5.1}% {:>8}  {}", c.name, c.image, c.cpu, fmt_bytes(c.mem), c.status);
                }
                println!("hosts: {}", out.len());
                for h in &out {
                    println!("  {h}");
                }
                if cfg.hosts.is_empty() {
                    println!("  (add [[hosts]] to {})", config::Config::path().display());
                }
            }
        }
        Some(Cmd::Mcp) => mcp::serve()?,
        Some(Cmd::Fs(a)) => run_fs(a, &cfg)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> std::result::Result<FsArgs, String> {
        let mut v = vec!["fat", "fs"];
        v.extend_from_slice(args);
        match Cli::try_parse_from(v).map_err(|e| e.to_string())?.cmd {
            Some(Cmd::Fs(a)) => Ok(a),
            _ => Err("not fs".into()),
        }
    }

    #[test]
    fn fs_cli_parsing() {
        let a = parse(&[]).unwrap();
        assert_eq!((a.path, a.depth, a.growth, a.volumes, a.largest, a.json), (None, 1, false, false, None, false));
        assert_eq!(a.since, "10m");
        let a = parse(&["/Users", "--depth", "3", "--json", "--wait", "30"]).unwrap();
        assert_eq!(a.path.as_deref(), Some("/Users"));
        assert_eq!(a.depth, 3);
        assert_eq!(a.wait.as_deref(), Some("30"));
        assert!(a.json);
        let a = parse(&["--growth", "--since", "1h", "--under", "/Users/me"]).unwrap();
        assert!(a.growth);
        assert_eq!(a.since, "1h");
        assert_eq!(a.under.as_deref(), Some("/Users/me"));
        assert!(parse(&["--volumes", "--json"]).unwrap().volumes);
        let a = parse(&["--largest", "20", "/var"]).unwrap();
        assert_eq!((a.largest, a.path.as_deref()), (Some(20), Some("/var")));
        // invalid combinations
        assert!(parse(&["--since", "1h"]).is_err(), "--since needs --growth");
        assert!(parse(&["--growth", "--volumes"]).is_err());
        assert!(parse(&["--depth", "0"]).is_err());
        assert!(parse(&["--largest", "x"]).is_err());
    }

    #[test]
    fn abs_paths() {
        assert_eq!(abs_path(None), "/");
        assert_eq!(abs_path(Some("/Users/me/")), "/Users/me");
        assert_eq!(abs_path(Some("/a/./b/../c")), "/a/c");
        assert_eq!(abs_path(Some("/..")), "/");
        let cwd = std::env::current_dir().unwrap().display().to_string();
        assert_eq!(abs_path(Some("x")), format!("{}/x", cwd.trim_end_matches('/')));
        if let Some(h) = dirs::home_dir() {
            assert_eq!(abs_path(Some("~/Downloads")), format!("{}/Downloads", h.display()));
        }
    }

    #[test]
    fn fs_human_output() {
        let de = |p: &str, size: u64, dir: bool| fs::DirEntry { path: p.into(), name: p.rsplit('/').next().unwrap().into(), is_dir: dir, size, files: 3, newest_mtime: 1000, ..Default::default() };
        let l = fs::Listing {
            dir: fs::DirEntry { files: 9, scanned_at: 1_000_000, partial: true, ..de("/w", 1000, true) },
            children: vec![de("/w/node_modules", 600, true), fs::DirEntry { denied: 1, ..de("/w/secret", 0, true) }, de("/w/b", 300, false), de("/w/c", 100, false)],
            progress: fs::ScanProgress { running: true, fraction: Some(0.43), ..Default::default() },
        };
        let mut sub = |p: &str| (p == "/w/node_modules").then(|| fs::Listing { dir: de(p, 600, true), children: vec![de("/w/node_modules/react", 500, true)], ..Default::default() });
        let out = fmt_listing(&l, 2, 3, 1_120_000, &mut sub);
        assert!(out.starts_with("/w  1000B  (9 files · still scanning 43%: sizes are lower bounds · as of 2m ago)"), "{out}");
        assert!(out.contains("    600B  60%  ███████▎····       3   2m ago  node_modules/"), "{out}");
        assert!(out.contains("    500B  83%  ██████████··       3   2m ago    react/"), "depth 2 nests children\n{out}");
        assert!(out.contains("?   0%") && out.contains("secret/ 🔒") && out.contains(locked_legend()), "{out}");
        assert_eq!(out.contains("Full Disk Access"), cfg!(target_os = "macos"), "{out}");
        assert!(!out.contains("not listed by name"), "partial listings have no remainder row\n{out}");
        // A complete listing whose loose files are not all listed gets a remainder row.
        let done = fs::Listing { dir: fs::DirEntry { files: 9, ..de("/w", 1000, true) }, children: vec![de("/w/a", 600, true)], ..Default::default() };
        let rest = fmt_listing(&done, 1, 3, 1_120_000, &mut |_| None);
        assert!(rest.contains("    400B  40%") && rest.contains("(6 other files not listed by name)"), "{rest}");
        assert!(out.contains("… 1 more"), "{out}");
        assert!(out.contains("💡 node_modules: npm"), "{out}");
        let g = fs::Growth {
            from: 1, to: 2,
            volumes: vec![("/".into(), 3 << 30)],
            growers: vec![fs::Grower { path: "/w/logs".into(), is_dir: true, delta: 2 << 30, size: 5 << 30, writers: vec![(42, "node".into(), 1 << 20), (7, "x".into(), 1)], evidence: vec![fs::Evidence::Fsevents, fs::Evidence::OpenFiles], ..Default::default() }],
            writers: vec![(42, "node".into(), 2 << 30)],
            deleted_open: vec![(9, "java".into(), "/tmp/old.log".into(), 3 << 30)],
            notes: vec!["fanotify needs root".into()],
        };
        let out = fmt_growth(&g, 600_000, 5);
        assert!(out.contains("last 10m") && out.contains("volume /: +3.0G"), "{out}");
        assert!(out.contains("    +2.0G     5.0G    1.0M/s  fsevents,open-files      /w/logs/  ← node (42) +1"), "{out}");
        assert!(out.contains("held by java (9)") && out.contains("fat why 42") && out.contains("note: fanotify"), "{out}");
        let vols = vec![fs::Volume { mount: "/".into(), fstype: "apfs".into(), total: 100 << 30, used: 95 << 30, avail: 5 << 30, primary: true, fill_bps: Some(1e6), eta_full_s: Some(5000), ..Default::default() }];
        let out = fmt_volumes(&vols);
        assert!(out.contains("95.0G/100.0G  95%") && out.contains("full in 1h") && out.contains("apfs primary"), "{out}");
    }
}
