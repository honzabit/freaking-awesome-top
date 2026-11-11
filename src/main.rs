//! fat — Freaking Awesome Top. A process monitor for humans and agents.
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
mod llm;
mod llm_cli;
mod mcp;
mod model;
mod server;
mod settings;
mod sys;
mod threads;
mod tui;
mod update;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use model::{ActionKind, Budget, Snapshot};

#[derive(Parser)]
#[command(name = "fat", version, about = "Freaking Awesome Top — what is my machine doing, why, and for whom?")]
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
        /// Serve the recorder's newest sample if fresh, else sample live with services and
        /// kernel; adds version/profile/volumes metadata (what `fat fleet` polls). [fleet]
        #[arg(long)]
        fast: bool,
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
    ///
    /// Answered by a language model: Claude (ANTHROPIC_API_KEY) or a self-hosted server ([ask]
    /// in the config, or `,` in the TUI). A redacted digest of the machine goes with the
    /// question; without a model nothing is sent and it says how to set one up (exit status 1).
    /// Each question starts a thread, kept locally; --continue / --thread N ask a follow-up.
    /// --dry-run prints exactly the request body and sends nothing.
    Ask {
        /// Print the request body that would be sent, and send nothing.
        #[arg(long)]
        dry_run: bool,
        /// Check the configured model with a tiny question (nothing about the machine is sent).
        #[arg(long, conflicts_with_all = ["dry_run", "list", "show", "delete", "continue_", "thread"])]
        test: bool,
        /// Follow up in the most recent thread.
        #[arg(long = "continue", short = 'c', conflicts_with = "thread")]
        continue_: bool,
        /// Follow up in thread N.
        #[arg(long, value_name = "N")]
        thread: Option<i64>,
        /// Don't keep this question and answer.
        #[arg(long)]
        no_save: bool,
        /// List threads (newest first).
        #[arg(long, conflicts_with_all = ["show", "continue_", "thread", "dry_run"])]
        list: bool,
        /// Print thread N.
        #[arg(long, value_name = "N", conflicts_with_all = ["continue_", "thread", "dry_run"])]
        show: Option<i64>,
        /// Delete thread N.
        #[arg(long, value_name = "N", conflicts_with_all = ["show", "list", "continue_", "thread", "dry_run"])]
        delete: Option<i64>,
        #[arg(long)]
        json: bool,
        question: Vec<String>,
    },
    /// Run the always-on flight recorder (foreground).
    ///
    /// The server profile (auto-detected on headless Linux, or `--server`) also records units,
    /// kernel health and events, and as root writes to /var/lib/fat/history.db. `--export
    /// prometheus` serves /metrics on 127.0.0.1:9877 (or --listen) from the newest sample.
    // --- recorder-export ---
    Record {
        /// Record units, kernel health and events too (default: when the server profile is detected).
        #[arg(long)]
        server: bool,
        /// Serve the newest sample as metrics. Only "prometheus".
        #[arg(long, value_name = "FORMAT", value_parser = ["prometheus"])]
        export: Option<String>,
        /// Listen address for --export: IP:PORT or a port (default [server] export_listen, loopback).
        #[arg(long, value_name = "ADDR", requires = "export")]
        listen: Option<String>,
    },
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
    /// Pause a process (SIGSTOP). Undoable: `fat undo` or `fat resume` continues it.
    Pause { pid: u32 },
    /// Resume a paused process (SIGCONT).
    Resume { pid: u32 },
    /// Change priority. Journaled; undoing a +N needs root (lowering nice is privileged).
    Renice { pid: u32, nice: i32 },
    /// Terminate (TERM), no prompt. NOT undoable: pause first to try it out. --tree: whole subtree (TERM); --force: KILL.
    Kill {
        pid: u32,
        /// TERM the whole subtree, leaves first. Can't be combined with --force.
        #[arg(long, conflicts_with = "force")]
        tree: bool,
        #[arg(long)]
        force: bool,
    },
    /// Undo the last pause or renice (or a specific id). A kill cannot be undone.
    Undo { id: Option<u64> },
    /// Show the action journal.
    Log {
        #[arg(long)]
        json: bool,
    },
    /// Fleet: health, findings, events and incidents across hosts over ssh (read-only).
    Fleet(fleet::cli::FleetArgs),
    /// Disk usage: what eats storage, and what is filling it right now. Read-only.
    ///
    /// `fat fs [PATH]` lists the children of PATH (default "/") by size from the cached
    /// background scan, scanning if needed. `--growth` answers "what grew in the last 10
    /// minutes", `--volumes` lists filesystems, `--largest N` the N biggest entries below PATH.
    Fs(FsArgs),
    /// Serve the MCP protocol on stdio (for agents).
    Mcp,
    /// Update fat to the latest release (signature-checked), check for one, or roll back.
    Update {
        /// Only check whether a newer release exists.
        #[arg(long, conflicts_with = "rollback")]
        check: bool,
        /// Go back to the binary the last update replaced.
        #[arg(long)]
        rollback: bool,
    },
    // === server mode (contract: src/server/mod.rs). Each agent adds its variants below its
    // own marker only: services | kernel | doctor-incident | recorder-export | fleet. ===
    // --- services ---
    /// Services: systemd units, containers, pods and cgroups with state, restarts, flapping, OOM kills, throttling.
    Services {
        /// Only failed or flapping units.
        #[arg(long)]
        failed: bool,
        /// Only one kind: systemd, container, k8s-pod or cgroup.
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        json: bool,
    },
    // --- kernel ---
    /// Kernel health (Linux): steal/iowait, PSI, disk latency, D state, fd/conntrack/port limits, kernel log events.
    Kernel {
        /// Kernel log events from this far back (e.g. 15m, 2h, 24h).
        #[arg(long, default_value = "24h")]
        since: String,
        #[arg(long)]
        json: bool,
        /// Stream kernel events as they happen (JSON lines with --json) until Ctrl-C.
        #[arg(long)]
        watch: bool,
    },
    // --- doctor-incident ---
    /// Event timeline: OOM kills, unit failures/restarts, disk latency, exhaustion, kernel errors (recorder, else live + kernel log).
    Events {
        /// How far back: a duration (2h, 30m, 1d) or a time (03:00, "2026-11-10 03:00").
        #[arg(long, default_value = "2h")]
        since: String,
        /// Only these kinds (repeatable or comma-separated): oom-kill, unit-failed, unit-restart, disk-latency-spike, ...
        #[arg(long)]
        kind: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// What happened and who did it: an incident's causal chain, culprits and next steps.
    #[command(name = "what-happened")]
    WhatHappened {
        /// Moment of interest: 03:12, 03:12:30, "2026-11-10 03:12", RFC 3339, epoch seconds, -2h or "2h ago". Default: the last --window.
        #[arg(long)]
        at: Option<String>,
        /// How much time before --at to examine (e.g. 15m, 1h).
        #[arg(long, default_value = "15m")]
        window: String,
        #[arg(long)]
        json: bool,
    },
}

/// Top-level help groups (clap has no per-subcommand headings, so the list is rendered here
/// from each subcommand's own about text; `help_groups_cover_every_subcommand` keeps it whole).
const HELP_GROUPS: &[(&str, &[&str])] = &[
    ("Everyday", &["snapshot", "ports", "fs", "why", "doctor", "ask"]),
    (
        "Actions (pause/resume can be undone, renice as root; kill cannot)",
        &["pause", "resume", "renice", "kill", "undo", "log"],
    ),
    ("Flight recorder", &["record", "history"]),
    ("Advanced", &["run", "mcp", "update"]),
    ("Server", &["services", "kernel", "events", "what-happened", "fleet"]),
];

fn cli_command() -> clap::Command {
    use clap::CommandFactory;
    let cmd = Cli::command();
    let mut groups = String::from("With no command, fat opens the TUI (processes by CPU; h for keys).\n");
    for (title, names) in HELP_GROUPS {
        groups.push_str(&format!("\n{title}:\n"));
        for n in *names {
            let about = cmd.find_subcommand(n).and_then(|c| c.get_about()).map(|a| a.to_string()).unwrap_or_default();
            // Names of 10+ chars ("what-happened") keep two spaces before their text.
            let name = if n.len() >= 10 { format!("{n}  ") } else { format!("{n:<10}") };
            groups.push_str(&format!("  {name}{about}\n"));
        }
    }
    groups.push_str("  help      Print help for a command (fat help <command>)\n");
    cmd.help_template(format!(
        "{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{groups}\nOptions:\n{{options}}{{after-help}}"
    ))
}

fn parse_cli() -> Cli {
    use clap::FromArgMatches;
    let m = cli_command().get_matches();
    Cli::from_arg_matches(&m).unwrap_or_else(|e| e.exit())
}

/// Two samples 600ms apart (rates need an interval). Containers, when wanted and enabled,
/// are fetched concurrently because `docker stats` alone can take ~2s.
fn sample_with(containers: bool) -> Snapshot {
    let cfg = config::Config::load();
    let want = containers && cfg.containers;
    let fetch = want.then(|| std::thread::spawn(fleet::containers));
    // [integrator] Server profile: units, kernel and events ride along in every live snapshot.
    // The sampler's first (baseline) pass overlaps the 600 ms rate interval.
    let mut sampler = (server::Profile::detect(&cfg.server) == server::Profile::Server)
        .then(|| server::ServerSampler::new(&cfg.server));
    let fill = |sampler: &mut Option<server::ServerSampler>, s: &mut Snapshot| {
        if let Some(sm) = sampler.as_mut()
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sm.fill(s))).is_err()
        {
            *sampler = None;
        }
    };
    let mut c = collect::Collector::new();
    let started = std::time::Instant::now();
    let mut first = c.sample();
    fill(&mut sampler, &mut first);
    std::thread::sleep(std::time::Duration::from_millis(600).saturating_sub(started.elapsed()));
    let mut s = c.sample();
    fill(&mut sampler, &mut s);
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
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            dirs::home_dir().map(|h| format!("{}{rest}", h.display())).unwrap_or_else(|| p.to_string())
        }
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
fn fmt_listing(
    l: &fs::Listing,
    depth: u8,
    top: usize,
    now: model::Ts,
    list: &mut dyn FnMut(&str) -> Option<fs::Listing>,
) -> String {
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
            let alias = c
                .path
                .strip_prefix("/System/Volumes/Data")
                .filter(|r| cfg!(target_os = "macos") && fs::volumes::firmlinks().iter().any(|f| f == r));
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
        if depth > 1
            && c.is_dir
            && !c.mount_point
            && c.size > 0
            && let Some(sub) = list(&c.path)
        {
            fmt_children(out, &sub, depth - 1, top, level + 1, now, list, notes);
        }
    }
    if l.children.len() > top {
        let rest = &l.children[top..];
        let _ = writeln!(
            out,
            "{:>8} {:>4}  {:<12} {:>7} {:>8}  {indent}… {} more",
            hb(rest.iter().map(|c| c.size).sum()),
            "",
            "",
            "",
            "",
            rest.len()
        );
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
                "{:>9} {:>8} {:>9}  {:<24} {}{who}",
                fmt_delta(x.delta),
                hb(x.size),
                if rate > 0 { format!("{}/s", hb(rate)) } else { "-".into() },
                evidence_tags(&x.evidence),
                tui::widgets::grower_label(x),
            );
        }
    }
    let quiet = g.growers.iter().filter(|x| x.delta == 0 && x.writers.is_empty()).count();
    if quiet > 0 {
        let n = quiet;
        let _ = writeln!(out, "  … {n} more paths touched with no net size change (--json lists them)");
    }
    let (groups, small, small_bytes) = tui::widgets::group_deleted(&g.deleted_open, tui::widgets::DELETED_MIN_BYTES);
    if !groups.is_empty() || small > 0 {
        let _ = writeln!(out, "Deleted but still open (space returns when the holder closes them or restarts):");
        const SHOW: usize = 8;
        for d in groups.iter().take(SHOW) {
            let what =
                if d.files == 1 { d.biggest.clone() } else { format!("{} files, biggest {}", d.files, d.biggest) };
            let _ = writeln!(out, "{:>9}  {} ({}) holds {what}", hb(d.bytes), d.name, d.pid);
        }
        if groups.len() > SHOW {
            let rest = &groups[SHOW..];
            let _ = writeln!(
                out,
                "{:>9}  … {} more processes (--json lists them)",
                hb(rest.iter().map(|d| d.bytes).sum()),
                rest.len()
            );
        }
        if small > 0 {
            let _ =
                writeln!(out, "{:>9}  … {small} small files under 1M not shown (--json lists them)", hb(small_bytes));
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
        let _ = writeln!(
            out,
            "(window {} → {}, evidence: fsevents/watch exact · open-files attributed · scan-diff coarse · mtime≤ upper bound)",
            fmt_hms(g.from),
            fmt_hms(g.to)
        );
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
    let _ = writeln!(
        out,
        "{:<w$} {:>17} {:>4}  {:<12} {:>8} {:>12}  {:<12} {:<22} TYPE",
        "MOUNT", "USED/TOTAL", "USE", "", "AVAIL", "FILL/10m", "ETA", "IO r/w"
    );
    for v in vols {
        let r = volume_ratio(v);
        let io = if v.read_bps + v.write_bps > 0 {
            format!("{}/s {}/s", hb(v.read_bps), hb(v.write_bps))
        } else {
            "-".into()
        };
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

struct AskArgs {
    question: Vec<String>,
    dry_run: bool,
    continue_: bool,
    thread: Option<i64>,
    no_save: bool,
    list: bool,
    show: Option<i64>,
    delete: Option<i64>,
    json: bool,
}

fn run_ask(a: AskArgs, cfg: &config::Config) -> Result<()> {
    let path = threads::default_path();
    let store = || threads::Store::open(&path);
    if a.list {
        let ts = store()?.threads(500)?;
        if a.json {
            return print_json(&ts);
        }
        if ts.is_empty() {
            println!("No threads yet. Ask something: fat ask \"why is this machine slow?\"");
        }
        let now = model::now_ms();
        for t in ts {
            let age = tui::widgets::fmt_ago((now - t.updated) / 1000);
            println!(
                "{:>5}  {:<9} {:>3} turn{}  {}",
                t.id,
                age,
                t.turns,
                if t.turns == 1 { " " } else { "s" },
                t.title
            );
        }
        return Ok(());
    }
    if let Some(id) = a.delete {
        let st = store()?;
        anyhow::ensure!(st.exists(id)?, "no thread {id} (fat ask --list)");
        st.delete(id)?;
        println!("deleted thread {id}");
        return Ok(());
    }
    if let Some(id) = a.show {
        let turns = store()?.turns(id)?;
        anyhow::ensure!(!turns.is_empty(), "no thread {id} (fat ask --list)");
        if a.json {
            return print_json(&turns);
        }
        for t in turns {
            let when = chrono::DateTime::from_timestamp_millis(t.ts)
                .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_default();
            println!("## {when} · {}\n\n{}\n\n_via {}_\n", t.question, t.answer, t.via);
        }
        return Ok(());
    }
    let q = a.question.join(" ");
    anyhow::ensure!(!q.trim().is_empty(), "ask what? e.g. fat ask \"why is this machine slow?\"");
    let thread = match (a.continue_, a.thread) {
        (true, _) => Some(store()?.latest()?.context("no thread to continue yet")?),
        (_, Some(id)) => {
            anyhow::ensure!(store()?.exists(id)?, "no thread {id} (fat ask --list)");
            Some(id)
        }
        _ => None,
    };
    let s = sample_with(true);
    let h = history::History::open_read_only(cfg.history_path.as_deref()).ok();
    let f = blame::diagnose(&s, h.as_ref());
    // Disk-space and write questions get the growth report: which paths, which writers.
    let st = ask::wants_storage(&q).then(|| ask::gather_storage(&q, cfg.history_path.as_deref()));
    if a.dry_run {
        let mut conv = ask::Conversation::default();
        if let Some(t) = thread {
            conv.prior = store()?.turns(t)?.into_iter().map(|t| (t.question, t.answer)).collect();
        }
        let (body, note) = ask::dry_run(&q, &conv, &s, &f, st.as_ref(), &cfg.ask);
        eprintln!("{note}");
        println!("{body}");
        return Ok(());
    }
    eprintln!("→ {}", llm::destination(&cfg.ask));
    let save = (!a.no_save).then_some(path.as_path());
    let r = threads::ask_and_save(save, thread, &q, &s, &f, st.as_ref(), &cfg.ask);
    if a.json {
        print_json(&serde_json::json!({
            "answered": r.answered, "thread": r.thread, "question": r.question, "answer": r.answer, "via": r.via,
            "error": r.error,
        }))?;
        if !r.answered {
            std::process::exit(1);
        }
        return Ok(());
    }
    if !r.answered {
        // Why there is no answer, and how to set one up: not an answer, so not on stdout.
        eprintln!("{}", r.answer);
        std::process::exit(1);
    }
    println!("{}", r.answer);
    if let Some(e) = &r.error {
        eprintln!("note: {e}");
    }
    if let Some(t) = r.thread {
        eprintln!("(thread {t}: follow up with `fat ask -c \"…\"`)");
    }
    Ok(())
}

fn run_fs(a: FsArgs, cfg: &config::Config) -> Result<()> {
    let now = model::now_ms();
    if a.volumes {
        let mut v = fs::volumes::Volumes::new();
        // FILL/10m and the ETA come from recorded volume use (`fat record` or a TUI); two
        // samples a second apart are too close for a rate.
        if let Ok(h) = history::History::open_read_only(cfg.history_path.as_deref()) {
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
        let h = history::History::open_read_only(cfg.history_path.as_deref()).ok();
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

/// `fat update [--check | --rollback]`.
fn run_update(check: bool, rollback: bool) -> Result<()> {
    let exe = update::current_exe()?;
    if rollback {
        let v = update::rollback(&exe)?;
        println!(
            "restored {v} at {} (the replaced binary is now {})",
            exe.display(),
            update::prev_path(&exe).display()
        );
        return Ok(());
    }
    let s = update::check_now(std::time::Duration::from_secs(15));
    if !s.error.is_empty() {
        eprintln!("fat update: can't tell which release is the latest: {}", s.error);
        std::process::exit(1);
    }
    let Some(v) = s.available().map(str::to_string) else {
        println!("fat {} is the latest release", update::VERSION);
        return Ok(());
    };
    if check {
        println!("fat {v} is available (this is {}); `fat update` installs it", update::VERSION);
        return Ok(());
    }
    println!("updating fat {} → {v} at {}", update::VERSION, exe.display());
    match update::install(&v, &exe) {
        Ok(i) => {
            println!("installed fat {} (signature and checksum verified)", i.version);
            println!("the previous binary is {}; `fat update --rollback` goes back", i.previous.display());
            println!("a running `fat record` keeps the old binary until it restarts");
            Ok(())
        }
        Err(e) => {
            eprintln!("fat update: {e:#}");
            std::process::exit(1);
        }
    }
}

fn main() -> Result<()> {
    // Behave like a normal Unix tool when piped into `head` etc.: die quietly on EPIPE
    // instead of panicking in println!.
    // SAFETY: setting a signal disposition to SIG_DFL at startup, before any threads exist.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    // Fleet polls set a self-deadline (see fleet::fanout::DEADLINE_ENV): a remote fat whose
    // ssh client gave up must not keep running on the host. SIGALRM's default action ends it.
    if let Some(s) =
        std::env::var(fleet::fanout::DEADLINE_ENV).ok().and_then(|v| v.trim().parse::<u32>().ok()).filter(|&s| s > 0)
    {
        // SAFETY: alarm() has no preconditions; SIGALRM keeps its default disposition.
        unsafe {
            libc::alarm(s);
        }
    }
    let cli = parse_cli();
    let cfg = config::Config::load();
    match cli.cmd {
        None => tui::run(cfg)?,
        Some(Cmd::Snapshot { json, top, fast }) => {
            // [fleet] --fast: recorder sample or live server sample, with fleet metadata.
            let s = if fast { fleet::cli::fast_snapshot(&cfg) } else { sample_with(json) };
            if json && fast {
                println!("{}", serde_json::to_string(&s)?); // compact: this is what fleet polls carry
            } else if json {
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
            // Ports need names, command lines and ppids, not cpu deltas: one sample, no 600 ms wait.
            let s = collect::Collector::new().sample();
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
            let h = history::History::open_read_only(cfg.history_path.as_deref()).ok();
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
            // doctor-incident: server profile adds unit, kernel and event findings.
            server::rules::fill_for_doctor(&cfg.server, &mut s);
            // Container names for container findings and VM-host advice, fetched only when
            // something runs in a container or hosts them (OrbStack, Docker Desktop, dockerd).
            if cfg.containers && blame::hosts_containers(&s) {
                s.containers = fleet::containers();
            }
            let h = history::History::open_read_only(cfg.history_path.as_deref()).ok();
            let mut f = blame::diagnose_with_fs(&s, h.as_ref(), &fs_facts(h.as_ref()));
            f.extend(update::finding(&cfg));
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
        Some(Cmd::Ask { question, dry_run, test, continue_, thread, no_save, list, show, delete, json }) => {
            if test {
                eprintln!("→ {}", llm::destination(&cfg.ask));
                return match llm::test_connection(&cfg.ask) {
                    Ok((took, reply)) => {
                        println!("ok: answered in {:.1}s: {reply}", took.as_secs_f64());
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("failed: {e}");
                        std::process::exit(1);
                    }
                };
            }
            return run_ask(AskArgs { question, dry_run, continue_, thread, no_save, list, show, delete, json }, &cfg);
        }
        // --- recorder-export ---
        Some(Cmd::Record { server: server_flag, export, listen }) => {
            let export = match (export, listen) {
                (Some(_), Some(l)) => Some(server::export::parse_listen(&l)?),
                (Some(_), None) => Some(server::export::parse_listen(&cfg.server.export_listen)?),
                (None, _) => None,
            };
            history::record_with(&cfg, &server::export::RecordOpts { server: server_flag, export })?
        }
        Some(Cmd::History { since, at, spikes, json }) => {
            let h = history::History::open_read_only(cfg.history_path.as_deref())?;
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
            print_action(&actions::Actions::open().with_origin("cli").apply(ActionKind::Pause, pid, None, &s));
        }
        Some(Cmd::Resume { pid }) => {
            let s = sample();
            print_action(&actions::Actions::open().with_origin("cli").apply(ActionKind::Resume, pid, None, &s));
        }
        Some(Cmd::Renice { pid, nice }) => {
            let s = sample();
            print_action(&actions::Actions::open().with_origin("cli").apply(ActionKind::Renice, pid, Some(nice), &s));
        }
        Some(Cmd::Kill { pid, tree, force }) => {
            let s = sample();
            let kind = if tree {
                ActionKind::KillTree
            } else if force {
                ActionKind::Kill
            } else {
                ActionKind::Term
            };
            print_action(&actions::Actions::open().with_origin("cli").apply(kind, pid, None, &s));
        }
        Some(Cmd::Undo { id }) => {
            let mut a = actions::Actions::open().with_origin("cli");
            match id {
                Some(id) => print_action(&a.undo(id)),
                None => match a.undo_last() {
                    Some(r) => print_action(&r),
                    None => println!("nothing to undo"),
                },
            }
        }
        Some(Cmd::Log { json }) => {
            let l = actions::Actions::open().with_origin("cli").log();
            if json {
                print_json(&l)?;
            } else {
                for r in &l {
                    let undone = if r.undone { " (undone)" } else { "" };
                    print!(
                        "{}  ",
                        chrono::DateTime::from_timestamp_millis(r.ts)
                            .map(|d| d.with_timezone(&chrono::Local).format("%m-%d %H:%M:%S").to_string())
                            .unwrap_or_default()
                    );
                    print_action(r);
                    if !undone.is_empty() {
                        println!("    {undone}");
                    }
                }
            }
        }
        // [fleet] inventory, parallel read-only polls, findings across hosts.
        Some(Cmd::Fleet(a)) => fleet::cli::run(a, &cfg)?,
        Some(Cmd::Mcp) => mcp::serve()?,
        Some(Cmd::Update { check, rollback }) => run_update(check, rollback)?,
        // === server mode dispatch: one arm per variant, each under its owner's marker. ===
        // --- services ---
        Some(Cmd::Services { failed, kind, json }) => {
            server::services::cli(&cfg.server, failed, kind.as_deref(), json)?
        }
        // --- kernel ---
        Some(Cmd::Kernel { since, json, watch }) => server::kernel::run_cli(&cfg, &since, json, watch)?,
        // --- doctor-incident ---
        Some(Cmd::Events { since, kind, json }) => server::incident::cli_events(&cfg, &since, &kind, json)?,
        Some(Cmd::WhatHappened { at, window, json }) => {
            server::incident::cli_what_happened(&cfg, at.as_deref(), &window, json)?
        }
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
    fn kill_tree_and_force_do_not_combine() {
        // A tree kill sends TERM; --force used to be dropped silently and the result said "[ok]".
        let e = Cli::try_parse_from(["fat", "kill", "123", "--tree", "--force"]).err().expect("rejected");
        assert_eq!(e.kind(), clap::error::ErrorKind::ArgumentConflict, "{e}");
        assert!(matches!(
            Cli::try_parse_from(["fat", "kill", "123", "--tree"]).unwrap().cmd,
            Some(Cmd::Kill { tree: true, force: false, .. })
        ));
        assert!(matches!(
            Cli::try_parse_from(["fat", "kill", "123", "--force"]).unwrap().cmd,
            Some(Cmd::Kill { tree: false, force: true, .. })
        ));
    }

    #[test]
    fn help_groups_cover_every_subcommand() {
        let cmd = cli_command();
        let mut listed: Vec<&str> = HELP_GROUPS.iter().flat_map(|(_, n)| n.iter().copied()).collect();
        let mut all: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        listed.sort_unstable();
        all.sort_unstable();
        assert_eq!(listed, all, "every subcommand in exactly one help group");
        let help = cli_command().render_help().to_string();
        for (title, names) in HELP_GROUPS {
            assert!(help.contains(&format!("{title}:")), "{help}");
            for n in *names {
                assert!(help.contains(&format!("  {n} ")), "{n} missing\n{help}");
            }
        }
        assert!(help.find("Everyday:").unwrap() < help.find("Advanced:").unwrap());
        // Every existing command still parses (no renames).
        for args in [
            &["fat", "snapshot"][..],
            &["fat", "log"],
            &["fat", "undo"],
            &["fat", "kill", "5", "--tree"],
            &["fat", "ask", "--dry-run", "why", "hot"],
            &["fat", "mcp"],
            &["fat", "fleet"],
            &["fat", "record"],
            &["fat", "history", "--spikes"],
            &["fat", "run", "--", "true"],
        ] {
            let m = cli_command().try_get_matches_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
            <Cli as clap::FromArgMatches>::from_arg_matches(&m).unwrap();
        }
        let m = cli_command().try_get_matches_from(["fat", "ask", "--dry-run", "why", "hot"]).unwrap();
        assert!(
            matches!(<Cli as clap::FromArgMatches>::from_arg_matches(&m).unwrap().cmd, Some(Cmd::Ask { dry_run: true, ref question, .. }) if question == &["why", "hot"])
        );
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
        let de = |p: &str, size: u64, dir: bool| fs::DirEntry {
            path: p.into(),
            name: p.rsplit('/').next().unwrap().into(),
            is_dir: dir,
            size,
            files: 3,
            newest_mtime: 1000,
            ..Default::default()
        };
        let l = fs::Listing {
            dir: fs::DirEntry { files: 9, scanned_at: 1_000_000, partial: true, ..de("/w", 1000, true) },
            children: vec![
                de("/w/node_modules", 600, true),
                fs::DirEntry { denied: 1, ..de("/w/secret", 0, true) },
                de("/w/b", 300, false),
                de("/w/c", 100, false),
            ],
            progress: fs::ScanProgress { running: true, fraction: Some(0.43), ..Default::default() },
        };
        let mut sub = |p: &str| {
            (p == "/w/node_modules").then(|| fs::Listing {
                dir: de(p, 600, true),
                children: vec![de("/w/node_modules/react", 500, true)],
                ..Default::default()
            })
        };
        let out = fmt_listing(&l, 2, 3, 1_120_000, &mut sub);
        assert!(
            out.starts_with("/w  1000B  (9 files · still scanning 43%: sizes are lower bounds · as of 2m ago)"),
            "{out}"
        );
        assert!(out.contains("    600B  60%  ███████▎····       3   2m ago  node_modules/"), "{out}");
        assert!(
            out.contains("    500B  83%  ██████████··       3   2m ago    react/"),
            "depth 2 nests children\n{out}"
        );
        assert!(out.contains("?   0%") && out.contains("secret/ 🔒") && out.contains(locked_legend()), "{out}");
        assert_eq!(out.contains("Full Disk Access"), cfg!(target_os = "macos"), "{out}");
        assert!(!out.contains("not listed by name"), "partial listings have no remainder row\n{out}");
        // A complete listing whose loose files are not all listed gets a remainder row.
        let done = fs::Listing {
            dir: fs::DirEntry { files: 9, ..de("/w", 1000, true) },
            children: vec![de("/w/a", 600, true)],
            ..Default::default()
        };
        let rest = fmt_listing(&done, 1, 3, 1_120_000, &mut |_| None);
        assert!(rest.contains("    400B  40%") && rest.contains("(6 other files not listed by name)"), "{rest}");
        assert!(out.contains("… 1 more"), "{out}");
        assert!(out.contains("💡 node_modules: npm"), "{out}");
        let g = fs::Growth {
            from: 1,
            to: 2,
            volumes: vec![("/".into(), 3 << 30)],
            growers: vec![fs::Grower {
                path: "/w/logs".into(),
                is_dir: true,
                delta: 2 << 30,
                size: 5 << 30,
                writers: vec![(42, "node".into(), 1 << 20), (7, "x".into(), 1)],
                evidence: vec![fs::Evidence::Fsevents, fs::Evidence::OpenFiles],
                ..Default::default()
            }],
            writers: vec![(42, "node".into(), 2 << 30)],
            deleted_open: vec![(9, "java".into(), "/tmp/old.log".into(), 3 << 30)],
            notes: vec!["fanotify needs root".into()],
            ..Default::default()
        };
        let out = fmt_growth(&g, 600_000, 5);
        assert!(out.contains("last 10m") && out.contains("volume /: +3.0G"), "{out}");
        assert!(
            out.contains("    +2.0G     5.0G    1.0M/s  fsevents,open-files      /w/logs/  ← node (42) +1"),
            "{out}"
        );
        assert!(
            out.contains("java (9) holds /tmp/old.log") && out.contains("fat why 42") && out.contains("note: fanotify"),
            "{out}"
        );
        let vols = vec![fs::Volume {
            mount: "/".into(),
            fstype: "apfs".into(),
            total: 100 << 30,
            used: 95 << 30,
            avail: 5 << 30,
            primary: true,
            fill_bps: Some(1e6),
            eta_full_s: Some(5000),
            ..Default::default()
        }];
        let out = fmt_volumes(&vols);
        assert!(
            out.contains("95.0G/100.0G  95%") && out.contains("full in 1h") && out.contains("apfs primary"),
            "{out}"
        );
    }
}
