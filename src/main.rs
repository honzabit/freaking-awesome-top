//! fat — Fucking Awesome Top. A process monitor for humans and agents.
//! OWNER: integration (lead). Subcommands are thin wrappers over modules.

mod actions;
mod ask;
mod blame;
mod budget;
mod collect;
mod config;
mod fleet;
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
    /// Ask in plain language ("why is my mac slow?").
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
        /// pause | kill | warn
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
    /// Serve the MCP protocol on stdio (for agents).
    Mcp,
}

fn sample() -> Snapshot {
    let mut c = collect::Collector::new();
    let _ = c.sample();
    std::thread::sleep(std::time::Duration::from_millis(600));
    let mut s = c.sample();
    let cfg = config::Config::load();
    if cfg.containers {
        s.containers = fleet::containers();
    }
    s
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
    if r.undoable && r.ok {
        println!("    undo with: fat undo {}", r.id);
    }
}

fn ago_ms(s: &str) -> Result<i64> {
    Ok(budget::parse_duration(s)? as i64 * 1000)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = config::Config::load();
    match cli.cmd {
        None => tui::run(cfg)?,
        Some(Cmd::Snapshot { json, top }) => {
            let s = sample();
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
                let mut procs = s.procs.clone();
                procs.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
                println!("{:>7} {:>6} {:>8} {:>7}  {}", "PID", "CPU%", "MEM", "POWER", "NAME");
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
                println!("{:<4} {:<22} {:>7}  {:<18} {}", "PROTO", "ADDR", "PID", "PROCESS", "NOTE");
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
            let s = sample();
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
            let s = sample();
            let h = history::History::open(cfg.history_path.as_deref()).ok();
            let f = blame::diagnose(&s, h.as_ref());
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
            let s = sample();
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
    }
    Ok(())
}
