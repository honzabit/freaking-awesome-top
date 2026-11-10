//! `fat fleet ...` and `fat snapshot --fast`, plus the fleet MCP tools' bodies. OWNER: fleet agent.
//!
//! Everything here is read-only towards remote hosts except `fat fleet act`, which needs
//! `--allow-actions`, exactly one host named exactly, an allowlisted reversible action, and
//! passes through the remote fat's own `[mcp] allow_actions` gate and pid-reuse checks.
use super::fanout::{self, LocalTransport, Polled, SshTransport, Transport};
use super::inventory::{self, Selector, Target};
use crate::config::Config;
use crate::model::{Finding, Snapshot, now_ms};
use crate::server::{Event, EventKind, FleetCfg, FleetHost, FleetOutlier, FleetSummary, Incident, Profile, Severity};
use serde_json::{Value, json};
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(clap::Args, Debug, Clone, Default)]
pub struct FleetArgs {
    /// Only hosts in this group (config `groups`, hosts-file `groups=`, or `[fleet.groups]`). Repeatable: any.
    #[arg(long = "group", short = 'g', global = true, value_name = "G")]
    pub groups: Vec<String>,
    /// Only hosts carrying this tag. Repeatable: all must match.
    #[arg(long = "tag", short = 't', global = true, value_name = "T")]
    pub tags: Vec<String>,
    /// Only hosts whose name matches this glob (web-*, db-0[1-3]). Repeatable: any.
    #[arg(long = "host", short = 'H', global = true, value_name = "GLOB")]
    pub hosts: Vec<String>,
    /// Leave out hosts matching this glob. Repeatable.
    #[arg(long, global = true, value_name = "GLOB")]
    pub exclude: Vec<String>,
    #[arg(long, global = true)]
    pub json: bool,
    /// Host table order: health (worst first), cpu, mem, disk, load, latency or name.
    #[arg(long, global = true, default_value = "health", value_parser = ["health", "cpu", "mem", "disk", "load", "latency", "name"])]
    pub sort: String,
    /// Show at most N hosts in the table (0 = all). Findings always cover every host.
    #[arg(long, global = true, default_value_t = 0)]
    pub top: usize,
    /// Parallel ssh sessions (default: fleet.concurrency).
    #[arg(long, global = true)]
    pub concurrency: Option<usize>,
    /// Per-host time limit in seconds (default: fleet.command_timeout_s).
    #[arg(long, global = true)]
    pub timeout: Option<u64>,
    #[command(subcommand)]
    pub cmd: Option<FleetCmd>,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum FleetCmd {
    /// Health table, findings aggregated across hosts, and group outliers (the default).
    Summary,
    /// List the inventory and where each host comes from (no network).
    Hosts,
    /// Findings per host, computed here with this fat's rules.
    Doctor,
    /// Merged event timeline across hosts (needs `fat record --server` on them).
    Events {
        /// How far back, e.g. 30m, 2h, 1d.
        #[arg(long, default_value = "1h")]
        since: String,
        /// Only these kinds (oom_kill, unit_failed, ...). Repeatable.
        #[arg(long = "kind")]
        kinds: Vec<String>,
    },
    /// "What happened at TIME and who did it?" on one host (select it with --host NAME).
    WhatHappened {
        /// 03:12, "2026-01-31 03:12", RFC 3339, -2h, "2h ago" (read on this machine's clock).
        #[arg(long)]
        at: Option<String>,
        #[arg(long, default_value = "15m")]
        window: String,
    },
    /// Run one allowlisted read-only fat command on every selected host
    /// (snapshot, doctor, why, ports, services, kernel, events, what-happened, history, fs).
    ExecReadonly {
        #[arg(required = true, num_args = 1.., allow_hyphen_values = true, trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Pause, resume, renice or undo on ONE host, through that host's own `fat mcp` checks.
    ///
    /// Needs --allow-actions, exactly one host named exactly with --host, and the process name
    /// you expect (--name). The remote must allow the action in its `[mcp] allow_actions`.
    /// There is no fleet-wide action and no remote kill.
    Act {
        #[arg(long)]
        allow_actions: bool,
        #[arg(value_parser = ["pause", "resume", "renice", "undo"])]
        action: String,
        /// Target pid (not needed for undo).
        pid: Option<u32>,
        /// The process name you expect at that pid; refused if it differs.
        #[arg(long)]
        name: Option<String>,
        /// The process start time (epoch seconds) you saw; read live when omitted.
        #[arg(long)]
        start_time: Option<u64>,
        /// Nice value for renice.
        #[arg(long, allow_hyphen_values = true)]
        nice: Option<i32>,
    },
    /// Containers on this machine (docker, podman, containerd).
    Containers,
}

/// Transport for fleet commands: ssh, or a local command when `FAT_FLEET_LOCAL` is set to
/// "PROGRAM [ARG...]" (`{host}` substituted per host). The latter is for tests and simulated
/// fleets; nothing in fat sets it.
pub fn transport(cfg: &FleetCfg) -> Box<dyn Transport> {
    match std::env::var("FAT_FLEET_LOCAL").ok().filter(|s| !s.trim().is_empty()) {
        Some(spec) => {
            let mut w = spec.split_whitespace().map(String::from);
            let program = w.next().unwrap_or_default();
            Box::new(LocalTransport { program, prefix: w.collect() })
        }
        None => Box::new(SshTransport { cfg: cfg.clone() }),
    }
}

fn selector(a: &FleetArgs) -> Selector {
    Selector { hosts: a.hosts.clone(), groups: a.groups.clone(), tags: a.tags.clone(), exclude: a.exclude.clone() }
}

fn effective(cfg: &Config, a: &FleetArgs) -> FleetCfg {
    let mut f = cfg.fleet.clone();
    if let Some(c) = a.concurrency {
        f.concurrency = c.max(1);
    }
    if let Some(t) = a.timeout {
        f.command_timeout_s = t.max(1);
    }
    f
}

/// One full poll: rows, findings, summary (with outliers and elapsed time).
pub struct FleetPoll {
    pub summary: FleetSummary,
    pub findings: Vec<(String, Vec<Finding>)>,
    pub outliers: Vec<FleetOutlier>,
}

/// Poll `targets` and summarize. `progress` gets (done, total) as hosts finish.
pub fn poll_summary(targets: &[Target], fc: &FleetCfg, tr: &dyn Transport, progress: &(dyn Fn(usize, usize) + Sync)) -> FleetPoll {
    let t0 = Instant::now();
    let done = AtomicUsize::new(0);
    let total = targets.len();
    let polled: Vec<Polled> = fanout::poll_detailed(targets, fc, tr, false, &|_h: &FleetHost| progress(done.fetch_add(1, Ordering::Relaxed) + 1, total));
    let mut rows = Vec::with_capacity(polled.len());
    let mut findings = Vec::with_capacity(polled.len());
    for p in polled {
        findings.push((p.host.name.clone(), p.findings));
        rows.push(p.host);
    }
    let outliers = fanout::outliers(&rows, fc);
    let mut summary = fanout::summarize(rows, &findings, fc.max_hosts_per_finding);
    summary.elapsed_ms = t0.elapsed().as_millis() as u64;
    FleetPoll { summary, findings, outliers }
}

/// `fat fleet ...`
pub fn run(a: FleetArgs, cfg: &Config) -> anyhow::Result<()> {
    let fc = effective(cfg, &a);
    let cmd = a.cmd.clone().unwrap_or(FleetCmd::Summary);
    if let FleetCmd::Containers = cmd {
        return containers(a.json);
    }
    if let FleetCmd::Act { allow_actions, .. } = &cmd {
        if !allow_actions {
            anyhow::bail!("fleet actions are off: add --allow-actions (one host, reversible actions only)");
        }
        if a.hosts.len() != 1 || inventory::is_glob(&a.hosts[0]) || !a.groups.is_empty() || !a.tags.is_empty() {
            anyhow::bail!("an action needs exactly one --host with an exact name (no globs, groups or tags)");
        }
    }
    let all = inventory::inventory(cfg)?;
    if all.is_empty() {
        if a.json {
            return print_json(&json!({ "hosts": [], "containers": super::containers(), "note": "no hosts configured" }));
        }
        println!("No fleet hosts configured. Add any of these to {}:", Config::path().display());
        println!("  [[hosts]]\n  name = \"web-01\"            # ssh destination defaults to the name\n  groups = [\"web\"]\n");
        println!("  [fleet]\n  hosts_file = \"~/fleet.txt\"   # lines: web-01 [ssh=user@web-01.example.com] [groups=web] [tags=prod]");
        println!("  ssh_config_hosts = true       # or use the Host aliases of ~/.ssh/config");
        println!("\nThis machine's containers:");
        return containers(false);
    }
    let ts = inventory::select(&all, &selector(&a), cfg);
    if ts.is_empty() {
        anyhow::bail!("no host matches the selection ({} hosts in the inventory; `fat fleet hosts` lists them)", all.len());
    }
    let tr = transport(&fc);
    match cmd {
        FleetCmd::Hosts => hosts(&ts, a.json),
        FleetCmd::Summary => {
            let p = poll_summary(&ts, &fc, tr.as_ref(), &progress_fn(a.json));
            clear_progress(a.json);
            if a.json {
                let mut v = serde_json::to_value(&p.summary)?;
                v["outliers"] = serde_json::to_value(&p.outliers)?;
                sort_rows_json(&mut v, &a.sort);
                return print_json(&v);
            }
            print!("{}", render_summary(&p.summary, &p.outliers, &a.sort, a.top, fc.concurrency));
            Ok(())
        }
        FleetCmd::Doctor => {
            let p = poll_summary(&ts, &fc, tr.as_ref(), &progress_fn(a.json));
            clear_progress(a.json);
            if a.json {
                let per: Vec<Value> = p.findings.iter().map(|(h, f)| json!({ "host": h, "findings": f })).collect();
                return print_json(&json!({ "summary": p.summary.findings, "hosts": per, "unreachable": p.summary.hosts.iter().filter(|h| !h.ok).map(|h| json!({"host": h.name, "error": h.error})).collect::<Vec<_>>() }));
            }
            print!("{}", render_doctor(&p));
            Ok(())
        }
        FleetCmd::Events { since, kinds } => {
            for k in &kinds {
                if EventKind::parse(k).is_none() {
                    anyhow::bail!("unknown event kind {k:?} (one of: {})", EventKind::ALL.map(|k| k.as_str()).join(", "));
                }
            }
            let (events, errors) = fleet_events(&ts, &fc, tr.as_ref(), &since, &kinds);
            if a.json {
                return print_json(&json!({ "events": events.iter().map(|(h, e)| { let mut v = serde_json::to_value(e).unwrap_or_default(); v["host"] = json!(h); v }).collect::<Vec<_>>(), "errors": errors }));
            }
            print!("{}", render_events(&events, &errors));
            Ok(())
        }
        FleetCmd::WhatHappened { at, window } => {
            let t = one_host(&ts, &a)?;
            let mut args = vec!["what-happened".to_string(), "--window".into(), window];
            if let Some(at) = at {
                args.push("--at".into());
                args.push(resolve_at(&at));
            }
            if a.json {
                args.push("--json".into());
            }
            print!("{}", fanout::remote_read_only(&t, &args, &fc, tr.as_ref())?);
            Ok(())
        }
        FleetCmd::ExecReadonly { args } => {
            let sub = args.first().cloned().unwrap_or_default();
            if !fanout::READ_ONLY_REMOTE.contains(&sub.as_str()) {
                anyhow::bail!("refusing `{sub}`: fleet runs only read-only fat commands ({})", fanout::READ_ONLY_REMOTE.join(", "));
            }
            let res = fanout::fan_out(&ts, fc.concurrency, |t| (t.name.clone(), fanout::remote_read_only(t, &args, &fc, tr.as_ref())));
            if a.json {
                let v: Vec<Value> = res
                    .iter()
                    .map(|(h, r)| match r {
                        Ok(out) => json!({ "host": h, "ok": true, "output": serde_json::from_str::<Value>(out.trim()).unwrap_or_else(|_| json!(out)) }),
                        Err(e) => json!({ "host": h, "ok": false, "error": e.to_string() }),
                    })
                    .collect();
                return print_json(&v);
            }
            for (h, r) in res {
                match r {
                    Ok(out) => {
                        for l in out.lines() {
                            println!("{h}: {l}");
                        }
                    }
                    Err(e) => println!("{h}: ERROR {e}"),
                }
            }
            Ok(())
        }
        FleetCmd::Act { action, pid, name, start_time, nice, .. } => {
            let t = one_host(&ts, &a)?;
            let (pid, name) = if action == "undo" {
                (0, String::new())
            } else {
                (pid.ok_or_else(|| anyhow::anyhow!("{action} needs a pid"))?, name.ok_or_else(|| anyhow::anyhow!("{action} needs --name (the process you expect at that pid)"))?)
            };
            if action == "renice" && nice.is_none() {
                anyhow::bail!("renice needs --nice N");
            }
            let req_action = action.clone();
            let req = fanout::ActionReq { action, pid, nice, expect_name: name, start_time };
            let r = fanout::remote_action(&t, &req, &fc, tr.as_ref())?;
            if a.json {
                print_json(&json!({ "host": t.name, "result": r }))?;
            } else {
                println!("{}: {}", t.name, serde_json::to_string_pretty(&r)?);
            }
            if r.get("error").is_some() || r.get("ok") == Some(&json!(false)) {
                anyhow::bail!("{}: the remote fat refused or failed the {}", t.name, req_action);
            }
            Ok(())
        }
        FleetCmd::Containers => unreachable!(),
    }
}

fn one_host(ts: &[Target], a: &FleetArgs) -> anyhow::Result<Target> {
    match ts {
        [t] => Ok(t.clone()),
        [] => anyhow::bail!("no host selected"),
        many => anyhow::bail!("this needs exactly one host; the selection {:?} matches {} (e.g. {})", a.hosts, many.len(), many.iter().take(3).map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ")),
    }
}

/// Resolve a human time on THIS machine's clock and timezone, then send it as RFC 3339 so a
/// host in another timezone examines the same instant. Unparsable input is passed through.
fn resolve_at(at: &str) -> String {
    let parsed = std::panic::catch_unwind(|| crate::server::incident::parse_at(at, now_ms())).ok().and_then(|r| r.ok());
    match parsed.and_then(chrono::DateTime::from_timestamp_millis) {
        Some(d) => d.to_rfc3339(),
        None => at.to_string(),
    }
}

fn containers(json: bool) -> anyhow::Result<()> {
    let cs = super::containers();
    if json {
        return print_json(&json!({ "containers": cs }));
    }
    println!("containers: {}", cs.len());
    for c in &cs {
        println!("  {:<24} {:<28} {:>5.1}% {:>8}  {}", c.name, c.image, c.cpu, human_bytes(c.mem), c.status);
    }
    Ok(())
}

fn hosts(ts: &[Target], json: bool) -> anyhow::Result<()> {
    if json {
        return print_json(&ts);
    }
    println!("{:<24} {:<32} {:<20} {:<20} FAT", "HOST", "SSH", "GROUPS", "TAGS");
    for t in ts {
        println!("{:<24} {:<32} {:<20} {:<20} {}", t.name, t.dest, t.groups.join(","), t.tags.join(","), t.fat_path.as_deref().unwrap_or("(probe)"));
    }
    println!("{} hosts", ts.len());
    Ok(())
}

fn print_json<T: serde::Serialize + ?Sized>(v: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn progress_fn(json: bool) -> impl Fn(usize, usize) + Sync {
    let tty = !json && std::io::stderr().is_terminal();
    let last = Mutex::new(Instant::now() - Duration::from_secs(1));
    move |done, total| {
        if !tty {
            return;
        }
        if let Ok(mut l) = last.lock()
            && (l.elapsed() >= Duration::from_millis(100) || done == total)
        {
            *l = Instant::now();
            let _ = write!(std::io::stderr(), "\rpolling {done}/{total} hosts…");
        }
    }
}

fn clear_progress(json: bool) {
    if !json && std::io::stderr().is_terminal() {
        let _ = write!(std::io::stderr(), "\r\x1b[K");
    }
}

fn sort_rows(rows: &mut [&FleetHost], key: &str) {
    let f = |x: f32| -x;
    match key {
        "cpu" => rows.sort_by(|a, b| f(a.cpu).total_cmp(&f(b.cpu))),
        "mem" => rows.sort_by(|a, b| f(a.mem_pct).total_cmp(&f(b.mem_pct))),
        "disk" => rows.sort_by(|a, b| f(a.disk_worst_pct).total_cmp(&f(b.disk_worst_pct))),
        "load" => rows.sort_by(|a, b| b.load1.total_cmp(&a.load1)),
        "latency" => rows.sort_by_key(|h| std::cmp::Reverse(h.latency_ms)),
        "name" => rows.sort_by(|a, b| a.name.cmp(&b.name)),
        _ => rows.sort_by(|a, b| a.health.cmp(&b.health).then(a.name.cmp(&b.name))),
    }
}

fn sort_rows_json(v: &mut Value, key: &str) {
    if let Some(hosts) = v.get("hosts").and_then(|h| serde_json::from_value::<Vec<FleetHost>>(h.clone()).ok()) {
        let mut refs: Vec<&FleetHost> = hosts.iter().collect();
        sort_rows(&mut refs, key);
        v["hosts"] = serde_json::to_value(refs).unwrap_or_default();
    }
}

fn human_bytes(b: u64) -> String {
    let f = b as f64;
    const K: f64 = 1024.0;
    if f >= K * K * K {
        format!("{:.1}G", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.0}M", f / (K * K))
    } else {
        format!("{:.0}K", f / K)
    }
}

fn sev_word(s: Severity) -> &'static str {
    match s {
        Severity::Crit => "CRIT",
        Severity::Warn => "warn",
        Severity::Info => "info",
    }
}

fn host_list(hosts: &[String], count: usize) -> String {
    let more = count.saturating_sub(hosts.len());
    if more > 0 { format!("{}, +{more} more", hosts.join(", ")) } else { hosts.join(", ") }
}

fn ago(ms: i64) -> String {
    match ms {
        ..=0 => "live".into(),
        1..60_000 => format!("{}s", ms / 1000),
        _ => format!("{}m", ms / 60_000),
    }
}

/// Text form of a fleet summary: headline, aggregated findings, outliers, host table.
pub fn render_summary(s: &FleetSummary, outliers: &[FleetOutlier], sort: &str, top: usize, concurrency: usize) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "fleet: {} hosts · {} ok · {} not polled · {:.1}s (concurrency {})\n",
        s.total,
        s.ok,
        s.unreachable,
        s.elapsed_ms as f64 / 1000.0,
        concurrency
    ));
    if !s.findings.is_empty() {
        o.push_str("\nfindings across hosts:\n");
        for f in &s.findings {
            o.push_str(&format!("  {:<4}  {}: {} host{} [{}]\n", sev_word(f.severity), f.title, f.count, if f.count == 1 { "" } else { "s" }, host_list(&f.hosts, f.count)));
        }
    }
    if !outliers.is_empty() {
        o.push_str("\noutliers (far from their group's median):\n");
        for x in outliers {
            o.push_str(&format!("  {:<20} {:<18} {:>6.0}  (group {} median {:.0}, z {:.1})\n", x.host, x.metric, x.value, x.group, x.median, x.z));
        }
    }
    let mut rows: Vec<&FleetHost> = s.hosts.iter().collect();
    sort_rows(&mut rows, sort);
    let shown = if top == 0 { rows.len() } else { top.min(rows.len()) };
    o.push_str(&format!(
        "\n{:<22} {:>6} {:>5} {:>5} {:>6} {:>6} {:>6} {:>4} {:>5} {:>6} {:>5}  {}\n",
        "HOST", "HEALTH", "CPU%", "MEM%", "LOAD1", "DISK%", "FAILED", "OOM", "C/W", "RTT", "AGE", "TOP FINDING / ERROR"
    ));
    for h in rows.iter().take(shown) {
        if !h.ok {
            o.push_str(&format!("{:<22} {:>6} {:>67}  {}\n", h.name, "-", "", h.error.as_deref().unwrap_or("not polled")));
            continue;
        }
        o.push_str(&format!(
            "{:<22} {:>6} {:>5.0} {:>5.0} {:>6.2} {:>6.0} {:>6} {:>4} {:>5} {:>5}ms {:>5}  {}\n",
            h.name,
            h.health,
            h.cpu,
            h.mem_pct,
            h.load1,
            h.disk_worst_pct,
            h.units_failed,
            h.oom_24h,
            format!("{}/{}", h.findings.crit, h.findings.warn),
            h.latency_ms,
            ago(h.age_ms),
            h.top_finding.as_deref().unwrap_or("")
        ));
    }
    if shown < rows.len() {
        o.push_str(&format!("… {} more hosts (--top 0 shows all)\n", rows.len() - shown));
    }
    o
}

fn render_doctor(p: &FleetPoll) -> String {
    let mut o = String::new();
    let s = &p.summary;
    o.push_str(&format!("fleet doctor: {} hosts · {} ok · {} not polled · {:.1}s\n", s.total, s.ok, s.unreachable, s.elapsed_ms as f64 / 1000.0));
    for f in &s.findings {
        o.push_str(&format!("  {:<4}  {}: {} [{}]\n", sev_word(f.severity), f.title, f.count, host_list(&f.hosts, f.count)));
    }
    let health: std::collections::HashMap<&str, u8> = s.hosts.iter().map(|h| (h.name.as_str(), h.health)).collect();
    let mut per: Vec<&(String, Vec<Finding>)> = p.findings.iter().filter(|(_, f)| f.iter().any(|x| x.severity != "info")).collect();
    per.sort_by_key(|(h, _)| health.get(h.as_str()).copied().unwrap_or(100));
    for (h, fs) in per {
        o.push_str(&format!("\n{h} (health {}):\n", health.get(h.as_str()).copied().unwrap_or(0)));
        for f in fs.iter().filter(|x| x.severity != "info") {
            o.push_str(&format!("  {:<4}  {}\n        {}\n", f.severity, f.title, f.detail));
        }
    }
    o
}

/// (host, event).
pub type HostEvent = (String, Event);

/// Run `fat events --since S --json` on every host; merged oldest first, plus per-host errors.
pub fn fleet_events(ts: &[Target], fc: &FleetCfg, tr: &dyn Transport, since: &str, kinds: &[String]) -> (Vec<HostEvent>, Vec<(String, String)>) {
    let mut args = vec!["events".to_string(), "--since".into(), since.to_string(), "--json".into()];
    for k in kinds {
        args.push("--kind".into());
        args.push(k.clone());
    }
    let res = fanout::fan_out(ts, fc.concurrency, |t| (t.name.clone(), fanout::remote_read_only(t, &args, fc, tr).and_then(|o| parse_events(&o))));
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for (h, r) in res {
        match r {
            Ok(evs) => events.extend(evs.into_iter().map(|e| (h.clone(), e))),
            Err(e) => errors.push((h, e.to_string())),
        }
    }
    events.sort_by(|a, b| a.1.ts.cmp(&b.1.ts).then(a.0.cmp(&b.0)));
    (events, errors)
}

/// Accepts a JSON array of events or an object with an `events` array (banners tolerated).
fn parse_events(out: &str) -> anyhow::Result<Vec<Event>> {
    let start = out.find(['[', '{']).ok_or_else(|| anyhow::anyhow!("bad-output: no JSON"))?;
    let v: Value = serde_json::from_str(out[start..].trim()).map_err(|e| anyhow::anyhow!("bad-output: {e}"))?;
    let arr = if v.is_array() { v } else { v.get("events").cloned().unwrap_or(Value::Array(vec![])) };
    Ok(serde_json::from_value(arr)?)
}

fn render_events(events: &[(String, Event)], errors: &[(String, String)]) -> String {
    let mut o = String::new();
    for (h, e) in events {
        let t = chrono::DateTime::from_timestamp_millis(e.ts).map(|d| d.with_timezone(&chrono::Local).format("%m-%d %H:%M:%S").to_string()).unwrap_or_default();
        o.push_str(&format!("{t}  {:<18} {:<4} {:<20} {:<28} {}\n", h, sev_word(e.severity), e.kind.as_str(), e.subject, e.detail));
    }
    if events.is_empty() {
        o.push_str("no events in that window\n");
    }
    for (h, e) in errors {
        o.push_str(&format!("{h}: not polled: {e}\n"));
    }
    o
}

// ---------------------------------------------------------------------------------------------
// fat snapshot --fast
// ---------------------------------------------------------------------------------------------

/// OOM events of the last 24 h attached by `fat snapshot --fast` (a host OOM-killing more
/// often than this is reported as "at least" this many).
const OOM_EVENTS_MAX: usize = 100;

/// `fat snapshot --fast`: the recorder's newest sample when it is younger than
/// `fleet.fast_max_age_ms` (one SQLite read, nothing sampled), else a live sample with server
/// sampling. Either way `meta` carries version, profile, source and age, `volumes` the
/// filesystems and `events` the last 24 h of OOM kills, so a fleet poll needs one command.
pub fn fast_snapshot(cfg: &Config) -> Snapshot {
    let now = now_ms();
    let hist = crate::history::History::open_read_only(cfg.history_path.as_deref()).ok();
    let recorded = hist.as_ref().and_then(|h| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.latest(cfg.fleet.fast_max_age_ms))).ok()?.ok().flatten());
    let mut s = match recorded {
        Some(s) => s,
        None => live_server_snapshot(cfg),
    };
    let profile = Profile::detect(&cfg.server);
    let mut meta = s.meta.take().unwrap_or_else(|| crate::server::SnapMeta::live(profile));
    meta.profile = profile;
    meta.version = env!("CARGO_PKG_VERSION").into();
    meta.root = crate::server::SnapMeta::live(profile).root;
    s.volumes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut v = crate::fs::volumes::Volumes::new();
        if let Some(h) = &hist {
            h.seed_volumes(&mut v, now);
        }
        v.sample()
    }))
    .unwrap_or_default();
    // The last day's OOM kills (victims, cgroups) ride along: they are what an operator asks
    // about first, and a fleet poll should not need a second call for them. Bounded.
    if let Some(h) = &hist {
        let ooms = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.events(now - 86_400_000, now, &[EventKind::OomKill], OOM_EVENTS_MAX))).ok().and_then(|r| r.ok()).unwrap_or_default();
        for e in ooms {
            if !s.events.iter().any(|x| x.ts == e.ts && x.kind == e.kind && x.subject == e.subject) {
                s.events.push(e);
            }
        }
        s.events.sort_by_key(|e| e.ts);
    }
    s.meta = Some(meta);
    s
}

/// Two samples ~600 ms apart (rates need an interval), with services and kernel filled when
/// the sampler can (it degrades to empty on hosts without cgroups/systemd, and on macOS).
fn live_server_snapshot(cfg: &Config) -> Snapshot {
    let mut c = crate::collect::Collector::new();
    let mut sampler = crate::server::ServerSampler::new(&cfg.server);
    let fill = |sampler: &mut crate::server::ServerSampler, s: &mut Snapshot| {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sampler.fill(s)));
    };
    let mut first = c.sample();
    fill(&mut sampler, &mut first);
    std::thread::sleep(Duration::from_millis(600));
    let mut s = c.sample();
    fill(&mut sampler, &mut s);
    s
}

// ---------------------------------------------------------------------------------------------
// MCP tool bodies (registered in src/mcp.rs). All read-only.
// ---------------------------------------------------------------------------------------------

type CacheEntry = (Instant, String, Arc<FleetPoll>);
static POLL_CACHE: Mutex<Option<CacheEntry>> = Mutex::new(None);

fn mcp_selector(args: &Value) -> Selector {
    let list = |k: &str| -> Vec<String> {
        match args.get(k) {
            Some(Value::String(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
            _ => vec![],
        }
    };
    Selector { hosts: list("host"), groups: list("group"), tags: list("tag"), exclude: list("exclude") }
}

/// Poll (or reuse a poll younger than fleet.cache_ttl_s for the same selection).
fn cached_poll(cfg: &Config, sel: &Selector, refresh: bool) -> anyhow::Result<(Arc<FleetPoll>, u64)> {
    let key = format!("{sel:?}");
    if !refresh
        && let Ok(g) = POLL_CACHE.lock()
        && let Some((at, k, p)) = g.as_ref()
        && *k == key
        && at.elapsed() < Duration::from_secs(cfg.fleet.cache_ttl_s)
    {
        return Ok((p.clone(), at.elapsed().as_millis() as u64));
    }
    let all = inventory::inventory(cfg)?;
    if all.is_empty() {
        anyhow::bail!("no fleet hosts configured: add [[hosts]], fleet.hosts_file or fleet.ssh_config_hosts to {}", Config::path().display());
    }
    let ts = inventory::select(&all, sel, cfg);
    if ts.is_empty() {
        anyhow::bail!("no host matches the selection ({} hosts in the inventory)", all.len());
    }
    let tr = transport(&cfg.fleet);
    let p = Arc::new(poll_summary(&ts, &cfg.fleet, tr.as_ref(), &|_, _| {}));
    if let Ok(mut g) = POLL_CACHE.lock() {
        *g = Some((Instant::now(), key, p.clone()));
    }
    Ok((p, 0))
}

fn limit_of(args: &Value, default: usize) -> usize {
    args.get("limit").and_then(Value::as_u64).map(|n| n.clamp(1, 10_000) as usize).unwrap_or(default)
}

/// MCP `fleet_summary`.
pub fn mcp_fleet_summary(cfg: &Config, args: &Value) -> anyhow::Result<Value> {
    let refresh = args.get("refresh").and_then(Value::as_bool).unwrap_or(false);
    let (p, age) = cached_poll(cfg, &mcp_selector(args), refresh)?;
    let limit = limit_of(args, 50);
    let s = &p.summary;
    Ok(json!({
        "total": s.total, "ok": s.ok, "unreachable": s.unreachable, "elapsed_ms": s.elapsed_ms, "cache_age_ms": age,
        "findings": s.findings,
        "outliers": p.outliers,
        "hosts_shown": s.hosts.len().min(limit),
        "hosts": s.hosts.iter().take(limit).collect::<Vec<_>>(),
        "note": "hosts are worst health first; findings cover every host",
    }))
}

/// MCP `fleet_doctor`.
pub fn mcp_fleet_doctor(cfg: &Config, args: &Value) -> anyhow::Result<Value> {
    let refresh = args.get("refresh").and_then(Value::as_bool).unwrap_or(false);
    let (p, age) = cached_poll(cfg, &mcp_selector(args), refresh)?;
    let limit = limit_of(args, 20);
    let order: Vec<&str> = p.summary.hosts.iter().map(|h| h.name.as_str()).collect();
    let by: std::collections::HashMap<&str, &Vec<Finding>> = p.findings.iter().map(|(h, f)| (h.as_str(), f)).collect();
    let hosts: Vec<Value> = order
        .iter()
        .filter_map(|h| by.get(h).map(|f| (h, f)))
        .filter(|(_, f)| f.iter().any(|x| x.severity != "info"))
        .take(limit)
        .map(|(h, f)| json!({ "host": h, "findings": f }))
        .collect();
    Ok(json!({ "cache_age_ms": age, "fleet_findings": p.summary.findings, "outliers": p.outliers, "hosts": hosts, "unreachable": p.summary.hosts.iter().filter(|h| !h.ok).map(|h| json!({"host": h.name, "error": h.error})).collect::<Vec<_>>() }))
}

fn exact_host(cfg: &Config, args: &Value) -> anyhow::Result<Target> {
    let name = args.get("host").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).ok_or_else(|| anyhow::anyhow!("`host` is required"))?;
    if inventory::is_glob(name) {
        anyhow::bail!("`host` must be one exact inventory name");
    }
    inventory::inventory(cfg)?.into_iter().find(|t| t.name == name).ok_or_else(|| anyhow::anyhow!("{name} is not in the fleet inventory"))
}

/// MCP `host_snapshot`: one host's state, trimmed for an agent (top processes, failed units,
/// kernel health, locally computed findings).
pub fn mcp_host_snapshot(cfg: &Config, args: &Value) -> anyhow::Result<Value> {
    let t = exact_host(cfg, args)?;
    let tr = transport(&cfg.fleet);
    let mut res = fanout::poll_detailed(std::slice::from_ref(&t), &cfg.fleet, tr.as_ref(), true, &|_| {});
    let p = res.pop().ok_or_else(|| anyhow::anyhow!("no result"))?;
    let Some(s) = p.snap else {
        anyhow::bail!("{}: {}", t.name, p.host.error.unwrap_or_default());
    };
    let limit = limit_of(args, 25);
    let mut procs: Vec<&crate::model::Proc> = s.procs.iter().collect();
    procs.sort_by(|a, b| b.cpu.total_cmp(&a.cpu));
    let mut by_mem: Vec<&crate::model::Proc> = s.procs.iter().collect();
    by_mem.sort_by_key(|p| std::cmp::Reverse(p.mem));
    let slim = |p: &&crate::model::Proc| json!({ "pid": p.pid, "name": p.name, "user": p.user, "cpu": p.cpu, "mem": p.mem, "cmd": p.cmd.chars().take(200).collect::<String>() });
    Ok(json!({
        "row": p.host,
        "system": s.system,
        "top_cpu": procs.iter().take(limit).map(slim).collect::<Vec<_>>(),
        "top_mem": by_mem.iter().take(limit).map(slim).collect::<Vec<_>>(),
        "units_not_ok": s.units.iter().filter(|u| u.is_failed() || u.flapping).collect::<Vec<_>>(),
        "units_total": s.units.len(),
        "kernel": s.kernel,
        "events": s.events,
        "findings": p.findings,
        "meta": s.meta,
    }))
}

/// MCP `host_what_happened`.
pub fn mcp_host_what_happened(cfg: &Config, args: &Value) -> anyhow::Result<Value> {
    let t = exact_host(cfg, args)?;
    let tr = transport(&cfg.fleet);
    let mut a = vec!["what-happened".to_string(), "--json".into()];
    if let Some(at) = args.get("at").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
        a.push("--at".into());
        a.push(resolve_at(at));
    }
    if let Some(w) = args.get("window").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
        a.push("--window".into());
        a.push(w.to_string());
    }
    let out = fanout::remote_read_only(&t, &a, &cfg.fleet, tr.as_ref())?;
    let start = out.find('{').ok_or_else(|| anyhow::anyhow!("{}: remote gave no JSON", t.name))?;
    let mut v: Value = serde_json::from_str(out[start..].trim())?;
    if serde_json::from_value::<Incident>(v.clone()).is_ok() {
        v["host"] = json!(t.name);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct T {
        #[command(flatten)]
        a: FleetArgs,
    }

    fn parse(v: &[&str]) -> Result<FleetArgs, String> {
        let mut args = vec!["fleet"];
        args.extend_from_slice(v);
        T::try_parse_from(args).map(|t| t.a).map_err(|e| e.to_string())
    }

    #[test]
    fn cli_parsing() {
        let a = parse(&[]).unwrap();
        assert!(a.cmd.is_none() && a.sort == "health");
        let a = parse(&["doctor", "--group", "web", "-g", "db", "--tag", "prod", "--json"]).unwrap();
        assert!(matches!(a.cmd, Some(FleetCmd::Doctor)) && a.groups == ["web", "db"] && a.json);
        let a = parse(&["--host", "db-01", "what-happened", "--at", "03:12"]).unwrap();
        assert!(matches!(a.cmd, Some(FleetCmd::WhatHappened { at: Some(ref t), ref window }) if t == "03:12" && window == "15m"));
        let a = parse(&["events", "--since", "2h", "--kind", "oom-kill", "--kind", "unit_failed"]).unwrap();
        assert!(matches!(a.cmd, Some(FleetCmd::Events { ref since, ref kinds }) if since == "2h" && kinds.len() == 2));
        let a = parse(&["exec-readonly", "kernel", "--json"]).unwrap();
        assert!(matches!(a.cmd, Some(FleetCmd::ExecReadonly { ref args }) if args == &["kernel", "--json"]));
        assert!(parse(&["--sort", "bogus"]).is_err());
        assert!(parse(&["act", "kill", "1"]).is_err(), "no remote kill");
        let a = parse(&["act", "--allow-actions", "--host", "web-01", "renice", "42", "--name", "make", "--nice", "-5"]).unwrap();
        assert!(matches!(a.cmd, Some(FleetCmd::Act { allow_actions: true, ref action, pid: Some(42), nice: Some(-5), .. }) if action == "renice"));
    }

    #[test]
    fn act_guards() {
        let cfg = Config { hosts: vec![crate::config::HostCfg { name: "web-01".into(), ..Default::default() }, crate::config::HostCfg { name: "web-02".into(), ..Default::default() }], ..Default::default() };
        let err = |v: &[&str]| run(parse(v).unwrap(), &cfg).unwrap_err().to_string();
        assert!(err(&["--host", "web-01", "act", "pause", "1", "--name", "x"]).contains("--allow-actions"));
        assert!(err(&["--host", "web-*", "act", "--allow-actions", "pause", "1", "--name", "x"]).contains("exactly one --host"));
        assert!(err(&["act", "--allow-actions", "pause", "1", "--name", "x"]).contains("exactly one --host"));
        assert!(err(&["--group", "g", "--host", "web-01", "act", "--allow-actions", "pause", "1"]).contains("exactly one --host"));
        assert!(err(&["--host", "web-01", "act", "--allow-actions", "pause", "1"]).contains("--name"));
        assert!(err(&["exec-readonly", "kill", "1"]).contains("read-only"));
        assert!(err(&["--host", "nope", "summary"]).contains("no host matches"));
        assert!(err(&["--host", "web-*", "what-happened"]).contains("exactly one host"));
    }

    #[test]
    fn events_parsing() {
        let e = Event { ts: 5, kind: EventKind::OomKill, detail: "x".into(), ..Default::default() };
        let arr = serde_json::to_string(&vec![e.clone()]).unwrap();
        assert_eq!(parse_events(&arr).unwrap(), vec![e.clone()]);
        assert_eq!(parse_events(&format!("motd\n{{\"events\": {arr}}}")).unwrap(), vec![e]);
        assert!(parse_events("nope").is_err());
    }

    #[test]
    fn summary_rendering() {
        let h = |n: &str, health: u8, cpu: f32| FleetHost { name: n.into(), ok: true, health, cpu, ..Default::default() };
        let s = FleetSummary {
            total: 3,
            ok: 2,
            unreachable: 1,
            hosts: vec![h("web-01", 50, 10.0), h("web-02", 90, 80.0), FleetHost { name: "db-01".into(), error: Some("auth: denied".into()), ..Default::default() }],
            findings: vec![crate::server::FleetFinding { title: "Disk / is #% full".into(), severity: Severity::Warn, count: 12, hosts: vec!["web-01".into(), "web-02".into()] }],
            ..Default::default()
        };
        let out = render_summary(&s, &[], "cpu", 0, 64);
        assert!(out.contains("3 hosts · 2 ok · 1 not polled"), "{out}");
        assert!(out.contains("Disk / is #% full: 12 hosts [web-01, web-02, +10 more]"), "{out}");
        assert!(out.find("web-02 ").unwrap() < out.find("web-01 ").unwrap(), "sorted by cpu\n{out}");
        assert!(out.contains("auth: denied"));
        assert!(render_summary(&s, &[], "health", 1, 64).contains("… 2 more hosts"));
    }

    #[test]
    fn mcp_selector_shapes() {
        let s = mcp_selector(&json!({"group": "web", "tag": ["a", "b"], "host": ""}));
        assert_eq!(s.groups, vec!["web"]);
        assert_eq!(s.tags, vec!["a", "b"]);
        assert!(s.hosts.is_empty());
    }
}
