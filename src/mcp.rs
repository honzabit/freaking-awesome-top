//! MCP server over stdio (JSON-RPC 2.0, newline-delimited). OWNER: mcp agent.
//!
//! Layout:
//! - [`serve`] owns stdin/stdout and nothing else: one JSON message per line in,
//!   one JSON message per line out. Logging goes to stderr only.
//! - [`handle_line`] / [`handle_message`] are the pure-ish dispatcher (testable).
//! - [`tools`] returns the tool catalog; [`call_tool`] routes to handlers of shape
//!   `fn(&mut State, &Value) -> Result<Value>`, each run under `catch_unwind`.

use std::io::{BufRead, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::actions::Actions;
use crate::collect::Collector;
use crate::config::Config;
use crate::history::History;
use crate::model::{ActionKind, ActionRecord, Proc, Snapshot, now_ms};

const SUPPORTED_PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_PROTOCOL: &str = "2025-06-18";
/// Re-sample if the cached snapshot is older than this.
const MAX_SNAPSHOT_AGE: Duration = Duration::from_secs(1);

// JSON-RPC error codes.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const INSTRUCTIONS: &str = "fat (Fucking Awesome Top) is a live process monitor for this machine. \
Use it to answer 'what is my machine doing, why, and what can I safely do about it'. \
Start with `doctor` (ranked findings) or `snapshot` (system totals + top processes; sort by cpu/mem/power/net/disk). \
Use `why {pid}` for a blame chain explaining why a process exists and what it costs, `process {pid}` for full details, \
`ports` / `find_port_owner {port}` for listeners (orphaned dev servers are flagged), `history` for the always-on flight \
recorder (timeline, spikes, or a past snapshot via at_minutes_ago; needs `fat record` running), `containers` for docker/podman, \
and `ask {question}` for a plain-language answer. Actions are reversible where possible and journaled: prefer `pause` \
(SIGSTOP, undo with `resume` or `undo`) or `renice` over `kill`; every action returns an id usable with `undo`. \
CPU percent is per-core (100 = one full core); memory/disk/net values are bytes and bytes/sec; power is milliwatts.";

/// Long-lived server state. Every field is optional so the dispatcher can run
/// (and be tested) without any collector/history/actions backend.
pub struct State {
    collector: Option<Collector>,
    history: Option<History>,
    actions: Option<Actions>,
    config: Config,
    last: Option<(Instant, Snapshot)>,
    /// Samples taken by the current collector. The first one has no interval, so its
    /// rates (cpu, power, disk) are all zero and must never be served.
    samples: u32,
}

/// Minimum spacing between a collector's first and second sample for meaningful rates.
const WARMUP: std::time::Duration = std::time::Duration::from_millis(500);

impl State {
    /// State with no backends attached (used by tests and as a fallback).
    pub fn empty() -> State {
        State { collector: None, history: None, actions: None, config: Config::default(), last: None, samples: 0 }
    }

    /// Full state: collector (with an initial sample), history DB, action journal.
    /// Each backend is constructed under `catch_unwind` so a broken module degrades
    /// to "unavailable" instead of killing the server.
    pub fn new() -> State {
        let config = guard(Config::load).unwrap_or_default();
        let mut collector = guard(Collector::new);
        let last = collector.as_mut().and_then(|c| guard(AssertUnwindSafe(|| c.sample())).map(|s| (Instant::now(), s)));
        let history_path = config.history_path.clone();
        let history = guard(move || History::open(history_path.as_deref()).ok()).flatten();
        let actions = guard(Actions::open);
        if collector.is_none() {
            log("collector unavailable; snapshot-based tools will fail");
        }
        let samples = u32::from(last.is_some());
        State { collector, history, actions, config, last, samples }
    }

    /// Current snapshot, re-sampled if the cached one is older than 1s.
    fn snapshot(&mut self) -> Result<&Snapshot> {
        let stale = self.samples < 2 || self.last.as_ref().is_none_or(|(t, _)| t.elapsed() > MAX_SNAPSHOT_AGE);
        if stale {
            if self.collector.is_none() {
                // The collector may have failed at startup; retry cheaply.
                self.collector = guard(Collector::new);
                self.samples = 0;
            }
            let c = self.collector.as_mut().ok_or_else(|| anyhow!("process collector is unavailable"))?;
            if self.samples == 0 {
                c.sample();
                self.samples = 1;
                std::thread::sleep(WARMUP);
            } else if self.samples == 1 {
                let since = self.last.as_ref().map(|(t, _)| t.elapsed()).unwrap_or_default();
                std::thread::sleep(WARMUP.saturating_sub(since));
            }
            self.last = Some((Instant::now(), c.sample()));
            self.samples += 1;
        }
        Ok(&self.last.as_ref().expect("set above").1)
    }

    fn history(&self) -> Result<&History> {
        self.history.as_ref().ok_or_else(|| {
            anyhow!("flight recorder database is unavailable; start the recorder with `fat record` and retry")
        })
    }

    fn actions(&mut self) -> Result<&mut Actions> {
        self.actions.as_mut().ok_or_else(|| anyhow!("action journal is unavailable"))
    }
}

/// Run `f`, converting a panic into `None`.
fn guard<T>(f: impl FnOnce() -> T) -> Option<T> {
    catch_unwind(AssertUnwindSafe(f)).ok()
}

fn log(msg: &str) {
    eprintln!("[fat mcp] {msg}");
}

/// Serve MCP on stdin/stdout until EOF.
pub fn serve() -> Result<()> {
    log("starting");
    let mut state = State::new();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                log(&format!("stdin error: {e}"));
                break;
            }
        };
        if let Some(out) = handle_line(&mut state, &line) {
            writeln!(stdout, "{out}")?;
            stdout.flush()?;
        }
    }
    log("stdin closed; exiting");
    Ok(())
}

/// Handle one raw line. Returns the serialized response, or None for
/// notifications / blank lines.
pub fn handle_line(state: &mut State, line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let resp = match serde_json::from_str::<Value>(line) {
        Err(e) => Some(error_response(Value::Null, PARSE_ERROR, &format!("parse error: {e}"))),
        Ok(Value::Array(items)) => {
            // Legacy JSON-RPC batch (allowed in 2025-03-26 and earlier).
            if items.is_empty() {
                Some(error_response(Value::Null, INVALID_REQUEST, "empty batch"))
            } else {
                let out: Vec<Value> = items.iter().filter_map(|m| handle_message(state, m)).collect();
                (!out.is_empty()).then_some(Value::Array(out))
            }
        }
        Ok(msg) => handle_message(state, &msg),
    };
    resp.map(|v| v.to_string())
}

/// Dispatch one JSON-RPC message. Returns None for notifications and responses.
pub fn handle_message(state: &mut State, msg: &Value) -> Option<Value> {
    let Some(obj) = msg.as_object() else {
        return Some(error_response(Value::Null, INVALID_REQUEST, "request must be a JSON object"));
    };
    let id = obj.get("id").cloned();
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        if obj.contains_key("result") || obj.contains_key("error") {
            return None; // a response to something we never sent; ignore
        }
        return Some(error_response(id.unwrap_or(Value::Null), INVALID_REQUEST, "missing method"));
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);

    // Notifications never get a response.
    let Some(id) = id else {
        if method != "notifications/initialized" && !method.starts_with("notifications/") {
            log(&format!("ignoring notification-style call to {method}"));
        }
        return None;
    };

    let result: std::result::Result<Value, (i64, String)> = match method {
        "initialize" => Ok(initialize_result(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => tools_call(state, &params),
        other => Err((METHOD_NOT_FOUND, format!("method not found: {other}"))),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err((code, m)) => error_response(id, code, &m),
    })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn initialize_result(params: &Value) -> Value {
    let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
    let version = if SUPPORTED_PROTOCOLS.contains(&requested) { requested } else { DEFAULT_PROTOCOL };
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "fat", "version": env!("CARGO_PKG_VERSION") },
        "instructions": INSTRUCTIONS,
    })
}

fn tools_call(state: &mut State, params: &Value) -> std::result::Result<Value, (i64, String)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((INVALID_PARAMS, "tools/call requires params.name".to_string()))?;
    let args = match params.get("arguments") {
        None | Some(Value::Null) => json!({}),
        Some(a @ Value::Object(_)) => a.clone(),
        Some(_) => return Err((INVALID_PARAMS, "params.arguments must be an object".into())),
    };
    let handler = handler_for(name).ok_or((INVALID_PARAMS, format!("unknown tool: {name}")))?;
    Ok(run_tool(state, name, handler, &args))
}

/// Run one tool handler, turning errors and panics into an `isError` result.
fn run_tool(state: &mut State, name: &str, handler: Handler, args: &Value) -> Value {
    let outcome = catch_unwind(AssertUnwindSafe(|| handler(state, args)));
    let (value, is_error) = match outcome {
        Ok(Ok(v)) => (v, false),
        Ok(Err(e)) => (json!({ "error": format!("{e:#}") }), true),
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            log(&format!("tool {name} panicked: {msg}"));
            (json!({ "error": format!("internal error in tool {name}: {msg}") }), true)
        }
    };
    tool_result(value, is_error)
}

fn tool_result(value: Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    // structuredContent must be an object; wrap arrays/scalars.
    let structured = if value.is_object() { value } else { json!({ "result": value }) };
    let mut r = json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured,
    });
    if is_error {
        r["isError"] = json!(true);
    }
    r
}

// ---------------------------------------------------------------------------
// Tool catalog
// ---------------------------------------------------------------------------

type Handler = fn(&mut State, &Value) -> Result<Value>;

fn handler_for(name: &str) -> Option<Handler> {
    Some(match name {
        "snapshot" => tool_snapshot,
        "process" => tool_process,
        "ports" => tool_ports,
        "why" => tool_why,
        "doctor" => tool_doctor,
        "history" => tool_history,
        "find_port_owner" => tool_find_port_owner,
        "pause" => tool_pause,
        "resume" => tool_resume,
        "renice" => tool_renice,
        "kill" => tool_kill,
        "undo" => tool_undo,
        "containers" => tool_containers,
        "ask" => tool_ask,
        _ => return None,
    })
}

fn pid_schema() -> Value {
    json!({ "type": "integer", "minimum": 1, "description": "Process id." })
}

fn schema(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required, "additionalProperties": false })
}

fn tool(name: &str, title: &str, description: &str, input: Value, destructive: bool) -> Value {
    let annotations = if destructive {
        json!({ "title": title, "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false })
    } else {
        json!({ "title": title, "readOnlyHint": true, "openWorldHint": false })
    };
    json!({ "name": name, "title": title, "description": description, "inputSchema": input, "annotations": annotations })
}

/// The full tool list advertised by `tools/list`.
pub fn tools() -> Vec<Value> {
    vec![
        tool(
            "snapshot",
            "System snapshot",
            "Current machine state: system totals (cpu %, memory, swap, memory pressure, thermal state, GPU, power mW, net/disk bytes/sec, battery) plus the top processes. \
             Sort by cpu (default), mem, power, net or disk. CPU is per-core percent (100 = one core). Use `filter` to match a substring of the process name or command line.",
            schema(
                json!({
                    "sort": { "type": "string", "enum": ["cpu", "mem", "power", "net", "disk"], "default": "cpu", "description": "Ranking key for the process list." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 30, "description": "Max processes to return." },
                    "filter": { "type": "string", "description": "Case-insensitive substring matched against process name and command line." }
                }),
                &[],
            ),
            false,
        ),
        tool(
            "process",
            "Process details",
            "Everything known about one process: full record (cmd, exe, cwd, user, cpu, mem, disk/net rates, power, threads, status, nice) plus its ancestor chain (names up to launchd) and child counts.",
            schema(json!({ "pid": pid_schema() }), &["pid"]),
            false,
        ),
        tool(
            "ports",
            "Listening ports",
            "All TCP listeners and bound UDP sockets with owning pid/process and a human note. `orphan: true` marks dev-server-like listeners whose launching terminal/agent is gone (re-parented to launchd) — prime candidates for cleanup.",
            schema(json!({ "only_orphans": { "type": "boolean", "default": false, "description": "Return only orphaned listeners." } }), &[]),
            false,
        ),
        tool(
            "why",
            "Explain a process",
            "Blame chain for a pid: why it is running (who launched it, up the parent chain), what it is costing, supporting evidence, and safe suggestions. Use after snapshot/doctor surfaces a suspicious pid.",
            schema(json!({ "pid": pid_schema() }), &["pid"]),
            false,
        ),
        tool(
            "doctor",
            "Diagnose machine",
            "Ranked findings about the whole machine (severity info/warn/crit, title, detail, involved pids, suggested safe action). The best first call when asked 'why is my computer slow/hot/loud'.",
            schema(json!({}), &[]),
            false,
        ),
        tool(
            "history",
            "Flight recorder",
            "Query the always-on flight recorder. Default: downsampled system timeline for the last `since_minutes`. With `spikes: true`: only moments where cpu/power/memory jumped. With `at_minutes_ago`: the full recorded snapshot nearest to that time (time travel). Requires `fat record` to have been running.",
            schema(
                json!({
                    "since_minutes": { "type": "integer", "minimum": 1, "default": 60, "description": "Look-back window for timeline/spikes." },
                    "spikes": { "type": "boolean", "default": false, "description": "Return only spike points." },
                    "at_minutes_ago": { "type": "integer", "minimum": 0, "description": "Return the snapshot nearest to this many minutes ago instead of a timeline." }
                }),
                &[],
            ),
            false,
        ),
        tool(
            "find_port_owner",
            "Who owns a port",
            "Which process is listening on / bound to a port (tcp or udp), with its pid, command, orphan flag, and ancestor chain. Use when 'address already in use'.",
            schema(json!({ "port": { "type": "integer", "minimum": 1, "maximum": 65535, "description": "Port number." } }), &["port"]),
            false,
        ),
        tool(
            "pause",
            "Pause process",
            "Freeze a process with SIGSTOP. Fully reversible (resume or undo) — prefer this over kill to test whether a process is the culprit. Returns an action record with an id for `undo`.",
            schema(json!({ "pid": pid_schema() }), &["pid"]),
            true,
        ),
        tool(
            "resume",
            "Resume process",
            "Continue a paused (stopped) process with SIGCONT.",
            schema(json!({ "pid": pid_schema() }), &["pid"]),
            true,
        ),
        tool(
            "renice",
            "Change priority",
            "Set a process's nice value (-20 highest priority .. 20 lowest). Raising nice (deprioritizing) is allowed for your own processes; lowering usually needs root. Undoable.",
            schema(
                json!({
                    "pid": pid_schema(),
                    "nice": { "type": "integer", "minimum": -20, "maximum": 20, "description": "New nice value." }
                }),
                &["pid", "nice"],
            ),
            true,
        ),
        tool(
            "kill",
            "Terminate process",
            "Terminate a process with SIGTERM (graceful). `tree: true` terminates the process and all its descendants; `force: true` sends SIGKILL instead. Not undoable — consider `pause` first. Journaled.",
            schema(
                json!({
                    "pid": pid_schema(),
                    "tree": { "type": "boolean", "default": false, "description": "Also terminate all descendants." },
                    "force": { "type": "boolean", "default": false, "description": "Send SIGKILL instead of SIGTERM." }
                }),
                &["pid"],
            ),
            true,
        ),
        tool(
            "undo",
            "Undo action",
            "Undo a previous pause or renice by its action id; without `id`, undoes the most recent undoable action.",
            schema(json!({ "id": { "type": "integer", "minimum": 0, "description": "Action id returned by a previous action." } }), &[]),
            true,
        ),
        tool(
            "containers",
            "Containers",
            "Running docker/podman/orbstack containers with image, status, cpu, memory and published ports. Empty if no container runtime is reachable.",
            schema(json!({}), &[]),
            false,
        ),
        tool(
            "ask",
            "Ask in plain language",
            "Ask a plain-language question about this machine ('why is my mac slow?', 'what is using port 3000?'). Answered from a fresh snapshot plus doctor findings.",
            schema(json!({ "question": { "type": "string", "minLength": 1, "description": "The question." } }), &["question"]),
            false,
        ),
    ]
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn arg_u64(args: &Value, key: &str) -> Result<Option<u64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| anyhow!("`{key}` must be a non-negative integer")),
    }
}

fn arg_i64(args: &Value, key: &str) -> Result<Option<i64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_i64().map(Some).ok_or_else(|| anyhow!("`{key}` must be an integer")),
    }
}

fn arg_bool(args: &Value, key: &str) -> Result<bool> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(v) => v.as_bool().ok_or_else(|| anyhow!("`{key}` must be a boolean")),
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_str().map(Some).ok_or_else(|| anyhow!("`{key}` must be a string")),
    }
}

fn arg_pid(args: &Value) -> Result<u32> {
    let pid = arg_u64(args, "pid")?.context("`pid` is required")?;
    if pid == 0 || pid > u32::MAX as u64 {
        bail!("`pid` out of range: {pid}");
    }
    Ok(pid as u32)
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    Ok(serde_json::to_value(v)?)
}

// ---------------------------------------------------------------------------
// Pure helpers (unit tested)
// ---------------------------------------------------------------------------

fn sort_key(p: &Proc, sort: &str) -> f64 {
    match sort {
        "mem" => p.mem as f64,
        "power" => p.power_mw as f64,
        "net" => (p.net_rx_bps + p.net_tx_bps) as f64,
        "disk" => (p.disk_read_bps + p.disk_write_bps) as f64,
        _ => p.cpu as f64,
    }
}

/// Filter by substring (case-insensitive, name or cmd), sort descending, truncate.
fn top_procs<'a>(procs: &'a [Proc], sort: &str, limit: usize, filter: Option<&str>) -> (usize, Vec<&'a Proc>) {
    let needle = filter.map(str::to_lowercase).filter(|s| !s.is_empty());
    let mut v: Vec<&Proc> = procs
        .iter()
        .filter(|p| match &needle {
            Some(n) => p.name.to_lowercase().contains(n) || p.cmd.to_lowercase().contains(n),
            None => true,
        })
        .collect();
    let matched = v.len();
    v.sort_by(|a, b| sort_key(b, sort).partial_cmp(&sort_key(a, sort)).unwrap_or(std::cmp::Ordering::Equal));
    v.truncate(limit);
    (matched, v)
}

fn action_value(r: &ActionRecord) -> Result<Value> {
    let mut v = to_value(r)?;
    if r.undoable && r.ok {
        v["hint"] = json!(format!("reversible: call undo with id {}", r.id));
    }
    Ok(v)
}

fn action_result(r: ActionRecord) -> Result<Value> {
    if !r.ok {
        bail!("{:?} {} failed: {}", r.kind, r.pid, r.message);
    }
    action_value(&r)
}

// ---------------------------------------------------------------------------
// Tool handlers
// ---------------------------------------------------------------------------

fn tool_snapshot(state: &mut State, args: &Value) -> Result<Value> {
    let sort = arg_str(args, "sort")?.unwrap_or("cpu");
    if !["cpu", "mem", "power", "net", "disk"].contains(&sort) {
        bail!("`sort` must be one of cpu, mem, power, net, disk");
    }
    let limit = arg_u64(args, "limit")?.unwrap_or(30).clamp(1, 1000) as usize;
    let filter = arg_str(args, "filter")?;
    let snap = state.snapshot()?;
    let (matched, procs) = top_procs(&snap.procs, sort, limit, filter);
    Ok(json!({
        "ts": snap.ts,
        "host": snap.host,
        "system": snap.system,
        "sort": sort,
        "total_procs": snap.procs.len(),
        "matched_procs": matched,
        "procs": procs,
        "listening_ports": snap.ports.len(),
        "orphan_ports": snap.ports.iter().filter(|p| p.orphan).count(),
    }))
}

fn tool_process(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    let snap = state.snapshot()?;
    let p = snap.proc(pid).with_context(|| format!("no process with pid {pid}"))?;
    let ancestors: Vec<Value> = snap.ancestors(pid).iter().map(|a| json!({ "pid": a.pid, "name": a.name })).collect();
    let children = snap.procs.iter().filter(|c| c.ppid == pid && c.pid != pid).count();
    let descendants = snap.descendants(pid).len();
    let ports: Vec<_> = snap.ports.iter().filter(|x| x.pid == pid).collect();
    Ok(json!({
        "process": p,
        "ancestors": ancestors,
        "children_count": children,
        "descendants_count": descendants,
        "ports": ports,
    }))
}

fn tool_ports(state: &mut State, args: &Value) -> Result<Value> {
    let only = arg_bool(args, "only_orphans")?;
    let snap = state.snapshot()?;
    let ports: Vec<_> = snap.ports.iter().filter(|p| !only || p.orphan).collect();
    Ok(json!({ "count": ports.len(), "ports": ports }))
}

fn tool_why(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    state.snapshot()?;
    let snap = &state.last.as_ref().expect("snapshot cached").1;
    if snap.proc(pid).is_none() {
        bail!("no process with pid {pid}");
    }
    to_value(&crate::blame::explain(snap, pid, state.history.as_ref()))
}

fn tool_doctor(state: &mut State, _args: &Value) -> Result<Value> {
    state.snapshot()?;
    let snap = &state.last.as_ref().expect("snapshot cached").1;
    let findings = crate::blame::diagnose(snap, state.history.as_ref());
    Ok(json!({ "count": findings.len(), "findings": findings }))
}

fn tool_history(state: &mut State, args: &Value) -> Result<Value> {
    let since = arg_u64(args, "since_minutes")?.unwrap_or(60).max(1) as i64;
    let spikes = arg_bool(args, "spikes")?;
    let at = arg_u64(args, "at_minutes_ago")?;
    let h = state.history()?;
    let now = now_ms();
    let bounds = h.bounds().ok().flatten().map(|(a, b)| json!({ "oldest_ts": a, "newest_ts": b }));
    if let Some(m) = at {
        let ts = now - m as i64 * 60_000;
        return match h.at(ts)? {
            Some(s) => Ok(json!({ "mode": "at", "requested_ts": ts, "snapshot": s, "bounds": bounds })),
            None => bail!("no recorded snapshot near {m} minutes ago — is `fat record` running?"),
        };
    }
    let from = now - since * 60_000;
    let (mode, pts) = if spikes { ("spikes", h.spikes(from, now)?) } else { ("timeline", h.timeline(from, now, 120)?) };
    Ok(json!({ "mode": mode, "from_ts": from, "to_ts": now, "count": pts.len(), "points": pts, "bounds": bounds }))
}

fn tool_find_port_owner(state: &mut State, args: &Value) -> Result<Value> {
    let port = arg_u64(args, "port")?.context("`port` is required")?;
    if port == 0 || port > 65535 {
        bail!("`port` must be 1..65535");
    }
    let snap = state.snapshot()?;
    let owners: Vec<Value> = snap
        .ports
        .iter()
        .filter(|p| p.port as u64 == port)
        .map(|p| {
            let ancestors: Vec<&str> = snap.ancestors(p.pid).iter().map(|a| a.name.as_str()).collect();
            json!({ "port": p, "process": snap.proc(p.pid), "ancestors": ancestors })
        })
        .collect();
    Ok(json!({ "port": port, "in_use": !owners.is_empty(), "owners": owners }))
}

fn apply(state: &mut State, kind: ActionKind, pid: u32, nice: Option<i32>) -> Result<Value> {
    state.snapshot()?;
    let snap = state.last.as_ref().expect("snapshot cached").1.clone();
    if snap.proc(pid).is_none() {
        bail!("no process with pid {pid}");
    }
    let r = state.actions()?.apply(kind, pid, nice, &snap);
    // Force a fresh sample next call so status changes are visible.
    state.last = None;
    action_result(r)
}

fn tool_pause(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    apply(state, ActionKind::Pause, pid, None)
}

fn tool_resume(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    apply(state, ActionKind::Resume, pid, None)
}

fn tool_renice(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    let nice = arg_i64(args, "nice")?.context("`nice` is required")?;
    if !(-20..=20).contains(&nice) {
        bail!("`nice` must be in -20..=20");
    }
    apply(state, ActionKind::Renice, pid, Some(nice as i32))
}

fn tool_kill(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    let kind = if arg_bool(args, "tree")? {
        ActionKind::KillTree
    } else if arg_bool(args, "force")? {
        ActionKind::Kill
    } else {
        ActionKind::Term
    };
    apply(state, kind, pid, None)
}

fn tool_undo(state: &mut State, args: &Value) -> Result<Value> {
    let id = arg_u64(args, "id")?;
    let actions = state.actions()?;
    let r = match id {
        Some(id) => actions.undo(id),
        None => actions.undo_last().context("nothing to undo")?,
    };
    state.last = None;
    action_result(r)
}

fn tool_containers(_state: &mut State, _args: &Value) -> Result<Value> {
    let cs = crate::fleet::containers();
    Ok(json!({ "count": cs.len(), "containers": cs }))
}

fn tool_ask(state: &mut State, args: &Value) -> Result<Value> {
    let q = arg_str(args, "question")?.map(str::trim).filter(|s| !s.is_empty()).context("`question` is required")?;
    let q = q.to_string();
    state.snapshot()?;
    let snap = &state.last.as_ref().expect("snapshot cached").1;
    let findings = crate::blame::diagnose(snap, state.history.as_ref());
    let answer = crate::ask::ask(&q, snap, &findings, &state.config.ask);
    Ok(json!({ "question": q, "answer": answer, "findings": findings }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(state: &mut State, line: &str) -> Value {
        serde_json::from_str(&handle_line(state, line).expect("response")).unwrap()
    }

    #[test]
    fn initialize_echoes_supported_version() {
        let mut s = State::empty();
        for v in SUPPORTED_PROTOCOLS {
            let r = call(&mut s, &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{v}"}}}}"#));
            assert_eq!(r["result"]["protocolVersion"], *v);
            assert_eq!(r["id"], 1);
        }
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#);
        assert_eq!(r["result"]["protocolVersion"], DEFAULT_PROTOCOL);
        assert_eq!(r["result"]["serverInfo"]["name"], "fat");
        assert_eq!(r["result"]["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
        assert!(r["result"]["capabilities"]["tools"].is_object());
        assert!(r["result"]["instructions"].as_str().unwrap().len() > 50);
        assert_eq!(r["id"], "a");
    }

    #[test]
    fn notifications_get_no_response() {
        let mut s = State::empty();
        assert!(handle_line(&mut s, r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        assert!(handle_line(&mut s, "   ").is_none());
    }

    #[test]
    fn ping_returns_empty_object() {
        let r = call(&mut State::empty(), r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#);
        assert_eq!(r["result"], json!({}));
    }

    #[test]
    fn unknown_method_and_parse_errors() {
        let mut s = State::empty();
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":2,"method":"nope"}"#);
        assert_eq!(r["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(r["id"], 2);
        let r = call(&mut s, "{not json");
        assert_eq!(r["error"]["code"], PARSE_ERROR);
        assert_eq!(r["id"], Value::Null);
        let r = call(&mut s, "42");
        assert_eq!(r["error"]["code"], INVALID_REQUEST);
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":3}"#);
        assert_eq!(r["error"]["code"], INVALID_REQUEST);
        let r = call(&mut s, "[]");
        assert_eq!(r["error"]["code"], INVALID_REQUEST);
    }

    #[test]
    fn batch_is_handled() {
        let r = call(
            &mut State::empty(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"x"}]"#,
        );
        let arr = r.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[1]["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn tools_list_schemas_are_valid() {
        let r = call(&mut State::empty(), r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let tools = r["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for n in [
            "snapshot", "process", "ports", "why", "doctor", "history", "find_port_owner", "pause", "resume", "renice", "kill",
            "undo", "containers", "ask",
        ] {
            assert!(names.contains(&n), "missing tool {n}");
            assert!(handler_for(n).is_some(), "no handler for {n}");
        }
        assert_eq!(names.len(), 14);
        for t in tools {
            assert!(t["description"].as_str().unwrap().len() > 20);
            let s = &t["inputSchema"];
            assert_eq!(s["type"], "object");
            let props = s["properties"].as_object().unwrap();
            for req in s["required"].as_array().unwrap() {
                assert!(props.contains_key(req.as_str().unwrap()), "{}: required {} not in properties", t["name"], req);
            }
            for (k, p) in props {
                assert!(p["type"].is_string(), "{}.{k} has no type", t["name"]);
                assert!(p["description"].is_string(), "{}.{k} has no description", t["name"]);
            }
            let a = &t["annotations"];
            let destructive = ["pause", "resume", "renice", "kill", "undo"].contains(&t["name"].as_str().unwrap());
            if destructive {
                assert_eq!(a["destructiveHint"], true);
                assert_eq!(a["readOnlyHint"], false);
            } else {
                assert_eq!(a["readOnlyHint"], true);
            }
        }
    }

    #[test]
    fn tools_call_errors() {
        let mut s = State::empty();
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bogus"}}"#);
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#);
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        // No collector attached at startup: it is created lazily on first use.
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"snapshot","arguments":{}}}"#);
        assert!(r["result"]["isError"].is_null() || r["result"]["isError"] == false, "{r}");
        assert_eq!(r["result"]["content"][0]["type"], "text");
        // An unknown pid is a tool failure (isError), not a protocol error or crash.
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"why","arguments":{"pid":4294967000}}}"#);
        assert_eq!(r["result"]["isError"], true, "{r}");
        assert!(r["result"]["structuredContent"]["error"].is_string());
        // Bad argument types are reported as tool errors.
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"process","arguments":{"pid":"x"}}}"#);
        assert_eq!(r["result"]["isError"], true);
        let r = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"history","arguments":{}}}"#);
        assert_eq!(r["result"]["isError"], true);
        assert!(r["result"]["structuredContent"]["error"].as_str().unwrap().contains("fat record"));
    }

    #[test]
    fn panicking_tool_becomes_is_error() {
        fn boom(_: &mut State, _: &Value) -> Result<Value> {
            panic!("kaboom")
        }
        let mut s = State::empty();
        let r = run_tool(&mut s, "boom", boom, &json!({}));
        assert_eq!(r["isError"], true);
        assert!(r["structuredContent"]["error"].as_str().unwrap().contains("kaboom"));
        let r = tool_result(json!({ "error": "x" }), true);
        assert_eq!(r["isError"], true);
        let r = tool_result(json!([1, 2]), false);
        assert_eq!(r["structuredContent"]["result"], json!([1, 2]));
        assert!(r.get("isError").is_none());
    }

    #[test]
    fn top_procs_sorts_filters_and_limits() {
        let mk = |pid, name: &str, cpu, mem| Proc { pid, name: name.into(), cpu, mem, ..Default::default() };
        let procs = vec![mk(1, "launchd", 0.1, 10), mk(2, "node", 50.0, 5), mk(3, "Chrome", 20.0, 900), mk(4, "nodemon", 5.0, 1)];
        let (n, v) = top_procs(&procs, "cpu", 2, None);
        assert_eq!(n, 4);
        assert_eq!(v.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![2, 3]);
        let (_, v) = top_procs(&procs, "mem", 1, None);
        assert_eq!(v[0].pid, 3);
        let (n, v) = top_procs(&procs, "cpu", 10, Some("NODE"));
        assert_eq!(n, 2);
        assert_eq!(v.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![2, 4]);
    }

    #[test]
    fn arg_parsing() {
        assert_eq!(arg_pid(&json!({"pid": 42})).unwrap(), 42);
        assert!(arg_pid(&json!({})).is_err());
        assert!(arg_pid(&json!({"pid": 0})).is_err());
        assert!(arg_pid(&json!({"pid": -1})).is_err());
        assert!(arg_bool(&json!({"x": 1}), "x").is_err());
        assert!(!arg_bool(&json!({}), "x").unwrap());
        assert_eq!(arg_i64(&json!({"n": -5}), "n").unwrap(), Some(-5));
    }
}
