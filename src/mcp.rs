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
use crate::model::{ActionKind, ActionRecord, Container, Proc, Snapshot, now_ms};

const SUPPORTED_PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_PROTOCOL: &str = "2025-06-18";
/// Re-sample if the cached snapshot is older than this.
const MAX_SNAPSHOT_AGE: Duration = Duration::from_secs(1);

// JSON-RPC error codes.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const INSTRUCTIONS: &str = "fat (Freaking Awesome Top) is a live process monitor for this machine. \
Use it to answer 'what is my machine doing, why, and what can I safely do about it'. \
Start with `doctor` (ranked findings) or `snapshot` (system totals + top processes; sort by cpu/mem/power/net/disk). \
Use `why {pid}` for a blame chain explaining why a process exists and what it costs, `process {pid}` for full details, \
`ports` / `find_port_owner {port}` for listeners (orphaned dev servers are flagged), `history` for the always-on flight \
recorder (timeline, spikes, or a past snapshot via at_minutes_ago; needs `fat record` running), `containers` for docker/podman/nerdctl \
(on Linux, `snapshot {container}` lists the host processes inside one container, joined via cgroups), \
and `ask {question}` for a plain-language answer. For disk space: `fs_volumes` (capacity, fill rate, ETA to full), \
`fs_list {path}` (du-style sizes, cached background scan), `fs_largest {path}`, and `fs_growth {since}` ('what is eating my space \
in the last 10 minutes': growing paths, their writers, deleted-but-open files). The fs tools only read; fat never deletes files. \
Side-effect tools (`pause`, `resume`, `renice`, `kill`, `undo`) are off unless the user enabled them in fat's config \
(`[mcp] allow_actions`); a disabled one returns an error saying how. Do not work around a disabled tool with a shell `kill`: \
tell the user. All actions are journaled. `pause` (SIGSTOP; undo with `resume` or `undo`) is undoable; `renice` is journaled, but \
only root can lower nice again, so as a normal user a renice can't be taken back; `kill` is NOT undoable, so prefer \
pausing a suspect first. `pause` and `kill` are refused for hubs, processes whose cost is other work (a VM or container \
host such as OrbStack Helper, a container runtime or a container's pid 1, init, a browser's or app's main process, the \
display server): the refusal names the workload to act on instead (`docker stop <name>`, close a tab), so tell the user. `kill` takes two calls: the first returns a preview (what would be \
signalled, protection checks, the tree) and a short-lived `confirm_token`; call `kill` again with that token to act. \
Pass the `start_time` (and `name`) you saw in snapshot/process with every action, so a pid that was reused by another \
process in the meantime is refused instead of signalled. Processes with `usage_unknown: true` belong to other users and \
can't be measured without root: their zero cpu/mem means unknown, not idle. \
CPU percent is per-core (100 = one full core); memory/disk/net values are bytes and bytes/sec; power is milliwatts \
(`system.power_source` says how it was obtained: rusage = macOS per-task energy, rapl = Linux package energy counters, \
estimate = CPU-time model). On Linux, `system.psi` gives pressure-stall percentages (avg10): sustained cpu/mem/io stalls \
are the most direct sign that the machine is overloaded.";

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
    /// Storage engines, created by the first fs_* call (never at startup).
    fs: FsEngines,
    /// Side-effect tools the user enabled in `[mcp] allow_actions` (default: none).
    allowed: Vec<String>,
    /// Outstanding kill confirmations (single use, short-lived).
    kill_tokens: Vec<KillToken>,
}

/// Every tool with a side effect. Each is refused unless named in `[mcp] allow_actions`.
pub const ACTION_TOOLS: &[&str] = &["pause", "resume", "renice", "kill", "undo"];
/// How long a kill preview's token stays valid.
const KILL_TOKEN_TTL: Duration = Duration::from_secs(60);

/// A kill the agent previewed: valid once, for this exact process and signal.
#[derive(Debug, Clone)]
struct KillToken {
    token: String,
    pid: u32,
    /// Start time seen at preview; a different process on the same pid is refused.
    start_time: Option<u64>,
    kind: ActionKind,
    issued: Instant,
    /// KillTree: the (pid, start time) of every descendant the preview showed. Only these
    /// (still alive, same start time) are signalled; anything forked since is left alone.
    tree: Vec<(u32, u64)>,
}

/// `[mcp]` in fat's config file (parsed here: the rest of the file belongs to `Config`).
#[derive(Debug, Default, serde::Deserialize)]
struct McpFile {
    #[serde(default)]
    mcp: McpCfg,
}

#[derive(Debug, Default, serde::Deserialize)]
struct McpCfg {
    /// `"all"`, `"none"`, or a list of tool names, e.g. `["pause", "renice"]`.
    #[serde(default)]
    allow_actions: Option<toml::Value>,
}

/// Which side-effect tools a config text enables. Unknown names are ignored (and logged).
pub fn allowed_actions(config_text: &str) -> Vec<String> {
    let v = match toml::from_str::<McpFile>(config_text) {
        Ok(f) => f.mcp.allow_actions,
        Err(e) => {
            log(&format!("ignoring [mcp] config: {e}"));
            None
        }
    };
    let names: Vec<String> = match v {
        Some(toml::Value::String(s)) if s.eq_ignore_ascii_case("all") => {
            ACTION_TOOLS.iter().map(|s| s.to_string()).collect()
        }
        Some(toml::Value::String(s)) if s.eq_ignore_ascii_case("none") || s.is_empty() => vec![],
        Some(toml::Value::String(s)) => vec![s],
        Some(toml::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => vec![],
    };
    let mut out = Vec::new();
    for n in names {
        let n = n.trim().to_ascii_lowercase();
        if n == "all" {
            return ACTION_TOOLS.iter().map(|s| s.to_string()).collect();
        }
        if ACTION_TOOLS.contains(&n.as_str()) {
            if !out.contains(&n) {
                out.push(n);
            }
        } else {
            log(&format!("[mcp] allow_actions: unknown action {n:?} ignored"));
        }
    }
    out
}

fn disabled_message(name: &str) -> String {
    format!(
        "`{name}` is disabled: fat's MCP server performs no side effects unless the user enables them. \
To enable it, the user adds to {}:\n\n[mcp]\nallow_actions = [\"{name}\"]   # or \"all\"\n\nand restarts the MCP server. \
Ask the user instead of signalling the process another way.",
        Config::path().display()
    )
}

#[derive(Default)]
struct FsEngines {
    scanner: Option<crate::fs::scan::Scanner>,
    volumes: Option<crate::fs::volumes::Volumes>,
    tracker: Option<crate::fs::growth::Tracker>,
}

/// Minimum spacing between a collector's first and second sample for meaningful rates.
const WARMUP: std::time::Duration = std::time::Duration::from_millis(500);

impl State {
    /// State with no backends attached (used by tests and as a fallback).
    #[allow(dead_code)]
    pub fn empty() -> State {
        State {
            collector: None,
            history: None,
            actions: None,
            config: Config::default(),
            last: None,
            samples: 0,
            fs: FsEngines::default(),
            allowed: Vec::new(),
            kill_tokens: Vec::new(),
        }
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
        let allowed = std::fs::read_to_string(Config::path()).map(|t| allowed_actions(&t)).unwrap_or_default();
        log(&if allowed.is_empty() {
            "side-effect tools disabled ([mcp] allow_actions not set)".to_string()
        } else {
            format!("side-effect tools enabled: {}", allowed.join(", "))
        });
        State {
            collector,
            history,
            actions,
            config,
            last,
            samples,
            fs: FsEngines::default(),
            allowed,
            kill_tokens: Vec::new(),
        }
    }

    fn scanner(&mut self) -> Result<&crate::fs::scan::Scanner> {
        if self.fs.scanner.is_none() {
            self.fs.scanner = guard(crate::fs::scan::Scanner::new);
        }
        self.fs.scanner.as_ref().ok_or_else(|| anyhow!("the storage scanner is unavailable"))
    }

    /// Current volumes. A fresh `Volumes` takes two samples 1s apart so I/O rates are real.
    fn volumes(&mut self) -> Result<Vec<crate::fs::Volume>> {
        if self.fs.volumes.is_none() {
            let mut v =
                guard(crate::fs::volumes::Volumes::new).ok_or_else(|| anyhow!("volume listing is unavailable"))?;
            // Fill rates need minutes of samples: take them from the recorder's history.
            if let Some(h) = self.history.as_ref() {
                let _ = guard(AssertUnwindSafe(|| h.seed_volumes(&mut v, crate::model::now_ms())));
            }
            guard(AssertUnwindSafe(|| v.sample())).ok_or_else(|| anyhow!("volume listing failed"))?;
            std::thread::sleep(Duration::from_millis(1000));
            self.fs.volumes = Some(v);
        }
        let v = self.fs.volumes.as_mut().expect("set above");
        match guard(AssertUnwindSafe(|| v.sample())) {
            Some(list) => Ok(list),
            None => {
                self.fs.volumes = None;
                bail!("volume listing failed")
            }
        }
    }

    /// Storage facts for doctor (volumes and deleted-but-open files); empty when unavailable.
    fn fs_facts(&mut self) -> crate::blame::FsFacts {
        crate::blame::FsFacts {
            volumes: self.volumes().unwrap_or_default(),
            growth: None,
            deleted_open: guard(crate::fs::volumes::deleted_open).unwrap_or_default(),
        }
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
            let mut snap = c.sample();
            // doctor/why name a VM's containers ("docker stop <its biggest>"); the list is
            // cached for 5s, so only the first call pays for `docker ps`.
            if snap.containers.is_empty() && self.config.containers && crate::blame::hosts_containers(&snap) {
                snap.containers = crate::fleet::containers();
            }
            self.last = Some((Instant::now(), snap));
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
        "tools/list" => Ok(json!({ "tools": tools_listed(&state.allowed) })),
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
    if ACTION_TOOLS.contains(&name) && !state.allowed.iter().any(|a| a == name) {
        return Ok(tool_result(json!({ "error": disabled_message(name), "disabled": true }), true));
    }
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
        "fs_volumes" => tool_fs_volumes,
        "fs_list" => tool_fs_list,
        "fs_largest" => tool_fs_largest,
        "fs_growth" => tool_fs_growth,
        // --- server mode: kernel ---
        "kernel" => tool_kernel,
        // --- server mode: services ---
        "services" => tool_services,
        // --- server mode: doctor-incident ---
        "events" => tool_events,
        "what_happened" => tool_what_happened,
        // --- server mode: fleet (read-only; bodies in src/fleet/cli.rs) ---
        "fleet_summary" => |s, a| crate::fleet::cli::mcp_fleet_summary(&s.config, a),
        "fleet_doctor" => |s, a| crate::fleet::cli::mcp_fleet_doctor(&s.config, a),
        "host_snapshot" => |s, a| crate::fleet::cli::mcp_host_snapshot(&s.config, a),
        "host_what_happened" => |s, a| crate::fleet::cli::mcp_host_what_happened(&s.config, a),
        _ => return None,
    })
}

fn pid_schema() -> Value {
    json!({ "type": "integer", "minimum": 1, "description": "Process id." })
}

/// Schema for an action target: pid plus the identity the agent saw, so a pid reused by
/// another process between `snapshot` and the action is refused instead of signalled.
fn target_schema(extra: Value) -> Value {
    let mut props = json!({
        "pid": pid_schema(),
        "start_time": { "type": "integer", "minimum": 0, "description": "The process's start_time (epoch seconds) exactly as returned by snapshot/process. Strongly recommended: the action is refused if the pid now belongs to a different process." },
        "name": { "type": "string", "description": "The process name as returned by snapshot/process; refused if the pid now runs something else." }
    });
    if let (Some(p), Some(e)) = (props.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            p.insert(k.clone(), v.clone());
        }
    }
    props
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
/// The catalog as `tools/list` serves it: every tool, with disabled side-effect tools marked
/// as such in their description (they stay listed so an agent can tell the user how to enable
/// one, rather than concluding fat cannot do it and reaching for a shell `kill`).
pub fn tools_listed(allowed: &[String]) -> Vec<Value> {
    let mut v = tools();
    for t in &mut v {
        let name = t["name"].as_str().unwrap_or_default().to_string();
        if ACTION_TOOLS.contains(&name.as_str()) && !allowed.contains(&name) {
            let d = t["description"].as_str().unwrap_or_default().to_string();
            t["description"] = json!(format!(
                "DISABLED in this fat (enable with `[mcp] allow_actions = [\"{name}\"]` in fat's config.toml; calling it returns how). {d}"
            ));
        }
    }
    v
}

pub fn tools() -> Vec<Value> {
    vec![
        tool(
            "snapshot",
            "System snapshot",
            "Current machine state: system totals (cpu %, memory, swap, memory pressure, thermal state and hottest temperature `temp_c`, GPU, power mW with `power_source`, \
             net/disk bytes/sec, battery, and on Linux `psi` pressure-stall percentages) plus the top processes. \
             Sort by cpu (default), mem, power, net or disk. CPU is per-core percent (100 = one core). Use `filter` to match a substring of the process name, command line, cgroup or container; \
             use `container` (name or id prefix) to list only the processes running inside one container. Processes in containers carry `container` (12-char id) and `container_name`.",
            schema(
                json!({
                    "sort": { "type": "string", "enum": ["cpu", "mem", "power", "net", "disk"], "default": "cpu", "description": "Ranking key for the process list." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 30, "description": "Max processes to return." },
                    "filter": { "type": "string", "description": "Case-insensitive substring matched against process name, command line, cgroup path and container name/id." },
                    "container": { "type": "string", "description": "Only processes inside this container: a container name (exact, case-insensitive) or an id prefix." }
                }),
                &[],
            ),
            false,
        ),
        tool(
            "process",
            "Process details",
            "Everything known about one process: full record (cmd, exe, cwd, user, cpu, mem, disk/net rates, power, threads, status, nice) plus its ancestor chain (names up to launchd / systemd / pid 1), child counts, and on Linux its cgroup and container.",
            schema(json!({ "pid": pid_schema() }), &["pid"]),
            false,
        ),
        tool(
            "ports",
            "Listening ports",
            "All TCP listeners and bound UDP sockets with owning pid/process and a human note. `orphan: true` marks dev-server-like listeners whose launching terminal/agent is gone (re-parented to launchd, init or a systemd user manager) — prime candidates for cleanup.",
            schema(
                json!({ "only_orphans": { "type": "boolean", "default": false, "description": "Return only orphaned listeners." } }),
                &[],
            ),
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
            schema(
                json!({ "port": { "type": "integer", "minimum": 1, "maximum": 65535, "description": "Port number." } }),
                &["port"],
            ),
            false,
        ),
        tool(
            "pause",
            "Pause process",
            "Freeze a process with SIGSTOP. Undoable (resume or undo) — prefer this over kill to test whether a process is the culprit. Refused for hubs (a VM/container host like OrbStack Helper, a container runtime or a container's pid 1, a browser's or app's main process: freezing one freezes everything it hosts; the refusal says what to act on instead) and for system/session daemons (launchd, WindowServer, cfprefsd on macOS; init, systemd, dbus, the display server on Linux, ...) that other apps block on. Pass `start_time` from snapshot so a reused pid is never hit. Returns an action record with an id for `undo`.",
            schema(target_schema(json!({})), &["pid"]),
            true,
        ),
        tool(
            "resume",
            "Resume process",
            "Continue a paused (stopped) process with SIGCONT. For a process-group leader (e.g. a job paused by `fat run`), its stopped group members are resumed too.",
            schema(target_schema(json!({})), &["pid"]),
            true,
        ),
        tool(
            "renice",
            "Change priority",
            "Set a process's nice value (-20 highest priority .. 20 lowest). Raising nice (deprioritizing) is allowed for your own processes; lowering usually needs root, so undoing a renice also needs root (the result's `undoable` says whether this one can be undone).",
            schema(
                target_schema(json!({
                    "nice": { "type": "integer", "minimum": -20, "maximum": 20, "description": "New nice value." }
                })),
                &["pid", "nice"],
            ),
            true,
        ),
        tool(
            "kill",
            "Terminate process",
            "Terminate a process with SIGTERM (graceful; a paused process is continued so it can act on it). `tree: true` terminates the process and all its descendants (SIGTERM, leaves first; it can't be combined with `force`); `force: true` sends SIGKILL instead. Refused for hubs (a VM/container host, runtime, container pid 1, browser or app main process), and a tree that contains one. NOT undoable — consider `pause` first. Two steps: a call without `confirm_token` signals nothing and returns a preview (target, signal, protection checks, the tree that would be hit) plus a `confirm_token` valid for 60 s; repeat the call with the same pid/tree/force and that token to execute. The token is single-use and bound to that process's start time, so a reused pid is refused; for a tree it is also bound to the previewed descendants, and processes that appeared since the preview are left alone. Journaled.",
            schema(
                target_schema(json!({
                    "tree": { "type": "boolean", "default": false, "description": "Also terminate all descendants." },
                    "force": { "type": "boolean", "default": false, "description": "Send SIGKILL instead of SIGTERM." },
                    "confirm_token": { "type": "string", "description": "Token from this call's preview; omit to get the preview." }
                })),
                &["pid"],
            ),
            true,
        ),
        tool(
            "undo",
            "Undo action",
            "Undo a previous pause or renice by its action id (resume / restore the nice value); without `id`, undoes the most recent undoable action. A kill can't be undone.",
            schema(
                json!({ "id": { "type": "integer", "minimum": 0, "description": "Action id returned by a previous action." } }),
                &[],
            ),
            true,
        ),
        tool(
            "containers",
            "Containers",
            "Running containers (docker, podman, OrbStack, colima, nerdctl/containerd) with 12-char id, name, image, runtime, status, cpu, memory and published ports. Empty if no container runtime is reachable. On Linux, pass a name or id to `snapshot {container}` to see its processes.",
            schema(json!({}), &[]),
            false,
        ),
        tool(
            "ask",
            "Ask in plain language",
            "Ask a plain-language question about this machine ('why is this machine slow?', 'what is using port 3000?', 'which container is eating memory?'). Answered from a fresh snapshot plus doctor findings.",
            schema(
                json!({ "question": { "type": "string", "minLength": 1, "description": "The question." } }),
                &["question"],
            ),
            false,
        ),
        tool(
            "fs_volumes",
            "Disk volumes",
            "Mounted volumes: mount, device, fstype, total/used/avail bytes, macOS purgeable bytes, inode use, read-only / network flags, \
             device read/write bytes/sec, `fill_bps` (bytes/sec the volume is filling; negative = freeing) and `eta_full_s` (seconds until full at that rate). \
             The first call takes ~1s to measure rates. Start here for 'my disk is full'.",
            schema(json!({}), &[]),
            false,
        ),
        tool(
            "fs_list",
            "Directory sizes",
            "Disk usage of a directory's children (like du), largest first: allocated `size` bytes (hard links once), `files` below, `newest_mtime` (epoch s), \
             `partial` (still being scanned: a lower bound), `denied` (unreadable subdirs: size unknown), `mount_point` (another filesystem, not counted). \
             `known` gives safe advice for well-known space hogs (caches, node_modules, Docker data). Reads cached scans first and scans up to `wait_seconds` otherwise. \
             Read-only: fat never deletes anything.",
            schema(
                json!({
                    "path": { "type": "string", "description": "Absolute directory path. Default \"/\"." },
                    "depth": { "type": "integer", "minimum": 1, "maximum": 4, "default": 1, "description": "Levels of children to include." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 30, "description": "Max children per directory (the rest are summarized)." },
                    "wait_seconds": { "type": "integer", "minimum": 0, "maximum": 120, "default": 10, "description": "If nothing is cached for `path`, scan for up to this long." }
                }),
                &[],
            ),
            false,
        ),
        tool(
            "fs_largest",
            "Largest files and dirs",
            "The `n` largest entries (files or directories, any depth) under `path`, without listing a directory next to the single child that explains it. \
             Uses the cached scan (scanning up to 15s if there is none).",
            schema(
                json!({
                    "path": { "type": "string", "description": "Absolute directory path." },
                    "n": { "type": "integer", "minimum": 1, "maximum": 200, "default": 20, "description": "How many entries." }
                }),
                &["path"],
            ),
            false,
        ),
        tool(
            "fs_growth",
            "What is eating disk space",
            "What grew in the last `since` (default 10m): per-volume used delta, the paths that grew most (`delta` bytes, rolled up to the deepest \
             directory that explains it) with the processes seen writing there, top writing processes, space held by deleted-but-still-open files \
             (restart the holder to free it), and `evidence` per path: fsevents (macOS journal, exact), watch (Linux inotify/fanotify, since fat started), \
             open_files (files a writer holds open), scan_diff (two scans compared), mtime (modified in the window; an upper bound). `notes` say what evidence was unavailable.",
            schema(
                json!({
                    "since": { "type": "string", "default": "10m", "description": "Window, e.g. 10m, 1h, 24h (max 7d)." },
                    "under": { "type": "string", "description": "Only paths below this absolute directory." }
                }),
                &[],
            ),
            false,
        ),
        // --- server mode: kernel ---
        tool(
            "kernel",
            "Kernel health (Linux)",
            "Linux kernel health over a 1 s interval plus recent kernel log events. Answers 'load is high but CPU is idle' (`procs_blocked`, `d_state_now` with the kernel \
             function each D-state process waits in), 'is it the hypervisor' (`steal_pct`), iowait/irq/softirq, PSI some/full, per-disk util/await/queue/iops, \
             fd / conntrack / ephemeral-port usage against their limits, TCP retransmits and listen-queue overflows, swap rates, OOM kills since boot, NUMA free memory, \
             filesystems that went read-only or logged errors, degraded md RAID, kernel taint and clock sync. `events` are classified kernel log lines \
             (oom_kill with victim, cgroup and rss; hung_task; disk_error; ro_remount; exhaustion; kernel_warn for lockups, oopses, segfaults). \
             The kernel log needs root (or kernel.dmesg_restrict=0); `notes` say what was unavailable. Read-only. Null `kernel` off Linux.",
            schema(
                json!({
                    "since": { "type": "string", "default": "24h", "description": "Kernel log events from this far back, e.g. 15m, 2h, 24h (max 30d)." },
                    "max_events": { "type": "integer", "minimum": 0, "maximum": 1000, "default": 50, "description": "Newest kernel log events to return." }
                }),
                &[],
            ),
            false,
        ),
        // --- server mode: services ---
        tool(
            "services",
            "Services (units, containers, pods)",
            "Services as the unit of thought: systemd units (services, scopes, and any failed unit), containers of any runtime, Kubernetes pods, and plain cgroups that hold processes. \
             Each has a normalised `state` (active/activating/deactivating/reloading/inactive/failed/unknown), `sub_state`, systemd `result` (exit-code, signal, oom-kill, start-limit-hit...) and `exit_code`, \
             lifetime `restarts`, `recent_restarts` and `flapping` (restarting repeatedly within the configured window), cgroup totals: `cpu` (100 = one core), `mem` / `mem_limit` / `mem_peak` bytes, \
             `oom_kills` (memory.events), `cpu_throttled_pct` (share of CPU periods throttled by its own cpu.max, a noisy-neighbour/undersized-limit sign), `cpu_quota` cores, io bytes/s and per-unit PSI. \
             Failed and flapping units sort first. `events` are transitions seen since the previous call (unit_failed, unit_restart, unit_flapping, oom_kill, throttle, exhaustion, deploy_burst). \
             `notes` say what was unavailable (no systemd, cgroup v1, names that need root). Read-only; on macOS only containers are listed.",
            schema(
                json!({
                    "failed": { "type": "boolean", "default": false, "description": "Only failed or flapping units." },
                    "kind": { "type": "string", "enum": ["systemd", "container", "k8s-pod", "cgroup"], "description": "Only units of this kind." },
                    "filter": { "type": "string", "description": "Case-insensitive substring of the unit name, description or cgroup." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "default": 200, "description": "Max units to return (failed/flapping first)." }
                }),
                &[],
            ),
            false,
        ),
        // --- server mode: doctor-incident ---
        tool(
            "events",
            "Event timeline",
            "What happened on this host, in time order: oom_kill (victim, cgroup, rss), unit_failed / unit_restart / unit_flapping / unit_start / unit_stop, deploy_burst \
             (many processes started in one unit), proc_spike, disk_latency_spike, disk_error, fs_fill, ro_remount, kernel_warn, hung_task, throttle (cpu.max), \
             pressure_spike (PSI), exhaustion (fds, conntrack, ephemeral ports, memory.max) and clock_unsynced. Each event has ts (epoch ms), severity, subject \
             (`unit:`, `container:`, `pod:`, `disk:`, `mount:`, `kernel`, `host`), unit, pid, a one-line detail and a value. From the flight recorder when it covers \
             the window (`source: recorder`); otherwise the current unit/kernel state plus the kernel log (`source: live`), with `gaps` saying what is missing. Read-only.",
            schema(
                json!({
                    "since": { "type": "string", "default": "2h", "description": "How far back: a duration (30m, 2h, 1d) or a time (03:00, 2026-11-10 03:00, RFC 3339). Max 31d." },
                    "kinds": { "type": "array", "items": { "type": "string" }, "description": "Only these event kinds (e.g. [\"oom_kill\", \"unit_failed\"]); empty = all." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 10000, "default": 300, "description": "Newest events to return." }
                }),
                &[],
            ),
            false,
        ),
        tool(
            "what_happened",
            "What happened and who did it",
            "Explain an incident: \"what happened at 03:12 and who did it?\". Picks the most important event in the window (or near `at`) and returns a causal `chain` \
             (symptom first, cause last), `culprits` (unit/process/kernel/external with the numbers that implicate them), `evidence` (including a confidence \
             level), read-only `suggestions` (journalctl/systemctl/docker/kubectl commands for a human or agent to run; fat runs none of them), the window's `events` \
             and `gaps` (missing recorder data, unreadable kernel log). Covers OOM kills (who held the memory at that moment, host-wide vs cgroup limit), restart \
             loops and failed units (exit status, OOM, package updates or deploys just before), load-high-but-CPU-idle (D state, iowait, steal), disk latency \
             (the unit whose I/O rose and the job that started it: backup, cron/timer, deploy), fs filling, fd/conntrack/port exhaustion and noisy neighbours \
             (cpu.max throttling, PSI). `text` is the same as plain text. Read-only.",
            schema(
                json!({
                    "at": { "type": "string", "description": "Moment of interest: 03:12, 03:12:30, 2026-11-10 03:12, RFC 3339, epoch seconds, -2h or '2h ago'. Omit for 'the last `window`'." },
                    "window": { "type": "string", "default": "15m", "description": "How much time before `at` (or now) to examine, e.g. 15m, 1h. Max 31d." }
                }),
                &[],
            ),
            false,
        ),
        // --- server mode: fleet ---
        tool(
            "fleet_summary",
            "Fleet health summary",
            "Poll every configured fleet host (or a selection) over ssh, read-only, in parallel, and summarise: per-host health 0-100 (worst first), cpu/mem/load/worst disk, \
             failed units, OOM kills in 24h, findings aggregated by title across hosts (`Disk / is #% full: 12 hosts [...]`), hosts that could not be polled grouped by \
             reason (unreachable, auth, host-key, fat-missing, timeout), and outliers far from their group's median. Results are reused for fleet.cache_ttl_s unless `refresh`. \
             The best first call for 'is anything wrong across my servers?'.",
            schema(
                json!({
                    "group": { "type": "string", "description": "Only hosts in this inventory group." },
                    "tag": { "type": "string", "description": "Only hosts with this tag." },
                    "host": { "type": "string", "description": "Only hosts whose name matches this glob (web-*)." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 10000, "default": 50, "description": "Max host rows returned (findings always cover every host)." },
                    "refresh": { "type": "boolean", "default": false, "description": "Poll again even if a recent result is cached." }
                }),
                &[],
            ),
            false,
        ),
        tool(
            "fleet_doctor",
            "Fleet diagnosis",
            "Findings for every selected fleet host, computed locally with this fat's rules from each host's snapshot: aggregated fleet findings, outliers, then hosts with \
             warn/crit findings (worst first) with title, detail and involved pids. Read-only; suggested actions are advice for the host's operator.",
            schema(
                json!({
                    "group": { "type": "string", "description": "Only hosts in this inventory group." },
                    "tag": { "type": "string", "description": "Only hosts with this tag." },
                    "host": { "type": "string", "description": "Only hosts whose name matches this glob." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 10000, "default": 20, "description": "Max hosts with findings returned." },
                    "refresh": { "type": "boolean", "default": false, "description": "Poll again even if a recent result is cached." }
                }),
                &[],
            ),
            false,
        ),
        tool(
            "host_snapshot",
            "One fleet host's state",
            "Read-only snapshot of one fleet host (exact inventory name): system totals, top processes by cpu and memory, failed or flapping units, kernel health, recent \
             events, and findings. Use after fleet_summary/fleet_doctor points at a host.",
            schema(
                json!({
                    "host": { "type": "string", "description": "Exact inventory host name." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 25, "description": "Processes per top list." }
                }),
                &["host"],
            ),
            false,
        ),
        tool(
            "host_what_happened",
            "Incident on one fleet host",
            "'What happened at TIME on HOST and who did it?': runs the host's own `fat what-happened` (from its flight recorder, falling back to live state) and returns the \
             incident: headline, causal chain, evidence, ranked culprits, read-only suggestions, events and data gaps. `at` is read on this machine's clock and timezone.",
            schema(
                json!({
                    "host": { "type": "string", "description": "Exact inventory host name." },
                    "at": { "type": "string", "description": "03:12, '2026-01-31 03:12', RFC 3339, -2h or '2h ago'. Default: the most severe recent event." },
                    "window": { "type": "string", "default": "15m", "description": "Window examined around `at`, e.g. 15m, 1h." }
                }),
                &["host"],
            ),
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
#[cfg(test)]
fn top_procs<'a>(procs: &'a [Proc], sort: &str, limit: usize, filter: Option<&str>) -> (usize, Vec<&'a Proc>) {
    top_procs_in(procs, &[], sort, limit, filter, None)
}

/// [`top_procs`] that can also match containers: `filter` additionally matches cgroup path and
/// container id/name; `container` keeps only processes in containers whose name equals it
/// (case-insensitive) or whose id starts with it.
fn top_procs_in<'a>(
    procs: &'a [Proc],
    containers: &[Container],
    sort: &str,
    limit: usize,
    filter: Option<&str>,
    container: Option<&str>,
) -> (usize, Vec<&'a Proc>) {
    let needle = filter.map(str::to_lowercase).filter(|s| !s.is_empty());
    let want = container.map(|c| c.trim().to_lowercase()).filter(|s| !s.is_empty());
    let ctr_name = |p: &Proc| {
        p.container
            .as_deref()
            .and_then(|id| crate::fleet::find_container(containers, id))
            .map(|c| c.name.to_lowercase())
    };
    let mut v: Vec<&Proc> = procs
        .iter()
        .filter(|p| match &needle {
            Some(n) => {
                p.name.to_lowercase().contains(n)
                    || p.cmd.to_lowercase().contains(n)
                    || p.cgroup.to_lowercase().contains(n)
                    || p.container.as_deref().is_some_and(|id| id.contains(n.as_str()))
                    || ctr_name(p).is_some_and(|c| c.contains(n.as_str()))
            }
            None => true,
        })
        .filter(|p| match (&want, p.container.as_deref()) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(w), Some(id)) => id.starts_with(w.as_str()) || ctr_name(p).is_some_and(|c| &c == w),
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
        v["hint"] = json!(format!("undoable: call undo with id {}", r.id));
    } else if r.ok && matches!(r.kind, ActionKind::Term | ActionKind::Kill | ActionKind::KillTree) {
        v["hint"] = json!("not undoable: the signal has been delivered");
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
    let container = arg_str(args, "container")?.map(str::trim).filter(|c| !c.is_empty());
    let snap = state.snapshot()?;
    // Container names only matter when some process is in a container (Linux cgroups) or the
    // caller asked for one; fleet::containers() is cached, so this is cheap after the first call.
    let in_containers = snap.procs.iter().any(|p| p.container.is_some());
    let containers = if !snap.containers.is_empty() {
        snap.containers.clone()
    } else if in_containers || container.is_some() {
        crate::fleet::containers()
    } else {
        Vec::new()
    };
    let snap = &state.last.as_ref().expect("snapshot cached").1;
    Ok(snapshot_value(snap, &containers, sort, limit, filter, container))
}

/// The `snapshot` tool's result (pure, for tests).
fn snapshot_value(
    snap: &Snapshot,
    containers: &[Container],
    sort: &str,
    limit: usize,
    filter: Option<&str>,
    container: Option<&str>,
) -> Value {
    let (matched, procs) = top_procs_in(&snap.procs, containers, sort, limit, filter, container);
    let procs: Vec<Value> = procs
        .into_iter()
        .map(|p| {
            let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
            // Secrets in command lines (other users' too) never go to the agent.
            v["cmd"] = json!(crate::ask::redact_cmd(&p.cmd));
            if let Some(c) = p.container.as_deref().and_then(|id| crate::fleet::find_container(containers, id))
                && !c.name.is_empty()
            {
                v["container_name"] = json!(c.name);
            }
            v
        })
        .collect();
    let s = &snap.system;
    let mut out = json!({
        "ts": snap.ts,
        "host": snap.host,
        "system": s,
        "sort": sort,
        "total_procs": snap.procs.len(),
        "matched_procs": matched,
        "procs": procs,
        "listening_ports": snap.ports.len(),
        "orphan_ports": snap.ports.iter().filter(|p| p.orphan).count(),
        // Also inside `system`; repeated at the top level (null when unavailable) so agents
        // can rely on the keys being present on every platform.
        "psi": s.psi,
        "temp_c": s.temp_c,
        "power_source": s.power_source,
    });
    if let Some(c) = container {
        out["container"] = json!(c);
        if let Some(found) = containers
            .iter()
            .find(|x| x.name.eq_ignore_ascii_case(c) || (!x.id.is_empty() && x.id.starts_with(&c.to_lowercase())))
        {
            out["container_info"] = json!(found);
        }
        if matched == 0 {
            out["note"] = json!(if snap.procs.iter().any(|p| p.container.is_some()) {
                "no process matches that container; see the `containers` tool for names and ids"
            } else {
                "no process is attributed to any container on this machine (needs Linux with cgroups v2 and a host pid namespace view)"
            });
        }
    }
    out
}

fn tool_process(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    let snap = state.snapshot()?;
    let p = snap.proc(pid).with_context(|| format!("no process with pid {pid}"))?;
    let ancestors: Vec<Value> = snap.ancestors(pid).iter().map(|a| json!({ "pid": a.pid, "name": a.name })).collect();
    let children = snap.procs.iter().filter(|c| c.ppid == pid && c.pid != pid).count();
    let descendants = snap.descendants(pid).len();
    let ports: Vec<_> = snap.ports.iter().filter(|x| x.pid == pid).collect();
    let containers = if p.container.is_some() && snap.containers.is_empty() {
        crate::fleet::containers()
    } else {
        snap.containers.clone()
    };
    let container = p.container.as_deref().and_then(|id| crate::fleet::find_container(&containers, id));
    let mut process = serde_json::to_value(p)?;
    process["cmd"] = json!(crate::ask::redact_cmd(&p.cmd));
    Ok(json!({
        "process": process,
        "container_info": container,
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
    let facts = state.fs_facts();
    let mut snap = state.last.as_ref().expect("snapshot cached").1.clone();
    // doctor-incident: server profile adds unit, kernel and event findings.
    crate::server::rules::fill_for_doctor(&state.config.server, &mut snap);
    let findings = crate::blame::diagnose_with_fs(&snap, state.history.as_ref(), &facts);
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

/// The identity the agent saw when it chose the target (optional `start_time` / `name` args).
fn arg_expect(args: &Value) -> Result<Option<crate::actions::Expect>> {
    let start_time = arg_u64(args, "start_time")?.filter(|&s| s != 0);
    let name = arg_str(args, "name")?.filter(|n| !n.is_empty()).map(str::to_string);
    Ok((start_time.is_some() || name.is_some()).then_some(crate::actions::Expect { start_time, name }))
}

fn apply(state: &mut State, kind: ActionKind, pid: u32, nice: Option<i32>, args: &Value) -> Result<Value> {
    let expect = arg_expect(args)?;
    state.snapshot()?;
    let snap = state.last.as_ref().expect("snapshot cached").1.clone();
    if snap.proc(pid).is_none() {
        bail!("no process with pid {pid}");
    }
    let r = state.actions()?.apply_expect(kind, pid, nice, &snap, expect.as_ref());
    // Force a fresh sample next call so status changes are visible.
    state.last = None;
    action_result(r)
}

fn tool_pause(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    let snap = state.snapshot()?;
    let (refusal, _) = hub_check(snap, ActionKind::Pause, pid);
    if let Some(r) = refusal {
        bail!("Pause {pid} refused: {r}");
    }
    apply(state, ActionKind::Pause, pid, None, args)
}

/// blame's hub gate for an agent's Pause/Term/Kill/KillTree: (refusal, warning). A hard hub
/// (VM/container host, runtime, container pid 1, init, browser/app main process, display,
/// kernel) is refused, and so is a tree with one inside; a session hub only warns.
fn hub_check(snap: &Snapshot, kind: ActionKind, pid: u32) -> (Option<String>, Option<String>) {
    if !matches!(kind, ActionKind::Pause | ActionKind::Term | ActionKind::Kill | ActionKind::KillTree) {
        return (None, None);
    }
    let verb = if kind == ActionKind::Pause { "freezes" } else { "ends" };
    match crate::blame::hub_gate(snap, pid) {
        Some(g) if g.hard => {
            return (
                Some(format!("{}; {kind:?} {verb} everything it hosts. Not offered to agents: tell the user", g.note)),
                None,
            );
        }
        Some(g) => return (None, Some(g.note)),
        None => {}
    }
    if kind == ActionKind::KillTree
        && let Some((d, g)) = crate::blame::hub_in_tree(snap, pid)
    {
        return (
            Some(format!("its tree contains pid {d}: {}; end the specific job instead of the whole tree", g.note)),
            None,
        );
    }
    (None, None)
}

/// `snap` minus the descendants of `pid` that are not in the previewed `tree` (same pid and
/// start time), so a tree kill signals only what the preview showed.
fn restrict_tree(snap: &Snapshot, pid: u32, tree: &[(u32, u64)]) -> (Snapshot, Vec<u32>) {
    let drop: std::collections::HashSet<u32> = snap
        .descendants(pid)
        .into_iter()
        .filter(|d| {
            !tree
                .iter()
                .any(|&(tp, ts)| tp == d.pid && (ts == 0 || d.start_time == 0 || ts.abs_diff(d.start_time) <= 2))
        })
        .map(|d| d.pid)
        .collect();
    let mut out = snap.clone();
    out.procs.retain(|p| !drop.contains(&p.pid));
    let mut new: Vec<u32> = drop.into_iter().collect();
    new.sort_unstable();
    (out, new)
}

fn tool_resume(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    apply(state, ActionKind::Resume, pid, None, args)
}

fn tool_renice(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    let nice = arg_i64(args, "nice")?.context("`nice` is required")?;
    if !(-20..=20).contains(&nice) {
        bail!("`nice` must be in -20..=20");
    }
    apply(state, ActionKind::Renice, pid, Some(nice as i32), args)
}

fn tool_kill(state: &mut State, args: &Value) -> Result<Value> {
    let pid = arg_pid(args)?;
    if arg_bool(args, "tree")? && arg_bool(args, "force")? {
        bail!(
            "`tree` and `force` can't be combined: a tree kill sends SIGTERM leaves-first. Kill the tree, then `force` any pid that survives"
        );
    }
    let kind = if arg_bool(args, "tree")? {
        ActionKind::KillTree
    } else if arg_bool(args, "force")? {
        ActionKind::Kill
    } else {
        ActionKind::Term
    };
    state.kill_tokens.retain(|t| t.issued.elapsed() < KILL_TOKEN_TTL);
    match arg_str(args, "confirm_token")?.map(str::trim).filter(|t| !t.is_empty()) {
        None => kill_preview(state, kind, pid, args),
        Some(tok) => {
            // Single use: the token is consumed whatever happens next.
            let i = state
                .kill_tokens
                .iter()
                .position(|t| t.token == tok)
                .context("unknown or expired confirm_token: call kill without it for a fresh preview")?;
            let t = state.kill_tokens.remove(i);
            if t.pid != pid || t.kind != kind {
                bail!(
                    "confirm_token was issued for {:?} of pid {}, not {kind:?} of pid {pid}: call kill without it for a fresh preview",
                    t.kind,
                    t.pid
                );
            }
            // The process must still be the one previewed (start time), plus any identity the caller passes.
            let mut expect = arg_expect(args)?.unwrap_or_default();
            if t.start_time.is_some() {
                expect.start_time = t.start_time;
            }
            let expect = (expect.start_time.is_some() || expect.name.is_some()).then_some(expect);
            state.snapshot()?;
            let snap = state.last.as_ref().expect("snapshot cached").1.clone();
            if snap.proc(pid).is_none() {
                bail!("no process with pid {pid}");
            }
            // Re-checked at execute: the tree may have grown a hub since the preview.
            let (snap, unseen) =
                if kind == ActionKind::KillTree { restrict_tree(&snap, pid, &t.tree) } else { (snap, Vec::new()) };
            if let (Some(r), _) = hub_check(&snap, kind, pid) {
                bail!("{kind:?} {pid} refused: {r}");
            }
            let mut r = state.actions()?.apply_expect(kind, pid, None, &snap, expect.as_ref());
            state.last = None;
            if !unseen.is_empty() {
                r.message =
                    format!("{}; left alone {} process(es) not in the preview: {unseen:?}", r.message, unseen.len());
            }
            action_result(r)
        }
    }
}

/// First kill call: what would happen, and a token to make it happen. Signals nothing.
fn kill_preview(state: &mut State, kind: ActionKind, pid: u32, args: &Value) -> Result<Value> {
    let expect = arg_expect(args)?;
    state.snapshot()?;
    let snap = state.last.as_ref().expect("snapshot cached").1.clone();
    let Some(p) = snap.proc(pid) else { bail!("no process with pid {pid}") };
    let pv = crate::actions::preview(kind, pid, &snap, expect.as_ref());
    let signal = if kind == ActionKind::Kill { "SIGKILL" } else { "SIGTERM" };
    let mut v = json!({
        "preview": true,
        "would_signal": { "pid": pid, "name": p.name, "cmd": crate::ask::redact_cmd(&p.cmd), "user": p.user, "start_time": pv.start_time.unwrap_or(p.start_time), "signal": signal, "tree": kind == ActionKind::KillTree },
        "ancestors": snap.ancestors(pid).iter().map(|a| json!({ "pid": a.pid, "name": a.name })).collect::<Vec<_>>(),
        "undoable": false,
    });
    if kind == ActionKind::KillTree {
        v["descendants"] = json!(
            pv.tree
                .iter()
                .map(|(cpid, name, skip)| {
                    let mut d = json!({ "pid": cpid, "name": name });
                    if let Some(why) = skip {
                        d["skipped"] = json!(why);
                    }
                    d
                })
                .collect::<Vec<_>>()
        );
    }
    let (hub_refusal, hub_warning) = hub_check(&snap, kind, pid);
    let refusal = match (pv.refusal, hub_refusal) {
        (Some(a), Some(b)) => Some(format!("{a}; and {b}")),
        (a, b) => a.or(b),
    };
    if let Some(r) = refusal {
        v["refused"] = json!(r);
        v["note"] = json!("fat would refuse this; no token issued");
        return Ok(v);
    }
    let warning: Vec<String> = pv.warning.into_iter().chain(hub_warning).collect();
    if !warning.is_empty() {
        v["warning"] = json!(warning.join("; "));
    }
    let token = new_token(pid);
    let tree: Vec<(u32, u64)> = if kind == ActionKind::KillTree {
        pv.tree.iter().map(|(cpid, _, _)| (*cpid, snap.proc(*cpid).map_or(0, |c| c.start_time))).collect()
    } else {
        Vec::new()
    };
    state.kill_tokens.push(KillToken {
        token: token.clone(),
        pid,
        start_time: pv.start_time.or((p.start_time != 0).then_some(p.start_time)),
        kind,
        issued: Instant::now(),
        tree,
    });
    v["confirm_token"] = json!(token);
    v["expires_in_s"] = json!(KILL_TOKEN_TTL.as_secs());
    v["next"] = json!(format!(
        "This cannot be undone. To proceed, call kill again with pid {pid}{} and confirm_token. Consider `pause` first.",
        match kind {
            ActionKind::KillTree => ", tree: true",
            ActionKind::Kill => ", force: true",
            _ => "",
        }
    ));
    Ok(v)
}

/// 128 random bits from the OS (hex), falling back to time and pid mixing if /dev/urandom is
/// unreadable. Unguessable enough for a 60-second, single-use, same-process confirmation.
fn new_token(pid: u32) -> String {
    use std::io::Read;
    let mut b = [0u8; 16];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_err() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let x = t ^ ((pid as u128) << 64) ^ (std::process::id() as u128);
        b = x.to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
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
    let storage =
        crate::ask::wants_storage(&q).then(|| crate::ask::gather_storage(&q, state.config.history_path.as_deref()));
    let answer = crate::ask::ask(&q, snap, &findings, storage.as_ref(), &state.config.ask);
    Ok(json!({ "question": q, "answer": answer, "findings": findings }))
}

// ---------------------------------------------------------------------------
// Storage tools
// ---------------------------------------------------------------------------

/// An absolute path argument ("/" when absent and `default_root`).
fn arg_path(args: &Value, key: &str, default_root: bool) -> Result<String> {
    let p = match arg_str(args, key)?.map(str::trim) {
        Some(p) if !p.is_empty() => p,
        _ if default_root => "/",
        _ => bail!("`{key}` is required"),
    };
    if !p.starts_with('/') {
        bail!("`{key}` must be an absolute path (got {p:?})");
    }
    if p.split('/').any(|c| c == "..") {
        bail!("`{key}` must not contain `..`");
    }
    Ok(if p.len() > 1 { p.trim_end_matches('/').to_string() } else { p.to_string() })
}

/// Compact JSON for one entry: zero/false flags are left out.
pub fn entry_json(e: &crate::fs::DirEntry) -> Value {
    let mut v = json!({ "name": e.name, "path": e.path, "size": e.size, "files": e.files });
    if e.is_dir {
        v["dir"] = json!(true);
    }
    if e.apparent > 0 && e.apparent != e.size {
        v["apparent"] = json!(e.apparent);
    }
    if e.newest_mtime > 0 {
        v["newest_mtime"] = json!(e.newest_mtime);
    }
    if e.denied > 0 {
        v["denied"] = json!(e.denied);
    }
    if e.mount_point {
        v["mount_point"] = json!(true);
    }
    if e.partial {
        v["partial"] = json!(true);
    }
    if let Some(k) = crate::blame::explain_path(&e.path).filter(|k| !k.starts_with("inside ")) {
        v["known"] = json!(k);
    }
    v
}

/// A listing as JSON, recursing `depth - 1` more levels through `list` (cache lookups), at most
/// `limit` children per directory; the rest are summarized as `more`.
pub fn listing_json(
    l: &crate::fs::Listing,
    depth: usize,
    limit: usize,
    list: &mut dyn FnMut(&str) -> Option<crate::fs::Listing>,
) -> Value {
    let mut out = entry_json(&l.dir);
    let mut kids = Vec::new();
    for c in l.children.iter().take(limit) {
        let mut v = entry_json(c);
        if depth > 1
            && c.is_dir
            && !c.mount_point
            && c.size > 0
            && let Some(sub) = list(&c.path)
        {
            let s = listing_json(&sub, depth - 1, limit, list);
            v["children"] = s["children"].clone();
            if let Some(m) = s.get("more") {
                v["more"] = m.clone();
            }
        }
        kids.push(v);
    }
    out["children"] = Value::Array(kids);
    if l.children.len() > limit {
        let rest = &l.children[limit..];
        out["more"] = json!({ "count": rest.len(), "size": rest.iter().map(|c| c.size).sum::<u64>() });
    }
    let (files, bytes) = unlisted(l);
    if !l.dir.partial && bytes > 0 && files > 0 {
        // Loose files not listed by name: so the children add up to the directory.
        out["other_files"] = json!({ "count": files, "size": bytes });
    }
    out
}

/// A listing with its children: the scanner keeps small completed subtrees folded (size
/// only) and the background walk does not keep loose files by name, so such a directory is
/// re-read (just itself) for up to `wait_ms` to list them.
pub fn list_expanded(sc: &crate::fs::scan::Scanner, path: &str, wait_ms: u64) -> Option<crate::fs::Listing> {
    let l = sc.list(path)?;
    if l.dir.is_dir && !l.dir.partial {
        return sc.expand(path, wait_ms).or(Some(l));
    }
    Some(l)
}

/// Bytes and files of `l.dir` that no listed child accounts for (loose files not listed by
/// name, the directory's own inode): (files, bytes).
pub fn unlisted(l: &crate::fs::Listing) -> (u64, u64) {
    let kids: u64 = l.children.iter().filter(|c| !c.mount_point).map(|c| c.size).sum();
    let files: u64 = l.children.iter().filter(|c| !c.mount_point).map(|c| c.files).sum();
    (l.dir.files.saturating_sub(files), l.dir.size.saturating_sub(kids))
}

/// Why `path` cannot be listed, if it is missing or not a directory/file we can stat.
pub fn path_problem(path: &str) -> Option<String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(format!("{path}: no such file or directory")),
        Err(e) => Some(format!("{path}: {e}")),
    }
}

/// Hint for a directory that could not be read.
pub fn unreadable_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "permission denied or blocked by macOS privacy: grant your terminal Full Disk Access, or check the dir's permissions"
    } else {
        "permission denied: run fat as the directory's owner or as root"
    }
}

fn progress_json(p: &crate::fs::ScanProgress) -> Value {
    json!({
        "root": p.root, "running": p.running, "files_seen": p.files_seen, "bytes_seen": p.bytes_seen,
        "fraction": p.fraction, "completed_at": p.completed_at, "errors": p.errors,
    })
}

fn tool_fs_volumes(state: &mut State, _args: &Value) -> Result<Value> {
    let vols = state.volumes()?;
    Ok(json!({ "count": vols.len(), "volumes": vols }))
}

fn tool_fs_list(state: &mut State, args: &Value) -> Result<Value> {
    let path = arg_path(args, "path", true)?;
    let depth = arg_u64(args, "depth")?.unwrap_or(1);
    if !(1..=4).contains(&depth) {
        bail!("`depth` must be 1..=4");
    }
    let limit = arg_u64(args, "limit")?.unwrap_or(30).clamp(1, 200) as usize;
    let wait = arg_u64(args, "wait_seconds")?.unwrap_or(10).min(120);
    if let Some(p) = path_problem(&path) {
        bail!("{p}");
    }
    let sc = state.scanner()?.clone();
    // The agent asked for this path: that is explicit intent (a protected dir or a mount
    // the background walk skipped is read now).
    sc.ensure(&path, true);
    let l = match sc.list(&path) {
        Some(l) if !l.dir.partial => list_expanded(&sc, &path, wait * 1000),
        _ => sc.scan_blocking(&path, wait * 1000),
    };
    let Some(l) = l else {
        bail!("nothing measured under {path} yet: the scan is still running; retry with a larger `wait_seconds`");
    };
    if l.dir.denied > 0 && l.dir.files == 0 && l.children.is_empty() {
        bail!("{path}: could not be read ({})", unreadable_hint());
    }
    let mut lookup = |p: &str| list_expanded(&sc, p, 3000);
    let mut v = listing_json(&l, depth as usize, limit, &mut lookup);
    v["progress"] = progress_json(&l.progress);
    Ok(v)
}

fn tool_fs_largest(state: &mut State, args: &Value) -> Result<Value> {
    let path = arg_path(args, "path", false)?;
    let n = arg_u64(args, "n")?.unwrap_or(20);
    if !(1..=200).contains(&n) {
        bail!("`n` must be 1..=200");
    }
    if let Some(p) = path_problem(&path) {
        bail!("{p}");
    }
    let sc = state.scanner()?.clone();
    let mut v = sc.largest(&path, n as usize);
    if v.is_empty() {
        sc.ensure(&path, true);
        let l = sc.scan_blocking(&path, 15_000);
        v = sc.largest(&path, n as usize);
        if v.is_empty() && l.as_ref().is_some_and(|l| l.dir.denied > 0 && l.dir.files == 0) {
            bail!("{path}: could not be read ({})", unreadable_hint());
        }
    }
    Ok(json!({ "path": path, "count": v.len(), "entries": v.iter().map(entry_json).collect::<Vec<_>>() }))
}

/// Concise growth JSON: top entries of each list.
pub fn growth_json(g: &crate::fs::Growth, window_ms: i64) -> Value {
    let growers: Vec<Value> = g
        .growers
        .iter()
        .take(25)
        .map(|x| {
            let mut v = json!({ "path": x.path, "delta": x.delta, "size": x.size, "evidence": x.evidence });
            if x.is_dir {
                v["dir"] = json!(true);
            }
            if x.other {
                // Only what the growers listed below this path leave unexplained.
                v["other_under"] = json!(true);
            }
            if x.files_touched > 0 {
                v["files_touched"] = json!(x.files_touched);
            }
            if !x.writers.is_empty() {
                v["writers"] = json!(
                    x.writers
                        .iter()
                        .map(|(p, n, b)| json!({ "pid": p, "name": n, "write_bps": b }))
                        .collect::<Vec<_>>()
                );
            }
            v
        })
        .collect();
    // Deleted-but-open files by the process holding them; files under 1 MB only counted.
    let (groups, small, small_bytes) =
        crate::tui::widgets::group_deleted(&g.deleted_open, crate::tui::widgets::DELETED_MIN_BYTES);
    let deleted = json!({
        "by_process": groups.iter().take(10).map(|d| json!({ "pid": d.pid, "name": d.name, "files": d.files, "bytes": d.bytes, "biggest": d.biggest })).collect::<Vec<_>>(),
        "small_files": small,
        "small_bytes": small_bytes,
    });
    json!({
        "from_ts": g.from,
        "to_ts": g.to,
        "window_s": window_ms / 1000,
        "volumes": g.volumes.iter().map(|(m, d)| json!({ "mount": m, "delta": d })).collect::<Vec<_>>(),
        "growers": growers,
        "writers": g.writers.iter().take(10).map(|(p, n, b)| json!({ "pid": p, "name": n, "bytes": b })).collect::<Vec<_>>(),
        "deleted_open": deleted,
        "notes": g.notes,
    })
}

// --- server mode: services ---
fn tool_services(state: &mut State, args: &Value) -> Result<Value> {
    use crate::server::services as svc;
    let failed = args.get("failed").and_then(Value::as_bool).unwrap_or(false);
    let kind = match arg_str(args, "kind")? {
        Some(k) => {
            Some(svc::parse_kind(k).ok_or_else(|| anyhow!("`kind` must be systemd, container, k8s-pod or cgroup"))?)
        }
        None => None,
    };
    let needle = arg_str(args, "filter")?.map(str::to_lowercase).filter(|s| !s.is_empty());
    let limit = arg_u64(args, "limit")?.unwrap_or(200).clamp(1, 5000) as usize;
    if !cfg!(target_os = "linux") && state.config.containers {
        let _ = crate::fleet::containers();
    }
    let procs = state.snapshot().map(|s| s.procs.clone()).unwrap_or_default();
    let (units, notes, events) = svc::shared_sample(&state.config.server, &procs);
    let total = units.len();
    let failed_n = units.iter().filter(|u| u.is_failed()).count();
    let flapping_n = units.iter().filter(|u| u.flapping).count();
    let mut units = svc::filter(units, failed, kind);
    if let Some(n) = &needle {
        units.retain(|u| {
            u.name.to_lowercase().contains(n)
                || u.description.to_lowercase().contains(n)
                || u.cgroup.to_lowercase().contains(n)
        });
    }
    let matched = units.len();
    units.truncate(limit);
    Ok(
        json!({ "total": total, "failed": failed_n, "flapping": flapping_n, "matched": matched, "units": units, "events": events, "notes": notes }),
    )
}

// --- server mode: doctor-incident ---
fn tool_events(state: &mut State, args: &Value) -> Result<Value> {
    use crate::server::incident as inc;
    let now = now_ms();
    let from = inc::parse_since(arg_str(args, "since")?.unwrap_or("2h"), now).map_err(|e| anyhow!("`since`: {e}"))?;
    let kinds: Vec<String> = match args.get("kinds") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a
            .iter()
            .map(|k| k.as_str().map(str::to_string).ok_or_else(|| anyhow!("`kinds` must be an array of strings")))
            .collect::<Result<_>>()?,
        Some(Value::String(k)) => vec![k.clone()],
        Some(_) => bail!("`kinds` must be an array of strings"),
    };
    let kinds = inc::parse_kinds(&kinds)?;
    let limit = arg_u64(args, "limit")?.unwrap_or(300).clamp(1, 10_000) as usize;
    let (source, events, gaps) = inc::events_report(&state.config, from, &kinds, limit);
    Ok(json!({ "source": source, "from": from, "to": now, "count": events.len(), "events": events, "gaps": gaps }))
}

fn tool_what_happened(state: &mut State, args: &Value) -> Result<Value> {
    let inc = crate::server::incident::what_happened_for(
        &state.config,
        arg_str(args, "at")?,
        arg_str(args, "window")?.unwrap_or("15m"),
    )?;
    let mut v = serde_json::to_value(&inc)?;
    v["text"] = json!(crate::server::incident::render(&inc));
    Ok(v)
}

// --- server mode: kernel ---
fn tool_kernel(state: &mut State, args: &Value) -> Result<Value> {
    let since = arg_str(args, "since")?.unwrap_or("24h");
    let secs = crate::budget::parse_duration(since).map_err(|e| anyhow!("`since`: {e}"))?;
    if secs == 0 || secs > 30 * 86_400 {
        bail!("`since` must be between 1s and 30d");
    }
    let max = args.get("max_events").and_then(Value::as_u64).unwrap_or(50).min(1000) as usize;
    let procs = state.snapshot().map(|s| s.procs.clone()).unwrap_or_default();
    let r = crate::server::kernel::report(
        &state.config.server,
        &procs,
        &[],
        std::time::Duration::from_secs(1),
        crate::model::now_ms() - secs as i64 * 1000,
        max,
    );
    Ok(serde_json::to_value(r)?)
}

fn tool_fs_growth(state: &mut State, args: &Value) -> Result<Value> {
    let since = arg_str(args, "since")?.unwrap_or("10m");
    let secs = crate::budget::parse_duration(since).map_err(|e| anyhow!("`since`: {e}"))?;
    if secs == 0 || secs > 7 * 86_400 {
        bail!("`since` must be between 1s and 7d");
    }
    let under = match args.get("under") {
        None | Some(Value::Null) => None,
        _ => Some(arg_path(args, "under", false)?),
    };
    // Recent per-process write rates make the open-file attribution work.
    let snap = state.snapshot().ok().cloned();
    if state.fs.tracker.is_none() {
        state.fs.tracker = guard(crate::fs::growth::Tracker::new);
    }
    let sc = state.scanner().ok().cloned();
    let hist = state.history.as_ref();
    let t = state.fs.tracker.as_mut().ok_or_else(|| anyhow!("growth tracking is unavailable"))?;
    if let Some(s) = &snap {
        t.observe(s);
    }
    let window_ms = secs as i64 * 1000;
    let g = t.report(window_ms, under.as_deref(), hist, sc.as_ref());
    Ok(growth_json(&g, window_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Secrets in command lines never reach the agent through snapshot results.
    #[test]
    fn snapshot_cmd_is_redacted() {
        let snap = Snapshot {
            procs: vec![Proc {
                pid: 9,
                name: "psql".into(),
                cmd: "psql postgres://app:s3cretpw@db-01/app".into(),
                cpu: 5.0,
                ..Default::default()
            }],
            ..Default::default()
        };
        let v = snapshot_value(&snap, &[], "cpu", 10, None, None);
        let c = v["procs"][0]["cmd"].as_str().unwrap();
        assert!(!c.contains("s3cretpw") && c.contains("psql"), "{c}");
    }

    fn call(state: &mut State, line: &str) -> Value {
        serde_json::from_str(&handle_line(state, line).expect("response")).unwrap()
    }

    fn tool_call(state: &mut State, name: &str, args: Value) -> Value {
        let line =
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
                .to_string();
        call(state, &line)["result"].clone()
    }

    #[test]
    fn allow_actions_config_parsing() {
        assert!(allowed_actions("").is_empty(), "default: no side effects");
        assert!(allowed_actions("interval_ms = 5\n").is_empty());
        assert_eq!(
            allowed_actions("[mcp]\nallow_actions = [\"pause\", \"renice\", \"bogus\"]\n"),
            vec!["pause", "renice"]
        );
        assert_eq!(allowed_actions("[mcp]\nallow_actions = \"all\"\n"), ACTION_TOOLS.to_vec());
        assert!(allowed_actions("[mcp]\nallow_actions = \"none\"\n").is_empty());
        assert_eq!(allowed_actions("[mcp]\nallow_actions = \"kill\"\n"), vec!["kill"]);
        assert!(allowed_actions("[mcp]\nallow_actions = 3\n").is_empty());
    }

    #[test]
    fn side_effect_tools_are_disabled_by_default() {
        let mut s = State::empty();
        let list = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let tools = list["result"]["tools"].as_array().unwrap();
        for t in tools {
            let name = t["name"].as_str().unwrap();
            let d = t["description"].as_str().unwrap();
            assert_eq!(d.starts_with("DISABLED"), ACTION_TOOLS.contains(&name), "{name}: {d}");
        }
        for name in ACTION_TOOLS {
            // pid 1 would be refused anyway; the gate answers before any handler runs.
            let r = tool_call(&mut s, name, json!({"pid": 1, "nice": 5}));
            assert_eq!(r["isError"], true, "{name}");
            let msg = r["structuredContent"]["error"].as_str().unwrap();
            assert!(msg.contains("disabled") && msg.contains("allow_actions") && msg.contains(name), "{msg}");
        }
        // Read-only tools are unaffected.
        assert_ne!(tool_call(&mut s, "containers", json!({}))["isError"], true);
        s.allowed = vec!["pause".into()];
        let list = call(&mut s, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let pause = list["result"]["tools"].as_array().unwrap().iter().find(|t| t["name"] == "pause").unwrap().clone();
        assert!(!pause["description"].as_str().unwrap().starts_with("DISABLED"));
        assert_eq!(tool_call(&mut s, "kill", json!({"pid": 1}))["structuredContent"]["disabled"], true);
    }

    #[test]
    fn kill_needs_a_preview_token_bound_to_the_process() {
        // Our own victim: a child we spawn and reap.
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let journal = std::env::temp_dir().join(format!("fat-mcp-kill-{}-{}.jsonl", std::process::id(), now_ms()));
        let mut s = State::empty();
        s.collector = Some(Collector::new());
        s.actions = Some(Actions::open_at(&journal));
        s.allowed = vec!["kill".into()];
        let alive = |pid: u32| unsafe { libc::kill(pid as i32, 0) == 0 };

        // 1. Preview: nothing is signalled, a token comes back.
        let r = tool_call(&mut s, "kill", json!({"pid": pid}));
        assert_ne!(r["isError"], true, "{r}");
        let p = &r["structuredContent"];
        assert_eq!(p["preview"], true);
        assert_eq!(p["would_signal"]["pid"], pid);
        assert_eq!(p["would_signal"]["signal"], "SIGTERM");
        assert_eq!(p["undoable"], false);
        let token = p["confirm_token"].as_str().unwrap().to_string();
        assert_eq!(token.len(), 32);
        assert!(alive(pid), "a preview never signals");
        assert!(child.try_wait().unwrap().is_none());

        // 2. A token for another signal or pid is refused, and is used up by trying.
        let r = tool_call(&mut s, "kill", json!({"pid": pid, "force": true, "confirm_token": token}));
        assert_eq!(r["isError"], true);
        assert!(r["structuredContent"]["error"].as_str().unwrap().contains("issued for"), "{r}");
        let r = tool_call(&mut s, "kill", json!({"pid": pid, "confirm_token": token}));
        assert!(r["structuredContent"]["error"].as_str().unwrap().contains("unknown or expired"), "single use: {r}");
        assert!(alive(pid));

        // 3. A token whose process identity no longer matches (pid reuse) is refused.
        let r = tool_call(&mut s, "kill", json!({"pid": pid}));
        let token = r["structuredContent"]["confirm_token"].as_str().unwrap().to_string();
        s.kill_tokens.iter_mut().for_each(|t| t.start_time = t.start_time.map(|st| st - 1000));
        let r = tool_call(&mut s, "kill", json!({"pid": pid, "confirm_token": token}));
        assert_eq!(r["isError"], true);
        assert!(r["structuredContent"]["error"].as_str().unwrap().contains("no longer the process"), "{r}");
        assert!(alive(pid));

        // 4. Preview + token executes, once.
        let r = tool_call(&mut s, "kill", json!({"pid": pid}));
        let token = r["structuredContent"]["confirm_token"].as_str().unwrap().to_string();
        let r = tool_call(&mut s, "kill", json!({"pid": pid, "confirm_token": token}));
        assert_ne!(r["isError"], true, "{r}");
        assert!(r["structuredContent"]["hint"].as_str().unwrap().contains("not undoable"));
        let st = child.wait().unwrap();
        assert!(!st.success(), "terminated by the signal");
        let r = tool_call(&mut s, "kill", json!({"pid": pid, "confirm_token": token}));
        assert_eq!(r["isError"], true);

        // 5. Expired tokens are dropped.
        s.kill_tokens.push(KillToken {
            token: "old".into(),
            pid: 42,
            start_time: None,
            kind: ActionKind::Term,
            issued: Instant::now() - KILL_TOKEN_TTL - Duration::from_secs(1),
            tree: vec![],
        });
        let r = tool_call(&mut s, "kill", json!({"pid": 42, "confirm_token": "old"}));
        assert!(r["structuredContent"]["error"].as_str().unwrap().contains("expired"));
        let _ = std::fs::remove_file(&journal);
    }

    #[test]
    fn kill_preview_refuses_protected_targets_without_a_token() {
        let mut s = State::empty();
        s.collector = Some(Collector::new());
        s.allowed = vec!["kill".into()];
        // fat itself: refused at preview, no token.
        let r = tool_call(&mut s, "kill", json!({"pid": std::process::id(), "tree": true}));
        let p = &r["structuredContent"];
        assert!(p["refused"].as_str().unwrap().contains("fat itself"), "{r}");
        assert!(p.get("confirm_token").is_none());
        assert!(p["descendants"].is_array());
        assert!(s.kill_tokens.is_empty());
    }

    #[test]
    fn initialize_echoes_supported_version() {
        let mut s = State::empty();
        for v in SUPPORTED_PROTOCOLS {
            let r = call(
                &mut s,
                &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{v}"}}}}"#),
            );
            assert_eq!(r["result"]["protocolVersion"], *v);
            assert_eq!(r["id"], 1);
        }
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
        );
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
            "snapshot",
            "process",
            "ports",
            "why",
            "doctor",
            "history",
            "find_port_owner",
            "pause",
            "resume",
            "renice",
            "kill",
            "undo",
            "containers",
            "ask",
            "fs_volumes",
            "fs_list",
            "fs_largest",
            "fs_growth",
            "kernel",
            "events",
            "what_happened",
        ] {
            assert!(names.contains(&n), "missing tool {n}");
            assert!(handler_for(n).is_some(), "no handler for {n}");
        }
        // Server-mode agents add tools; every listed name is checked above and below.
        assert!(names.len() >= 19, "{names:?}");
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
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"snapshot","arguments":{}}}"#,
        );
        assert!(r["result"]["isError"].is_null() || r["result"]["isError"] == false, "{r}");
        assert_eq!(r["result"]["content"][0]["type"], "text");
        // An unknown pid is a tool failure (isError), not a protocol error or crash.
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"why","arguments":{"pid":4294967000}}}"#,
        );
        assert_eq!(r["result"]["isError"], true, "{r}");
        assert!(r["result"]["structuredContent"]["error"].is_string());
        // Bad argument types are reported as tool errors.
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"process","arguments":{"pid":"x"}}}"#,
        );
        assert_eq!(r["result"]["isError"], true);
        let r = call(
            &mut s,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"history","arguments":{}}}"#,
        );
        assert_eq!(r["result"]["isError"], true);
        assert!(r["result"]["structuredContent"]["error"].as_str().unwrap().contains("fat record"));
    }

    #[test]
    fn action_tools_take_expected_identity() {
        for t in tools() {
            let name = t["name"].as_str().unwrap();
            if ["pause", "resume", "renice", "kill"].contains(&name) {
                let props = &t["inputSchema"]["properties"];
                assert!(props["start_time"].is_object() && props["name"].is_object(), "{name}");
            }
        }
        assert_eq!(arg_expect(&json!({"pid": 5})).unwrap(), None);
        assert_eq!(
            arg_expect(&json!({"pid": 5, "start_time": 1700000000u64, "name": "node"})).unwrap(),
            Some(crate::actions::Expect { start_time: Some(1_700_000_000), name: Some("node".into()) })
        );
        assert!(arg_expect(&json!({"start_time": "soon"})).is_err());
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
        let procs = vec![
            mk(1, "launchd", 0.1, 10),
            mk(2, "node", 50.0, 5),
            mk(3, "Chrome", 20.0, 900),
            mk(4, "nodemon", 5.0, 1),
        ];
        let (n, v) = top_procs(&procs, "cpu", 2, None);
        assert_eq!(n, 4);
        assert_eq!(v.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![2, 3]);
        let (_, v) = top_procs(&procs, "mem", 1, None);
        assert_eq!(v[0].pid, 3);
        let (n, v) = top_procs(&procs, "cpu", 10, Some("NODE"));
        assert_eq!(n, 2);
        assert_eq!(v.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![2, 4]);
    }

    fn linuxish() -> Snapshot {
        let mk = |pid, name: &str, cpu, ctr: Option<&str>| Proc {
            pid,
            name: name.into(),
            cpu,
            cgroup: match ctr {
                Some(id) => format!("/system.slice/docker-{id}0000000000000000.scope"),
                None => "/user.slice/user-1000.slice/session-2.scope".into(),
            },
            container: ctr.map(str::to_string),
            ..Default::default()
        };
        Snapshot {
            system: crate::model::System {
                psi: Some(crate::model::Psi {
                    cpu_some: 4.5,
                    mem_some: 0.0,
                    mem_full: 0.0,
                    io_some: 12.0,
                    io_full: 3.0,
                }),
                temp_c: Some(64.0),
                power_source: "rapl".into(),
                ..Default::default()
            },
            procs: vec![
                mk(1, "systemd", 0.1, None),
                mk(10, "postgres", 30.0, Some("410892b21be2")),
                mk(11, "postgres", 5.0, Some("410892b21be2")),
                mk(20, "redis-server", 2.0, Some("f592d553371f")),
                mk(30, "bash", 1.0, None),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn snapshot_filters_by_container_and_reports_linux_fields() {
        let snap = linuxish();
        let cs = vec![Container {
            id: "410892b21be2".into(),
            name: "db-1".into(),
            image: "postgres:16".into(),
            runtime: "docker".into(),
            ..Default::default()
        }];
        let v = snapshot_value(&snap, &cs, "cpu", 30, None, Some("DB-1"));
        assert_eq!(v["matched_procs"], 2);
        assert_eq!(v["procs"][0]["pid"], 10);
        assert_eq!(v["procs"][0]["container_name"], "db-1");
        assert_eq!(v["procs"][0]["container"], "410892b21be2");
        assert_eq!(v["container_info"]["image"], "postgres:16");
        assert_eq!(v["psi"]["io_some"], 12.0);
        assert_eq!(v["system"]["psi"]["cpu_some"], 4.5);
        assert_eq!(v["temp_c"], 64.0);
        assert_eq!(v["power_source"], "rapl");
        // id prefix works even for a container the runtime didn't report
        let v = snapshot_value(&snap, &cs, "cpu", 30, None, Some("f592"));
        assert_eq!(v["matched_procs"], 1);
        assert!(v["procs"][0].get("container_name").is_none());
        let v = snapshot_value(&snap, &cs, "cpu", 30, None, Some("nope"));
        assert_eq!(v["matched_procs"], 0);
        assert!(v["note"].as_str().unwrap().contains("containers"));
        // filter matches container names and cgroup paths
        let v = snapshot_value(&snap, &cs, "cpu", 30, Some("db-1"), None);
        assert_eq!(v["matched_procs"], 2);
        let v = snapshot_value(&snap, &cs, "cpu", 30, Some("session-2.scope"), None);
        assert_eq!(v["matched_procs"], 2);
        // macOS-shaped snapshot: keys present, null
        let v = snapshot_value(&Snapshot::default(), &[], "cpu", 30, None, None);
        assert!(v["psi"].is_null() && v["temp_c"].is_null());
        assert!(v.get("container").is_none());
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

    #[test]
    fn fs_tools_are_read_only_and_validate_arguments() {
        for t in tools() {
            if t["name"].as_str().unwrap().starts_with("fs_") {
                assert_eq!(t["annotations"]["readOnlyHint"], true, "{}", t["name"]);
                assert!(t["annotations"].get("destructiveHint").is_none());
            }
        }
        let mut s = State::empty();
        let err = |s: &mut State, name: &str, args: &str| -> String {
            let r = call(
                s,
                &format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#
                ),
            );
            assert_eq!(r["result"]["isError"], true, "{name} {args}: {r}");
            r["result"]["structuredContent"]["error"].as_str().unwrap().to_string()
        };
        // Bad arguments are rejected before any storage engine is touched.
        assert!(err(&mut s, "fs_list", r#"{"path":"relative/dir"}"#).contains("absolute"));
        assert!(err(&mut s, "fs_list", r#"{"path":7}"#).contains("`path` must be a string"));
        assert!(err(&mut s, "fs_list", r#"{"path":"/a/../b"}"#).contains(".."));
        assert!(err(&mut s, "fs_list", r#"{"depth":9}"#).contains("depth"));
        assert!(err(&mut s, "fs_largest", r#"{}"#).contains("`path` is required"));
        assert!(err(&mut s, "fs_largest", r#"{"path":"/","n":0}"#).contains("`n`"));
        assert!(err(&mut s, "fs_growth", r#"{"since":"soon"}"#).contains("since"));
        assert!(err(&mut s, "fs_growth", r#"{"since":"30d"}"#).contains("7d"));
        assert!(err(&mut s, "fs_growth", r#"{"under":"tmp"}"#).contains("absolute"));
        assert!(s.fs.scanner.is_none() && s.fs.tracker.is_none(), "no engine started for invalid calls");
        assert_eq!(arg_path(&json!({"path": "/Users/me/"}), "path", false).unwrap(), "/Users/me");
        assert_eq!(arg_path(&json!({}), "path", true).unwrap(), "/");
    }

    #[test]
    fn fs_json_is_compact_and_recursive() {
        use crate::fs::{DirEntry, Listing};
        let de = |p: &str, size: u64, dir: bool| DirEntry {
            path: p.into(),
            name: p.rsplit('/').next().unwrap().into(),
            is_dir: dir,
            size,
            files: 1,
            ..Default::default()
        };
        let root = Listing {
            dir: de("/w", 600, true),
            children: vec![
                de("/w/a", 400, true),
                DirEntry { denied: 2, ..de("/w/node_modules", 150, true) },
                de("/w/f", 50, false),
            ],
            ..Default::default()
        };
        let mut lookup = |p: &str| {
            (p == "/w/a").then(|| Listing {
                dir: de("/w/a", 400, true),
                children: vec![de("/w/a/x", 300, false), de("/w/a/y", 100, false)],
                ..Default::default()
            })
        };
        let v = listing_json(&root, 2, 2, &mut lookup);
        assert_eq!(v["size"], 600);
        assert_eq!(v["children"].as_array().unwrap().len(), 2);
        assert_eq!(v["more"], json!({"count": 1, "size": 50}));
        assert_eq!(v["children"][0]["children"][0]["name"], "x");
        assert_eq!(v["children"][1]["denied"], 2);
        assert!(v["children"][1]["known"].as_str().unwrap().contains("npm"));
        assert!(v["children"][0].get("partial").is_none(), "false flags left out");
        let g = crate::fs::Growth {
            growers: vec![crate::fs::Grower {
                path: "/w/a".into(),
                is_dir: true,
                delta: 5,
                writers: vec![(9, "cc".into(), 7)],
                evidence: vec![crate::fs::Evidence::OpenFiles],
                ..Default::default()
            }],
            deleted_open: vec![(3, "x".into(), "/tmp/z".into(), 1 << 30)],
            ..Default::default()
        };
        let j = growth_json(&g, 600_000);
        assert_eq!(j["window_s"], 600);
        assert_eq!(j["growers"][0]["evidence"][0], "open_files");
        assert_eq!(j["growers"][0]["writers"][0]["pid"], 9);
        assert_eq!(j["deleted_open"]["by_process"][0]["bytes"], 1u64 << 30);
        assert_eq!(j["deleted_open"]["by_process"][0]["files"], 1);
    }

    fn hp(pid: u32, ppid: u32, name: &str, exe: &str) -> Proc {
        Proc {
            pid,
            ppid,
            name: name.into(),
            cmd: exe.into(),
            exe: exe.into(),
            user: "me".into(),
            start_time: 1_700_000_000 + pid as u64,
            ..Default::default()
        }
    }

    fn hub_snap() -> Snapshot {
        let mut s = Snapshot::default();
        s.system.os = "macOS 15.6".into();
        let helper =
            "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper";
        let mut l = hp(1, 0, "launchd", "/sbin/launchd");
        l.user = "root".into();
        s.procs = vec![
            l,
            hp(13792, 1, "OrbStack Helper", helper),
            hp(1686, 1, "Brave Browser", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
            hp(
                1700,
                1686,
                "Brave Browser Helper (Renderer)",
                "/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Helper (Renderer).app/Contents/MacOS/Brave Browser Helper (Renderer)",
            ),
            hp(900, 1, "node", "/usr/local/bin/node"),
            hp(901, 900, "node", "/usr/local/bin/node"),
            hp(902, 901, "esbuild", "/usr/local/bin/esbuild"),
        ];
        s
    }

    #[test]
    fn agent_pause_and_kill_refuse_hubs() {
        let s = hub_snap();
        for kind in [ActionKind::Pause, ActionKind::Term, ActionKind::Kill, ActionKind::KillTree] {
            let (r, _) = hub_check(&s, kind, 13792);
            let r = r.unwrap_or_else(|| panic!("{kind:?} of the VM host must be refused"));
            assert!(r.contains("OrbStack VM") && r.contains("tell the user"), "{r}");
            assert!(
                hub_check(&s, kind, 1686).0.is_some_and(|r| r.contains("Brave's main process")),
                "{kind:?} browser main"
            );
            assert_eq!(hub_check(&s, kind, 900), (None, None), "{kind:?} a plain process");
        }
        // Renice and resume are not gated (renice of a VM host is blame's call, not a freeze).
        assert_eq!(hub_check(&s, ActionKind::Renice, 13792), (None, None));
        assert_eq!(hub_check(&s, ActionKind::Resume, 13792), (None, None));
        // A tree with a hub inside is refused for KillTree only.
        let mut s2 = s.clone();
        s2.procs.push(hp(950, 902, "OrbStack Helper", "/Applications/OrbStack.app/Contents/MacOS/OrbStack Helper"));
        assert!(hub_check(&s2, ActionKind::KillTree, 900).0.is_some_and(|r| r.contains("pid 950")));
        assert_eq!(hub_check(&s2, ActionKind::Term, 900).0, None);

        // Through the tools: preview refuses with no token; pause errors without signalling.
        let mut st = State::empty();
        st.allowed = vec!["kill".into(), "pause".into()];
        st.last = Some((Instant::now(), s.clone()));
        st.samples = 2;
        let r = tool_call(&mut st, "kill", json!({"pid": 13792}));
        let p = &r["structuredContent"];
        assert!(p["refused"].as_str().is_some_and(|x| x.contains("OrbStack VM")), "{r}");
        assert!(p["confirm_token"].is_null(), "{r}");
        st.last = Some((Instant::now(), s.clone()));
        let r = tool_call(&mut st, "pause", json!({"pid": 13792}));
        assert_eq!(r["isError"], true, "{r}");
        assert!(r["structuredContent"]["error"].as_str().unwrap().contains("refused"), "{r}");
        // tree + force is rejected instead of silently sending TERM.
        st.last = Some((Instant::now(), s));
        let r = tool_call(&mut st, "kill", json!({"pid": 900, "tree": true, "force": true}));
        assert!(r["structuredContent"]["error"].as_str().unwrap().contains("can't be combined"), "{r}");
    }

    #[test]
    fn tree_kill_token_covers_only_the_previewed_descendants() {
        let s = hub_snap();
        // Previewed: 901 and 902. Since then 903 was forked under 901, and 902's pid was reused.
        let tree = vec![(901, 1_700_000_901), (902, 1_700_000_902)];
        let mut now = s.clone();
        now.procs.push(hp(903, 901, "sh", "/bin/sh"));
        now.procs.iter_mut().find(|p| p.pid == 902).unwrap().start_time += 500;
        let (r, unseen) = restrict_tree(&now, 900, &tree);
        assert_eq!(unseen, vec![902, 903]);
        let left: Vec<u32> = r.descendants(900).iter().map(|p| p.pid).collect();
        assert_eq!(left, vec![901]);
        assert!(r.proc(900).is_some() && r.proc(13792).is_some(), "the rest of the snapshot is kept");
        // Unchanged tree: nothing dropped.
        assert!(restrict_tree(&s, 900, &tree).1.is_empty());
    }
}
