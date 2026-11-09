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

const INSTRUCTIONS: &str = "fat (Fucking Awesome Top) is a live process monitor for this machine. \
Use it to answer 'what is my machine doing, why, and what can I safely do about it'. \
Start with `doctor` (ranked findings) or `snapshot` (system totals + top processes; sort by cpu/mem/power/net/disk). \
Use `why {pid}` for a blame chain explaining why a process exists and what it costs, `process {pid}` for full details, \
`ports` / `find_port_owner {port}` for listeners (orphaned dev servers are flagged), `history` for the always-on flight \
recorder (timeline, spikes, or a past snapshot via at_minutes_ago; needs `fat record` running), `containers` for docker/podman/nerdctl \
(on Linux, `snapshot {container}` lists the host processes inside one container, joined via cgroups), \
and `ask {question}` for a plain-language answer. For disk space: `fs_volumes` (capacity, fill rate, ETA to full), \
`fs_list {path}` (du-style sizes, cached background scan), `fs_largest {path}`, and `fs_growth {since}` ('what is eating my space \
in the last 10 minutes': growing paths, their writers, deleted-but-open files). The fs tools only read; fat never deletes files. Actions are reversible where possible and journaled: prefer `pause` \
(SIGSTOP, undo with `resume` or `undo`) or `renice` over `kill`; every action returns an id usable with `undo`. \
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
        State { collector: None, history: None, actions: None, config: Config::default(), last: None, samples: 0, fs: FsEngines::default() }
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
        State { collector, history, actions, config, last, samples, fs: FsEngines::default() }
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
            let mut v = guard(crate::fs::volumes::Volumes::new).ok_or_else(|| anyhow!("volume listing is unavailable"))?;
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
        "fs_volumes" => tool_fs_volumes,
        "fs_list" => tool_fs_list,
        "fs_largest" => tool_fs_largest,
        "fs_growth" => tool_fs_growth,
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
            "Freeze a process with SIGSTOP. Reversible (resume or undo) — prefer this over kill to test whether a process is the culprit. Refused for system/session daemons (launchd, WindowServer, cfprefsd on macOS; init, systemd, dbus, the display server on Linux, ...) that other apps block on. Pass `start_time` from snapshot so a reused pid is never hit. Returns an action record with an id for `undo`.",
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
            "Set a process's nice value (-20 highest priority .. 20 lowest). Raising nice (deprioritizing) is allowed for your own processes; lowering usually needs root. Undoable.",
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
            "Terminate a process with SIGTERM (graceful; a paused process is continued so it can act on it). `tree: true` terminates the process and all its descendants; `force: true` sends SIGKILL instead. Not undoable — consider `pause` first. Pass `start_time` from snapshot so a reused pid is never hit. Journaled.",
            schema(
                target_schema(json!({
                    "tree": { "type": "boolean", "default": false, "description": "Also terminate all descendants." },
                    "force": { "type": "boolean", "default": false, "description": "Send SIGKILL instead of SIGTERM." }
                })),
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
            "Running containers (docker, podman, OrbStack, colima, nerdctl/containerd) with 12-char id, name, image, runtime, status, cpu, memory and published ports. Empty if no container runtime is reachable. On Linux, pass a name or id to `snapshot {container}` to see its processes.",
            schema(json!({}), &[]),
            false,
        ),
        tool(
            "ask",
            "Ask in plain language",
            "Ask a plain-language question about this machine ('why is this machine slow?', 'what is using port 3000?', 'which container is eating memory?'). Answered from a fresh snapshot plus doctor findings.",
            schema(json!({ "question": { "type": "string", "minLength": 1, "description": "The question." } }), &["question"]),
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
    let ctr_name = |p: &Proc| p.container.as_deref().and_then(|id| crate::fleet::find_container(containers, id)).map(|c| c.name.to_lowercase());
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
fn snapshot_value(snap: &Snapshot, containers: &[Container], sort: &str, limit: usize, filter: Option<&str>, container: Option<&str>) -> Value {
    let (matched, procs) = top_procs_in(&snap.procs, containers, sort, limit, filter, container);
    let procs: Vec<Value> = procs
        .into_iter()
        .map(|p| {
            let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
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
    let containers = if p.container.is_some() && snap.containers.is_empty() { crate::fleet::containers() } else { snap.containers.clone() };
    let container = p.container.as_deref().and_then(|id| crate::fleet::find_container(&containers, id));
    Ok(json!({
        "process": p,
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
    let snap = &state.last.as_ref().expect("snapshot cached").1;
    let findings = crate::blame::diagnose_with_fs(snap, state.history.as_ref(), &facts);
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
    apply(state, ActionKind::Pause, pid, None, args)
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
    let kind = if arg_bool(args, "tree")? {
        ActionKind::KillTree
    } else if arg_bool(args, "force")? {
        ActionKind::Kill
    } else {
        ActionKind::Term
    };
    apply(state, kind, pid, None, args)
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
pub fn listing_json(l: &crate::fs::Listing, depth: usize, limit: usize, list: &mut dyn FnMut(&str) -> Option<crate::fs::Listing>) -> Value {
    let mut out = entry_json(&l.dir);
    let mut kids = Vec::new();
    for c in l.children.iter().take(limit) {
        let mut v = entry_json(c);
        if depth > 1 && c.is_dir && !c.mount_point && c.size > 0
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
            if x.files_touched > 0 {
                v["files_touched"] = json!(x.files_touched);
            }
            if !x.writers.is_empty() {
                v["writers"] = json!(x.writers.iter().map(|(p, n, b)| json!({ "pid": p, "name": n, "write_bps": b })).collect::<Vec<_>>());
            }
            v
        })
        .collect();
    json!({
        "from_ts": g.from,
        "to_ts": g.to,
        "window_s": window_ms / 1000,
        "volumes": g.volumes.iter().map(|(m, d)| json!({ "mount": m, "delta": d })).collect::<Vec<_>>(),
        "growers": growers,
        "writers": g.writers.iter().take(10).map(|(p, n, b)| json!({ "pid": p, "name": n, "bytes": b })).collect::<Vec<_>>(),
        "deleted_open": g.deleted_open.iter().take(10).map(|(p, n, path, b)| json!({ "pid": p, "name": n, "path": path, "bytes": b })).collect::<Vec<_>>(),
        "notes": g.notes,
    })
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
            "undo", "containers", "ask", "fs_volumes", "fs_list", "fs_largest", "fs_growth",
        ] {
            assert!(names.contains(&n), "missing tool {n}");
            assert!(handler_for(n).is_some(), "no handler for {n}");
        }
        assert_eq!(names.len(), 18);
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
                psi: Some(crate::model::Psi { cpu_some: 4.5, mem_some: 0.0, mem_full: 0.0, io_some: 12.0, io_full: 3.0 }),
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
        let cs = vec![Container { id: "410892b21be2".into(), name: "db-1".into(), image: "postgres:16".into(), runtime: "docker".into(), ..Default::default() }];
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
            let r = call(s, &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#));
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
        let de = |p: &str, size: u64, dir: bool| DirEntry { path: p.into(), name: p.rsplit('/').next().unwrap().into(), is_dir: dir, size, files: 1, ..Default::default() };
        let root = Listing {
            dir: de("/w", 600, true),
            children: vec![de("/w/a", 400, true), DirEntry { denied: 2, ..de("/w/node_modules", 150, true) }, de("/w/f", 50, false)],
            ..Default::default()
        };
        let mut lookup = |p: &str| (p == "/w/a").then(|| Listing { dir: de("/w/a", 400, true), children: vec![de("/w/a/x", 300, false), de("/w/a/y", 100, false)], ..Default::default() });
        let v = listing_json(&root, 2, 2, &mut lookup);
        assert_eq!(v["size"], 600);
        assert_eq!(v["children"].as_array().unwrap().len(), 2);
        assert_eq!(v["more"], json!({"count": 1, "size": 50}));
        assert_eq!(v["children"][0]["children"][0]["name"], "x");
        assert_eq!(v["children"][1]["denied"], 2);
        assert!(v["children"][1]["known"].as_str().unwrap().contains("npm"));
        assert!(v["children"][0].get("partial").is_none(), "false flags left out");
        let g = crate::fs::Growth {
            growers: vec![crate::fs::Grower { path: "/w/a".into(), is_dir: true, delta: 5, writers: vec![(9, "cc".into(), 7)], evidence: vec![crate::fs::Evidence::OpenFiles], ..Default::default() }],
            deleted_open: vec![(3, "x".into(), "/tmp/z".into(), 1 << 30)],
            ..Default::default()
        };
        let j = growth_json(&g, 600_000);
        assert_eq!(j["window_s"], 600);
        assert_eq!(j["growers"][0]["evidence"][0], "open_files");
        assert_eq!(j["growers"][0]["writers"][0]["pid"], 9);
        assert_eq!(j["deleted_open"][0]["bytes"], 1u64 << 30);
    }
}
