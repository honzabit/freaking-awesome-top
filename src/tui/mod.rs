//! Interactive TUI. OWNER: tui agent (everything under src/tui/).
//!
//! Threads:
//! - main: input + rendering + executing [`app::Command`]s (actions, journal reads)
//! - sampler: `Collector::sample` every `interval_ms`, records into History (≤ every 2s,
//!   only while it holds the single-writer lease, pruning to `history_days`),
//!   runs `blame::diagnose` every ~5s
//! - history: owns a read-side History; timeline, spikes, time-travel loads and explain run
//!   here so SQLite never stalls input or rendering (requests are coalesced)
//! - fleet: containers every ~5s, remote hosts every ~10s
//! - fat-volumes: mounted volumes every sample (statfs can hang on a dead network mount, so it
//!   never runs on the sampler), deleted-but-open files every ~60s; feeds the Fs tab and doctor
//! - fat-fs: started the first time the Fs tab is opened (never before): owns the Scanner
//!   (background du of "/"); listings, rescans, largest-entry and time-travel queries run here
//! - fat-fs-growth: owns the growth Tracker (fed every collector sample) and builds reports
//! - ask: one short-lived thread per question
//!
//! Calls into other modules are wrapped in [`guarded`] so a panic in a collector
//! degrades to a status message instead of tearing down the terminal.

pub mod app;
pub mod markdown;
#[cfg(test)]
mod screenshots;
pub mod server;
mod server_ui;
pub mod ui;
pub mod widgets;

use crate::actions::Actions;
use crate::config::Config;
use crate::fleet::fanout::{self, Transport};
use crate::fleet::inventory::Target;
use crate::fs::{DirEntry, Growth, Listing, Volume};
use crate::history::History;
use crate::history::Point;
use crate::model::{Container, Explanation, Finding, Snapshot, Ts, now_ms};
use crate::server::{FleetHost, FleetSummary, Incident};
use app::{App, Command};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::cell::Cell;
use std::collections::HashMap;
use std::io::Stdout;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

enum Msg {
    Snap(Box<Snapshot>),
    CollectorError(String),
    /// Findings plus the start time of every pid they mention (from the same snapshot).
    Findings(Vec<Finding>, HashMap<u32, u64>),
    Fleet {
        containers: Option<Vec<Container>>,
    },
    /// Server profile: recorder events for the window starting at `from` (None = no recorder).
    Events(Ts, Option<Vec<crate::server::Event>>),
    Incident(u64, Result<Incident, String>),
    /// OOM kills in the last 24h from the recorder (None = unknown).
    Counts(Option<u64>),
    FleetInventory(Result<usize, String>),
    FleetHost(Box<FleetHost>),
    FleetDone(Box<FleetSummary>),
    FleetFailed(String),
    FleetDrill(String, Result<(Box<Snapshot>, Vec<Finding>), String>),
    Answer(u64, Box<crate::threads::Asked>),
    /// Settings: a check's result (message, is_error).
    SettingsNote(String, bool),
    SettingsModels(Result<Vec<String>, String>),
    /// The ways to connect ask found on this machine.
    AskOptions(Vec<crate::llm::AskOption>),
    /// The update check's result.
    Update(crate::update::State),
    /// None = no recorded history for this window (fall back to the in-memory ring).
    Timeline(Option<(Vec<Point>, Vec<Ts>)>),
    Past(Ts, Option<Box<Snapshot>>),
    Why(Result<Explanation, String>),
    FsVolumes(Ts, Vec<Volume>),
    FsListing(String, Option<Listing>),
    FsGrowth(Box<Growth>),
    FsLargest(String, Vec<DirEntry>),
    FsPast(Box<app::FsPast>),
    FsError(String),
}

/// Work for the storage thread.
enum FsReq {
    List {
        path: String,
        explicit: bool,
    },
    Growth {
        window_ms: i64,
        under: Option<String>,
    },
    Rescan(String),
    Largest(String),
    At {
        ts: Ts,
        path: String,
    },
    /// Every collector sample, for the growth tracker's open-file attribution.
    Observe(Box<Snapshot>),
}

/// Storage facts shared between threads (plain data only: the engines stay on their threads).
#[derive(Default)]
struct FsShared {
    volumes: Mutex<Vec<Volume>>,
    deleted_open: Mutex<Vec<(u32, String, String, u64)>>,
    growth: Mutex<Option<Growth>>,
    /// Set once the storage thread runs; the sampler forwards snapshots to it.
    observe: Mutex<Option<Sender<FsReq>>>,
}

impl FsShared {
    fn facts(&self) -> crate::blame::FsFacts {
        crate::blame::FsFacts {
            volumes: self.volumes.lock().map(|v| v.clone()).unwrap_or_default(),
            growth: self.growth.lock().ok().and_then(|g| g.clone()),
            deleted_open: self.deleted_open.lock().map(|v| v.clone()).unwrap_or_default(),
        }
    }
}

/// Work for the history thread.
enum HistReq {
    Timeline {
        from: Ts,
        to: Ts,
    },
    LoadAt(Ts),
    Explain(Box<Snapshot>, u32),
    /// Server profile requests (incident engine and recorder event tables).
    Events {
        from: Ts,
        to: Ts,
    },
    ExplainEvent {
        id: u64,
        live: Box<Snapshot>,
        event: Box<crate::server::Event>,
    },
    WhatHappened {
        id: u64,
        live: Box<Snapshot>,
        at: Option<Ts>,
        window_ms: i64,
    },
    Counts,
}

// ------------------------------------------------------------------ panic safety

thread_local! {
    /// >0 while inside `guarded`: the panic hook stays quiet and leaves the terminal alone.
    static GUARD_DEPTH: Cell<u32> = const { Cell::new(0) };
}
static TERM_ACTIVE: AtomicBool = AtomicBool::new(false);
/// The thread that owns the terminal. Only its panics may tear the terminal down: after a
/// background panic the UI keeps running, so restoring would draw into cooked scrollback.
static UI_THREAD: OnceLock<thread::ThreadId> = OnceLock::new();
/// Panics from background threads while the UI is up, printed after the terminal is restored.
static BG_PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Set by SIGTERM/SIGHUP/SIGINT so the event loop exits and restores the terminal.
static QUIT_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_quit_signal(sig: libc::c_int) {
    // Async-signal-safe: a single atomic store.
    QUIT_SIGNAL.store(sig, Ordering::SeqCst);
}

/// Install quit handlers; returns the previous dispositions for [`restore_signals`].
fn install_quit_signals() -> [(libc::c_int, libc::sighandler_t); 3] {
    let h = on_quit_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: the handler only performs an atomic store.
    [libc::SIGTERM, libc::SIGHUP, libc::SIGINT].map(|sig| (sig, unsafe { libc::signal(sig, h) }))
}

fn restore_signals(old: [(libc::c_int, libc::sighandler_t); 3]) {
    for (sig, h) in old {
        // SAFETY: restoring dispositions returned by signal().
        unsafe {
            libc::signal(sig, h);
        }
    }
}

/// Whether our terminal hung up (its window closed, ssh dropped): poll reports POLLHUP on
/// stdin. Only meaningful while stdin is a tty.
fn tty_hung_up() -> bool {
    let mut p = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
    // SAFETY: one pollfd we own, zero timeout; isatty only inspects fd 0.
    unsafe { libc::isatty(0) == 1 && libc::poll(&mut p, 1, 0) == 1 && p.revents & libc::POLLHUP != 0 }
}

/// Guarantee that a quit signal or a hung-up terminal ends the process. When the tty goes
/// away, crossterm's `event::poll` can spin inside its read loop at 100% CPU without ever
/// returning, so the event loop never sees QUIT_SIGNAL (a closed terminal window used to
/// leave fat running forever). Normally the loop exits within 50ms; if it has not after a
/// grace period, restore what can be restored and exit from here.
fn spawn_quit_watchdog() {
    const GRACE: Duration = Duration::from_millis(1500);
    thread::spawn(|| {
        let mut since: Option<Instant> = None;
        loop {
            thread::sleep(Duration::from_millis(250));
            if QUIT_SIGNAL.load(Ordering::SeqCst) == 0 && tty_hung_up() {
                QUIT_SIGNAL.store(libc::SIGHUP, Ordering::SeqCst);
            }
            let sig = QUIT_SIGNAL.load(Ordering::SeqCst);
            if sig == 0 {
                since = None;
                continue;
            }
            if since.get_or_insert_with(Instant::now).elapsed() >= GRACE {
                restore_terminal();
                std::process::exit(128 + sig);
            }
        }
    });
}

/// Run `f`, converting a panic into `Err(message)`.
pub fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    GUARD_DEPTH.with(|d| d.set(d.get() + 1));
    let r = panic::catch_unwind(AssertUnwindSafe(f));
    GUARD_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    r.map_err(|p| {
        p.downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panicked".into())
    })
}

fn install_panic_hook() {
    let prev = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        if GUARD_DEPTH.with(|d| d.get()) > 0 {
            return;
        }
        let on_ui = UI_THREAD.get().is_none_or(|t| *t == thread::current().id());
        if !on_ui && TERM_ACTIVE.load(Ordering::SeqCst) {
            // Keep the terminal intact (the UI is still running) and don't scribble over it.
            if let Ok(mut v) = BG_PANICS.lock() {
                let name = thread::current().name().unwrap_or("background").to_string();
                v.push(format!("fat: thread '{name}' panicked: {info}"));
            }
            return;
        }
        restore_terminal();
        prev(info);
    }));
}

fn restore_terminal() {
    if TERM_ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
    }
}

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    TERM_ACTIVE.store(true, Ordering::SeqCst);
    let mut out = std::io::stdout();
    if let Err(e) = execute!(out, EnterAlternateScreen, crossterm::cursor::Hide) {
        restore_terminal();
        return Err(e.into());
    }
    match Terminal::new(CrosstermBackend::new(out)) {
        Ok(t) => Ok(t),
        Err(e) => {
            restore_terminal();
            Err(e.into())
        }
    }
}

// ------------------------------------------------------------------ shell (`!`)

/// Hand the terminal to an interactive shell and take it back when it exits. Everything
/// else keeps running meanwhile (sampling, history, fleet polls); only drawing pauses.
///
/// The shell gets its own process group and the terminal's foreground, as a shell does for
/// a job: Ctrl-C, Ctrl-Z and Ctrl-\ go to it and its children, never to fat.
fn run_shell(term: &mut Terminal<CrosstermBackend<Stdout>>, env: &[(String, String)]) -> anyhow::Result<Option<i32>> {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let shell = std::env::var("SHELL").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "/bin/sh".into());
    restore_terminal();
    {
        use std::io::Write;
        let mut out = std::io::stdout();
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            let _ = writeln!(out, "\x1b[1;31mfat: this shell runs as root\x1b[0m");
        }
        let _ = writeln!(out, "\x1b[2mfat is still running and sampling · type exit to return\x1b[0m");
        let _ = out.flush();
    }
    let mut cmd = std::process::Command::new(&shell);
    cmd.envs(env.iter().map(|(k, v)| (k, v)));
    // SAFETY: setpgid is async-signal-safe; between fork and exec it only moves the child
    // into a process group of its own.
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let result = match cmd.spawn() {
        Ok(mut child) => {
            let pid = child.id() as libc::pid_t;
            // Also from here, so the terminal can be handed over before the child has run.
            // SAFETY: plain syscalls on our own child and the controlling terminal (fd 0).
            unsafe {
                libc::setpgid(pid, pid);
            }
            foreground(pid);
            let status = child.wait();
            // SAFETY: getpgrp cannot fail.
            foreground(unsafe { libc::getpgrp() });
            status.map(|s| s.code().or_else(|| s.signal().map(|n| 128 + n))).map_err(anyhow::Error::from)
        }
        Err(e) => Err(anyhow::anyhow!("cannot start {shell}: {e}")),
    };
    enable_raw_mode()?;
    TERM_ACTIVE.store(true, Ordering::SeqCst);
    execute!(
        std::io::stdout(),
        EnterAlternateScreen,
        crossterm::cursor::Hide,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
    )?;
    // Make the next draw repaint every cell: an empty frame first, so ratatui's diff starts
    // from blank. (Terminal::clear would ask the terminal where its cursor is, and stall on
    // one that does not answer.)
    term.draw(|_| {})?;
    result
}

/// Make `pgrp` the terminal's foreground process group. Called by a background group
/// (handing it back), tcsetpgrp would stop us with SIGTTOU, so that is ignored meanwhile.
fn foreground(pgrp: libc::pid_t) {
    // SAFETY: signal swaps a disposition and returns the previous one, restored right after;
    // tcsetpgrp acts on fd 0, our controlling terminal; failures leave things as they were.
    unsafe {
        let prev = libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::tcsetpgrp(0, pgrp);
        libc::signal(libc::SIGTTOU, prev);
    }
}

fn shell_status(code: Option<i32>) -> String {
    match code {
        Some(0) | None => "back from the shell".into(),
        Some(c) => format!("back from the shell (exit {c})"),
    }
}

// ------------------------------------------------------------------ background threads

fn spawn_sampler(cfg: Config, profile: crate::server::Profile, tx: Sender<Msg>, fs: Arc<FsShared>) {
    thread::spawn(move || {
        // Server profile: units, kernel health and events on top of every sample. A panic in
        // it (an engine bug, an odd /proc) disables it and the process view carries on.
        let mut server = (profile == crate::server::Profile::Server)
            .then(|| guarded(|| crate::server::ServerSampler::new(&cfg.server)).ok())
            .flatten();
        let interval = Duration::from_millis(cfg.interval_ms.max(250));
        let mut col = match guarded(crate::collect::Collector::new) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Msg::CollectorError(e));
                return;
            }
        };
        // The TUI may start over a per-user DB of another fat version (kept aside), never the
        // shared system recorder's.
        let may_reset =
            History::resolve(cfg.history_path.as_deref()) != std::path::Path::new(crate::history::SYSTEM_DB);
        let mut hist =
            guarded(|| History::open_recorder(cfg.history_path.as_deref(), may_reset)).ok().and_then(Result::ok);
        if server.is_some()
            && let Some(h) = hist.as_mut()
        {
            let _ = guarded(|| h.set_server_limits(&cfg.server));
        }
        let keep_days = cfg.history_days.max(1);
        // Retention runs where the writing happens: at startup and hourly, like `fat record`.
        let mut last_prune: Option<Instant> = None;
        let mut diagnose_ok = true;
        let (mut last_rec, mut last_diag) = (0i64, 0i64);
        let mut first = true;
        loop {
            let mut snap = match guarded(|| col.sample()) {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(Msg::CollectorError(e));
                    return;
                }
            };
            if let Some(ss) = server.as_mut()
                && guarded(|| ss.fill(&mut snap)).is_err()
            {
                server = None;
                let _ = tx.send(Msg::CollectorError(
                    "server sampling (services, kernel, events) failed and was turned off".into(),
                ));
            }
            let now = now_ms();
            if now - last_rec >= 2000 {
                last_rec = now;
                if let Some(h) = hist.as_mut() {
                    // A panic means the recorder is unusable; stop trying. Errors are ignored.
                    // record() is a no-op while another fat (e.g. `fat record`) holds the lease.
                    if guarded(|| h.record(&snap).and_then(|_| h.record_server(&snap))).is_err() {
                        hist = None;
                    } else if h.is_writer() {
                        // Same storage rows `fat record` keeps, so time travel shows volume use.
                        let vols = fs.volumes.lock().map(|v| v.clone()).unwrap_or_default();
                        if !vols.is_empty() {
                            let _ = guarded(|| h.record_volumes(now, &vols));
                        }
                        if last_prune.is_none_or(|t| t.elapsed() >= Duration::from_secs(3600)) {
                            last_prune = Some(Instant::now());
                            let _ = guarded(|| h.prune(keep_days));
                        }
                    }
                }
            }
            // The growth tracker attributes writes to processes; only once the Fs tab started it.
            if let Some(obs) = fs.observe.lock().ok().and_then(|o| o.clone())
                && obs.send(FsReq::Observe(Box::new(snap.clone()))).is_err()
                && let Ok(mut o) = fs.observe.lock()
            {
                *o = None;
            }
            if diagnose_ok && now - last_diag >= 5000 {
                last_diag = now;
                let facts = fs.facts();
                // Name a VM's containers in the advice: reuse the list the fleet thread keeps
                // fresh (never blocks on docker here).
                if snap.containers.is_empty()
                    && cfg.containers
                    && crate::blame::hosts_containers(&snap)
                    && let Some(cs) = crate::fleet::cached_containers()
                {
                    snap.containers = cs;
                }
                match guarded(|| crate::blame::diagnose_with_fs(&snap, hist.as_ref(), &facts)) {
                    Ok(f) => {
                        let starts = finding_starts(&f, &snap);
                        if tx.send(Msg::Findings(f, starts)).is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        diagnose_ok = false;
                        let _ = tx.send(Msg::Findings(Vec::new(), HashMap::new()));
                    }
                }
            }
            if tx.send(Msg::Snap(Box::new(snap))).is_err() {
                return; // UI gone
            }
            // The first sample has no rates; take the second one sooner.
            thread::sleep(if first { interval.min(Duration::from_millis(500)) } else { interval });
            first = false;
        }
    });
}

/// Start time of every pid the findings mention, so "Run suggested action" acts on the very
/// process the finding was about (or refuses if its pid was reused since).
fn finding_starts(findings: &[Finding], snap: &Snapshot) -> HashMap<u32, u64> {
    let mut out = HashMap::new();
    for f in findings {
        let action_pid = f.action.as_deref().and_then(app::parse_action).map(|(_, pid, _)| pid);
        for pid in f.pids.iter().copied().chain(action_pid) {
            if let Some(p) = snap.proc(pid) {
                out.insert(pid, p.start_time);
            }
        }
    }
    out
}

/// How long a spikes scan for the same zoom span is reused (spikes() reads every raw row).
const SPIKES_TTL: Duration = Duration::from_secs(30);

/// Kernel-log events the Events tab and the OOM/24h header merge with the recorder's, so a
/// TUI without a system recorder still shows the OOM kills `fat kernel` lists. Re-read at most
/// every [`KMSG_TTL`].
struct KernelLogCache {
    read: Box<dyn Fn(Ts) -> anyhow::Result<Vec<crate::server::Event>> + Send>,
    /// (read at, since, events)
    cached: Option<(Instant, Ts, Vec<crate::server::Event>)>,
}

const KMSG_TTL: Duration = Duration::from_secs(30);

impl KernelLogCache {
    fn events(&mut self, from: Ts, to: Ts) -> Vec<crate::server::Event> {
        let fresh = self.cached.as_ref().is_some_and(|(at, since, _)| at.elapsed() < KMSG_TTL && *since <= from);
        if !fresh {
            let since = from.min(now_ms() - 86_400_000);
            let got = guarded(|| (self.read)(since)).ok().and_then(Result::ok).unwrap_or_default();
            self.cached = Some((Instant::now(), since, got));
        }
        self.cached
            .as_ref()
            .map(|(_, _, v)| v.iter().filter(|e| e.ts >= from && e.ts <= to).cloned().collect())
            .unwrap_or_default()
    }
}

fn spawn_history(hist: Option<History>, tx: Sender<Msg>, mut klog: Option<KernelLogCache>) -> Sender<HistReq> {
    let (req_tx, req_rx) = mpsc::channel::<HistReq>();
    // If the thread can't start, requests go nowhere and views fall back to live data.
    let _ = thread::Builder::new().name("fat-history".into()).spawn(move || {
        let hist = hist;
        // (span, computed_at, spike timestamps)
        let mut spikes_cache: Option<(Ts, Instant, Vec<Ts>)> = None;
        while let Ok(first) = req_rx.recv() {
            // Coalesce a burst (held arrow keys, repeated refreshes): only the newest
            // timeline and time-travel requests matter.
            let (mut timeline, mut load_at, mut explain) = (None, None, None);
            let (mut events, mut incident, mut counts) = (None, None, false);
            for req in std::iter::once(first).chain(req_rx.try_iter()) {
                match req {
                    HistReq::Timeline { from, to } => timeline = Some((from, to)),
                    HistReq::LoadAt(ts) => load_at = Some(ts),
                    HistReq::Explain(s, pid) => explain = Some((s, pid)),
                    HistReq::Events { from, to } => events = Some((from, to)),
                    r @ (HistReq::ExplainEvent { .. } | HistReq::WhatHappened { .. }) => incident = Some(r),
                    HistReq::Counts => counts = true,
                }
            }
            if let Some(r) = incident {
                let (id, res) = run_incident(hist.as_ref(), r);
                if tx.send(Msg::Incident(id, res)).is_err() {
                    return;
                }
            }
            if let Some((from, to)) = events {
                let mut got = hist
                    .as_ref()
                    .and_then(|h| guarded(|| crate::server::incident::timeline(h, from, to, &[])).ok()?.ok());
                if let Some(k) = klog.as_mut() {
                    got = Some(crate::server::incident::merge_events(got.unwrap_or_default(), k.events(from, to)));
                }
                if tx.send(Msg::Events(from, got)).is_err() {
                    return;
                }
            }
            if counts {
                let (from, to) = (now_ms() - 86_400_000, now_ms());
                let oom = [crate::server::EventKind::OomKill];
                let n = match klog.as_mut() {
                    // Recorder and kernel log together, each kill once.
                    Some(k) => {
                        let rec = hist
                            .as_ref()
                            .and_then(|h| guarded(|| crate::server::incident::timeline(h, from, to, &oom)).ok()?.ok())
                            .unwrap_or_default();
                        let kev: Vec<_> = k.events(from, to).into_iter().filter(|e| e.kind == oom[0]).collect();
                        Some(crate::server::incident::merge_events(rec, kev).len() as u64)
                    }
                    None => hist.as_ref().and_then(|h| guarded(|| h.event_count(oom[0], from)).ok()?.ok()),
                };
                if tx.send(Msg::Counts(n)).is_err() {
                    return;
                }
            }
            if let Some((s, pid)) = explain {
                let r = guarded(|| crate::blame::explain(&s, pid, hist.as_ref()));
                if tx.send(Msg::Why(r)).is_err() {
                    return;
                }
            }
            if let Some(ts) = load_at {
                let snap = hist.as_ref().and_then(|h| guarded(|| h.at(ts)).ok()?.ok()?).map(Box::new);
                if tx.send(Msg::Past(ts, snap)).is_err() {
                    return;
                }
            }
            if let Some((from, to)) = timeline {
                let got = hist.as_ref().and_then(|h| {
                    let pts = guarded(|| h.timeline(from, to, 600)).ok()?.ok()?;
                    if pts.is_empty() {
                        return None;
                    }
                    let span = to - from;
                    let spikes = match &spikes_cache {
                        Some((s, at, v)) if *s == span && at.elapsed() < SPIKES_TTL => v.clone(),
                        _ => {
                            let mut v: Vec<Ts> = guarded(|| h.spikes(from, to))
                                .ok()
                                .and_then(Result::ok)
                                .unwrap_or_default()
                                .into_iter()
                                .map(|p| p.ts)
                                .collect();
                            v.sort_unstable();
                            spikes_cache = Some((span, Instant::now(), v.clone()));
                            v
                        }
                    };
                    Some((pts, spikes))
                });
                if tx.send(Msg::Timeline(got)).is_err() {
                    return;
                }
            }
        }
    });
    req_tx
}

/// An incident request answered on the history thread. The engine falls back to the live
/// snapshot and the kernel log when the recorder has nothing, and lists what it lacked.
fn run_incident(hist: Option<&History>, r: HistReq) -> (u64, Result<Incident, String>) {
    match r {
        HistReq::ExplainEvent { id, live, event } => {
            (id, guarded(|| crate::server::incident::explain_event(hist, &live, &event)))
        }
        HistReq::WhatHappened { id, live, at, window_ms } => (
            id,
            guarded(|| crate::server::incident::what_happened(hist, &live, at, window_ms))
                .and_then(|r| r.map_err(|e| e.to_string())),
        ),
        _ => (0, Err("not an incident request".into())),
    }
}

/// The remote hosts the Fleet tab shows: the inventory, read once per TUI session.
type Inventory = Arc<Mutex<Option<Vec<Target>>>>;

/// Read the inventory on its own thread (a hosts file or ~/.ssh/config may be slow to read on
/// a network home) and report its size.
fn spawn_inventory(cfg: Config, inv: Inventory, tx: Sender<Msg>) {
    let _ = thread::Builder::new().name("fat-inventory".into()).spawn(move || {
        let r = guarded(|| crate::fleet::inventory::inventory(&cfg))
            .map_err(|e| format!("inventory unavailable ({e})"))
            .and_then(|r| r.map_err(|e| e.to_string()));
        let msg = match r {
            Ok(t) => {
                let n = t.len();
                if let Ok(mut g) = inv.lock() {
                    *g = Some(t);
                }
                Ok(n)
            }
            Err(e) => Err(e),
        };
        let _ = tx.send(Msg::FleetInventory(msg));
    });
}

/// One read-only poll of every target, streaming each host's row as it answers and finishing
/// with the grouped summary. Snapshots are not kept (memory stays bounded by the host count
/// times one row); findings are computed locally from each snapshot as it arrives.
fn fleet_poll(targets: &[Target], cfg: &crate::server::FleetCfg, tr: &dyn Transport, tx: &Sender<Msg>) {
    let start = Instant::now();
    let txs = Mutex::new(tx.clone());
    let on_row = |h: &FleetHost| {
        if let Ok(t) = txs.lock() {
            let _ = t.send(Msg::FleetHost(Box::new(h.clone())));
        }
    };
    let polled = match guarded(|| fanout::poll_detailed(targets, cfg, tr, false, &on_row)) {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.send(Msg::FleetFailed(e));
            return;
        }
    };
    let findings: Vec<(String, Vec<Finding>)> =
        polled.iter().map(|p| (p.host.name.clone(), p.findings.clone())).collect();
    let rows: Vec<FleetHost> = polled.into_iter().map(|p| p.host).collect();
    // Every affected host is kept: the panel shows as many names as fit, and ⏎ on a finding
    // filters the table to all of them.
    match guarded(|| fanout::summarize(rows, &findings, usize::MAX)) {
        Ok(mut s) => {
            s.elapsed_ms = start.elapsed().as_millis() as u64;
            let _ = tx.send(Msg::FleetDone(Box::new(s)));
        }
        Err(e) => {
            let _ = tx.send(Msg::FleetFailed(format!("summary failed ({e})")));
        }
    }
}

/// Fetch one host's snapshot (read-only allowlisted command) and diagnose it locally.
fn fleet_drill(
    t: &Target,
    cfg: &crate::server::FleetCfg,
    tr: &dyn Transport,
) -> Result<(Box<Snapshot>, Vec<Finding>), String> {
    let args: Vec<String> = ["snapshot", "--json", "--fast"].iter().map(|s| s.to_string()).collect();
    let out = guarded(|| fanout::remote_read_only(t, &args, cfg, tr)).and_then(|r| r.map_err(|e| e.to_string()))?;
    let snap = crate::fleet::parse_remote_snapshot(&out, &t.name).map_err(|e| e.to_string())?;
    let findings = guarded(|| fanout::findings_of(&snap)).unwrap_or_default();
    Ok((Box::new(snap), findings))
}

fn spawn_fleet(cfg: Config, tx: Sender<Msg>) {
    thread::spawn(move || {
        let mut containers_ok = cfg.containers;
        let mut last_c = i64::MIN / 2;
        loop {
            let now = now_ms();
            let containers = if containers_ok && now - last_c >= 5000 {
                last_c = now;
                match guarded(crate::fleet::containers) {
                    Ok(c) => Some(c),
                    Err(_) => {
                        containers_ok = false;
                        Some(Vec::new())
                    }
                }
            } else if !cfg.containers && last_c < 0 {
                last_c = now;
                Some(Vec::new())
            } else {
                None
            };
            if containers.is_some() && tx.send(Msg::Fleet { containers }).is_err() {
                return;
            }
            if !containers_ok {
                return; // nothing left to poll (remote hosts are polled on demand)
            }
            thread::sleep(Duration::from_millis(1000));
        }
    });
}

/// Volumes every `interval_ms`, deleted-but-open files every 60s. A panic in either disables it.
fn spawn_volumes(interval_ms: u64, history_path: Option<String>, tx: Sender<Msg>, shared: Arc<FsShared>) {
    let _ = thread::Builder::new().name("fat-volumes".into()).spawn(move || {
        let mut vols = guarded(crate::fs::volumes::Volumes::new).ok();
        // Fill rates from the first sample on, instead of extrapolating a few seconds.
        if let Some(v) = vols.as_mut() {
            let _ = guarded(|| {
                if let Ok(h) = History::open(history_path.as_deref()) {
                    h.seed_volumes(v, now_ms());
                }
            });
        }
        let mut deleted_ok = true;
        let mut last_deleted = i64::MIN / 2;
        loop {
            if let Some(v) = vols.as_mut() {
                match guarded(|| v.sample()) {
                    Ok(list) => {
                        if let Ok(mut s) = shared.volumes.lock() {
                            *s = list.clone();
                        }
                        if tx.send(Msg::FsVolumes(now_ms(), list)).is_err() {
                            return;
                        }
                    }
                    Err(_) => vols = None,
                }
            }
            let now = now_ms();
            if deleted_ok && now - last_deleted >= 60_000 {
                last_deleted = now;
                match guarded(crate::fs::volumes::deleted_open) {
                    Ok(d) => {
                        if let Ok(mut s) = shared.deleted_open.lock() {
                            *s = d;
                        }
                    }
                    Err(_) => deleted_ok = false,
                }
            }
            if vols.is_none() && !deleted_ok {
                return;
            }
            thread::sleep(Duration::from_millis(interval_ms.max(500)));
        }
    });
}

/// Background scan CPU budget (cores) while the Fs tab is visible / otherwise.
const FS_BUDGET_VISIBLE: f32 = 1.0;
const FS_BUDGET_IDLE: f32 = 0.25;

/// The storage thread: created on the first Fs command. Engines are built here and never leave
/// it. Requests are coalesced (only the newest listing / growth / largest query matters).
fn spawn_fs(history_path: Option<String>, tx: Sender<Msg>, shared: Arc<FsShared>) -> Sender<FsReq> {
    let (req_tx, rx) = mpsc::channel::<FsReq>();
    if let Ok(mut o) = shared.observe.lock() {
        *o = Some(req_tx.clone());
    }
    let _ = thread::Builder::new().name("fat-fs".into()).spawn(move || {
        let scanner = match guarded(|| {
            let s = crate::fs::scan::Scanner::new();
            // Keep "/" fresh in the background (low priority; skips network mounts and
            // TCC-protected dirs until the user opens one).
            s.ensure("/", false);
            s
        }) {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(Msg::FsError(format!("scanner unavailable ({e})")));
                return;
            }
        };
        // Growth reports can take seconds (journal replay, mtime walks): their own thread, so
        // listings stay responsive. The tracker never leaves it.
        let (gtx, grx) = mpsc::channel::<FsReq>();
        {
            let (sc, tx, shared, hp) = (scanner.clone(), tx.clone(), shared.clone(), history_path.clone());
            let _ =
                thread::Builder::new().name("fat-fs-growth".into()).spawn(move || growth_loop(grx, sc, hp, tx, shared));
        }
        let hist = guarded(|| History::open(history_path.as_deref())).ok().and_then(Result::ok);
        let mut focused = String::new();
        let mut explicit_done: std::collections::HashSet<String> = std::collections::HashSet::new();
        // While the Fs tab is on screen (it polls listings) the background scan may use a whole
        // core; otherwise it stays at the scanner's default quarter core.
        let mut fast_until: Option<std::time::Instant> = None;
        loop {
            let next = rx.recv_timeout(Duration::from_secs(5));
            // Checked on every wake-up: process samples (Observe) arrive constantly.
            if fast_until.is_some_and(|t| std::time::Instant::now() >= t) {
                fast_until = None;
                let _ = guarded(|| scanner.set_budget(FS_BUDGET_IDLE));
            }
            let first = match next {
                Ok(r) => r,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            };
            let (mut list, mut largest, mut at) = (None, None, None);
            let mut rescans: Vec<String> = Vec::new();
            for req in std::iter::once(first).chain(rx.try_iter()) {
                match req {
                    FsReq::List { path, explicit } => list = Some((path, explicit)),
                    FsReq::Growth { window_ms, under } => {
                        let _ = gtx.send(FsReq::Growth { window_ms, under });
                    }
                    FsReq::Largest(p) => largest = Some(p),
                    FsReq::At { ts, path } => at = Some((ts, path)),
                    FsReq::Rescan(p) => {
                        if !rescans.contains(&p) {
                            rescans.push(p)
                        }
                    }
                    FsReq::Observe(s) => {
                        let _ = gtx.send(FsReq::Observe(s));
                    }
                }
            }
            for p in rescans {
                if let Err(e) = guarded(|| scanner.rescan(&p)) {
                    let _ = tx.send(Msg::FsError(format!("rescan failed ({e})")));
                    return;
                }
            }
            if let Some((path, explicit)) = list {
                if fast_until.is_none() {
                    let _ = guarded(|| scanner.set_budget(FS_BUDGET_VISIBLE));
                }
                fast_until = Some(std::time::Instant::now() + Duration::from_secs(15));
                let r = guarded(|| {
                    // The user opened a protected / mounted dir: allow reading it (once per path).
                    if explicit && explicit_done.insert(path.clone()) {
                        scanner.ensure(&path, true);
                    }
                    if path != focused {
                        scanner.focus(&path);
                    }
                    scanner.list(&path)
                });
                match r {
                    Ok(l) => {
                        focused = path.clone();
                        if tx.send(Msg::FsListing(path, l)).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::FsError(format!("listing failed ({e})")));
                        return;
                    }
                }
            }
            if let Some((ts, path)) = at {
                let past = fs_past(hist.as_ref(), ts, &path, &shared);
                if tx.send(Msg::FsPast(Box::new(past))).is_err() {
                    return;
                }
            }
            if let Some(p) = largest {
                let v = guarded(|| scanner.largest(&p, 50)).unwrap_or_default();
                if tx.send(Msg::FsLargest(p, v)).is_err() {
                    return;
                }
            }
        }
    });
    req_tx
}

/// The growth thread: owns the Tracker, observes every sample, answers growth reports
/// (coalesced: only the newest request in a burst is computed).
fn growth_loop(
    rx: Receiver<FsReq>,
    scanner: crate::fs::scan::Scanner,
    history_path: Option<String>,
    tx: Sender<Msg>,
    shared: Arc<FsShared>,
) {
    let mut tracker = guarded(crate::fs::growth::Tracker::new).ok();
    let hist = guarded(|| History::open(history_path.as_deref())).ok().and_then(Result::ok);
    let mut growth_err = false;
    while let Ok(first) = rx.recv() {
        let mut growth = None;
        for req in std::iter::once(first).chain(rx.try_iter()) {
            match req {
                FsReq::Observe(s) => {
                    if let Some(t) = tracker.as_mut()
                        && guarded(|| t.observe(&s)).is_err()
                    {
                        tracker = None;
                    }
                }
                FsReq::Growth { window_ms, under } => growth = Some((window_ms, under)),
                _ => {}
            }
        }
        let Some((window_ms, under)) = growth else { continue };
        let r = match tracker.as_mut() {
            Some(t) => guarded(|| t.report(window_ms, under.as_deref(), hist.as_ref(), Some(&scanner))),
            None => Err("the tracker could not start".to_string()),
        };
        match r {
            Ok(g) => {
                if under.is_none()
                    && let Ok(mut s) = shared.growth.lock()
                {
                    *s = Some(g.clone());
                }
                if tx.send(Msg::FsGrowth(Box::new(g))).is_err() {
                    return;
                }
            }
            Err(e) => {
                tracker = None;
                if !growth_err {
                    growth_err = true;
                    let _ = tx.send(Msg::FsGrowth(Box::new(Growth {
                        notes: vec![format!("growth tracking unavailable ({e})")],
                        ..Default::default()
                    })));
                }
            }
        }
    }
}

/// Recorded directory sizes and volume use at `ts` (empty when the recorder has none).
fn fs_past(hist: Option<&History>, ts: Ts, path: &str, shared: &FsShared) -> app::FsPast {
    let Some(h) = hist else { return app::FsPast { ts, path: path.to_string(), ..Default::default() } };
    let (at, rows) = match guarded(|| h.dir_sizes_near(ts, path)) {
        Ok(Ok(Some((at, rows)))) => (Some(at), rows),
        _ => (None, Vec::new()),
    };
    let mounts: Vec<String> =
        shared.volumes.lock().map(|v| v.iter().map(|x| x.mount.clone()).collect()).unwrap_or_default();
    let vols = mounts
        .into_iter()
        .filter_map(|m| {
            let series = guarded(|| h.volume_series(&m, ts - 15 * 60_000, ts)).ok()?.ok()?;
            series.last().map(|(_, used, _)| (m, *used))
        })
        .collect();
    app::fs_past_from(ts, path, at, &rows, vols)
}

// ------------------------------------------------------------------ main loop

struct Ctx {
    cfg: Config,
    /// Requests to the history thread (None in tests: views fall back to live data).
    hist: Option<Sender<HistReq>>,
    actions: Option<Actions>,
    actions_failed: bool,
    tx: Sender<Msg>,
    fs_shared: Arc<FsShared>,
    /// Storage thread, started by the first Fs command.
    fs: Option<Sender<FsReq>>,
    inventory: Inventory,
    /// Transport for fleet polls (ssh through the operator's own ssh config).
    transport: Arc<dyn Transport>,
    /// Where ask threads are kept (None: not kept, as in tests).
    threads_path: Option<std::path::PathBuf>,
    /// The config file the settings screen edits (None: read-only, as in tests).
    settings_path: Option<std::path::PathBuf>,
}

/// The settings overlay for `cfg`, reading `path` to tell file values from defaults.
fn settings_ui(cfg: &Config, path: Option<&std::path::Path>) -> app::SettingsUi {
    let text = path.and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    let env = |k: &str| std::env::var(k).ok();
    let file_cfg = Config::parse(&text).ok();
    app::SettingsUi {
        fields: crate::settings::fields(
            &file_cfg.clone().map(|f| Config { ask: cfg.ask.clone(), ..f }).unwrap_or_else(|| cfg.clone()),
            &text,
            &env,
        ),
        hosts: file_cfg.map(|c| c.hosts).unwrap_or_else(|| cfg.hosts.clone()),
        path: path.map(|p| p.display().to_string()).unwrap_or_default(),
        key_status: crate::settings::key_status(cfg, &env),
        ..Default::default()
    }
}

impl Ctx {
    /// After a settings write: apply what can apply live, rebuild the screen, say what happened.
    fn after_settings_write(
        &mut self,
        app: &mut App,
        path: &std::path::Path,
        result: Result<(Config, String), String>,
        section: &str,
    ) {
        let note = match result {
            Ok((cfg, what)) => {
                let mut msg = format!("saved {what} to {}", path.display());
                if section == "ask"
                    && let Err(e) = crate::llm::resolve(&cfg.ask)
                {
                    msg = format!("saved; but ask can't use it yet: {e}");
                } else if section != "ask" {
                    msg.push_str(" (takes effect the next time fat starts)");
                }
                // Live from now on: ask and the destination shown. The rest is read at start.
                self.cfg.ask = cfg.ask.clone();
                app.ask_dest = crate::llm::destination(&self.cfg.ask);
                app.ask_ready = self.cfg.ask.enabled && crate::llm::resolve(&self.cfg.ask).is_ok_and(|e| e.usable());
                // Keep the rest of the screen's view of the file current.
                self.cfg.hosts = cfg.hosts;
                self.cfg.history_days = cfg.history_days;
                (msg, false)
            }
            Err(e) => (e, true),
        };
        let sel = app.settings.sel;
        let host_form = app.settings.host_form.take();
        let ask_options = std::mem::take(&mut app.settings.ask_options);
        let ask_advanced = app.settings.ask_advanced;
        let mut ui = settings_ui(&self.cfg, Some(path));
        // Settings other than ask apply at the next start: show the file's values for them.
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(file_cfg) = Config::parse(&text)
        {
            let env = |k: &str| std::env::var(k).ok();
            ui.fields = crate::settings::fields(&Config { ask: self.cfg.ask.clone(), ..file_cfg.clone() }, &text, &env);
            ui.hosts = file_cfg.hosts;
        }
        ui.sel = sel.min(ui.rows().len().saturating_sub(1));
        ui.host_form = host_form;
        ui.ask_options = ask_options;
        ui.ask_advanced = ask_advanced;
        ui.note = Some(note);
        app.settings = ui;
    }

    fn actions(&mut self) -> Option<&mut Actions> {
        if self.actions.is_none() && !self.actions_failed {
            match guarded(|| Actions::open().with_origin("tui")) {
                Ok(a) => self.actions = Some(a),
                Err(_) => self.actions_failed = true,
            }
        }
        self.actions.as_mut()
    }

    fn fs_send(&mut self, app: &mut App, req: FsReq) {
        if app.fs.error.is_some() {
            return;
        }
        let tx = self
            .fs
            .get_or_insert_with(|| spawn_fs(self.cfg.history_path.clone(), self.tx.clone(), self.fs_shared.clone()));
        if tx.send(req).is_err() {
            app.set_fs_error("storage thread stopped".into());
        }
    }

    /// Incident requests go to the history thread (the recorder lives there); without one the
    /// engine still answers from the live snapshot, on a short-lived thread.
    fn incident(&mut self, app: &mut App, req: HistReq) {
        if let Some(h) = &self.hist
            && app.history_ok
        {
            let _ = h.send(req);
            return;
        }
        let tx = self.tx.clone();
        let _ = thread::Builder::new().name("fat-incident".into()).spawn(move || {
            let (id, r) = run_incident(None, req);
            let _ = tx.send(Msg::Incident(id, r));
        });
    }

    fn exec(&mut self, app: &mut App, cmd: Command) {
        match cmd {
            Command::FsList { path, explicit } => self.fs_send(app, FsReq::List { path, explicit }),
            Command::FsGrowth { window_ms, under } => self.fs_send(app, FsReq::Growth { window_ms, under }),
            Command::FsRescan(p) => self.fs_send(app, FsReq::Rescan(p)),
            Command::FsLargest(p) => self.fs_send(app, FsReq::Largest(p)),
            Command::FsAt { ts, path } => self.fs_send(app, FsReq::At { ts, path }),
            Command::Quit => app.quit = true,
            Command::LoadEvents { from, to } => match &self.hist {
                Some(h) if app.history_ok => {
                    let _ = h.send(HistReq::Events { from, to });
                }
                _ => app.set_events(from, None),
            },
            Command::ExplainEvent { id, event } => {
                let live = Box::new(app.live.clone().unwrap_or_default());
                self.incident(app, HistReq::ExplainEvent { id, live, event });
            }
            Command::WhatHappened { id, at, window_ms } => {
                let live = Box::new(app.live.clone().unwrap_or_default());
                self.incident(app, HistReq::WhatHappened { id, live, at, window_ms });
            }
            Command::RefreshCounts => match &self.hist {
                Some(h) if app.history_ok => {
                    let _ = h.send(HistReq::Counts);
                }
                _ => app.set_counts(None),
            },
            Command::FleetPoll => {
                let targets = self.inventory.lock().ok().and_then(|g| g.clone()).unwrap_or_default();
                if targets.is_empty() {
                    app.fleet_failed("no hosts in the inventory".into());
                    return;
                }
                let (cfg, tr, tx) = (self.cfg.fleet.clone(), self.transport.clone(), self.tx.clone());
                let spawned = thread::Builder::new()
                    .name("fat-fleet-poll".into())
                    .spawn(move || fleet_poll(&targets, &cfg, tr.as_ref(), &tx));
                if let Err(e) = spawned {
                    app.fleet_failed(e.to_string());
                }
            }
            Command::FleetDrill(name) => {
                let target =
                    self.inventory.lock().ok().and_then(|g| g.as_ref()?.iter().find(|t| t.name == name).cloned());
                let Some(t) = target else {
                    app.set_fleet_drill(&name, Err("not in the inventory".into()));
                    return;
                };
                let (cfg, tr, tx) = (self.cfg.fleet.clone(), self.transport.clone(), self.tx.clone());
                let _ = thread::Builder::new().name("fat-fleet-drill".into()).spawn(move || {
                    let r = fleet_drill(&t, &cfg, tr.as_ref());
                    let _ = tx.send(Msg::FleetDrill(t.name.clone(), r));
                });
            }
            Command::Act { kind, pid, nice, start } => {
                let Some(live) = app.live.clone() else {
                    app.set_status("no live snapshot yet", true);
                    return;
                };
                let Some(a) = self.actions() else {
                    app.set_status("actions unavailable", true);
                    return;
                };
                // Check against the identity chosen in the UI, not just the newest snapshot
                // (which would already describe a process that reused the pid).
                let expect = crate::actions::Expect { start_time: (start != 0).then_some(start), name: None };
                match guarded(|| a.apply_expect(kind, pid, nice, &live, Some(&expect))) {
                    Ok(r) => app.action_done(&r),
                    Err(e) => app.set_status(format!("action failed: {e}"), true),
                }
                self.exec(app, Command::RefreshLog);
            }
            Command::Undo => {
                let Some(a) = self.actions() else {
                    app.set_status("actions unavailable", true);
                    return;
                };
                match guarded(|| a.undo_last()) {
                    Ok(r) => app.undo_done(r.as_ref()),
                    Err(e) => app.set_status(format!("undo failed: {e}"), true),
                }
                self.exec(app, Command::RefreshLog);
            }
            Command::UndoId(id) => {
                let Some(a) = self.actions() else {
                    app.set_status("actions unavailable", true);
                    return;
                };
                match guarded(|| a.undo(id)) {
                    Ok(r) => app.undo_done(Some(&r)),
                    Err(e) => app.set_status(format!("undo failed: {e}"), true),
                }
                self.exec(app, Command::RefreshLog);
            }
            Command::RefreshLog => {
                if let Some(a) = self.actions()
                    && let Ok(log) = guarded(|| a.log())
                {
                    app.set_log(log);
                }
            }
            Command::Explain(pid) => {
                let Some(s) = app.view() else {
                    app.set_status("why unavailable: no snapshot", true);
                    return;
                };
                match &self.hist {
                    Some(h) => {
                        let _ = h.send(HistReq::Explain(Box::new(s.clone()), pid));
                    }
                    None => apply_msg(app, Msg::Why(guarded(|| crate::blame::explain(s, pid, None)))),
                }
            }
            Command::Ask { id, question: q, thread } => {
                app.ask_dest = crate::llm::destination(&self.cfg.ask);
                app.ask_ready = self.cfg.ask.enabled && crate::llm::resolve(&self.cfg.ask).is_ok_and(|e| e.usable());
                let snap = app.live.clone().unwrap_or_default();
                let findings = app.findings.clone();
                let ask_cfg = self.cfg.ask.clone();
                let hist_path = self.cfg.history_path.clone();
                let threads_path = self.threads_path.clone();
                let tx = self.tx.clone();
                // The Fs tab's growth report, when it has one: reused if fresh, so a disk
                // question doesn't wait for a second FSEvents replay.
                let facts = self.fs_shared.facts();
                let now = app.now;
                thread::spawn(move || {
                    let asked = guarded(|| {
                        let st = crate::ask::wants_storage(&q).then(|| {
                            crate::ask::reuse_storage(&q, facts.volumes, facts.growth, now, 120_000)
                                .unwrap_or_else(|| crate::ask::gather_storage(&q, hist_path.as_deref()))
                        });
                        crate::threads::ask_and_save(
                            threads_path.as_deref(),
                            thread,
                            &q,
                            &snap,
                            &findings,
                            st.as_ref(),
                            &ask_cfg,
                        )
                    })
                    .unwrap_or_else(|e| crate::threads::Asked {
                        question: q.clone(),
                        answer: format!("ask is unavailable right now ({e})."),
                        via: "error".into(),
                        ..Default::default()
                    });
                    let _ = tx.send(Msg::Answer(id, Box::new(asked)));
                });
            }
            Command::Threads => {
                app.ask_dest = crate::llm::destination(&self.cfg.ask);
                app.ask_ready = self.cfg.ask.enabled && crate::llm::resolve(&self.cfg.ask).is_ok_and(|e| e.usable());
                if let Some(p) = &self.threads_path {
                    let r = guarded(|| crate::threads::Store::open(p).and_then(|s| s.threads(500)))
                        .map_err(|e| format!("threads unavailable ({e})"))
                        .and_then(|r| r.map_err(|e| format!("threads unavailable ({e:#})")));
                    app.set_threads(r);
                }
            }
            Command::OpenThread(id) => {
                if let Some(p) = &self.threads_path
                    && let Ok(Ok(t)) = guarded(|| crate::threads::Store::open(p).and_then(|s| s.turns(id)))
                {
                    app.set_thread(id, t);
                }
            }
            Command::LoadSettings => {
                let keep = std::mem::take(&mut app.settings);
                let mut ui = settings_ui(&self.cfg, self.settings_path.as_deref());
                ui.ask_options = keep.ask_options.clone();
                ui.ask_advanced = keep.ask_advanced;
                if self.settings_path.is_some() {
                    ui.ask_detecting = true;
                    let tx = self.tx.clone();
                    thread::spawn(move || {
                        let env = |k: &str| std::env::var(k).ok();
                        if let Ok(opts) = guarded(|| crate::llm::detect(&env)) {
                            let _ = tx.send(Msg::AskOptions(opts));
                        }
                    });
                }
                ui.sel = keep.sel.min(ui.rows().len().saturating_sub(1));
                ui.note = keep.note.or_else(|| {
                    Some(("⏎ change · r reset to default · t test · m pick a model · ←→ groups".into(), false))
                });
                app.settings = ui;
            }
            Command::SetSetting { section, key, value } => {
                let Some(path) = self.settings_path.clone() else { return };
                let fields = settings_ui(&self.cfg, Some(&path)).fields;
                let result = match (fields.iter().find(|f| f.section == section && f.key == key), value) {
                    (None, _) => Err(format!("unknown setting {section}.{key}")),
                    (Some(f), Some(v)) => crate::settings::parse_input(f, &v),
                    (Some(_), None) => Ok(None),
                }
                .and_then(|v| crate::settings::write(&path, &section, &key, v).map_err(|e| format!("{e:#}")));
                self.after_settings_write(app, &path, result.map(|c| (c, key.clone())), &section);
            }
            Command::SaveHost { index, host } => {
                let Some(path) = self.settings_path.clone() else { return };
                let name = host.name.clone();
                let r = crate::settings::write_host(&path, index, Some(&host)).map_err(|e| format!("{e:#}"));
                if r.is_ok() {
                    app.settings.host_form = None;
                } else if app.settings.host_form.is_none() {
                    app.settings.host_form = Some(app::HostForm::from(index, &host));
                }
                self.after_settings_write(app, &path, r.map(|c| (c, format!("host {name}"))), "hosts");
            }
            Command::DeleteHost(i) => {
                let Some(path) = self.settings_path.clone() else { return };
                let r = crate::settings::write_host(&path, Some(i), None).map_err(|e| format!("{e:#}"));
                self.after_settings_write(app, &path, r.map(|c| (c, "the host removal".to_string())), "hosts");
            }
            Command::ApplyAskOption(o) => {
                let Some(path) = self.settings_path.clone() else { return };
                let mut writes: Vec<(&str, Option<toml_edit::Value>)> = Vec::new();
                if o.key == "off" {
                    writes.push(("enabled", Some(false.into())));
                } else {
                    // enabled defaults to true: drop an explicit false.
                    writes.push(("enabled", None));
                    writes.push(("provider", Some(o.key.as_str().into())));
                    if let Some(u) = &o.url {
                        writes.push(("url", Some(u.as_str().into())));
                    }
                }
                let mut result = Err("nothing to change".to_string());
                for (key, v) in writes {
                    result = crate::settings::write(&path, "ask", key, v).map_err(|e| format!("{e:#}"));
                    if result.is_err() {
                        break;
                    }
                }
                let label = o.label.clone();
                self.after_settings_write(app, &path, result.map(|c| (c, format!("ask → {label}"))), "ask");
                // A choice that still needs its address or command: go type it.
                let need = match o.key.as_str() {
                    "openai" | "ollama" if app.settings.ask_value("url").is_empty() => Some("url"),
                    "command" if app.settings.ask_value("command").is_empty() => Some("command"),
                    _ => None,
                };
                if let Some(key) = need {
                    let rows = app.settings.rows();
                    if let Some(i) = rows.iter().position(|r| matches!(r, app::SRow::Field(f) if app.settings.fields[*f].key == key && app.settings.fields[*f].section == "ask")) {
                        app.settings.sel = i;
                        app.settings.editing = Some(String::new());
                    }
                } else if o.key != "off" && app.ask_ready {
                    app.settings.note = Some((format!("ask → {label}. Press t to test it."), false));
                }
            }
            Command::TestHost(h) => {
                let tx = self.tx.clone();
                let timeout = self.cfg.fleet.connect_timeout_s;
                thread::spawn(move || {
                    let (msg, err) = match guarded(|| crate::settings::test_host(&h, timeout)) {
                        Ok(Ok(v)) => (format!("✓ {v}"), false),
                        Ok(Err(e)) => (format!("✗ {e}"), true),
                        Err(e) => (format!("✗ {e}"), true),
                    };
                    let _ = tx.send(Msg::SettingsNote(msg, err));
                });
            }
            Command::SettingsTest => {
                let ask = self.cfg.ask.clone();
                let tx = self.tx.clone();
                thread::spawn(move || {
                    let msg = match guarded(|| crate::llm::test_connection(&ask)) {
                        Ok(Ok((took, reply))) => (
                            format!(
                                "✓ {} answered in {:.1}s: {reply}",
                                crate::llm::destination(&ask),
                                took.as_secs_f64()
                            ),
                            false,
                        ),
                        Ok(Err(e)) => (format!("✗ {e}"), true),
                        Err(e) => (format!("✗ {e}"), true),
                    };
                    let _ = tx.send(Msg::SettingsNote(msg.0, msg.1));
                });
            }
            Command::SettingsModels => {
                let ask = self.cfg.ask.clone();
                let tx = self.tx.clone();
                thread::spawn(move || {
                    let r = guarded(|| crate::llm::resolve(&ask).and_then(|ep| ep.models())).unwrap_or_else(Err);
                    let _ = tx.send(Msg::SettingsModels(r));
                });
            }
            Command::DeleteThread(id) => {
                if let Some(p) = &self.threads_path {
                    match guarded(|| crate::threads::Store::open(p).and_then(|s| s.delete(id))) {
                        Ok(Ok(())) => {
                            if app.ask.open == Some(id) {
                                app.ask.open = None;
                                app.ask.turns.clear();
                            }
                            app.set_status("thread deleted", false);
                            self.exec(app, Command::Threads);
                        }
                        Ok(Err(e)) => app.set_status(format!("could not delete the thread: {e:#}"), true),
                        Err(e) => app.set_status(format!("could not delete the thread: {e}"), true),
                    }
                }
            }
            Command::RefreshTimeline { from, to } => match &self.hist {
                Some(h) if app.history_ok => {
                    let _ = h.send(HistReq::Timeline { from, to });
                }
                _ => app.use_ring_timeline(),
            },
            Command::LoadAt(ts) => match &self.hist {
                Some(h) if app.history_ok => {
                    let _ = h.send(HistReq::LoadAt(ts));
                }
                _ => app.set_past(ts, None),
            },
        }
    }
}

fn apply_msg(app: &mut App, msg: Msg) {
    match msg {
        Msg::Snap(s) => app.on_snapshot(*s),
        Msg::CollectorError(e) => app.collector_error = Some(e),
        Msg::Findings(f, starts) => app.set_findings_with_starts(f, starts),
        Msg::Fleet { containers } => app.set_fleet(containers),
        Msg::Events(from, ev) => app.set_events(from, ev),
        Msg::Incident(id, r) => app.set_incident(id, r),
        Msg::Counts(n) => app.set_counts(n),
        Msg::FleetInventory(r) => app.set_fleet_inventory(r),
        Msg::FleetHost(h) => app.fleet_host(*h),
        Msg::FleetDone(s) => app.fleet_done(*s),
        Msg::FleetFailed(e) => app.fleet_failed(e),
        Msg::FleetDrill(name, r) => app.set_fleet_drill(&name, r.map(|(s, f)| (*s, f))),
        Msg::Answer(id, a) => app.answered(id, *a),
        Msg::SettingsNote(text, err) => {
            if let Some(ui) = app.settings_ui() {
                ui.busy = None;
                ui.note = Some((text, err));
            }
        }
        Msg::Update(s) => app.update_note = crate::update::header_note(&s),
        Msg::AskOptions(opts) => {
            app.settings.ask_options = opts;
            app.settings.ask_detecting = false;
        }
        Msg::SettingsModels(r) => {
            if let Some(ui) = app.settings_ui() {
                ui.busy = None;
                match r {
                    Ok(models) => {
                        let cur =
                            ui.fields.iter().find(|f| f.key == "model").map(|f| f.value.clone()).unwrap_or_default();
                        let i = models.iter().position(|m| *m == cur).unwrap_or(0);
                        ui.picker = Some((models, i));
                    }
                    Err(e) => ui.note = Some((e, true)),
                }
            }
        }
        Msg::Timeline(Some((pts, spikes))) => app.set_timeline(pts, spikes),
        Msg::Timeline(None) => app.use_ring_timeline(),
        Msg::Past(ts, snap) => app.set_past(ts, snap.map(|s| *s)),
        Msg::Why(Ok(e)) => app.set_why(e),
        Msg::Why(Err(e)) => app.set_status(format!("why unavailable: {e}"), true),
        Msg::FsVolumes(ts, v) => app.set_volumes(ts, v),
        Msg::FsListing(p, l) => app.set_fs_listing(&p, l),
        Msg::FsGrowth(g) => app.set_fs_growth(*g),
        Msg::FsLargest(p, v) => app.set_fs_largest(&p, v),
        Msg::FsPast(p) => app.set_fs_past(*p),
        Msg::FsError(e) => app.set_fs_error(e),
    }
}

fn event_loop(
    term: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    ctx: &mut Ctx,
    rx: Receiver<Msg>,
) -> anyhow::Result<()> {
    let mut dirty = true;
    let mut last_draw = 0i64;
    while !app.quit {
        if QUIT_SIGNAL.load(Ordering::SeqCst) != 0 {
            app.quit = true;
            break;
        }
        let now = now_ms();
        for cmd in app.tick(now) {
            ctx.exec(app, cmd);
            dirty = true;
        }
        // spinner / status expiry need periodic redraws
        let periodic = if app.ask.pending.is_some() { 100 } else { 1000 };
        if dirty || now - last_draw >= periodic {
            term.draw(|f| ui::draw(f, app))?;
            last_draw = now;
            dirty = false;
        }
        if event::poll(Duration::from_millis(50))? {
            // drain everything queued so held keys don't lag behind rendering
            loop {
                match event::read()? {
                    Event::Key(k) if k.kind != KeyEventKind::Release => {
                        for cmd in app.on_key(k) {
                            ctx.exec(app, cmd);
                        }
                        if let Some(env) = app.shell.take() {
                            let (msg, err) = match run_shell(term, &env) {
                                Ok(code) => (shell_status(code), false),
                                Err(e) => (format!("shell: {e}"), true),
                            };
                            app.now = now_ms();
                            app.set_status(msg, err);
                            break;
                        }
                    }
                    Event::Resize(..) => {}
                    _ => {}
                }
                dirty = true;
                if app.quit || !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }
        while let Ok(msg) = rx.try_recv() {
            apply_msg(app, msg);
            dirty = true;
        }
    }
    Ok(())
}

pub fn run(cfg: crate::config::Config) -> anyhow::Result<()> {
    let _ = UI_THREAD.set(thread::current().id());
    install_panic_hook();
    let config_path =
        guarded(|| Config::path().display().to_string()).unwrap_or_else(|_| "~/.config/fat/config.toml".into());
    let hist = guarded(|| History::open(cfg.history_path.as_deref())).ok().and_then(Result::ok);

    let (tx, rx) = mpsc::channel::<Msg>();
    let fs_shared = Arc::new(FsShared::default());
    let profile = guarded(|| crate::server::Profile::detect(&cfg.server)).unwrap_or_default();
    spawn_sampler(cfg.clone(), profile, tx.clone(), fs_shared.clone());
    spawn_fleet(cfg.clone(), tx.clone());
    spawn_volumes(cfg.interval_ms, cfg.history_path.clone(), tx.clone(), fs_shared.clone());

    let mut app = App::new(cfg.interval_ms);
    app.config_path = config_path;
    app.history_ok = hist.is_some();
    app.shell_enabled = cfg.tui.shell;
    if std::env::var_os("FAT_SHELL").is_some() {
        app.set_status("this fat runs in a shell opened from another fat: exit both to get back to it", false);
    }
    app.configured_hosts = cfg.hosts.len();
    app.set_profile(profile, cfg.server.clone(), cfg.fleet.tui_refresh_s);
    let klog = (profile == crate::server::Profile::Server && cfg.server.kmsg && cfg!(target_os = "linux")).then(|| {
        KernelLogCache { read: Box::new(|since| crate::server::kernel::read_kmsg_since(Some(since))), cached: None }
    });
    let hist_tx = spawn_history(hist, tx.clone(), klog);
    // Peer names and networks for the Ports view (background; answers arrive with later samples).
    crate::peers::init(&cfg);
    // Update check (daily, cached; with [update] auto also the install): never delays the UI.
    {
        let (cfg, tx) = (cfg.clone(), tx.clone());
        let _ = thread::Builder::new().name("fat-update".into()).spawn(move || {
            if let Ok(Some(s)) = guarded(|| crate::update::background(&cfg)) {
                let _ = tx.send(Msg::Update(s));
            }
        });
    }
    let inventory: Inventory = Arc::default();
    spawn_inventory(cfg.clone(), inventory.clone(), tx.clone());
    let transport: Arc<dyn Transport> = Arc::new(fanout::SshTransport { cfg: cfg.fleet.clone() });
    let mut ctx = Ctx {
        cfg,
        hist: Some(hist_tx),
        actions: None,
        actions_failed: false,
        tx,
        fs_shared,
        fs: None,
        inventory,
        transport,
        threads_path: Some(crate::threads::default_path()),
        settings_path: Some(Config::path()),
    };
    // Nothing else runs before the first frame: the journal is read when the action log (`a`)
    // opens or an action runs, samples arrive from the sampler thread.

    QUIT_SIGNAL.store(0, Ordering::SeqCst);
    let old_signals = install_quit_signals();
    spawn_quit_watchdog();
    let res = setup_terminal().and_then(|mut term| event_loop(&mut term, &mut app, &mut ctx, rx));
    restore_terminal();
    restore_signals(old_signals);
    if let Ok(mut v) = BG_PANICS.lock() {
        for m in v.drain(..) {
            eprintln!("{m}");
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_catches_panics_quietly() {
        install_panic_hook();
        assert_eq!(guarded(|| 2 + 2), Ok(4));
        let e = guarded(|| -> u32 { panic!("boom {}", 1) }).unwrap_err();
        assert!(e.contains("boom 1"));
        let e = guarded(|| -> u32 { unreachable!("engine gap") }).unwrap_err();
        assert!(e.contains("engine gap"));
        // nested guards keep the depth balanced
        let r = guarded(|| guarded(|| -> u8 { panic!("inner") }).is_err());
        assert_eq!(r, Ok(true));
        assert_eq!(GUARD_DEPTH.with(|d| d.get()), 0);
    }

    #[test]
    fn exec_degrades_without_backends() {
        // Other modules may be stubs; executing commands must never panic.
        let (tx, _rx) = mpsc::channel();
        let mut ctx = Ctx {
            cfg: Config::default(),
            hist: None,
            actions: None,
            actions_failed: false,
            tx,
            fs_shared: Arc::default(),
            fs: None,
            inventory: Arc::default(),
            transport: Arc::new(fanout::LocalTransport { program: "true".into(), prefix: vec![] }),
            threads_path: None,
            settings_path: None,
        };
        let mut app = App::new(1000);
        ctx.exec(&mut app, Command::RefreshTimeline { from: 0, to: 1 });
        ctx.exec(&mut app, Command::LoadAt(5));
        app.on_snapshot(crate::tui::app::tests::snap(1));
        ctx.exec(&mut app, Command::Explain(200));
        // Note: Act/Undo are intentionally not exercised here — they would signal real pids.
        assert!(!app.quit);
        assert!(app.why.is_some(), "explain without history still answers inline");
    }

    #[test]
    fn settings_save_to_the_config_file_and_apply_live() {
        use app::Modal;
        let dir = std::env::temp_dir().join(format!("fat-tui-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "# mine\n[ask]\nprovider = \"anthropic\" # for now\n").unwrap();
        let (tx, _rx) = mpsc::channel();
        let mut ctx = Ctx {
            cfg: Config::parse(&std::fs::read_to_string(&path).unwrap()).unwrap(),
            hist: None,
            actions: None,
            actions_failed: false,
            tx,
            fs_shared: Arc::default(),
            fs: None,
            inventory: Arc::default(),
            transport: Arc::new(fanout::LocalTransport { program: "true".into(), prefix: vec![] }),
            threads_path: None,
            settings_path: Some(path.clone()),
        };
        let mut app = App::new(1000);
        use crossterm::event::{KeyCode, KeyEvent};
        let select = |app: &mut App, key: &str| {
            let ui = &mut app.settings;
            ui.sel =
                ui.rows().iter().position(|r| matches!(r, app::SRow::Field(i) if ui.fields[*i].key == key)).unwrap();
        };
        for c in app.on_key(KeyEvent::from(KeyCode::Char(','))) {
            ctx.exec(&mut app, c);
        }
        assert_eq!(app.tab, app::Tab::Settings);
        // Choices cycle and save at once.
        select(&mut app, "detail");
        let cmds = app.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            cmds,
            vec![Command::SetSetting { section: "ask".into(), key: "detail".into(), value: Some("minimal".into()) }]
        );
        for c in cmds {
            ctx.exec(&mut app, c);
        }
        assert_eq!(ctx.cfg.ask.detail, "minimal", "applied live");
        // Picking a way to connect writes it; one that needs an address opens it for typing.
        let server =
            crate::llm::AskOption { key: "openai".into(), label: "Another model server".into(), ..Default::default() };
        app.settings.ask_options = vec![server.clone()];
        ctx.exec(&mut app, Command::ApplyAskOption(server));
        assert_eq!(ctx.cfg.ask.provider, "openai");
        assert_eq!(app.settings.editing.as_deref(), Some(""), "the URL is waiting to be typed");
        assert_eq!(app.settings.field().map(|f| f.key.as_str()), Some("url"));
        app.settings.editing = None;
        assert_eq!(app.settings.ask_options.len(), 1, "the detected options survive the save");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("provider = \"openai\" # for now") && text.contains("# mine"), "{text}");
        let note = app.settings.note.clone().unwrap();
        assert!(!note.1 && note.0.contains("needs url"), "saved, with a warning that ask can't use it yet: {note:?}");
        // Bad input is refused with a reason; the file stays as it was.
        let set = |k: &str, v: Option<&str>| Command::SetSetting {
            section: "ask".into(),
            key: k.into(),
            value: v.map(str::to_string),
        };
        ctx.exec(&mut app, set("url", Some("llm:1234")));
        assert!(app.settings.note.as_ref().is_some_and(|(t, e)| *e && t.contains("http://")));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        ctx.exec(&mut app, set("url", Some("http://127.0.0.1:1")));
        ctx.exec(&mut app, set("model", Some("m")));
        assert_eq!(app.ask_dest, "openai · m · http://127.0.0.1:1 · minimal detail");
        // Reset removes the key; the default applies again.
        ctx.exec(&mut app, set("model", None));
        assert!(ctx.cfg.ask.model.is_empty());
        assert!(!std::fs::read_to_string(&path).unwrap().contains("model ="));
        // Server settings are editable too (they apply at the next start).
        ctx.exec(
            &mut app,
            Command::SetSetting { section: "fleet".into(), key: "concurrency".into(), value: Some("16".into()) },
        );
        assert!(std::fs::read_to_string(&path).unwrap().contains("concurrency = 16"));
        assert!(app.settings.note.as_ref().unwrap().0.contains("next time"));
        let shown = app.settings.fields.iter().find(|f| f.key == "concurrency").unwrap();
        assert_eq!((shown.value.as_str(), shown.source.clone()), ("16", crate::settings::Source::File));
        // Letting agents act asks first.
        select(&mut app, "allow_actions");
        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(app.settings.multi.is_some());
        app.on_key(KeyEvent::from(KeyCode::Char(' '))); // pause
        assert!(app.on_key(KeyEvent::from(KeyCode::Enter)).is_empty());
        let Modal::Confirm { prompt, cmd } = app.modal.clone() else { panic!("expected a confirmation") };
        assert!(prompt.contains("pause"), "{prompt}");
        app.modal = Modal::None;
        ctx.exec(&mut app, cmd);
        assert!(std::fs::read_to_string(&path).unwrap().contains("allow_actions = [\"pause\"]"));
        // Hosts: add one through the form, then remove it.
        ctx.exec(
            &mut app,
            Command::SaveHost {
                index: None,
                host: crate::config::HostCfg {
                    name: "web-01".into(),
                    ssh: Some("ops@web-01".into()),
                    ..Default::default()
                },
            },
        );
        assert_eq!(app.settings.hosts.len(), 1);
        assert!(std::fs::read_to_string(&path).unwrap().contains("[[hosts]]"));
        ctx.exec(&mut app, Command::DeleteHost(0));
        assert!(app.settings.hosts.is_empty());
        // Esc goes back to the view.
        app.on_key(KeyEvent::from(KeyCode::Esc));
        assert_eq!(app.tab, app::Tab::Procs);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn background_panic_leaves_terminal_alone() {
        install_panic_hook();
        let _ = UI_THREAD.set(thread::current().id());
        if UI_THREAD.get() != Some(&thread::current().id()) {
            return; // another test claimed the UI thread first; nothing to assert reliably
        }
        TERM_ACTIVE.store(true, Ordering::SeqCst);
        let r = thread::Builder::new().name("fat-test-bg".into()).spawn(|| panic!("collector blew up")).unwrap().join();
        let still_active = TERM_ACTIVE.swap(false, Ordering::SeqCst);
        assert!(r.is_err());
        assert!(still_active, "a background panic must not restore the terminal under the running UI");
        let msgs = BG_PANICS.lock().unwrap().drain(..).collect::<Vec<_>>();
        assert!(msgs.iter().any(|m| m.contains("collector blew up") && m.contains("fat-test-bg")), "{msgs:?}");
    }

    #[test]
    fn quit_signal_ends_event_loop_flag() {
        let old = install_quit_signals();
        QUIT_SIGNAL.store(0, Ordering::SeqCst);
        // SAFETY: raising SIGHUP at ourselves; our handler only stores an atomic.
        unsafe { libc::raise(libc::SIGHUP) };
        assert_eq!(QUIT_SIGNAL.swap(0, Ordering::SeqCst), libc::SIGHUP);
        restore_signals(old);
    }

    #[test]
    fn finding_starts_come_from_the_findings_snapshot() {
        let s = crate::tui::app::tests::snap(1);
        let pid = s.procs[0].pid;
        let f = vec![Finding { action: Some(format!("pause {pid}")), ..Default::default() }];
        let m = finding_starts(&f, &s);
        assert_eq!(m.get(&pid), Some(&s.procs[0].start_time));
    }

    /// Without a recorder, the OOM/24h header and the Events tab still show the kernel log's
    /// OOM kills.
    #[test]
    fn history_thread_merges_kernel_log() {
        let kill = now_ms() - 3_600_000;
        let read = move |_since: Ts| -> anyhow::Result<Vec<crate::server::Event>> {
            Ok(vec![crate::server::Event {
                ts: kill,
                kind: crate::server::EventKind::OomKill,
                subject: "pid:42".into(),
                source: "kmsg".into(),
                ..Default::default()
            }])
        };
        let (tx, rx) = mpsc::channel();
        let req = spawn_history(None, tx, Some(KernelLogCache { read: Box::new(read), cached: None }));
        req.send(HistReq::Counts).unwrap();
        req.send(HistReq::Events { from: kill - 60_000, to: now_ms() }).unwrap();
        let (mut counts, mut events) = (None, None);
        let deadline = Instant::now() + Duration::from_secs(5);
        while (counts.is_none() || events.is_none()) && Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Msg::Counts(n)) => counts = Some(n),
                Ok(Msg::Events(_, v)) => events = Some(v),
                _ => {}
            }
        }
        assert_eq!(counts, Some(Some(1)));
        assert_eq!(events.flatten().map(|v| v.len()), Some(1));
    }

    #[test]
    fn history_thread_serves_timeline_past_and_why() {
        let path = std::env::temp_dir().join(format!("fat-tui-hist-{}-{}.db", std::process::id(), now_ms()));
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut s = crate::tui::app::tests::snap(now_ms() - 10_000);
        for i in 0..5 {
            s.ts += 1000;
            s.system.cpu = 10.0 + i as f32;
            h.record(&s).unwrap();
        }
        let (tx, rx) = mpsc::channel();
        let req = spawn_history(Some(h), tx, None);
        let last_ts = s.ts;
        // A burst of time-travel requests: the newest must win, older ones may be skipped.
        for ts in (s.ts - 4000..=last_ts).step_by(1000) {
            req.send(HistReq::LoadAt(ts)).unwrap();
        }
        req.send(HistReq::Timeline { from: last_ts - 60_000, to: last_ts + 1 }).unwrap();
        req.send(HistReq::Explain(Box::new(s.clone()), s.procs[0].pid)).unwrap();
        let (mut past, mut timeline, mut why) = (Vec::new(), None, None);
        let deadline = Instant::now() + Duration::from_secs(5);
        while (timeline.is_none() || why.is_none() || past.last().map(|(t, _)| *t) != Some(last_ts))
            && Instant::now() < deadline
        {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Msg::Past(ts, snap)) => past.push((ts, snap.is_some())),
                Ok(Msg::Timeline(t)) => timeline = Some(t),
                Ok(Msg::Why(w)) => why = Some(w),
                _ => {}
            }
        }
        assert_eq!(past.last(), Some(&(last_ts, true)), "{past:?}");
        assert!(past.len() <= 5);
        assert!(matches!(timeline, Some(Some((ref pts, _))) if !pts.is_empty()), "timeline missing");
        assert!(matches!(why, Some(Ok(_))));
        drop(req);
        let _ = std::fs::remove_file(&path);
    }
}
