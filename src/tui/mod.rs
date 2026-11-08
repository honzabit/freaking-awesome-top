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
//! - ask: one short-lived thread per question
//!
//! Calls into other modules are wrapped in [`guarded`] so a panic in a collector
//! degrades to a status message instead of tearing down the terminal.

pub mod app;
pub mod ui;
pub mod widgets;

use crate::actions::Actions;
use crate::config::Config;
use crate::history::History;
use crate::history::Point;
use crate::model::{Container, Explanation, Finding, Snapshot, Ts, now_ms};
use app::{App, Command, HostRow};
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
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

enum Msg {
    Snap(Box<Snapshot>),
    CollectorError(String),
    /// Findings plus the start time of every pid they mention (from the same snapshot).
    Findings(Vec<Finding>, HashMap<u32, u64>),
    Fleet { containers: Option<Vec<Container>>, hosts: Option<Vec<HostRow>> },
    Answer(u64, String),
    /// None = no recorded history for this window (fall back to the in-memory ring).
    Timeline(Option<(Vec<Point>, Vec<Ts>)>),
    Past(Ts, Option<Box<Snapshot>>),
    Why(Result<Explanation, String>),
}

/// Work for the history thread.
enum HistReq {
    Timeline { from: Ts, to: Ts },
    LoadAt(Ts),
    Explain(Box<Snapshot>, u32),
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

// ------------------------------------------------------------------ background threads

fn spawn_sampler(cfg: Config, tx: Sender<Msg>) {
    thread::spawn(move || {
        let interval = Duration::from_millis(cfg.interval_ms.max(250));
        let mut col = match guarded(crate::collect::Collector::new) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Msg::CollectorError(e));
                return;
            }
        };
        let mut hist = guarded(|| History::open(cfg.history_path.as_deref())).ok().and_then(Result::ok);
        let keep_days = cfg.history_days.max(1);
        // Retention runs where the writing happens: at startup and hourly, like `fat record`.
        let mut last_prune: Option<Instant> = None;
        let mut diagnose_ok = true;
        let (mut last_rec, mut last_diag) = (0i64, 0i64);
        let mut first = true;
        loop {
            let snap = match guarded(|| col.sample()) {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(Msg::CollectorError(e));
                    return;
                }
            };
            let now = now_ms();
            if now - last_rec >= 2000 {
                last_rec = now;
                if let Some(h) = hist.as_mut() {
                    // A panic means the recorder is unusable; stop trying. Errors are ignored.
                    // record() is a no-op while another fat (e.g. `fat record`) holds the lease.
                    if guarded(|| h.record(&snap)).is_err() {
                        hist = None;
                    } else if h.is_writer() && last_prune.is_none_or(|t| t.elapsed() >= Duration::from_secs(3600)) {
                        last_prune = Some(Instant::now());
                        let _ = guarded(|| h.prune(keep_days));
                    }
                }
            }
            if diagnose_ok && now - last_diag >= 5000 {
                last_diag = now;
                match guarded(|| crate::blame::diagnose(&snap, hist.as_ref())) {
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

fn spawn_history(hist: Option<History>, tx: Sender<Msg>) -> Sender<HistReq> {
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
            for req in std::iter::once(first).chain(req_rx.try_iter()) {
                match req {
                    HistReq::Timeline { from, to } => timeline = Some((from, to)),
                    HistReq::LoadAt(ts) => load_at = Some(ts),
                    HistReq::Explain(s, pid) => explain = Some((s, pid)),
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

fn host_row(h: &crate::config::HostCfg) -> HostRow {
    match guarded(|| crate::fleet::remote(h)) {
        Ok(Ok(s)) => HostRow {
            name: h.name.clone(),
            ok: true,
            cpu: s.system.cpu,
            mem_used: s.system.mem_used,
            mem_total: s.system.mem_total,
            procs: s.procs.len(),
            ports: s.ports.len(),
            error: String::new(),
        },
        Ok(Err(e)) => HostRow { name: h.name.clone(), error: e.to_string(), ..Default::default() },
        Err(e) => HostRow { name: h.name.clone(), error: format!("unavailable: {e}"), ..Default::default() },
    }
}

fn spawn_fleet(cfg: Config, tx: Sender<Msg>) {
    thread::spawn(move || {
        let mut containers_ok = cfg.containers;
        let (mut last_c, mut last_h) = (i64::MIN / 2, i64::MIN / 2);
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
            let hosts = if now - last_h >= 10_000 {
                last_h = now;
                Some(cfg.hosts.iter().map(host_row).collect())
            } else {
                None
            };
            if (containers.is_some() || hosts.is_some()) && tx.send(Msg::Fleet { containers, hosts }).is_err() {
                return;
            }
            if !containers_ok && cfg.hosts.is_empty() {
                return; // nothing left to poll
            }
            thread::sleep(Duration::from_millis(1000));
        }
    });
}

// ------------------------------------------------------------------ main loop

struct Ctx {
    cfg: Config,
    /// Requests to the history thread (None in tests: views fall back to live data).
    hist: Option<Sender<HistReq>>,
    actions: Option<Actions>,
    actions_failed: bool,
    tx: Sender<Msg>,
}

impl Ctx {
    fn actions(&mut self) -> Option<&mut Actions> {
        if self.actions.is_none() && !self.actions_failed {
            match guarded(Actions::open) {
                Ok(a) => self.actions = Some(a),
                Err(_) => self.actions_failed = true,
            }
        }
        self.actions.as_mut()
    }

    fn exec(&mut self, app: &mut App, cmd: Command) {
        match cmd {
            Command::Quit => app.quit = true,
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
            Command::RefreshLog => {
                if let Some(a) = self.actions()
                    && let Ok(log) = guarded(|| a.log()) {
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
            Command::Ask { id, question: q } => {
                let snap = app.live.clone().unwrap_or_default();
                let findings = app.findings.clone();
                let ask_cfg = self.cfg.ask.clone();
                let tx = self.tx.clone();
                thread::spawn(move || {
                    let ans = guarded(|| crate::ask::ask(&q, &snap, &findings, &ask_cfg))
                        .unwrap_or_else(|e| format!("ask is unavailable right now ({e})."));
                    let _ = tx.send(Msg::Answer(id, ans));
                });
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
        Msg::Fleet { containers, hosts } => app.set_fleet(containers, hosts),
        Msg::Answer(id, a) => app.set_answer(id, a),
        Msg::Timeline(Some((pts, spikes))) => app.set_timeline(pts, spikes),
        Msg::Timeline(None) => app.use_ring_timeline(),
        Msg::Past(ts, snap) => app.set_past(ts, snap.map(|s| *s)),
        Msg::Why(Ok(e)) => app.set_why(e),
        Msg::Why(Err(e)) => app.set_status(format!("why unavailable: {e}"), true),
    }
}

fn event_loop(term: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App, ctx: &mut Ctx, rx: Receiver<Msg>) -> anyhow::Result<()> {
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
        let periodic = if matches!(app.ask, app::AskState::Thinking { .. }) { 100 } else { 1000 };
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
    let config_path = guarded(|| Config::path().display().to_string()).unwrap_or_else(|_| "~/.config/fat/config.toml".into());
    let hist = guarded(|| History::open(cfg.history_path.as_deref())).ok().and_then(Result::ok);

    let (tx, rx) = mpsc::channel::<Msg>();
    spawn_sampler(cfg.clone(), tx.clone());
    spawn_fleet(cfg.clone(), tx.clone());

    let mut app = App::new(cfg.interval_ms);
    app.config_path = config_path;
    app.history_ok = hist.is_some();
    app.configured_hosts = cfg.hosts.len();
    let hist_tx = spawn_history(hist, tx.clone());
    let mut ctx = Ctx { cfg, hist: Some(hist_tx), actions: None, actions_failed: false, tx };
    // Load the journal up front so the Log tab is ready.
    ctx.exec(&mut app, Command::RefreshLog);

    QUIT_SIGNAL.store(0, Ordering::SeqCst);
    let old_signals = install_quit_signals();
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
        let e = guarded(|| -> u32 { todo!() }).unwrap_err();
        assert!(e.contains("not yet implemented"));
        // nested guards keep the depth balanced
        let r = guarded(|| guarded(|| -> u8 { panic!("inner") }).is_err());
        assert_eq!(r, Ok(true));
        assert_eq!(GUARD_DEPTH.with(|d| d.get()), 0);
    }

    #[test]
    fn exec_degrades_without_backends() {
        // Other modules may be stubs; executing commands must never panic.
        let (tx, _rx) = mpsc::channel();
        let mut ctx = Ctx { cfg: Config::default(), hist: None, actions: None, actions_failed: false, tx };
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
        let req = spawn_history(Some(h), tx);
        let last_ts = s.ts;
        // A burst of time-travel requests: the newest must win, older ones may be skipped.
        for ts in (s.ts - 4000..=last_ts).step_by(1000) {
            req.send(HistReq::LoadAt(ts)).unwrap();
        }
        req.send(HistReq::Timeline { from: last_ts - 60_000, to: last_ts + 1 }).unwrap();
        req.send(HistReq::Explain(Box::new(s.clone()), s.procs[0].pid)).unwrap();
        let (mut past, mut timeline, mut why) = (Vec::new(), None, None);
        let deadline = Instant::now() + Duration::from_secs(5);
        while (timeline.is_none() || why.is_none() || past.last().map(|(t, _)| *t) != Some(last_ts)) && Instant::now() < deadline {
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
