//! Interactive TUI. OWNER: tui agent (everything under src/tui/).
//!
//! Threads:
//! - main: input + rendering + executing [`app::Command`]s (actions, why, history reads)
//! - sampler: `Collector::sample` every `interval_ms`, records into History (≤ every 2s),
//!   runs `blame::diagnose` every ~5s
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
use crate::model::{Container, Finding, Snapshot, now_ms};
use app::{App, Command, HostRow};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::cell::Cell;
use std::io::Stdout;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

enum Msg {
    Snap(Box<Snapshot>),
    CollectorError(String),
    Findings(Vec<Finding>),
    Fleet { containers: Option<Vec<Container>>, hosts: Option<Vec<HostRow>> },
    Answer(String),
}

// ------------------------------------------------------------------ panic safety

thread_local! {
    /// >0 while inside `guarded`: the panic hook stays quiet and leaves the terminal alone.
    static GUARD_DEPTH: Cell<u32> = const { Cell::new(0) };
}
static TERM_ACTIVE: AtomicBool = AtomicBool::new(false);

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
                    if guarded(|| h.record(&snap)).is_err() {
                        hist = None;
                    }
                }
            }
            if diagnose_ok && now - last_diag >= 5000 {
                last_diag = now;
                match guarded(|| crate::blame::diagnose(&snap, hist.as_ref())) {
                    Ok(f) => {
                        if tx.send(Msg::Findings(f)).is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        diagnose_ok = false;
                        let _ = tx.send(Msg::Findings(Vec::new()));
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
    hist: Option<History>,
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
            Command::Act { kind, pid, nice } => {
                let Some(live) = app.live.clone() else {
                    app.set_status("no live snapshot yet", true);
                    return;
                };
                let Some(a) = self.actions() else {
                    app.set_status("actions unavailable", true);
                    return;
                };
                match guarded(|| a.apply(kind, pid, nice, &live)) {
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
                let res = match app.view() {
                    Some(s) => guarded(|| crate::blame::explain(s, pid, self.hist.as_ref())),
                    None => Err("no snapshot".into()),
                };
                match res {
                    Ok(e) => app.set_why(e),
                    Err(e) => app.set_status(format!("why unavailable: {e}"), true),
                }
            }
            Command::Ask(q) => {
                let snap = app.live.clone().unwrap_or_default();
                let findings = app.findings.clone();
                let ask_cfg = self.cfg.ask.clone();
                let tx = self.tx.clone();
                thread::spawn(move || {
                    let ans = guarded(|| crate::ask::ask(&q, &snap, &findings, &ask_cfg))
                        .unwrap_or_else(|e| format!("ask is unavailable right now ({e})."));
                    let _ = tx.send(Msg::Answer(ans));
                });
            }
            Command::RefreshTimeline { from, to } => {
                let got = self.hist.as_ref().and_then(|h| {
                    let pts = guarded(|| h.timeline(from, to, 600)).ok()?.ok()?;
                    if pts.is_empty() {
                        return None;
                    }
                    let spikes = guarded(|| h.spikes(from, to)).ok().and_then(Result::ok).unwrap_or_default();
                    Some((pts, spikes.into_iter().map(|p| p.ts).collect::<Vec<_>>()))
                });
                match got {
                    Some((pts, mut spikes)) => {
                        spikes.sort_unstable();
                        app.set_timeline(pts, spikes);
                    }
                    None => app.use_ring_timeline(),
                }
            }
            Command::LoadAt(ts) => {
                let snap = self.hist.as_ref().and_then(|h| guarded(|| h.at(ts)).ok()?.ok()?);
                app.set_past(ts, snap);
            }
        }
    }
}

fn apply_msg(app: &mut App, msg: Msg) {
    match msg {
        Msg::Snap(s) => app.on_snapshot(*s),
        Msg::CollectorError(e) => app.collector_error = Some(e),
        Msg::Findings(f) => app.set_findings(f),
        Msg::Fleet { containers, hosts } => app.set_fleet(containers, hosts),
        Msg::Answer(a) => app.set_answer(a),
    }
}

fn event_loop(term: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App, ctx: &mut Ctx, rx: Receiver<Msg>) -> anyhow::Result<()> {
    let mut dirty = true;
    let mut last_draw = 0i64;
    while !app.quit {
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
    let mut ctx = Ctx { cfg, hist, actions: None, actions_failed: false, tx };
    // Load the journal up front so the Log tab is ready.
    ctx.exec(&mut app, Command::RefreshLog);

    let mut term = setup_terminal()?;
    let res = event_loop(&mut term, &mut app, &mut ctx, rx);
    restore_terminal();
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
    }
}
