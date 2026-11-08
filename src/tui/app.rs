//! TUI state and key handling. Pure: no terminal, no signals, no I/O.
//! Side effects are requested as [`Command`]s which `tui::mod` executes and
//! feeds back through the `set_*` / `*_done` methods.

use crate::history::Point;
use crate::model::{ActionKind, ActionRecord, Container, Explanation, Finding, Proc, Snapshot, Ts};
use crate::tui::widgets::contains_ci;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

/// How much in-memory history we keep for time travel without the recorder.
pub const RING_MS: i64 = 10 * 60 * 1000;
/// Timeline window choices (ms) cycled with +/-.
pub const ZOOMS: [i64; 5] = [5 * 60_000, 10 * 60_000, 3_600_000, 6 * 3_600_000, 24 * 3_600_000];
pub const ZOOM_NAMES: [&str; 5] = ["5m", "10m", "1h", "6h", "24h"];
/// Status messages fade after this long.
pub const STATUS_MS: i64 = 6000;
const TIMELINE_REFRESH_MS: i64 = 3000;
const RING_PROCS_CPU: usize = 60;
const RING_PROCS_MEM: usize = 30;
const RING_PROCS_POWER: usize = 20;
const RING_CMD_MAX: usize = 160;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Procs,
    Ports,
    Fleet,
    Timeline,
    Doctor,
    Log,
}

impl Tab {
    pub const ALL: [Tab; 6] = [Tab::Procs, Tab::Ports, Tab::Fleet, Tab::Timeline, Tab::Doctor, Tab::Log];
    pub fn title(self) -> &'static str {
        match self {
            Tab::Procs => "Procs",
            Tab::Ports => "Ports",
            Tab::Fleet => "Fleet",
            Tab::Timeline => "Timeline",
            Tab::Doctor => "Doctor",
            Tab::Log => "Log",
        }
    }
    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    Cpu,
    Mem,
    Power,
    Net,
    Disk,
    Pid,
    Name,
}

impl SortKey {
    pub fn label(self) -> &'static str {
        match self {
            SortKey::Cpu => "cpu",
            SortKey::Mem => "mem",
            SortKey::Power => "power",
            SortKey::Net => "net",
            SortKey::Disk => "disk",
            SortKey::Pid => "pid",
            SortKey::Name => "name",
        }
    }
    /// Numeric columns sort hottest-first by default; identifiers ascending.
    pub fn default_desc(self) -> bool {
        !matches!(self, SortKey::Pid | SortKey::Name)
    }
}

/// Side effects the event loop must perform.
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// `start` is the target's start time when it was chosen (0 = unknown); the action is
    /// refused if the pid has since been reused by another process.
    Act { kind: ActionKind, pid: u32, nice: Option<i32>, start: u64 },
    Undo,
    Explain(u32),
    /// `id` ties the eventual answer to this question (a cancelled ask's late answer is dropped).
    Ask { id: u64, question: String },
    RefreshLog,
    RefreshTimeline { from: Ts, to: Ts },
    LoadAt(Ts),
    Quit,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Modal {
    None,
    /// Editing `App::filter` (shown in the footer).
    Filter,
    Confirm { prompt: String, cmd: Command },
    Renice { pid: u32, name: String, input: String, start: u64 },
    AskInput(String),
    Help,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AskState {
    Idle,
    Thinking { question: String, since: Ts, id: u64 },
    Answer { question: String, text: String, scroll: u16 },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostRow {
    pub name: String,
    pub ok: bool,
    pub cpu: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub procs: usize,
    pub ports: usize,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    pub text: String,
    pub error: bool,
    pub at: Ts,
}

/// One visible process row: index into the viewed snapshot's `procs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub idx: usize,
    pub depth: u16,
}

pub struct App {
    pub tab: Tab,
    pub live: Option<Snapshot>,
    /// Reduced snapshots for the last [`RING_MS`].
    pub ring: VecDeque<Snapshot>,
    /// Full-resolution system points for the last [`RING_MS`].
    pub ring_points: VecDeque<Point>,

    // time travel
    pub cursor: Option<Ts>,
    pub past: Option<Snapshot>,
    pub past_loading: bool,
    pub timeline: Vec<Point>,
    pub spikes: Vec<Ts>,
    pub timeline_from_history: bool,
    pub zoom: usize,
    last_timeline_refresh: Ts,

    // procs table
    pub sort: SortKey,
    pub sort_desc: bool,
    pub tree: bool,
    pub filter: String,
    filter_lower: String,
    pub rows: Vec<Row>,
    /// Some process in the current view runs in a container (shows the CONTAINER column).
    pub has_containers: bool,
    rows_dirty: bool,
    pub sel_pid: Option<u32>,
    /// Glue the selection to `sel_pid` across refreshes. Only after the user
    /// navigates; otherwise the cursor stays put at its row (top = hottest).
    pub follow: bool,
    pub sel: usize,
    pub offset: usize,

    // other lists
    pub port_rows: Vec<usize>,
    pub port_sel: usize,
    pub port_offset: usize,
    pub fleet_sel: usize,
    pub doctor_sel: usize,
    pub log_sel: usize,

    pub findings: Vec<Finding>,
    /// Start time of each pid the findings mention, from the snapshot they were computed on.
    pub findings_starts: HashMap<u32, u64>,
    pub findings_loaded: bool,
    pub log: Vec<ActionRecord>,
    pub containers: Vec<Container>,
    pub hosts: Vec<HostRow>,
    pub fleet_loaded: bool,

    pub why: Option<Explanation>,
    pub why_scroll: u16,
    pub ask: AskState,
    ask_seq: u64,
    pub modal: Modal,
    pub status: Option<Status>,

    pub now: Ts,
    pub config_path: String,
    pub history_ok: bool,
    pub configured_hosts: usize,
    pub interval_ms: u64,
    pub collector_error: Option<String>,
    pub quit: bool,
}

impl Default for App {
    fn default() -> Self {
        App::new(1500)
    }
}

impl App {
    pub fn new(interval_ms: u64) -> App {
        App {
            tab: Tab::Procs,
            live: None,
            ring: VecDeque::new(),
            ring_points: VecDeque::new(),
            cursor: None,
            past: None,
            past_loading: false,
            timeline: Vec::new(),
            spikes: Vec::new(),
            timeline_from_history: false,
            zoom: 1,
            last_timeline_refresh: 0,
            sort: SortKey::Cpu,
            sort_desc: true,
            tree: false,
            filter: String::new(),
            filter_lower: String::new(),
            has_containers: false,
            rows: Vec::new(),
            rows_dirty: true,
            sel_pid: None,
            follow: false,
            sel: 0,
            offset: 0,
            port_rows: Vec::new(),
            port_sel: 0,
            port_offset: 0,
            fleet_sel: 0,
            doctor_sel: 0,
            log_sel: 0,
            findings: Vec::new(),
            findings_starts: HashMap::new(),
            findings_loaded: false,
            log: Vec::new(),
            containers: Vec::new(),
            hosts: Vec::new(),
            fleet_loaded: false,
            why: None,
            why_scroll: 0,
            ask: AskState::Idle,
            ask_seq: 0,
            modal: Modal::None,
            status: None,
            now: crate::model::now_ms(),
            config_path: String::new(),
            history_ok: false,
            configured_hosts: 0,
            interval_ms,
            collector_error: None,
            quit: false,
        }
    }

    // ---------------------------------------------------------------- data in

    /// The snapshot every view renders: the past one when rewound, else live.
    pub fn view(&self) -> Option<&Snapshot> {
        if self.cursor.is_some() { self.past.as_ref() } else { self.live.as_ref() }
    }

    pub fn rewound(&self) -> bool {
        self.cursor.is_some()
    }

    pub fn on_snapshot(&mut self, mut snap: Snapshot) {
        if snap.containers.is_empty() && !self.containers.is_empty() {
            snap.containers = self.containers.clone();
        }
        self.ring_points.push_back(point_of(&snap));
        self.ring.push_back(reduce(&snap));
        let cutoff = snap.ts - RING_MS;
        while self.ring.front().is_some_and(|s| s.ts < cutoff) {
            self.ring.pop_front();
        }
        while self.ring_points.front().is_some_and(|p| p.ts < cutoff) {
            self.ring_points.pop_front();
        }
        self.live = Some(snap);
        self.collector_error = None;
        if !self.rewound() {
            self.rows_dirty = true;
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_findings(&mut self, f: Vec<Finding>) {
        self.set_findings_with_starts(f, HashMap::new());
    }

    pub fn set_findings_with_starts(&mut self, f: Vec<Finding>, starts: HashMap<u32, u64>) {
        self.findings_starts = starts;
        self.findings = f;
        self.findings_loaded = true;
        self.doctor_sel = self.doctor_sel.min(self.findings.len().saturating_sub(1));
    }

    pub fn set_fleet(&mut self, containers: Option<Vec<Container>>, hosts: Option<Vec<HostRow>>) {
        if let Some(c) = containers {
            if !self.filter.is_empty() && c != self.containers {
                self.rows_dirty = true; // the filter also matches container names
            }
            self.containers = c;
        }
        if let Some(h) = hosts {
            self.hosts = h;
        }
        self.fleet_loaded = true;
    }

    pub fn set_log(&mut self, log: Vec<ActionRecord>) {
        self.log = log;
        self.log_sel = self.log_sel.min(self.log.len().saturating_sub(1));
    }

    pub fn set_status(&mut self, text: impl Into<String>, error: bool) {
        self.status = Some(Status { text: text.into(), error, at: self.now });
    }

    pub fn set_why(&mut self, e: Explanation) {
        self.why = Some(e);
        self.why_scroll = 0;
    }

    /// Answer for ask `id`; ignored unless that exact question is still pending.
    pub fn set_answer(&mut self, id: u64, text: String) {
        if let AskState::Thinking { question, id: want, .. } = &self.ask
            && *want == id
        {
            self.ask = AskState::Answer { question: question.clone(), text, scroll: 0 };
        }
    }

    pub fn action_done(&mut self, r: &ActionRecord) {
        let verb = match r.kind {
            ActionKind::Pause => "paused",
            ActionKind::Resume => "resumed",
            ActionKind::Renice => "reniced",
            ActionKind::Term => "sent TERM to",
            ActionKind::Kill => "killed",
            ActionKind::KillTree => "terminated tree of",
        };
        let msg = if r.ok {
            let undo = if r.undoable { " · u to undo" } else { "" };
            format!("✓ {verb} {} ({}) {}{undo}", r.pid, r.name, r.message)
        } else {
            format!("✗ {:?} {} failed: {}", r.kind, r.pid, r.message)
        };
        self.set_status(msg, !r.ok);
        // Optimistic feedback until the next sample confirms it.
        if r.ok {
            let new_status = match r.kind {
                ActionKind::Pause => Some("T"),
                ActionKind::Resume => Some("S"),
                _ => None,
            };
            if let (Some(st), Some(live)) = (new_status, self.live.as_mut()) {
                let pids: Vec<u32> = if r.pids.is_empty() { vec![r.pid] } else { r.pids.clone() };
                for p in live.procs.iter_mut().filter(|p| pids.contains(&p.pid)) {
                    p.status = st.to_string();
                }
            }
            if let (Some(n), Some(live)) = (r.new_nice, self.live.as_mut())
                && let Some(p) = live.procs.iter_mut().find(|p| p.pid == r.pid) {
                    p.nice = n;
                }
        }
    }

    pub fn undo_done(&mut self, r: Option<&ActionRecord>) {
        match r {
            Some(r) if r.ok => self.set_status(format!("↶ undid #{} on {} ({}) {}", r.id, r.pid, r.name, r.message), false),
            Some(r) => self.set_status(format!("✗ undo failed: {}", r.message), true),
            None => self.set_status("nothing to undo", false),
        }
    }

    /// Timeline points from the recorder (sorted by ts).
    pub fn set_timeline(&mut self, mut points: Vec<Point>, spikes: Vec<Ts>) {
        points.sort_by_key(|p| p.ts);
        self.timeline = points;
        self.spikes = spikes;
        self.timeline_from_history = true;
    }

    /// Fallback: build the timeline from the in-memory ring.
    pub fn use_ring_timeline(&mut self) {
        let from = self.now - ZOOMS[self.zoom];
        self.timeline = self.ring_points.iter().filter(|p| p.ts >= from).cloned().collect();
        self.spikes = detect_spikes(&self.timeline);
        self.timeline_from_history = false;
    }

    /// Result of a `LoadAt` request.
    pub fn set_past(&mut self, ts: Ts, snap: Option<Snapshot>) {
        if self.cursor == Some(ts) {
            self.past = snap;
            self.past_loading = false;
            self.rows_dirty = true;
        }
    }

    /// Periodic housekeeping; returns refresh requests.
    pub fn tick(&mut self, now: Ts) -> Vec<Command> {
        self.now = now;
        if self.status.as_ref().is_some_and(|s| now - s.at > STATUS_MS) {
            self.status = None;
        }
        if self.tab == Tab::Timeline && now - self.last_timeline_refresh >= TIMELINE_REFRESH_MS {
            return vec![self.timeline_refresh()];
        }
        Vec::new()
    }

    fn timeline_refresh(&mut self) -> Command {
        self.last_timeline_refresh = self.now;
        Command::RefreshTimeline { from: self.now - ZOOMS[self.zoom], to: self.now }
    }

    // ---------------------------------------------------------------- rows

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn mark_dirty(&mut self) {
        self.rows_dirty = true;
    }

    /// Rebuild cached row order if anything changed. Cheap no-op otherwise.
    pub fn ensure_rows(&mut self) {
        if !self.rows_dirty {
            return;
        }
        self.rows_dirty = false;
        let (rows, ports, has_ctr) = match self.view() {
            Some(s) => {
                // Rewound snapshots carry their own container list; live ones get the fleet's.
                let cs = if s.containers.is_empty() { &self.containers } else { &s.containers };
                (
                    build_rows_in(&s.procs, cs, self.sort, self.sort_desc, self.tree, &self.filter_lower),
                    port_order(s),
                    s.procs.iter().any(|p| p.container.is_some()),
                )
            }
            None => (Vec::new(), Vec::new(), false),
        };
        self.rows = rows;
        self.has_containers = has_ctr;
        self.port_rows = ports;
        self.port_sel = self.port_sel.min(self.port_rows.len().saturating_sub(1));
        // keep the selection glued to the same pid across refreshes
        let found = self.sel_pid.filter(|_| self.follow).and_then(|pid| {
            let procs = &self.view()?.procs;
            self.rows.iter().position(|r| procs[r.idx].pid == pid)
        });
        self.sel = found.unwrap_or_else(|| self.sel.min(self.rows.len().saturating_sub(1)));
        self.sel_pid = self.row_pid(self.sel);
    }

    fn row_pid(&self, i: usize) -> Option<u32> {
        let s = self.view()?;
        self.rows.get(i).map(|r| s.procs[r.idx].pid)
    }

    pub fn selected_proc(&self) -> Option<&Proc> {
        let s = self.view()?;
        let row = self.rows.get(self.sel)?;
        s.procs.get(row.idx)
    }

    fn move_sel(&mut self, delta: isize) {
        self.ensure_rows();
        if self.rows.is_empty() {
            return;
        }
        self.sel = step(self.sel, delta, self.rows.len());
        self.sel_pid = self.row_pid(self.sel);
        self.follow = self.sel != 0;
    }

    pub fn selected_port(&self) -> Option<&crate::model::Port> {
        let s = self.view()?;
        s.ports.get(*self.port_rows.get(self.port_sel)?)
    }

    pub fn fleet_len(&self) -> usize {
        1 + self.containers.len() + self.hosts.len()
    }

    // ---------------------------------------------------------------- time travel

    fn move_cursor(&mut self, delta: isize) -> Vec<Command> {
        if self.timeline.is_empty() {
            self.set_status("no timeline yet — samples are still arriving", false);
            return Vec::new();
        }
        let len = self.timeline.len() as isize;
        let cur = match self.cursor {
            None => len, // live sits one past the newest point
            Some(ts) => nearest_idx(&self.timeline, ts) as isize,
        };
        let next = cur + delta;
        if next >= len {
            self.go_live();
            return Vec::new();
        }
        let ts = self.timeline[next.max(0) as usize].ts;
        self.jump_to(ts)
    }

    pub fn jump_to(&mut self, ts: Ts) -> Vec<Command> {
        self.cursor = Some(ts);
        self.rows_dirty = true;
        let tol = (self.interval_ms as i64 * 3).max(5000);
        let hit = self
            .ring
            .iter()
            .min_by_key(|s| (s.ts - ts).abs())
            .filter(|s| (s.ts - ts).abs() <= tol)
            .cloned();
        match hit {
            Some(s) => {
                self.past = Some(s);
                self.past_loading = false;
                Vec::new()
            }
            None => {
                self.past = None;
                self.past_loading = true;
                vec![Command::LoadAt(ts)]
            }
        }
    }

    pub fn go_live(&mut self) {
        if self.cursor.take().is_some() {
            self.set_status("▶ back to live", false);
        }
        self.past = None;
        self.past_loading = false;
        self.rows_dirty = true;
    }

    fn next_spike(&mut self) -> Vec<Command> {
        if self.spikes.is_empty() {
            self.set_status("no spikes in this window", false);
            return Vec::new();
        }
        let target = match self.cursor {
            None => *self.spikes.last().unwrap_or(&0),
            Some(c) => match self.spikes.iter().find(|&&t| t > c) {
                Some(&t) => t,
                None => {
                    self.set_status("wrapped to first spike", false);
                    self.spikes[0]
                }
            },
        };
        self.jump_to(target)
    }

    // ---------------------------------------------------------------- keys

    pub fn on_key(&mut self, k: KeyEvent) -> Vec<Command> {
        if k.kind == KeyEventKind::Release {
            return Vec::new();
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('c')) {
            self.quit = true;
            return vec![Command::Quit];
        }
        if self.modal != Modal::None {
            return self.on_modal_key(k);
        }
        if !matches!(self.ask, AskState::Idle) {
            return self.on_ask_key(k);
        }
        if self.why.is_some() {
            match k.code {
                KeyCode::Esc => {
                    self.why = None;
                    return Vec::new();
                }
                KeyCode::PageDown => {
                    self.why_scroll = self.why_scroll.saturating_add(5);
                    return Vec::new();
                }
                KeyCode::PageUp => {
                    self.why_scroll = self.why_scroll.saturating_sub(5);
                    return Vec::new();
                }
                _ => {}
            }
        }
        self.on_global_key(k)
    }

    fn on_modal_key(&mut self, k: KeyEvent) -> Vec<Command> {
        let modal = std::mem::replace(&mut self.modal, Modal::None);
        match modal {
            Modal::None => Vec::new(),
            Modal::Help => Vec::new(), // any key closes
            Modal::Filter => {
                match k.code {
                    KeyCode::Esc => self.set_filter(String::new()),
                    KeyCode::Enter => {}
                    KeyCode::Backspace => {
                        let mut f = self.filter.clone();
                        f.pop();
                        self.set_filter(f);
                        self.modal = Modal::Filter;
                    }
                    KeyCode::Char(c) => {
                        let mut f = self.filter.clone();
                        f.push(c);
                        self.set_filter(f);
                        self.modal = Modal::Filter;
                    }
                    _ => self.modal = Modal::Filter,
                }
                Vec::new()
            }
            Modal::Confirm { prompt, cmd } => match k.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => vec![cmd],
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Char('q') => {
                    self.set_status("cancelled", false);
                    Vec::new()
                }
                _ => {
                    self.modal = Modal::Confirm { prompt, cmd };
                    Vec::new()
                }
            },
            Modal::Renice { pid, name, mut input, start } => match k.code {
                KeyCode::Esc => {
                    self.set_status("renice cancelled", false);
                    Vec::new()
                }
                KeyCode::Enter => match input.trim().parse::<i32>() {
                    Ok(n) if (-20..=20).contains(&n) => {
                        vec![Command::Act { kind: ActionKind::Renice, pid, nice: Some(n), start }]
                    }
                    _ => {
                        self.set_status(format!("invalid nice '{input}' (use -20..20)"), true);
                        self.modal = Modal::Renice { pid, name, input, start };
                        Vec::new()
                    }
                },
                KeyCode::Backspace => {
                    input.pop();
                    self.modal = Modal::Renice { pid, name, input, start };
                    Vec::new()
                }
                KeyCode::Char(c) if c.is_ascii_digit() || c == '-' || c == '+' => {
                    if input.len() < 4 {
                        input.push(c);
                    }
                    self.modal = Modal::Renice { pid, name, input, start };
                    Vec::new()
                }
                _ => {
                    self.modal = Modal::Renice { pid, name, input, start };
                    Vec::new()
                }
            },
            Modal::AskInput(mut q) => match k.code {
                KeyCode::Esc => Vec::new(),
                KeyCode::Enter => {
                    let q = q.trim().to_string();
                    if q.is_empty() {
                        return Vec::new();
                    }
                    self.ask_seq += 1;
                    let id = self.ask_seq;
                    self.ask = AskState::Thinking { question: q.clone(), since: self.now, id };
                    vec![Command::Ask { id, question: q }]
                }
                KeyCode::Backspace => {
                    q.pop();
                    self.modal = Modal::AskInput(q);
                    Vec::new()
                }
                KeyCode::Char(c) => {
                    q.push(c);
                    self.modal = Modal::AskInput(q);
                    Vec::new()
                }
                _ => {
                    self.modal = Modal::AskInput(q);
                    Vec::new()
                }
            },
        }
    }

    fn on_ask_key(&mut self, k: KeyEvent) -> Vec<Command> {
        match &mut self.ask {
            AskState::Thinking { .. } => {
                if matches!(k.code, KeyCode::Esc | KeyCode::Char('q')) {
                    self.ask = AskState::Idle;
                    self.set_status("ask cancelled", false);
                }
            }
            AskState::Answer { scroll, .. } => match k.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => self.ask = AskState::Idle,
                KeyCode::Down => *scroll = scroll.saturating_add(1),
                KeyCode::Up => *scroll = scroll.saturating_sub(1),
                KeyCode::PageDown | KeyCode::Char(' ') => *scroll = scroll.saturating_add(10),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                KeyCode::Home => *scroll = 0,
                KeyCode::Char('?') => self.modal = Modal::AskInput(String::new()),
                _ => {}
            },
            AskState::Idle => {}
        }
        Vec::new()
    }

    pub fn set_filter(&mut self, f: String) {
        self.filter_lower = f.to_lowercase();
        self.filter = f;
        self.rows_dirty = true;
    }

    pub fn switch_tab(&mut self, t: Tab) -> Vec<Command> {
        if self.tab != t {
            self.why = None;
        }
        self.tab = t;
        match t {
            Tab::Log => vec![Command::RefreshLog],
            Tab::Timeline => vec![self.timeline_refresh()],
            _ => Vec::new(),
        }
    }

    fn on_global_key(&mut self, k: KeyEvent) -> Vec<Command> {
        match k.code {
            KeyCode::Char('q') => {
                self.quit = true;
                return vec![Command::Quit];
            }
            KeyCode::Char(c @ '1'..='6') => return self.switch_tab(Tab::ALL[(c as u8 - b'1') as usize]),
            KeyCode::Tab => return self.switch_tab(Tab::ALL[(self.tab.index() + 1) % 6]),
            KeyCode::BackTab => return self.switch_tab(Tab::ALL[(self.tab.index() + 5) % 6]),
            KeyCode::Char('h') | KeyCode::F(1) => {
                self.modal = Modal::Help;
                return Vec::new();
            }
            KeyCode::Char('?') => {
                self.modal = Modal::AskInput(String::new());
                return Vec::new();
            }
            KeyCode::Char('L') => {
                self.go_live();
                return Vec::new();
            }
            KeyCode::Char('u') => return vec![Command::Undo],
            KeyCode::Esc => {
                if !self.filter.is_empty() {
                    self.set_filter(String::new());
                } else if self.rewound() {
                    self.go_live();
                }
                return Vec::new();
            }
            _ => {}
        }
        match self.tab {
            Tab::Procs => self.on_procs_key(k),
            Tab::Timeline => self.on_timeline_key(k),
            Tab::Ports => self.on_ports_key(k),
            Tab::Fleet => {
                let n = self.fleet_len();
                list_nav(&mut self.fleet_sel, n, k.code);
                Vec::new()
            }
            Tab::Doctor => self.on_doctor_key(k),
            Tab::Log => {
                list_nav(&mut self.log_sel, self.log.len(), k.code);
                Vec::new()
            }
        }
    }

    fn set_sort(&mut self, key: SortKey) {
        if self.sort == key {
            self.sort_desc = !self.sort_desc;
        } else {
            self.sort = key;
            self.sort_desc = key.default_desc();
        }
        self.rows_dirty = true;
    }

    fn on_procs_key(&mut self, k: KeyEvent) -> Vec<Command> {
        match k.code {
            KeyCode::Up => self.move_sel(-1),
            KeyCode::Down => self.move_sel(1),
            KeyCode::PageUp => self.move_sel(-15),
            KeyCode::PageDown => self.move_sel(15),
            KeyCode::Home | KeyCode::Char('g') => self.move_sel(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_sel(isize::MAX / 2),
            KeyCode::Char('c') => self.set_sort(SortKey::Cpu),
            KeyCode::Char('m') => self.set_sort(SortKey::Mem),
            KeyCode::Char('p') => self.set_sort(SortKey::Power),
            KeyCode::Char('n') => self.set_sort(SortKey::Net),
            KeyCode::Char('d') => self.set_sort(SortKey::Disk),
            KeyCode::Char('i') => self.set_sort(SortKey::Pid),
            KeyCode::Char('N') => self.set_sort(SortKey::Name),
            KeyCode::Char('t') => {
                self.tree = !self.tree;
                self.rows_dirty = true;
            }
            KeyCode::Char('/') => self.modal = Modal::Filter,
            KeyCode::Enter | KeyCode::Char('w') => {
                self.ensure_rows();
                return self.selected_proc().map(|p| vec![Command::Explain(p.pid)]).unwrap_or_default();
            }
            KeyCode::Char(' ') | KeyCode::Char('z') | KeyCode::Char('r') | KeyCode::Char('k') | KeyCode::Char('K') => {
                self.ensure_rows();
                let Some(p) = self.selected_proc() else { return Vec::new() };
                let (pid, name, paused, start) = (p.pid, p.name.clone(), p.status == "T", p.start_time);
                return self.process_action(k.code, pid, name, start, paused, false);
            }
            _ => {}
        }
        Vec::new()
    }

    /// Shared action keys for any process-centric view.
    fn process_action(&mut self, code: KeyCode, pid: u32, name: String, start: u64, paused: bool, k_is_tree: bool) -> Vec<Command> {
        if self.rewound() {
            self.set_status("⏪ viewing the past — press L to return to live before acting", true);
            return Vec::new();
        }
        match code {
            KeyCode::Char(' ') | KeyCode::Char('z') => {
                let kind = if paused { ActionKind::Resume } else { ActionKind::Pause };
                vec![Command::Act { kind, pid, nice: None, start }]
            }
            KeyCode::Char('r') => {
                self.modal = Modal::Renice { pid, name, input: "10".into(), start };
                Vec::new()
            }
            KeyCode::Char('k') if !k_is_tree => {
                self.modal = Modal::Confirm {
                    prompt: format!("Send TERM to {pid} ({name})?"),
                    cmd: Command::Act { kind: ActionKind::Term, pid, nice: None, start },
                };
                Vec::new()
            }
            KeyCode::Char('k') | KeyCode::Char('K') => {
                self.modal = Modal::Confirm {
                    prompt: format!("Terminate {pid} ({name}) AND all its descendants?"),
                    cmd: Command::Act { kind: ActionKind::KillTree, pid, nice: None, start },
                };
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn on_timeline_key(&mut self, k: KeyEvent) -> Vec<Command> {
        let big = if k.modifiers.contains(KeyModifiers::SHIFT) { 10 } else { 1 };
        match k.code {
            KeyCode::Left | KeyCode::Char('[') => self.move_cursor(-big),
            KeyCode::Right | KeyCode::Char(']') => self.move_cursor(big),
            KeyCode::Char('{') => self.move_cursor(-10),
            KeyCode::Char('}') => self.move_cursor(10),
            KeyCode::Char('s') => self.next_spike(),
            KeyCode::Char('+') | KeyCode::Char('=') => {
                self.zoom = (self.zoom + 1).min(ZOOMS.len() - 1);
                vec![self.timeline_refresh()]
            }
            KeyCode::Char('-') | KeyCode::Char('_') => {
                self.zoom = self.zoom.saturating_sub(1);
                vec![self.timeline_refresh()]
            }
            _ => self.on_procs_key(k),
        }
    }

    fn on_ports_key(&mut self, k: KeyEvent) -> Vec<Command> {
        self.ensure_rows();
        let n = self.port_rows.len();
        if list_nav(&mut self.port_sel, n, k.code) {
            return Vec::new();
        }
        let Some(port) = self.selected_port() else { return Vec::new() };
        let (pid, name) = (port.pid, port.process.clone());
        match k.code {
            KeyCode::Enter | KeyCode::Char('w') => vec![Command::Explain(pid)],
            KeyCode::Char(' ') | KeyCode::Char('z') | KeyCode::Char('r') | KeyCode::Char('k') | KeyCode::Char('K') => {
                let p = self.view().and_then(|s| s.proc(pid));
                let paused = p.is_some_and(|p| p.status == "T");
                let start = p.map(|p| p.start_time).unwrap_or(0);
                self.process_action(k.code, pid, name, start, paused, true)
            }
            _ => Vec::new(),
        }
    }

    fn on_doctor_key(&mut self, k: KeyEvent) -> Vec<Command> {
        let n = self.findings.len();
        if list_nav(&mut self.doctor_sel, n, k.code) {
            return Vec::new();
        }
        let Some(f) = self.findings.get(self.doctor_sel) else { return Vec::new() };
        match k.code {
            KeyCode::Char('w') => f.pids.first().map(|&p| vec![Command::Explain(p)]).unwrap_or_default(),
            KeyCode::Enter => {
                let Some(action) = f.action.clone() else {
                    self.set_status("this finding has no suggested action", false);
                    return Vec::new();
                };
                if self.rewound() {
                    self.set_status("⏪ viewing the past — press L to return to live before acting", true);
                    return Vec::new();
                }
                match parse_action(&action) {
                    Some((kind, pid, nice)) => {
                        // Identity from the snapshot the finding was computed on, not today's.
                        let start = self.findings_starts.get(&pid).copied().unwrap_or(0);
                        self.modal = Modal::Confirm {
                            prompt: format!("Run suggested action: {action}?"),
                            cmd: Command::Act { kind, pid, nice, start },
                        };
                    }
                    None => self.set_status(format!("can't run '{action}' automatically"), true),
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
}

// -------------------------------------------------------------------- pure helpers

fn step(cur: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    (cur as isize).saturating_add(delta).clamp(0, len as isize - 1) as usize
}

/// Up/Down/PgUp/PgDn/Home/End on a plain list. Returns true if handled.
fn list_nav(sel: &mut usize, len: usize, code: KeyCode) -> bool {
    let delta = match code {
        KeyCode::Up => -1,
        KeyCode::Down => 1,
        KeyCode::PageUp => -10,
        KeyCode::PageDown => 10,
        KeyCode::Home | KeyCode::Char('g') => isize::MIN / 2,
        KeyCode::End | KeyCode::Char('G') => isize::MAX / 2,
        _ => return false,
    };
    *sel = step(*sel, delta, len);
    true
}

fn nearest_idx(points: &[Point], ts: Ts) -> usize {
    match points.binary_search_by_key(&ts, |p| p.ts) {
        Ok(i) => i,
        Err(i) => {
            if i == 0 {
                0
            } else if i >= points.len() {
                points.len() - 1
            } else if (points[i].ts - ts).abs() < (ts - points[i - 1].ts).abs() {
                i
            } else {
                i - 1
            }
        }
    }
}

pub fn point_of(s: &Snapshot) -> Point {
    let top = s.procs.iter().max_by(|a, b| a.cpu.total_cmp(&b.cpu));
    Point {
        ts: s.ts,
        cpu: s.system.cpu,
        mem_used: s.system.mem_used,
        power_mw: s.system.power_mw,
        net_rx_bps: s.system.net_rx_bps,
        net_tx_bps: s.system.net_tx_bps,
        disk_read_bps: s.system.disk_read_bps,
        disk_write_bps: s.system.disk_write_bps,
        top_name: top.map(|p| p.name.clone()).unwrap_or_default(),
        top_cpu: top.map(|p| p.cpu).unwrap_or(0.0),
    }
}

/// Shrink a snapshot for the in-memory ring: keep the interesting processes
/// (top by cpu/mem/power, plus any paused) and clip long command lines.
pub fn reduce(s: &Snapshot) -> Snapshot {
    let mut keep: HashSet<usize> = HashSet::new();
    let mut idx: Vec<usize> = (0..s.procs.len()).collect();
    idx.sort_by(|&a, &b| s.procs[b].cpu.total_cmp(&s.procs[a].cpu));
    keep.extend(idx.iter().take(RING_PROCS_CPU));
    idx.sort_by(|&a, &b| s.procs[b].mem.cmp(&s.procs[a].mem));
    keep.extend(idx.iter().take(RING_PROCS_MEM));
    idx.sort_by(|&a, &b| s.procs[b].power_mw.total_cmp(&s.procs[a].power_mw));
    keep.extend(idx.iter().take(RING_PROCS_POWER));
    keep.extend(s.procs.iter().enumerate().filter(|(_, p)| p.status == "T").map(|(i, _)| i));
    let mut kept: Vec<usize> = keep.into_iter().collect();
    kept.sort_unstable();
    let procs = kept
        .into_iter()
        .map(|i| {
            let p = &s.procs[i];
            Proc {
                cmd: crate::tui::widgets::clip(&p.cmd, RING_CMD_MAX).to_string(),
                exe: String::new(),
                cwd: String::new(),
                ..p.clone()
            }
        })
        .collect();
    Snapshot { ts: s.ts, host: s.host.clone(), system: s.system.clone(), procs, ports: s.ports.clone(), containers: Vec::new() }
}

/// Fallback spike detection over a timeline: sharp CPU or power jumps.
pub fn detect_spikes(points: &[Point]) -> Vec<Ts> {
    let mut out: Vec<Ts> = Vec::new();
    let mut last_i: Option<usize> = None;
    for i in 1..points.len() {
        let (a, b) = (&points[i - 1], &points[i]);
        let cpu_jump = b.cpu - a.cpu >= 25.0;
        let pw_jump = b.power_mw >= a.power_mw * 1.5 && b.power_mw - a.power_mw >= 5000.0;
        if (cpu_jump || pw_jump) && last_i.is_none_or(|l| i - l > 3) {
            out.push(b.ts);
            last_i = Some(i);
        }
    }
    out
}

fn cmp_proc(a: &Proc, b: &Proc, key: SortKey) -> Ordering {
    let o = match key {
        SortKey::Cpu => a.cpu.total_cmp(&b.cpu),
        SortKey::Mem => a.mem.cmp(&b.mem),
        SortKey::Power => a.power_mw.total_cmp(&b.power_mw),
        SortKey::Net => (a.net_rx_bps + a.net_tx_bps).cmp(&(b.net_rx_bps + b.net_tx_bps)),
        SortKey::Disk => (a.disk_read_bps + a.disk_write_bps).cmp(&(b.disk_read_bps + b.disk_write_bps)),
        SortKey::Pid => a.pid.cmp(&b.pid),
        SortKey::Name => a
            .name
            .bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.name.bytes().map(|c| c.to_ascii_lowercase())),
    };
    o.then(a.pid.cmp(&b.pid))
}

/// Filter match: name, command line, and (Linux) the cgroup path, container id and container
/// name, so `/postgres` finds every process of a `postgres` container and `/nginx.service`
/// finds a systemd unit's processes.
fn proc_matches(p: &Proc, containers: &[Container], filter_lower: &str) -> bool {
    if filter_lower.is_empty() || contains_ci(&p.name, filter_lower) || contains_ci(&p.cmd, filter_lower) {
        return true;
    }
    if !p.cgroup.is_empty() && contains_ci(&p.cgroup, filter_lower) {
        return true;
    }
    match &p.container {
        Some(id) => {
            contains_ci(id, filter_lower)
                || crate::fleet::find_container(containers, id)
                    .is_some_and(|c| contains_ci(&c.name, filter_lower) || contains_ci(&c.image, filter_lower))
        }
        None => false,
    }
}

/// Sorted (and optionally tree-ordered, filtered) row order for a proc list.
/// In tree mode a filter keeps matching processes plus their ancestors.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_rows(procs: &[Proc], key: SortKey, desc: bool, tree: bool, filter_lower: &str) -> Vec<Row> {
    build_rows_in(procs, &[], key, desc, tree, filter_lower)
}

/// [`build_rows`] with the container list the filter can match names against.
pub fn build_rows_in(procs: &[Proc], containers: &[Container], key: SortKey, desc: bool, tree: bool, filter_lower: &str) -> Vec<Row> {
    let ord = |a: usize, b: usize| {
        let o = cmp_proc(&procs[a], &procs[b], key);
        if desc { o.reverse() } else { o }
    };
    if !tree {
        let mut v: Vec<usize> = (0..procs.len()).filter(|&i| proc_matches(&procs[i], containers, filter_lower)).collect();
        v.sort_by(|&a, &b| ord(a, b));
        return v.into_iter().map(|idx| Row { idx, depth: 0 }).collect();
    }

    let by_pid: HashMap<u32, usize> = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
    let mut keep = vec![filter_lower.is_empty(); procs.len()];
    if !filter_lower.is_empty() {
        for (i, p) in procs.iter().enumerate() {
            if proc_matches(p, containers, filter_lower) {
                keep[i] = true;
                let mut cur = p.ppid;
                let mut guard = 0;
                while let Some(&j) = by_pid.get(&cur) {
                    if keep[j] || guard > 64 {
                        break;
                    }
                    keep[j] = true;
                    cur = procs[j].ppid;
                    guard += 1;
                }
            }
        }
    }
    let mut children: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    for (i, p) in procs.iter().enumerate() {
        if !keep[i] {
            continue;
        }
        if p.ppid != p.pid && by_pid.contains_key(&p.ppid) {
            children.entry(p.ppid).or_default().push(i);
        } else {
            roots.push(i);
        }
    }
    roots.sort_by(|&a, &b| ord(a, b));
    for v in children.values_mut() {
        v.sort_by(|&a, &b| ord(a, b));
    }
    let mut out = Vec::with_capacity(procs.len());
    let mut seen = vec![false; procs.len()];
    let mut stack: Vec<(usize, u16)> = roots.into_iter().rev().map(|i| (i, 0)).collect();
    while let Some((i, d)) = stack.pop() {
        if std::mem::replace(&mut seen[i], true) {
            continue;
        }
        out.push(Row { idx: i, depth: d });
        if let Some(kids) = children.get(&procs[i].pid) {
            stack.extend(kids.iter().rev().map(|&k| (k, d.saturating_add(1))));
        }
    }
    // Anything in a ppid cycle was never reached from a root; list it flat.
    for i in 0..procs.len() {
        if keep[i] && !seen[i] {
            out.push(Row { idx: i, depth: 0 });
        }
    }
    out
}

/// Ports ordered orphans first, then by port number.
pub fn port_order(s: &Snapshot) -> Vec<usize> {
    let mut v: Vec<usize> = (0..s.ports.len()).collect();
    v.sort_by(|&a, &b| {
        let (pa, pb) = (&s.ports[a], &s.ports[b]);
        pb.orphan.cmp(&pa.orphan).then(pa.port.cmp(&pb.port)).then(pa.pid.cmp(&pb.pid))
    });
    v
}

/// Parse a suggested action string like "pause 1234", "renice 1234 +10",
/// "kill -9 1234", "kill tree 1234", "fat resume 42".
pub fn parse_action(s: &str) -> Option<(ActionKind, u32, Option<i32>)> {
    let lower = s.to_lowercase();
    let toks: Vec<&str> = lower
        .split(|c: char| c.is_whitespace() || c == ':' || c == ',' || c == '(' || c == ')')
        .filter(|t| !t.is_empty())
        .collect();
    let mut it = toks.iter().skip_while(|t| **t == "fat").copied();
    let verb = it.next()?;
    let rest: Vec<&str> = it.collect();
    let is_pid = |t: &&str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    let pid_pos = rest.iter().position(is_pid)?;
    let pid: u32 = rest[pid_pos].parse().ok()?;
    let has = |w: &[&str]| rest.iter().any(|t| w.contains(t));
    let kind = match verb {
        "pause" | "stop" | "suspend" => ActionKind::Pause,
        "resume" | "cont" | "continue" | "unpause" => ActionKind::Resume,
        "renice" | "nice" => ActionKind::Renice,
        "term" | "terminate" => ActionKind::Term,
        "killtree" | "kill-tree" | "kill_tree" => ActionKind::KillTree,
        "kill" if has(&["tree", "--tree", "-tree"]) => ActionKind::KillTree,
        "kill" if has(&["-9", "--force", "force", "-kill"]) => ActionKind::Kill,
        "kill" => ActionKind::Term,
        _ => return None,
    };
    let nice = if kind == ActionKind::Renice {
        let n = rest[pid_pos + 1..].iter().find_map(|t| t.trim_start_matches('+').parse::<i32>().ok());
        Some(n.unwrap_or(10).clamp(-20, 20))
    } else {
        None
    };
    Some((kind, pid, nice))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{Port, Proto, System};

    pub fn proc(pid: u32, ppid: u32, name: &str, cpu: f32, mem: u64) -> Proc {
        Proc {
            pid,
            ppid,
            name: name.into(),
            cmd: format!("/usr/bin/{name} --flag"),
            user: "me".into(),
            cpu,
            mem,
            status: "S".into(),
            threads: 4,
            power_mw: cpu * 10.0,
            start_time: 1_700_000_000 + pid as u64,
            ..Default::default()
        }
    }

    pub fn snap(ts: Ts) -> Snapshot {
        Snapshot {
            ts,
            host: "local".into(),
            system: System {
                hostname: "testbox".into(),
                os: "macOS 15".into(),
                cpu_model: "Apple M3 Max".into(),
                cores: 4,
                per_core: vec![10.0, 50.0, 90.0, 5.0],
                cpu: 38.0,
                load: [2.5, 2.0, 1.5],
                mem_total: 64 << 30,
                mem_used: 24 << 30,
                swap_total: 4 << 30,
                swap_used: 1 << 30,
                mem_pressure: "warn".into(),
                thermal: "nominal".into(),
                gpus: vec![crate::model::Gpu { name: "M3 Max".into(), util: 12.0, mem_used: 0 }],
                power_mw: 23_400.0,
                net_rx_bps: 1 << 20,
                net_tx_bps: 300 << 10,
                disk_read_bps: 2 << 20,
                disk_write_bps: 1 << 20,
                uptime: 3 * 86400 + 4 * 3600,
                battery_pct: Some(85.0),
                on_battery: Some(false),
                ..Default::default()
            },
            procs: vec![
                proc(1, 0, "launchd", 0.1, 20 << 20),
                proc(100, 1, "zsh", 0.0, 5 << 20),
                proc(200, 100, "node", 88.0, 900 << 20),
                proc(201, 200, "esbuild", 40.0, 200 << 20),
                Proc { status: "T".into(), ..proc(300, 1, "sleepy", 0.0, 1 << 20) },
                proc(400, 1, "Google Chrome Helper", 12.0, 3 << 30),
            ],
            ports: vec![
                Port { proto: Proto::Tcp, addr: "127.0.0.1".into(), port: 5432, pid: 400, process: "postgres".into(), state: "LISTEN".into(), orphan: false, note: "postgres".into() },
                Port { proto: Proto::Tcp, addr: "*".into(), port: 3000, pid: 200, process: "node".into(), state: "LISTEN".into(), orphan: true, note: "vite dev server in ~/proj".into() },
            ],
            containers: vec![],
        }
    }

    /// A Linux-flavoured snapshot: PSI, RAPL power, a hwmon temperature, cgroups and two
    /// docker containers (one known to the runtime, one only by its cgroup id).
    pub fn linux_snap(ts: Ts) -> Snapshot {
        let mut s = snap(ts);
        s.system.os = "Ubuntu 24.04".into();
        s.system.cpu_model = "AMD EPYC 7763".into();
        s.system.mem_pressure = "normal".into();
        s.system.thermal = String::new();
        s.system.gpus.clear();
        s.system.battery_pct = None;
        s.system.on_battery = None;
        s.system.psi = Some(crate::model::Psi { cpu_some: 12.5, mem_some: 0.4, mem_full: 0.1, io_some: 31.0, io_full: 8.0 });
        s.system.temp_c = Some(71.0);
        s.system.power_mw = 48_200.0;
        s.system.power_source = "rapl".into();
        s.procs[0].name = "systemd".into();
        s.procs[0].cgroup = "/init.scope".into();
        for p in s.procs.iter_mut().skip(1) {
            p.cgroup = "/user.slice/user-1000.slice/session-3.scope".into();
        }
        let ctr = "/system.slice/docker-410892b21be2ffda255ceb4e7e2077d968864674cefc8174a3843e6f01c860f7.scope";
        s.procs.push(Proc { cgroup: ctr.into(), container: Some("410892b21be2".into()), ..proc(500, 1, "postgres", 22.0, 400 << 20) });
        s.procs.push(Proc { cgroup: ctr.into(), container: Some("410892b21be2".into()), ..proc(501, 500, "pg-worker", 3.0, 60 << 20) });
        s.procs.push(Proc {
            cgroup: "/system.slice/docker-f592d553371ffde52670af3ebf50d462cf46a69dde69dc441c816a077198847a.scope".into(),
            container: Some("f592d553371f".into()),
            ..proc(600, 1, "clickhouse", 9.0, 2 << 30)
        });
        s.containers = vec![Container {
            id: "410892b21be2".into(),
            name: "db-1".into(),
            image: "postgres:16".into(),
            runtime: "docker".into(),
            status: "Up 2 hours".into(),
            cpu: 25.0,
            mem: 460 << 20,
            ports: "5432/tcp".into(),
        }];
        s
    }

    #[test]
    fn filter_matches_container_name_id_and_cgroup() {
        let mut a = App::new(1000);
        a.on_snapshot(linux_snap(1_000_000));
        a.ensure_rows();
        assert!(a.has_containers);
        a.set_filter("db-1".into());
        a.ensure_rows();
        let mut n = names(&a);
        n.sort();
        assert_eq!(n, vec!["pg-worker", "postgres"]);
        a.set_filter("postgres:16".into()); // image
        a.ensure_rows();
        assert_eq!(a.rows.len(), 2);
        a.set_filter("f592d5".into()); // id of a container the runtime didn't report
        a.ensure_rows();
        assert_eq!(names(&a), vec!["clickhouse"]);
        a.set_filter("init.scope".into());
        a.ensure_rows();
        assert_eq!(names(&a), vec!["systemd"]);
        // macOS snapshot: no containers, column hidden
        let mut m = app();
        m.ensure_rows();
        assert!(!m.has_containers);
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn code(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }
    fn app() -> App {
        let mut a = App::new(1000);
        a.now = 1_000_000;
        a.on_snapshot(snap(1_000_000));
        a.ensure_rows();
        a
    }
    fn names(a: &App) -> Vec<String> {
        let s = a.view().unwrap();
        a.rows.iter().map(|r| s.procs[r.idx].name.clone()).collect()
    }

    #[test]
    fn default_sort_is_cpu_desc() {
        let a = app();
        assert_eq!(names(&a)[0], "node");
        assert_eq!(a.sel_pid, Some(200));
    }

    #[test]
    fn sort_keys_and_toggle() {
        let mut a = app();
        a.on_key(key('m'));
        a.ensure_rows();
        assert_eq!(names(&a)[0], "Google Chrome Helper");
        a.on_key(key('m'));
        a.ensure_rows();
        assert!(!a.sort_desc);
        assert_eq!(names(&a)[0], "sleepy");
        a.on_key(key('i'));
        a.ensure_rows();
        assert_eq!(a.sort, SortKey::Pid);
        assert!(!a.sort_desc);
        assert_eq!(names(&a)[0], "launchd");
        a.on_key(key('N'));
        a.ensure_rows();
        assert_eq!(names(&a)[0], "esbuild");
    }

    #[test]
    fn selection_follows_pid_across_resort() {
        let mut a = app();
        a.on_key(code(KeyCode::Down)); // esbuild
        assert_eq!(a.sel_pid, Some(201));
        a.on_key(key('i'));
        a.ensure_rows();
        assert_eq!(a.selected_proc().unwrap().pid, 201);
    }

    #[test]
    fn untouched_selection_stays_on_top_row() {
        let mut a = app();
        let mut s = snap(1_001_000);
        s.procs.iter_mut().find(|p| p.pid == 400).unwrap().cpu = 99.0;
        a.on_snapshot(s);
        a.ensure_rows();
        assert_eq!(a.sel, 0);
        assert_eq!(a.sel_pid, Some(400), "top row tracks the hottest process");
        // after explicit navigation the selection follows the pid
        a.on_key(code(KeyCode::Down));
        let pid = a.sel_pid;
        let mut s = snap(1_002_000);
        s.procs.iter_mut().find(|p| p.pid == 1).unwrap().cpu = 500.0;
        a.on_snapshot(s);
        a.ensure_rows();
        assert_eq!(a.sel_pid, pid);
        a.on_key(code(KeyCode::Home));
        assert!(!a.follow);
    }

    #[test]
    fn filter_flow() {
        let mut a = app();
        a.on_key(key('/'));
        assert_eq!(a.modal, Modal::Filter);
        for c in "CHROME".chars() {
            a.on_key(key(c));
        }
        a.ensure_rows();
        assert_eq!(names(&a), vec!["Google Chrome Helper"]);
        a.on_key(code(KeyCode::Enter));
        assert_eq!(a.modal, Modal::None);
        assert_eq!(a.filter, "CHROME");
        a.on_key(code(KeyCode::Esc));
        a.ensure_rows();
        assert!(a.filter.is_empty());
        assert_eq!(a.rows.len(), 6);
    }

    #[test]
    fn tree_view_indents_children_and_keeps_ancestors() {
        let mut a = app();
        a.on_key(key('t'));
        a.ensure_rows();
        let s = a.view().unwrap();
        let dep: Vec<(u32, u16)> = a.rows.iter().map(|r| (s.procs[r.idx].pid, r.depth)).collect();
        assert_eq!(dep[0], (1, 0));
        assert!(dep.contains(&(201, 3)));
        let i_node = dep.iter().position(|d| d.0 == 200).unwrap();
        assert_eq!(dep[i_node + 1].0, 201);
        a.set_filter("esbuild".into());
        a.ensure_rows();
        let s = a.view().unwrap();
        let pids: Vec<u32> = a.rows.iter().map(|r| s.procs[r.idx].pid).collect();
        assert_eq!(pids, vec![1, 100, 200, 201]);
    }

    #[test]
    fn tree_survives_ppid_cycle() {
        let procs = vec![proc(5, 6, "a", 1.0, 1), proc(6, 5, "b", 2.0, 1)];
        let rows = build_rows(&procs, SortKey::Cpu, true, true, "");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn tab_switching() {
        let mut a = app();
        assert_eq!(a.on_key(key('6')), vec![Command::RefreshLog]);
        assert_eq!(a.tab, Tab::Log);
        a.on_key(code(KeyCode::Tab));
        assert_eq!(a.tab, Tab::Procs);
        a.on_key(code(KeyCode::BackTab));
        assert_eq!(a.tab, Tab::Log);
        a.on_key(key('2'));
        assert_eq!(a.tab, Tab::Ports);
        let cmds = a.on_key(key('4'));
        assert!(matches!(cmds[0], Command::RefreshTimeline { .. }));
    }

    #[test]
    fn term_needs_confirmation() {
        let mut a = app();
        assert!(a.on_key(key('k')).is_empty());
        assert!(matches!(a.modal, Modal::Confirm { .. }));
        assert!(a.on_key(key('x')).is_empty()); // ignored, still open
        assert!(matches!(a.modal, Modal::Confirm { .. }));
        let cmds = a.on_key(key('y'));
        assert_eq!(cmds, vec![Command::Act { kind: ActionKind::Term, pid: 200, nice: None, start: 1700000200 }]);
        assert_eq!(a.modal, Modal::None);
        // cancel path
        a.on_key(key('K'));
        assert!(a.on_key(code(KeyCode::Esc)).is_empty());
        assert_eq!(a.modal, Modal::None);
    }

    #[test]
    fn pause_toggle_and_renice_prompt() {
        let mut a = app();
        assert_eq!(a.on_key(key(' ')), vec![Command::Act { kind: ActionKind::Pause, pid: 200, nice: None, start: 1700000200 }]);
        a.on_key(key('i'));
        a.ensure_rows();
        while a.sel_pid != Some(300) {
            a.on_key(code(KeyCode::Down));
        }
        assert_eq!(a.on_key(key('z')), vec![Command::Act { kind: ActionKind::Resume, pid: 300, nice: None, start: 1700000300 }]);
        a.on_key(key('r'));
        a.on_key(code(KeyCode::Backspace));
        a.on_key(code(KeyCode::Backspace));
        a.on_key(key('5'));
        assert_eq!(a.on_key(code(KeyCode::Enter)), vec![Command::Act { kind: ActionKind::Renice, pid: 300, nice: Some(5), start: 1700000300 }]);
        // default +10
        a.on_key(key('r'));
        assert_eq!(a.on_key(code(KeyCode::Enter)), vec![Command::Act { kind: ActionKind::Renice, pid: 300, nice: Some(10), start: 1700000300 }]);
        // invalid keeps prompt open
        a.on_key(key('r'));
        for c in "99".chars() {
            a.on_key(key(c));
        }
        assert!(a.on_key(code(KeyCode::Enter)).is_empty());
        assert!(matches!(a.modal, Modal::Renice { .. }));
    }

    #[test]
    fn action_done_marks_paused() {
        let mut a = app();
        let r = ActionRecord {
            id: 7, ts: 0, kind: ActionKind::Pause, pid: 200, name: "node".into(), prev_nice: None, new_nice: None,
            pids: vec![200], undoable: true, undone: false, ok: true, message: "SIGSTOP".into(),
        };
        a.action_done(&r);
        assert_eq!(a.live.as_ref().unwrap().proc(200).unwrap().status, "T");
        assert!(a.status.as_ref().unwrap().text.contains("u to undo"));
    }

    #[test]
    fn ports_k_is_kill_tree_and_enter_is_why() {
        let mut a = app();
        a.on_key(key('2'));
        a.ensure_rows();
        // orphan (3000, node) sorts first
        assert_eq!(a.selected_port().unwrap().port, 3000);
        assert_eq!(a.on_key(code(KeyCode::Enter)), vec![Command::Explain(200)]);
        a.on_key(key('k'));
        match &a.modal {
            Modal::Confirm { cmd, .. } => assert_eq!(*cmd, Command::Act { kind: ActionKind::KillTree, pid: 200, nice: None, start: 1700000200 }),
            m => panic!("expected confirm, got {m:?}"),
        }
    }

    #[test]
    fn ask_flow() {
        let mut a = app();
        a.on_key(key('?'));
        for c in "why slow".chars() {
            a.on_key(key(c));
        }
        assert_eq!(a.on_key(code(KeyCode::Enter)), vec![Command::Ask { id: 1, question: "why slow".into() }]);
        assert!(matches!(a.ask, AskState::Thinking { .. }));
        // keys don't leak to the table while thinking
        assert!(a.on_key(key('k')).is_empty());
        a.set_answer(1, "line\n".repeat(50));
        assert!(matches!(a.ask, AskState::Answer { .. }));
        a.on_key(code(KeyCode::PageDown));
        assert!(matches!(a.ask, AskState::Answer { scroll: 10, .. }));
        a.on_key(code(KeyCode::Esc));
        assert_eq!(a.ask, AskState::Idle);
    }

    #[test]
    fn cancelled_ask_answer_is_not_shown_under_the_next_question() {
        let mut a = app();
        let ask = |a: &mut App, q: &str| {
            a.on_key(key('?'));
            for c in q.chars() {
                a.on_key(key(c));
            }
            a.on_key(code(KeyCode::Enter))
        };
        assert_eq!(ask(&mut a, "q1"), vec![Command::Ask { id: 1, question: "q1".into() }]);
        a.on_key(code(KeyCode::Esc)); // cancel; q1's thread keeps running
        assert_eq!(ask(&mut a, "q2"), vec![Command::Ask { id: 2, question: "q2".into() }]);
        a.set_answer(1, "answer to q1".into());
        assert!(matches!(a.ask, AskState::Thinking { id: 2, .. }), "late q1 answer must be dropped");
        a.set_answer(2, "answer to q2".into());
        assert_eq!(a.ask, AskState::Answer { question: "q2".into(), text: "answer to q2".into(), scroll: 0 });
    }

    #[test]
    fn time_travel_through_ring() {
        let mut a = App::new(1000);
        for i in 0..20 {
            let mut s = snap(1_000_000 + i * 1000);
            s.system.cpu = if i == 10 { 95.0 } else { 10.0 };
            a.now = s.ts;
            a.on_snapshot(s);
        }
        a.tab = Tab::Timeline;
        a.use_ring_timeline();
        assert_eq!(a.timeline.len(), 20);
        assert_eq!(a.spikes, vec![1_010_000]);
        // left from live goes to the newest point
        assert!(a.on_key(code(KeyCode::Left)).is_empty());
        assert_eq!(a.cursor, Some(1_019_000));
        assert!(a.past.is_some());
        a.on_key(key('['));
        assert_eq!(a.cursor, Some(1_018_000));
        a.on_key(key('s'));
        assert_eq!(a.cursor, Some(1_010_000), "wraps to first spike");
        assert_eq!(a.view().unwrap().system.cpu, 95.0);
        // actions refused while rewound
        a.ensure_rows();
        assert!(a.on_key(key(' ')).is_empty());
        assert!(a.status.as_ref().unwrap().error);
        a.on_key(key('L'));
        assert!(!a.rewound());
        // right at the end returns to live
        a.on_key(code(KeyCode::Left));
        a.on_key(code(KeyCode::Right));
        assert!(!a.rewound());
    }

    #[test]
    fn jump_outside_ring_requests_history() {
        let mut a = app();
        let cmds = a.jump_to(5);
        assert_eq!(cmds, vec![Command::LoadAt(5)]);
        assert!(a.view().is_none());
        a.set_past(5, Some(snap(5)));
        assert_eq!(a.view().unwrap().ts, 5);
        a.set_past(6, None); // stale result ignored
        assert!(a.view().is_some());
    }

    #[test]
    fn ring_is_bounded_and_reduced() {
        let mut a = App::new(1000);
        let mut big = snap(0);
        for i in 0..500 {
            big.procs.push(Proc { cmd: "x".repeat(1000), ..proc(1000 + i, 1, "w", (i % 7) as f32, i as u64) });
        }
        for i in 0..700 {
            big.ts = i * 1000;
            a.on_snapshot(big.clone());
        }
        assert!(a.ring.len() <= 601);
        let r = a.ring.back().unwrap();
        assert!(r.procs.len() <= RING_PROCS_CPU + RING_PROCS_MEM + RING_PROCS_POWER + 5);
        assert!(r.procs.iter().all(|p| p.cmd.len() <= RING_CMD_MAX));
        assert!(r.procs.iter().any(|p| p.status == "T"), "paused procs survive reduction");
    }

    #[test]
    fn parse_suggested_actions() {
        assert_eq!(parse_action("pause 1234"), Some((ActionKind::Pause, 1234, None)));
        assert_eq!(parse_action("fat resume 42"), Some((ActionKind::Resume, 42, None)));
        assert_eq!(parse_action("renice 99 +10"), Some((ActionKind::Renice, 99, Some(10))));
        assert_eq!(parse_action("renice 99 -5"), Some((ActionKind::Renice, 99, Some(-5))));
        assert_eq!(parse_action("renice 99"), Some((ActionKind::Renice, 99, Some(10))));
        assert_eq!(parse_action("kill 7"), Some((ActionKind::Term, 7, None)));
        assert_eq!(parse_action("kill -9 7"), Some((ActionKind::Kill, 7, None)));
        assert_eq!(parse_action("kill --tree 7"), Some((ActionKind::KillTree, 7, None)));
        assert_eq!(parse_action("kill-tree 7"), Some((ActionKind::KillTree, 7, None)));
        assert_eq!(parse_action("Pause 55 (node)"), Some((ActionKind::Pause, 55, None)));
        assert_eq!(parse_action("restart docker"), None);
        assert_eq!(parse_action("pause it"), None);
    }

    #[test]
    fn doctor_enter_confirms_suggested_action() {
        let mut a = app();
        a.on_key(key('5'));
        a.set_findings_with_starts(
            vec![
                Finding { severity: "info".into(), title: "x".into(), detail: "".into(), pids: vec![], action: None },
                Finding { severity: "crit".into(), title: "node hot".into(), detail: "".into(), pids: vec![200], action: Some("pause 200".into()) },
            ],
            HashMap::from([(200, 42)]),
        );
        assert!(a.on_key(code(KeyCode::Enter)).is_empty());
        assert_eq!(a.modal, Modal::None);
        a.on_key(code(KeyCode::Down));
        a.on_key(code(KeyCode::Enter));
        // The identity comes from the findings' snapshot, not whatever is live now.
        assert_eq!(a.on_key(key('y')), vec![Command::Act { kind: ActionKind::Pause, pid: 200, nice: None, start: 42 }]);
        assert_eq!(a.on_key(key('w')), vec![Command::Explain(200)]);
    }

    #[test]
    fn quit_keys() {
        let mut a = app();
        assert_eq!(a.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)), vec![Command::Quit]);
        let mut a = app();
        a.on_key(key('/'));
        a.on_key(key('q')); // typed into filter, not quit
        assert!(!a.quit);
        assert_eq!(a.filter, "q");
    }

    #[test]
    fn status_expires() {
        let mut a = app();
        a.set_status("hi", false);
        a.tick(a.now + STATUS_MS + 1);
        assert!(a.status.is_none());
    }
}
