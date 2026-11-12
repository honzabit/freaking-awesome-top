//! TUI state and key handling. Pure: no terminal, no signals, no I/O.
//! Side effects are requested as [`Command`]s which `tui::mod` executes and
//! feeds back through the `set_*` / `*_done` methods.

use crate::fs::{DirEntry, Evidence, Grower, Growth, Listing, Volume};
use crate::history::Point;
use crate::model::{ActionKind, ActionRecord, Container, Explanation, Finding, Proc, Snapshot, Ts};
use crate::server::{Event, FleetHost, FleetSummary, Incident, Profile, ServerCfg, Severity};
use crate::tui::server::{
    DrillView, EVENT_RING, EVENT_WINDOW_NAMES, EVENT_WINDOWS, EVENTS_REFRESH_MS, EventsView, FleetSort, FleetView,
    HostDrill, INCIDENT_WINDOW_MS, Panel, ServicesView, UnitSort,
};
use crate::tui::widgets::{DELETED_MIN_BYTES, DeletedGroup, contains_ci, group_deleted};
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
const RING_UNITS: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// Server profile: systemd units, containers, pods and cgroups (first tab there).
    Services,
    /// Server profile: the event timeline and incident explanations.
    Events,
    Procs,
    Ports,
    Fs,
    Timeline,
    Doctor,
    /// Questions to the model, kept as threads.
    Ask,
    /// Only shown when there is something beyond this machine (see [`App::fleet_visible`]).
    Fleet,
    /// Screens at the right of the tab bar, not views of the machine: no number key.
    /// The action journal (`a`).
    Log,
    /// Settings (`,`).
    Settings,
}

impl Tab {
    /// Every tab (tests iterate it). Which ones a profile shows, and their number keys, come
    /// from [`App::tab_order`].
    #[cfg(test)]
    pub const ALL: [Tab; 11] = [
        Tab::Services,
        Tab::Events,
        Tab::Procs,
        Tab::Ports,
        Tab::Fs,
        Tab::Timeline,
        Tab::Doctor,
        Tab::Ask,
        Tab::Fleet,
        Tab::Log,
        Tab::Settings,
    ];
    /// Screens (right of the tab bar, reached with `a` and `,` or Tab).
    pub const SCREENS: [Tab; 2] = [Tab::Log, Tab::Settings];
    /// Desktop: number keys 1-7. Fleet is last so hiding it never renumbers.
    pub const DESKTOP: [Tab; 7] = [Tab::Procs, Tab::Ports, Tab::Fs, Tab::Timeline, Tab::Doctor, Tab::Ask, Tab::Fleet];
    /// Server: services first, the event timeline next to processes.
    pub const SERVER: [Tab; 9] =
        [Tab::Services, Tab::Procs, Tab::Events, Tab::Ports, Tab::Fs, Tab::Timeline, Tab::Doctor, Tab::Ask, Tab::Fleet];
    pub fn title(self) -> &'static str {
        match self {
            Tab::Services => "Services",
            Tab::Events => "Events",
            Tab::Procs => "Procs",
            Tab::Ports => "Ports",
            Tab::Fs => "Fs",
            Tab::Timeline => "Timeline",
            Tab::Doctor => "Doctor",
            Tab::Ask => "Ask",
            Tab::Fleet => "Fleet",
            Tab::Log => "Log",
            Tab::Settings => "Settings",
        }
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
    Act {
        kind: ActionKind,
        pid: u32,
        nice: Option<i32>,
        start: u64,
    },
    /// Undo the most recent undoable action.
    Undo,
    /// Undo one journal entry by id (from the action log).
    UndoId(u64),
    Explain(u32),
    /// `id` ties the eventual answer to this question (a cancelled ask's late answer is not
    /// shown). `thread` None starts a new thread.
    Ask {
        id: u64,
        question: String,
        thread: Option<i64>,
    },
    /// Reload the list of ask threads.
    Threads,
    /// Load one thread's turns.
    OpenThread(i64),
    DeleteThread(i64),
    /// (Re)build the Settings screen from the config the app runs with.
    LoadSettings,
    /// Set `section.key` in the config file (None: remove it, so the default applies).
    SetSetting {
        section: String,
        key: String,
        value: Option<String>,
    },
    /// Add (index None) or replace a `[[hosts]]` entry.
    SaveHost {
        index: Option<usize>,
        host: crate::config::HostCfg,
    },
    DeleteHost(usize),
    /// ssh to the host and run `fat --version`.
    TestHost(crate::config::HostCfg),
    /// Connect ask this way (writes provider, enabled and, for a found server, its URL).
    ApplyAskOption(crate::llm::AskOption),
    /// Send a tiny question to the configured model.
    SettingsTest,
    /// List the configured server's models.
    SettingsModels,
    RefreshLog,
    RefreshTimeline {
        from: Ts,
        to: Ts,
    },
    LoadAt(Ts),
    /// Storage: children of `path`. `explicit` = the user drilled into a protected / mounted
    /// entry, which allows reading it (TCC-protected dirs, network mounts) this once.
    FsList {
        path: String,
        explicit: bool,
    },
    /// Storage growth report for the last `window_ms` (`under` = only paths below it).
    FsGrowth {
        window_ms: i64,
        under: Option<String>,
    },
    FsRescan(String),
    FsLargest(String),
    /// Recorded directory sizes below `path` and volume use near `ts` (time travel).
    FsAt {
        ts: Ts,
        path: String,
    },
    /// Server profile: recorded events in [from, to] (falls back to the live ring).
    LoadEvents {
        from: Ts,
        to: Ts,
    },
    /// Explain one event ("what happened around it"); `id` ties the answer to the panel.
    ExplainEvent {
        id: u64,
        event: Box<Event>,
    },
    /// What happened at `at` (None = now) within `window_ms`.
    WhatHappened {
        id: u64,
        at: Option<Ts>,
        window_ms: i64,
    },
    /// Header counters from the recorder (OOM kills in the last 24h).
    RefreshCounts,
    /// Poll every inventory host once (read-only), streaming rows back.
    FleetPoll,
    /// Fetch one host's snapshot (read-only) for the drill-in view.
    FleetDrill(String),
    Quit,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Modal {
    None,
    /// Editing `App::filter` (shown in the footer).
    Filter,
    Confirm {
        prompt: String,
        cmd: Command,
    },
    Renice {
        pid: u32,
        name: String,
        input: String,
        start: u64,
    },
    Help,
    /// The Ports filter dialog (`f` in Ports).
    PortFilter(PortFilterForm),
}

/// Ports view presets (the chips above the table). All is the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PortView {
    #[default]
    All,
    Listen,
    Established,
    TimeWait,
    CloseWait,
    /// SYN_*, FIN_WAIT*, LAST_ACK, CLOSING…
    Other,
    Orphans,
}

impl PortView {
    pub const ALL: [PortView; 7] = [
        PortView::All,
        PortView::Listen,
        PortView::Established,
        PortView::TimeWait,
        PortView::CloseWait,
        PortView::Other,
        PortView::Orphans,
    ];

    pub fn title(self) -> &'static str {
        match self {
            PortView::All => "All",
            PortView::Listen => "Listen",
            PortView::Established => "Established",
            PortView::TimeWait => "Time-wait",
            PortView::CloseWait => "Close-wait",
            PortView::Other => "Other",
            PortView::Orphans => "Orphans",
        }
    }

    /// Does a connection in TCP `state` belong here?
    pub fn has_state(self, state: &str) -> bool {
        match self {
            PortView::All => true,
            PortView::Established => state == "ESTABLISHED",
            PortView::TimeWait => state == "TIME_WAIT",
            PortView::CloseWait => state == "CLOSE_WAIT",
            PortView::Other => !matches!(state, "ESTABLISHED" | "TIME_WAIT" | "CLOSE_WAIT" | "LISTEN"),
            PortView::Listen | PortView::Orphans => false,
        }
    }
}

/// Where an address is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PortScope {
    #[default]
    Any,
    Loopback,
    /// RFC 1918, CGNAT, IPv6 ULA and link-local.
    Private,
    Public,
}

impl PortScope {
    pub const ALL: [PortScope; 4] = [PortScope::Any, PortScope::Loopback, PortScope::Private, PortScope::Public];

    pub fn title(self) -> &'static str {
        match self {
            PortScope::Any => "any",
            PortScope::Loopback => "loopback",
            PortScope::Private => "private (LAN)",
            PortScope::Public => "public",
        }
    }

    /// The scope of an address as fat shows it ("127.0.0.1", "[::1]", "*"). A listener on
    /// every interface ("*") is reachable from outside: public.
    pub fn of(addr: &str) -> PortScope {
        let a = addr.trim_start_matches('[').trim_end_matches(']');
        if a == "*" || a.is_empty() {
            return PortScope::Public;
        }
        match a.parse::<std::net::IpAddr>() {
            Ok(ip) if ip.is_loopback() => PortScope::Loopback,
            Ok(ip) if crate::llm::is_local(ip) => PortScope::Private,
            Ok(_) => PortScope::Public,
            Err(_) => PortScope::Any,
        }
    }
}

/// The Ports filter (`f`). Empty fields match everything.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PortFilter {
    pub proto: Option<crate::model::Proto>,
    pub scope: PortScope,
    /// Substring of the process name.
    pub process: String,
    /// "8080" or "8000-8100": our port or the peer's.
    pub port: String,
    /// Substring of the peer address.
    pub remote: String,
}

impl PortFilter {
    pub fn is_empty(&self) -> bool {
        *self == PortFilter::default()
    }

    fn port_range(&self) -> Option<(u16, u16)> {
        let t = self.port.trim();
        match t.split_once('-') {
            Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
            None => t.parse().ok().map(|p| (p, p)),
        }
    }

    fn port_ok(&self, ports: &[u16]) -> bool {
        if self.port.trim().is_empty() {
            return true;
        }
        match self.port_range() {
            Some((lo, hi)) => ports.iter().any(|p| *p != 0 && (lo..=hi).contains(p)),
            None => false,
        }
    }

    fn process_ok(&self, name: &str) -> bool {
        self.process.is_empty() || name.to_lowercase().contains(&self.process.trim().to_lowercase())
    }

    pub fn matches_port(&self, p: &crate::model::Port) -> bool {
        self.proto.is_none_or(|x| x == p.proto)
            && (self.scope == PortScope::Any || PortScope::of(&p.addr) == self.scope)
            && self.process_ok(&p.process)
            && self.port_ok(&[p.port])
            && self.remote.trim().is_empty()
    }

    pub fn matches_group(&self, g: &crate::model::ConnGroup) -> bool {
        self.proto.is_none_or(|x| x == crate::model::Proto::Tcp)
            && (self.scope == PortScope::Any || PortScope::of(&g.remote) == self.scope)
            && self.process_ok(&g.process)
            && self.port_ok(&[g.local_port, g.remote_port])
            && (self.remote.trim().is_empty() || peer_matches(g, self.remote.trim()))
    }

    /// "tcp · public · port 443" for titles.
    pub fn describe(&self) -> String {
        let mut v = Vec::new();
        if let Some(p) = self.proto {
            v.push(format!("{p:?}").to_lowercase());
        }
        if self.scope != PortScope::Any {
            v.push(self.scope.title().to_string());
        }
        if !self.process.is_empty() {
            v.push(format!("process ~{}", self.process));
        }
        if !self.port.is_empty() {
            v.push(format!("port {}", self.port));
        }
        if !self.remote.is_empty() {
            v.push(format!("peer ~{}", self.remote));
        }
        v.join(" · ")
    }
}

/// The filter dialog: rows protocol, scope, process, port, peer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PortFilterForm {
    pub sel: usize,
    pub editing: bool,
}

impl PortFilterForm {
    pub const LABELS: [&'static str; 5] = ["Protocol", "Address scope", "Process", "Port", "Peer"];
}

/// The peer filter: part of the address, of its name, or of its network ("AS15169", "google").
fn peer_matches(g: &crate::model::ConnGroup, q: &str) -> bool {
    if g.remote.contains(q) {
        return true;
    }
    let q = q.to_lowercase();
    g.peer_name.contains(&q)
        || g.peer_net
            .as_ref()
            .is_some_and(|n| format!("as{}", n.asn).starts_with(&q) || n.name.to_lowercase().contains(&q))
}

/// One row of the Ports table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortRow {
    /// A listener or bound UDP socket (index into `Snapshot::ports`).
    Listen(usize),
    /// A group of connections (index into `Snapshot::conns.groups`).
    Group(usize),
}

/// The Settings screen: every setting, its value and where it comes from, by group.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SettingsUi {
    pub fields: Vec<crate::settings::Field>,
    pub hosts: Vec<crate::config::HostCfg>,
    /// Selected row in [`SettingsUi::rows`].
    pub sel: usize,
    /// Text being typed for the selected field.
    pub editing: Option<String>,
    /// Models offered by the server, and the highlighted one.
    pub picker: Option<(Vec<String>, usize)>,
    /// A checklist being edited (agents' allowed actions): (option, on), highlighted row.
    pub multi: Option<(Vec<(String, bool)>, usize)>,
    pub host_form: Option<HostForm>,
    /// The ways to connect ask found on this machine (empty while detecting).
    pub ask_options: Vec<crate::llm::AskOption>,
    pub ask_detecting: bool,
    /// Show the advanced ask settings.
    pub ask_advanced: bool,
    /// Last result: (message, is_error).
    pub note: Option<(String, bool)>,
    /// A background check is running ("testing…").
    pub busy: Option<String>,
    pub path: String,
    pub key_status: String,
}

/// One row of the Settings screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SRow {
    Field(usize),
    Host(usize),
    AddHost,
    /// One of the detected ways to connect ask (index into `ask_options`).
    AskOption(usize),
    /// Show or hide the advanced ask settings.
    AskAdvanced,
}

impl SettingsUi {
    /// Rows in sidebar-group order.
    pub fn rows(&self) -> Vec<SRow> {
        let mut out = Vec::new();
        for g in crate::settings::GROUPS {
            if *g == "Ask" {
                out.extend(self.ask_rows());
            } else if *g == "Hosts" {
                out.extend((0..self.hosts.len()).map(SRow::Host));
                out.push(SRow::AddHost);
            } else {
                out.extend(self.fields.iter().enumerate().filter(|(_, f)| f.group == *g).map(|(i, _)| SRow::Field(i)));
            }
        }
        out
    }

    pub fn group_of(&self, r: SRow) -> &'static str {
        match r {
            SRow::Field(i) => self.fields.get(i).map_or("", |f| f.group),
            SRow::AskOption(_) | SRow::AskAdvanced => "Ask",
            _ => "Hosts",
        }
    }

    /// An `[ask]` field's value as the screen shows it.
    pub fn ask_value(&self, key: &str) -> &str {
        self.fields.iter().find(|f| f.section == "ask" && f.key == key).map_or("", |f| f.value.as_str())
    }

    /// The Ask page: the ways to connect, then the details that choice needs, then privacy,
    /// then (on request) the advanced settings.
    pub fn ask_rows(&self) -> Vec<SRow> {
        let provider = self.ask_value("provider").to_string();
        let field_rows = |sub: &str| -> Vec<SRow> {
            self.fields
                .iter()
                .enumerate()
                .filter(|(_, f)| f.section == "ask" && f.sub == sub && crate::settings::ask_relevant(&f.key, &provider))
                .map(|(i, _)| SRow::Field(i))
                .collect()
        };
        let mut out: Vec<SRow> = (0..self.ask_options.len()).map(SRow::AskOption).collect();
        out.extend(field_rows("details"));
        out.extend(field_rows("privacy"));
        out.push(SRow::AskAdvanced);
        if self.ask_advanced {
            out.extend(field_rows("advanced"));
        }
        out
    }

    /// Which detected option the current settings are (None while detecting).
    pub fn current_ask_option(&self) -> Option<usize> {
        if self.ask_value("enabled") == "false" {
            return self.ask_options.iter().position(|o| o.key == "off");
        }
        let provider = self.ask_value("provider");
        let url = self.ask_value("url").trim_end_matches('/');
        let server = matches!(provider, "ollama" | "openai" | "openai-compatible" | "lmstudio" | "vllm");
        self.ask_options
            .iter()
            .position(|o| o.key == provider && o.url.as_deref().is_some_and(|u| u == url))
            .or_else(|| self.ask_options.iter().position(|o| o.key == provider && o.url.is_none()))
            // A server elsewhere (any kind): "Another model server".
            .or_else(|| {
                server.then(|| self.ask_options.iter().position(|o| o.key == "openai" && o.url.is_none())).flatten()
            })
    }

    pub fn selected(&self) -> Option<SRow> {
        self.rows().get(self.sel).copied()
    }

    pub fn field(&self) -> Option<&crate::settings::Field> {
        match self.selected() {
            Some(SRow::Field(i)) => self.fields.get(i),
            _ => None,
        }
    }

    /// Something has the keyboard (typing, a picker, a checklist, the host form).
    pub fn capturing(&self) -> bool {
        self.editing.is_some() || self.picker.is_some() || self.multi.is_some() || self.host_form.is_some()
    }
}

/// Adding or editing one `[[hosts]]` entry.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostForm {
    /// None: a new host.
    pub index: Option<usize>,
    /// name, ssh destination, fat path, groups, tags.
    pub values: [String; 5],
    pub sel: usize,
    pub editing: bool,
}

impl HostForm {
    pub const LABELS: [&'static str; 5] = ["Name", "ssh destination", "fat path", "Groups", "Tags"];
    pub const HELP: [&'static str; 5] = [
        "how fat names it (and the ssh destination if none is given)",
        "user@host or an ssh config alias; empty = the name",
        "fat on that host; empty = found on PATH or the usual install dirs",
        "comma-separated, for fat fleet --group",
        "comma-separated, for fat fleet --tag",
    ];

    pub fn from(index: Option<usize>, h: &crate::config::HostCfg) -> HostForm {
        HostForm {
            index,
            values: [
                h.name.clone(),
                h.ssh.clone().unwrap_or_default(),
                h.fat_path.clone().unwrap_or_default(),
                h.groups.join(", "),
                h.tags.join(", "),
            ],
            sel: 0,
            editing: index.is_none(),
        }
    }

    pub fn host(&self) -> crate::config::HostCfg {
        let opt = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
        let list = |s: &str| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
        crate::config::HostCfg {
            name: self.values[0].trim().to_string(),
            ssh: opt(&self.values[1]),
            fat_path: opt(&self.values[2]),
            groups: list(&self.values[3]),
            tags: list(&self.values[4]),
        }
    }
}

/// The Ask tab: past threads on the left, the open thread on the right, an input line below.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AskTab {
    pub threads: Vec<crate::threads::Thread>,
    /// Selected row in `threads`.
    pub sel: usize,
    /// The thread shown; None = a new thread (the next question starts one).
    pub open: Option<i64>,
    pub turns: Vec<crate::threads::Turn>,
    pub input: String,
    /// Keys go to the input line.
    pub typing: bool,
    /// Lines scrolled up from the bottom of the conversation.
    pub scroll_up: u16,
    pub pending: Option<Pending>,
    /// Why threads can't be saved or read (shown instead of the list).
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pending {
    pub id: u64,
    pub question: String,
    pub since: Ts,
    pub thread: Option<i64>,
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

// -------------------------------------------------------------------- storage (Fs tab)

/// Growth windows cycled with `w` in the Fs tab.
pub const FS_WINDOWS: [i64; 3] = [10 * 60_000, 3_600_000, 24 * 3_600_000];
/// Listing refresh while the tree is still being scanned / once it is complete.
const FS_LIST_REFRESH_MS: i64 = 1000;
const FS_LIST_IDLE_REFRESH_MS: i64 = 5000;
const FS_GROWTH_REFRESH_MS: i64 = 5000;
/// In-memory volume history for time travel without the recorder.
const FS_VOL_RING: usize = 600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsSort {
    Size,
    Growth,
    Io,
    Name,
    Files,
    Age,
}

impl FsSort {
    pub const ALL: [FsSort; 6] = [FsSort::Size, FsSort::Growth, FsSort::Io, FsSort::Name, FsSort::Files, FsSort::Age];
    pub fn label(self) -> &'static str {
        match self {
            FsSort::Size => "size",
            FsSort::Growth => "growth",
            FsSort::Io => "io",
            FsSort::Name => "name",
            FsSort::Files => "files",
            FsSort::Age => "age",
        }
    }
    pub fn next(self) -> FsSort {
        let i = FsSort::ALL.iter().position(|s| *s == self).unwrap_or(0);
        FsSort::ALL[(i + 1) % FsSort::ALL.len()]
    }
}

/// What the Fs tab's main table shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsMode {
    /// Children of the current directory.
    Tree,
    /// Fastest growers anywhere, deleted-but-open files, top writers.
    Growth,
    /// Largest entries below the current directory.
    Largest,
}

/// One row of the growth view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrowthRow {
    Grower(usize),
    Deleted(usize),
    Writer(usize),
}

/// What the growth report says about one directory (from growers at or below it).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChildGrowth {
    pub delta: i64,
    /// Sum of the write rates of distinct processes seen writing below it.
    pub write_bps: u64,
    pub evidence: Vec<Evidence>,
    /// The fastest of those writers: (pid, name, bytes/sec).
    pub top_writer: Option<(u32, String, u64)>,
}

/// `p` is `dir` or below it (component-wise: "/a/bc" is not below "/a/b").
pub fn path_within(p: &str, dir: &str) -> bool {
    let dir = if dir.len() > 1 { dir.trim_end_matches('/') } else { dir };
    if dir == "/" {
        return p.starts_with('/');
    }
    p == dir || (p.starts_with(dir) && p.as_bytes().get(dir.len()) == Some(&b'/'))
}

/// "/a/b" -> "/a", "/a" -> "/", "/" -> None.
pub fn parent_dir(p: &str) -> Option<String> {
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return None;
    }
    match t.rfind('/') {
        Some(0) => Some("/".into()),
        Some(i) => Some(t[..i].to_string()),
        None => None,
    }
}

/// Δ, writers and evidence for `path` from the growers at or below it. Growers are disjoint
/// ("other under X" rows carry only X's remainder), so they add up; a full row nested under
/// another full row (older reports) is skipped so it is not counted twice.
pub fn child_growth(path: &str, growers: &[Grower]) -> ChildGrowth {
    let mut under: Vec<&Grower> = growers.iter().filter(|g| path_within(&g.path, path)).collect();
    under.sort_by(|a, b| {
        a.path.len().cmp(&b.path.len()).then_with(|| a.path.cmp(&b.path)).then_with(|| b.other.cmp(&a.other))
    });
    under.dedup_by(|a, b| a.path == b.path && a.other == b.other);
    let mut out = ChildGrowth::default();
    let mut kept: Vec<&Grower> = Vec::new();
    for g in under {
        if kept.iter().any(|k| !k.other && path_within(&g.path, &k.path)) {
            continue;
        }
        kept.push(g);
    }
    let mut writers: HashMap<u32, (String, u64)> = HashMap::new();
    for g in &kept {
        out.delta = out.delta.saturating_add(g.delta);
        for e in &g.evidence {
            if !out.evidence.contains(e) {
                out.evidence.push(*e);
            }
        }
    }
    // Writers are attributed per grower; nested growers' writers count too (same process once).
    for g in growers.iter().filter(|g| path_within(&g.path, path)) {
        for (pid, name, bps) in &g.writers {
            let w = writers.entry(*pid).or_insert_with(|| (name.clone(), 0));
            w.1 = w.1.max(*bps);
        }
    }
    out.write_bps = writers.values().map(|w| w.1).sum();
    out.top_writer =
        writers.into_iter().max_by_key(|(pid, w)| (w.1, std::cmp::Reverse(*pid))).map(|(pid, (n, b))| (pid, n, b));
    out
}

/// Deleted-but-open holders shown in the growth view: at most this many.
pub const DELETED_ROWS: usize = 8;

/// Row order for the growth view: growers, then deleted-but-open files grouped by the process
/// holding them (`Deleted(i)` indexes the returned groups; files under 1 MB are only counted),
/// then top writers.
pub fn growth_rows(g: &Growth, filter_lower: &str) -> (Vec<GrowthRow>, Vec<DeletedGroup>) {
    let mut v: Vec<GrowthRow> = Vec::new();
    // Paths merely touched (no net change, no writer) are noise here.
    v.extend(
        g.growers
            .iter()
            .enumerate()
            .filter(|(_, x)| x.delta != 0 || !x.writers.is_empty())
            .filter(|(_, x)| {
                contains_ci(&x.path, filter_lower) || x.writers.iter().any(|w| contains_ci(&w.1, filter_lower))
            })
            .map(|(i, _)| GrowthRow::Grower(i)),
    );
    // Only files worth restarting a process for (browsers alone hold hundreds of small temp
    // files), one row per holder, biggest first.
    let matching: Vec<(u32, String, String, u64)> = g
        .deleted_open
        .iter()
        .filter(|x| contains_ci(&x.1, filter_lower) || contains_ci(&x.2, filter_lower))
        .cloned()
        .collect();
    let (groups, _, _) = group_deleted(&matching, DELETED_MIN_BYTES);
    v.extend((0..groups.len().min(DELETED_ROWS)).map(GrowthRow::Deleted));
    v.extend(
        g.writers
            .iter()
            .enumerate()
            .filter(|(_, x)| contains_ci(&x.1, filter_lower))
            .map(|(i, _)| GrowthRow::Writer(i)),
    );
    (v, groups)
}

/// Sorted, filtered order of a listing's children. Each sort has its natural direction:
/// biggest / fastest / newest first, names ascending.
pub fn fs_order(children: &[DirEntry], growth: &[ChildGrowth], sort: FsSort, filter_lower: &str) -> Vec<usize> {
    let mut v: Vec<usize> = (0..children.len()).filter(|&i| contains_ci(&children[i].name, filter_lower)).collect();
    let delta = |i: usize| growth.get(i).map_or(0, |c| c.delta);
    let io = |i: usize| growth.get(i).map_or(0, |c| c.write_bps);
    v.sort_by(|&a, &b| {
        let (x, y) = (&children[a], &children[b]);
        let o = match sort {
            FsSort::Size => y.size.cmp(&x.size),
            FsSort::Growth => delta(b).cmp(&delta(a)),
            FsSort::Io => io(b).cmp(&io(a)),
            FsSort::Name => x.name.to_lowercase().cmp(&y.name.to_lowercase()),
            FsSort::Files => y.files.cmp(&x.files),
            FsSort::Age => y.newest_mtime.cmp(&x.newest_mtime),
        };
        o.then_with(|| y.size.cmp(&x.size)).then_with(|| x.name.cmp(&y.name))
    });
    v
}

/// What the recorder knew about a directory at a past moment.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FsPast {
    /// Requested time and directory.
    pub ts: Ts,
    pub path: String,
    /// Time of the recorded directory snapshot used (None = nothing recorded that early).
    pub at: Option<Ts>,
    /// Recorded size of `path` itself.
    pub dir_size: Option<u64>,
    pub children: Vec<DirEntry>,
    /// (mount, used) recorded near `ts`.
    pub vols: Vec<(String, u64)>,
}

/// Build an [`FsPast`] from recorded (path, size) rows at and below `path`.
pub fn fs_past_from(ts: Ts, path: &str, at: Option<Ts>, rows: &[(String, u64)], vols: Vec<(String, u64)>) -> FsPast {
    let dir = if path.len() > 1 { path.trim_end_matches('/') } else { path };
    let mut children: Vec<DirEntry> = rows
        .iter()
        .filter(|(p, _)| parent_dir(p).as_deref() == Some(dir))
        .map(|(p, size)| DirEntry {
            path: p.clone(),
            name: p.rsplit('/').next().unwrap_or_default().to_string(),
            // The recorder keeps sizes, not kinds; most recorded entries are directories.
            is_dir: true,
            size: *size,
            scanned_at: at.unwrap_or(0),
            ..Default::default()
        })
        .collect();
    children.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));
    let dir_size = rows.iter().find(|(p, _)| p == dir).map(|(_, s)| *s);
    FsPast { ts, path: dir.to_string(), at, dir_size, children, vols }
}

pub struct FsView {
    /// The tab was opened at least once: the storage engines run from then on.
    pub opened: bool,
    /// Directory shown in the tree view.
    pub path: String,
    /// The user explicitly opened this protected / mounted dir: reading below it is allowed.
    pub explicit_root: Option<String>,
    pub listing: Option<Listing>,
    /// When `listing` arrived (epoch ms).
    pub listing_at: Ts,
    pub volumes: Vec<Volume>,
    /// (ts, [(mount, used)]) for time travel within this session.
    pub vol_ring: VecDeque<(Ts, Vec<(String, u64)>)>,
    pub growth: Option<Growth>,
    pub growth_at: Ts,
    pub window: usize,
    pub sort: FsSort,
    pub mode: FsMode,
    /// Largest entries below `largest_path` (None = loading).
    pub largest: Option<Vec<DirEntry>>,
    pub largest_path: String,
    pub filter: String,
    filter_lower: String,
    /// Row order for the current mode (indices into children / largest; growth uses `grows`).
    pub rows: Vec<usize>,
    pub grows: Vec<GrowthRow>,
    /// Deleted-but-open files by holder, for `GrowthRow::Deleted`.
    pub deleted: Vec<DeletedGroup>,
    /// Per child of `listing`, aligned with `listing.children`.
    pub child_growth: Vec<ChildGrowth>,
    rows_dirty: bool,
    pub sel: usize,
    pub offset: usize,
    /// Name of the selected entry, kept across refreshes and re-sorts.
    sel_name: Option<String>,
    pub error: Option<String>,
    last_list_req: Ts,
    last_growth_req: Ts,
    /// Mirrors `App::cursor` (time travel).
    pub cursor: Option<Ts>,
    pub past: Option<FsPast>,
    last_past_req: Option<(Ts, String)>,
}

impl Default for FsView {
    fn default() -> Self {
        FsView {
            opened: false,
            path: "/".into(),
            explicit_root: None,
            listing: None,
            listing_at: 0,
            volumes: Vec::new(),
            vol_ring: VecDeque::new(),
            growth: None,
            growth_at: 0,
            window: 0,
            sort: FsSort::Size,
            mode: FsMode::Tree,
            largest: None,
            largest_path: String::new(),
            filter: String::new(),
            filter_lower: String::new(),
            rows: Vec::new(),
            grows: Vec::new(),
            deleted: Vec::new(),
            child_growth: Vec::new(),
            rows_dirty: true,
            sel: 0,
            offset: 0,
            sel_name: None,
            error: None,
            last_list_req: i64::MIN / 2,
            last_growth_req: i64::MIN / 2,
            cursor: None,
            past: None,
            last_past_req: None,
        }
    }
}

impl FsView {
    pub fn window_ms(&self) -> i64 {
        FS_WINDOWS[self.window % FS_WINDOWS.len()]
    }

    /// Current listing, only if it is for the directory being shown.
    pub fn current(&self) -> Option<&Listing> {
        self.listing.as_ref()
    }

    /// Recorded sizes for the moment being viewed, when rewound and the recorder has them.
    pub fn past_view(&self) -> Option<&FsPast> {
        let c = self.cursor?;
        self.past.as_ref().filter(|p| p.ts == c && p.path == self.path && p.at.is_some())
    }

    /// Children the tree view shows: recorded ones when rewound (if recorded), else the scan.
    pub fn tree_children(&self) -> &[DirEntry] {
        match self.past_view() {
            Some(p) => &p.children,
            None => self.listing.as_ref().map(|l| l.children.as_slice()).unwrap_or(&[]),
        }
    }

    pub fn ensure_rows(&mut self) {
        if !self.rows_dirty {
            return;
        }
        self.rows_dirty = false;
        let f = self.filter_lower.as_str();
        match self.mode {
            FsMode::Tree => {
                let (cg, rows) = {
                    let children: &[DirEntry] = self.tree_children();
                    // Rewound: live growth (now-window..now) does not belong next to past sizes.
                    let growers: &[Grower] = match self.past_view() {
                        Some(_) => &[],
                        None => self.growth.as_ref().map(|g| g.growers.as_slice()).unwrap_or(&[]),
                    };
                    let cg: Vec<ChildGrowth> = children.iter().map(|c| child_growth(&c.path, growers)).collect();
                    let rows = fs_order(children, &cg, self.sort, f);
                    (cg, rows)
                };
                self.child_growth = cg;
                self.rows = rows;
                self.grows.clear();
            }
            FsMode::Largest => {
                let l: &[DirEntry] = self.largest.as_deref().unwrap_or(&[]);
                self.rows = (0..l.len()).filter(|&i| contains_ci(&l[i].path, f)).collect();
                self.grows.clear();
            }
            FsMode::Growth => {
                (self.grows, self.deleted) = self.growth.as_ref().map(|g| growth_rows(g, f)).unwrap_or_default();
                self.rows.clear();
            }
        }
        let len = self.len();
        let found =
            self.sel_name.clone().and_then(|n| (0..len).find(|&i| self.row_key(i).as_deref() == Some(n.as_str())));
        self.sel = found.unwrap_or_else(|| self.sel.min(len.saturating_sub(1)));
    }

    pub fn len(&self) -> usize {
        if self.mode == FsMode::Growth { self.grows.len() } else { self.rows.len() }
    }

    /// Stable identity of row `i` for keeping the selection.
    fn row_key(&self, i: usize) -> Option<String> {
        match self.mode {
            FsMode::Tree => Some(self.tree_children().get(*self.rows.get(i)?)?.name.clone()),
            FsMode::Largest => Some(self.largest.as_ref()?.get(*self.rows.get(i)?)?.path.clone()),
            FsMode::Growth => {
                let g = self.growth.as_ref()?;
                Some(match self.grows.get(i)? {
                    GrowthRow::Grower(j) => format!("g:{}", g.growers.get(*j)?.path),
                    GrowthRow::Deleted(j) => format!("d:{}", self.deleted.get(*j)?.pid),
                    GrowthRow::Writer(j) => format!("w:{}", g.writers.get(*j)?.0),
                })
            }
        }
    }

    /// The selected child in tree mode.
    pub fn selected_entry(&self) -> Option<&DirEntry> {
        match self.mode {
            FsMode::Tree => self.tree_children().get(*self.rows.get(self.sel)?),
            FsMode::Largest => self.largest.as_ref()?.get(*self.rows.get(self.sel)?),
            FsMode::Growth => None,
        }
    }

    pub fn selected_growth(&self) -> Option<GrowthRow> {
        if self.mode == FsMode::Growth { self.grows.get(self.sel).copied() } else { None }
    }

    /// Growth numbers of the selected tree child.
    pub fn selected_child_growth(&self) -> Option<&ChildGrowth> {
        if self.mode != FsMode::Tree {
            return None;
        }
        self.child_growth.get(*self.rows.get(self.sel)?)
    }

    fn move_sel(&mut self, delta: isize) {
        self.ensure_rows();
        self.sel = step(self.sel, delta, self.len());
        self.sel_name = self.row_key(self.sel);
    }

    fn set_mode(&mut self, m: FsMode) {
        if self.mode != m {
            self.mode = m;
            self.sel = 0;
            self.offset = 0;
            self.sel_name = None;
            self.rows_dirty = true;
        }
    }

    fn explicit(&self) -> bool {
        self.explicit_root.as_deref().is_some_and(|r| path_within(&self.path, r))
    }

    fn list_cmd(&mut self, now: Ts) -> Command {
        self.last_list_req = now;
        Command::FsList { path: self.path.clone(), explicit: self.explicit() }
    }

    fn growth_under(&self) -> Option<String> {
        // The growth view is "anywhere"; the tree asks about the directory being shown.
        (self.mode == FsMode::Tree && self.path != "/").then(|| self.path.clone())
    }

    fn growth_cmd(&mut self, now: Ts) -> Command {
        self.last_growth_req = now;
        Command::FsGrowth { window_ms: self.window_ms(), under: self.growth_under() }
    }

    /// Go to `path`, selecting `select` (a child name) when it shows up.
    fn go(&mut self, path: String, select: Option<String>, explicit: bool, now: Ts) -> Vec<Command> {
        if explicit {
            self.explicit_root = Some(path.clone());
        } else if !self.explicit_root.as_deref().is_some_and(|r| path_within(&path, r)) {
            self.explicit_root = None;
        }
        let changed = path != self.path;
        self.path = path;
        self.set_mode(FsMode::Tree);
        if changed {
            self.listing = None;
            self.sel = 0;
            self.offset = 0;
        }
        self.sel_name = select;
        self.rows_dirty = true;
        vec![self.list_cmd(now), self.growth_cmd(now)]
    }

    /// Used bytes of `mount` nearest to `ts` from this session's samples (time travel).
    pub fn used_at(&self, mount: &str, ts: Ts) -> Option<(Ts, u64)> {
        let (at, vols) = self.vol_ring.iter().min_by_key(|(t, _)| (t - ts).abs())?;
        if (at - ts).abs() > 30_000 {
            return None;
        }
        vols.iter().find(|(m, _)| m == mount).map(|(_, u)| (*at, *u))
    }
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
    pub port_rows: Vec<PortRow>,
    pub port_view: PortView,
    pub port_filter: PortFilter,
    /// CLOSE_WAIT counts of the last few live samples (a steady rise is a leak).
    pub close_wait_hist: std::collections::VecDeque<u32>,
    pub port_sel: usize,
    pub port_offset: usize,
    pub fleet_sel: usize,
    pub doctor_sel: usize,
    pub log_sel: usize,
    pub fs: FsView,

    pub findings: Vec<Finding>,
    /// Start time of each pid the findings mention, from the snapshot they were computed on.
    pub findings_starts: HashMap<u32, u64>,
    pub findings_loaded: bool,
    pub log: Vec<ActionRecord>,
    pub containers: Vec<Container>,
    pub fleet_loaded: bool,

    // server profile
    pub profile: Profile,
    /// Thresholds for colours and "problem" flags (exhaustion, disk await).
    pub server_cfg: ServerCfg,
    pub svc: ServicesView,
    pub ev: EventsView,
    /// Events seen in live samples this session, oldest first (bounded by [`EVENT_RING`]).
    pub event_ring: VecDeque<Event>,
    pub fleet: FleetView,
    /// Explanation overlay (unit why, incident).
    pub panel: Option<Panel>,
    incident_seq: u64,
    /// OOM kills in the last 24h according to the recorder (None = unknown).
    pub oom_24h: Option<u64>,
    last_counts: Ts,

    pub why: Option<Explanation>,
    pub why_scroll: u16,
    pub ask: AskTab,
    pub settings: SettingsUi,
    /// The view to return to from a screen (Log, Settings) on Esc.
    pub back_tab: Tab,
    /// Action log filter by kind (None = all).
    pub log_kind: Option<ActionKind>,
    /// Action log text filter (`/`): name, pid, who, message.
    pub log_filter: String,
    /// Where the current question goes ("ollama · qwen3 · http://…", "no model set up (…)").
    pub ask_dest: String,
    /// A model is set up, so a question can be answered.
    pub ask_ready: bool,
    ask_seq: u64,
    pub modal: Modal,
    pub status: Option<Status>,

    pub now: Ts,
    pub config_path: String,
    pub history_ok: bool,
    /// "⬆ fat 0.2.0 · fat update" when a newer release is known.
    pub update_note: Option<String>,
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
            port_view: PortView::All,
            port_filter: PortFilter::default(),
            close_wait_hist: std::collections::VecDeque::new(),
            port_sel: 0,
            port_offset: 0,
            fleet_sel: 0,
            doctor_sel: 0,
            log_sel: 0,
            fs: FsView::default(),
            findings: Vec::new(),
            findings_starts: HashMap::new(),
            findings_loaded: false,
            log: Vec::new(),
            containers: Vec::new(),
            fleet_loaded: false,
            profile: Profile::Desktop,
            server_cfg: ServerCfg::default(),
            svc: ServicesView::default(),
            ev: EventsView::default(),
            event_ring: VecDeque::new(),
            fleet: FleetView::default(),
            panel: None,
            incident_seq: 0,
            oom_24h: None,
            last_counts: i64::MIN / 2,
            why: None,
            why_scroll: 0,
            ask: AskTab::default(),
            settings: SettingsUi::default(),
            back_tab: Tab::Procs,
            log_kind: None,
            log_filter: String::new(),
            ask_dest: String::new(),
            ask_ready: false,
            ask_seq: 0,
            modal: Modal::None,
            status: None,
            now: crate::model::now_ms(),
            config_path: String::new(),
            history_ok: false,
            update_note: None,
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
        self.close_wait_hist.push_back(snap.conns.count("CLOSE_WAIT"));
        while self.close_wait_hist.len() > 6 {
            self.close_wait_hist.pop_front();
        }
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
        if !snap.events.is_empty() {
            self.event_ring.extend(snap.events.iter().cloned());
            while self.event_ring.len() > EVENT_RING {
                self.event_ring.pop_front();
            }
            self.ev.dirty = true;
        }
        self.live = Some(snap);
        self.collector_error = None;
        if !self.rewound() {
            self.rows_dirty = true;
            self.svc.dirty = true;
        }
    }

    /// Choose the profile's views and thresholds (called once at startup).
    pub fn set_profile(&mut self, p: Profile, server: ServerCfg, fleet_refresh_s: u64) {
        self.profile = p;
        self.server_cfg = server;
        self.fleet.refresh_ms = (fleet_refresh_s.max(1) * 1000) as i64;
        if p == Profile::Server {
            self.tab = Tab::Services;
        }
    }

    pub fn server(&self) -> bool {
        self.profile == Profile::Server
    }

    /// Units of the viewed snapshot (empty in the desktop profile).
    pub fn units(&self) -> &[crate::server::Unit] {
        self.view().map(|s| s.units.as_slice()).unwrap_or(&[])
    }

    /// Rebuild the server views' row caches (cheap when nothing changed).
    pub fn ensure_server_rows(&mut self) {
        let warn = self.server_cfg.exhaustion_warn;
        let units: &[crate::server::Unit] =
            match if self.cursor.is_some() { self.past.as_ref() } else { self.live.as_ref() } {
                Some(s) => &s.units,
                None => &[],
            };
        self.svc.ensure_rows(units, warn);
        self.ev.ensure_rows(&self.event_ring, self.now);
        self.fleet.ensure_rows();
    }

    // ---------------------------------------------------------------- server data in

    /// Recorder events for the Events window (None = no recorder: the live ring is used).
    pub fn set_events(&mut self, from: Ts, events: Option<Vec<Event>>) {
        // A late answer for an older request (another window) is dropped.
        if from != self.ev.req_from {
            return;
        }
        self.ev.recorded = events;
        self.ev.dirty = true;
    }

    /// Incident answer for request `id`; ignored unless that panel is still waiting.
    pub fn set_incident(&mut self, id: u64, r: Result<Incident, String>) {
        let Some(p) = self.panel.as_ref() else { return };
        if p.pending != Some(id) {
            return;
        }
        match r {
            Ok(inc) => self.panel = Some(crate::tui::server::incident_panel(&inc)),
            Err(e) => {
                let title = p.title.clone();
                self.panel = Some(Panel {
                    title,
                    headline: format!("could not explain this: {e}"),
                    severity: Severity::Warn,
                    sections: vec![("Missing data".into(), vec!["the incident engine or the recorder is unavailable; the event list and unit view still work".into()])],
                    ..Default::default()
                });
            }
        }
    }

    pub fn set_counts(&mut self, oom_24h: Option<u64>) {
        self.oom_24h = oom_24h;
    }

    /// Inventory size (or why it could not be read).
    pub fn set_fleet_inventory(&mut self, r: Result<usize, String>) {
        match r {
            Ok(n) => {
                self.fleet.targets = Some(n);
                self.fleet.inventory_error = None;
                self.configured_hosts = n;
            }
            Err(e) => {
                self.fleet.targets = Some(0);
                self.fleet.inventory_error = Some(e);
            }
        }
    }

    pub fn fleet_host(&mut self, h: FleetHost) {
        self.fleet.upsert(h);
    }

    pub fn fleet_done(&mut self, s: FleetSummary) {
        self.fleet.done(s, self.now);
    }

    /// The poll could not run at all.
    pub fn fleet_failed(&mut self, e: String) {
        self.fleet.polling = false;
        self.fleet.last_done = self.now;
        self.set_status(format!("fleet poll failed: {e}"), true);
    }

    /// Drill-in answer; ignored if the user closed it or moved to another host.
    pub fn set_fleet_drill(&mut self, name: &str, r: Result<(Snapshot, Vec<Finding>), String>) {
        let Some(d) = self.fleet.drill.as_mut().filter(|d| d.name == name) else { return };
        match r {
            Ok((s, f)) => {
                d.snap = Some(Box::new(s));
                d.findings = f;
                d.error = None;
            }
            Err(e) => d.error = Some(e),
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

    pub fn set_fleet(&mut self, containers: Option<Vec<Container>>) {
        if let Some(c) = containers {
            if !self.filter.is_empty() && c != self.containers {
                self.rows_dirty = true; // the filter also matches container names
            }
            self.containers = c;
        }
        self.fleet_loaded = true;
        if self.tab == Tab::Fleet && !self.fleet_visible() {
            self.tab = Tab::Procs;
        }
    }

    /// The Fleet tab exists only when there is something beyond this machine: configured
    /// hosts, or local containers running.
    pub fn fleet_visible(&self) -> bool {
        self.configured_hosts > 0 || self.fleet.active() || !self.containers.is_empty()
    }

    /// The profile's tabs in number-key order (Fleet included even while hidden).
    pub fn tab_order(&self) -> &'static [Tab] {
        match self.profile {
            Profile::Desktop => &Tab::DESKTOP,
            Profile::Server => &Tab::SERVER,
        }
    }

    /// Number key of a tab in this profile (1-based; 0 = not in this profile).
    pub fn tab_number(&self, t: Tab) -> usize {
        self.tab_order().iter().position(|x| *x == t).map_or(0, |i| i + 1)
    }

    /// The tabs on screen, in order.
    pub fn tabs(&self) -> Vec<Tab> {
        let mut v: Vec<Tab> =
            self.tab_order().iter().copied().filter(|t| *t != Tab::Fleet || self.fleet_visible()).collect();
        v.extend(Tab::SCREENS);
        v
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

    /// The answer to ask `id` arrived. Shown only if that question is still pending (a
    /// cancelled one is still saved in its thread).
    pub fn answered(&mut self, id: u64, a: crate::threads::Asked) {
        if !a.threads.is_empty() {
            self.set_threads(Ok(a.threads));
        }
        if self.ask.pending.as_ref().is_none_or(|p| p.id != id) {
            return;
        }
        self.ask.pending = None;
        self.ask.scroll_up = 0;
        match a.thread {
            Some(t) => {
                self.ask.open = Some(t);
                self.ask.turns = a.turns;
                if let Some(i) = self.ask.threads.iter().position(|x| x.id == t) {
                    self.ask.sel = i;
                }
            }
            None => self.ask.turns.push(crate::threads::Turn {
                question: a.question,
                answer: a.answer,
                via: a.via,
                ts: self.now,
                ..Default::default()
            }),
        }
        if let Some(e) = a.error {
            self.set_status(e, true);
        }
    }

    pub fn set_threads(&mut self, threads: Result<Vec<crate::threads::Thread>, String>) {
        match threads {
            Ok(t) => {
                self.ask.threads = t;
                self.ask.error = None;
                // Keep the open thread selected.
                if let Some(i) = self.ask.open.and_then(|id| self.ask.threads.iter().position(|x| x.id == id)) {
                    self.ask.sel = i;
                }
                self.ask.sel = self.ask.sel.min(self.ask.threads.len().saturating_sub(1));
            }
            Err(e) => self.ask.error = Some(e),
        }
    }

    pub fn set_thread(&mut self, id: i64, turns: Vec<crate::threads::Turn>) {
        if self.ask.pending.is_none() {
            self.ask.open = Some(id);
            self.ask.turns = turns;
            self.ask.scroll_up = 0;
        }
    }

    /// Start a new thread with the input line focused (the `?` key, anywhere).
    pub fn ask_new(&mut self) -> Vec<Command> {
        let mut cmds = self.switch_tab(Tab::Ask);
        if self.ask.pending.is_none() {
            self.ask.open = None;
            self.ask.turns.clear();
            self.ask.scroll_up = 0;
        }
        self.ask.typing = true;
        cmds.retain(|c| !matches!(c, Command::OpenThread(_)));
        cmds
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
                && let Some(p) = live.procs.iter_mut().find(|p| p.pid == r.pid)
            {
                p.nice = n;
            }
        }
    }

    pub fn undo_done(&mut self, r: Option<&ActionRecord>) {
        match r {
            Some(r) if r.ok => {
                self.set_status(format!("↶ undid #{} on {} ({}) {}", r.id, r.pid, r.name, r.message), false)
            }
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
        let mut server = self.server_tick(now);
        if !server.is_empty() {
            server.extend(self.view_tick(now));
            return server;
        }
        self.view_tick(now)
    }

    /// Refreshes the server views need: recorder events while Events is on screen, header
    /// counters, and fleet polls while Fleet is on screen (never overlapping).
    fn server_tick(&mut self, now: Ts) -> Vec<Command> {
        let mut out = Vec::new();
        if self.server() && now - self.last_counts >= 30_000 {
            self.last_counts = now;
            out.push(Command::RefreshCounts);
        }
        if self.tab == Tab::Events && now - self.ev.last_req >= EVENTS_REFRESH_MS {
            out.push(self.events_refresh());
        }
        if self.tab == Tab::Events {
            // The window slides with the clock even without new events.
            self.ev.dirty = true;
        }
        if self.tab == Tab::Fleet && self.fleet.drill.is_none() {
            out.extend(self.fleet_poll_if_due(now, false));
        }
        out
    }

    fn fleet_poll_if_due(&mut self, now: Ts, force: bool) -> Option<Command> {
        let f = &mut self.fleet;
        if f.polling || f.targets.is_none_or(|n| n == 0) {
            return None;
        }
        if !force && now - f.last_done < f.refresh_ms {
            return None;
        }
        f.polling = true;
        f.poll_started = now;
        f.answered = 0;
        Some(Command::FleetPoll)
    }

    fn events_refresh(&mut self) -> Command {
        self.ev.last_req = self.now;
        self.ev.req_from = self.now - self.ev.window_ms();
        Command::LoadEvents { from: self.ev.req_from, to: self.now }
    }

    fn view_tick(&mut self, now: Ts) -> Vec<Command> {
        if self.tab == Tab::Timeline && now - self.last_timeline_refresh >= TIMELINE_REFRESH_MS {
            return vec![self.timeline_refresh()];
        }
        if self.tab == Tab::Fs && self.fs.opened && self.fs.error.is_none() {
            let mut out = Vec::new();
            // A summarized (folded) directory is being re-expanded after focus: poll fast too.
            let scanning = self
                .fs
                .listing
                .as_ref()
                .is_none_or(|l| l.dir.partial || l.progress.running || (l.children.is_empty() && l.dir.files > 1));
            let every = if scanning { FS_LIST_REFRESH_MS } else { FS_LIST_IDLE_REFRESH_MS };
            if now - self.fs.last_list_req >= every {
                out.push(self.fs.list_cmd(now));
            }
            if now - self.fs.last_growth_req >= FS_GROWTH_REFRESH_MS {
                out.push(self.fs.growth_cmd(now));
            }
            if let Some(c) = self.cursor {
                let want = (c, self.fs.path.clone());
                if self.history_ok && self.fs.last_past_req.as_ref() != Some(&want) {
                    self.fs.last_past_req = Some(want);
                    out.push(Command::FsAt { ts: c, path: self.fs.path.clone() });
                }
            }
            return out;
        }
        Vec::new()
    }

    // ---------------------------------------------------------------- storage data in

    /// Volumes from the sampler (every sample, whether or not the Fs tab was opened).
    pub fn set_volumes(&mut self, ts: Ts, vols: Vec<Volume>) {
        self.fs.vol_ring.push_back((ts, vols.iter().map(|v| (v.mount.clone(), v.used)).collect()));
        while self.fs.vol_ring.len() > FS_VOL_RING || self.fs.vol_ring.front().is_some_and(|(t, _)| ts - *t > RING_MS) {
            self.fs.vol_ring.pop_front();
        }
        self.fs.volumes = vols;
    }

    /// Listing for `path`; ignored if the user has moved elsewhere since asking.
    /// None = nothing known yet (the scan has not reached it).
    pub fn set_fs_listing(&mut self, path: &str, l: Option<Listing>) {
        if path != self.fs.path {
            return;
        }
        if let Some(l) = l {
            self.fs.listing = Some(l);
            self.fs.listing_at = self.now;
            if self.fs.mode == FsMode::Tree {
                self.fs.rows_dirty = true;
            }
        }
    }

    pub fn set_fs_growth(&mut self, g: Growth) {
        self.fs.growth = Some(g);
        self.fs.growth_at = self.now;
        self.fs.rows_dirty = true;
    }

    /// Recorded storage state for a past moment; ignored unless it is still what is viewed.
    pub fn set_fs_past(&mut self, p: FsPast) {
        if self.cursor == Some(p.ts) && p.path == self.fs.path {
            self.fs.past = Some(p);
            self.fs.rows_dirty = true;
        }
    }

    pub fn set_fs_largest(&mut self, path: &str, v: Vec<DirEntry>) {
        if path == self.fs.largest_path {
            self.fs.largest = Some(v);
            self.fs.rows_dirty = true;
        }
    }

    /// The storage engine is unavailable: stop polling it and say why.
    pub fn set_fs_error(&mut self, e: String) {
        self.set_status(format!("storage: {e}"), true);
        self.fs.error = Some(e);
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
                    port_rows_of(s, self.port_view, &self.port_filter),
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

    /// The selected listener, when the selected row is one.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn selected_port(&self) -> Option<&crate::model::Port> {
        let s = self.view()?;
        match self.port_rows.get(self.port_sel)? {
            PortRow::Listen(i) => s.ports.get(*i),
            PortRow::Group(_) => None,
        }
    }

    /// The process behind the selected Ports row (pid 0: none, e.g. TIME_WAIT).
    pub fn selected_port_owner(&self) -> Option<(u32, String)> {
        let s = self.view()?;
        match self.port_rows.get(self.port_sel)? {
            PortRow::Listen(i) => s.ports.get(*i).map(|p| (p.pid, p.process.clone())),
            PortRow::Group(i) => s.conns.groups.get(*i).map(|g| (g.pid, g.process.clone())),
        }
    }

    /// Whether CLOSE_WAIT rose in each of the last three samples (connections the
    /// application never closes).
    pub fn close_wait_rising(&self) -> bool {
        let h: Vec<u32> = self.close_wait_hist.iter().copied().collect();
        h.len() >= 4 && h.windows(2).rev().take(3).all(|w| w[1] > w[0])
    }

    /// Rows of the local Fleet view (this machine and its containers).
    pub fn fleet_len(&self) -> usize {
        1 + self.containers.len()
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
        self.fs.cursor = Some(ts);
        self.fs.rows_dirty = true;
        self.rows_dirty = true;
        let tol = (self.interval_ms as i64 * 3).max(5000);
        let hit = self.ring.iter().min_by_key(|s| (s.ts - ts).abs()).filter(|s| (s.ts - ts).abs() <= tol).cloned();
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
        self.fs.cursor = None;
        self.fs.past = None;
        self.fs.last_past_req = None;
        self.fs.rows_dirty = true;
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
        if self.tab == Tab::Settings && self.settings.capturing() {
            return self.on_settings_key(k);
        }
        if self.tab == Tab::Ask && (self.ask.typing || (k.code == KeyCode::Esc && self.ask.pending.is_some())) {
            return if self.ask.typing { self.on_ask_input(k) } else { self.on_ask_tab_key(k) };
        }
        if self.panel.is_some() && self.why.is_none() {
            return self.on_panel_key(k);
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
            Modal::PortFilter(form) => self.on_port_filter_key(form, k),

            Modal::Filter => {
                match k.code {
                    KeyCode::Esc => self.set_active_filter(String::new()),
                    KeyCode::Enter => {}
                    KeyCode::Backspace => {
                        let mut f = self.active_filter().to_string();
                        f.pop();
                        self.set_active_filter(f);
                        self.modal = Modal::Filter;
                    }
                    KeyCode::Char(c) => {
                        let mut f = self.active_filter().to_string();
                        f.push(c);
                        self.set_active_filter(f);
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
        }
    }

    fn on_settings_key(&mut self, k: KeyEvent) -> Vec<Command> {
        use crate::settings::{Kind, Source};
        let ui = &mut self.settings;
        let rows = ui.rows();
        let n = rows.len();
        // Typing a value.
        if let Some(mut input) = ui.editing.take() {
            match k.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    if let Some(f) = ui.field() {
                        return vec![Command::SetSetting {
                            section: f.section.clone(),
                            key: f.key.clone(),
                            value: Some(input),
                        }];
                    }
                }
                KeyCode::Backspace => {
                    input.pop();
                    ui.editing = Some(input);
                }
                KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => ui.editing = Some(String::new()),
                KeyCode::Char(c) => {
                    input.push(c);
                    ui.editing = Some(input);
                }
                _ => ui.editing = Some(input),
            }
            return Vec::new();
        }
        // Choosing a model.
        if let Some((models, mut i)) = ui.picker.take() {
            match k.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    if let Some(m) = models.get(i) {
                        return vec![Command::SetSetting {
                            section: "ask".into(),
                            key: "model".into(),
                            value: Some(m.clone()),
                        }];
                    }
                }
                code => {
                    list_nav(&mut i, models.len(), code);
                    ui.picker = Some((models, i));
                }
            }
            return Vec::new();
        }
        // A checklist (agents' allowed actions).
        if let Some((mut items, mut i)) = ui.multi.take() {
            match k.code {
                KeyCode::Esc => {}
                KeyCode::Char(' ') | KeyCode::Char('x') => {
                    if let Some(it) = items.get_mut(i) {
                        it.1 = !it.1;
                    }
                    ui.multi = Some((items, i));
                }
                KeyCode::Enter => {
                    let Some(f) = ui.field().cloned() else { return Vec::new() };
                    let chosen: Vec<String> = items.iter().filter(|x| x.1).map(|x| x.0.clone()).collect();
                    let before: Vec<&str> = f.value.split(',').map(str::trim).filter(|x| !x.is_empty()).collect();
                    let added: Vec<&String> = chosen.iter().filter(|c| !before.contains(&c.as_str())).collect();
                    let cmd = Command::SetSetting {
                        section: f.section.clone(),
                        key: f.key.clone(),
                        value: Some(chosen.join(", ")),
                    };
                    if f.sensitive() && !added.is_empty() {
                        let what = added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                        let kill = if added.iter().any(|a| *a == "kill") { " Kill cannot be undone." } else { "" };
                        self.modal = Modal::Confirm {
                            prompt: format!(
                                "Let agents (MCP) {what} processes on this machine?{kill} They still have to ask through fat's tools, and every action is journaled."
                            ),
                            cmd,
                        };
                        return Vec::new();
                    }
                    return vec![cmd];
                }
                code => {
                    list_nav(&mut i, items.len(), code);
                    ui.multi = Some((items, i));
                }
            }
            return Vec::new();
        }
        // The host form.
        if let Some(mut form) = ui.host_form.take() {
            if form.editing {
                match k.code {
                    KeyCode::Esc | KeyCode::Enter => form.editing = false,
                    KeyCode::Backspace => {
                        form.values[form.sel].pop();
                    }
                    KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => form.values[form.sel].clear(),
                    KeyCode::Char(c) => form.values[form.sel].push(c),
                    KeyCode::Tab | KeyCode::Down => form.sel = (form.sel + 1) % 5,
                    KeyCode::BackTab | KeyCode::Up => form.sel = (form.sel + 4) % 5,
                    _ => {}
                }
                ui.host_form = Some(form);
                return Vec::new();
            }
            match k.code {
                KeyCode::Esc => return Vec::new(),
                KeyCode::Up | KeyCode::Char('k') => form.sel = form.sel.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => form.sel = (form.sel + 1).min(4),
                KeyCode::Enter | KeyCode::Char('e') => form.editing = true,
                KeyCode::Char('s') => {
                    let host = form.host();
                    let index = form.index;
                    if let Err(e) = crate::settings::check_host(&host) {
                        ui.note = Some((e, true));
                        ui.host_form = Some(form);
                        return Vec::new();
                    }
                    return vec![Command::SaveHost { index, host }];
                }
                KeyCode::Char('t') if ui.busy.is_none() => {
                    let host = form.host();
                    ui.busy = Some(format!("ssh {}…", host.ssh.as_deref().unwrap_or(&host.name)));
                    ui.note = None;
                    ui.host_form = Some(form);
                    return vec![Command::TestHost(host)];
                }
                _ => {}
            }
            ui.host_form = Some(form);
            return Vec::new();
        }
        let group_start = |ui: &SettingsUi, g: &str| rows.iter().position(|r| ui.group_of(*r) == g);
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => ui.sel = ui.sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => ui.sel = (ui.sel + 1).min(n.saturating_sub(1)),
            KeyCode::PageUp => ui.sel = ui.sel.saturating_sub(10),
            KeyCode::PageDown => ui.sel = (ui.sel + 10).min(n.saturating_sub(1)),
            KeyCode::Home | KeyCode::Char('g') => ui.sel = 0,
            KeyCode::End | KeyCode::Char('G') => ui.sel = n.saturating_sub(1),
            KeyCode::Left | KeyCode::Right => {
                let groups = crate::settings::GROUPS;
                let cur = rows.get(ui.sel).map(|r| ui.group_of(*r)).unwrap_or(groups[0]);
                let gi = groups.iter().position(|g| *g == cur).unwrap_or(0);
                let next = if k.code == KeyCode::Right {
                    (gi + 1) % groups.len()
                } else {
                    (gi + groups.len() - 1) % groups.len()
                };
                if let Some(i) = group_start(ui, groups[next]) {
                    ui.sel = i;
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => match rows.get(ui.sel).copied() {
                Some(SRow::Host(i)) => {
                    if let Some(h) = ui.hosts.get(i) {
                        ui.host_form = Some(HostForm::from(Some(i), h));
                    }
                }
                Some(SRow::AddHost) => ui.host_form = Some(HostForm::from(None, &Default::default())),
                Some(SRow::AskOption(i)) => {
                    if let Some(o) = ui.ask_options.get(i).cloned() {
                        return vec![Command::ApplyAskOption(o)];
                    }
                }
                Some(SRow::AskAdvanced) => ui.ask_advanced = !ui.ask_advanced,
                Some(SRow::Field(i)) => {
                    let Some(f) = ui.fields.get(i).cloned() else { return Vec::new() };
                    match (&f.kind, &f.source) {
                        (_, Source::Env(var)) => {
                            ui.note =
                                Some((format!("{} is set by {var}; unset it to change this here", f.label), true));
                        }
                        (Kind::Bool, _) => {
                            let v = if f.value == "true" { "false" } else { "true" };
                            return vec![Command::SetSetting { section: f.section, key: f.key, value: Some(v.into()) }];
                        }
                        (Kind::Choice(opts), _) => {
                            let i = opts.iter().position(|o| *o == f.value).map_or(0, |i| (i + 1) % opts.len());
                            return vec![Command::SetSetting {
                                section: f.section,
                                key: f.key,
                                value: Some(opts[i].to_string()),
                            }];
                        }
                        (Kind::Multi(opts), _) => {
                            let on: Vec<&str> = f.value.split(',').map(str::trim).collect();
                            ui.multi = Some((opts.iter().map(|o| (o.to_string(), on.contains(o))).collect(), 0));
                        }
                        _ => ui.editing = Some(f.value.clone()),
                    }
                }
                None => {}
            },
            KeyCode::Char('d') | KeyCode::Delete => {
                if let Some(SRow::Host(i)) = rows.get(ui.sel).copied()
                    && let Some(h) = ui.hosts.get(i)
                {
                    self.modal = Modal::Confirm {
                        prompt: format!("Remove host {} from the config?", h.name),
                        cmd: Command::DeleteHost(i),
                    };
                }
            }
            KeyCode::Char('r') => {
                if let Some(f) = ui.field() {
                    if f.editable() && f.source == Source::File {
                        let f = f.clone();
                        return vec![Command::SetSetting { section: f.section, key: f.key, value: None }];
                    } else if f.editable() {
                        ui.note = Some((format!("{} already uses its default", f.label), false));
                    }
                }
            }
            KeyCode::Char('t') if ui.busy.is_none() => match rows.get(ui.sel).copied() {
                Some(SRow::Host(i)) => {
                    if let Some(h) = ui.hosts.get(i).cloned() {
                        ui.busy = Some(format!("ssh {}…", h.ssh.as_deref().unwrap_or(&h.name)));
                        ui.note = None;
                        return vec![Command::TestHost(h)];
                    }
                }
                _ => {
                    ui.busy = Some("testing the model…".into());
                    ui.note = None;
                    return vec![Command::SettingsTest];
                }
            },
            KeyCode::Char('m') if ui.busy.is_none() => {
                ui.busy = Some("asking the server for its models…".into());
                ui.note = None;
                return vec![Command::SettingsModels];
            }
            _ => {}
        }
        Vec::new()
    }

    /// The Settings screen's state.
    pub fn settings_ui(&mut self) -> Option<&mut SettingsUi> {
        Some(&mut self.settings)
    }

    /// Rows of the action log under the current filters (indices into `log`).
    pub fn log_rows(&self) -> Vec<usize> {
        let q = self.log_filter.to_lowercase();
        self.log
            .iter()
            .enumerate()
            .filter(|(_, r)| self.log_kind.is_none_or(|k| r.kind == k))
            .filter(|(_, r)| {
                q.is_empty()
                    || r.name.to_lowercase().contains(&q)
                    || r.pid.to_string() == q
                    || r.origin.to_lowercase().contains(&q)
                    || r.message.to_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Keys while typing a question.
    fn on_ask_input(&mut self, k: KeyEvent) -> Vec<Command> {
        match k.code {
            KeyCode::Esc => self.ask.typing = false,
            KeyCode::Enter => {
                let q = self.ask.input.trim().to_string();
                if q.is_empty() || self.ask.pending.is_some() {
                    return Vec::new();
                }
                self.ask.input.clear();
                self.ask.typing = false;
                self.ask_seq += 1;
                let id = self.ask_seq;
                let thread = self.ask.open;
                self.ask.pending = Some(Pending { id, question: q.clone(), since: self.now, thread });
                self.ask.scroll_up = 0;
                return vec![Command::Ask { id, question: q, thread }];
            }
            KeyCode::Backspace => {
                self.ask.input.pop();
            }
            KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => self.ask.input.clear(),
            KeyCode::Char(c) => self.ask.input.push(c),
            KeyCode::PageUp => self.ask.scroll_up = self.ask.scroll_up.saturating_add(10),
            KeyCode::PageDown => self.ask.scroll_up = self.ask.scroll_up.saturating_sub(10),
            _ => {}
        }
        Vec::new()
    }

    /// Ask tab keys when not typing.
    fn on_ask_tab_key(&mut self, k: KeyEvent) -> Vec<Command> {
        let n = self.ask.threads.len();
        match k.code {
            KeyCode::Up | KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('k') => {
                let before = self.ask.sel;
                let code = match k.code {
                    KeyCode::Char('j') => KeyCode::Down,
                    KeyCode::Char('k') => KeyCode::Up,
                    c => c,
                };
                list_nav(&mut self.ask.sel, n, code);
                if (self.ask.sel != before || self.ask.open.is_none())
                    && self.ask.pending.is_none()
                    && let Some(t) = self.ask.threads.get(self.ask.sel)
                {
                    return vec![Command::OpenThread(t.id)];
                }
            }
            KeyCode::Enter | KeyCode::Char('i') => self.ask.typing = true,
            KeyCode::Char('n') => return self.ask_new(),
            KeyCode::Char('d') => {
                if let Some(t) = self.ask.threads.get(self.ask.sel) {
                    self.modal = Modal::Confirm {
                        prompt: format!("Delete the thread \"{}\" ({} turns)?", t.title, t.turns),
                        cmd: Command::DeleteThread(t.id),
                    };
                }
            }
            KeyCode::PageUp => self.ask.scroll_up = self.ask.scroll_up.saturating_add(10),
            KeyCode::PageDown | KeyCode::Char(' ') => self.ask.scroll_up = self.ask.scroll_up.saturating_sub(10),
            KeyCode::Home => self.ask.scroll_up = u16::MAX,
            KeyCode::End => self.ask.scroll_up = 0,
            KeyCode::Esc if self.ask.pending.is_some() => {
                self.ask.pending = None;
                self.set_status("stopped waiting; the answer will still be saved to its thread", false);
            }
            _ => {}
        }
        Vec::new()
    }

    pub fn set_filter(&mut self, f: String) {
        self.filter_lower = f.to_lowercase();
        self.filter = f;
        self.rows_dirty = true;
    }

    pub fn set_fs_filter(&mut self, f: String) {
        self.fs.filter_lower = f.to_lowercase();
        self.fs.filter = f;
        self.fs.rows_dirty = true;
    }

    /// The filter the `/` prompt edits: Fs, Services, Events and Fleet each have their own
    /// (paths, units, events, hosts); the rest filter processes.
    pub fn active_filter(&self) -> &str {
        match self.tab {
            Tab::Fs => &self.fs.filter,
            Tab::Services => &self.svc.filter,
            Tab::Events => &self.ev.filter,
            Tab::Fleet if self.fleet.active() => &self.fleet.filter,
            Tab::Log => &self.log_filter,
            _ => &self.filter,
        }
    }

    fn set_active_filter(&mut self, f: String) {
        match self.tab {
            Tab::Fs => self.set_fs_filter(f),
            Tab::Services => self.svc.set_filter(f),
            Tab::Events => self.ev.set_filter(f),
            Tab::Fleet if self.fleet.active() => self.fleet.set_filter(f),
            Tab::Log => {
                self.log_filter = f;
                self.log_sel = 0;
            }
            _ => self.set_filter(f),
        }
    }

    pub fn switch_tab(&mut self, t: Tab) -> Vec<Command> {
        if self.tab != t {
            self.why = None;
        }
        if t == Tab::Ports {
            crate::peers::activate();
        }
        if Tab::SCREENS.contains(&t) {
            if !Tab::SCREENS.contains(&self.tab) {
                self.back_tab = self.tab;
            }
            self.tab = t;
            return vec![if t == Tab::Log { Command::RefreshLog } else { Command::LoadSettings }];
        }
        if t == Tab::Fleet && !self.fleet_visible() {
            self.set_status(
                "no Fleet yet: start a container or add hosts ([[hosts]] or [fleet] hosts_file) to the config",
                false,
            );
            return Vec::new();
        }
        if !self.tab_order().contains(&t) {
            self.set_status(
                format!(
                    "{} is part of the server profile (FAT_PROFILE=server or profile = \"server\" in [server])",
                    t.title()
                ),
                false,
            );
            return Vec::new();
        }
        self.tab = t;
        match t {
            Tab::Timeline => vec![self.timeline_refresh()],
            Tab::Events => {
                self.ev.dirty = true;
                vec![self.events_refresh()]
            }
            Tab::Fleet => self.fleet_poll_if_due(self.now, false).into_iter().collect(),
            Tab::Ask => {
                let mut v = vec![Command::Threads];
                if self.ask.open.is_none()
                    && self.ask.pending.is_none()
                    && self.ask.turns.is_empty()
                    && let Some(t) = self.ask.threads.get(self.ask.sel)
                {
                    v.push(Command::OpenThread(t.id));
                }
                v
            }
            Tab::Fs => {
                // Opening the tab is what starts the storage engines (never before).
                self.fs.opened = true;
                if self.fs.error.is_some() {
                    return Vec::new();
                }
                let now = self.now;
                vec![self.fs.list_cmd(now), self.fs.growth_cmd(now)]
            }
            _ => Vec::new(),
        }
    }

    fn on_global_key(&mut self, k: KeyEvent) -> Vec<Command> {
        // The fleet drill-in uses `u` for its Units view (global `u` is undo).
        if self.tab == Tab::Fleet && self.fleet.drill.is_some() && k.code == KeyCode::Char('u') {
            return self.on_drill_key(k);
        }
        match k.code {
            KeyCode::Char('q') => {
                self.quit = true;
                return vec![Command::Quit];
            }
            KeyCode::Char(c @ '1'..='9') => {
                return match self.tab_order().get((c as u8 - b'1') as usize) {
                    Some(&t) => self.switch_tab(t),
                    None => Vec::new(),
                };
            }
            KeyCode::Tab | KeyCode::BackTab => {
                let tabs = self.tabs();
                let n = tabs.len();
                let cur = tabs.iter().position(|t| *t == self.tab).unwrap_or(0);
                let next = if k.code == KeyCode::Tab { (cur + 1) % n } else { (cur + n - 1) % n };
                return self.switch_tab(tabs[next]);
            }
            KeyCode::Char('a') => return self.switch_tab(Tab::Log),
            KeyCode::Char('h') | KeyCode::F(1) => {
                self.modal = Modal::Help;
                return Vec::new();
            }
            KeyCode::Char('?') => return self.ask_new(),
            KeyCode::Char(',') => return self.switch_tab(Tab::Settings),
            KeyCode::Char('L') => {
                self.go_live();
                return Vec::new();
            }
            KeyCode::Char('u') => return vec![Command::Undo],
            KeyCode::Esc if Tab::SCREENS.contains(&self.tab) => {
                if self.tab == Tab::Log && (!self.log_filter.is_empty() || self.log_kind.is_some()) {
                    self.log_filter.clear();
                    self.log_kind = None;
                    self.log_sel = 0;
                    return Vec::new();
                }
                let back = self.back_tab;
                return self.switch_tab(back);
            }
            KeyCode::Esc
                if self.tab == Tab::Ports && (self.port_view != PortView::All || !self.port_filter.is_empty()) =>
            {
                self.port_filter = PortFilter::default();
                self.set_port_view(PortView::All);
                return Vec::new();
            }
            KeyCode::Esc => {
                if let Some(done) = self.server_esc() {
                    return done;
                }
                if self.tab == Tab::Fs {
                    if !self.fs.filter.is_empty() {
                        self.set_fs_filter(String::new());
                        return Vec::new();
                    }
                    if self.fs.mode != FsMode::Tree {
                        self.fs.set_mode(FsMode::Tree);
                        return Vec::new();
                    }
                    if self.rewound() {
                        self.go_live();
                    }
                    return Vec::new();
                }
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
            Tab::Fs => self.on_fs_key(k),
            Tab::Fleet if self.fleet.active() => self.on_fleet_key(k),
            Tab::Fleet => {
                let n = self.fleet_len();
                list_nav(&mut self.fleet_sel, n, k.code);
                Vec::new()
            }
            Tab::Doctor => self.on_doctor_key(k),
            Tab::Ask => self.on_ask_tab_key(k),
            Tab::Log => self.on_log_key(k),
            Tab::Settings => self.on_settings_key(k),
            Tab::Services => self.on_services_key(k),
            Tab::Events => self.on_events_key(k),
        }
    }

    /// Keys while the action log is open. It stays open until Esc / q / a.
    fn on_log_key(&mut self, k: KeyEvent) -> Vec<Command> {
        let rows = self.log_rows();
        if list_nav(&mut self.log_sel, rows.len(), k.code) {
            return Vec::new();
        }
        match k.code {
            KeyCode::Char('f') => {
                use ActionKind::*;
                const CYCLE: [Option<ActionKind>; 7] =
                    [None, Some(Pause), Some(Resume), Some(Renice), Some(Term), Some(Kill), Some(KillTree)];
                let i = CYCLE.iter().position(|c| *c == self.log_kind).unwrap_or(0);
                self.log_kind = CYCLE[(i + 1) % CYCLE.len()];
                self.log_sel = 0;
                Vec::new()
            }
            KeyCode::Enter => match rows.get(self.log_sel).and_then(|i| self.log.get(*i)) {
                Some(r) if r.ok && r.undoable && !r.undone && r.id != 0 => vec![Command::UndoId(r.id)],
                Some(r) if r.undone => {
                    self.set_status(format!("#{} was already undone", r.id), false);
                    Vec::new()
                }
                Some(r) => {
                    let why = match r.kind {
                        ActionKind::Term | ActionKind::Kill | ActionKind::KillTree => {
                            "a signal to end a process cannot be taken back"
                        }
                        _ if !r.ok => "it did not succeed",
                        _ => "fat could not record how to reverse it",
                    };
                    self.set_status(format!("#{} is not undoable: {why}", r.id), false);
                    Vec::new()
                }
                None => Vec::new(),
            },
            _ => Vec::new(),
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
    fn process_action(
        &mut self,
        code: KeyCode,
        pid: u32,
        name: String,
        start: u64,
        paused: bool,
        k_is_tree: bool,
    ) -> Vec<Command> {
        if self.rewound() {
            self.set_status("⏪ viewing the past — press L to return to live before acting", true);
            return Vec::new();
        }
        // blame's hub gate: a VM host, runtime, container pid 1, browser/app main process or
        // session takes everything it hosts with it, so say so before acting.
        let hub = self.view().and_then(|s| crate::blame::hub_gate(s, pid)).map(|g| g.note);
        let hub_warn = hub.as_deref().map(|n| format!(" WARNING: {n}.")).unwrap_or_default();
        match code {
            KeyCode::Char(' ') | KeyCode::Char('z') if !paused && hub.is_some() => {
                self.modal = Modal::Confirm {
                    prompt: format!("Pause {pid} ({name})? It freezes everything it hosts.{hub_warn}"),
                    cmd: Command::Act { kind: ActionKind::Pause, pid, nice: None, start },
                };
                Vec::new()
            }
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
                    prompt: format!(
                        "Send TERM to {pid} ({name})? This cannot be undone (space pauses it instead, which can).{hub_warn}"
                    ),
                    cmd: Command::Act { kind: ActionKind::Term, pid, nice: None, start },
                };
                Vec::new()
            }
            KeyCode::Char('k') | KeyCode::Char('K') => {
                self.modal = Modal::Confirm {
                    prompt: format!(
                        "Terminate {pid} ({name}) AND all its descendants? This cannot be undone.{hub_warn}"
                    ),
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

    /// Keys in the Ports filter dialog. Changes apply as they are made.
    fn on_port_filter_key(&mut self, mut form: PortFilterForm, k: KeyEvent) -> Vec<Command> {
        use crate::model::Proto;
        fn text(f: &mut PortFilter, i: usize) -> Option<&mut String> {
            match i {
                2 => Some(&mut f.process),
                3 => Some(&mut f.port),
                4 => Some(&mut f.remote),
                _ => None,
            }
        }
        let f = &mut self.port_filter;
        if form.editing {
            match k.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Tab => form.editing = false,
                KeyCode::Backspace => {
                    if let Some(t) = text(f, form.sel) {
                        t.pop();
                    }
                }
                KeyCode::Char(c) => {
                    if let Some(t) = text(f, form.sel) {
                        t.push(c);
                    }
                }
                _ => {}
            }
        } else {
            match k.code {
                KeyCode::Esc | KeyCode::Char('f') | KeyCode::Char('q') => {
                    self.rows_dirty = true;
                    self.port_sel = 0;
                    return Vec::new();
                }
                KeyCode::Up | KeyCode::Char('k') => form.sel = form.sel.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => form.sel = (form.sel + 1).min(4),
                KeyCode::Char('c') => *f = PortFilter::default(),
                KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right => match form.sel {
                    0 => {
                        let opts = [None, Some(Proto::Tcp), Some(Proto::Udp)];
                        let i = opts.iter().position(|o| *o == f.proto).unwrap_or(0);
                        f.proto = opts[if k.code == KeyCode::Left { (i + 2) % 3 } else { (i + 1) % 3 }];
                    }
                    1 => {
                        let all = PortScope::ALL;
                        let i = all.iter().position(|s| *s == f.scope).unwrap_or(0);
                        f.scope = all[if k.code == KeyCode::Left { (i + 3) % 4 } else { (i + 1) % 4 }];
                    }
                    _ if matches!(k.code, KeyCode::Enter | KeyCode::Char(' ')) => form.editing = true,
                    _ => {}
                },
                KeyCode::Backspace | KeyCode::Delete => {
                    if let Some(t) = text(f, form.sel) {
                        t.clear();
                    }
                }
                _ => {}
            }
        }
        self.rows_dirty = true;
        self.port_sel = 0;
        self.modal = Modal::PortFilter(form);
        Vec::new()
    }

    fn set_port_view(&mut self, v: PortView) {
        self.port_view = v;
        self.port_sel = 0;
        self.port_offset = 0;
        self.rows_dirty = true;
    }

    fn on_ports_key(&mut self, k: KeyEvent) -> Vec<Command> {
        self.ensure_rows();
        match k.code {
            KeyCode::Left | KeyCode::Right | KeyCode::Char('s') => {
                let all = PortView::ALL;
                let i = all.iter().position(|v| *v == self.port_view).unwrap_or(0);
                let next = if k.code == KeyCode::Left { (i + all.len() - 1) % all.len() } else { (i + 1) % all.len() };
                self.set_port_view(all[next]);
                return Vec::new();
            }
            KeyCode::Char('f') => {
                self.modal = Modal::PortFilter(PortFilterForm::default());
                return Vec::new();
            }
            _ => {}
        }
        let n = self.port_rows.len();
        if list_nav(&mut self.port_sel, n, k.code) {
            return Vec::new();
        }
        let Some((pid, name)) = self.selected_port_owner() else { return Vec::new() };
        if pid == 0 {
            if matches!(k.code, KeyCode::Enter | KeyCode::Char('w' | ' ' | 'z' | 'r' | 'k' | 'K')) {
                self.set_status(
                    "no process owns these sockets (the kernel holds TIME_WAIT; other users' owners need root)",
                    false,
                );
            }
            return Vec::new();
        }
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

    /// Fs tab. `h` stays help and `L` stays "back to live" as everywhere else, so going up is
    /// ←/Backspace and the largest-files list is `b` (biggest).
    fn on_fs_key(&mut self, k: KeyEvent) -> Vec<Command> {
        let now = self.now;
        self.fs.ensure_rows();
        match k.code {
            KeyCode::Up => self.fs.move_sel(-1),
            KeyCode::Down => self.fs.move_sel(1),
            KeyCode::PageUp => self.fs.move_sel(-15),
            KeyCode::PageDown => self.fs.move_sel(15),
            KeyCode::Home => self.fs.move_sel(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.fs.move_sel(isize::MAX / 2),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                return self.fs_open_selected(k.code == KeyCode::Enter);
            }
            KeyCode::Left | KeyCode::Backspace => return self.fs_up(),
            KeyCode::Char('s') => {
                if self.fs.mode == FsMode::Tree {
                    self.fs.sort = self.fs.sort.next();
                    self.fs.rows_dirty = true;
                } else {
                    self.set_status("sorting applies to the directory view (Esc returns to it)", false);
                }
            }
            KeyCode::Char('g') => {
                let m = if self.fs.mode == FsMode::Growth { FsMode::Tree } else { FsMode::Growth };
                self.fs.set_mode(m);
                return vec![self.fs.growth_cmd(now)];
            }
            KeyCode::Char('w') | KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('-') => {
                let n = FS_WINDOWS.len();
                self.fs.window =
                    if k.code == KeyCode::Char('-') { (self.fs.window + n - 1) % n } else { (self.fs.window + 1) % n };
                self.set_status(
                    format!("growth window: last {}", crate::tui::widgets::fmt_window(self.fs.window_ms())),
                    false,
                );
                return vec![self.fs.growth_cmd(now)];
            }
            KeyCode::Char('r') => {
                let p = self.fs.path.clone();
                self.set_status(format!("rescanning {p} in the background"), false);
                return vec![Command::FsRescan(p), self.fs.list_cmd(now)];
            }
            KeyCode::Char('b') => {
                self.fs.largest_path = self.fs.path.clone();
                self.fs.largest = None;
                self.fs.set_mode(FsMode::Largest);
                return vec![Command::FsLargest(self.fs.path.clone())];
            }
            KeyCode::Char('/') => self.modal = Modal::Filter,
            _ => {}
        }
        Vec::new()
    }

    /// ⏎ / → on the selected row: drill into a directory, jump to a grower, or explain a writer.
    fn fs_open_selected(&mut self, enter: bool) -> Vec<Command> {
        let now = self.now;
        match self.fs.mode {
            FsMode::Tree | FsMode::Largest => {
                let Some(e) = self.fs.selected_entry() else { return Vec::new() };
                let (path, is_dir, name) = (e.path.clone(), e.is_dir, e.name.clone());
                let explicit = e.denied > 0 || e.mount_point;
                if is_dir {
                    return self.fs.go(path, None, explicit, now);
                }
                if self.fs.mode == FsMode::Largest
                    && let Some(parent) = parent_dir(&path)
                {
                    return self.fs.go(parent, Some(name), false, now);
                }
                self.set_status(format!("{name} is a file"), false);
                Vec::new()
            }
            FsMode::Growth => {
                let (Some(row), Some(g)) = (self.fs.selected_growth(), self.fs.growth.as_ref()) else {
                    return Vec::new();
                };
                match row {
                    GrowthRow::Grower(i) => {
                        let Some(x) = g.growers.get(i) else { return Vec::new() };
                        if x.is_dir {
                            let p = x.path.clone();
                            self.fs.go(p, None, false, now)
                        } else {
                            let name = x.path.rsplit('/').next().unwrap_or_default().to_string();
                            let parent = parent_dir(&x.path).unwrap_or_else(|| "/".into());
                            self.fs.go(parent, Some(name), false, now)
                        }
                    }
                    // Only ⏎ explains (→ is navigation).
                    GrowthRow::Deleted(i) if enter => {
                        self.fs.deleted.get(i).map(|d| vec![Command::Explain(d.pid)]).unwrap_or_default()
                    }
                    GrowthRow::Writer(i) if enter => {
                        g.writers.get(i).map(|w| vec![Command::Explain(w.0)]).unwrap_or_default()
                    }
                    _ => Vec::new(),
                }
            }
        }
    }

    fn fs_up(&mut self) -> Vec<Command> {
        if self.fs.mode != FsMode::Tree {
            self.fs.set_mode(FsMode::Tree);
            return Vec::new();
        }
        let Some(parent) = parent_dir(&self.fs.path) else { return Vec::new() };
        let came_from = self.fs.path.trim_end_matches('/').rsplit('/').next().map(str::to_string);
        let now = self.now;
        self.fs.go(parent, came_from, false, now)
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
                        let warn = match kind {
                            ActionKind::Term | ActionKind::Kill | ActionKind::KillTree => " This cannot be undone.",
                            ActionKind::Renice => " Undoing it needs root.",
                            _ => "",
                        };
                        self.modal = Modal::Confirm {
                            prompt: format!("Run suggested action: {action}?{warn}"),
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

    // ---------------------------------------------------------------- server keys

    /// Esc in the server views: close the drill-in, then clear that view's filter / focus.
    /// None = not handled here (fall through to the generic Esc).
    fn server_esc(&mut self) -> Option<Vec<Command>> {
        match self.tab {
            Tab::Fleet if self.fleet.drill.is_some() => self.fleet.drill = None,
            Tab::Fleet if self.fleet.active() && !self.fleet.filter.is_empty() => self.fleet.set_filter(String::new()),
            Tab::Fleet if self.fleet.only.is_some() => {
                self.fleet.only = None;
                self.fleet.dirty = true;
            }
            Tab::Fleet if self.fleet.focus_findings => self.fleet.focus_findings = false,
            Tab::Services if !self.svc.filter.is_empty() => self.svc.set_filter(String::new()),
            Tab::Events if !self.ev.filter.is_empty() => self.ev.set_filter(String::new()),
            _ => return None,
        }
        Some(Vec::new())
    }

    /// Keys while an explanation panel is open: scroll, `w` explains its process, Esc closes.
    fn on_panel_key(&mut self, k: KeyEvent) -> Vec<Command> {
        let Some(p) = self.panel.as_mut() else { return Vec::new() };
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => self.panel = None,
            KeyCode::Down | KeyCode::Char('j') => p.scroll = p.scroll.saturating_add(1),
            KeyCode::Up | KeyCode::Char('k') => p.scroll = p.scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => p.scroll = p.scroll.saturating_add(10),
            KeyCode::PageUp => p.scroll = p.scroll.saturating_sub(10),
            KeyCode::Home | KeyCode::Char('g') => p.scroll = 0,
            KeyCode::Char('w') => match p.pid {
                Some(pid) => {
                    self.panel = None;
                    return vec![Command::Explain(pid)];
                }
                None => self.set_status("no process to explain here", false),
            },
            _ => {}
        }
        Vec::new()
    }

    fn next_incident_id(&mut self) -> u64 {
        self.incident_seq += 1;
        self.incident_seq
    }

    /// `W`: what happened in the last INCIDENT_WINDOW (or around the rewind cursor).
    fn what_happened_now(&mut self) -> Vec<Command> {
        let id = self.next_incident_id();
        let at = self.cursor;
        let when = at.map(crate::tui::widgets::fmt_clock).unwrap_or_else(|| "now".into());
        self.panel = Some(Panel::loading(format!("What happened · {when}"), id));
        vec![Command::WhatHappened { id, at, window_ms: INCIDENT_WINDOW_MS }]
    }

    fn on_services_key(&mut self, k: KeyEvent) -> Vec<Command> {
        self.ensure_server_rows();
        // Field access (not self.view()) so the selection can move while units are borrowed.
        let units_ref: &[crate::server::Unit] =
            match if self.cursor.is_some() { self.past.as_ref() } else { self.live.as_ref() } {
                Some(s) => &s.units,
                None => &[],
            };
        let delta = match k.code {
            KeyCode::Up => Some(-1),
            KeyCode::Down => Some(1),
            KeyCode::PageUp => Some(-15),
            KeyCode::PageDown => Some(15),
            KeyCode::Home | KeyCode::Char('g') => Some(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => Some(isize::MAX / 2),
            _ => None,
        };
        if let Some(d) = delta {
            self.svc.move_sel(d, units_ref);
            return Vec::new();
        }
        if k.code == KeyCode::Enter {
            let warn = self.server_cfg.exhaustion_warn;
            let Some(u) = self.svc.selected(units_ref) else { return Vec::new() };
            let mut evs: Vec<Event> = self.event_ring.iter().cloned().collect();
            evs.extend(self.ev.recorded.iter().flatten().cloned());
            self.panel = Some(crate::tui::server::unit_panel(u, self.view(), &evs, warn, self.now));
            return Vec::new();
        }
        if k.code == KeyCode::Char('w') {
            return match self.svc.selected(units_ref).and_then(|u| u.main_pid) {
                Some(pid) => vec![Command::Explain(pid)],
                None => {
                    self.set_status("this unit has no main process right now", false);
                    Vec::new()
                }
            };
        }
        match k.code {
            KeyCode::Char('c') => self.svc.set_sort(UnitSort::Cpu),
            KeyCode::Char('m') => self.svc.set_sort(UnitSort::Mem),
            KeyCode::Char('d') => self.svc.set_sort(UnitSort::Io),
            KeyCode::Char('r') => self.svc.set_sort(UnitSort::Restarts),
            KeyCode::Char('s') => self.svc.set_sort(UnitSort::State),
            KeyCode::Char('N') => self.svc.set_sort(UnitSort::Name),
            KeyCode::Char('t') => {
                self.svc.group = !self.svc.group;
                self.svc.dirty = true;
            }
            KeyCode::Char('f') => {
                self.svc.problems_only = !self.svc.problems_only;
                self.svc.dirty = true;
            }
            KeyCode::Char('i') => {
                self.svc.show_inactive = !self.svc.show_inactive;
                self.svc.dirty = true;
            }
            KeyCode::Char('W') => return self.what_happened_now(),
            KeyCode::Char('/') => self.modal = Modal::Filter,
            _ => {}
        }
        Vec::new()
    }

    fn on_events_key(&mut self, k: KeyEvent) -> Vec<Command> {
        self.ensure_server_rows();
        let delta = match k.code {
            KeyCode::Up => Some(-1),
            KeyCode::Down => Some(1),
            KeyCode::PageUp => Some(-15),
            KeyCode::PageDown => Some(15),
            KeyCode::Home | KeyCode::Char('g') => Some(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => Some(isize::MAX / 2),
            _ => None,
        };
        if let Some(d) = delta {
            self.ev.move_sel(d);
            return Vec::new();
        }
        match k.code {
            KeyCode::Enter => {
                let Some(e) = self.ev.selected().cloned() else { return Vec::new() };
                let id = self.next_incident_id();
                self.panel = Some(Panel::loading(
                    format!("What happened · {} {}", crate::tui::widgets::fmt_clock(e.ts), e.kind.as_str()),
                    id,
                ));
                return vec![Command::ExplainEvent { id, event: Box::new(e) }];
            }
            KeyCode::Char('W') => return self.what_happened_now(),
            KeyCode::Char('f') => {
                self.ev.min_sev = match self.ev.min_sev {
                    Severity::Info => Severity::Warn,
                    Severity::Warn => Severity::Crit,
                    Severity::Crit => Severity::Info,
                };
                self.ev.dirty = true;
            }
            KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('-') | KeyCode::Char('_') => {
                let n = EVENT_WINDOWS.len();
                let up = matches!(k.code, KeyCode::Char('+') | KeyCode::Char('='));
                self.ev.window = if up { (self.ev.window + 1).min(n - 1) } else { self.ev.window.saturating_sub(1) };
                self.ev.recorded = None;
                self.ev.dirty = true;
                self.set_status(format!("events: last {}", EVENT_WINDOW_NAMES[self.ev.window]), false);
                return vec![self.events_refresh()];
            }
            KeyCode::Char('r') => return vec![self.events_refresh()],
            KeyCode::Char('/') => self.modal = Modal::Filter,
            _ => {}
        }
        Vec::new()
    }

    /// Fleet table (remote hosts). Read-only: nothing here can act on a remote host.
    fn on_fleet_key(&mut self, k: KeyEvent) -> Vec<Command> {
        if self.fleet.drill.is_some() {
            return self.on_drill_key(k);
        }
        self.fleet.ensure_rows();
        if self.fleet.focus_findings {
            let n = self.fleet.findings.len();
            if list_nav(&mut self.fleet.finding_sel, n, k.code) {
                return Vec::new();
            }
            match k.code {
                KeyCode::Left => self.fleet.focus_findings = false,
                KeyCode::Enter => {
                    if let Some(f) = self.fleet.findings.get(self.fleet.finding_sel).cloned() {
                        let hosts = f.hosts.iter().cloned().collect();
                        self.set_status(format!("hosts with: {} ({}) · Esc shows all", f.title, f.count), false);
                        self.fleet.only = Some((f.title, hosts));
                        self.fleet.focus_findings = false;
                        self.fleet.sel = 0;
                        self.fleet.dirty = true;
                    }
                }
                KeyCode::Char('r') => return self.fleet_poll_if_due(self.now, true).into_iter().collect(),
                KeyCode::Char('/') => self.modal = Modal::Filter,
                _ => {}
            }
            return Vec::new();
        }
        let delta = match k.code {
            KeyCode::Up => Some(-1),
            KeyCode::Down => Some(1),
            KeyCode::PageUp => Some(-15),
            KeyCode::PageDown => Some(15),
            KeyCode::Home | KeyCode::Char('g') => Some(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => Some(isize::MAX / 2),
            _ => None,
        };
        if let Some(d) = delta {
            self.fleet.move_sel(d);
            return Vec::new();
        }
        match k.code {
            KeyCode::Enter => {
                let Some(h) = self.fleet.selected() else { return Vec::new() };
                let name = h.name.clone();
                self.fleet.drill = Some(HostDrill {
                    name: name.clone(),
                    requested: self.now,
                    snap: None,
                    findings: Vec::new(),
                    error: None,
                    view: DrillView::Doctor,
                    scroll: 0,
                });
                return vec![Command::FleetDrill(name)];
            }
            KeyCode::Right => {
                if self.fleet.findings.is_empty() {
                    self.set_status("no fleet findings yet (they appear when a poll completes)", false);
                } else {
                    self.fleet.focus_findings = true;
                }
            }
            KeyCode::Char('H') => self.fleet.set_sort(FleetSort::Health),
            KeyCode::Char('c') => self.fleet.set_sort(FleetSort::Cpu),
            KeyCode::Char('m') => self.fleet.set_sort(FleetSort::Mem),
            KeyCode::Char('d') => self.fleet.set_sort(FleetSort::Disk),
            KeyCode::Char('f') => self.fleet.set_sort(FleetSort::Findings),
            KeyCode::Char('n') | KeyCode::Char('N') => self.fleet.set_sort(FleetSort::Name),
            KeyCode::Char('l') => self.fleet.set_sort(FleetSort::Latency),
            KeyCode::Char('s') => {
                let next = self.fleet.sort.next();
                self.fleet.set_sort(next);
            }
            KeyCode::Char('r') => {
                if self.fleet.polling {
                    self.set_status("a poll is already running", false);
                }
                return self.fleet_poll_if_due(self.now, true).into_iter().collect();
            }
            KeyCode::Char('/') => self.modal = Modal::Filter,
            _ => {}
        }
        Vec::new()
    }

    fn on_drill_key(&mut self, k: KeyEvent) -> Vec<Command> {
        let Some(d) = self.fleet.drill.as_mut() else { return Vec::new() };
        let n = d.len();
        if list_nav(&mut d.scroll, n, k.code) {
            return Vec::new();
        }
        let views = [DrillView::Doctor, DrillView::Units, DrillView::Procs];
        let i = views.iter().position(|v| *v == d.view).unwrap_or(0);
        match k.code {
            KeyCode::Right => d.view = views[(i + 1) % views.len()],
            KeyCode::Left => d.view = views[(i + views.len() - 1) % views.len()],
            KeyCode::Char('d') => d.view = DrillView::Doctor,
            KeyCode::Char('u') => d.view = DrillView::Units,
            KeyCode::Char('p') => d.view = DrillView::Procs,
            KeyCode::Char('r') => {
                let name = d.name.clone();
                d.snap = None;
                d.error = None;
                d.requested = self.now;
                return vec![Command::FleetDrill(name)];
            }
            _ => return Vec::new(),
        }
        d.scroll = 0;
        Vec::new()
    }
}

// -------------------------------------------------------------------- pure helpers

pub(crate) fn step(cur: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    (cur as isize).saturating_add(delta).clamp(0, len as isize - 1) as usize
}

/// Up/Down/PgUp/PgDn/Home/End on a plain list. Returns true if handled.
pub(crate) fn list_nav(sel: &mut usize, len: usize, code: KeyCode) -> bool {
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
    Snapshot {
        ts: s.ts,
        host: s.host.clone(),
        system: s.system.clone(),
        procs,
        ports: s.ports.clone(),
        containers: Vec::new(),
        units: reduce_units(&s.units),
        kernel: s.kernel.clone(),
        meta: s.meta.clone(),
        // Events live in App::event_ring, not in every ring entry; volumes in FsView.
        ..Default::default()
    }
}

/// Units kept per ring entry: every unit with a problem or not plain active/inactive, plus
/// the top ones by cpu and memory. Bounds ring memory on hosts with thousands of units.
fn reduce_units(units: &[crate::server::Unit]) -> Vec<crate::server::Unit> {
    if units.len() <= RING_UNITS * 2 {
        return units.to_vec();
    }
    let mut keep: HashSet<usize> = units
        .iter()
        .enumerate()
        .filter(|(_, u)| {
            u.is_failed() || u.flapping || u.recent_restarts > 0 || !matches!(u.state.as_str(), "active" | "inactive")
        })
        .map(|(i, _)| i)
        .collect();
    let mut idx: Vec<usize> = (0..units.len()).collect();
    idx.sort_by(|&a, &b| units[b].cpu.total_cmp(&units[a].cpu));
    keep.extend(idx.iter().take(RING_UNITS));
    idx.sort_by(|&a, &b| units[b].mem.cmp(&units[a].mem));
    keep.extend(idx.iter().take(RING_UNITS));
    let mut kept: Vec<usize> = keep.into_iter().collect();
    kept.sort_unstable();
    kept.into_iter().map(|i| units[i].clone()).collect()
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
        SortKey::Name => {
            a.name.bytes().map(|c| c.to_ascii_lowercase()).cmp(b.name.bytes().map(|c| c.to_ascii_lowercase()))
        }
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
pub fn build_rows_in(
    procs: &[Proc],
    containers: &[Container],
    key: SortKey,
    desc: bool,
    tree: bool,
    filter_lower: &str,
) -> Vec<Row> {
    let ord = |a: usize, b: usize| {
        let o = cmp_proc(&procs[a], &procs[b], key);
        if desc { o.reverse() } else { o }
    };
    if !tree {
        let mut v: Vec<usize> =
            (0..procs.len()).filter(|&i| proc_matches(&procs[i], containers, filter_lower)).collect();
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
/// Ports table rows for a view and filter: listeners first (orphans on top), then
/// connection groups (largest first).
pub fn port_rows_of(s: &Snapshot, view: PortView, filter: &PortFilter) -> Vec<PortRow> {
    let mut rows: Vec<PortRow> = Vec::new();
    if matches!(view, PortView::All | PortView::Listen | PortView::Orphans) {
        rows.extend(
            port_order(s)
                .into_iter()
                .filter(|&i| view != PortView::Orphans || s.ports[i].orphan)
                .filter(|&i| filter.matches_port(&s.ports[i]))
                .map(PortRow::Listen),
        );
    }
    if !matches!(view, PortView::Listen | PortView::Orphans) {
        rows.extend(
            s.conns
                .groups
                .iter()
                .enumerate()
                .filter(|(_, g)| view.has_state(&g.state) && filter.matches_group(g))
                .map(|(i, _)| PortRow::Group(i)),
        );
    }
    rows
}

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
                Port {
                    proto: Proto::Tcp,
                    addr: "127.0.0.1".into(),
                    port: 5432,
                    pid: 400,
                    process: "postgres".into(),
                    state: "LISTEN".into(),
                    orphan: false,
                    note: "postgres".into(),
                },
                Port {
                    proto: Proto::Tcp,
                    addr: "*".into(),
                    port: 3000,
                    pid: 200,
                    process: "node".into(),
                    state: "LISTEN".into(),
                    orphan: true,
                    note: "vite dev server in ~/proj".into(),
                },
            ],
            containers: vec![],
            ..Default::default()
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
        s.system.psi =
            Some(crate::model::Psi { cpu_some: 12.5, mem_some: 0.4, mem_full: 0.1, io_some: 31.0, io_full: 8.0 });
        s.system.temp_c = Some(71.0);
        s.system.power_mw = 48_200.0;
        s.system.power_source = "rapl".into();
        s.procs[0].name = "systemd".into();
        s.procs[0].cgroup = "/init.scope".into();
        for p in s.procs.iter_mut().skip(1) {
            p.cgroup = "/user.slice/user-1000.slice/session-3.scope".into();
        }
        let ctr = "/system.slice/docker-410892b21be2ffda255ceb4e7e2077d968864674cefc8174a3843e6f01c860f7.scope";
        s.procs.push(Proc {
            cgroup: ctr.into(),
            container: Some("410892b21be2".into()),
            ..proc(500, 1, "postgres", 22.0, 400 << 20)
        });
        s.procs.push(Proc {
            cgroup: ctr.into(),
            container: Some("410892b21be2".into()),
            ..proc(501, 500, "pg-worker", 3.0, 60 << 20)
        });
        s.procs.push(Proc {
            cgroup: "/system.slice/docker-f592d553371ffde52670af3ebf50d462cf46a69dde69dc441c816a077198847a.scope"
                .into(),
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
        assert_eq!(a.tab, Tab::Procs, "the first screen is the process list");
        assert_eq!((a.sort, a.sort_desc), (SortKey::Cpu, true), "sorted by cpu, hottest first");
        // No Fleet without containers or hosts: six views, then the Log and Settings screens.
        assert_eq!(
            a.tabs(),
            vec![Tab::Procs, Tab::Ports, Tab::Fs, Tab::Timeline, Tab::Doctor, Tab::Ask, Tab::Log, Tab::Settings]
        );
        a.on_key(code(KeyCode::BackTab));
        assert_eq!(a.tab, Tab::Settings);
        a.on_key(code(KeyCode::Tab));
        assert_eq!(a.tab, Tab::Procs);
        assert!(a.on_key(key('7')).is_empty());
        assert_eq!(a.tab, Tab::Procs, "7 does nothing while Fleet is hidden");
        a.on_key(key('2'));
        assert_eq!(a.tab, Tab::Ports);
        a.on_key(code(KeyCode::Tab));
        assert_eq!(a.tab, Tab::Fs, "Fs sits right after Ports");
        let cmds = a.on_key(key('4'));
        assert!(matches!(cmds[0], Command::RefreshTimeline { .. }));
        assert_eq!(a.tab, Tab::Timeline);
        a.on_key(key('5'));
        assert_eq!(a.tab, Tab::Doctor);
        // A running container makes Fleet appear as 7, after Ask.
        a.set_fleet(Some(vec![Container { id: "abc".into(), name: "pg".into(), ..Default::default() }]));
        a.on_key(code(KeyCode::Tab));
        assert_eq!(a.tab, Tab::Ask);
        a.on_key(code(KeyCode::Tab));
        assert_eq!(a.tab, Tab::Fleet);
        a.on_key(key('7'));
        assert_eq!(a.tab, Tab::Fleet);
        // ... and disappear when it stops (the view falls back to Procs).
        a.set_fleet(Some(vec![]));
        assert_eq!(a.tab, Tab::Procs);
        assert_eq!(Tab::DESKTOP.map(|t| t.title()), ["Procs", "Ports", "Fs", "Timeline", "Doctor", "Ask", "Fleet"]);
        // The action log and settings are screens without number keys; Esc returns.
        a.on_key(key('3'));
        assert_eq!(a.on_key(key('a')), vec![Command::RefreshLog]);
        assert_eq!(a.tab, Tab::Log);
        assert_eq!(a.on_key(key('u')), vec![Command::Undo]);
        assert_eq!(a.tab, Tab::Log, "undo stays on the log");
        assert_eq!(a.on_key(key(',')), vec![Command::LoadSettings]);
        assert_eq!(a.tab, Tab::Settings);
        a.on_key(code(KeyCode::Esc));
        assert_eq!(a.tab, Tab::Fs, "Esc goes back to the view, not the previous screen");
        assert_eq!(a.tab_number(Tab::Log), 0);
    }

    #[test]
    fn log_overlay_undoes_the_selected_entry_only_if_undoable() {
        let mut a = app();
        let rec = |id: u64, kind: ActionKind, undoable: bool, undone: bool| ActionRecord {
            id,
            ts: 0,
            kind,
            pid: 200,
            name: "node".into(),
            prev_nice: None,
            new_nice: None,
            pids: vec![],
            ok: true,
            undoable,
            undone,
            message: String::new(),
            origin: String::new(),
        };
        a.set_log(vec![
            rec(3, ActionKind::Term, false, false),
            rec(2, ActionKind::Pause, true, false),
            rec(1, ActionKind::Pause, true, true),
        ]);
        a.on_key(key('a'));
        assert!(a.on_key(code(KeyCode::Enter)).is_empty(), "TERM is not undoable");
        assert!(a.status.as_ref().unwrap().text.contains("cannot be taken back"));
        a.on_key(code(KeyCode::Down));
        assert_eq!(a.on_key(code(KeyCode::Enter)), vec![Command::UndoId(2)]);
        a.on_key(code(KeyCode::Down));
        assert!(a.on_key(code(KeyCode::Enter)).is_empty());
        assert!(a.status.as_ref().unwrap().text.contains("already undone"));
        // Filters: by kind, and by text.
        a.on_key(key('f'));
        assert_eq!(a.log_kind, Some(ActionKind::Pause));
        assert_eq!(a.log_rows(), vec![1, 2]);
        a.on_key(code(KeyCode::Esc));
        assert_eq!((a.log_kind, a.tab), (None, Tab::Log), "Esc clears the filter first");
        a.on_key(code(KeyCode::Esc));
        assert_eq!(a.tab, Tab::Procs);
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
        assert_eq!(
            a.on_key(key(' ')),
            vec![Command::Act { kind: ActionKind::Pause, pid: 200, nice: None, start: 1700000200 }]
        );
        a.on_key(key('i'));
        a.ensure_rows();
        while a.sel_pid != Some(300) {
            a.on_key(code(KeyCode::Down));
        }
        assert_eq!(
            a.on_key(key('z')),
            vec![Command::Act { kind: ActionKind::Resume, pid: 300, nice: None, start: 1700000300 }]
        );
        a.on_key(key('r'));
        a.on_key(code(KeyCode::Backspace));
        a.on_key(code(KeyCode::Backspace));
        a.on_key(key('5'));
        assert_eq!(
            a.on_key(code(KeyCode::Enter)),
            vec![Command::Act { kind: ActionKind::Renice, pid: 300, nice: Some(5), start: 1700000300 }]
        );
        // default +10
        a.on_key(key('r'));
        assert_eq!(
            a.on_key(code(KeyCode::Enter)),
            vec![Command::Act { kind: ActionKind::Renice, pid: 300, nice: Some(10), start: 1700000300 }]
        );
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
            id: 7,
            ts: 0,
            kind: ActionKind::Pause,
            pid: 200,
            name: "node".into(),
            prev_nice: None,
            new_nice: None,
            pids: vec![200],
            undoable: true,
            undone: false,
            ok: true,
            message: "SIGSTOP".into(),
            origin: String::new(),
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
            Modal::Confirm { cmd, .. } => {
                assert_eq!(*cmd, Command::Act { kind: ActionKind::KillTree, pid: 200, nice: None, start: 1700000200 })
            }
            m => panic!("expected confirm, got {m:?}"),
        }
    }

    fn asked(thread: i64, turns: &[(&str, &str)]) -> crate::threads::Asked {
        let turns: Vec<crate::threads::Turn> = turns
            .iter()
            .enumerate()
            .map(|(i, (q, ans))| crate::threads::Turn {
                id: i as i64 + 1,
                thread,
                question: q.to_string(),
                answer: ans.to_string(),
                via: "test".into(),
                ..Default::default()
            })
            .collect();
        let t = crate::threads::Thread {
            id: thread,
            title: turns[0].question.clone(),
            turns: turns.len() as u32,
            ..Default::default()
        };
        crate::threads::Asked { thread: Some(thread), turns, threads: vec![t], ..Default::default() }
    }

    #[test]
    fn ask_tab_flow() {
        let mut a = app();
        // `?` from any tab opens the Ask tab on a new thread, typing.
        let cmds = a.on_key(key('?'));
        assert_eq!(a.tab, Tab::Ask);
        assert_eq!(cmds, vec![Command::Threads]);
        assert!(a.ask.typing && a.ask.open.is_none());
        // While typing, keys are text: q doesn't quit, digits don't switch tabs.
        for c in "why q1 slow".chars() {
            assert!(a.on_key(key(c)).is_empty());
        }
        assert!(!a.quit && a.tab == Tab::Ask);
        assert_eq!(
            a.on_key(code(KeyCode::Enter)),
            vec![Command::Ask { id: 1, question: "why q1 slow".into(), thread: None }]
        );
        assert!(a.ask.pending.is_some() && !a.ask.typing && a.ask.input.is_empty());
        a.answered(1, asked(7, &[("why q1 slow", "node is busy")]));
        assert!(a.ask.pending.is_none());
        assert_eq!((a.ask.open, a.ask.turns.len(), a.ask.threads.len()), (Some(7), 1, 1));
        // Enter follows up in the open thread.
        a.on_key(code(KeyCode::Enter));
        for c in "since when".chars() {
            a.on_key(key(c));
        }
        assert_eq!(
            a.on_key(code(KeyCode::Enter)),
            vec![Command::Ask { id: 2, question: "since when".into(), thread: Some(7) }]
        );
        a.answered(2, asked(7, &[("why q1 slow", "node is busy"), ("since when", "10 minutes")]));
        assert_eq!(a.ask.turns.len(), 2);
        // n starts a new thread; d asks before deleting.
        a.on_key(key('n'));
        assert!(a.ask.typing && a.ask.open.is_none() && a.ask.turns.is_empty());
        a.on_key(code(KeyCode::Esc));
        assert!(!a.ask.typing);
        a.on_key(key('d'));
        assert!(matches!(&a.modal, Modal::Confirm { cmd: Command::DeleteThread(7), .. }));
        a.on_key(key('n'));
        a.on_key(code(KeyCode::Esc));
        // Up/Down open threads.
        a.set_threads(Ok(vec![
            crate::threads::Thread { id: 9, title: "b".into(), ..Default::default() },
            crate::threads::Thread { id: 7, title: "a".into(), ..Default::default() },
        ]));
        assert_eq!(a.on_key(code(KeyCode::Down)), vec![Command::OpenThread(7)]);
        a.set_thread(7, vec![]);
        assert_eq!(a.ask.open, Some(7));
        // Outside typing, q still quits.
        a.on_key(key('q'));
        assert!(a.quit);
    }

    #[test]
    fn a_stopped_ask_is_saved_but_not_shown() {
        let mut a = app();
        a.on_key(key('?'));
        for c in "q1".chars() {
            a.on_key(key(c));
        }
        a.on_key(code(KeyCode::Enter));
        a.on_key(code(KeyCode::Esc)); // stop waiting; q1 keeps running and is saved
        assert!(a.ask.pending.is_none());
        a.on_key(key('?'));
        for c in "q2".chars() {
            a.on_key(key(c));
        }
        assert_eq!(a.on_key(code(KeyCode::Enter)), vec![Command::Ask { id: 2, question: "q2".into(), thread: None }]);
        a.answered(1, asked(1, &[("q1", "answer to q1")]));
        assert!(a.ask.pending.as_ref().is_some_and(|p| p.id == 2), "late q1 answer must not replace q2");
        assert_eq!(a.ask.threads.len(), 1, "but its thread is listed");
        a.answered(2, asked(2, &[("q2", "answer to q2")]));
        assert_eq!(a.ask.turns[0].answer, "answer to q2");
        // An answer that could not be saved is still shown, with the reason.
        a.on_key(key('?'));
        a.on_key(key('x'));
        a.on_key(code(KeyCode::Enter));
        a.answered(
            3,
            crate::threads::Asked {
                question: "x".into(),
                answer: "y".into(),
                error: Some("disk full".into()),
                ..Default::default()
            },
        );
        assert_eq!(a.ask.turns.last().unwrap().answer, "y");
        assert!(a.status.as_ref().is_some_and(|s| s.error && s.text.contains("disk full")));
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
    fn ports_actions_on_the_vm_host_warn_and_pause_asks_first() {
        let mut s = snap(1_000_000);
        let helper =
            "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper";
        s.procs.push(Proc {
            exe: helper.into(),
            cmd: helper.into(),
            ..proc(13792, 1, "OrbStack Helper", 30.0, 2 << 30)
        });
        s.ports.push(Port {
            proto: Proto::Tcp,
            addr: "127.0.0.1".into(),
            port: 8080,
            pid: 13792,
            process: "OrbStack Helper".into(),
            state: "LISTEN".into(),
            orphan: false,
            note: String::new(),
        });
        let mut a = App::new(1000);
        a.now = 1_000_000;
        a.on_snapshot(s);
        a.on_key(key('2'));
        a.ensure_rows();
        for _ in 0..10 {
            if a.selected_port().is_some_and(|p| p.pid == 13792) {
                break;
            }
            a.on_key(code(KeyCode::Down));
        }
        assert_eq!(a.selected_port().map(|p| p.pid), Some(13792));
        // space no longer freezes the VM at once: it asks, naming what it hosts.
        assert!(a.on_key(key(' ')).is_empty());
        match &a.modal {
            Modal::Confirm { prompt, cmd } => {
                assert!(prompt.contains("WARNING") && prompt.contains("OrbStack VM"), "{prompt}");
                assert!(matches!(cmd, Command::Act { kind: ActionKind::Pause, pid: 13792, .. }));
            }
            m => panic!("{m:?}"),
        }
        a.on_key(code(KeyCode::Esc));
        // k (tree kill on Ports) says it is the VM host, besides "cannot be undone".
        a.on_key(key('k'));
        match &a.modal {
            Modal::Confirm { prompt, .. } => {
                assert!(prompt.contains("cannot be undone") && prompt.contains("OrbStack VM"), "{prompt}")
            }
            m => panic!("{m:?}"),
        }
        a.on_key(code(KeyCode::Esc));
        // A plain process still pauses with one key, and its prompt has no warning.
        let mut b = app();
        assert_eq!(
            b.on_key(key(' ')),
            vec![Command::Act { kind: ActionKind::Pause, pid: 200, nice: None, start: 1700000200 }]
        );
        b.on_key(key('k'));
        assert!(matches!(&b.modal, Modal::Confirm { prompt, .. } if !prompt.contains("WARNING")));
    }

    #[test]
    fn doctor_kill_confirmation_says_it_cannot_be_undone() {
        let mut a = app();
        a.on_key(key('5'));
        a.set_findings_with_starts(
            vec![Finding {
                severity: "warn".into(),
                title: "orphan".into(),
                detail: "".into(),
                pids: vec![200],
                action: Some("kill 200 --tree".into()),
            }],
            HashMap::from([(200, 42)]),
        );
        a.on_key(code(KeyCode::Enter));
        match &a.modal {
            Modal::Confirm { prompt, .. } => assert!(prompt.contains("cannot be undone"), "{prompt}"),
            m => panic!("{m:?}"),
        }
    }

    #[test]
    fn doctor_enter_confirms_suggested_action() {
        let mut a = app();
        a.on_key(key('5'));
        a.set_findings_with_starts(
            vec![
                Finding { severity: "info".into(), title: "x".into(), detail: "".into(), pids: vec![], action: None },
                Finding {
                    severity: "crit".into(),
                    title: "node hot".into(),
                    detail: "".into(),
                    pids: vec![200],
                    action: Some("pause 200".into()),
                },
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

    // ------------------------------------------------------------ Fs tab

    fn de(path: &str, size: u64, is_dir: bool) -> DirEntry {
        DirEntry {
            path: path.into(),
            name: path.rsplit('/').next().unwrap_or("/").into(),
            is_dir,
            size,
            files: size / 100,
            newest_mtime: (size % 1000) as i64,
            ..Default::default()
        }
    }

    fn listing(dir: &str, children: Vec<DirEntry>, partial: bool) -> Listing {
        Listing {
            dir: DirEntry { partial, ..de(dir, children.iter().map(|c| c.size).sum(), true) },
            children,
            progress: crate::fs::ScanProgress { root: "/".into(), running: partial, ..Default::default() },
        }
    }

    fn grower(path: &str, delta: i64, writers: Vec<(u32, &str, u64)>) -> Grower {
        Grower {
            path: path.into(),
            is_dir: !path.ends_with(".log"),
            delta,
            size: delta.max(0) as u64,
            writers: writers.into_iter().map(|(p, n, b)| (p, n.to_string(), b)).collect(),
            evidence: vec![Evidence::Fsevents],
            ..Default::default()
        }
    }

    fn fs_app() -> App {
        let mut a = app();
        let cmds = a.on_key(key('3'));
        assert_eq!(a.tab, Tab::Fs);
        assert_eq!(
            cmds,
            vec![
                Command::FsList { path: "/".into(), explicit: false },
                Command::FsGrowth { window_ms: 600_000, under: None }
            ]
        );
        a.set_fs_listing(
            "/",
            Some(listing(
                "/",
                vec![
                    de("/Users", 500, true),
                    de("/Applications", 300, true),
                    DirEntry { denied: 1, ..de("/private", 100, true) },
                    de("/big.iso", 400, false),
                ],
                true,
            )),
        );
        a
    }

    fn fs_names(a: &mut App) -> Vec<String> {
        a.fs.ensure_rows();
        let l = a.fs.listing.as_ref().unwrap();
        a.fs.rows.iter().map(|&i| l.children[i].name.clone()).collect()
    }

    #[test]
    fn fs_tab_is_lazy_and_polls_only_while_visible() {
        let mut a = app();
        assert!(!a.fs.opened);
        assert!(a.tick(a.now + 10_000).is_empty(), "nothing touches storage before the tab is opened");
        a.on_key(key('3'));
        assert!(a.fs.opened);
        // just asked: nothing new until the refresh intervals pass
        assert!(a.tick(a.now + 10).is_empty());
        let cmds = a.tick(a.now + FS_GROWTH_REFRESH_MS + 20);
        assert!(cmds.contains(&Command::FsList { path: "/".into(), explicit: false }), "{cmds:?}");
        assert!(cmds.iter().any(|c| matches!(c, Command::FsGrowth { .. })));
        a.on_key(key('1'));
        assert!(a.tick(a.now + 60_000).is_empty(), "no polling from other tabs");
        a.on_key(key('3'));
        a.set_fs_error("not available".into());
        assert!(a.tick(a.now + 60_000).is_empty(), "a broken engine is not polled");
    }

    #[test]
    fn fs_drill_up_and_selection() {
        let mut a = fs_app();
        assert_eq!(fs_names(&mut a), vec!["Users", "big.iso", "Applications", "private"]);
        // a file can't be opened
        a.on_key(code(KeyCode::Down));
        assert!(a.on_key(code(KeyCode::Enter)).is_empty());
        assert!(a.status.as_ref().unwrap().text.contains("file"));
        // drill into Users
        a.on_key(code(KeyCode::Home));
        let cmds = a.on_key(code(KeyCode::Enter));
        assert_eq!(a.fs.path, "/Users");
        assert_eq!(cmds[0], Command::FsList { path: "/Users".into(), explicit: false });
        assert_eq!(cmds[1], Command::FsGrowth { window_ms: 600_000, under: Some("/Users".into()) });
        assert!(a.fs.listing.is_none(), "old listing dropped");
        // a stale answer for "/" is ignored
        a.set_fs_listing("/", Some(listing("/", vec![de("/x", 1, true)], false)));
        assert!(a.fs.listing.is_none());
        a.set_fs_listing(
            "/Users",
            Some(listing("/Users", vec![de("/Users/me", 450, true), de("/Users/Shared", 50, true)], false)),
        );
        assert_eq!(fs_names(&mut a), vec!["me", "Shared"]);
        a.on_key(key('l'));
        assert_eq!(a.fs.path, "/Users/me");
        // up twice: back at "/" with the dir we came from selected
        a.on_key(code(KeyCode::Backspace));
        assert_eq!(a.fs.path, "/Users");
        let cmds = a.on_key(code(KeyCode::Left));
        assert_eq!(a.fs.path, "/");
        assert_eq!(cmds[1], Command::FsGrowth { window_ms: 600_000, under: None });
        a.set_fs_listing("/", Some(listing("/", vec![de("/Applications", 300, true), de("/Users", 500, true)], false)));
        a.fs.ensure_rows();
        assert_eq!(a.fs.selected_entry().unwrap().name, "Users");
        assert!(a.on_key(code(KeyCode::Left)).is_empty(), "nothing above /");
        // h is still help, L is still live
        a.on_key(key('h'));
        assert_eq!(a.modal, Modal::Help);
    }

    #[test]
    fn fs_protected_drill_is_explicit_and_sticky_below() {
        let mut a = fs_app();
        a.fs.ensure_rows();
        while a.fs.selected_entry().unwrap().name != "private" {
            a.on_key(code(KeyCode::Down));
        }
        let cmds = a.on_key(code(KeyCode::Enter));
        assert_eq!(cmds[0], Command::FsList { path: "/private".into(), explicit: true });
        a.set_fs_listing("/private", Some(listing("/private", vec![de("/private/var", 90, true)], false)));
        let cmds = a.on_key(code(KeyCode::Enter));
        assert_eq!(
            cmds[0],
            Command::FsList { path: "/private/var".into(), explicit: true },
            "still under the explicit root"
        );
        a.on_key(code(KeyCode::Left));
        a.on_key(code(KeyCode::Left));
        assert_eq!(a.fs.path, "/");
        assert_eq!(a.tick(a.now + 60_000)[0], Command::FsList { path: "/".into(), explicit: false });
    }

    #[test]
    fn fs_sort_cycles_and_keeps_selection() {
        let mut a = fs_app();
        a.on_key(code(KeyCode::Down)); // big.iso
        assert_eq!(a.fs.sort, FsSort::Size);
        let mut seen = vec![];
        for _ in 0..6 {
            a.on_key(key('s'));
            seen.push(a.fs.sort);
            a.fs.ensure_rows();
            assert_eq!(a.fs.selected_entry().unwrap().name, "big.iso", "{:?}", a.fs.sort);
        }
        assert_eq!(seen, vec![FsSort::Growth, FsSort::Io, FsSort::Name, FsSort::Files, FsSort::Age, FsSort::Size]);
        a.fs.sort = FsSort::Name;
        a.fs.rows_dirty = true;
        assert_eq!(fs_names(&mut a), vec!["Applications", "big.iso", "private", "Users"]);
        // filter narrows the children
        a.on_key(key('/'));
        for c in "us".chars() {
            a.on_key(key(c));
        }
        a.on_key(code(KeyCode::Enter));
        assert_eq!(a.fs.filter, "us");
        assert!(a.filter.is_empty(), "the procs filter is untouched");
        assert_eq!(fs_names(&mut a), vec!["Users"]);
        a.on_key(code(KeyCode::Esc));
        assert!(a.fs.filter.is_empty());
    }

    #[test]
    fn fs_growth_view_window_and_writers() {
        let mut a = fs_app();
        a.set_fs_growth(Growth {
            growers: vec![
                grower("/Users/me/Library/Caches", 3 << 30, vec![(200, "node", 5 << 20)]),
                grower("/private/var/log/x.log", 1 << 20, vec![]),
            ],
            writers: vec![(200, "node".into(), 3 << 30)],
            deleted_open: vec![(400, "Chrome".into(), "/tmp/gone".into(), 2 << 30)],
            ..Default::default()
        });
        // Δ attributed to the child holding the grower; growth sort puts it first
        a.on_key(key('s'));
        assert_eq!(a.fs.sort, FsSort::Growth);
        assert_eq!(fs_names(&mut a)[0], "Users");
        assert_eq!(a.fs.selected_child_growth().unwrap().delta, 3 << 30);
        // growth view
        let cmds = a.on_key(key('g'));
        assert_eq!(cmds, vec![Command::FsGrowth { window_ms: 600_000, under: None }]);
        assert_eq!(a.fs.mode, FsMode::Growth);
        a.fs.ensure_rows();
        assert_eq!(
            a.fs.grows,
            vec![GrowthRow::Grower(0), GrowthRow::Grower(1), GrowthRow::Deleted(0), GrowthRow::Writer(0)]
        );
        // window cycles 10m -> 1h -> 24h -> 10m
        assert_eq!(a.on_key(key('w')), vec![Command::FsGrowth { window_ms: 3_600_000, under: None }]);
        a.on_key(key('w'));
        assert_eq!(a.fs.window_ms(), 86_400_000);
        a.on_key(key('w'));
        assert_eq!(a.fs.window_ms(), 600_000);
        a.on_key(key('-'));
        assert_eq!(a.fs.window_ms(), 86_400_000);
        // ⏎ on a writer row explains the pid; on deleted-open too
        a.on_key(code(KeyCode::End));
        assert_eq!(a.on_key(code(KeyCode::Enter)), vec![Command::Explain(200)]);
        a.on_key(code(KeyCode::Up));
        assert_eq!(a.on_key(code(KeyCode::Enter)), vec![Command::Explain(400)]);
        assert!(a.on_key(code(KeyCode::Right)).is_empty(), "→ only navigates");
        // ⏎ on a file grower opens its directory with the file selected
        a.on_key(code(KeyCode::Home));
        a.on_key(code(KeyCode::Down));
        let cmds = a.on_key(code(KeyCode::Enter));
        assert_eq!(a.fs.mode, FsMode::Tree);
        assert_eq!(a.fs.path, "/private/var/log");
        assert_eq!(cmds[0], Command::FsList { path: "/private/var/log".into(), explicit: false });
        a.set_fs_listing(
            "/private/var/log",
            Some(listing(
                "/private/var/log",
                vec![de("/private/var/log/a", 9, false), de("/private/var/log/x.log", 5, false)],
                false,
            )),
        );
        a.fs.ensure_rows();
        assert_eq!(a.fs.selected_entry().unwrap().name, "x.log");
        // Esc leaves the growth view
        a.on_key(key('g'));
        a.on_key(code(KeyCode::Esc));
        assert_eq!(a.fs.mode, FsMode::Tree);
    }

    #[test]
    fn fs_largest_rescan_and_no_destructive_keys() {
        let mut a = fs_app();
        assert_eq!(a.on_key(key('b')), vec![Command::FsLargest("/".into())]);
        assert_eq!(a.fs.mode, FsMode::Largest);
        a.set_fs_largest("/", vec![de("/Users/me/vm.img", 9000, false), de("/Users/me/node_modules", 800, true)]);
        a.fs.ensure_rows();
        assert_eq!(a.fs.len(), 2);
        a.on_key(code(KeyCode::Enter));
        assert_eq!(a.fs.path, "/Users/me");
        assert_eq!(a.fs.mode, FsMode::Tree);
        let cmds = a.on_key(key('r'));
        assert_eq!(cmds[0], Command::FsRescan("/Users/me".into()));
        // process-action keys do nothing here (fat never deletes; no signals from the Fs tab)
        for c in [' ', 'k', 'K', 'z', 'd', 'x'] {
            for cmd in a.on_key(key(c)) {
                assert!(!matches!(cmd, Command::Act { .. }), "{c} -> {cmd:?}");
            }
            a.modal = Modal::None;
        }
    }

    #[test]
    fn child_growth_sums_without_double_counting() {
        let gs = vec![
            grower("/Users/me", 10 << 20, vec![(1, "a", 100)]),
            grower("/Users/me/cache", 8 << 20, vec![(2, "b", 300), (1, "a", 50)]),
            grower("/Users/other", 1 << 20, vec![]),
            grower("/Users/meh", 5, vec![(9, "z", 1)]),
            grower("/Applications", -(4 << 20), vec![]),
        ];
        let me = child_growth("/Users/me", &gs);
        assert_eq!(me.delta, 10 << 20, "nested grower not added on top of its parent");
        assert_eq!(me.write_bps, 400, "distinct writers, max rate each");
        assert_eq!(me.top_writer, Some((2, "b".into(), 300)));
        let users = child_growth("/Users", &gs);
        assert_eq!(users.delta, (10 << 20) + (1 << 20) + 5);
        assert_eq!(child_growth("/Applications", &gs).delta, -(4 << 20));
        assert_eq!(child_growth("/", &gs).delta, (10 << 20) + (1 << 20) + 5 - (4 << 20));
        assert_eq!(child_growth("/nope", &gs), ChildGrowth::default());
        assert!(
            path_within("/a/b", "/a")
                && path_within("/a", "/a")
                && path_within("/a/b", "/a/")
                && path_within("/x", "/")
        );
        assert!(!path_within("/a/bc", "/a/b"));
        assert_eq!(parent_dir("/a/b"), Some("/a".into()));
        assert_eq!(parent_dir("/a"), Some("/".into()));
        assert_eq!(parent_dir("/a/b/"), Some("/a".into()));
        assert_eq!(parent_dir("/"), None);
    }

    #[test]
    fn fs_volume_ring_for_time_travel() {
        let mut a = app();
        for i in 0..5 {
            a.set_volumes(
                1_000_000 + i * 1000,
                vec![Volume { mount: "/".into(), used: 100 + i as u64, ..Default::default() }],
            );
        }
        assert_eq!(a.fs.used_at("/", 1_002_100), Some((1_002_000, 102)));
        assert_eq!(a.fs.used_at("/", 5_000_000), None, "outside what this session saw");
        assert_eq!(a.fs.used_at("/home", 1_002_000), None);
        a.set_volumes(1_000_000 + RING_MS + 10_000, vec![]);
        assert_eq!(a.fs.vol_ring.len(), 1, "ring bounded to RING_MS");
    }

    #[test]
    fn ports_views_filters_and_owners() {
        use crate::model::{ConnGroup, Conns, Port, Proto};
        let mut a = app();
        let mut s = snap(2_000_000);
        s.ports = vec![
            Port {
                proto: Proto::Tcp,
                addr: "*".into(),
                port: 443,
                pid: 10,
                process: "nginx".into(),
                state: "LISTEN".into(),
                ..Default::default()
            },
            Port {
                proto: Proto::Udp,
                addr: "127.0.0.1".into(),
                port: 53,
                pid: 11,
                process: "dnsmasq".into(),
                ..Default::default()
            },
        ];
        let g = |state: &str, pid: u32, process: &str, inbound: bool, remote: &str, rport: u16, count: u32| ConnGroup {
            state: state.into(),
            pid,
            process: process.into(),
            inbound,
            local: if inbound { "10.0.0.2".into() } else { String::new() },
            local_port: if inbound { 443 } else { 0 },
            remote: remote.into(),
            remote_port: rport,
            count,
            ..Default::default()
        };
        s.conns = Conns {
            states: vec![
                ("ESTABLISHED".into(), 7),
                ("TIME_WAIT".into(), 30),
                ("CLOSE_WAIT".into(), 2),
                ("SYN_SENT".into(), 1),
                ("LISTEN".into(), 1),
            ],
            groups: vec![
                g("TIME_WAIT", 0, "", true, "203.0.113.5", 0, 30),
                g("ESTABLISHED", 10, "nginx", true, "203.0.113.5", 0, 5),
                g("ESTABLISHED", 20, "app", false, "10.0.0.9", 5432, 2),
                g("CLOSE_WAIT", 20, "app", false, "10.0.0.9", 5432, 2),
                g("SYN_SENT", 20, "app", false, "198.51.100.1", 443, 1),
            ],
            ..Default::default()
        };
        a.on_snapshot(s);
        a.switch_tab(Tab::Ports);
        a.ensure_rows();
        assert_eq!(a.port_rows.len(), 7, "All: both listeners and every group");
        assert!(matches!(a.port_rows[0], PortRow::Listen(_)), "listeners first");
        let view = |a: &mut App, v: PortView| {
            a.set_port_view(v);
            a.ensure_rows();
            a.port_rows.clone()
        };
        assert_eq!(view(&mut a, PortView::Listen).len(), 2);
        assert_eq!(view(&mut a, PortView::Established), vec![PortRow::Group(1), PortRow::Group(2)]);
        assert_eq!(view(&mut a, PortView::TimeWait), vec![PortRow::Group(0)]);
        assert_eq!(view(&mut a, PortView::CloseWait), vec![PortRow::Group(3)]);
        assert_eq!(view(&mut a, PortView::Other), vec![PortRow::Group(4)]);
        assert!(view(&mut a, PortView::Orphans).is_empty());
        // ←→ cycle the chips.
        a.set_port_view(PortView::All);
        a.on_key(code(KeyCode::Right));
        assert_eq!(a.port_view, PortView::Listen);
        a.on_key(code(KeyCode::Left));
        a.on_key(code(KeyCode::Left));
        assert_eq!(a.port_view, PortView::Orphans);
        // Filters combine; Esc clears view and filter.
        a.set_port_view(PortView::All);
        a.port_filter.scope = PortScope::Private;
        a.rows_dirty = true;
        a.ensure_rows();
        assert_eq!(a.port_rows, vec![PortRow::Group(2), PortRow::Group(3)], "peers on private networks");
        a.port_filter = PortFilter { port: "5000-6000".into(), ..Default::default() };
        a.rows_dirty = true;
        a.ensure_rows();
        assert_eq!(a.port_rows.len(), 2);
        a.port_filter = PortFilter { proto: Some(Proto::Udp), ..Default::default() };
        a.rows_dirty = true;
        a.ensure_rows();
        assert_eq!(a.port_rows, vec![PortRow::Listen(1)]);
        a.port_filter = PortFilter { port: "nonsense".into(), ..Default::default() };
        a.rows_dirty = true;
        a.ensure_rows();
        assert!(a.port_rows.is_empty(), "an unreadable port matches nothing, rather than everything");
        a.on_key(code(KeyCode::Esc));
        assert!(a.port_filter.is_empty() && a.port_view == PortView::All && a.tab == Tab::Ports);
        // The dialog edits the filter live.
        a.on_key(key('f'));
        assert!(matches!(a.modal, Modal::PortFilter(_)));
        a.on_key(code(KeyCode::Enter)); // protocol: any -> tcp
        assert_eq!(a.port_filter.proto, Some(Proto::Tcp));
        a.on_key(code(KeyCode::Down));
        a.on_key(code(KeyCode::Down)); // process
        a.on_key(code(KeyCode::Enter));
        for c in "ngi".chars() {
            a.on_key(key(c));
        }
        a.on_key(code(KeyCode::Enter));
        assert_eq!(a.port_filter.process, "ngi");
        a.on_key(code(KeyCode::Esc));
        assert_eq!(a.modal, Modal::None);
        a.ensure_rows();
        assert_eq!(a.port_rows, vec![PortRow::Listen(0), PortRow::Group(1)]);
        // A row nobody owns (TIME_WAIT) says so instead of acting.
        a.port_filter = PortFilter::default();
        a.set_port_view(PortView::TimeWait);
        a.ensure_rows();
        assert!(a.on_key(key('k')).is_empty());
        assert!(a.status.as_ref().unwrap().text.contains("kernel"));
        assert_eq!(a.modal, Modal::None);
        // Scopes of addresses.
        assert_eq!(PortScope::of("*"), PortScope::Public);
        assert_eq!(PortScope::of("[::1]"), PortScope::Loopback);
        assert_eq!(PortScope::of("192.168.1.4"), PortScope::Private);
        assert_eq!(PortScope::of("8.8.8.8"), PortScope::Public);
    }

    #[test]
    fn close_wait_rising_needs_a_steady_climb() {
        let mut a = app();
        a.close_wait_hist.clear();
        for n in [5, 6, 7] {
            a.close_wait_hist.push_back(n);
        }
        assert!(!a.close_wait_rising(), "needs four samples");
        a.close_wait_hist.push_back(9);
        assert!(a.close_wait_rising());
        a.close_wait_hist.push_back(9);
        assert!(!a.close_wait_rising(), "flat is not rising");
    }

    #[test]
    fn the_ask_page_shows_the_choice_then_only_what_it_needs() {
        let fields = crate::settings::fields(&crate::config::Config::default(), "", &|_: &str| None);
        let opt = |key: &str, url: Option<&str>| crate::llm::AskOption {
            key: key.into(),
            label: key.into(),
            url: url.map(str::to_string),
            ..Default::default()
        };
        let mut ui = SettingsUi {
            fields,
            ask_options: vec![
                opt("claude-code", None),
                opt("ollama", Some("http://127.0.0.1:11434")),
                opt("anthropic", None),
                opt("off", None),
            ],
            ..Default::default()
        };
        let keys = |ui: &SettingsUi| -> Vec<String> {
            ui.ask_rows()
                .iter()
                .map(|r| match r {
                    SRow::Field(i) => ui.fields[*i].key.clone(),
                    SRow::AskOption(i) => format!("opt:{}", ui.ask_options[*i].key),
                    SRow::AskAdvanced => "advanced".into(),
                    _ => "?".into(),
                })
                .collect()
        };
        // Default: the Claude API. Its details are the model and key variable; no URL, no command.
        let k = keys(&ui);
        assert_eq!(&k[..4], &["opt:claude-code", "opt:ollama", "opt:anthropic", "opt:off"]);
        assert!(k.contains(&"model".into()) && k.contains(&"key_env".into()));
        assert!(!k.contains(&"url".into()) && !k.contains(&"command".into()) && !k.contains(&"provider".into()));
        assert!(k.contains(&"local_only".into()) && k.ends_with(&["advanced".to_string()]));
        assert_eq!(ui.current_ask_option(), Some(2));
        // Ollama on this machine: URL and model, and its context window under Advanced.
        let set = |ui: &mut SettingsUi, key: &str, v: &str| {
            ui.fields.iter_mut().find(|f| f.section == "ask" && f.key == key).unwrap().value = v.into();
        };
        set(&mut ui, "provider", "ollama");
        set(&mut ui, "url", "http://10.0.0.20:11434");
        ui.ask_options.push(opt("openai", None));
        assert_eq!(ui.current_ask_option(), Some(4), "a server elsewhere is \"another model server\"");
        ui.ask_options.pop();
        set(&mut ui, "url", "http://127.0.0.1:11434");
        ui.ask_advanced = true;
        let k = keys(&ui);
        assert!(k.contains(&"url".into()) && k.contains(&"num_ctx".into()), "a server may also need a key: {k:?}");
        assert_eq!(ui.current_ask_option(), Some(1));
        // A signed-in tool: just the optional model.
        set(&mut ui, "provider", "claude-code");
        let k = keys(&ui);
        assert!(k.contains(&"model".into()) && !k.contains(&"url".into()) && !k.contains(&"key_env".into()));
        assert_eq!(ui.current_ask_option(), Some(0));
        set(&mut ui, "enabled", "false");
        assert_eq!(ui.current_ask_option(), Some(3));
        // Enter on an option applies it.
        let mut a = app();
        a.settings = ui;
        a.tab = Tab::Settings;
        a.settings.sel = 1;
        assert_eq!(
            a.on_key(code(KeyCode::Enter)),
            vec![Command::ApplyAskOption(opt("ollama", Some("http://127.0.0.1:11434")))]
        );
        a.settings.sel = a.settings.rows().iter().position(|r| *r == SRow::AskAdvanced).unwrap();
        a.on_key(code(KeyCode::Enter));
        assert!(!a.settings.ask_advanced, "Enter folds Advanced");
    }

    #[test]
    fn peer_filter_matches_name_and_network() {
        let g = crate::model::ConnGroup {
            remote: "203.0.113.5".into(),
            peer_name: "edge-3.cdn.example".into(),
            peer_net: Some(crate::model::PeerNet { asn: 64500, name: "Example-CDN".into(), country: String::new() }),
            ..Default::default()
        };
        for q in ["203.0.113", "cdn.example", "AS64500", "as645", "example-cdn", "Example"] {
            assert!(peer_matches(&g, q), "{q}");
        }
        for q in ["10.0.0", "AS1", "other"] {
            assert!(!peer_matches(&g, q), "{q}");
        }
    }
}
