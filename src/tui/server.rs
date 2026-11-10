//! Server-profile TUI state: the Services table, the Events/Incidents timeline, the fleet
//! health table and the explanation panels they open. OWNER: tui agent.
//!
//! Pure like `app.rs`: no terminal and no I/O. Data arrives through `App::set_*`, side effects
//! leave as `app::Command`s. Nothing here assumes a fleet size, distro, init system or
//! runtime: every unit kind and every host is treated the same way, and the only thresholds
//! used for colour come from `ServerCfg`.

use crate::model::{Finding, Snapshot, Ts};
use crate::server::{Event, EventKind, FleetFinding, FleetHost, FleetSummary, Incident, Severity, Unit, UnitKind};
use crate::tui::widgets::{contains_ci, fmt_bytes, fmt_clock, fmt_dur, fmt_rate};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

/// Events kept in memory from live samples (the recorder keeps the rest). A memory bound for
/// one TUI session, not a product limit: events are sparse, so this is hours to days.
pub const EVENT_RING: usize = 5000;
/// Time windows of the Events view, cycled with +/-.
pub const EVENT_WINDOWS: [i64; 5] = [15 * 60_000, 3_600_000, 6 * 3_600_000, 24 * 3_600_000, 7 * 24 * 3_600_000];
pub const EVENT_WINDOW_NAMES: [&str; 5] = ["15m", "1h", "6h", "24h", "7d"];
/// How often the visible Events view re-reads the recorder.
pub const EVENTS_REFRESH_MS: i64 = 5000;
/// Window examined by `W` (what happened) and around a selected event.
pub const INCIDENT_WINDOW_MS: i64 = 15 * 60_000;
/// Units / events / procs shown in a unit's explanation panel.
const PANEL_ITEMS: usize = 8;

// ------------------------------------------------------------------------------- panel

/// A read-only explanation overlay: a unit's "why", an incident ("what happened"), a fleet
/// finding. Sections render as headed bullet lists.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Panel {
    pub title: String,
    pub headline: String,
    pub severity: Severity,
    pub sections: Vec<(String, Vec<String>)>,
    /// `w` explains this process (a unit's main pid, an OOM victim's culprit).
    pub pid: Option<u32>,
    /// Waiting for the incident answer with this request id.
    pub pending: Option<u64>,
    pub scroll: u16,
}

impl Panel {
    pub fn loading(title: impl Into<String>, id: u64) -> Panel {
        Panel { title: title.into(), headline: "working it out…".into(), pending: Some(id), ..Default::default() }
    }
}

/// The incident report as a panel: chain first (symptom → root cause), then who, the numbers,
/// what to do, the events it is built from and what data was missing.
pub fn incident_panel(inc: &Incident) -> Panel {
    let mut sections = Vec::new();
    if !inc.chain.is_empty() {
        sections.push(("What happened".to_string(), inc.chain.iter().enumerate().map(|(i, s)| format!("{}{s}", if i == 0 { "" } else { "↳ " })).collect()));
    }
    if !inc.culprits.is_empty() {
        let v = inc
            .culprits
            .iter()
            .map(|c| {
                let mut s = format!("{} {}", c.kind, c.name);
                if let Some(p) = c.pid {
                    s.push_str(&format!(" (pid {p})"));
                }
                if let Some(u) = c.unit.as_ref().filter(|u| **u != c.name) {
                    s.push_str(&format!(" in {u}"));
                }
                if !c.why.is_empty() {
                    s.push_str(&format!(": {}", c.why));
                }
                s
            })
            .collect();
        sections.push(("Who".to_string(), v));
    }
    if !inc.evidence.is_empty() {
        sections.push(("Evidence".to_string(), inc.evidence.clone()));
    }
    if !inc.suggestions.is_empty() {
        sections.push(("What you can do (read-only first)".to_string(), inc.suggestions.clone()));
    }
    if !inc.events.is_empty() {
        sections.push(("Events".to_string(), inc.events.iter().map(event_line).collect()));
    }
    if !inc.gaps.is_empty() {
        sections.push(("Missing data".to_string(), inc.gaps.clone()));
    }
    let when = if inc.from > 0 && inc.to > inc.from {
        format!("{} … {}", fmt_clock(inc.from), fmt_clock(inc.to))
    } else {
        fmt_clock(inc.at)
    };
    let host = if inc.host.is_empty() { String::new() } else { format!("{} · ", inc.host) };
    Panel {
        title: format!("What happened · {host}{when}"),
        headline: if inc.headline.is_empty() { "nothing unusual found in this window".into() } else { inc.headline.clone() },
        severity: inc.severity,
        sections,
        pid: inc.culprits.iter().find_map(|c| c.pid),
        pending: None,
        scroll: 0,
    }
}

/// "03:12:04 oom_kill unit:postgres.service — postgres (1234) killed …"
pub fn event_line(e: &Event) -> String {
    format!("{} {} {} — {}", fmt_clock(e.ts), e.kind.as_str(), e.subject, e.detail)
}

// ------------------------------------------------------------------------------- services

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitSort {
    /// Problems first (failed, flapping, transitioning), then CPU.
    State,
    Cpu,
    Mem,
    Io,
    Restarts,
    Name,
}

impl UnitSort {
    pub fn label(self) -> &'static str {
        match self {
            UnitSort::State => "state",
            UnitSort::Cpu => "cpu",
            UnitSort::Mem => "mem",
            UnitSort::Io => "io",
            UnitSort::Restarts => "restarts",
            UnitSort::Name => "name",
        }
    }
}

/// 0 = most urgent. Used by the State sort and the row colours.
pub fn unit_rank(u: &Unit) -> u8 {
    if u.is_failed() {
        0
    } else if u.flapping {
        1
    } else {
        match u.state.as_str() {
            "activating" | "deactivating" | "reloading" => 2,
            "unknown" | "" => 3,
            "active" => 4,
            _ => 5,
        }
    }
}

/// Container runtime for containers ("docker", "podman"…), else the kind name.
pub fn unit_kind_label(u: &Unit) -> &str {
    match (&u.kind, &u.container) {
        (UnitKind::Container, Some(c)) if !c.runtime.is_empty() => &c.runtime,
        (k, _) => k.as_str(),
    }
}

/// memory.current / memory.max when a limit is set.
pub fn mem_limit_ratio(u: &Unit) -> Option<f64> {
    u.mem_limit.filter(|l| *l > 0 && *l < u64::MAX / 2).map(|l| u.mem as f64 / l as f64)
}

/// Worth a look: failed, flapping, restarting, unhealthy, OOM-killed, throttled, or memory
/// near its limit (`warn` = `ServerCfg::exhaustion_warn`).
pub fn unit_is_problem(u: &Unit, warn: f32) -> bool {
    u.is_failed()
        || u.flapping
        || u.recent_restarts > 0
        || u.oom_kills > 0
        || u.cpu_throttled_pct > 0.0
        || u.container.as_ref().and_then(|c| c.health.as_deref()) == Some("unhealthy")
        || mem_limit_ratio(u).is_some_and(|r| r >= warn as f64)
}

fn unit_matches(u: &Unit, f: &str) -> bool {
    if f.is_empty() {
        return true;
    }
    let c = u.container.as_ref();
    contains_ci(&u.name, f)
        || contains_ci(&u.description, f)
        || contains_ci(&u.state, f)
        || contains_ci(&u.sub_state, f)
        || contains_ci(u.kind.as_str(), f)
        || contains_ci(&u.cgroup, f)
        || c.is_some_and(|c| {
            contains_ci(&c.name, f)
                || contains_ci(&c.image, f)
                || contains_ci(&c.runtime, f)
                || c.pod.as_deref().is_some_and(|p| contains_ci(p, f))
                || c.namespace.as_deref().is_some_and(|n| contains_ci(n, f))
        })
}

fn cmp_unit(a: &Unit, b: &Unit, key: UnitSort) -> Ordering {
    // Numeric keys: descending (hottest first) is the natural order, so compare b to a.
    let o = match key {
        UnitSort::State => unit_rank(a).cmp(&unit_rank(b)).then(b.cpu.total_cmp(&a.cpu)),
        UnitSort::Cpu => b.cpu.total_cmp(&a.cpu),
        UnitSort::Mem => b.mem.cmp(&a.mem),
        UnitSort::Io => (b.io_read_bps + b.io_write_bps).cmp(&(a.io_read_bps + a.io_write_bps)),
        UnitSort::Restarts => (b.recent_restarts, b.restarts).cmp(&(a.recent_restarts, a.restarts)),
        UnitSort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    };
    o.then_with(|| a.name.cmp(&b.name))
}

pub struct ServicesView {
    pub sort: UnitSort,
    /// false = the natural order of `sort` reversed.
    pub natural: bool,
    /// Rows grouped by kind (systemd, container, k8s-pod, cgroup).
    pub group: bool,
    pub problems_only: bool,
    pub show_inactive: bool,
    pub filter: String,
    pub(crate) filter_lower: String,
    /// Indices into the viewed snapshot's `units`.
    pub rows: Vec<usize>,
    /// Inactive units left out (shown with `i`).
    pub hidden: usize,
    pub(crate) dirty: bool,
    pub sel: usize,
    pub offset: usize,
    sel_key: Option<(UnitKind, String)>,
}

impl Default for ServicesView {
    fn default() -> Self {
        ServicesView {
            sort: UnitSort::State,
            natural: true,
            group: false,
            problems_only: false,
            show_inactive: false,
            filter: String::new(),
            filter_lower: String::new(),
            rows: Vec::new(),
            hidden: 0,
            dirty: true,
            sel: 0,
            offset: 0,
            sel_key: None,
        }
    }
}

/// Row order for the Services table.
pub fn unit_order(units: &[Unit], v: &ServicesView, warn: f32) -> (Vec<usize>, usize) {
    let mut hidden = 0;
    let mut rows: Vec<usize> = (0..units.len())
        .filter(|&i| {
            let u = &units[i];
            if !unit_matches(u, &v.filter_lower) {
                return false;
            }
            if v.problems_only && !unit_is_problem(u, warn) {
                return false;
            }
            // Inactive units are noise on most hosts (hundreds of unused unit files) unless
            // something is wrong with them or the operator searches for them.
            if !v.show_inactive && v.filter_lower.is_empty() && u.state == "inactive" && !unit_is_problem(u, warn) {
                hidden += 1;
                return false;
            }
            true
        })
        .collect();
    rows.sort_by(|&a, &b| {
        let (x, y) = (&units[a], &units[b]);
        let g = if v.group { x.kind.cmp(&y.kind) } else { Ordering::Equal };
        let o = cmp_unit(x, y, v.sort);
        g.then(if v.natural { o } else { o.reverse() })
    });
    (rows, hidden)
}

impl ServicesView {
    pub fn ensure_rows(&mut self, units: &[Unit], warn: f32) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        (self.rows, self.hidden) = unit_order(units, self, warn);
        let found = self.sel_key.as_ref().and_then(|(k, n)| self.rows.iter().position(|&i| units[i].kind == *k && units[i].name == *n));
        self.sel = found.unwrap_or_else(|| self.sel.min(self.rows.len().saturating_sub(1)));
    }

    pub fn selected<'a>(&self, units: &'a [Unit]) -> Option<&'a Unit> {
        units.get(*self.rows.get(self.sel)?)
    }

    pub fn move_sel(&mut self, delta: isize, units: &[Unit]) {
        self.sel = crate::tui::app::step(self.sel, delta, self.rows.len());
        self.sel_key = self.selected(units).map(|u| (u.kind, u.name.clone()));
    }

    pub fn set_sort(&mut self, key: UnitSort) {
        if self.sort == key {
            self.natural = !self.natural;
        } else {
            self.sort = key;
            self.natural = true;
        }
        self.dirty = true;
    }

    pub fn set_filter(&mut self, f: String) {
        self.filter_lower = f.to_lowercase();
        self.filter = f;
        self.dirty = true;
    }
}

/// Processes of a unit in the snapshot: same cgroup or below it (or its main pid when the
/// cgroup is unknown), busiest first.
pub fn unit_procs<'a>(u: &Unit, snap: &'a Snapshot) -> Vec<&'a crate::model::Proc> {
    let cg = u.cgroup.trim_end_matches('/');
    let mut v: Vec<&crate::model::Proc> = snap
        .procs
        .iter()
        .filter(|p| {
            if !cg.is_empty() && cg != "/" {
                p.cgroup == cg || (p.cgroup.starts_with(cg) && p.cgroup.as_bytes().get(cg.len()) == Some(&b'/'))
            } else {
                Some(p.pid) == u.main_pid
            }
        })
        .collect();
    v.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.mem.cmp(&a.mem)));
    v
}

/// Does this event concern unit `u`?
pub fn event_is_about(e: &Event, u: &Unit) -> bool {
    if e.unit.as_deref() == Some(u.name.as_str()) {
        return true;
    }
    let subj = e.subject.split_once(':').map(|(_, s)| s).unwrap_or(&e.subject);
    subj == u.name
        || u.container.as_ref().is_some_and(|c| subj == c.name || (!c.id.is_empty() && subj.starts_with(&c.id)))
        || (e.pid.is_some() && e.pid == u.main_pid)
}

/// Read-only next steps for a unit, built from what was detected about it (its kind and
/// runtime), never from assumptions about the host.
pub fn unit_hints(u: &Unit) -> Vec<String> {
    let mut v = Vec::new();
    match u.kind {
        UnitKind::Systemd => {
            v.push(format!("journalctl -u {} --since -1h --no-pager", u.name));
            v.push(format!("systemctl status {} --no-pager", u.name));
            if u.flapping || u.is_failed() {
                v.push(format!("systemctl show {} -p Result,ExecMainStatus,NRestarts,MemoryMax", u.name));
            }
        }
        UnitKind::Container => {
            let c = u.container.as_ref();
            // The runtime as detected; unknown = no runtime CLI is suggested at all.
            let rt = c.map(|c| c.runtime.as_str()).unwrap_or("");
            let name = c.map(|c| if c.name.is_empty() { c.id.as_str() } else { c.name.as_str() }).unwrap_or(u.name.as_str());
            match rt {
                "" => {
                    if !u.cgroup.is_empty() {
                        v.push(format!("cat /sys/fs/cgroup{}/memory.events", u.cgroup));
                    }
                }
                // CRI runtimes are driven through the CRI client, not a docker-like CLI.
                "containerd" | "cri-o" | "crio" | "cri-containerd" => {
                    v.push(format!("crictl logs --tail 200 {}", c.map(|c| c.id.as_str()).unwrap_or(name)));
                    v.push(format!("crictl inspect {}", c.map(|c| c.id.as_str()).unwrap_or(name)));
                }
                _ => {
                    v.push(format!("{rt} logs --since 1h {name}"));
                    v.push(format!("{rt} inspect {name}"));
                }
            }
            if let Some((pod, ns)) = c.and_then(|c| Some((c.pod.as_deref()?, c.namespace.as_deref().unwrap_or("default")))) {
                v.push(format!("kubectl -n {ns} describe pod {pod}"));
            }
        }
        UnitKind::Pod => {
            let (ns, pod) = u.name.split_once('/').unwrap_or(("default", u.name.as_str()));
            v.push(format!("kubectl -n {ns} describe pod {pod}"));
            v.push(format!("kubectl -n {ns} logs {pod} --all-containers --since=1h"));
        }
        UnitKind::Cgroup => {
            if !u.cgroup.is_empty() {
                v.push(format!("cat /sys/fs/cgroup{}/cgroup.procs", u.cgroup));
                v.push(format!("cat /sys/fs/cgroup{}/memory.events", u.cgroup));
            }
        }
    }
    v
}

/// The unit "why": what it is, its state and history, its resources against its limits, its
/// processes, its recent events and read-only next steps.
pub fn unit_panel(u: &Unit, snap: Option<&Snapshot>, events: &[Event], warn: f32, now: Ts) -> Panel {
    let since = u.since.map(|s| format!(" for {}", fmt_dur(((now - s).max(0) / 1000) as u64))).unwrap_or_default();
    let mut head = format!("{} {}{since}", u.name, if u.sub_state.is_empty() || u.sub_state == u.state { u.state.clone() } else { format!("{} ({})", u.state, u.sub_state) });
    if !u.result.is_empty() && u.result != "success" {
        head.push_str(&format!(" · result {}", u.result));
    }
    if let Some(c) = u.exit_code.filter(|c| *c != 0) {
        head.push_str(&format!(" · exit {c}"));
    }
    if u.flapping {
        head.push_str(&format!(" · FLAPPING ({} restarts recently)", u.recent_restarts));
    }
    let severity = match unit_rank(u) {
        0 => Severity::Crit,
        1 | 2 => Severity::Warn,
        _ if unit_is_problem(u, warn) => Severity::Warn,
        _ => Severity::Info,
    };

    let mut what = vec![format!("kind {}", unit_kind_label(u))];
    if !u.description.is_empty() {
        what.push(u.description.clone());
    }
    if let Some(c) = &u.container {
        let mut s = format!("container {} ({})", if c.name.is_empty() { &c.id } else { &c.name }, c.id);
        if !c.image.is_empty() {
            s.push_str(&format!(" image {}", c.image));
        }
        what.push(s);
        if let Some(p) = &c.pod {
            what.push(format!("pod {}/{}", c.namespace.as_deref().unwrap_or("-"), p));
        }
        if let Some(h) = &c.health {
            what.push(format!("health {h}"));
        }
    }
    if !u.cgroup.is_empty() {
        what.push(format!("cgroup {}", u.cgroup));
    }
    if let Some(p) = u.main_pid {
        let name = snap.and_then(|s| s.proc(p)).map(|p| format!(" ({})", p.name)).unwrap_or_default();
        what.push(format!("main pid {p}{name}"));
    }
    what.push(format!("restarts {} total, {} recently", u.restarts, u.recent_restarts));

    let mut res = vec![format!("cpu {:.1}%{}", u.cpu, u.cpu_quota.map(|q| format!(" of a {q:.2}-core quota")).unwrap_or_default())];
    let mut mem = format!("memory {}", fmt_bytes(u.mem));
    if let (Some(l), Some(r)) = (u.mem_limit, mem_limit_ratio(u)) {
        mem.push_str(&format!(" of {} limit ({:.0}%)", fmt_bytes(l), r * 100.0));
        if r >= warn as f64 {
            mem.push_str(" — near its limit");
        }
    }
    if let Some(p) = u.mem_peak {
        mem.push_str(&format!(", peak {}", fmt_bytes(p)));
    }
    res.push(mem);
    if u.io_read_bps + u.io_write_bps > 0 {
        res.push(format!("disk read {}/s write {}/s", fmt_rate(u.io_read_bps), fmt_rate(u.io_write_bps)));
    }
    if u.cpu_throttled_pct > 0.0 {
        res.push(format!("throttled {:.0}% of the last interval by its cpu limit", u.cpu_throttled_pct));
    }
    if let Some(p) = &u.psi {
        res.push(format!("pressure (avg10) cpu {:.0}% mem {:.0}%/{:.0}% io {:.0}%/{:.0}% (some/full)", p.cpu_some, p.mem_some, p.mem_full, p.io_some, p.io_full));
    }
    if u.oom_kills > 0 {
        res.push(format!("{} OOM kill(s) inside this unit", u.oom_kills));
    }
    res.push(format!("{} process(es)", u.pids));

    let mut sections = vec![("What it is".to_string(), what), ("Resources".to_string(), res)];
    if let Some(s) = snap {
        let procs = unit_procs(u, s);
        if !procs.is_empty() {
            let mut v: Vec<String> = procs
                .iter()
                .take(PANEL_ITEMS)
                .map(|p| format!("{} {} cpu {:.1}% mem {}{}", p.pid, p.name, p.cpu, fmt_bytes(p.mem), if p.status == "D" { " (D: waiting on I/O)" } else { "" }))
                .collect();
            if procs.len() > PANEL_ITEMS {
                v.push(format!("… {} more", procs.len() - PANEL_ITEMS));
            }
            sections.push(("Processes".to_string(), v));
        }
    }
    let mut evs: Vec<&Event> = events.iter().filter(|e| event_is_about(e, u)).collect();
    evs.sort_by_key(|e| std::cmp::Reverse(e.ts));
    if !evs.is_empty() {
        sections.push(("Recent events".to_string(), evs.iter().take(PANEL_ITEMS).map(|e| event_line(e)).collect()));
    }
    sections.push(("Look closer (read-only)".to_string(), unit_hints(u)));
    if !u.notes.is_empty() {
        sections.push(("Notes".to_string(), u.notes.clone()));
    }
    Panel { title: format!("Unit · {}", u.name), headline: head, severity, sections, pid: u.main_pid, pending: None, scroll: 0 }
}

// ------------------------------------------------------------------------------- events

pub struct EventsView {
    pub window: usize,
    /// Events from the recorder for the current window (None = no recorder answer yet / none).
    pub recorded: Option<Vec<Event>>,
    /// Recorder ∪ live ring for the window, oldest first.
    pub merged: Vec<Event>,
    /// Indices into `merged`, newest first, filtered.
    pub rows: Vec<usize>,
    pub min_sev: Severity,
    pub filter: String,
    pub(crate) filter_lower: String,
    pub(crate) dirty: bool,
    pub sel: usize,
    pub offset: usize,
    sel_key: Option<(Ts, EventKind, String)>,
    pub(crate) last_req: Ts,
    /// `from` of the newest recorder request; older answers are dropped.
    pub(crate) req_from: Ts,
}

impl Default for EventsView {
    fn default() -> Self {
        EventsView {
            window: 1,
            recorded: None,
            merged: Vec::new(),
            rows: Vec::new(),
            min_sev: Severity::Info,
            filter: String::new(),
            filter_lower: String::new(),
            dirty: true,
            sel: 0,
            offset: 0,
            sel_key: None,
            last_req: i64::MIN / 2,
            req_from: 0,
        }
    }
}

fn event_key(e: &Event) -> (Ts, EventKind, String) {
    (e.ts, e.kind, e.subject.clone())
}

fn event_matches(e: &Event, f: &str) -> bool {
    f.is_empty()
        || contains_ci(e.kind.as_str(), f)
        || contains_ci(&e.subject, f)
        || contains_ci(&e.detail, f)
        || contains_ci(&e.source, f)
        || e.unit.as_deref().is_some_and(|u| contains_ci(u, f))
        || contains_ci(e.severity.as_str(), f)
}

/// Recorder events plus live ones it may not have yet, de-duplicated on (ts, kind, subject),
/// oldest first.
pub fn merge_events(recorded: &[Event], ring: &VecDeque<Event>, from: Ts) -> Vec<Event> {
    let mut seen: HashSet<(Ts, EventKind, String)> = HashSet::with_capacity(recorded.len() + ring.len());
    let mut out: Vec<Event> = Vec::with_capacity(recorded.len() + ring.len());
    for e in recorded.iter().chain(ring.iter().filter(|e| e.ts >= from)) {
        if seen.insert(event_key(e)) {
            out.push(e.clone());
        }
    }
    out.sort_by_key(|e| e.ts);
    out
}

impl EventsView {
    pub fn window_ms(&self) -> i64 {
        EVENT_WINDOWS[self.window % EVENT_WINDOWS.len()]
    }

    pub fn ensure_rows(&mut self, ring: &VecDeque<Event>, now: Ts) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let from = now - self.window_ms();
        self.merged = merge_events(self.recorded.as_deref().unwrap_or(&[]), ring, from);
        let f = self.filter_lower.as_str();
        self.rows = (0..self.merged.len()).rev().filter(|&i| self.merged[i].severity >= self.min_sev && event_matches(&self.merged[i], f)).collect();
        let found = self.sel_key.as_ref().and_then(|k| self.rows.iter().position(|&i| event_key(&self.merged[i]) == *k));
        self.sel = found.unwrap_or_else(|| self.sel.min(self.rows.len().saturating_sub(1)));
    }

    pub fn selected(&self) -> Option<&Event> {
        self.merged.get(*self.rows.get(self.sel)?)
    }

    pub fn move_sel(&mut self, delta: isize) {
        self.sel = crate::tui::app::step(self.sel, delta, self.rows.len());
        self.sel_key = self.selected().map(event_key);
    }

    pub fn set_filter(&mut self, f: String) {
        self.filter_lower = f.to_lowercase();
        self.filter = f;
        self.dirty = true;
    }

    /// Counts by severity in the merged window (for the title).
    pub fn counts(&self) -> (usize, usize, usize) {
        self.merged.iter().fold((0, 0, 0), |(i, w, c), e| match e.severity {
            Severity::Info => (i + 1, w, c),
            Severity::Warn => (i, w + 1, c),
            Severity::Crit => (i, w, c + 1),
        })
    }
}

// ------------------------------------------------------------------------------- fleet

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FleetSort {
    /// Least healthy first.
    Health,
    Cpu,
    Mem,
    Disk,
    Findings,
    Name,
    Latency,
}

impl FleetSort {
    pub const ALL: [FleetSort; 7] = [FleetSort::Health, FleetSort::Cpu, FleetSort::Mem, FleetSort::Disk, FleetSort::Findings, FleetSort::Name, FleetSort::Latency];
    pub fn label(self) -> &'static str {
        match self {
            FleetSort::Health => "health",
            FleetSort::Cpu => "cpu",
            FleetSort::Mem => "mem",
            FleetSort::Disk => "disk",
            FleetSort::Findings => "findings",
            FleetSort::Name => "name",
            FleetSort::Latency => "latency",
        }
    }
    pub fn next(self) -> FleetSort {
        let i = FleetSort::ALL.iter().position(|s| *s == self).unwrap_or(0);
        FleetSort::ALL[(i + 1) % FleetSort::ALL.len()]
    }
}

fn cmp_host(a: &FleetHost, b: &FleetHost, key: FleetSort) -> Ordering {
    let sev = |h: &FleetHost| (h.findings.crit, h.findings.warn, h.findings.info);
    let o = match key {
        // Unreachable hosts are the least healthy of all.
        FleetSort::Health => (a.ok, a.health).cmp(&(b.ok, b.health)),
        FleetSort::Cpu => b.cpu.total_cmp(&a.cpu),
        FleetSort::Mem => b.mem_pct.total_cmp(&a.mem_pct),
        FleetSort::Disk => b.disk_worst_pct.total_cmp(&a.disk_worst_pct),
        FleetSort::Findings => sev(b).cmp(&sev(a)),
        FleetSort::Name => a.name.cmp(&b.name),
        FleetSort::Latency => b.latency_ms.cmp(&a.latency_ms),
    };
    o.then_with(|| a.name.cmp(&b.name))
}

fn host_matches(h: &FleetHost, f: &str) -> bool {
    f.is_empty()
        || contains_ci(&h.name, f)
        || h.groups.iter().any(|g| contains_ci(g, f))
        || h.tags.iter().any(|t| contains_ci(t, f))
        || h.top_finding.as_deref().is_some_and(|t| contains_ci(t, f))
        || h.error.as_deref().is_some_and(|e| contains_ci(e, f))
        || contains_ci(&h.version, f)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrillView {
    Doctor,
    Units,
    Procs,
}

/// One host's remote snapshot, fetched read-only for the drill-in view.
#[derive(Clone, Debug, PartialEq)]
pub struct HostDrill {
    pub name: String,
    pub requested: Ts,
    pub snap: Option<Box<Snapshot>>,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
    pub view: DrillView,
    pub scroll: usize,
}

impl HostDrill {
    pub fn loading(&self) -> bool {
        self.snap.is_none() && self.error.is_none()
    }
    pub fn len(&self) -> usize {
        match (&self.snap, self.view) {
            (_, DrillView::Doctor) => self.findings.len(),
            (Some(s), DrillView::Units) => s.units.len(),
            (Some(s), DrillView::Procs) => s.procs.len(),
            (None, _) => 0,
        }
    }
}

pub struct FleetView {
    /// Inventory size (None = not read yet).
    pub targets: Option<usize>,
    pub inventory_error: Option<String>,
    pub hosts: Vec<FleetHost>,
    index: HashMap<String, usize>,
    pub findings: Vec<FleetFinding>,
    pub polling: bool,
    pub poll_started: Ts,
    /// Hosts answered in the running poll.
    pub answered: usize,
    pub last_done: Ts,
    pub last_elapsed_ms: u64,
    pub refresh_ms: i64,
    pub sort: FleetSort,
    pub natural: bool,
    pub filter: String,
    pub(crate) filter_lower: String,
    /// Restrict the table to the hosts of one fleet finding (⏎ in the findings panel).
    pub only: Option<(String, HashSet<String>)>,
    pub rows: Vec<usize>,
    pub(crate) dirty: bool,
    pub sel: usize,
    pub offset: usize,
    sel_name: Option<String>,
    pub focus_findings: bool,
    pub finding_sel: usize,
    pub drill: Option<HostDrill>,
}

impl Default for FleetView {
    fn default() -> Self {
        FleetView {
            targets: None,
            inventory_error: None,
            hosts: Vec::new(),
            index: HashMap::new(),
            findings: Vec::new(),
            polling: false,
            poll_started: 0,
            answered: 0,
            last_done: i64::MIN / 2,
            last_elapsed_ms: 0,
            refresh_ms: 30_000,
            sort: FleetSort::Health,
            natural: true,
            filter: String::new(),
            filter_lower: String::new(),
            only: None,
            rows: Vec::new(),
            dirty: true,
            sel: 0,
            offset: 0,
            sel_name: None,
            focus_findings: false,
            finding_sel: 0,
            drill: None,
        }
    }
}

impl FleetView {
    /// Remote hosts are configured (or have answered): the new fleet table applies.
    pub fn active(&self) -> bool {
        self.targets.is_some_and(|n| n > 0) || !self.hosts.is_empty()
    }

    /// A streamed row from the running poll (insert or replace by name).
    pub fn upsert(&mut self, h: FleetHost) {
        match self.index.get(&h.name) {
            Some(&i) => self.hosts[i] = h,
            None => {
                self.index.insert(h.name.clone(), self.hosts.len());
                self.hosts.push(h);
            }
        }
        self.answered += 1;
        self.dirty = true;
    }

    /// The finished poll: authoritative rows and grouped findings.
    pub fn done(&mut self, s: FleetSummary, now: Ts) {
        self.hosts = s.hosts;
        self.index = self.hosts.iter().enumerate().map(|(i, h)| (h.name.clone(), i)).collect();
        self.findings = s.findings;
        self.finding_sel = self.finding_sel.min(self.findings.len().saturating_sub(1));
        self.polling = false;
        self.last_done = now;
        self.last_elapsed_ms = s.elapsed_ms;
        self.dirty = true;
    }

    pub fn ensure_rows(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let f = self.filter_lower.as_str();
        let mut rows: Vec<usize> = (0..self.hosts.len())
            .filter(|&i| host_matches(&self.hosts[i], f) && self.only.as_ref().is_none_or(|(_, set)| set.contains(&self.hosts[i].name)))
            .collect();
        rows.sort_by(|&a, &b| {
            let o = cmp_host(&self.hosts[a], &self.hosts[b], self.sort);
            if self.natural { o } else { o.reverse() }
        });
        self.rows = rows;
        let found = self.sel_name.as_ref().and_then(|n| self.rows.iter().position(|&i| self.hosts[i].name == *n));
        self.sel = found.unwrap_or_else(|| self.sel.min(self.rows.len().saturating_sub(1)));
    }

    pub fn selected(&self) -> Option<&FleetHost> {
        self.hosts.get(*self.rows.get(self.sel)?)
    }

    pub fn move_sel(&mut self, delta: isize) {
        self.sel = crate::tui::app::step(self.sel, delta, self.rows.len());
        self.sel_name = self.selected().map(|h| h.name.clone());
    }

    pub fn set_sort(&mut self, key: FleetSort) {
        if self.sort == key {
            self.natural = !self.natural;
        } else {
            self.sort = key;
            self.natural = true;
        }
        self.dirty = true;
    }

    pub fn set_filter(&mut self, f: String) {
        self.filter_lower = f.to_lowercase();
        self.filter = f;
        self.dirty = true;
    }

    /// (ok, unreachable, crit hosts, warn hosts) over the current rows set.
    pub fn tally(&self) -> (usize, usize, usize, usize) {
        self.hosts.iter().fold((0, 0, 0, 0), |(ok, bad, c, w), h| {
            if !h.ok {
                (ok, bad + 1, c, w)
            } else if h.findings.crit > 0 {
                (ok + 1, bad, c + 1, w)
            } else if h.findings.warn > 0 {
                (ok + 1, bad, c, w + 1)
            } else {
                (ok + 1, bad, c, w)
            }
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::server::{ContainerMeta, DiskStat, Kernel, Pressure, Profile, SevCounts, ServerCfg};
    use crate::tui::app::{App, Command, Modal, Tab};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// `n` synthetic units of every kind: a few failed / flapping / throttled / near their
    /// memory limit, a third inactive. Names are neutral placeholders.
    pub fn units(n: usize) -> Vec<Unit> {
        (0..n)
            .map(|i| {
                let kind = match i % 10 {
                    0..=5 => UnitKind::Systemd,
                    6 | 7 => UnitKind::Container,
                    8 => UnitKind::Pod,
                    _ => UnitKind::Cgroup,
                };
                let name = match kind {
                    UnitKind::Systemd => format!("svc-{i:03}.service"),
                    UnitKind::Container => format!("ctr-{i:03}"),
                    UnitKind::Pod => format!("default/pod-{i:03}"),
                    UnitKind::Cgroup => format!("/workload/job-{i:03}"),
                };
                let state = if i % 3 == 2 { "inactive" } else { "active" };
                Unit {
                    name: name.clone(),
                    kind,
                    state: state.into(),
                    sub_state: if state == "active" { "running".into() } else { "dead".into() },
                    description: format!("placeholder service {i}"),
                    cgroup: format!("/system.slice/{}", name.trim_start_matches('/').replace('/', "-")),
                    main_pid: Some(10_000 + i as u32),
                    pids: 1 + (i % 7) as u32,
                    cpu: (i % 37) as f32 * 1.5,
                    mem: ((i % 50) as u64 + 1) << 22,
                    restarts: (i % 4) as u32,
                    container: (kind == UnitKind::Container).then(|| ContainerMeta {
                        id: format!("{:012x}", 0xabc000 + i),
                        name: name.clone(),
                        image: "registry.example.com/app:1.0".into(),
                        runtime: if i % 20 == 6 { "podman".into() } else { "docker".into() },
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            })
            .collect()
    }

    pub fn server_snap(ts: Ts, n_units: usize) -> Snapshot {
        let mut s = crate::tui::app::tests::linux_snap(ts);
        s.system.hostname = "web-01".into();
        s.units = units(n_units);
        // The cases an operator must see at once.
        let u = &mut s.units[0];
        u.name = "db.service".into();
        u.state = "failed".into();
        u.sub_state = "failed".into();
        u.result = "oom-kill".into();
        u.exit_code = Some(137);
        u.oom_kills = 1;
        u.main_pid = None;
        u.since = Some(ts - 12 * 60_000);
        let u = &mut s.units[1];
        u.name = "worker.service".into();
        u.flapping = true;
        u.recent_restarts = 5;
        u.restarts = 40;
        u.state = "activating".into();
        u.sub_state = "auto-restart".into();
        u.cgroup = "/user.slice/user-1000.slice/session-3.scope".into(); // the test procs live there
        u.main_pid = Some(200);
        let u = &mut s.units[2];
        u.name = "batch.service".into();
        u.state = "active".into();
        u.cpu = 95.0;
        u.cpu_throttled_pct = 42.0;
        u.cpu_quota = Some(0.5);
        u.mem_limit = Some(1 << 30);
        u.mem = 950 << 20;
        u.psi = Some(Pressure { cpu_some: 30.0, ..Default::default() });
        s.kernel = Some(Kernel {
            steal_pct: 14.0,
            iowait_pct: 22.0,
            softirq_pct: 1.5,
            procs_running: 3,
            procs_blocked: 9,
            pressure: Some(Pressure { cpu_some: 12.5, mem_some: 0.4, mem_full: 0.1, io_some: 31.0, io_full: 8.0, ..Default::default() }),
            mem_available: 20 << 30,
            fd_used: Some(10_000),
            fd_max: Some(100_000),
            conntrack_used: Some(230_000),
            conntrack_max: Some(262_144),
            ephemeral_used: Some(1000),
            ephemeral_range: Some((32768, 60999)),
            disks: vec![
                DiskStat { name: "sda".into(), r_await_ms: 3.0, w_await_ms: 4.0, ..Default::default() },
                DiskStat { name: "nvme0n1".into(), r_await_ms: 2.0, w_await_ms: 230.0, ..Default::default() },
            ],
            ..Default::default()
        });
        s.events = vec![
            Event { ts: ts - 60_000, kind: EventKind::OomKill, severity: Severity::Crit, subject: "unit:db.service".into(), unit: Some("db.service".into()), pid: Some(4242), detail: "db (4242) killed by the OOM killer, anon-rss 5.9G".into(), source: "kmsg".into(), ..Default::default() },
            Event { ts: ts - 30_000, kind: EventKind::UnitFlapping, severity: Severity::Warn, subject: "unit:worker.service".into(), unit: Some("worker.service".into()), detail: "worker.service restarted 5 times in 10m".into(), source: "systemd".into(), ..Default::default() },
            Event { ts: ts - 10_000, kind: EventKind::DiskLatencySpike, severity: Severity::Warn, subject: "disk:nvme0n1".into(), detail: "nvme0n1 write await 230ms".into(), source: "procfs".into(), ..Default::default() },
        ];
        s
    }

    pub fn server_app() -> App {
        let mut a = App::new(1000);
        a.set_profile(Profile::Server, ServerCfg::default(), 30);
        for i in 0..5 {
            let mut s = server_snap(1_000_000_000 + i * 1000, 300);
            if i > 0 {
                s.events.clear();
            }
            a.now = s.ts;
            a.on_snapshot(s);
        }
        a.ensure_rows();
        a.ensure_server_rows();
        a
    }

    /// `n` fleet rows: every 50th unreachable, every 7th with a critical finding.
    pub fn fleet_hosts(n: usize) -> Vec<FleetHost> {
        (0..n)
            .map(|i| {
                let ok = i % 50 != 49;
                FleetHost {
                    name: format!("web-{i:04}"),
                    groups: vec![if i % 2 == 0 { "web".into() } else { "db".into() }],
                    tags: vec!["placeholder".into()],
                    ok,
                    error: (!ok).then(|| "ssh: connect timed out".into()),
                    latency_ms: 20 + (i % 90) as u64,
                    health: if ok { (100 - (i * 13) % 100) as u8 } else { 0 },
                    cpu: (i % 100) as f32,
                    mem_pct: ((i * 7) % 100) as f32,
                    load1: (i % 16) as f64,
                    cores: 8,
                    disk_worst_pct: ((i * 3) % 100) as f32,
                    disk_worst_mount: "/var".into(),
                    findings: SevCounts { info: 1, warn: (i % 3) as u32, crit: (i % 7 == 0) as u32 },
                    top_finding: (i % 7 == 0).then(|| "disk /var almost full".into()),
                    units_failed: (i % 11 == 0) as u32,
                    version: "0.0.0".into(),
                    ..Default::default()
                }
            })
            .collect()
    }

    pub fn fleet_app(n: usize) -> App {
        let mut a = server_app();
        a.set_fleet_inventory(Ok(n));
        let hosts = fleet_hosts(n);
        let crit: Vec<String> = hosts.iter().filter(|h| h.findings.crit > 0).map(|h| h.name.clone()).collect();
        let summary = FleetSummary {
            ts: a.now,
            elapsed_ms: 8200,
            total: n,
            ok: hosts.iter().filter(|h| h.ok).count(),
            unreachable: hosts.iter().filter(|h| !h.ok).count(),
            hosts,
            findings: vec![
                FleetFinding { title: "disk /var almost full".into(), severity: Severity::Crit, count: crit.len(), hosts: crit, ..Default::default() },
                FleetFinding { title: "a unit is flapping".into(), severity: Severity::Warn, count: 2, hosts: vec!["web-0001".into(), "web-0002".into()], ..Default::default() },
            ],
        };
        a.fleet_done(summary);
        a
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn code(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }
    fn sel_unit(a: &App) -> String {
        a.svc.selected(a.units()).map(|u| u.name.clone()).unwrap_or_default()
    }

    #[test]
    fn server_profile_tabs_and_number_keys() {
        let mut a = server_app();
        assert_eq!(a.tab, Tab::Services, "services first");
        assert_eq!(a.tab_order()[0], Tab::Services);
        assert_eq!(a.tab_number(Tab::Events), 3);
        a.on_key(key('3'));
        assert_eq!(a.tab, Tab::Events);
        a.on_key(key('2'));
        assert_eq!(a.tab, Tab::Procs);
        a.on_key(key('1'));
        assert_eq!(a.tab, Tab::Services);
        // desktop keeps today's numbering and has no Services / Events
        let mut d = App::new(1000);
        assert_eq!(d.tab, Tab::Procs);
        assert_eq!(d.tab_number(Tab::Doctor), 5);
        assert_eq!(d.tab_number(Tab::Services), 0);
        d.on_key(key('5'));
        assert_eq!(d.tab, Tab::Doctor);
        d.switch_tab(Tab::Services);
        assert_eq!(d.tab, Tab::Doctor, "not part of the desktop profile");
        d.on_key(key('8'));
        assert_eq!(d.tab, Tab::Doctor);
    }

    #[test]
    fn services_default_order_is_problems_first_and_inactive_hidden() {
        let a = server_app();
        assert_eq!(sel_unit(&a), "db.service", "failed first");
        let units = a.units();
        let order: Vec<&str> = a.svc.rows.iter().take(3).map(|&i| units[i].name.as_str()).collect();
        assert_eq!(order[..2], ["db.service", "worker.service"]);
        assert!(a.svc.hidden > 50, "inactive units hidden by default: {}", a.svc.hidden);
        assert!(a.svc.rows.iter().all(|&i| units[i].state != "inactive" || unit_is_problem(&units[i], 0.85)));
    }

    #[test]
    fn services_keys_sort_filter_group_and_explain() {
        let mut a = server_app();
        let n_default = a.svc.rows.len();
        a.on_key(key('i'));
        a.ensure_server_rows();
        assert!(a.svc.rows.len() > n_default && a.svc.hidden == 0);
        a.on_key(key('f'));
        a.ensure_server_rows();
        let units = a.units();
        assert!(a.svc.rows.iter().all(|&i| unit_is_problem(&units[i], 0.85)));
        assert!(a.svc.rows.len() >= 3, "{}", a.svc.rows.len());
        a.on_key(key('f'));
        a.on_key(key('i'));
        // cpu sort: hottest first; again = reversed
        a.on_key(key('c'));
        a.ensure_server_rows();
        let units = a.units();
        let cpus: Vec<f32> = a.svc.rows.iter().map(|&i| units[i].cpu).collect();
        assert!(cpus.windows(2).all(|w| w[0] >= w[1]));
        a.on_key(key('c'));
        a.ensure_server_rows();
        let units = a.units();
        assert!(units[a.svc.rows[0]].cpu <= units[*a.svc.rows.last().unwrap()].cpu);
        // group by kind keeps kinds contiguous
        a.on_key(key('t'));
        a.ensure_server_rows();
        let units = a.units();
        let kinds: Vec<UnitKind> = a.svc.rows.iter().map(|&i| units[i].kind).collect();
        assert!(kinds.windows(2).all(|w| w[0] <= w[1]), "grouped");
        // filter by runtime / image
        a.on_key(key('/'));
        for c in "podman".chars() {
            a.on_key(key(c));
        }
        a.on_key(code(KeyCode::Enter));
        a.ensure_server_rows();
        let units = a.units();
        assert!(!a.svc.rows.is_empty() && a.svc.rows.iter().all(|&i| units[i].container.as_ref().unwrap().runtime == "podman"));
        assert_eq!(a.active_filter(), "podman");
        a.on_key(code(KeyCode::Esc));
        assert!(a.svc.filter.is_empty());
        // ⏎ explains the selected unit; w explains its main pid
        a.on_key(key('s'));
        a.ensure_server_rows();
        a.on_key(code(KeyCode::Home));
        a.on_key(code(KeyCode::Down)); // worker.service (flapping)
        assert_eq!(sel_unit(&a), "worker.service");
        assert!(a.on_key(code(KeyCode::Enter)).is_empty());
        let p = a.panel.as_ref().expect("panel");
        assert!(p.headline.contains("FLAPPING") && p.severity == Severity::Warn, "{p:?}");
        let flat: Vec<&String> = p.sections.iter().flat_map(|(_, v)| v).collect();
        assert!(flat.iter().any(|l| l.contains("journalctl -u worker.service")), "{flat:?}");
        assert!(flat.iter().any(|l| l.contains("restarted 5 times")), "recent events: {flat:?}");
        assert!(flat.iter().any(|l| l.contains("node")), "processes in its cgroup: {flat:?}");
        assert_eq!(a.on_key(key('w')), vec![Command::Explain(200)]);
        assert!(a.panel.is_none());
        a.why = None;
        // the panel never offers an action: space / k do nothing in Services
        assert!(a.on_key(key(' ')).is_empty() && a.on_key(key('k')).is_empty() && a.modal == Modal::None);
    }

    #[test]
    fn failed_unit_panel_explains_oom() {
        let a = server_app();
        let u = a.units().iter().find(|u| u.name == "db.service").unwrap();
        let p = unit_panel(u, a.view(), &a.event_ring.iter().cloned().collect::<Vec<_>>(), 0.85, a.now);
        assert_eq!(p.severity, Severity::Crit);
        assert!(p.headline.contains("result oom-kill") && p.headline.contains("exit 137") && p.headline.contains("for 12m"), "{}", p.headline);
        let flat: Vec<&String> = p.sections.iter().flat_map(|(_, v)| v).collect();
        assert!(flat.iter().any(|l| l.contains("OOM kill")), "{flat:?}");
        assert!(flat.iter().any(|l| l.contains("killed by the OOM killer")), "{flat:?}");
        // container hints follow the detected runtime
        let c = a.units().iter().find(|u| u.container.as_ref().is_some_and(|c| c.runtime == "podman")).unwrap();
        assert!(unit_hints(c)[0].starts_with("podman logs"), "{:?}", unit_hints(c));
        let pod = a.units().iter().find(|u| u.kind == UnitKind::Pod).unwrap();
        assert!(unit_hints(pod)[0].starts_with("kubectl -n default describe pod pod-"));
    }

    #[test]
    fn events_view_merges_filters_and_explains() {
        let mut a = server_app();
        let cmds = a.switch_tab(Tab::Events);
        assert!(matches!(cmds.as_slice(), [Command::LoadEvents { .. }]), "{cmds:?}");
        a.ensure_server_rows();
        assert_eq!(a.ev.rows.len(), 3, "live ring without a recorder");
        assert_eq!(a.ev.selected().unwrap().kind, EventKind::DiskLatencySpike, "newest first");
        // recorder answer for the current request merges and de-duplicates
        let Command::LoadEvents { from, .. } = cmds[0] else { unreachable!() };
        let mut rec: Vec<Event> = a.event_ring.iter().cloned().collect();
        rec.push(Event { ts: a.now - 3_000_000, kind: EventKind::UnitFailed, severity: Severity::Crit, subject: "unit:old.service".into(), detail: "old.service failed".into(), ..Default::default() });
        a.set_events(from, Some(rec));
        a.ensure_server_rows();
        assert_eq!(a.ev.merged.len(), 4);
        // a stale answer (other window) is ignored
        a.set_events(from - 1, Some(vec![]));
        a.ensure_server_rows();
        assert_eq!(a.ev.merged.len(), 4);
        // severity filter
        a.on_key(key('f'));
        a.ensure_server_rows();
        assert_eq!(a.ev.rows.len(), 4);
        a.on_key(key('f'));
        a.ensure_server_rows();
        assert_eq!(a.ev.rows.len(), 2, "crit only");
        a.on_key(key('f'));
        // text filter
        a.on_key(key('/'));
        for c in "nvme".chars() {
            a.on_key(key(c));
        }
        a.on_key(code(KeyCode::Enter));
        a.ensure_server_rows();
        assert_eq!(a.ev.rows.len(), 1);
        a.on_key(code(KeyCode::Esc));
        a.ensure_server_rows();
        // ⏎ asks for the incident around the event; the answer fills the waiting panel
        a.on_key(code(KeyCode::End));
        let cmds = a.on_key(code(KeyCode::Enter));
        let Some(Command::ExplainEvent { id, event }) = cmds.first().cloned() else { panic!("{cmds:?}") };
        assert_eq!(event.kind, EventKind::UnitFailed);
        assert_eq!(a.panel.as_ref().unwrap().pending, Some(id));
        a.set_incident(id + 1, Ok(Incident::default()));
        assert_eq!(a.panel.as_ref().unwrap().pending, Some(id), "answer for another request ignored");
        let inc = Incident {
            host: "web-01".into(),
            at: event.ts,
            severity: Severity::Crit,
            headline: "db.service OOM-killed — backup.service grew to 6 GiB".into(),
            chain: vec!["db.service failed".into(), "the kernel OOM-killed db (4242)".into(), "backup.service grew 4 GiB in 5 min".into()],
            culprits: vec![crate::server::Culprit { kind: "unit".into(), name: "backup.service".into(), pid: Some(777), why: "6 GiB at 03:11".into(), ..Default::default() }],
            suggestions: vec!["journalctl -u backup.service --since 03:00".into()],
            gaps: vec!["recorder not running before 03:05".into()],
            ..Default::default()
        };
        a.set_incident(id, Ok(inc));
        let p = a.panel.clone().unwrap();
        assert!(p.pending.is_none() && p.headline.contains("OOM-killed") && p.pid == Some(777));
        assert!(p.sections.iter().any(|(t, v)| t == "What happened" && v[1].starts_with("↳ ")));
        assert!(p.sections.iter().any(|(t, _)| t == "Missing data"));
        // scroll, then close
        a.on_key(code(KeyCode::PageDown));
        assert_eq!(a.panel.as_ref().unwrap().scroll, 10);
        a.on_key(code(KeyCode::Esc));
        assert!(a.panel.is_none());
        // window keys request again
        let cmds = a.on_key(key('+'));
        assert!(matches!(cmds.as_slice(), [Command::LoadEvents { .. }]));
        assert_eq!(a.ev.window, 2);
        // W: what happened recently
        let cmds = a.on_key(key('W'));
        assert!(matches!(cmds.as_slice(), [Command::WhatHappened { at: None, .. }]), "{cmds:?}");
        // an engine error degrades to a readable panel
        let Command::WhatHappened { id, .. } = cmds[0] else { unreachable!() };
        a.set_incident(id, Err("incident engine failed".into()));
        assert!(a.panel.as_ref().unwrap().headline.contains("could not explain"));
    }

    #[test]
    fn ticks_request_only_what_is_visible() {
        let mut a = server_app();
        let now = a.now + 60_000;
        let cmds = a.tick(now);
        assert!(cmds.contains(&Command::RefreshCounts));
        assert!(!cmds.iter().any(|c| matches!(c, Command::LoadEvents { .. } | Command::FleetPoll)), "{cmds:?}");
        a.set_counts(Some(3));
        a.switch_tab(Tab::Events);
        let cmds = a.tick(now + 6000);
        assert!(cmds.iter().any(|c| matches!(c, Command::LoadEvents { .. })), "{cmds:?}");
        // desktop: none of this
        let mut d = App::new(1000);
        assert!(d.tick(now).is_empty());
    }

    #[test]
    fn fleet_polls_on_demand_never_overlapping() {
        let mut a = server_app();
        assert!(!a.fleet_visible());
        a.set_fleet_inventory(Ok(2000));
        assert!(a.fleet_visible());
        let cmds = a.switch_tab(Tab::Fleet);
        assert_eq!(cmds, vec![Command::FleetPoll]);
        assert!(a.fleet.polling);
        assert!(a.tick(a.now + 120_000).iter().all(|c| *c != Command::FleetPoll), "no overlap while polling");
        assert!(a.on_key(key('r')).is_empty(), "r while polling does nothing");
        for h in fleet_hosts(5) {
            a.fleet_host(h);
        }
        assert_eq!(a.fleet.answered, 5);
        a.ensure_server_rows();
        assert_eq!(a.fleet.rows.len(), 5, "rows stream in");
        a.fleet_done(FleetSummary { hosts: fleet_hosts(2000), ..Default::default() });
        assert!(!a.fleet.polling);
        assert!(a.tick(a.now + 1000).iter().all(|c| *c != Command::FleetPoll), "not due yet");
        assert!(a.tick(a.now + 31_000).contains(&Command::FleetPoll), "due after tui_refresh_s");
        // leaving the tab stops polling
        a.fleet_done(FleetSummary { hosts: fleet_hosts(2000), ..Default::default() });
        a.switch_tab(Tab::Services);
        assert!(a.tick(a.now + 3_600_000).iter().all(|c| *c != Command::FleetPoll));
    }

    #[test]
    fn fleet_keys_sort_filter_findings_and_drill() {
        let mut a = fleet_app(2000);
        a.switch_tab(Tab::Fleet);
        a.fleet.polling = false;
        a.ensure_server_rows();
        assert_eq!(a.fleet.rows.len(), 2000);
        let first = a.fleet.selected().unwrap().clone();
        assert!(!first.ok, "unreachable hosts are least healthy: {first:?}");
        a.on_key(key('c'));
        a.ensure_server_rows();
        let cpus: Vec<f32> = a.fleet.rows.iter().map(|&i| a.fleet.hosts[i].cpu).collect();
        assert!(cpus.windows(2).all(|w| w[0] >= w[1]));
        a.on_key(key('n'));
        a.ensure_server_rows();
        assert_eq!(a.fleet.selected().unwrap().name, "web-0000");
        // filter by name or group
        a.on_key(key('/'));
        for c in "web-19".chars() {
            a.on_key(key(c));
        }
        a.on_key(code(KeyCode::Enter));
        a.ensure_server_rows();
        assert_eq!(a.fleet.rows.len(), 100);
        a.on_key(code(KeyCode::Esc));
        a.ensure_server_rows();
        assert_eq!(a.fleet.rows.len(), 2000);
        // findings panel: ⏎ narrows the table to the affected hosts
        a.on_key(code(KeyCode::Right));
        assert!(a.fleet.focus_findings);
        a.on_key(code(KeyCode::Enter));
        a.ensure_server_rows();
        let expect = fleet_hosts(2000).iter().filter(|h| h.findings.crit > 0).count();
        assert_eq!(a.fleet.rows.len(), expect);
        a.on_key(code(KeyCode::Esc));
        a.ensure_server_rows();
        assert_eq!(a.fleet.rows.len(), 2000);
        // drill-in: read-only fetch, then switch sub-views; Esc returns
        a.on_key(code(KeyCode::Down));
        let name = a.fleet.selected().unwrap().name.clone();
        assert_eq!(a.on_key(code(KeyCode::Enter)), vec![Command::FleetDrill(name.clone())]);
        assert!(a.fleet.drill.as_ref().unwrap().loading());
        a.set_fleet_drill("other", Err("x".into()));
        assert!(a.fleet.drill.as_ref().unwrap().loading(), "answer for another host ignored");
        a.set_fleet_drill(&name, Ok((server_snap(a.now, 50), vec![])));
        assert_eq!(a.fleet.drill.as_ref().unwrap().view, DrillView::Doctor);
        a.on_key(key('u'));
        assert_eq!(a.fleet.drill.as_ref().unwrap().view, DrillView::Units);
        a.on_key(code(KeyCode::Right));
        assert_eq!(a.fleet.drill.as_ref().unwrap().view, DrillView::Procs);
        // nothing in the drill acts on the host
        for c in [' ', 'k', 'K', 'z'] {
            assert!(a.on_key(key(c)).is_empty());
        }
        assert_eq!(a.on_key(key('r')), vec![Command::FleetDrill(name)]);
        a.on_key(code(KeyCode::Esc));
        assert!(a.fleet.drill.is_none() && a.tab == Tab::Fleet);
    }

    #[test]
    fn ring_keeps_units_bounded() {
        let mut a = server_app();
        let mut s = server_snap(a.now + 1000, 2000);
        s.units[1999].state = "failed".into();
        a.on_snapshot(s);
        let kept = &a.ring.back().unwrap().units;
        assert!(kept.len() <= 2 * 40 + 10, "{}", kept.len());
        assert!(kept.iter().any(|u| u.state == "failed" && u.name.contains("1999")), "problem units always kept");
        assert!(a.ring.back().unwrap().kernel.is_some());
        assert!(a.event_ring.len() <= EVENT_RING);
    }
}
