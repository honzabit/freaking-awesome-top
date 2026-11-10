//! Services as the primary unit: systemd units, containers (any runtime), Kubernetes pods and
//! plain cgroups, with restart/flap tracking. OWNER: services agent.
//!
//! Sources, each optional (degrade to the next, never fail):
//! - cgroup v2 files under the unified hierarchy (cpu.stat usage/throttling, memory.current/
//!   peak/events, io.stat, pids.current, {cpu,memory,io}.pressure): cheap, read every sample for
//!   units that have a cgroup. Limits (memory.max, cpu.max, pids.max) and the directory walk
//!   that discovers containers and pods are refreshed every `ServerCfg::unit_refresh_s`.
//!   cgroup v1 (and hybrid) hosts: memory, cpuacct, cpu and pids controllers, best effort; no
//!   per-unit PSI or io, with a note.
//! - systemd (only when /run/systemd/system exists and `systemctl` is on PATH). Every
//!   `unit_refresh_s`: one `systemctl list-units --all` (one D-Bus ListUnits call: ~3 ms and
//!   no measurable PID 1 time on a host with a few hundred units), then one batched
//!   `systemctl show -p ...` only for units whose state, sub-state or main pid changed, plus
//!   all loaded services/scopes every `unit_full_refresh_s`. `systemctl show` costs PID 1 about
//!   0.25 ms of CPU per unit, so reading every unit every 10 s would alone cost ~0.3% of a core
//!   on a host with 100 units; the delta keeps it proportional to change. D-Bus directly would
//!   save the process spawn but needs a hand-written wire protocol (no new crates): not worth
//!   it at this cadence.
//! - container names/state via [`runtime::Resolver`] (runtime state files, never a CLI call on
//!   the hot path) and `crate::fleet::cached_containers()` (never blocks).
//! - no init integration at all (minimal containers, other inits): units are the cgroups that
//!   hold processes, kind Cgroup.
//!
//! Bounded by `ServerCfg::max_units` (inactive dropped first). Works unprivileged; fields that
//! need root stay empty with a note.
pub mod runtime;

use super::{Event, EventKind, Pressure, ServerCfg, Severity, Unit, UnitKind, unit_of_cgroup};
use crate::model::{Proc, Ts};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Runs `systemctl <args>` and returns stdout (None on failure/timeout). Swappable for tests.
type Runner = Box<dyn FnMut(&[&str]) -> Option<String> + Send>;

/// Where unit cgroups live.
#[derive(Debug, Clone, PartialEq)]
enum CgMode {
    /// Unified hierarchy at this path.
    V2(PathBuf),
    /// Legacy/hybrid: controllers under `root` ("memory", "cpu", "cpuacct", "pids"), unit tree
    /// (for discovery and the procs join) under `tree`.
    V1 {
        root: PathBuf,
        tree: PathBuf,
    },
    None,
}

impl CgMode {
    fn detect() -> CgMode {
        let root = PathBuf::from("/sys/fs/cgroup");
        if root.join("cgroup.controllers").exists() {
            return CgMode::V2(root);
        }
        for t in ["unified", "systemd"] {
            if root.join(t).join("cgroup.procs").exists() {
                return CgMode::V1 { tree: root.join(t), root };
            }
        }
        CgMode::None
    }

    fn tree(&self) -> Option<&Path> {
        match self {
            CgMode::V2(p) => Some(p),
            CgMode::V1 { tree, .. } => Some(tree),
            CgMode::None => None,
        }
    }
}

/// A discovered unit cgroup.
#[derive(Debug, Clone)]
struct Dir {
    rel: String,
    kind: UnitKind,
    key: String,
    /// Full hex id for containers (as in the path), for the runtime resolver.
    full_id: String,
    runtime: &'static str,
}

/// One line of `systemctl list-units --plain --no-legend --full`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Listed {
    pub id: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

/// Raw cgroup counters at one instant.
#[derive(Debug, Clone, Default)]
struct Counters {
    usage_usec: Option<u64>,
    periods: u64,
    throttled: u64,
    mem: Option<u64>,
    peak: Option<u64>,
    oom_kills: Option<u64>,
    io: Option<(u64, u64)>,
    pids: Option<u64>,
    psi: Option<Pressure>,
    frozen: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct Limits {
    mem_max: Option<u64>,
    cpu_quota: Option<f32>,
    pids_max: Option<u64>,
}

/// Per-unit memory between samples (keyed "kind:name").
#[derive(Debug, Clone, Default)]
struct Track {
    state: String,
    restarts: u32,
    restart_ts: VecDeque<Ts>,
    flapping: bool,
    oom_kills: u64,
    throttled: bool,
    mem_high: bool,
    pids_high: bool,
    last_burst: Option<Ts>,
    /// Restart events of a unit that is already flapping are coalesced: the time of the last
    /// one emitted and the restarts seen since (emitted at most once per spike_cooldown_s).
    last_restart_ev: Option<Ts>,
    held_restarts: u32,
    /// An OOM kill was already reported for this unit's current run (from its cgroup's
    /// memory.events), so systemd's later Result=oom-kill for the same kill is not a second one.
    /// Cleared when the unit starts again.
    oom_this_run: bool,
    pids: HashSet<u32>,
    first_seen: Ts,
    last_seen: Ts,
    present: bool,
    /// Last unit as built, kept for departed containers.
    last: Option<Unit>,
}

/// Stateful sampler: remembers previous counters (cpu usage, throttled time, io bytes, restarts,
/// states) to produce rates and events.
pub struct Services {
    cfg: ServerCfg,
    /// Events detected but not yet drained.
    pending: Vec<Event>,
    cg: CgMode,
    systemctl: Option<Runner>,
    resolver: runtime::Resolver,
    /// Realtime ms minus monotonic ms (maps systemd monotonic timestamps to epoch ms).
    boot_ms: Ts,
    dirs: Vec<Dir>,
    limits: HashMap<String, Limits>,
    listed: BTreeMap<String, Listed>,
    props: HashMap<String, SystemdProps>,
    last_refresh: Option<i64>,
    last_full: Option<i64>,
    track: HashMap<String, Track>,
    /// Previous raw counters per unit (monotonic ms, counters) for rates.
    prev: HashMap<String, (i64, Counters)>,
    samples: u64,
    notes: Vec<String>,
    walk_truncated: bool,
}

impl Services {
    pub fn new(cfg: &ServerCfg) -> Services {
        let systemd =
            cfg!(target_os = "linux") && Path::new("/run/systemd/system").is_dir() && which("systemctl").is_some();
        let timeout = Duration::from_secs(cfg.unit_refresh_s.max(1));
        let runner: Option<Runner> =
            systemd.then(|| Box::new(move |args: &[&str]| run_systemctl(args, timeout)) as Runner);
        Self::with_sources(cfg, CgMode::detect(), runner, runtime::Resolver::new())
    }

    fn with_sources(cfg: &ServerCfg, cg: CgMode, systemctl: Option<Runner>, resolver: runtime::Resolver) -> Services {
        Services {
            cfg: cfg.clone(),
            pending: Vec::new(),
            cg,
            systemctl,
            resolver,
            boot_ms: crate::model::now_ms() - mono_ms(),
            dirs: Vec::new(),
            limits: HashMap::new(),
            listed: BTreeMap::new(),
            props: HashMap::new(),
            last_refresh: None,
            last_full: None,
            track: HashMap::new(),
            prev: HashMap::new(),
            samples: 0,
            notes: Vec::new(),
            walk_truncated: false,
        }
    }

    /// Why some units or fields may be missing on this host (no systemd, cgroup v1, unit cap...).
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Current units with rates over the interval since the previous call (first call: rates 0).
    /// Joins `procs` by cgroup for pids/main pid fallback. Emits unit_start/stop/failed/restart/
    /// flapping, deploy_burst, throttle, exhaustion (memory.max) and oom_kill (memory.events
    /// delta, per unit) events into the pending queue. On macOS: containers only.
    pub fn sample(&mut self, procs: &[Proc]) -> Vec<Unit> {
        self.sample_at(procs, crate::model::now_ms(), mono_ms())
    }

    /// [`Self::sample`] at explicit wall (event timestamps) and monotonic (rates, cadence) times.
    fn sample_at(&mut self, procs: &[Proc], now: Ts, mono: i64) -> Vec<Unit> {
        let baseline = self.samples == 0;
        self.samples += 1;
        let refresh = self.last_refresh.is_none_or(|t| mono - t >= (self.cfg.unit_refresh_s * 1000) as i64);
        let mut notes = Vec::new();
        if refresh {
            self.last_refresh = Some(mono);
            self.walk();
            self.refresh_systemd(procs, mono);
        }
        match &self.cg {
            CgMode::V2(_) => {}
            CgMode::V1 { .. } => {
                notes.push("cgroup v1: per-unit io and pressure (PSI) unavailable; memory/cpu best effort".to_string())
            }
            CgMode::None if cfg!(target_os = "linux") => {
                notes.push("no cgroup filesystem mounted: unit resources unknown".to_string())
            }
            CgMode::None => {}
        }
        if self.systemctl.is_none() && cfg!(target_os = "linux") {
            notes.push("systemd not detected: units come from cgroups and container runtimes only".into());
        }
        if self.walk_truncated {
            notes.push(format!(
                "cgroup tree larger than {} directories: walk truncated (raise server.max_units)",
                self.max_dirs()
            ));
        }

        // 1. Candidate units: (Unit skeleton, cgroup rel path or "").
        let mut units: Vec<Unit> = Vec::new();
        let mut seen_names: HashSet<(UnitKind, String)> = HashSet::new();
        // systemd
        for l in self.listed.values() {
            if !wanted(l) {
                continue;
            }
            let p = self.props.get(&l.id);
            let cg = p
                .map(|p| p.control_group.clone())
                .filter(|c| !c.is_empty())
                .or_else(|| {
                    self.dirs.iter().find(|d| d.kind == UnitKind::Systemd && d.key == l.id).map(|d| d.rel.clone())
                })
                .unwrap_or_default();
            let state = normalize_state(&l.active);
            let mut u = Unit {
                name: l.id.clone(),
                kind: UnitKind::Systemd,
                sub_state: l.sub.clone(),
                description: l.description.clone(),
                cgroup: cg,
                ..Default::default()
            };
            if let Some(p) = p {
                u.result = p.result.clone();
                u.exit_code = p.exit_status;
                u.restarts = p.n_restarts;
                u.since = p.state_change_ts;
                u.main_pid = p.main_pid.filter(|_| state != "inactive" && state != "failed");
                u.mem_limit = p.memory_max;
                if u.description.is_empty() {
                    u.description = p.description.clone();
                }
            }
            u.state = state;
            seen_names.insert((UnitKind::Systemd, u.name.clone()));
            units.push(u);
        }
        // cgroup-discovered: systemd units unknown to systemctl, containers, pods
        let mut live_ids = HashSet::new();
        for d in self.dirs.clone() {
            match d.kind {
                UnitKind::Systemd => {
                    if seen_names.contains(&(UnitKind::Systemd, d.key.clone())) || self.listed.contains_key(&d.key) {
                        continue;
                    }
                    seen_names.insert((UnitKind::Systemd, d.key.clone()));
                    let mut u = Unit {
                        name: d.key.clone(),
                        kind: UnitKind::Systemd,
                        state: "active".into(),
                        sub_state: "running".into(),
                        cgroup: d.rel.clone(),
                        ..Default::default()
                    };
                    if self.systemctl.is_some() {
                        u.notes.push("not listed by systemd (state from cgroup)".into());
                    }
                    units.push(u);
                }
                UnitKind::Container => {
                    let (meta, st) = self.resolver.resolve(&d.full_id, d.runtime, refresh);
                    live_ids.insert(meta.id.clone());
                    let mut u = Unit {
                        name: meta.name.clone(),
                        kind: UnitKind::Container,
                        state: st
                            .state
                            .clone()
                            .filter(|s| s != "inactive" && s != "failed")
                            .unwrap_or_else(|| "active".into()),
                        sub_state: if st.sub_state.is_empty() { "running".into() } else { st.sub_state.clone() },
                        description: meta.image.clone(),
                        exit_code: None,
                        restarts: st.restarts.unwrap_or(0),
                        since: st.started,
                        cgroup: d.rel.clone(),
                        ..Default::default()
                    };
                    if meta.name == meta.id {
                        u.notes.push(
                            if is_root() {
                                "name unknown: no runtime state visible from here (other mount namespace?)"
                            } else {
                                "name unknown: reading the runtime's state needs root"
                            }
                            .into(),
                        );
                    }
                    u.container = Some(meta);
                    seen_names.insert((UnitKind::Container, u.name.clone()));
                    units.push(u);
                }
                UnitKind::Pod => {
                    let u = Unit {
                        name: d.key.clone(),
                        kind: UnitKind::Pod,
                        state: "active".into(),
                        sub_state: "running".into(),
                        cgroup: d.rel.clone(),
                        ..Default::default()
                    };
                    units.push(u);
                }
                UnitKind::Cgroup => {}
            }
        }
        self.resolver.retain(&live_ids);
        // Pods take their name from any of their containers' Kubernetes metadata.
        let pod_names: HashMap<String, (String, Option<String>)> = units
            .iter()
            .filter_map(|u| u.container.as_ref())
            .filter_map(|m| Some((m.pod_uid.clone()?, (m.pod.clone()?, m.namespace.clone()))))
            .collect();
        for u in units.iter_mut().filter(|u| u.kind == UnitKind::Pod) {
            let uid = u.name.clone();
            let mut meta = super::ContainerMeta { pod_uid: Some(uid.clone()), ..Default::default() };
            if let Some((pod, ns)) = pod_names.get(&uid) {
                u.name = match ns {
                    Some(n) => format!("{n}/{pod}"),
                    None => pod.clone(),
                };
                meta.pod = Some(pod.clone());
                meta.namespace = ns.clone();
            }
            meta.name = u.name.clone();
            u.container = Some(meta);
        }
        // Containers known to a runtime CLI but without a visible cgroup (macOS, private cgroup
        // namespace): resources from the CLI.
        if let Some(cs) = crate::fleet::cached_containers() {
            for c in cs {
                let short: String = c.id.chars().take(12).collect();
                if short.is_empty() || units.iter().any(|u| u.container.as_ref().is_some_and(|m| m.id == short)) {
                    continue;
                }
                let st = c.status.to_ascii_lowercase();
                let (state, sub) = if st.starts_with("up") && st.contains("paused") {
                    ("active", "paused")
                } else if st.starts_with("up") {
                    ("active", "running")
                } else if st.starts_with("restarting") {
                    ("activating", "restarting")
                } else {
                    ("unknown", "")
                };
                let health = ["unhealthy", "healthy", "starting"]
                    .into_iter()
                    .find(|h| st.contains(&format!("({h}")))
                    .map(str::to_string);
                units.push(Unit {
                    name: if c.name.is_empty() { short.clone() } else { c.name.clone() },
                    kind: UnitKind::Container,
                    state: state.into(),
                    sub_state: sub.into(),
                    description: c.image.clone(),
                    cpu: c.cpu,
                    mem: c.mem,
                    container: Some(super::ContainerMeta {
                        id: short,
                        name: c.name.clone(),
                        image: c.image.clone(),
                        runtime: c.runtime.clone(),
                        health,
                        ..Default::default()
                    }),
                    notes: vec!["resources from the runtime CLI (no cgroup visible)".into()],
                    ..Default::default()
                });
            }
        }

        // 2. Join processes: nearest ancestor cgroup that is a unit; else a plain cgroup unit.
        let mut by_path: HashMap<String, usize> = HashMap::new();
        for (i, u) in units.iter().enumerate() {
            if !u.cgroup.is_empty() && u.state != "inactive" && u.state != "failed" {
                by_path.entry(u.cgroup.clone()).or_insert(i);
            }
        }
        let mut members: HashMap<usize, Vec<&Proc>> = HashMap::new();
        let tree_present = self.cg.tree().is_some();
        for p in procs.iter().filter(|p| !p.cgroup.is_empty()) {
            let mut path = p.cgroup.as_str();
            let idx = loop {
                if let Some(&i) = by_path.get(path) {
                    break Some(i);
                }
                match path.rfind('/') {
                    Some(0) | None => break None,
                    Some(i) => path = &path[..i],
                }
            };
            let idx = match idx {
                Some(i) => i,
                None => match unit_of_cgroup(&p.cgroup) {
                    Some(r) if r.kind == UnitKind::Cgroup && tree_present => {
                        units.push(Unit {
                            name: r.key.clone(),
                            kind: UnitKind::Cgroup,
                            state: "active".into(),
                            sub_state: "running".into(),
                            cgroup: r.key.clone(),
                            ..Default::default()
                        });
                        let i = units.len() - 1;
                        by_path.insert(r.key, i);
                        i
                    }
                    _ => continue,
                },
            };
            members.entry(idx).or_default().push(p);
        }

        // 3. Counters, rates, events.
        let pids_alive: HashSet<u32> = procs.iter().map(|p| p.pid).collect();
        for (i, u) in units.iter_mut().enumerate() {
            let mem = members.remove(&i).unwrap_or_default();
            let pl = self.fill_unit(u, &mem, refresh, mono);
            if u.main_pid.is_some_and(|p| !procs.is_empty() && !pids_alive.contains(&p)) {
                u.main_pid = None;
            }
            if u.main_pid.is_none() && u.state != "inactive" && u.state != "failed" {
                let set: HashSet<u32> = mem.iter().map(|p| p.pid).collect();
                u.main_pid = mem.iter().filter(|p| !set.contains(&p.ppid)).map(|p| p.pid).min();
            }
            let pid_set: HashSet<u32> = mem.iter().map(|p| p.pid).collect();
            self.observe(u, pid_set, pl, now, baseline);
        }
        // Units that disappeared since the last sample.
        let present: HashSet<String> = units.iter().map(|u| tkey(u.kind, &u.name)).collect();
        let window_ms = (self.cfg.flap_window_s * 1000) as i64;
        let mut departed = Vec::new();
        for (k, t) in self.track.iter_mut() {
            if present.contains(k) || !t.present {
                continue;
            }
            t.present = false;
            // Restarts held back while it flapped are reported before it goes.
            if t.held_restarts > 0
                && let Some(last) = &t.last
            {
                let n = std::mem::take(&mut t.held_restarts);
                let mut e = event(
                    now,
                    EventKind::UnitRestart,
                    Severity::Warn,
                    last,
                    format!("{} restarted {n} times since the last report", last.name),
                    if last.kind == UnitKind::Systemd { "systemd" } else { "runtime" },
                );
                e.value = Some(n as f64);
                departed.push(e);
            }
            // A unit last seen failed leaves the list when it is cleaned up (`systemctl
            // reset-failed`, garbage collection of a transient unit): its failure was recorded
            // when it entered the failed state, so the cleanup is not another event.
            if let Some(last) = &t.last
                && !baseline
                && last.state != "failed"
                && (last.kind != UnitKind::Systemd || !last.name.ends_with(".scope"))
            {
                departed.push(event(
                    now,
                    EventKind::UnitStop,
                    Severity::Info,
                    last,
                    format!("{} went away", last.name),
                    "cgroup",
                ));
            }
        }
        self.pending.extend(departed);
        // Departed containers stay listed (inactive) for the flap window: "what restarted".
        for t in self.track.values() {
            if !t.present
                && now - t.last_seen <= window_ms
                && let Some(last) = &t.last
                && last.kind == UnitKind::Container
            {
                let mut u = last.clone();
                if u.state != "failed" {
                    u.state = "inactive".into();
                }
                u.sub_state = "exited".into();
                (u.cpu, u.io_read_bps, u.io_write_bps, u.cpu_throttled_pct, u.pids, u.main_pid, u.mem) =
                    (0.0, 0, 0, 0.0, 0, None, 0);
                units.push(u);
            }
        }
        self.track.retain(|_, t| t.present || now - t.last_seen <= window_ms.max(1));
        self.prev.retain(|k, _| present.contains(k));
        let cgs: HashSet<&str> = units.iter().map(|u| u.cgroup.as_str()).collect();
        self.limits.retain(|k, _| cgs.contains(k.as_str()));

        // 4. Bound and order: failed first, then busy, inactive last (dropped first).
        units.sort_by(|a, b| {
            rank(a)
                .cmp(&rank(b))
                .then(b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal))
                .then(a.name.cmp(&b.name))
        });
        if units.len() > self.cfg.max_units {
            notes.push(format!(
                "{} units over server.max_units = {}: least relevant (inactive first) not shown",
                units.len() - self.cfg.max_units,
                self.cfg.max_units
            ));
            units.truncate(self.cfg.max_units);
        }
        self.notes = notes;
        units
    }

    /// Events detected since the last drain, oldest first.
    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.pending)
    }

    fn max_dirs(&self) -> usize {
        // A unit rarely spans more than a handful of cgroup directories (slices above it,
        // a container's inner cgroups), so 8 per allowed unit bounds the walk generically.
        self.cfg.max_units.saturating_mul(8).max(64)
    }

    /// Discover unit cgroups: systemd units (outermost; units nested in another unit, like a
    /// user manager's services, are folded into it), containers (outermost) and pods.
    fn walk(&mut self) {
        let Some(tree) = self.cg.tree().map(Path::to_path_buf) else {
            self.dirs.clear();
            return;
        };
        let max = self.max_dirs();
        let mut out: Vec<Dir> = Vec::new();
        let mut keys: HashSet<(UnitKind, String)> = HashSet::new();
        let mut stack: Vec<(PathBuf, String, bool)> = vec![(tree, String::new(), false)];
        let mut visited = 0usize;
        self.walk_truncated = false;
        while let Some((dir, rel, in_unit)) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                if !e.file_type().is_ok_and(|t| t.is_dir()) {
                    continue;
                }
                visited += 1;
                if visited > max {
                    self.walk_truncated = true;
                    stack.clear();
                    break;
                }
                let name = e.file_name().to_string_lossy().into_owned();
                let crel = format!("{rel}/{name}");
                let r = unit_of_cgroup(&crel);
                let mut child_in_unit = in_unit;
                match r {
                    Some(r) if r.kind == UnitKind::Container => {
                        if keys.insert((r.kind, r.key.clone())) {
                            let full = hex_tail(&name).unwrap_or(&r.key).to_ascii_lowercase();
                            out.push(Dir {
                                rel: crel.clone(),
                                kind: r.kind,
                                key: r.key,
                                full_id: full,
                                runtime: runtime::runtime_of_segment(&name, &crel),
                            });
                        }
                        continue; // a container's inner cgroups are the container
                    }
                    Some(r) if r.kind == UnitKind::Pod => {
                        if keys.insert((r.kind, r.key.clone())) {
                            out.push(Dir {
                                rel: crel.clone(),
                                kind: r.kind,
                                key: r.key,
                                full_id: String::new(),
                                runtime: "",
                            });
                        }
                    }
                    Some(r)
                        if r.kind == UnitKind::Systemd
                            && unit_of_cgroup(&format!("/{name}")).is_some_and(|x| x.kind == UnitKind::Systemd) =>
                    {
                        if !in_unit && keys.insert((r.kind, r.key.clone())) {
                            out.push(Dir {
                                rel: crel.clone(),
                                kind: r.kind,
                                key: r.key,
                                full_id: String::new(),
                                runtime: "",
                            });
                        }
                        // A unit's inner cgroups are the unit. Only a per-user service manager
                        // (systemd's user@UID.service) nests units of its own, among them
                        // rootless containers; skipping the rest keeps the walk to slices.
                        if !name.starts_with("user@") {
                            continue;
                        }
                        child_in_unit = true;
                    }
                    _ => {}
                }
                stack.push((e.path(), crel, child_in_unit));
            }
        }
        out.sort_by(|a, b| a.rel.cmp(&b.rel));
        self.dirs = out;
    }

    /// list-units every refresh, then `show` for what changed (all loaded every full refresh).
    fn refresh_systemd(&mut self, procs: &[Proc], mono: i64) {
        let Some(run) = self.systemctl.as_mut() else { return };
        let Some(text) = run(&["list-units", "--all", "--plain", "--no-legend", "--full", "--no-pager"]) else {
            return; // keep the previous view; transient failure
        };
        let fresh: BTreeMap<String, Listed> = parse_list_units(&text).into_iter().map(|l| (l.id.clone(), l)).collect();
        let full = self.last_full.is_none_or(|t| mono - t >= (self.cfg.unit_full_refresh_s * 1000) as i64);
        let alive: HashSet<u32> = procs.iter().map(|p| p.pid).collect();
        let mut ids: Vec<&str> = Vec::new();
        for (id, l) in &fresh {
            if !wanted(l) {
                continue;
            }
            let prev = self.listed.get(id);
            let changed = prev.is_none_or(|p| p.active != l.active || p.sub != l.sub);
            let transient = matches!(l.active.as_str(), "activating" | "deactivating" | "reloading");
            let main_gone =
                self.props.get(id).and_then(|p| p.main_pid).is_some_and(|m| !procs.is_empty() && !alive.contains(&m));
            // The periodic full pass skips inactive units: nothing about them changes without
            // a state change, which list-units already shows.
            let stale = full && l.active != "inactive";
            if stale || changed || transient || main_gone || !self.props.contains_key(id) {
                ids.push(id);
            }
        }
        if full {
            self.last_full = Some(mono);
        }
        let mut got = Vec::new();
        for chunk in ids.chunks(200) {
            let mut args = vec!["show", "-p", SHOW_PROPS, "--no-pager"];
            args.extend(chunk.iter().copied());
            if let Some(out) = run(&args) {
                got.extend(parse_systemctl_show_at(&out, self.boot_ms));
            }
        }
        for p in got {
            self.props.insert(p.id.clone(), p);
        }
        self.props.retain(|k, _| fresh.contains_key(k));
        self.listed = fresh;
    }

    /// Read cgroup counters/limits into `u` and compute rates against the previous sample.
    /// Returns (pids.current, pids.max) for the exhaustion check.
    fn fill_unit(&mut self, u: &mut Unit, members: &[&Proc], refresh: bool, mono: i64) -> (Option<u64>, Option<u64>) {
        // No cgroup to read (a unit without processes, a container known only to a runtime
        // CLI): keep what the process join and the CLI already gave.
        if u.cgroup.is_empty() || u.state == "inactive" || (u.state == "failed" && members.is_empty()) {
            u.pids = u.pids.max(members.len() as u32);
            u.cpu += members.iter().map(|p| p.cpu).sum::<f32>();
            return (None, None);
        }
        let rel = u.cgroup.clone();
        let lim = match self.limits.get(&rel) {
            Some(l) if !refresh => *l,
            _ => {
                let l = read_limits(&self.cg, &rel);
                self.limits.insert(rel.clone(), l);
                l
            }
        };
        let c = read_counters(&self.cg, &rel, u.kind == UnitKind::Container);
        let k = tkey(u.kind, &u.name);
        u.mem = c.mem.unwrap_or_else(|| members.iter().map(|p| p.mem).sum());
        u.mem_peak = c.peak;
        u.mem_limit = lim.mem_max.or(u.mem_limit);
        u.cpu_quota = lim.cpu_quota;
        u.oom_kills = c.oom_kills.unwrap_or(0);
        u.psi = c.psi;
        u.pids = if members.is_empty() { c.pids.unwrap_or(0) as u32 } else { members.len() as u32 };
        if c.frozen {
            u.sub_state = "paused".into();
        }
        if c.usage_usec.is_none() && c.mem.is_none() {
            u.cpu = members.iter().map(|p| p.cpu).sum();
            u.notes.push("cgroup accounting unavailable: cpu/mem summed from processes".into());
        }
        if let Some((t0, p)) = self.prev.get(&k) {
            let dt_ms = mono - t0;
            if dt_ms > 0 {
                if let (Some(a), Some(b)) = (p.usage_usec, c.usage_usec) {
                    u.cpu = (b.saturating_sub(a) as f64 / (dt_ms as f64 * 1000.0) * 100.0) as f32;
                }
                if let (Some((r0, w0)), Some((r1, w1))) = (p.io, c.io) {
                    u.io_read_bps = r1.saturating_sub(r0) * 1000 / dt_ms as u64;
                    u.io_write_bps = w1.saturating_sub(w0) * 1000 / dt_ms as u64;
                }
                let periods = c.periods.saturating_sub(p.periods);
                if periods > 0 {
                    u.cpu_throttled_pct =
                        (c.throttled.saturating_sub(p.throttled) as f64 / periods as f64 * 100.0).min(100.0) as f32;
                }
            }
        }
        let pids = c.pids;
        self.prev.insert(k, (mono, c));
        (pids, lim.pids_max)
    }

    /// Compare with the previous observation of the same unit; queue events; update tracking.
    fn observe(
        &mut self,
        u: &mut Unit,
        pids: HashSet<u32>,
        (pids_cur, pids_max): (Option<u64>, Option<u64>),
        now: Ts,
        baseline: bool,
    ) {
        let cfg = &self.cfg;
        let k = tkey(u.kind, &u.name);
        let is_new = !self.track.contains_key(&k);
        let t = self.track.entry(k).or_insert_with(|| Track {
            first_seen: now,
            state: u.state.clone(),
            restarts: u.restarts,
            oom_kills: u.oom_kills,
            ..Default::default()
        });
        let was_present = t.present || is_new;
        let reappeared = !is_new && !t.present;
        let prev_state = if reappeared { "inactive".to_string() } else { t.state.clone() };
        let mut ev: Vec<Event> = Vec::new();

        // Restarts: lifetime counter delta; a container whose runtime count is unknown counts
        // re-appearing after going away as one restart.
        let mut restarted = 0u32;
        if !is_new {
            if u.restarts > t.restarts {
                restarted = u.restarts - t.restarts;
            } else if reappeared
                && u.kind == UnitKind::Container
                && u.restarts == 0
                && now - t.last_seen <= (cfg.flap_window_s * 1000) as i64
            {
                restarted = 1;
            }
        }
        let cap = (cfg.flap_restarts as usize).saturating_mul(4).max(16);
        for _ in 0..restarted.min(cap as u32) {
            t.restart_ts.push_back(now);
        }
        while t.restart_ts.len() > cap {
            t.restart_ts.pop_front();
        }
        let window_ms = (cfg.flap_window_s * 1000) as i64;
        while t.restart_ts.front().is_some_and(|&x| x <= now - window_ms) {
            t.restart_ts.pop_front();
        }
        let (recent, flapping) = flap_state(t.restart_ts.make_contiguous(), now, cfg.flap_window_s, cfg.flap_restarts);
        u.recent_restarts = recent;
        u.flapping = flapping;
        if u.since.is_none() {
            u.since = Some(t.first_seen);
        }
        let quiet_lifecycle = u.kind == UnitKind::Systemd && u.name.ends_with(".scope");
        let src = match u.kind {
            UnitKind::Systemd => "systemd",
            UnitKind::Container | UnitKind::Pod => "runtime",
            UnitKind::Cgroup => "cgroup",
        };
        if !baseline {
            let why = outcome(u);
            // A unit in a restart loop would otherwise log one event per restart (thousands a
            // day); while it keeps flapping, restarts are summed into one event per cooldown.
            // `value` always carries the number of restarts the event stands for.
            let coalesce = t.flapping && flapping;
            let cooled = t.last_restart_ev.is_none_or(|x| now - x >= (cfg.spike_cooldown_s * 1000) as i64);
            let count = restarted + t.held_restarts;
            if count > 0 && (!coalesce || cooled) {
                let mins = cfg.flap_window_s / 60;
                let what = if count > restarted || coalesce {
                    format!("restarted {count} times since the last report")
                } else {
                    "restarted".to_string()
                };
                ev.push(event(
                    now,
                    EventKind::UnitRestart,
                    Severity::Warn,
                    u,
                    format!(
                        "{} {what}{why}, {} restart(s) in the last {}",
                        u.name,
                        recent,
                        if mins > 0 { format!("{mins} min") } else { format!("{} s", cfg.flap_window_s) }
                    ),
                    src,
                ));
                ev.last_mut().expect("pushed").value = Some(count as f64);
                t.held_restarts = 0;
                t.last_restart_ev = Some(now);
            } else if restarted > 0 {
                t.held_restarts += restarted;
            }
            if flapping && !t.flapping {
                ev.push(event(
                    now,
                    EventKind::UnitFlapping,
                    Severity::Crit,
                    u,
                    format!("{} is flapping: {} restarts within {} s{why}", u.name, recent, cfg.flap_window_s),
                    src,
                ));
                ev.last_mut().expect("pushed").value = Some(recent as f64);
            }
            if prev_state != u.state || is_new {
                let active_now = matches!(u.state.as_str(), "active" | "activating" | "reloading");
                let was_down = is_new || matches!(prev_state.as_str(), "inactive" | "failed" | "unknown" | "");
                if u.state == "failed" {
                    let crit = matches!(u.result.as_str(), "oom-kill" | "start-limit-hit" | "core-dump" | "watchdog");
                    ev.push(event(
                        now,
                        EventKind::UnitFailed,
                        if crit { Severity::Crit } else { Severity::Warn },
                        u,
                        format!("{} failed{why}", u.name),
                        src,
                    ));
                } else if active_now && was_down && restarted == 0 && !quiet_lifecycle {
                    ev.push(event(now, EventKind::UnitStart, Severity::Info, u, format!("{} started", u.name), src));
                } else if u.state == "inactive" && !was_down && restarted == 0 && !quiet_lifecycle {
                    ev.push(event(
                        now,
                        EventKind::UnitStop,
                        Severity::Info,
                        u,
                        format!("{} stopped{why}", u.name),
                        src,
                    ));
                }
            }
            let cgroup_oom = !is_new && u.oom_kills > t.oom_kills && u.kind != UnitKind::Pod;
            // A unit killed by the OOM killer usually dies between two samples and its cgroup
            // (with memory.events) goes with it; systemd still reports Result=oom-kill.
            let result_oom =
                u.result == "oom-kill" && (restarted > 0 || (u.state == "failed" && prev_state != "failed"));
            if !cgroup_oom && result_oom && !t.oom_this_run {
                let lim = u.mem_limit.map(|l| format!(" (limit {})", human(l))).unwrap_or_default();
                let mut e =
                    event(now, EventKind::OomKill, Severity::Crit, u, format!("{} was OOM-killed{lim}", u.name), src);
                e.extra.insert("cgroup".into(), u.cgroup.clone());
                ev.push(e);
            }
            // The kill result_oom reports belongs to the run that ended; a new run starts clean.
            if result_oom
                || restarted > 0
                || (matches!(u.state.as_str(), "active" | "activating") && prev_state != u.state)
            {
                t.oom_this_run = false;
            }
            if cgroup_oom {
                t.oom_this_run = true;
                let n = u.oom_kills - t.oom_kills;
                let lim = u.mem_limit.map(|l| format!(" of its {} limit", human(l))).unwrap_or_default();
                let mut e = event(
                    now,
                    EventKind::OomKill,
                    Severity::Crit,
                    u,
                    format!(
                        "{n} process(es) OOM-killed in {} (memory {}{lim})",
                        u.name,
                        human(u.mem.max(u.mem_peak.unwrap_or(0)))
                    ),
                    "cgroup",
                );
                e.value = Some(n as f64);
                e.extra.insert("cgroup".into(), u.cgroup.clone());
                if let Some(l) = u.mem_limit {
                    e.extra.insert("mem_limit".into(), l.to_string());
                }
                ev.push(e);
            }
            // CPU limit throttling (hysteresis: re-arm below half the threshold).
            let thr = cfg.throttle_warn_pct;
            if u.cpu_throttled_pct >= thr && !t.throttled {
                let q = u.cpu_quota.map(|q| format!(" (cpu.max {q:.2} cores)")).unwrap_or_default();
                let mut e = event(
                    now,
                    EventKind::Throttle,
                    Severity::Warn,
                    u,
                    format!(
                        "{} throttled in {:.0}% of CPU periods{q} while using {:.0}% cpu",
                        u.name, u.cpu_throttled_pct, u.cpu
                    ),
                    "cgroup",
                );
                e.value = Some(u.cpu_throttled_pct as f64);
                ev.push(e);
            }
            // memory.max / pids.max close to exhaustion (memory counts only non-reclaimable use).
            if let Some(l) = u.mem_limit.filter(|&l| l > 0) {
                let raw = u.mem as f64 / l as f64;
                let used = if raw >= cfg.exhaustion_warn as f64 {
                    reclaim_adjusted(&self.cg, &u.cgroup, u.mem) as f64 / l as f64
                } else {
                    raw
                };
                if used >= cfg.exhaustion_warn as f64 && !t.mem_high {
                    let mut e = event(
                        now,
                        EventKind::Exhaustion,
                        Severity::Warn,
                        u,
                        format!(
                            "{} at {:.0}% of its memory limit ({} of {})",
                            u.name,
                            used * 100.0,
                            human((used * l as f64) as u64),
                            human(l)
                        ),
                        "cgroup",
                    );
                    e.value = Some(used * 100.0);
                    e.extra.insert("resource".into(), "memory.max".into());
                    ev.push(e);
                    t.mem_high = true;
                } else if used < cfg.exhaustion_warn as f64 * 0.9 {
                    t.mem_high = false;
                }
            }
            if let (Some(c), Some(m)) = (pids_cur, pids_max.filter(|&m| m > 0 && m < u64::MAX)) {
                let r = c as f64 / m as f64;
                if r >= cfg.exhaustion_warn as f64 && !t.pids_high {
                    let mut e = event(
                        now,
                        EventKind::Exhaustion,
                        Severity::Warn,
                        u,
                        format!("{} at {c} of {m} tasks (pids.max)", u.name),
                        "cgroup",
                    );
                    e.value = Some(r * 100.0);
                    e.extra.insert("resource".into(), "pids.max".into());
                    ev.push(e);
                    t.pids_high = true;
                } else if r < cfg.exhaustion_warn as f64 * 0.9 {
                    t.pids_high = false;
                }
            }
            // Many new processes in one interval: deploy, cron storm, fork loop.
            if !is_new && was_present && !t.pids.is_empty() {
                let fresh = pids.difference(&t.pids).count() as u32;
                let cooled = t.last_burst.is_none_or(|b| now - b >= (cfg.spike_cooldown_s * 1000) as i64);
                if cfg.burst_procs > 0 && fresh >= cfg.burst_procs && cooled {
                    let mut e = event(
                        now,
                        EventKind::DeployBurst,
                        Severity::Info,
                        u,
                        format!("{fresh} new processes in {} within one sample", u.name),
                        "procfs",
                    );
                    e.value = Some(fresh as f64);
                    ev.push(e);
                    t.last_burst = Some(now);
                }
            }
        }
        if u.cpu_throttled_pct >= cfg.throttle_warn_pct {
            t.throttled = true;
        } else if u.cpu_throttled_pct < cfg.throttle_warn_pct / 2.0 {
            t.throttled = false;
        }
        t.state = u.state.clone();
        t.restarts = u.restarts;
        t.flapping = flapping;
        t.oom_kills = u.oom_kills;
        t.pids = pids;
        t.last_seen = now;
        t.present = true;
        t.last = Some(u.clone());
        self.pending.extend(ev);
    }
}

const SHOW_PROPS: &str = "Id,Description,LoadState,ActiveState,SubState,Result,NRestarts,MainPID,ExecMainCode,ExecMainStatus,ControlGroup,StateChangeTimestampMonotonic,MemoryMax";

/// Units worth listing: loaded services and scopes, plus anything failed. Container scopes are
/// listed as containers instead.
fn wanted(l: &Listed) -> bool {
    if l.active == "failed" {
        return true;
    }
    let typed = l.id.ends_with(".service") || l.id.ends_with(".scope");
    typed && l.load == "loaded" && unit_of_cgroup(&format!("/{}", l.id)).is_none_or(|r| r.kind == UnitKind::Systemd)
}

fn normalize_state(s: &str) -> String {
    match s {
        "active" | "activating" | "deactivating" | "reloading" | "inactive" | "failed" => s,
        "refreshing" => "reloading",
        "maintenance" => "inactive",
        _ => "unknown",
    }
    .to_string()
}

fn rank(u: &Unit) -> u8 {
    match u.state.as_str() {
        "failed" => 0,
        _ if u.flapping => 0,
        "activating" | "deactivating" | "reloading" => 1,
        "active" => 2,
        "unknown" => 3,
        _ => 4,
    }
}

fn tkey(kind: UnitKind, name: &str) -> String {
    format!("{}:{name}", kind.as_str())
}

/// " (exit-code, status 1)" style suffix from a unit's result and exit code.
fn outcome(u: &Unit) -> String {
    match (u.result.as_str(), u.exit_code) {
        ("" | "success", None | Some(0)) => String::new(),
        ("" | "success", Some(c)) => format!(" (exit status {c})"),
        (r @ ("signal" | "core-dump" | "oom-kill" | "watchdog" | "timeout"), Some(c)) if c > 128 => {
            format!(" ({r}, signal {})", c - 128)
        }
        (r, Some(c)) if c != 0 => format!(" ({r}, status {c})"),
        (r, _) => format!(" ({r})"),
    }
}

fn event(ts: Ts, kind: EventKind, severity: Severity, u: &Unit, detail: String, source: &str) -> Event {
    let subject = match u.kind {
        UnitKind::Systemd | UnitKind::Cgroup => format!("unit:{}", u.name),
        UnitKind::Container => format!("container:{}", u.name),
        UnitKind::Pod => format!("pod:{}", u.name),
    };
    let mut extra = BTreeMap::new();
    extra.insert("kind".to_string(), u.kind.as_str().to_string());
    if !u.result.is_empty() && u.result != "success" {
        extra.insert("result".into(), u.result.clone());
    }
    if let Some(c) = u.exit_code.filter(|&c| c != 0) {
        extra.insert("exit_code".into(), c.to_string());
    }
    Event {
        ts,
        kind,
        severity,
        subject,
        unit: Some(u.name.clone()),
        pid: u.main_pid,
        detail,
        value: None,
        source: source.into(),
        extra,
    }
}

fn human(b: u64) -> String {
    let f = b as f64;
    match b {
        0..1024 => format!("{b}B"),
        1024..1_048_576 => format!("{:.0}K", f / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.0}M", f / 1_048_576.0),
        _ => format!("{:.1}G", f / 1_073_741_824.0),
    }
}

// ---------------------------------------------------------------------------------------------
// cgroup readers
// ---------------------------------------------------------------------------------------------

fn rd(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn rd_u64(p: &Path) -> Option<u64> {
    rd(p)?.trim().parse().ok()
}

fn cg_dir(base: &Path, rel: &str) -> PathBuf {
    base.join(rel.trim_start_matches('/'))
}

fn read_counters(cg: &CgMode, rel: &str, want_freeze: bool) -> Counters {
    let mut c = Counters::default();
    match cg {
        CgMode::V2(root) => {
            let d = cg_dir(root, rel);
            match rd(&d.join("cpu.stat")) {
                Some(t) => {
                    let (u, p, th, _) = parse_cpu_stat(&t);
                    (c.usage_usec, c.periods, c.throttled) = (Some(u), p, th);
                }
                // No cgroup (unit without processes): one stat instead of nine failed opens.
                None if !d.is_dir() => return c,
                None => {}
            }
            c.mem = rd_u64(&d.join("memory.current"));
            c.peak = rd_u64(&d.join("memory.peak"));
            c.oom_kills = rd(&d.join("memory.events")).and_then(|t| kv(&t, "oom_kill"));
            c.io = rd(&d.join("io.stat")).map(|t| parse_io_stat(&t));
            c.pids = rd_u64(&d.join("pids.current"));
            let (cpu, mem, io) =
                (rd(&d.join("cpu.pressure")), rd(&d.join("memory.pressure")), rd(&d.join("io.pressure")));
            if cpu.is_some() || mem.is_some() || io.is_some() {
                let f = |t: Option<String>| t.map(|t| parse_pressure(&t)).unwrap_or_default();
                let ((cs, cf), (ms, mf), (is, isf)) = (f(cpu), f(mem), f(io));
                c.psi = Some(Pressure {
                    cpu_some: cs,
                    cpu_full: cf,
                    mem_some: ms,
                    mem_full: mf,
                    io_some: is,
                    io_full: isf,
                });
            }
            if want_freeze {
                c.frozen = rd(&d.join("cgroup.freeze")).is_some_and(|t| t.trim() == "1");
            }
        }
        CgMode::V1 { root, .. } => {
            let m = cg_dir(&root.join("memory"), rel);
            c.mem = rd_u64(&m.join("memory.usage_in_bytes"));
            c.peak = rd_u64(&m.join("memory.max_usage_in_bytes"));
            c.oom_kills = rd(&m.join("memory.oom_control")).and_then(|t| kv(&t, "oom_kill"));
            c.usage_usec = rd_u64(&cg_dir(&root.join("cpuacct"), rel).join("cpuacct.usage")).map(|ns| ns / 1000);
            if let Some(t) = rd(&cg_dir(&root.join("cpu"), rel).join("cpu.stat")) {
                c.periods = kv(&t, "nr_periods").unwrap_or(0);
                c.throttled = kv(&t, "nr_throttled").unwrap_or(0);
            }
            c.pids = rd_u64(&cg_dir(&root.join("pids"), rel).join("pids.current"));
            if want_freeze {
                c.frozen =
                    rd(&cg_dir(&root.join("freezer"), rel).join("freezer.state")).is_some_and(|t| t.trim() == "FROZEN");
            }
        }
        CgMode::None => {}
    }
    c
}

fn read_limits(cg: &CgMode, rel: &str) -> Limits {
    match cg {
        CgMode::V2(root) => {
            let d = cg_dir(root, rel);
            Limits {
                mem_max: rd(&d.join("memory.max")).and_then(|t| t.trim().parse().ok()),
                cpu_quota: rd(&d.join("cpu.max")).and_then(|t| parse_cpu_max(&t)),
                pids_max: rd(&d.join("pids.max")).and_then(|t| t.trim().parse().ok()),
            }
        }
        CgMode::V1 { root, .. } => {
            let cpu = cg_dir(&root.join("cpu"), rel);
            let quota = rd(&cpu.join("cpu.cfs_quota_us")).and_then(|t| t.trim().parse::<i64>().ok()).filter(|&q| q > 0);
            let period = rd_u64(&cpu.join("cpu.cfs_period_us")).filter(|&p| p > 0);
            Limits {
                // v1 reports "unlimited" as a huge page-rounded number.
                mem_max: rd_u64(&cg_dir(&root.join("memory"), rel).join("memory.limit_in_bytes"))
                    .filter(|&l| l < 1 << 60),
                cpu_quota: quota.zip(period).map(|(q, p)| q as f32 / p as f32),
                pids_max: rd(&cg_dir(&root.join("pids"), rel).join("pids.max")).and_then(|t| t.trim().parse().ok()),
            }
        }
        CgMode::None => Limits::default(),
    }
}

/// memory.current minus reclaimable inactive page cache (what the OOM killer would not free).
fn reclaim_adjusted(cg: &CgMode, rel: &str, mem: u64) -> u64 {
    let stat = match cg {
        CgMode::V2(root) => rd(&cg_dir(root, rel).join("memory.stat")),
        CgMode::V1 { root, .. } => rd(&cg_dir(&root.join("memory"), rel).join("memory.stat")),
        CgMode::None => None,
    };
    let inactive = stat.and_then(|t| kv(&t, "inactive_file").or_else(|| kv(&t, "total_inactive_file"))).unwrap_or(0);
    mem.saturating_sub(inactive)
}

/// Value of `key N` in a flat keyed file.
fn kv(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next() == Some(key)).then(|| it.next()?.parse().ok()).flatten()
    })
}

/// cpu.max "quota period" -> cores (None for "max").
fn parse_cpu_max(t: &str) -> Option<f32> {
    let mut it = t.split_whitespace();
    let q: f64 = it.next()?.parse().ok()?;
    let p: f64 = it.next().and_then(|p| p.parse().ok()).unwrap_or(100_000.0);
    (p > 0.0).then_some((q / p) as f32)
}

/// Trailing 32+ hex chars of a cgroup segment ("docker-<64hex>.scope" -> the 64 hex).
fn hex_tail(seg: &str) -> Option<&str> {
    let s = seg.strip_suffix(".scope").unwrap_or(seg);
    let h = match s.rfind('-') {
        Some(i) => &s[i + 1..],
        None => s,
    };
    (h.len() >= 32 && h.bytes().all(|b| b.is_ascii_hexdigit())).then_some(h)
}

// ---------------------------------------------------------------------------------------------
// systemctl
// ---------------------------------------------------------------------------------------------

fn which(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> =
        std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    dirs.extend(["/usr/bin", "/bin", "/usr/sbin", "/sbin"].map(PathBuf::from));
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

/// `systemctl args` with a hard timeout, C locale, no pager/colors. stdout on success.
fn run_systemctl(args: &[&str], timeout: Duration) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new("systemctl")
        .args(args)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            _ => {
                // Our own child, past its deadline.
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let text = reader.join().ok()?;
    status.filter(|s| s.success()).map(|_| text)
}

/// Parse `systemctl list-units --all --plain --no-legend --full` lines.
pub fn parse_list_units(text: &str) -> Vec<Listed> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_start_matches(|c: char| c == '●' || c == '*' || c.is_whitespace());
            let mut it = line.split_whitespace();
            let id = it.next()?.to_string();
            let load = it.next()?.to_string();
            let active = it.next()?.to_string();
            let sub = it.next()?.to_string();
            let description = it.collect::<Vec<_>>().join(" ");
            Some(Listed { id, load, active, sub, description })
        })
        .collect()
}

fn mono_ms() -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid out-pointer; CLOCK_MONOTONIC is always available.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    #[allow(clippy::unnecessary_cast)] // time_t/c_long are not i64 on every target
    let ms = ts.tv_sec as i64 * 1000 + ts.tv_nsec as i64 / 1_000_000;
    ms
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// One unit's properties as printed by `systemctl show -p ... unit1 unit2 ...` (blocks separated
/// by blank lines).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SystemdProps {
    pub id: String,
    pub description: String,
    pub active_state: String,
    pub sub_state: String,
    pub result: String,
    pub n_restarts: u32,
    pub main_pid: Option<u32>,
    pub exit_status: Option<i32>,
    pub control_group: String,
    pub state_change_ts: Option<Ts>,
    pub memory_max: Option<u64>,
    /// "loaded" | "not-found" | "masked" | ...
    pub load_state: String,
    /// StateChangeTimestampMonotonic (µs since boot), the source of `state_change_ts`.
    pub state_change_mono_us: Option<u64>,
    /// Signal that ended the main process (ExecMainCode killed/dumped); `exit_status` is then
    /// 128 + signal, the shell and container-runtime convention.
    pub exit_signal: Option<i32>,
}

/// Parse batched `systemctl show` output. Unknown keys ignored; "[not set]"/"infinity" -> None.
#[cfg_attr(not(test), allow(dead_code))] // tests and callers without a boot-time reference
pub fn parse_systemctl_show(text: &str) -> Vec<SystemdProps> {
    parse_systemctl_show_at(text, crate::model::now_ms() - mono_ms())
}

/// [`parse_systemctl_show`] with an explicit boot time (epoch ms of monotonic zero).
pub fn parse_systemctl_show_at(text: &str, boot_ms: Ts) -> Vec<SystemdProps> {
    let mut out = Vec::new();
    let mut cur = SystemdProps::default();
    // ExecMainCode: 0 never exited, 1 CLD_EXITED, 2 CLD_KILLED, 3 CLD_DUMPED.
    let mut exit_code_known: Option<i32> = None;
    let flush = |cur: &mut SystemdProps, known: &mut Option<i32>, out: &mut Vec<SystemdProps>| {
        if !cur.id.is_empty() {
            match *known {
                Some(0) => cur.exit_status = None,
                Some(2 | 3) => {
                    cur.exit_signal = cur.exit_status;
                    cur.exit_status = cur.exit_status.map(|s| 128 + s);
                }
                _ => {}
            }
            out.push(std::mem::take(cur));
        }
        *cur = SystemdProps::default();
        *known = None;
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            flush(&mut cur, &mut exit_code_known, &mut out);
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let none = v.is_empty() || v == "[not set]" || v == "infinity";
        match k {
            "Id" => cur.id = v.to_string(),
            "Description" => cur.description = v.to_string(),
            "LoadState" => cur.load_state = v.to_string(),
            "ActiveState" => cur.active_state = v.to_string(),
            "SubState" => cur.sub_state = v.to_string(),
            "Result" => cur.result = v.to_string(),
            "NRestarts" => cur.n_restarts = v.parse().unwrap_or(0),
            "MainPID" => cur.main_pid = v.parse().ok().filter(|&p: &u32| p > 0),
            "ExecMainCode" => exit_code_known = v.parse().ok(),
            "ExecMainStatus" => cur.exit_status = v.parse().ok(),
            "ControlGroup" => cur.control_group = v.to_string(),
            "StateChangeTimestampMonotonic" => {
                cur.state_change_mono_us = v.parse().ok().filter(|&x: &u64| x > 0);
                cur.state_change_ts = cur.state_change_mono_us.map(|us| boot_ms + (us / 1000) as i64);
            }
            "MemoryMax" => cur.memory_max = if none { None } else { v.parse().ok() },
            _ => {}
        }
    }
    flush(&mut cur, &mut exit_code_known, &mut out);
    out
}

/// Parse a cgroup v2 `cpu.stat` into (usage_usec, nr_periods, nr_throttled, throttled_usec).
pub fn parse_cpu_stat(text: &str) -> (u64, u64, u64, u64) {
    let g = |k| kv(text, k).unwrap_or(0);
    (g("usage_usec"), g("nr_periods"), g("nr_throttled"), g("throttled_usec"))
}

/// Parse a cgroup v2 `io.stat` into total (rbytes, wbytes).
pub fn parse_io_stat(text: &str) -> (u64, u64) {
    let (mut r, mut w) = (0u64, 0u64);
    for tok in text.split_whitespace() {
        if let Some(v) = tok.strip_prefix("rbytes=") {
            r = r.saturating_add(v.parse().unwrap_or(0));
        } else if let Some(v) = tok.strip_prefix("wbytes=") {
            w = w.saturating_add(v.parse().unwrap_or(0));
        }
    }
    (r, w)
}

/// Parse a PSI file (`some avg10=.. ` / `full avg10=..`) into (some_avg10, full_avg10).
pub fn parse_pressure(text: &str) -> (f32, f32) {
    let (mut some, mut full) = (0.0, 0.0);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let kind = it.next();
        let avg10 = it.find_map(|kv| kv.strip_prefix("avg10=")).and_then(|v| v.parse::<f32>().ok()).unwrap_or(0.0);
        match kind {
            Some("some") => some = avg10,
            Some("full") => full = avg10,
            _ => {}
        }
    }
    (some, full)
}

/// Restart timestamps per unit -> (recent_restarts, flapping) for the window ending `now`.
pub fn flap_state(restart_ts: &[Ts], now: Ts, window_s: u64, threshold: u32) -> (u32, bool) {
    let from = now - (window_s as i64) * 1000;
    let n = restart_ts.iter().filter(|&&t| t > from && t <= now).count() as u32;
    (n, threshold > 0 && n >= threshold)
}

// ---------------------------------------------------------------------------------------------
// Front ends (CLI `fat services`, MCP `services`)
// ---------------------------------------------------------------------------------------------

/// Parse a `--kind` value ("systemd" | "container" | "k8s-pod"/"pod" | "cgroup").
pub fn parse_kind(s: &str) -> Option<UnitKind> {
    match s.trim().to_ascii_lowercase().as_str() {
        "systemd" | "service" | "unit" => Some(UnitKind::Systemd),
        "container" | "containers" | "docker" | "podman" => Some(UnitKind::Container),
        "k8s-pod" | "pod" | "pods" | "k8s" => Some(UnitKind::Pod),
        "cgroup" | "cgroups" => Some(UnitKind::Cgroup),
        _ => None,
    }
}

/// Keep failed (and flapping) units only, and/or one kind.
pub fn filter(units: Vec<Unit>, failed: bool, kind: Option<UnitKind>) -> Vec<Unit> {
    units
        .into_iter()
        .filter(|u| !failed || u.is_failed() || u.flapping)
        .filter(|u| kind.is_none_or(|k| u.kind == k))
        .collect()
}

/// Two samples a short interval apart (rates need an interval), using a fresh collector.
pub fn sample_once(cfg: &ServerCfg) -> (Vec<Unit>, Vec<String>) {
    if !cfg!(target_os = "linux") && crate::config::Config::load().containers {
        let _ = crate::fleet::containers();
    }
    let mut c = crate::collect::Collector::new();
    let mut s = Services::new(cfg);
    let first = c.sample();
    s.sample(&first.procs);
    std::thread::sleep(Duration::from_millis(600));
    let snap = c.sample();
    let units = s.sample(&snap.procs);
    (units, s.notes().to_vec())
}

/// MCP: one long-lived sampler per process so repeated calls get real rates and transitions.
pub fn shared_sample(cfg: &ServerCfg, procs: &[Proc]) -> (Vec<Unit>, Vec<String>, Vec<Event>) {
    static SHARED: std::sync::Mutex<Option<Services>> = std::sync::Mutex::new(None);
    let mut g = SHARED.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_none() {
        let mut s = Services::new(cfg);
        s.sample(procs);
        std::thread::sleep(Duration::from_millis(500));
        *g = Some(s);
    }
    let s = g.as_mut().expect("set above");
    let units = s.sample(procs);
    (units, s.notes().to_vec(), s.drain_events())
}

/// Human table for `fat services`.
pub fn render(units: &[Unit], notes: &[String]) -> String {
    let mut out = String::new();
    let failed = units.iter().filter(|u| u.is_failed()).count();
    let flapping = units.iter().filter(|u| u.flapping).count();
    let active = units.iter().filter(|u| u.state == "active").count();
    out.push_str(&format!("{} units: {active} active, {failed} failed, {flapping} flapping\n", units.len()));
    out.push_str(&format!(
        "{:<12} {:<9} {:<40} {:>6} {:>7} {:>7} {:>5} {:>4} {:>5} {:>9} {:>11}  {}\n",
        "STATE", "KIND", "NAME", "CPU%", "MEM", "LIMIT", "PIDS", "RST", "THR%", "IO r/w/s", "PSI c/m/io", "DETAIL"
    ));
    for u in units {
        let mut name = u.name.clone();
        if name.chars().count() > 40 {
            name =
                format!("…{}", name.chars().rev().take(39).collect::<Vec<_>>().into_iter().rev().collect::<String>());
        }
        let state = if u.flapping { format!("{}!flap", u.state) } else { u.state.clone() };
        let io = if u.io_read_bps + u.io_write_bps > 0 {
            format!("{}/{}", human(u.io_read_bps), human(u.io_write_bps))
        } else {
            "-".into()
        };
        let psi = u
            .psi
            .map(|p| format!("{:.0}/{:.0}/{:.0}", p.cpu_some, p.mem_some, p.io_some))
            .unwrap_or_else(|| "-".into());
        let rst = if u.recent_restarts > 0 { format!("{}*", u.restarts) } else { u.restarts.to_string() };
        let mut detail = vec![u.sub_state.clone()];
        let why = outcome(u);
        if !why.is_empty() {
            detail.push(why.trim().to_string());
        }
        if u.oom_kills > 0 {
            detail.push(format!("oom_kills={}", u.oom_kills));
        }
        if let Some(h) = u.container.as_ref().and_then(|c| c.health.clone()) {
            detail.push(h);
        }
        if u.kind == UnitKind::Container
            && let Some(m) = &u.container
            && !m.runtime.is_empty()
        {
            detail.push(m.runtime.clone());
        }
        let (cpu, mem) = if u.state == "inactive" || (u.state == "failed" && u.mem == 0) {
            ("-".to_string(), "-".to_string())
        } else {
            (format!("{:.1}", u.cpu), human(u.mem))
        };
        out.push_str(&format!(
            "{:<12} {:<9} {:<40} {:>6} {:>7} {:>7} {:>5} {:>4} {:>5} {:>9} {:>11}  {}\n",
            state,
            u.kind.as_str(),
            name,
            cpu,
            mem,
            u.mem_limit.map(human).unwrap_or_else(|| "-".into()),
            if u.pids > 0 { u.pids.to_string() } else { "-".into() },
            rst,
            if u.cpu_throttled_pct > 0.0 { format!("{:.0}", u.cpu_throttled_pct) } else { "-".into() },
            io,
            psi,
            detail.join(" ")
        ));
    }
    for n in notes {
        out.push_str(&format!("note: {n}\n"));
    }
    if units.iter().any(|u| u.recent_restarts > 0) {
        out.push_str("RST*: restarted within server.flap_window_s\n");
    }
    out
}

/// `fat services [--failed] [--kind K] [--json]`.
pub fn cli(cfg: &ServerCfg, failed: bool, kind: Option<&str>, json: bool) -> anyhow::Result<()> {
    let kind = match kind {
        Some(k) => Some(
            parse_kind(k)
                .ok_or_else(|| anyhow::anyhow!("unknown --kind {k:?}: use systemd, container, k8s-pod or cgroup"))?,
        ),
        None => None,
    };
    let (units, notes) = sample_once(cfg);
    let total = units.len();
    let units = filter(units, failed, kind);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "units": units, "total_units": total, "notes": notes }))?
        );
    } else {
        let what = match (failed, kind) {
            (true, Some(k)) => format!("failed or flapping {} units", k.as_str()),
            (true, None) => "failed or flapping units".to_string(),
            (false, Some(k)) => format!("{} units", k.as_str()),
            (false, None) => String::new(),
        };
        print!("{}", render_filtered(&units, total, &what, &notes));
    }
    Ok(())
}

/// [`render`] of a filtered list: says what was filtered out of how many, and prints no empty
/// table, so "nothing failed" never reads as "fat found no units".
pub fn render_filtered(units: &[Unit], total: usize, what: &str, notes: &[String]) -> String {
    if what.is_empty() {
        return render(units, notes);
    }
    if units.is_empty() {
        let mut out = format!("no {what} ({total} units in all)\n");
        for n in notes {
            out.push_str(&format!("note: {n}\n"));
        }
        return out;
    }
    format!("{} {what} of {total} units\n{}", units.len(), render(units, notes))
}

#[cfg(test)]
mod tests;
