//! "What is eating my space in the last N minutes?" OWNER: fs-growth agent.
//!
//! [`Tracker::report`] combines every evidence source available, each tagged:
//! - [`Evidence::Fsevents`] (macOS): the FSEvents journal, replayed retroactively from an
//!   event id and then tailed live on a dedicated CFRunLoop thread ([`fsevents`]). Works as a
//!   normal user. Event ids are mapped to wall time by fat's own id clock (anchors persisted in
//!   fat's data dir) and, before any anchor exists, by fitting the ctime of returned files.
//! - [`Evidence::Watch`] (Linux): fanotify on whole filesystems as root, else inotify on a
//!   bounded set of hot dirs; covers only the time since fat started ([`watch`]).
//! - [`Evidence::OpenFiles`]: files the top disk writers hold open for writing, sized over
//!   time ([`openfiles`]).
//! - [`Evidence::ScanDiff`]: recorded dir-size snapshots (History) vs the latest ones/scanner.
//! - [`Evidence::Mtime`]: budgeted walk for files modified in the window (fallback).
//!
//! Paths changed in the window are stat'ed for their current size. Created-in-window files
//! (birth time) count their full size; other files need a baseline size (an earlier stat by
//! this tracker, an open-files sample, or a scanner listing) or their delta stays unknown and
//! they count as "touched". Paths inside TCC-protected locations (macOS) are never stat'ed
//! without Full Disk Access (or an explicit `under` inside them): they are counted by events.
//! Read-only: nothing here writes anything but fat's own id-clock file.
use super::{Evidence, Growth};
use crate::model::{Snapshot, Ts, now_ms};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod fsevents;
mod mtime;
mod openfiles;
mod paths;
mod rollup;
#[cfg(target_os = "linux")]
mod watch;

use rollup::Obs;

pub(crate) const F_CREATED: u32 = 1;
pub(crate) const F_REMOVED: u32 = 2;
pub(crate) const F_MODIFIED: u32 = 4;
pub(crate) const F_RENAMED: u32 = 8;
pub(crate) const F_DIR: u32 = 16;
/// Entry is a directory standing for several folded paths (memory cap reached).
pub(crate) const F_AGG: u32 = 32;

/// Events aggregated for one path.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PathEv {
    pub flags: u32,
    pub count: u32,
    /// First / last stamp: FSEvents event id (macOS) or epoch ms (Linux).
    pub first: i64,
    pub last: i64,
    /// Writer pids (fanotify), at most 3.
    pub pids: Vec<u32>,
}

/// Max distinct paths a live journal/watch keeps (beyond it paths fold into parents).
const EVENT_CAP: usize = 100_000;
/// Max growers returned.
const MAX_GROWERS: usize = 50;
/// Baseline sizes remembered.
const BASELINE_CAP: usize = 100_000;
/// How long per-file / per-process memory is kept.
const KEEP_MS: i64 = 70 * 60 * 1000;
/// Mtime fallback walk budget.
const MTIME_BUDGET: std::time::Duration = std::time::Duration::from_millis(2000);

/// `p` is `prefix` or below it (component-wise).
pub(crate) fn under_prefix(p: &str, prefix: &str) -> bool {
    if prefix == "/" || prefix.is_empty() {
        return p.starts_with('/');
    }
    let prefix = prefix.trim_end_matches('/');
    p.starts_with(prefix) && (p.len() == prefix.len() || p.as_bytes()[prefix.len()] == b'/')
}

fn parent_of(p: &str) -> Option<&str> {
    match p.rfind('/') {
        Some(0) if p.len() > 1 => Some("/"),
        Some(i) if i > 0 => Some(&p[..i]),
        _ => None,
    }
}

/// Add one event to a bounded per-path map. Once `cap` paths are held, new paths fold into
/// their parent directory (flag F_AGG), climbing further up if the map keeps growing.
pub(crate) fn record_event(
    map: &mut HashMap<String, PathEv>,
    cap: usize,
    path: &str,
    flags: u32,
    stamp: i64,
    pid: u32,
) {
    let mut key = path;
    let mut fl = flags;
    if !map.contains_key(key) && map.len() >= cap {
        fl = (fl & !(F_CREATED | F_REMOVED | F_RENAMED)) | F_AGG | F_DIR | F_MODIFIED;
        if let Some(p) = parent_of(key) {
            key = p;
        }
        while !map.contains_key(key) && map.len() >= cap + cap / 4 && key.matches('/').count() > 2 {
            match parent_of(key) {
                Some(p) => key = p,
                None => break,
            }
        }
    }
    if let Some(e) = map.get_mut(key) {
        e.flags |= fl;
        e.count = e.count.saturating_add(1);
        e.last = e.last.max(stamp);
        if pid != 0 && !e.pids.contains(&pid) && e.pids.len() < 3 {
            e.pids.push(pid);
        }
        return;
    }
    let pids = if pid != 0 { vec![pid] } else { vec![] };
    map.insert(
        key.to_string(),
        PathEv {
            flags: fl,
            count: 1,
            first: stamp,
            last: stamp,
            pids,
        },
    );
}

/// (ts, [(mount, used, remote)]).
type VolSample = (Ts, Vec<(String, u64, bool)>);

/// Remembered sizes of one file.
#[derive(Debug, Clone, Default)]
struct Seen {
    samples: Vec<(Ts, u64)>,
    birth: Option<i64>,
}

/// Long-lived tracker (TUI / recorder keep one; CLI makes one and calls `report`).
pub struct Tracker {
    home: String,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fda: bool,
    exclude: Vec<String>,
    baseline: HashMap<String, Seen>,
    open: openfiles::OpenFiles,
    /// (ts, interval ms, [(pid, name, write bps)]) of observed snapshots with writers.
    writes: VecDeque<(Ts, i64, Vec<openfiles::Writer>)>,
    last_snap: Ts,
    names: HashMap<u32, String>,
    vols: Option<super::volumes::Volumes>,
    /// (ts, [(mount, used, remote)]).
    vol_samples: VecDeque<VolSample>,
    last_vol: Ts,
    #[cfg(target_os = "macos")]
    mac: Mac,
    #[cfg(target_os = "linux")]
    watch: Option<watch::Watcher>,
}

#[cfg(target_os = "macos")]
struct Mac {
    journal: Option<fsevents::Journal>,
    clock: fsevents::IdClock,
    /// Wall time the journal's start id corresponds to (estimated).
    journal_from_ms: Ts,
}

/// How far back the live journal replays at startup.
#[cfg(target_os = "macos")]
const JOURNAL_BACK_MS: i64 = super::DEFAULT_WINDOW_MS + 2 * 60 * 1000;
/// FSEvents ids per ms assumed before the clock has measured the real rate (this Mac: ~1.3).
#[cfg(target_os = "macos")]
const DEFAULT_ID_RATE: f64 = 2.0;
/// How long `report` waits for a history replay.
#[cfg(target_os = "macos")]
const HISTORY_WAIT: std::time::Duration = std::time::Duration::from_secs(12);

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracker {
    /// Start live watchers that are available (Linux fanotify as root, else inotify on hot dirs).
    pub fn new() -> Self {
        Self::with_state_dir(Some(paths::state_dir()))
    }

    /// `state_dir` holds the FSEvents id clock (None = keep it in memory only).
    pub fn with_state_dir(state_dir: Option<PathBuf>) -> Self {
        let home = paths::home();
        let exclude = paths::own_dirs();
        let _ = &state_dir;
        let mut t = Tracker {
            fda: paths::full_disk_access(),
            home,
            exclude,
            baseline: HashMap::new(),
            open: openfiles::OpenFiles::default(),
            writes: VecDeque::new(),
            last_snap: 0,
            names: HashMap::new(),
            vols: None,
            vol_samples: VecDeque::new(),
            last_vol: 0,
            #[cfg(target_os = "macos")]
            mac: Mac {
                journal: None,
                clock: fsevents::IdClock::load(state_dir.map(|d| d.join("fsevents-clock.tsv"))),
                journal_from_ms: 0,
            },
            #[cfg(target_os = "linux")]
            watch: None,
        };
        #[cfg(target_os = "macos")]
        t.start_journal(now_ms() - JOURNAL_BACK_MS);
        #[cfg(target_os = "linux")]
        {
            let mut dirs = vec![];
            if !t.home.is_empty() && t.home != "/" {
                dirs.push(t.home.clone());
                if let Ok(rd) = std::fs::read_dir(&t.home) {
                    let mut kids: Vec<String> = rd
                        .flatten()
                        .filter(|e| e.file_type().is_ok_and(|f| f.is_dir()))
                        .map(|e| e.path().to_string_lossy().into_owned())
                        .collect();
                    kids.sort();
                    dirs.extend(kids.into_iter().take(60));
                }
            }
            for d in ["/tmp", "/var/tmp", "/var/log", "/var/cache", "/var/lib"] {
                dirs.push(d.to_string());
            }
            t.watch = Some(watch::Watcher::start(t.exclude.clone(), EVENT_CAP, dirs));
        }
        t
    }

    #[cfg(target_os = "macos")]
    fn start_journal(&mut self, from_ms: Ts) {
        self.mac.clock.anchor_now();
        let cur = fsevents::current_id();
        // Root can ask fseventsd directly; normal users get 0 there.
        let root_id = if unsafe { libc::geteuid() } == 0 {
            std::fs::metadata("/")
                .map(|m| fsevents::id_before(std::os::unix::fs::MetadataExt::dev(&m), from_ms))
                .unwrap_or(0)
        } else {
            0
        };
        let since = self
            .mac
            .clock
            .id_at(from_ms)
            .or((root_id > 0).then_some(root_id))
            .unwrap_or_else(|| {
                let rate = self.mac.clock.rate().unwrap_or(DEFAULT_ID_RATE).max(0.05);
                cur.saturating_sub(((now_ms() - from_ms).max(0) as f64 * rate) as u64)
                    .max(1)
            });
        self.mac.journal = Some(fsevents::Journal::start(
            vec!["/".into()],
            since,
            EVENT_CAP,
            self.exclude.clone(),
        ));
        self.mac.journal_from_ms = from_ms;
    }

    /// Feed each collector snapshot (per-process write rates, for open-file attribution).
    pub fn observe(&mut self, snap: &Snapshot) {
        let ts = if snap.ts > 0 { snap.ts } else { now_ms() };
        let dt = if self.last_snap > 0 {
            (ts - self.last_snap).clamp(0, 10_000)
        } else {
            2_000
        };
        self.last_snap = ts;
        let w: Vec<(u32, String, u64)> = snap
            .procs
            .iter()
            .filter(|p| p.disk_write_bps > 0)
            .map(|p| (p.pid, p.name.clone(), p.disk_write_bps))
            .collect();
        if !w.is_empty() {
            self.writes.push_back((ts, dt, w));
        }
        while self.writes.front().is_some_and(|x| ts - x.0 > KEEP_MS) || self.writes.len() > 5000 {
            self.writes.pop_front();
        }
        self.names.clear();
        self.names.extend(snap.procs.iter().map(|p| (p.pid, p.name.clone())));
        self.open.maybe_scan(snap, &self.exclude);
        // Feed open-file sizes into the shared baseline so journal paths get real deltas.
        for (p, t) in &self.open.files {
            if t.last_seen == self.open.last_scan
                && let Some(&(ts, sz)) = t.samples.last()
            {
                Self::remember(&mut self.baseline, p, ts, sz, None);
            }
        }
        if ts - self.last_vol >= 10_000 {
            self.sample_volumes(ts);
        }
        #[cfg(target_os = "macos")]
        self.mac.clock.anchor_now();
    }

    fn sample_volumes(&mut self, ts: Ts) {
        let v = self.vols.get_or_insert_with(super::volumes::Volumes::new).sample();
        self.last_vol = ts;
        self.vol_samples
            .push_back((ts, v.into_iter().map(|v| (v.mount, v.used, v.remote)).collect()));
        while self.vol_samples.front().is_some_and(|x| ts - x.0 > KEEP_MS) {
            self.vol_samples.pop_front();
        }
    }

    fn remember(map: &mut HashMap<String, Seen>, path: &str, ts: Ts, size: u64, birth: Option<i64>) {
        if map.len() >= BASELINE_CAP && !map.contains_key(path) {
            let cut = ts - KEEP_MS;
            map.retain(|_, s| s.samples.last().is_some_and(|x| x.0 >= cut));
            if map.len() >= BASELINE_CAP {
                // Still full: forget the stalest half.
                let mut v: Vec<(Ts, String)> = map
                    .iter()
                    .map(|(k, s)| (s.samples.last().map(|x| x.0).unwrap_or(0), k.clone()))
                    .collect();
                v.sort();
                for (_, k) in v.into_iter().take(BASELINE_CAP / 2) {
                    map.remove(&k);
                }
            }
        }
        let s = map.entry(path.to_string()).or_default();
        if birth.is_some() {
            s.birth = birth;
        }
        if s.samples.last().is_some_and(|x| ts - x.0 < 2_000) {
            let n = s.samples.len();
            s.samples[n - 1] = (ts, size);
        } else {
            openfiles::push_sample(&mut s.samples, ts, size);
        }
    }

    /// Build the report for the last `window_ms`, optionally limited to paths under `under`.
    /// `history` gives recorder data (volume series, process writes, recorded dir sizes) when present.
    pub fn report(
        &mut self,
        window_ms: i64,
        under: Option<&str>,
        history: Option<&crate::history::History>,
        scanner: Option<&super::scan::Scanner>,
    ) -> Growth {
        let window_ms = if window_ms > 0 {
            window_ms
        } else {
            super::DEFAULT_WINDOW_MS
        };
        let now = now_ms();
        let from = now - window_ms;
        let root = match under {
            Some(u) if !u.is_empty() => {
                let u = rollup::normalize(u);
                std::fs::canonicalize(&u)
                    .map(|c| c.to_string_lossy().into_owned())
                    .unwrap_or(u)
            }
            _ => "/".to_string(),
        };
        let mut notes: Vec<String> = vec![];
        let mut obs: Vec<Obs> = vec![];
        // Protected roots may be stat'ed with FDA or when the user explicitly asked for them.
        let explicit_prot = under.is_some() && paths::protected_root(&root, &self.home).is_some();
        let may_stat = |p: &str, home: &str| explicit_prot || paths::protected_root(p, home).is_none();

        // 1. Live/retroactive events.
        #[cfg(target_os = "macos")]
        let (live, exact_cover) = self.fsevents_obs(from, now, &root, &may_stat, &mut notes);
        #[cfg(target_os = "linux")]
        let (live, exact_cover) = self.watch_obs(from, now, &root, scanner, &mut notes);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let (live, exact_cover): (Vec<Obs>, bool) = (vec![], false);
        obs.extend(live);

        // 2. Open files of writers.
        if self.open.scans > 0 {
            obs.extend(self.open.obs(from).into_iter().filter(|o| under_prefix(&o.path, &root)));
        } else {
            notes
                .push("open-file attribution needs a running fat (TUI or `fat record`) feeding process samples".into());
        }

        // 3. Scan diff from recorded dir sizes.
        if let Some(h) = history {
            obs.extend(scan_diff(h, scanner, &root, from, now, window_ms, &mut notes));
        }

        // 4. Mtime fallback.
        if !exact_cover {
            obs.extend(self.mtime_obs(from, &root, scanner, &may_stat, &mut notes));
        }

        // Scanner listings as baselines for files whose delta is unknown.
        if let Some(sc) = scanner {
            obs.extend(scanner_baselines(sc, &obs, from));
        }

        let items = rollup::merge(obs);
        let mut growers = rollup::rollup(&root, items, MAX_GROWERS);
        if let Some(sc) = scanner {
            for g in growers.iter_mut().filter(|g| g.is_dir) {
                if let Some(l) = sc.list(&g.path) {
                    g.size = g.size.max(l.dir.size);
                }
            }
        }
        // Writer pids from fanotify carry no rate: fill in names/rates from the last snapshot.
        let last_rates: HashMap<u32, u64> = self
            .writes
            .back()
            .map(|w| w.2.iter().map(|x| (x.0, x.2)).collect())
            .unwrap_or_default();
        for g in &mut growers {
            for w in &mut g.writers {
                if w.1.is_empty() {
                    w.1 = self.proc_name(w.0);
                }
                if w.2 == 0 {
                    w.2 = last_rates.get(&w.0).copied().unwrap_or(0);
                }
            }
        }

        // Volumes.
        let volumes = self.volume_deltas(from, now, &root, history, &mut notes);
        // Writers.
        let mut writers: Vec<(u32, String, u64)> =
            history.and_then(|h| h.proc_writes(from, now).ok()).unwrap_or_default();
        if writers.is_empty() {
            writers = self.observed_writes(from);
        }
        writers.truncate(10);
        let deleted_open = super::volumes::deleted_open();

        // Unexplained growth.
        if let Some((m, d)) = volumes
            .iter()
            .find(|v| v.1 > 0 && (root == "/" || under_prefix(&root, &v.0)))
            .cloned()
        {
            let explained: i64 = top_level_sum(&growers);
            if d > 64 << 20 && explained * 2 < d {
                notes.push(format!(
                    "{} of {m}'s +{} is not attributed to paths (APFS snapshots/purgeable, swap, protected dirs, or files modified without a baseline size)",
                    human(d - explained.max(0)),
                    human(d)
                ));
            }
        }
        let mut seen_notes = std::collections::HashSet::new();
        notes.retain(|n| seen_notes.insert(n.clone()));
        Growth {
            from,
            to: now,
            volumes,
            growers,
            writers,
            deleted_open,
            notes,
        }
    }

    fn proc_name(&self, pid: u32) -> String {
        if let Some(n) = self.names.get(&pid) {
            return n.clone();
        }
        #[cfg(target_os = "linux")]
        if let Ok(c) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            return c.trim().to_string();
        }
        String::new()
    }

    fn observed_writes(&self, from: Ts) -> Vec<(u32, String, u64)> {
        let mut by: HashMap<u32, (String, f64)> = HashMap::new();
        for (ts, dt, w) in &self.writes {
            if *ts < from {
                continue;
            }
            for (pid, name, bps) in w {
                let e = by.entry(*pid).or_insert_with(|| (name.clone(), 0.0));
                e.1 += *bps as f64 * *dt as f64 / 1000.0;
            }
        }
        let mut v: Vec<(u32, String, u64)> = by
            .into_iter()
            .map(|(p, (n, b))| (p, n, b as u64))
            .filter(|x| x.2 > 0)
            .collect();
        v.sort_by(|a, b| b.2.cmp(&a.2));
        v
    }

    fn volume_deltas(
        &mut self,
        from: Ts,
        now: Ts,
        root: &str,
        history: Option<&crate::history::History>,
        notes: &mut Vec<String>,
    ) -> Vec<(String, i64)> {
        self.sample_volumes(now);
        let latest: Vec<(String, u64, bool)> = self.vol_samples.back().map(|s| s.1.clone()).unwrap_or_default();
        let mut out: Vec<(String, i64)> = vec![];
        for (mount, used, remote) in &latest {
            if *remote {
                continue;
            }
            let mut base: Option<u64> = None;
            if let Some(h) = history
                && let Ok(series) = h.volume_series(mount, from, now)
                && let Some(first) = series.first()
                && first.0 <= from + 60_000
            {
                base = Some(first.1);
            }
            if base.is_none() {
                let s = self
                    .vol_samples
                    .iter()
                    .rev()
                    .find(|x| x.0 <= from)
                    // Only a sample that covers most of the window: a delta over the last few
                    // seconds of a one-shot CLI run would read as "the window's growth".
                    .or_else(|| self.vol_samples.front().filter(|x| x.0 < now && x.0 <= from + ((now - from) / 4).max(30_000)));
                base = s.and_then(|x| x.1.iter().find(|v| v.0 == *mount).map(|v| v.1));
            }
            if let Some(b) = base {
                out.push((mount.clone(), *used as i64 - b as i64));
            }
        }
        if out.is_empty() && !latest.is_empty() {
            notes.push("volume deltas need recorder history (`fat record`) or a fat that has been running".into());
        }
        if root != "/" {
            let vols: Vec<super::Volume> = latest
                .iter()
                .map(|(m, _, _)| super::Volume {
                    mount: m.clone(),
                    ..Default::default()
                })
                .collect();
            if let Some(v) = super::volumes::volume_for(&vols, root) {
                let m = v.mount.clone();
                out.retain(|x| x.0 == m);
            }
        }
        out.sort_by(|a, b| b.1.cmp(&a.1));
        out
    }

    /// Turn per-path events into observations: stat surviving paths, use baselines.
    /// `exact_times`: the stamps are wall-clock (Linux), so F_CREATED in window is reliable.
    fn events_to_obs(
        &mut self,
        entries: Vec<(String, PathEv)>,
        from: Ts,
        ev: Evidence,
        may_stat: &dyn Fn(&str, &str) -> bool,
        exact_times: bool,
        pre: Option<&HashMap<String, Option<paths::FileStat>>>,
    ) -> Vec<Obs> {
        let now = now_ms();
        let mut out = vec![];
        let mut prot: HashMap<String, u64> = HashMap::new();
        for (path, e) in entries {
            if e.flags & F_AGG != 0 {
                let mut o = Obs::new(path, ev);
                o.is_dir = true;
                o.touched = e.count as u64;
                out.push(o);
                continue;
            }
            if !may_stat(&path, &self.home) {
                let r = paths::protected_root(&path, &self.home).unwrap_or(path);
                *prot.entry(r).or_default() += 1;
                continue;
            }
            let st = match pre.and_then(|m| m.get(&path)) {
                Some(s) => *s,
                None => paths::lstat(&path),
            };
            let seen = self.baseline.get(&path).cloned();
            let mut o = Obs::new(path.clone(), ev);
            o.touched = 1;
            o.writers = e.pids.iter().map(|&p| (p, String::new(), 0)).collect();
            match st {
                Some(s) if s.is_file => {
                    o.size = Some(s.alloc);
                    let created = match s.birth_ms {
                        Some(b) => b >= from,
                        None => exact_times && e.flags & F_CREATED != 0,
                    };
                    let before = seen
                        .as_ref()
                        .and_then(|x| x.samples.iter().rev().find(|y| y.0 <= from).map(|y| y.1));
                    let after = seen.as_ref().and_then(|x| x.samples.first().map(|y| y.1));
                    o.delta = match (before, created, after) {
                        (Some(b), _, _) => Some(s.alloc as i64 - b as i64),
                        (None, true, _) => Some(s.alloc as i64),
                        (None, false, Some(a)) => Some(s.alloc as i64 - a as i64),
                        _ => None,
                    };
                    // Hardlinked files: count once, only when created here.
                    if s.nlink > 1 && !created {
                        o.delta = o.delta.map(|_| 0);
                    }
                    Self::remember(
                        &mut self.baseline,
                        &path,
                        now,
                        s.alloc,
                        created.then_some(s.birth_ms.unwrap_or(now)),
                    );
                }
                Some(_) => continue, // dirs, symlinks, devices
                None => {
                    if e.flags & F_DIR != 0 {
                        continue;
                    }
                    let born_in_window = seen.as_ref().and_then(|x| x.birth).is_some_and(|b| b >= from);
                    let last = seen.as_ref().and_then(|x| x.samples.last().map(|y| y.1));
                    o.delta = match (born_in_window, last) {
                        (true, _) => Some(0),
                        (false, Some(l)) => Some(-(l as i64)),
                        (false, None) => None,
                    };
                    o.size = Some(0);
                    self.baseline.remove(&path);
                }
            }
            out.push(o);
        }
        for (r, n) in prot {
            let mut o = Obs::new(r, ev);
            o.is_dir = true;
            o.touched = n;
            out.push(o);
        }
        out
    }

    #[cfg(target_os = "macos")]
    fn fsevents_obs(
        &mut self,
        from: Ts,
        now: Ts,
        root: &str,
        may_stat: &dyn Fn(&str, &str) -> bool,
        notes: &mut Vec<String>,
    ) -> (Vec<Obs>, bool) {
        self.mac.clock.anchor_now();
        // Window older than the live journal: restart it further back (it keeps tailing).
        if self.mac.journal.is_none() || from < self.mac.journal_from_ms - 30_000 {
            self.start_journal(from - 60_000);
        }
        let t0 = std::time::Instant::now();
        let mut tries = 0;
        loop {
            tries += 1;
            let Some(j) = self.mac.journal.as_ref() else {
                return (vec![], false);
            };
            let done = j.wait_history(
                HISTORY_WAIT
                    .saturating_sub(t0.elapsed())
                    .max(std::time::Duration::from_millis(500)),
            );
            let since_id = j.since_id;
            let (err, dropped) = {
                let st = j.state.lock().unwrap();
                (st.error.clone(), st.dropped)
            };
            if let Some(e) = err {
                notes.push(format!("FSEvents unavailable: {e}"));
                return (vec![], false);
            }
            // Window start as an event id: fat's clock, else fit file ctimes of a sample of
            // the whole journal (then remember the fit as an anchor).
            let mut boundary = self.mac.clock.id_at(from);
            if boundary.is_none() {
                let sample: Vec<(String, u64)> = {
                    let st = j.state.lock().unwrap();
                    let step = (st.paths.len() / 4000).max(1);
                    st.paths
                        .iter()
                        .filter(|(_, e)| e.flags & (F_AGG | F_REMOVED) == 0)
                        .step_by(step)
                        .map(|(p, e)| (p.clone(), e.last as u64))
                        .collect()
                };
                let mut pairs: Vec<(u64, i64)> = sample
                    .iter()
                    .filter(|(p, _)| may_stat(p, &self.home))
                    .filter_map(|(p, id)| paths::lstat(p).filter(|s| s.is_file).map(|s| (*id, s.ctime_ms)))
                    .collect();
                boundary = fsevents::fit_boundary(&mut pairs, from);
                match boundary {
                    Some(b) => self.mac.clock.insert_fitted(from, b),
                    None if pairs.is_empty() && done => boundary = Some(since_id),
                    None => {}
                }
            }
            let b = match boundary {
                Some(b) if b + 1 < since_id && tries < 3 => {
                    // The window starts before the journal: replay from the exact id.
                    self.mac.journal = Some(fsevents::Journal::start(
                        vec!["/".into()],
                        b,
                        EVENT_CAP,
                        self.exclude.clone(),
                    ));
                    self.mac.journal_from_ms = from;
                    continue;
                }
                Some(b) => b,
                None if tries < 3 && t0.elapsed() < std::time::Duration::from_secs(20) => {
                    // Every sampled file changed after `from`: history does not reach back far enough.
                    let span = (now - self.mac.journal_from_ms).max(60_000);
                    self.start_journal(self.mac.journal_from_ms - span);
                    continue;
                }
                None => {
                    notes.push(
                        "FSEvents: could not place the window start in the journal; counting every replayed event"
                            .into(),
                    );
                    since_id
                }
            };
            if !done {
                notes.push(format!(
                    "FSEvents history replay still running after {:.0?}: results are partial",
                    t0.elapsed()
                ));
            }
            if dropped > 0 {
                notes.push(format!(
                    "FSEvents coalesced {dropped} event batches (heavy churn): some paths may be missing"
                ));
            }
            // Drop entries too old to matter for any window we serve.
            let keep = self.mac.clock.id_at(now - KEEP_MS);
            let in_window: Vec<(String, PathEv)> = {
                let mut st = j.state.lock().unwrap();
                if let Some(k) = keep {
                    st.paths.retain(|_, e| e.last as u64 > k);
                }
                st.paths
                    .iter()
                    .filter(|(p, e)| e.last as u64 > b && under_prefix(p, root))
                    .map(|(p, e)| (p.clone(), e.clone()))
                    .collect()
            };
            if !self.fda {
                notes.push("no Full Disk Access: changes inside TCC-protected folders (Documents, Desktop, Downloads, Mail, app containers...) are counted, not sized".into());
            }
            let o = self.events_to_obs(in_window, from, Evidence::Fsevents, may_stat, false, None);
            return (o, done);
        }
    }

    #[cfg(target_os = "linux")]
    fn watch_obs(
        &mut self,
        from: Ts,
        now: Ts,
        root: &str,
        scanner: Option<&super::scan::Scanner>,
        notes: &mut Vec<String>,
    ) -> (Vec<Obs>, bool) {
        let Some(w) = self.watch.as_ref() else {
            return (vec![], false);
        };
        let mode = w.mode();
        if mode == watch::Mode::Inotify
            && let Some(sc) = scanner
        {
            let hot: Vec<String> = sc
                .largest(root, 40)
                .into_iter()
                .filter(|d| d.is_dir && !d.mount_point)
                .map(|d| d.path)
                .collect();
            w.add_dirs(&hot);
        }
        let (entries, started, overflow, marked, errors, partial) = {
            let mut s = w.state.lock().unwrap();
            s.paths.retain(|_, e| now - e.last < KEEP_MS);
            let v: Vec<(String, PathEv)> = s
                .paths
                .iter()
                .filter(|(p, e)| e.last >= from && under_prefix(p, root))
                .map(|(p, e)| (p.clone(), e.clone()))
                .collect();
            (v, s.started, s.overflow, s.marked.len(), s.errors.clone(), s.partial)
        };
        let hhmm = |t: Ts| {
            chrono::DateTime::from_timestamp_millis(t)
                .map(|d| d.with_timezone(&chrono::Local).format("%H:%M").to_string())
                .unwrap_or_default()
        };
        match mode {
            watch::Mode::Fanotify => notes.push(format!("fanotify on {marked} filesystem(s) since {}", hhmm(started))),
            watch::Mode::Inotify => {
                let why = if unsafe { libc::geteuid() } == 0 {
                    "fanotify unavailable"
                } else {
                    "fanotify needs root"
                };
                notes.push(format!(
                    "{why}; using inotify on {marked} dirs (non-recursive) since {}",
                    hhmm(started)
                ));
            }
            watch::Mode::Off => notes.push(format!("no file watch available: {}", errors.join("; "))),
        }
        if mode == watch::Mode::Fanotify && !errors.is_empty() {
            notes.push(format!("fanotify: {}", errors.join("; ")));
        }
        if overflow > 0 {
            notes.push(format!(
                "watch queue overflowed {overflow} times: some changes were missed"
            ));
        }
        if started > from + 5_000 {
            notes.push(format!(
                "watch only covers the last {} min of the window (since fat started)",
                (now - started) / 60_000
            ));
        }
        let cover = mode == watch::Mode::Fanotify && !partial && started <= from + 5_000 && overflow == 0;
        let o = self.events_to_obs(entries, from, Evidence::Watch, &|_, _| true, true, None);
        (o, cover)
    }

    fn mtime_obs(
        &mut self,
        from: Ts,
        root: &str,
        scanner: Option<&super::scan::Scanner>,
        may_stat: &dyn Fn(&str, &str) -> bool,
        notes: &mut Vec<String>,
    ) -> Vec<Obs> {
        let mut roots: Vec<String> = vec![];
        if let Some(sc) = scanner {
            roots = sc
                .largest(root, 12)
                .into_iter()
                .filter(|d| d.is_dir && !d.mount_point)
                .map(|d| d.path)
                .collect();
            roots.retain(|r| may_stat(r, &self.home));
            roots.truncate(6);
        }
        if roots.is_empty() {
            if root != "/" {
                roots.push(root.to_string());
            } else {
                if !self.home.is_empty() && self.home != "/" {
                    roots.push(self.home.clone());
                }
                for d in ["/var/log", "/var/lib", "/var/tmp", "/tmp", "/opt"] {
                    if std::path::Path::new(d).is_dir() {
                        roots.push(d.to_string());
                    }
                }
            }
        }
        let home = self.home.clone();
        let excl = self.exclude.clone();
        let skip = |p: &str| !may_stat(p, &home) || paths::is_pseudo_path(p) || excl.iter().any(|e| under_prefix(p, e));
        let w = mtime::walk(&roots, from, MTIME_BUDGET, 20_000, &skip);
        notes.push(format!(
            "mtime scan of {} ({} dirs, {} files{}): modified files are an upper bound",
            roots.join(", "),
            w.dirs,
            w.files,
            if w.truncated { ", time budget hit" } else { "" }
        ));
        let entries: Vec<(String, PathEv)> = w
            .hits
            .iter()
            .filter(|(p, _)| !excl.iter().any(|e| under_prefix(p, e)))
            .map(|(p, _)| {
                (
                    p.clone(),
                    PathEv {
                        flags: F_MODIFIED,
                        count: 1,
                        ..Default::default()
                    },
                )
            })
            .collect();
        let pre: HashMap<String, Option<paths::FileStat>> = w.hits.into_iter().map(|(p, s)| (p, Some(s))).collect();
        let mut o = self.events_to_obs(entries, from, Evidence::Mtime, may_stat, false, Some(&pre));
        // Without a birth time or baseline the current size is the (upper-bound) growth.
        for x in &mut o {
            if x.delta.is_none()
                && let Some(Some(s)) = pre.get(&x.path)
                && s.birth_ms.is_none()
            {
                x.delta = Some(s.alloc as i64);
            }
        }
        o
    }

    /// Test hook: the number of paths the live journal/watch currently holds.
    #[cfg(test)]
    fn live_paths(&self) -> usize {
        #[cfg(target_os = "macos")]
        return self
            .mac
            .journal
            .as_ref()
            .map(|j| j.state.lock().unwrap().paths.len())
            .unwrap_or(0);
        #[cfg(target_os = "linux")]
        return self
            .watch
            .as_ref()
            .map(|w| w.state.lock().unwrap().paths.len())
            .unwrap_or(0);
        #[allow(unreachable_code)]
        0
    }
}

/// Sum of deltas of growers not nested in another listed grower.
fn top_level_sum(g: &[crate::fs::Grower]) -> i64 {
    g.iter()
        .filter(|x| !g.iter().any(|y| y.path != x.path && under_prefix(&x.path, &y.path)))
        .map(|x| x.delta)
        .sum()
}

pub(crate) fn human(b: i64) -> String {
    let a = b.unsigned_abs() as f64;
    let (v, u) = if a >= 1e9 {
        (a / 1e9, "GB")
    } else if a >= 1e6 {
        (a / 1e6, "MB")
    } else if a >= 1e3 {
        (a / 1e3, "kB")
    } else {
        (a, "B")
    };
    let s = if b < 0 { "-" } else { "" };
    if u == "B" {
        format!("{s}{v:.0} {u}")
    } else {
        format!("{s}{v:.1} {u}")
    }
}

/// Evidence::ScanDiff: recorded dir sizes near window start vs the latest snapshot (or the
/// scanner's current numbers). Only movements >= 1 MiB; a dir total is a floor (see rollup).
fn scan_diff(
    h: &crate::history::History,
    scanner: Option<&super::scan::Scanner>,
    root: &str,
    from: Ts,
    now: Ts,
    window_ms: i64,
    notes: &mut Vec<String>,
) -> Vec<Obs> {
    let Ok(Some((t0, old))) = h.dir_sizes_near(from, root) else {
        return vec![];
    };
    if t0 < from - window_ms.max(10 * 60_000) {
        return vec![];
    }
    let (t1, new, complete) = match h.dir_sizes_near(now, root) {
        Ok(Some((t1, v))) if t1 > t0 && t1 >= from => (t1, v, true),
        _ => match scanner {
            Some(sc) => (now, sc.sizes(root, 4).into_iter().collect::<Vec<_>>(), false),
            None => return vec![],
        },
    };
    let oldm: HashMap<&str, u64> = old.iter().map(|(p, s)| (p.as_str(), *s)).collect();
    let mut out = vec![];
    let mut seen: std::collections::HashSet<&str> = Default::default();
    for (p, s) in &new {
        seen.insert(p.as_str());
        if let Some(&o) = oldm.get(p.as_str()) {
            let d = *s as i64 - o as i64;
            if d.abs() >= 1 << 20 {
                let mut x = Obs::new(p.clone(), Evidence::ScanDiff);
                x.is_dir = true;
                x.delta = Some(d);
                x.size = Some(*s);
                x.total = true;
                out.push(x);
            }
        }
    }
    if complete {
        for (p, o) in &old {
            if !seen.contains(p.as_str()) && *o >= 1 << 20 {
                let mut x = Obs::new(p.clone(), Evidence::ScanDiff);
                x.is_dir = true;
                x.delta = Some(-(*o as i64));
                x.size = Some(0);
                x.total = true;
                out.push(x);
            }
        }
    }
    if !out.is_empty() {
        let fmt = |t: Ts| {
            chrono::DateTime::from_timestamp_millis(t)
                .map(|d| d.with_timezone(&chrono::Local).format("%H:%M").to_string())
                .unwrap_or_default()
        };
        notes.push(format!(
            "scan diff {}–{} ({} dirs moved >= 1 MiB)",
            fmt(t0),
            fmt(t1),
            out.len()
        ));
    }
    out
}

/// For files with an unknown delta, use the scanner's earlier listing of their parent dir.
fn scanner_baselines(sc: &super::scan::Scanner, obs: &[Obs], from: Ts) -> Vec<Obs> {
    let mut by_parent: HashMap<&str, Vec<&Obs>> = HashMap::new();
    for o in obs
        .iter()
        .filter(|o| o.delta.is_none() && !o.is_dir && o.size.is_some_and(|s| s > 0))
    {
        if let Some(p) = parent_of(&o.path) {
            by_parent.entry(p).or_default().push(o);
        }
    }
    let mut parents: Vec<(&str, Vec<&Obs>)> = by_parent.into_iter().collect();
    // Biggest current files first; bounded number of listings.
    parents.sort_by_key(|(_, v)| std::cmp::Reverse(v.iter().filter_map(|o| o.size).sum::<u64>()));
    let mut out = vec![];
    for (p, files) in parents.into_iter().take(100) {
        let Some(l) = sc.list(p) else { continue };
        for o in files {
            let name = o.path.rsplit('/').next().unwrap_or("");
            if let Some(c) = l.children.iter().find(|c| !c.is_dir && c.name == name)
                && c.scanned_at > 0
                && c.scanned_at <= from
            {
                let mut x = Obs::new(o.path.clone(), Evidence::ScanDiff);
                x.delta = Some(o.size.unwrap_or(0) as i64 - c.size as i64);
                x.size = o.size;
                out.push(x);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_event_bounds_memory() {
        let mut m = HashMap::new();
        for i in 0..1000 {
            record_event(&mut m, 100, &format!("/a/b/c{}/f{i}", i % 7), F_CREATED, i, 0);
        }
        assert!(m.len() <= 100 + 7 + 2, "{}", m.len());
        let agg: Vec<_> = m.iter().filter(|(_, e)| e.flags & F_AGG != 0).collect();
        assert!(!agg.is_empty());
        let total: u32 = m.values().map(|e| e.count).sum();
        assert_eq!(total, 1000, "no event lost while folding");
        record_event(&mut m, 100, "/a/b/c0/f0", F_MODIFIED, 5000, 9);
        let e = &m["/a/b/c0/f0"];
        assert_eq!(e.flags, F_CREATED | F_MODIFIED);
        assert_eq!((e.count, e.last, e.pids.clone()), (2, 5000, vec![9]));
    }

    #[test]
    fn prefix_matching() {
        assert!(under_prefix("/a/b", "/a"));
        assert!(under_prefix("/a", "/a/"));
        assert!(!under_prefix("/ab", "/a"));
        assert!(under_prefix("/x", "/"));
        assert_eq!(parent_of("/a/b"), Some("/a"));
        assert_eq!(parent_of("/a"), Some("/"));
        assert_eq!(parent_of("/"), None);
        assert_eq!(human(1_500_000), "1.5 MB");
        assert_eq!(human(-2_000), "-2.0 kB");
    }

    fn scratch(tag: &str) -> PathBuf {
        let base = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let d = base.join(format!("fat-growth-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    /// Events -> obs: created file counts its size, a modified file uses its baseline, a
    /// removed file with a baseline counts negative, unknown stays unknown.
    #[test]
    fn events_to_obs_deltas() {
        let d = scratch("e2o");
        let mut t = Tracker::with_state_dir(None);
        let from = now_ms() - 60_000;
        let newf = d.join("new.bin");
        std::fs::write(&newf, vec![1u8; 64 * 1024]).unwrap();
        let oldf = d.join("old.log");
        std::fs::write(&oldf, vec![1u8; 8 * 1024]).unwrap();
        let gone = d.join("gone.bin");
        let s = |p: &PathBuf| p.to_string_lossy().into_owned();
        // Baselines from "before the window".
        Tracker::remember(&mut t.baseline, &s(&oldf), from - 10_000, 4096, None);
        Tracker::remember(&mut t.baseline, &s(&gone), from - 10_000, 1 << 20, None);
        let ev = |f| PathEv {
            flags: f,
            count: 1,
            ..Default::default()
        };
        let entries = vec![
            (s(&newf), ev(F_CREATED)),
            (s(&oldf), ev(F_MODIFIED)),
            (s(&gone), ev(F_REMOVED)),
            (s(&d.join("never")), ev(F_REMOVED)),
        ];
        let o = t.events_to_obs(entries, from, Evidence::Watch, &|_, _| true, true, None);
        let get = |n: &str| o.iter().find(|x| x.path.ends_with(n)).unwrap();
        let nb = get("new.bin");
        assert!(nb.delta.unwrap() >= 64 * 1024, "{nb:?}");
        let ol = get("old.log");
        assert_eq!(ol.delta, Some(ol.size.unwrap() as i64 - 4096));
        assert_eq!(get("gone.bin").delta, Some(-(1 << 20)));
        assert_eq!(get("never").delta, None);
        assert_eq!(get("never").touched, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Protected paths are attributed by count to their protected root and never stat'ed.
    #[test]
    fn protected_paths_counted_not_stated() {
        let mut t = Tracker::with_state_dir(None);
        t.home = "/Users/zz-test".into();
        let ev = PathEv {
            flags: F_MODIFIED,
            count: 1,
            ..Default::default()
        };
        let entries = vec![
            ("/Users/zz-test/Documents/a.txt".to_string(), ev.clone()),
            ("/Users/zz-test/Documents/b/c.txt".to_string(), ev.clone()),
        ];
        let may = |p: &str, h: &str| paths::protected_root(p, h).is_none();
        let o = t.events_to_obs(entries, 0, Evidence::Fsevents, &may, false, None);
        if cfg!(target_os = "macos") {
            assert_eq!(o.len(), 1);
            assert_eq!(o[0].path, "/Users/zz-test/Documents");
            assert_eq!(o[0].touched, 2);
            assert_eq!(o[0].delta, None);
        } else {
            // Not protected on Linux: stat'ed (missing) -> unknown removed paths.
            assert_eq!(o.len(), 2);
        }
    }

    /// End to end: a file written by a child process in a scratch dir shows up as a grower of
    /// a report limited to that dir. macOS: FSEvents replay; Linux: watch (inotify/fanotify).
    #[test]
    fn report_sees_new_file_under_dir() {
        let d = scratch("rep");
        let ds = d.to_string_lossy().into_owned();
        let mut t = Tracker::with_state_dir(None);
        #[cfg(target_os = "linux")]
        if let Some(w) = &t.watch {
            w.add_dirs(std::slice::from_ref(&ds));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        let f = d.join("payload.bin");
        let fp = f.to_string_lossy().into_owned();
        let st = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("head -c 3000000 /dev/zero > '{fp}'"))
            .status()
            .unwrap();
        assert!(st.success());
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let g = t.report(5 * 60_000, Some(&ds), None, None);
        eprintln!(
            "growers={:?}\nnotes={:?}\nlive_paths={}",
            g.growers,
            g.notes,
            t.live_paths()
        );
        let hit = g
            .growers
            .iter()
            .find(|x| x.path == fp)
            .unwrap_or_else(|| panic!("{fp} not reported: {:?}", g.growers));
        assert!(hit.delta >= 3_000_000, "{hit:?}");
        assert!(
            hit.evidence.contains(&Evidence::Fsevents)
                || hit.evidence.contains(&Evidence::Watch)
                || hit.evidence.contains(&Evidence::Mtime),
            "{hit:?}"
        );
        drop(t);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A child process appending to a file: two observed snapshots attribute the growth
    /// to it through its open file (Evidence::OpenFiles, writer pid listed).
    #[test]
    fn observe_attributes_open_file_writer() {
        let d = scratch("of");
        let ds = d.to_string_lossy().into_owned();
        let fp = format!("{ds}/app.log");
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "exec >'{fp}'; while :; do head -c 65536 /dev/zero; sleep 0.05; done"
            ))
            .spawn()
            .unwrap();
        let pid = child.id();
        let snap = |ts: Ts| Snapshot {
            ts,
            procs: vec![crate::model::Proc {
                pid,
                name: "sh".into(),
                disk_write_bps: 1_000_000,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut t = Tracker::with_state_dir(None);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let t1 = now_ms();
        t.observe(&snap(t1));
        std::thread::sleep(std::time::Duration::from_millis(800));
        t.observe(&snap(t1 + openfiles::MIN_INTERVAL_MS));
        let _ = child.kill();
        let _ = child.wait();
        let g = t.report(10 * 60_000, Some(&ds), None, None);
        let hit = g
            .growers
            .iter()
            .find(|x| x.path == fp)
            .unwrap_or_else(|| panic!("{fp} missing: {:?} {:?}", g.growers, g.notes));
        assert!(hit.evidence.contains(&Evidence::OpenFiles), "{hit:?}");
        assert!(hit.writers.iter().any(|w| w.0 == pid && w.1 == "sh"), "{hit:?}");
        assert!(hit.delta > 0, "{hit:?}");
        assert!(g.writers.iter().any(|w| w.0 == pid), "{:?}", g.writers);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Manual: time a full 10-minute report on this machine.
    /// `cargo test --release growth::tests::measure_report -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn measure_report() {
        let t0 = std::time::Instant::now();
        let mut t = Tracker::with_state_dir(None);
        let g = t.report(super::super::DEFAULT_WINDOW_MS, None, None, None);
        let first = t0.elapsed();
        let t1 = std::time::Instant::now();
        let g2 = t.report(super::super::DEFAULT_WINDOW_MS, None, None, None);
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
        let rss_mb = if cfg!(target_os = "macos") {
            ru.ru_maxrss as f64 / 1e6
        } else {
            ru.ru_maxrss as f64 / 1e3
        };
        eprintln!(
            "first report {first:?}, second {:?}, live paths {}, max rss {rss_mb:.0} MB, cpu user {:.2}s sys {:.2}s",
            t1.elapsed(),
            t.live_paths(),
            ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 / 1e6,
            ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 / 1e6
        );
        for x in g.growers.iter().take(25) {
            eprintln!(
                "{:>10} {:>10} {:>6} {:?} {}",
                human(x.delta),
                human(x.size as i64),
                x.files_touched,
                x.evidence,
                x.path
            );
        }
        eprintln!("volumes={:?}\nwriters={:?}\nnotes={:#?}", g.volumes, g.writers, g.notes);
        assert!(g2.from > g.from);
    }
}
