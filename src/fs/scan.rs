//! Background, cached, low-priority du. OWNER: fs-scan agent.
//!
//! - Walker: N = min(8, cores/2) std threads share one priority queue of directories
//!   (depth-first so subtrees complete and fold quickly; whatever the user focuses on, or a
//!   blocking CLI scan targets, jumps ahead). Each job reads ONE directory with
//!   openat/fstatat (never following symlinks): allocated = st_blocks*512, apparent = st_size,
//!   hardlinked files counted once per pass, other filesystems recorded as `mount_point`
//!   children (macOS: /System/Volumes/Data is the firmlink alias of what "/" already shows;
//!   it is walked as its own tree minus the firmlinked parts, /System/Volumes/VM likewise).
//! - Index: [`tree`] keeps one node per *kept* directory; files are aggregated, small
//!   completed subtrees folded into their parent (re-expanded when the user focuses one).
//! - Priority: background threads run at QoS background (macOS; also throttles I/O) or
//!   nice 19 + ioprio idle (Linux), under a CPU budget (default 0.25 core), and pause on
//!   battery below 20%. Focused work is not throttled.
//! - macOS privacy: background scans skip TCC-protected locations (Desktop, Documents,
//!   Downloads, Mail, other apps' containers, ...) unless Full Disk Access is granted; an
//!   explicit request (`ensure(path, true)`, `scan_blocking`) reads them.
//! - Cache: [`cache`] (SQLite, ~/.cache/fat/fs-index.db) loaded in `new()`, flushed every 30s
//!   and when a pass ends. One process (holder of `fs-index.db.writer-lock`) scans in the
//!   background; others read its results from the cache and only scan on demand.
//! - Refresh: on start and every 10 min, re-stat kept directories (mtime/ctime change ->
//!   re-read just that directory); full rescan every 6h.

mod cache;
mod sys;
mod tree;

use super::{DirEntry, Listing, ScanProgress};
use crate::model::{Ts, now_ms};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as AO};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use sys::{DirRead, Kind, Policy, under};
use tree::*;

pub use sys::DevHook;

/// Scanner tuning. `Options::default()` is what [`Scanner::new`] uses.
#[derive(Clone)]
pub struct Options {
    /// SQLite index; None = memory only.
    pub cache_path: Option<PathBuf>,
    /// Background walker threads.
    pub threads: usize,
    /// Average CPU budget of background (unfocused) work, in cores.
    pub budget: f32,
    /// CPU budget of work the user is looking at (`focus`), in cores. 0 = unlimited.
    pub focus_budget: f32,
    pub full_interval: Duration,
    pub restat_interval: Duration,
    /// Completed subdirectories smaller than this (deeper than `keep_depth`) are folded.
    pub fold_bytes: u64,
    pub keep_depth: u16,
    /// Files at least this large keep a name in the index (for `largest`).
    pub big_file: u64,
    /// Apply macOS TCC rules.
    pub protect: bool,
    pub extra_protected: Vec<String>,
    pub dev_hook: Option<DevHook>,
    pub battery_check: bool,
    /// Take the background lock and refresh ensured roots on a schedule.
    pub background: bool,
    /// Cache write / (non-writer) cache re-read cadence.
    pub flush_interval: Duration,
    pub reload_interval: Duration,
}

impl Default for Options {
    fn default() -> Self {
        let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
        Options {
            cache_path: Some(cache::default_path()),
            threads: (cores / 2).clamp(1, 8),
            budget: 0.25,
            focus_budget: 1.5,
            full_interval: Duration::from_secs(6 * 3600),
            restat_interval: Duration::from_secs(600),
            fold_bytes: 1 << 20,
            keep_depth: 3,
            big_file: 64 << 20,
            protect: cfg!(target_os = "macos"),
            extra_protected: Vec::new(),
            dev_hook: None,
            battery_check: true,
            background: true,
            flush_interval: Duration::from_secs(30),
            reload_interval: Duration::from_secs(15),
        }
    }
}

/// Files kept by name in a directory the user looks at.
const EXPAND_FILES: usize = 200;

#[derive(PartialEq, Eq)]
struct QItem {
    boost: u8,
    depth: u16,
    seq: u64,
    id: Id,
    stamp: u32,
}
impl Ord for QItem {
    fn cmp(&self, o: &Self) -> Ordering {
        (self.boost, self.depth, std::cmp::Reverse(self.seq)).cmp(&(o.boost, o.depth, std::cmp::Reverse(o.seq)))
    }
}
impl PartialOrd for QItem {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

struct Root {
    path: Vec<u8>,
    background: bool,
    started_at: Ts,
    completed_at: Ts,
    files: u64,
    bytes: u64,
    errors: u64,
    used: Option<u64>,
    full_running: bool,
    last_restat: Ts,
    restat_running: bool,
}

struct Job {
    id: Id,
    stamp: u32,
    path: Vec<u8>,
    expand: bool,
    boosted: bool,
    policy: Arc<Policy>,
}

struct St {
    tree: Tree,
    queue: BinaryHeap<QItem>,
    seq: u64,
    focus: Option<Vec<u8>>,
    blocking: Vec<Vec<u8>>,
    roots: Vec<Root>,
    policy: Arc<Policy>,
    removed: Vec<Vec<u8>>,
    reading: usize,
    started: bool,
    writer: bool,
    last_reload: Ts,
    fold_bytes: u64,
    keep_depth: u16,
    /// Jobs queued / pass roots completed since the last `take_signals` (wakeup accounting).
    pushed: usize,
    finished: bool,
}

struct Shared {
    st: Mutex<St>,
    work: Condvar,
    done: Condvar,
    links: Mutex<HashSet<(u64, u64)>>,
    db: Option<Mutex<cache::Db>>,
    opts: Options,
    shutdown: AtomicBool,
    paused: AtomicBool,
    budget_milli: AtomicU32,
}

struct Handle {
    sh: Arc<Shared>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.sh.shutdown.store(true, AO::SeqCst);
        self.sh.work.notify_all();
        self.sh.done.notify_all();
    }
}

/// Shared handle to the scanner. Cheap to clone; one background worker per process.
#[derive(Clone)]
pub struct Scanner {
    h: Arc<Handle>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Absolute, lexically normalized path bytes (symlinks are not resolved).
fn norm(p: &str) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let push = |s: &[u8], parts: &mut Vec<Vec<u8>>| {
        for c in s.split(|&b| b == b'/') {
            match c {
                b"" | b"." => {}
                b".." => {
                    parts.pop();
                }
                c => parts.push(c.to_vec()),
            }
        }
    };
    if !p.starts_with('/') {
        use std::os::unix::ffi::OsStrExt;
        if let Ok(cwd) = std::env::current_dir() {
            push(cwd.as_os_str().as_bytes(), &mut parts);
        }
    }
    push(p.as_bytes(), &mut parts);
    if parts.is_empty() {
        return b"/".to_vec();
    }
    let mut out = Vec::new();
    for c in parts {
        out.push(b'/');
        out.extend_from_slice(&c);
    }
    out
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn row_of(t: &Tree, id: Id) -> cache::Row {
    let n = t.n(id);
    cache::Row {
        path: t.path(id),
        total: n.total,
        own: n.own,
        flags: n.flags & (F_MOUNT | F_PROTECTED | F_DENIED | F_FOLDED | F_DESCEND),
        at: n.at,
        dev: n.dev,
        ino: n.ino,
        mtime: n.mtime,
        ctime: n.ctime,
        self_size: n.self_size,
        self_apparent: n.self_apparent,
        big: n.big.clone(),
    }
}

impl St {
    fn boost(&self, id: Id) -> u8 {
        if self.focus.is_none() && self.blocking.is_empty() {
            return 0;
        }
        let p = self.tree.path(id);
        if self.blocking.iter().any(|b| under(&p, b) || under(b, &p)) {
            return 2;
        }
        match &self.focus {
            // Focusing a whole background root ("/") is just looking at the overview: it
            // must not turn the full-disk walk into priority work.
            Some(f) if self.roots.iter().any(|r| r.background && r.path == *f) => 0,
            Some(f) if under(&p, f) || under(f, &p) => 1,
            _ => 0,
        }
    }

    fn enqueue(&mut self, id: Id) {
        let boost = self.boost(id);
        let n = self.tree.m(id);
        n.state = State::Queued;
        n.own = Agg::default();
        let (depth, stamp) = (n.depth, n.stamp);
        self.seq += 1;
        self.pushed += 1;
        self.queue.push(QItem { boost, depth, seq: self.seq, id, stamp });
    }

    fn take_signals(&mut self) -> (usize, bool) {
        (std::mem::take(&mut self.pushed), std::mem::take(&mut self.finished))
    }

    fn rebuild_queue(&mut self) {
        let items: Vec<QItem> = std::mem::take(&mut self.queue).into_vec();
        for mut it in items {
            if self.tree.valid(it.id, it.stamp) && self.tree.n(it.id).state == State::Queued {
                it.boost = self.boost(it.id);
                self.queue.push(it);
            }
        }
    }

    fn pop(&mut self, only_boosted: bool) -> Option<Job> {
        loop {
            if only_boosted && self.queue.peek()?.boost == 0 {
                return None;
            }
            let it = self.queue.pop()?;
            if !self.tree.valid(it.id, it.stamp) || self.tree.n(it.id).state != State::Queued {
                continue;
            }
            let n = self.tree.m(it.id);
            n.state = State::Reading;
            let expand = n.has(F_EXPAND);
            self.reading += 1;
            return Some(Job {
                id: it.id,
                stamp: it.stamp,
                path: self.tree.path(it.id),
                expand,
                boosted: it.boost > 0,
                policy: self.policy.clone(),
            });
        }
    }

    /// Queue `id` for a (re)read. `full` resets its whole subtree (every kept dir is re-read);
    /// otherwise only `id` itself is re-read and measured children are reused.
    fn requeue(&mut self, id: Id, full: bool, expand: bool) -> bool {
        let n = self.tree.n(id);
        if n.in_flight() {
            if expand {
                self.tree.m(id).flags |= F_EXPAND;
            }
            return false;
        }
        let parent = n.parent;
        if n.state == State::Done
            && parent != NONE
            && !n.has(F_MOUNT)
            && self.tree.n(parent).state == State::Waiting
            && !n.has(F_COUNTED)
        {
            self.tree.m(parent).pending += 1;
            self.tree.m(id).flags |= F_COUNTED;
        }
        if full {
            let mut stack: Vec<Id> = self.tree.n(id).children.clone();
            while let Some(x) = stack.pop() {
                let n = self.tree.m(x);
                if n.in_flight() {
                    continue;
                }
                n.state = State::Unvisited;
                n.own = Agg::default();
                n.flags &= !(F_EXPAND | F_COUNTED);
                stack.extend(n.children.iter().copied());
            }
        }
        if expand {
            self.tree.m(id).flags |= F_EXPAND;
        }
        self.enqueue(id);
        true
    }

    fn apply(&mut self, job: &Job, res: Result<DirRead, i32>, opts: &Options) {
        self.reading = self.reading.saturating_sub(1);
        let id = job.id;
        if !self.tree.valid(id, job.stamp) || self.tree.n(id).state != State::Reading {
            return;
        }
        let now = now_ms();
        let r = match res {
            Ok(r) => r,
            Err(e) => {
                let denied = e == libc::EACCES || e == libc::EPERM;
                if e != libc::ENOENT && e != libc::ENOTDIR {
                    for root in self.roots.iter_mut().filter(|r| under(&job.path, &r.path)) {
                        root.errors += 1;
                    }
                }
                for c in std::mem::take(&mut self.tree.m(id).children) {
                    self.tree.free_subtree(c, &mut self.removed);
                }
                let n = self.tree.m(id);
                n.big.clear();
                n.flags &= !(F_FOLDED | F_PROTECTED);
                if denied {
                    n.flags |= F_DENIED;
                } else {
                    n.flags &= !F_DENIED;
                }
                n.own = Agg {
                    size: n.self_size,
                    apparent: n.self_apparent,
                    files: 0,
                    newest: sys::secs(n.mtime),
                    denied: denied as u32,
                };
                self.complete(id, opts);
                return;
            }
        };
        for root in self.roots.iter_mut().filter(|rt| under(&job.path, &rt.path)) {
            root.files += r.files.files;
            root.bytes += r.files.size + r.self_size;
            root.errors += r.errors as u64;
        }
        {
            let n = self.tree.m(id);
            n.own = Agg {
                size: r.files.size + r.self_size,
                apparent: r.files.apparent + r.self_apparent,
                files: r.files.files,
                newest: r.files.newest.max(sys::secs(r.mtime)),
                denied: 0,
            };
            n.dev = r.dev;
            n.ino = r.ino;
            n.mtime = r.mtime;
            n.ctime = r.ctime;
            n.self_size = r.self_size;
            n.self_apparent = r.self_apparent;
            n.big = r.big;
            n.flags &= !(F_DENIED | F_FOLDED | F_PROTECTED);
        }
        let old = std::mem::take(&mut self.tree.m(id).children);
        let mut by_name: HashMap<Box<[u8]>, Id> = HashMap::with_capacity(old.len());
        for c in old {
            let name = self.tree.n(c).name.clone();
            if let Some(dup) = by_name.insert(name, c) {
                self.tree.free_subtree(dup, &mut self.removed);
            }
        }
        let mut kids: Vec<Id> = Vec::with_capacity(r.subs.len());
        let mut pending = 0u32;
        let mut to_queue: Vec<Id> = Vec::new();
        for s in r.subs {
            let want = match s.kind {
                Kind::Normal => 0,
                Kind::Mount { descend: false } => F_MOUNT,
                Kind::Mount { descend: true } => F_MOUNT | F_DESCEND,
                Kind::Protected => F_PROTECTED,
            };
            let mask = F_MOUNT | F_DESCEND | F_PROTECTED;
            let c = match by_name.remove(&s.name) {
                Some(c) if self.tree.n(c).flags & mask == want => c,
                other => {
                    if let Some(c) = other {
                        self.tree.free_subtree(c, &mut self.removed);
                    }
                    let c = self.tree.alloc_raw(id, &s.name);
                    self.tree.m(c).flags |= want;
                    c
                }
            };
            kids.push(c);
            let n = self.tree.m(c);
            n.dev = s.dev;
            n.self_size = s.size;
            n.self_apparent = s.apparent;
            n.flags &= !F_MATERIALIZE;
            if n.state != State::Done {
                n.ino = s.ino;
                n.mtime = s.mtime;
                n.ctime = s.ctime;
            }
            match s.kind {
                Kind::Normal => match n.state {
                    State::Unvisited => {
                        n.flags |= F_COUNTED;
                        pending += 1;
                        to_queue.push(c);
                    }
                    State::Queued | State::Reading | State::Waiting => {
                        if !n.has(F_COUNTED) {
                            n.flags |= F_COUNTED;
                            pending += 1;
                        }
                    }
                    State::Done => {}
                },
                Kind::Mount { descend: true } => {
                    if n.state == State::Unvisited {
                        to_queue.push(c);
                    }
                }
                Kind::Mount { descend: false } | Kind::Protected => {
                    let protected = s.kind == Kind::Protected;
                    if n.state != State::Done || n.at == 0 {
                        n.state = State::Done;
                        n.own = Agg { denied: protected as u32, newest: sys::secs(s.mtime), ..Agg::default() };
                        n.total = n.own;
                        n.at = now;
                        n.ino = s.ino;
                        n.mtime = s.mtime;
                        n.ctime = s.ctime;
                        n.flags |= F_DIRTY;
                    }
                    for g in std::mem::take(&mut n.children) {
                        self.tree.free_subtree(g, &mut self.removed);
                    }
                }
            }
        }
        for (_, c) in by_name {
            self.tree.free_subtree(c, &mut self.removed);
        }
        let n = self.tree.m(id);
        n.children = kids;
        n.pending = pending;
        n.state = State::Waiting;
        for c in to_queue {
            self.enqueue(c);
        }
        if pending == 0 {
            self.complete(id, opts);
        }
    }

    fn can_fold(&self, c: Id) -> bool {
        let n = self.tree.n(c);
        n.state == State::Done
            && n.flags & (F_MOUNT | F_PROTECTED | F_DENIED | F_EXPAND) == 0
            && n.depth > self.keep_depth
            && n.total.size < self.fold_bytes
            && n.total.denied == 0
            && n.children.is_empty()
            && n.big.is_empty()
    }

    fn complete(&mut self, mut id: Id, _opts: &Options) {
        let now = now_ms();
        loop {
            if !self.tree.n(id).has(F_EXPAND) {
                let kids = std::mem::take(&mut self.tree.m(id).children);
                let mut keep = Vec::with_capacity(kids.len());
                let mut folded = Agg::default();
                let mut any = false;
                for c in kids {
                    if self.can_fold(c) {
                        folded.add(&self.tree.n(c).total);
                        any = true;
                        self.tree.free_subtree(c, &mut self.removed);
                    } else {
                        keep.push(c);
                    }
                }
                let n = self.tree.m(id);
                n.children = keep;
                if any {
                    n.own.add(&folded);
                    n.flags |= F_FOLDED;
                }
            }
            {
                let n = self.tree.m(id);
                n.state = State::Done;
                n.pending = 0;
                n.at = now;
                n.flags &= !F_EXPAND;
                n.flags |= F_DIRTY;
            }
            self.tree.recompute(id);
            let n = self.tree.n(id);
            let (parent, mount, counted, materialize, total) =
                (n.parent, n.has(F_MOUNT), n.has(F_COUNTED), n.has(F_MATERIALIZE), n.total);
            self.tree.m(id).flags &= !(F_COUNTED | F_MATERIALIZE);
            if parent == NONE || mount {
                self.finished = true;
                return;
            }
            match self.tree.n(parent).state {
                State::Waiting => {
                    if !counted {
                        self.finished = true;
                        return;
                    }
                    let p = self.tree.m(parent);
                    p.pending = p.pending.saturating_sub(1);
                    if p.pending > 0 {
                        return;
                    }
                    id = parent;
                }
                State::Done => {
                    if materialize {
                        self.tree.m(parent).own.sub_sat(&total);
                    }
                    let mut p = parent;
                    while p != NONE && self.tree.n(p).state == State::Done {
                        self.tree.recompute(p);
                        self.tree.m(p).flags |= F_DIRTY;
                        if self.tree.n(p).has(F_MOUNT) {
                            break;
                        }
                        p = self.tree.n(p).parent;
                    }
                    self.finished = true;
                    return;
                }
                _ => {
                    self.finished = true;
                    return;
                }
            }
        }
    }

    fn entry(&self, id: Id, as_child: bool, now: Ts) -> DirEntry {
        let n = self.tree.n(id);
        let (mut a, mut partial, at) = self.tree.display(id, now);
        let mount = n.has(F_MOUNT);
        if mount && (as_child || !n.has(F_DESCEND)) {
            a = Agg { denied: a.denied, newest: a.newest, ..Agg::default() };
            partial = false;
        }
        let name = if id == ROOT { "/".to_string() } else { lossy(&n.name) };
        DirEntry {
            path: lossy(&self.tree.path(id)),
            name,
            is_dir: true,
            size: a.size,
            apparent: a.apparent,
            files: a.files,
            newest_mtime: a.newest,
            denied: a.denied,
            mount_point: mount,
            partial,
            scanned_at: at,
        }
    }

    fn progress_of(&self, r: &Root) -> ScanProgress {
        let node = self.tree.find(&r.path);
        let (running, done) = node.map_or((false, false), |id| {
            let n = self.tree.n(id);
            (n.in_flight() || r.restat_running, n.state == State::Done)
        });
        // A resumed pass reuses cached subtrees it never re-reads: count what is known.
        let known = node.map_or(0, |id| self.tree.live(id).size).max(r.bytes);
        let fraction = if done && !running {
            Some(1.0)
        } else {
            r.used.filter(|&u| u > 0).map(|u| (known as f64 / u as f64).min(0.99) as f32)
        };
        ScanProgress {
            root: lossy(&r.path),
            running,
            files_seen: r.files,
            bytes_seen: r.bytes,
            fraction,
            started_at: r.started_at,
            completed_at: r.completed_at,
            errors: r.errors,
        }
    }

    fn add_root(&mut self, path: &[u8], background: bool, completed_at: Ts) -> usize {
        if let Some(i) = self.roots.iter().position(|r| r.path == path) {
            self.roots[i].background |= background;
            return i;
        }
        self.roots.push(Root {
            path: path.to_vec(),
            background,
            started_at: 0,
            completed_at,
            files: 0,
            bytes: 0,
            errors: 0,
            used: None,
            full_running: false,
            last_restat: 0,
            restat_running: false,
        });
        self.roots.len() - 1
    }

    fn allow(&mut self, path: &[u8]) {
        if !self.policy.allowed(path) {
            let mut p = (*self.policy).clone();
            p.allowed.push(path.to_vec());
            self.policy = Arc::new(p);
        }
    }

    /// Prepare `path` as the root of a (re)scan. Returns false when it may not be scanned
    /// (pseudo fs, or protected/mount without explicit permission): it is marked accordingly.
    fn prepare_root(&mut self, id: Id, path: &[u8]) -> bool {
        let kind = self.policy.root_kind(path);
        let now = now_ms();
        let n = self.tree.m(id);
        match kind {
            Kind::Normal => {
                n.flags &= !F_PROTECTED;
                true
            }
            Kind::Mount { descend: true } => {
                n.flags |= F_MOUNT | F_DESCEND;
                true
            }
            Kind::Mount { descend: false } | Kind::Protected => {
                if !n.in_flight() {
                    n.flags |= if kind == Kind::Protected { F_PROTECTED } else { F_MOUNT };
                    if n.state != State::Done {
                        n.state = State::Done;
                        n.own = Agg { denied: (kind == Kind::Protected) as u32, ..Agg::default() };
                        n.total = n.own;
                        n.at = now;
                    }
                }
                false
            }
        }
    }

    fn merge_rows(&mut self, rows: Vec<cache::Row>) {
        for r in rows {
            let id = self.tree.find_or_create(&r.path);
            let n = self.tree.m(id);
            if n.in_flight() || (n.state == State::Done && n.at > r.at) {
                continue;
            }
            n.total = r.total;
            n.own = r.own;
            n.flags = (n.flags & !(F_MATERIALIZE | F_DIRTY)) | r.flags | F_PERSISTED;
            n.at = r.at;
            n.dev = r.dev;
            n.ino = r.ino;
            n.mtime = r.mtime;
            n.ctime = r.ctime;
            n.self_size = r.self_size;
            n.self_apparent = r.self_apparent;
            n.big = r.big;
            n.state = State::Done;
        }
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    /// Start (or attach to) the scanner. Loads the on-disk cache immediately so callers get
    /// numbers before any scanning. Does not start scanning by itself.
    pub fn new() -> Self {
        static GLOBAL: OnceLock<Scanner> = OnceLock::new();
        GLOBAL.get_or_init(|| Scanner::with_options(Options::default())).clone()
    }

    /// A private scanner (tests, tools). `new()` returns the process-wide one.
    pub fn with_options(opts: Options) -> Self {
        let home: Vec<u8> = {
            use std::os::unix::ffi::OsStrExt;
            dirs::home_dir().map(|h| h.as_os_str().as_bytes().to_vec()).unwrap_or_default()
        };
        let policy = Policy {
            mounts: sys::mounts(),
            fda: !opts.protect || sys::full_disk_access(&home),
            protect: opts.protect,
            home,
            extra_protected: opts.extra_protected.iter().map(|p| norm(p)).collect(),
            allowed: Vec::new(),
            firmlink_skip: sys::firmlink_aliases(),
            dev_hook: opts.dev_hook.clone(),
        };
        let db = opts.cache_path.as_ref().and_then(|p| cache::Db::open(p).ok());
        let mut st = St {
            tree: Tree::new(),
            queue: BinaryHeap::new(),
            seq: 0,
            focus: None,
            blocking: Vec::new(),
            roots: Vec::new(),
            policy: Arc::new(policy),
            removed: Vec::new(),
            reading: 0,
            started: false,
            writer: false,
            last_reload: 0,
            fold_bytes: opts.fold_bytes,
            keep_depth: opts.keep_depth,
            pushed: 0,
            finished: false,
        };
        if let Some(db) = &db {
            if let Ok(rows) = db.load_all() {
                st.merge_rows(rows);
            }
            st.last_reload = db.meta("updated").unwrap_or(0);
        }
        let budget = (opts.budget.max(0.0) * 1000.0) as u32;
        let sh = Arc::new(Shared {
            st: Mutex::new(st),
            work: Condvar::new(),
            done: Condvar::new(),
            links: Mutex::new(HashSet::new()),
            db: db.map(Mutex::new),
            opts,
            shutdown: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            budget_milli: AtomicU32::new(budget),
        });
        Scanner { h: Arc::new(Handle { sh }) }
    }

    fn sh(&self) -> &Arc<Shared> {
        &self.h.sh
    }

    /// Average CPU budget for background (unfocused) scanning, in cores (e.g. raise it while
    /// the Fs tab is visible). 0 = unlimited.
    #[allow(dead_code)] // API for the TUI / CLI
    pub fn set_budget(&self, cores: f32) {
        self.sh().budget_milli.store((cores.max(0.0) * 1000.0) as u32, AO::Relaxed);
    }

    /// Why `path` is not scanned in the background (macOS privacy), if it is not.
    #[allow(dead_code)] // API for the TUI / CLI
    pub fn protected_hint(&self, path: &str) -> Option<&'static str> {
        let st = lock(&self.sh().st);
        let p = norm(path);
        if st.policy.allowed(&p) { None } else { st.policy.protected(&p) }
    }

    /// macOS Full Disk Access detected (always true elsewhere).
    #[allow(dead_code)] // API for the TUI / CLI
    pub fn full_disk_access(&self) -> bool {
        lock(&self.sh().st).policy.fda
    }

    fn start(&self) {
        let sh = self.sh();
        {
            let mut st = lock(&sh.st);
            if st.started {
                return;
            }
            st.started = true;
        }
        for i in 0..sh.opts.threads.max(1) {
            let s = sh.clone();
            let _ = thread::Builder::new().name(format!("fat-scan-{i}")).spawn(move || worker(s, true, None));
        }
        let s = sh.clone();
        let _ = thread::Builder::new().name("fat-scan-sched".into()).spawn(move || coordinator(s));
    }

    /// Ensure `root` (and the volume tree it belongs to) is being kept fresh in the background.
    /// `explicit` = the user asked for it (allows remote/protected paths once).
    pub fn ensure(&self, root: &str, explicit: bool) {
        let p = norm(root);
        let sh = self.sh();
        let completed = sh.db.as_ref().and_then(|db| lock(db).meta(&format!("completed:{}", lossy(&p)))).unwrap_or(0);
        {
            let mut st = lock(&sh.st);
            if explicit {
                st.allow(&p);
            }
            st.add_root(&p, true, completed);
            let id = st.tree.find_or_create(&p);
            let n = st.tree.n(id);
            let blocked = n.has(F_PROTECTED) || n.has(F_DENIED) || (n.has(F_MOUNT) && !n.has(F_DESCEND));
            let never = n.state == State::Unvisited && n.at == 0;
            if explicit && !n.in_flight() && (blocked || never) {
                st.tree.m(id).flags &= !(F_PROTECTED | F_DENIED);
                if st.prepare_root(id, &p) {
                    // Never measured: resume, keeping subtrees the cache already holds.
                    st.requeue(id, blocked, true);
                }
            }
        }
        if let Some(db) = &sh.db {
            let db = lock(db);
            if !db.is_locked() {
                let _ = db.set_meta(&format!("want:{}", lossy(&p)), now_ms());
            }
        }
        self.start();
        sh.work.notify_all();
    }

    /// Prioritize scanning `path` next (the user is looking at it).
    pub fn focus(&self, path: &str) {
        let p = norm(path);
        let sh = self.sh();
        let is_dir = sys::lstat(&p).is_some_and(|s| s.4);
        {
            let mut st = lock(&sh.st);
            let changed = st.focus.as_deref() != Some(&p[..]);
            st.focus = Some(p.clone());
            // Keep the focused chain unfolded.
            let mut x = st.tree.find(&p);
            match x {
                Some(id) => {
                    let n = st.tree.n(id);
                    if n.state == State::Done && n.has(F_FOLDED) {
                        st.requeue(id, false, true);
                    } else if n.in_flight() {
                        st.tree.m(id).flags |= F_EXPAND;
                    }
                }
                None if is_dir => {
                    // Deepest known ancestor: if nothing is reading it, materialize the path.
                    let mut anc = p.clone();
                    let mut a = None;
                    while a.is_none() {
                        match anc.iter().rposition(|&b| b == b'/') {
                            Some(0) => anc.truncate(1),
                            Some(i) => anc.truncate(i),
                            None => break,
                        }
                        a = st.tree.find(&anc);
                        if anc == b"/" {
                            break;
                        }
                    }
                    let blocked_above = a.is_some_and(|a| {
                        let mut y = a;
                        loop {
                            let n = st.tree.n(y);
                            if n.has(F_PROTECTED) || (n.has(F_MOUNT) && !n.has(F_DESCEND)) || n.in_flight() {
                                return true;
                            }
                            if n.parent == NONE {
                                return false;
                            }
                            y = n.parent;
                        }
                    });
                    if !blocked_above {
                        let id = st.tree.find_or_create(&p);
                        // Queue the topmost created node.
                        let mut top = id;
                        while let Some(par) = Some(st.tree.n(top).parent).filter(|&q| q != NONE) {
                            if st.tree.n(par).state == State::Unvisited && st.tree.n(par).at == 0 && Some(par) != a {
                                top = par;
                            } else {
                                break;
                            }
                        }
                        let tp = st.tree.path(top);
                        if st.prepare_root(top, &tp) {
                            for y in st.tree.subtree(top) {
                                st.tree.m(y).flags |= F_EXPAND;
                            }
                            st.requeue(top, true, true);
                        }
                        x = Some(id);
                    }
                }
                None => {}
            }
            let _ = x;
            if changed {
                st.rebuild_queue();
            }
        }
        self.start();
        sh.work.notify_all();
    }

    /// Force a rescan of `path`'s subtree.
    pub fn rescan(&self, path: &str) {
        let p = norm(path);
        let sh = self.sh();
        {
            let mut st = lock(&sh.st);
            let id = st.tree.find_or_create(&p);
            if st.prepare_root(id, &p) {
                st.requeue(id, true, false);
            }
        }
        self.start();
        sh.work.notify_all();
    }

    /// Children of `path` from the best data we have (cache + in-progress). None if unknown yet.
    pub fn list(&self, path: &str) -> Option<Listing> {
        let p = norm(path);
        let st = lock(&self.sh().st);
        list_locked(&st, &p)
    }

    /// The `n` largest entries (files or dirs, any depth) under `path`, deduped so a dir is
    /// not listed alongside the single child that explains it.
    pub fn largest(&self, path: &str, n: usize) -> Vec<DirEntry> {
        let p = norm(path);
        let st = lock(&self.sh().st);
        let Some(root) = st.tree.find(&p) else { return Vec::new() };
        let now = now_ms();
        enum C {
            Dir(Id),
            File(Id, usize),
        }
        let mut cands: Vec<(u64, C)> = Vec::new();
        let mut stack = vec![root];
        while let Some(x) = stack.pop() {
            let node = st.tree.n(x);
            for (i, f) in node.big.iter().enumerate() {
                cands.push((f.size, C::File(x, i)));
            }
            let mut max_child = node.big.iter().map(|f| f.size).max().unwrap_or(0);
            for &c in &node.children {
                let cn = st.tree.n(c);
                if cn.has(F_MOUNT) {
                    continue;
                }
                max_child = max_child.max(st.tree.display(c, now).0.size);
                stack.push(c);
            }
            if x != root {
                let size = st.tree.display(x, now).0.size;
                if size > 0 && (max_child as f64) < 0.8 * size as f64 {
                    cands.push((size, C::Dir(x)));
                }
            }
        }
        cands.sort_by(|a, b| b.0.cmp(&a.0));
        cands
            .into_iter()
            .take(n)
            .map(|(_, c)| match c {
                C::Dir(x) => st.entry(x, false, now),
                C::File(x, i) => file_entry(&st, x, i),
            })
            .collect()
    }

    pub fn progress(&self) -> Vec<ScanProgress> {
        let st = lock(&self.sh().st);
        st.roots.iter().map(|r| st.progress_of(r)).collect()
    }

    /// Blocking one-shot scan for the CLI (`fat fs PATH --wait`), with a deadline.
    pub fn scan_blocking(&self, path: &str, deadline_ms: u64) -> Option<Listing> {
        let p = norm(path);
        let sh = self.sh().clone();
        let deadline = Instant::now() + Duration::from_millis(deadline_ms);
        let st_meta = sys::lstat(&p)?;
        if !st_meta.4 {
            // A file: report it alone.
            let md = std::fs::symlink_metadata(lossy(&p)).ok()?;
            use std::os::unix::fs::MetadataExt;
            let name = p.rsplit(|&b| b == b'/').next().map(lossy).unwrap_or_default();
            let e = DirEntry {
                path: lossy(&p),
                name,
                is_dir: false,
                size: md.blocks() * 512,
                apparent: md.size(),
                files: 1,
                newest_mtime: md.mtime(),
                scanned_at: now_ms(),
                ..Default::default()
            };
            return Some(Listing { dir: e, children: Vec::new(), progress: ScanProgress::default() });
        }
        {
            let mut st = lock(&sh.st);
            st.allow(&p);
            let i = st.add_root(&p, false, 0);
            let used = sys::fs_used(&p);
            let r = &mut st.roots[i];
            (r.started_at, r.files, r.bytes, r.errors, r.used) = (now_ms(), 0, 0, 0, used);
            let id = st.tree.find_or_create(&p);
            // A completed tree is re-measured in full; an unfinished one (an interrupted earlier
            // run) resumes and keeps the finished subtrees loaded from the cache.
            let full = st.tree.n(id).state == State::Done || st.tree.n(id).has(F_PROTECTED | F_DENIED);
            st.tree.m(id).flags &= !(F_PROTECTED | F_DENIED);
            if st.prepare_root(id, &p) {
                st.requeue(id, full, true);
            }
            st.blocking.push(p.clone());
            st.rebuild_queue();
        }
        sh.work.notify_all();
        let stop = Arc::new(AtomicBool::new(false));
        let helpers: Vec<_> = (0..sh.opts.threads.max(1))
            .filter_map(|i| {
                let (s, stop) = (sh.clone(), stop.clone());
                thread::Builder::new().name(format!("fat-scan-cli-{i}")).spawn(move || worker(s, false, Some(stop))).ok()
            })
            .collect();
        let mut completed = 0;
        {
            let mut st = lock(&sh.st);
            loop {
                let done = st.tree.find(&p).is_some_and(|id| st.tree.n(id).state == State::Done);
                let now = Instant::now();
                if done || now >= deadline || sh.shutdown.load(AO::Relaxed) {
                    break;
                }
                let wait = (deadline - now).min(Duration::from_millis(100));
                st = sh.done.wait_timeout(st, wait).map(|r| r.0).unwrap_or_else(|e| e.into_inner().0);
            }
            if let Some(i) = st.blocking.iter().position(|b| *b == p) {
                st.blocking.remove(i);
            }
            st.rebuild_queue();
            if st.tree.find(&p).is_some_and(|id| st.tree.n(id).state == State::Done)
                && let Some(r) = st.roots.iter_mut().find(|r| r.path == p)
            {
                r.completed_at = now_ms();
                completed = r.completed_at;
            }
        }
        stop.store(true, AO::SeqCst);
        sh.work.notify_all();
        for h in helpers {
            let _ = h.join();
        }
        flush(&sh);
        if completed > 0
            && let Some(db) = &sh.db
        {
            // Lets a background writer (or the next run) skip a full pass it would redo.
            let _ = lock(db).set_meta(&format!("completed:{}", lossy(&p)), completed);
        }
        self.list(&lossy(&p))
    }

    /// Sizes of dirs at `path` depth <= `depth` for the recorder (scan-diff evidence).
    pub fn sizes(&self, path: &str, depth: usize) -> Vec<(String, u64)> {
        let p = norm(path);
        let st = lock(&self.sh().st);
        let Some(root) = st.tree.find(&p) else { return Vec::new() };
        let now = now_ms();
        let mut out = Vec::new();
        let mut stack = vec![(root, 0usize)];
        while let Some((x, d)) = stack.pop() {
            let n = st.tree.n(x);
            if x != root && n.has(F_MOUNT) {
                continue;
            }
            let (a, _, at) = st.tree.display(x, now);
            if at > 0 || n.state != State::Unvisited {
                out.push((lossy(&st.tree.path(x)), a.size));
            }
            if d < depth {
                stack.extend(n.children.iter().map(|&c| (c, d + 1)));
            }
        }
        out
    }

    /// Kept index nodes (memory diagnostics).
    #[allow(dead_code)] // API for the TUI / CLI
    pub fn index_nodes(&self) -> usize {
        lock(&self.sh().st).tree.kept()
    }

    /// Write measured directories to the cache now.
    #[allow(dead_code)] // API for the TUI / CLI
    pub fn flush(&self) {
        flush(self.sh());
    }
}

fn file_entry(st: &St, x: Id, i: usize) -> DirEntry {
    let n = st.tree.n(x);
    let f = &n.big[i];
    DirEntry {
        path: lossy(&sys::join(&st.tree.path(x), &f.name)),
        name: lossy(&f.name),
        is_dir: false,
        size: f.size,
        apparent: f.apparent,
        files: 1,
        newest_mtime: f.mtime,
        denied: 0,
        mount_point: false,
        partial: false,
        scanned_at: n.at,
    }
}

fn list_locked(st: &St, p: &[u8]) -> Option<Listing> {
    let id = st.tree.find(p)?;
    let n = st.tree.n(id);
    if !matches!(n.state, State::Done | State::Waiting) && n.at == 0 && n.children.is_empty() {
        return None;
    }
    let now = now_ms();
    let dir = st.entry(id, false, now);
    let mut children: Vec<DirEntry> = n.children.iter().map(|&c| st.entry(c, true, now)).collect();
    children.extend((0..n.big.len()).map(|i| file_entry(st, id, i)));
    children.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));
    let progress = st
        .roots
        .iter()
        .filter(|r| under(p, &r.path))
        .max_by_key(|r| r.path.len())
        .map(|r| st.progress_of(r))
        .unwrap_or_else(|| ScanProgress {
            root: lossy(p),
            running: n.in_flight(),
            completed_at: if n.state == State::Done { n.at } else { 0 },
            fraction: (n.state == State::Done).then_some(1.0),
            ..Default::default()
        });
    Some(Listing { dir, children, progress })
}

/// Per-thread CPU token bucket: this thread's share of the background budget.
struct Throttle {
    cpu0: u64,
    tokens: f64,
    last: Instant,
}

impl Throttle {
    fn new() -> Self {
        Throttle { cpu0: sys::thread_cpu_ns(), tokens: 0.0, last: Instant::now() }
    }
    /// Account the CPU used since the last call; sleep if over `share` cores.
    fn pace(&mut self, share: f64, enforce: bool, sh: &Shared) {
        let cpu = sys::thread_cpu_ns();
        let used = cpu.saturating_sub(self.cpu0) as f64;
        self.cpu0 = cpu;
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_nanos() as f64;
        self.last = now;
        if !enforce || share <= 0.0 {
            self.tokens = 0.0;
            return;
        }
        self.tokens = (self.tokens + dt * share).min(50e6) - used;
        if self.tokens < 0.0 {
            let ns = (-self.tokens / share).min(2e9) as u64;
            let until = Instant::now() + Duration::from_nanos(ns);
            while Instant::now() < until && !sh.shutdown.load(AO::Relaxed) {
                thread::sleep((until - Instant::now()).min(Duration::from_millis(200)));
            }
        }
    }
}

fn worker(sh: Arc<Shared>, background: bool, stop: Option<Arc<AtomicBool>>) {
    if background {
        sys::set_background(true);
    }
    let mut lowered = background;
    let mut throttle = Throttle::new();
    let keep_default = 0usize;
    loop {
        if sh.shutdown.load(AO::Relaxed) || stop.as_ref().is_some_and(|s| s.load(AO::Relaxed)) {
            break;
        }
        let job = {
            let mut st = lock(&sh.st);
            let only_boosted = background && sh.paused.load(AO::Relaxed);
            match st.pop(only_boosted) {
                Some(j) => j,
                None => {
                    let _ = sh.work.wait_timeout(st, Duration::from_millis(if background { 1000 } else { 50 }));
                    continue;
                }
            }
        };
        if background && job.boosted == lowered {
            // Focused work runs at utility QoS / best-effort I/O; the rest at background.
            lowered = !job.boosted;
            sys::set_background(lowered);
        }
        let keep = if job.expand { EXPAND_FILES } else { keep_default };
        let res = sys::read_dir(&job.path, sh.opts.big_file, keep, &job.policy, &sh.links);
        let (pushed, finished) = {
            let mut st = lock(&sh.st);
            st.apply(&job, res, &sh.opts);
            st.take_signals()
        };
        if finished {
            sh.done.notify_all();
        }
        for _ in 0..pushed.min(sh.opts.threads.max(1)) {
            sh.work.notify_one();
        }
        if background {
            // Focused work gets a larger budget than the walk behind it, but is still paced.
            let budget = if job.boosted {
                sh.opts.focus_budget as f64
            } else {
                sh.budget_milli.load(AO::Relaxed) as f64 / 1000.0
            };
            let share = budget / sh.opts.threads.max(1) as f64;
            throttle.pace(share, budget > 0.0, &sh);
        }
    }
}

/// Write dirty measured nodes (and deletions) to the cache.
fn flush(sh: &Shared) {
    let Some(db) = &sh.db else { return };
    let (rows, removed) = {
        let mut st = lock(&sh.st);
        let mut rows = Vec::new();
        for i in 0..st.tree.nodes.len() {
            let id = i as Id;
            let n = st.tree.n(id);
            if n.live && n.has(F_DIRTY) && n.state == State::Done && n.at > 0 {
                rows.push(row_of(&st.tree, id));
                let n = st.tree.m(id);
                n.flags = (n.flags & !F_DIRTY) | F_PERSISTED;
            }
        }
        (rows, std::mem::take(&mut st.removed))
    };
    if rows.is_empty() && removed.is_empty() {
        return;
    }
    let mut db = lock(db);
    let _ = db.write(&rows, &removed, now_ms());
}

fn coordinator(sh: Arc<Shared>) {
    sys::set_background(true);
    let mut last_batt: Option<Instant> = None;
    let mut last_lock_try: Option<Instant> = None;
    let mut last_flush = Instant::now();
    let mut last_reload = Instant::now();
    let mut last_mounts = Instant::now();
    loop {
        if sh.shutdown.load(AO::Relaxed) {
            break;
        }
        if sh.opts.battery_check && last_batt.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            last_batt = Some(Instant::now());
            let (pct, on_batt) = crate::collect::system::battery();
            let pause = on_batt == Some(true) && pct.is_some_and(|p| p < 20.0);
            sh.paused.store(pause, AO::Relaxed);
        }
        if last_mounts.elapsed() >= Duration::from_secs(120) {
            last_mounts = Instant::now();
            let m = sys::mounts();
            let mut st = lock(&sh.st);
            let mut p = (*st.policy).clone();
            p.mounts = m;
            st.policy = Arc::new(p);
        }
        let mut writer = lock(&sh.st).writer;
        if sh.opts.background
            && !writer
            && last_lock_try.is_none_or(|t| t.elapsed() >= Duration::from_secs(30))
            && let Some(db) = &sh.db
        {
            last_lock_try = Some(Instant::now());
            if lock(db).try_lock() {
                writer = true;
                lock(&sh.st).writer = true;
            }
        }
        if sh.opts.background && (writer || sh.db.is_none()) {
            schedule(&sh);
        } else if let Some(db) = &sh.db
            && last_reload.elapsed() >= sh.opts.reload_interval
        {
            last_reload = Instant::now();
            reload(&sh, db);
        }
        if last_flush.elapsed() >= sh.opts.flush_interval {
            last_flush = Instant::now();
            flush(&sh);
        }
        let st = lock(&sh.st);
        let tick = sh.opts.reload_interval.min(sh.opts.flush_interval).clamp(Duration::from_millis(20), Duration::from_secs(1));
        let _ = sh.done.wait_timeout(st, tick);
    }
    flush(&sh);
}

/// Non-writer: pull what the background scanner (another process) wrote.
fn reload(sh: &Shared, db: &Mutex<cache::Db>) {
    let since = lock(&sh.st).last_reload;
    let (rows, updated, completed) = {
        let db = lock(db);
        let updated = db.meta("updated").unwrap_or(0);
        if updated <= since {
            return;
        }
        let roots: Vec<Vec<u8>> = lock(&sh.st).roots.iter().map(|r| r.path.clone()).collect();
        let completed: Vec<(Vec<u8>, Ts)> =
            roots.into_iter().filter_map(|r| db.meta(&format!("completed:{}", lossy(&r))).map(|t| (r, t))).collect();
        (db.load_since(since).unwrap_or_default(), updated, completed)
    };
    let mut st = lock(&sh.st);
    st.merge_rows(rows);
    st.last_reload = updated;
    for (p, t) in completed {
        if let Some(r) = st.roots.iter_mut().find(|r| r.path == p) {
            r.completed_at = r.completed_at.max(t);
        }
    }
}

/// Writer: keep background roots fresh (full pass when never/long ago completed, quick
/// re-stat otherwise).
fn schedule(sh: &Arc<Shared>) {
    if let Some(db) = &sh.db {
        let wants = lock(db).wants();
        if !wants.is_empty() {
            let mut st = lock(&sh.st);
            for w in wants {
                let p = norm(&w);
                if !st.roots.iter().any(|r| r.path == p) {
                    let completed = lock(db).meta(&format!("completed:{w}")).unwrap_or(0);
                    st.add_root(&p, true, completed);
                }
            }
        }
    }
    let now = now_ms();
    let full_ms = sh.opts.full_interval.as_millis() as i64;
    let restat_ms = sh.opts.restat_interval.as_millis() as i64;
    let mut restat: Option<Vec<u8>> = None;
    let mut completed: Vec<(Vec<u8>, Ts)> = Vec::new();
    {
        let mut st = lock(&sh.st);
        let idle = st.queue.is_empty() && st.reading == 0;
        for i in 0..st.roots.len() {
            if !st.roots[i].background {
                continue;
            }
            let path = st.roots[i].path.clone();
            let id = st.tree.find_or_create(&path);
            let (in_flight, done) = (st.tree.n(id).in_flight(), st.tree.n(id).state == State::Done);
            if in_flight {
                continue;
            }
            if st.roots[i].full_running {
                st.roots[i].full_running = false;
                if done {
                    st.roots[i].completed_at = now;
                    st.roots[i].last_restat = now;
                    completed.push((path.clone(), now));
                }
                continue;
            }
            let r = &st.roots[i];
            let r_completed = r.completed_at;
            if r.completed_at == 0 || now - r.completed_at > full_ms {
                if idle {
                    lock(&sh.links).clear();
                }
                let used = if cfg!(target_os = "macos") && path == b"/" {
                    sys::fs_used(b"/").zip(sys::fs_used(b"/System/Volumes/Data")).map(|(a, b)| a + b)
                } else {
                    sys::fs_used(&path)
                };
                let r = &mut st.roots[i];
                (r.full_running, r.started_at, r.files, r.bytes, r.errors, r.used) = (true, now, 0, 0, 0, used);
                if st.prepare_root(id, &path) {
                    // Never completed (e.g. fat was quit mid-scan): resume from the cached
                    // finished subtrees instead of starting over; a stale tree is redone.
                    let resume = r_completed == 0;
                    st.requeue(id, !resume, false);
                } else {
                    st.roots[i].full_running = false;
                    st.roots[i].completed_at = now;
                }
                sh.work.notify_all();
            } else if restat.is_none() && !r.restat_running && now - r.last_restat > restat_ms && idle {
                st.roots[i].restat_running = true;
                restat = Some(path);
            }
        }
    }
    if !completed.is_empty() {
        flush(sh);
        if let Some(db) = &sh.db {
            let db = lock(db);
            for (p, t) in completed {
                let _ = db.set_meta(&format!("completed:{}", lossy(&p)), t);
            }
        }
    }
    if let Some(p) = restat {
        restat_pass(sh, &p);
    }
}

/// Re-stat every kept directory under `root`; re-read the ones whose entries changed.
fn restat_pass(sh: &Arc<Shared>, root: &[u8]) {
    let items: Vec<(Id, u32, Vec<u8>, u64, i64, i64)> = {
        let st = lock(&sh.st);
        let Some(rid) = st.tree.find(root) else { return };
        st.tree
            .subtree(rid)
            .into_iter()
            .filter(|&x| {
                let n = st.tree.n(x);
                n.state == State::Done
                    && n.at > 0
                    && n.flags & (F_PROTECTED | F_DENIED) == 0
                    && (!n.has(F_MOUNT) || n.has(F_DESCEND))
            })
            .map(|x| {
                let n = st.tree.n(x);
                (x, n.stamp, st.tree.path(x), n.ino, n.mtime, n.ctime)
            })
            .collect()
    };
    let mut changed: Vec<(Id, u32)> = Vec::new();
    let mut throttle = Throttle::new();
    for (i, (id, stamp, path, ino, mtime, ctime)) in items.iter().enumerate() {
        if sh.shutdown.load(AO::Relaxed) {
            return;
        }
        match sys::lstat(path) {
            Some((_, i2, m2, c2, true)) if i2 == *ino && m2 == *mtime && c2 == *ctime => {}
            _ => changed.push((*id, *stamp)),
        }
        if i % 64 == 63 {
            let budget = sh.budget_milli.load(AO::Relaxed) as f64 / 1000.0;
            throttle.pace(budget, budget > 0.0, sh);
        }
    }
    let mut st = lock(&sh.st);
    for (id, stamp) in changed {
        if !st.tree.valid(id, stamp) {
            continue;
        }
        // A vanished dir: re-read its parent instead.
        let target = if sys::lstat(&st.tree.path(id)).is_some_and(|s| s.4) { id } else { st.tree.n(id).parent };
        if target != NONE && st.tree.n(target).state == State::Done {
            st.requeue(target, false, false);
        }
    }
    let now = now_ms();
    if let Some(r) = st.roots.iter_mut().find(|r| r.path == root) {
        r.restat_running = false;
        r.last_restat = now;
    }
    drop(st);
    sh.work.notify_all();
}

#[cfg(test)]
mod tests;
