//! Safe, reversible actions with a persisted journal. OWNER: actions agent.
//!
//! Every action (including refused ones) is appended to a JSONL journal so the
//! TUI, CLI and MCP all share one audit trail. The journal is strictly
//! append-only: an undo is a new record whose `resolves` names the original id,
//! and `undone` is derived when loading. Lines this build can't parse (a torn
//! write, a newer fat's record) are therefore never lost. Every read-allocate-
//! append runs under an exclusive `flock` on `actions.jsonl.lock`, so concurrent
//! fat processes never hand out the same id.
use crate::model::{now_ms, ActionKind, ActionRecord, Snapshot};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Process names we never signal, whatever the uid or action.
const PROTECTED_NAMES: &[&str] = &["kernel_task", "launchd", "WindowServer", "loginwindow"];
/// Session and system daemons that other processes block on via IPC. Freezing or killing one
/// can hang every app (including the agent that would issue the undo), so Pause/Term/Kill are
/// refused for them whatever the uid. Renice and Resume stay allowed.
#[cfg(not(target_os = "linux"))]
const CRITICAL_NAMES: &[&str] = &[
    "kernel_task", "launchd", "WindowServer", "loginwindow", "logd", "runningboardd", "coreaudiod",
    "opendirectoryd", "mds", "mds_stores", "trustd", "syspolicyd", "secd", "securityd", "bluetoothd",
    "configd", "notifyd", "distnoted", "cfprefsd", "usernoted", "UserEventAgent", "coreservicesd",
    "lsd", "tccd", "powerd", "diskarbitrationd", "fseventsd", "mDNSResponder", "kernelmanagerd",
    "watchdogd", "hidd", "airportd", "sshd", "launchservicesd", "nsurlsessiond", "containermanagerd",
    "symptomsd", "thermalmonitord", "sandboxd", "authd", "keybagd", "apsd", "corebrightnessd",
];
/// Linux: init/session plumbing, the display server and compositor, and the cluster agent.
/// Names are matched against the kernel's 15-char `comm` too ("systemd-journald" shows up as
/// "systemd-journal"). sshd, containerd and dockerd only warn (see [`WARN_NAMES`]): stopping a
/// session's sshd or a container runtime is sometimes exactly what's wanted.
#[cfg(target_os = "linux")]
const CRITICAL_NAMES: &[&str] = &[
    "systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "systemd-resolved",
    "systemd-networkd", "systemd-oomd", "dbus-daemon", "dbus-broker", "dbus-broker-launch", "Xorg", "Xwayland",
    "gnome-shell", "gnome-session-binary", "kwin_wayland", "kwin_x11", "plasmashell", "gdm", "gdm3",
    "gdm-session-worker", "sddm", "lightdm", "polkitd", "NetworkManager", "kubelet", "pipewire",
    "wireplumber",
];
/// Process names that are allowed but deserve a warning.
#[cfg(not(target_os = "linux"))]
const WARN_NAMES: &[&str] = &["Finder", "Dock", "SystemUIServer"];
#[cfg(target_os = "linux")]
const WARN_NAMES: &[&str] = &["sshd", "containerd", "dockerd"];
/// Tolerance (seconds) when comparing snapshot vs live start times. On Linux both sides use the
/// same formula (btime + starttime / CLK_TCK, whole seconds), so they agree to within rounding.
#[cfg(not(target_os = "linux"))]
const START_TIME_SLACK: u64 = 2;
#[cfg(target_os = "linux")]
const START_TIME_SLACK: u64 = 1;

/// `name` is `full`, or the kernel's truncation of it (Linux `comm` keeps 15 bytes).
fn name_is(name: &str, full: &str) -> bool {
    if name.eq_ignore_ascii_case(full) {
        return true;
    }
    cfg!(target_os = "linux") && name.len() == 15 && full.len() > 15 && full.is_char_boundary(15) && full[..15].eq_ignore_ascii_case(name)
}

/// True for daemons whose loss or freeze stalls the login session (shared with blame).
pub fn is_critical_name(name: &str) -> bool {
    CRITICAL_NAMES.iter().any(|n| name_is(name, n))
}

/// Refusal for actions that would freeze or end a critical daemon.
pub fn critical_refusal(kind: ActionKind, name: &str) -> Option<String> {
    let freezes_or_ends = matches!(kind, ActionKind::Pause | ActionKind::Term | ActionKind::Kill | ActionKind::KillTree);
    (freezes_or_ends && is_critical_name(name)).then(|| {
        format!("refusing: {name} is a system/session daemon other apps depend on; {kind:?} could hang the whole session")
    })
}

/// The identity a user or agent saw when choosing a target. Actions refuse if the live
/// process no longer matches it (exited, pid reused) instead of signalling a stranger.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Expect {
    /// Epoch seconds, as in `Proc::start_time`. None/0 = don't check.
    pub start_time: Option<u64>,
    pub name: Option<String>,
}

impl Expect {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn of(start_time: u64, name: impl Into<String>) -> Expect {
        Expect { start_time: (start_time != 0).then_some(start_time), name: Some(name.into()) }
    }
}

/// One journal line: the public record plus private bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    #[serde(flatten)]
    rec: ActionRecord,
    /// Target's start time (epoch secs) when the action was applied; used to
    /// make sure undo does not hit a recycled pid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    start_time: Option<u64>,
    /// Ids this record undid or made moot (an undo, a resume, a kill of a paused process).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    resolves: Vec<u64>,
    /// Renice on Linux: nice is per thread, so the previous value of every thread
    /// (tid, nice) we changed, for undo to restore each one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    thread_nice: Vec<(u32, i32)>,
}

impl Entry {
    fn new(rec: ActionRecord, start_time: Option<u64>) -> Entry {
        Entry { rec, start_time, resolves: Vec::new(), thread_nice: Vec::new() }
    }
}

pub struct Actions {
    path: PathBuf,
    entries: Vec<Entry>,
}

/// What the kernel says about a pid right now.
#[derive(Debug, Clone, PartialEq)]
pub struct LiveProc {
    pub pid: u32,
    pub ppid: u32,
    /// Effective and real uid.
    pub uid: u32,
    pub ruid: u32,
    pub name: String,
    /// Epoch seconds.
    pub start_time: u64,
    pub stopped: bool,
}

/// Default journal location.
pub fn journal_path() -> PathBuf {
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join("fat")
        .join("actions.jsonl")
}

/// Exclusive advisory lock on `<journal>.lock`, released on drop (when the fd closes).
/// If the lock file can't be created we proceed unlocked rather than refuse to act.
struct JournalLock {
    _file: Option<File>,
}

fn lock_journal(path: &Path) -> JournalLock {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let lock_path = path.with_extension("jsonl.lock");
    let file = fs::OpenOptions::new().create(true).truncate(false).write(true).open(lock_path).ok().filter(|f| {
        use std::os::fd::AsRawFd;
        // SAFETY: flock on a valid, owned fd; blocks until other fat processes release it.
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) == 0 }
    });
    JournalLock { _file: file }
}

fn open_for_append(path: &Path) -> std::io::Result<File> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::OpenOptions::new().create(true).append(true).open(path)
}

impl Actions {
    /// Journal at dirs::state_dir()|data_local_dir()/fat/actions.jsonl
    pub fn open() -> Actions {
        Self::open_at(journal_path())
    }

    /// Open (or lazily create) a journal at an explicit path.
    pub fn open_at(path: impl Into<PathBuf>) -> Actions {
        let path = path.into();
        let entries = load(&path);
        Actions { path, entries }
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Apply an action. `nice` required for Renice. Refuses protected pids (0, 1, self, kernel_task, WindowServer, launchd, loginwindow).
    pub fn apply(&mut self, kind: ActionKind, pid: u32, nice: Option<i32>, snap: &Snapshot) -> ActionRecord {
        self.apply_expect(kind, pid, nice, snap, None)
    }

    /// Like [`apply`](Self::apply), but also refuses unless the live process still matches the
    /// identity the caller chose (start time, name). Use whenever time passes between choosing
    /// a target and acting on it (a confirm dialog, an agent's earlier snapshot).
    pub fn apply_expect(
        &mut self,
        kind: ActionKind,
        pid: u32,
        nice: Option<i32>,
        snap: &Snapshot,
        expect: Option<&Expect>,
    ) -> ActionRecord {
        let _lock = lock_journal(&self.path);
        // Opened before acting so we know up front whether this action can be undone later.
        let journal = open_for_append(&self.path);
        self.entries = load(&self.path);

        let snap_name = snap.proc(pid).map(|p| p.name.clone());
        let live = live_proc(pid);
        let name = snap_name
            .clone()
            .or_else(|| live.as_ref().map(|l| l.name.clone()))
            .unwrap_or_else(|| "?".into());
        let mut rec = blank(kind, pid, &name);
        let start_time = live.as_ref().map(|l| l.start_time);
        let mut resolves = Vec::new();
        let mut thread_nice = Vec::new();

        match check_target(kind, pid, live.as_ref(), snap, expect) {
            Err(msg) => rec.message = msg,
            Ok(warning) => {
                thread_nice = execute(&mut rec, kind, pid, nice, snap);
                if rec.ok {
                    resolves = self.close_pauses(kind, &rec, start_time);
                    if !resolves.is_empty() {
                        let ids: Vec<String> = resolves.iter().map(|i| format!("#{i}")).collect();
                        rec.message = format!("{} (closes pause {})", rec.message, ids.join(", "));
                    }
                }
                if let Some(w) = warning {
                    rec.message = format!("{} (warning: {w})", rec.message);
                }
            }
        }
        let mut entry = Entry::new(rec, start_time);
        entry.resolves = resolves;
        entry.thread_nice = thread_nice;
        self.write(entry, journal)
    }

    /// Open Pause records made moot by a successful action on the same process: a Resume
    /// (nothing left to undo) or a Term/Kill/KillTree (undo would only deliver the TERM).
    fn close_pauses(&self, kind: ActionKind, rec: &ActionRecord, start_time: Option<u64>) -> Vec<u64> {
        if !matches!(kind, ActionKind::Resume | ActionKind::Term | ActionKind::Kill | ActionKind::KillTree) {
            return Vec::new();
        }
        let touched: HashSet<u32> = rec.pids.iter().copied().chain(std::iter::once(rec.pid)).collect();
        open_entries(&self.entries)
            .filter(|e| e.rec.kind == ActionKind::Pause && touched.contains(&e.rec.pid))
            // Only the same incarnation: an old pause of a recycled pid stays as it was.
            .filter(|e| e.rec.pid != rec.pid || same_start(e.start_time, start_time))
            .map(|e| e.rec.id)
            .collect()
    }

    /// Undo by id (pause->resume, renice->restore). Kill is not undoable.
    pub fn undo(&mut self, id: u64) -> ActionRecord {
        let _lock = lock_journal(&self.path);
        self.entries = load(&self.path);
        self.undo_locked(id)
    }

    /// Undo with the journal lock held and `self.entries` fresh.
    fn undo_locked(&mut self, id: u64) -> ActionRecord {
        let Some(idx) = self.entries.iter().position(|e| e.rec.id == id) else {
            return failed(ActionKind::Resume, 0, "?", format!("no action #{id} in journal"));
        };
        let orig = self.entries[idx].clone();
        let o = &orig.rec;
        let undo_kind = match o.kind {
            ActionKind::Renice => ActionKind::Renice,
            _ => ActionKind::Resume,
        };
        if !o.ok {
            return failed(undo_kind, o.pid, &o.name, format!("#{id} did not succeed; nothing to undo"));
        }
        if !o.undoable {
            return failed(undo_kind, o.pid, &o.name, format!("#{id} ({:?}) is not undoable", o.kind));
        }
        if o.undone {
            return failed(undo_kind, o.pid, &o.name, format!("#{id} was already undone"));
        }
        let journal = open_for_append(&self.path);
        let mut rec = blank(undo_kind, o.pid, &o.name);

        // Targets: the pids the original touched (falls back to the main pid).
        let targets: Vec<u32> = if o.pids.is_empty() { vec![o.pid] } else { o.pids.clone() };
        let main_live = live_proc(o.pid);
        let gone = match (&main_live, orig.start_time) {
            (None, _) => true,
            (Some(l), st) => !same_start(st, Some(l.start_time)),
        };
        if gone {
            rec.message = format!("undo #{id}: process {} is gone (exited or pid reused); marking undone", o.pid);
            rec.ok = true;
            let mut e = Entry::new(rec, orig.start_time);
            e.resolves = vec![id];
            return self.write(e, journal);
        }

        match o.kind {
            ActionKind::Pause => {
                let mut done = Vec::new();
                let mut errs = Vec::new();
                for &p in &targets {
                    match send_signal(p, libc::SIGCONT) {
                        Ok(()) => done.push(p),
                        Err(e) => errs.push(format!("{p}: {e}")),
                    }
                }
                rec.ok = !done.is_empty();
                rec.pids = done;
                rec.message = if errs.is_empty() {
                    format!("undo #{id}: resumed (SIGCONT)")
                } else {
                    format!("undo #{id}: SIGCONT errors: {}", errs.join(", "))
                };
            }
            ActionKind::Renice => {
                let prev = o.prev_nice.unwrap_or(0);
                match get_nice(o.pid) {
                    Ok(cur) => {
                        rec.prev_nice = Some(cur);
                        rec.new_nice = Some(prev);
                        #[cfg(target_os = "linux")]
                        let res = restore_thread_nices(o.pid, prev, &orig.thread_nice);
                        #[cfg(not(target_os = "linux"))]
                        let res = set_nice(o.pid, prev);
                        match res {
                            Ok(()) => {
                                rec.ok = true;
                                rec.pids = vec![o.pid];
                                rec.message = format!("undo #{id}: nice {cur} -> {prev}");
                            }
                            Err(e) => rec.message = format!("undo #{id}: {e}"),
                        }
                    }
                    Err(e) => rec.message = format!("undo #{id}: {e}"),
                }
            }
            other => rec.message = format!("{other:?} cannot be undone"),
        }
        let mut e = Entry::new(rec, orig.start_time);
        if e.rec.ok {
            e.resolves = vec![id];
        }
        self.write(e, journal)
    }

    pub fn undo_last(&mut self) -> Option<ActionRecord> {
        let _lock = lock_journal(&self.path);
        self.entries = load(&self.path);
        let id = open_entries(&self.entries).last().map(|e| e.rec.id)?;
        Some(self.undo_locked(id))
    }

    /// Most recent first.
    pub fn log(&self) -> Vec<ActionRecord> {
        let mut v: Vec<ActionRecord> = load(&self.path).into_iter().map(|e| e.rec).collect();
        v.sort_by(|a, b| b.id.cmp(&a.id));
        v
    }

    // ---- journal persistence ----

    /// Assign the next id and append. Caller holds the journal lock and refreshed `entries`.
    /// If the record can't be persisted it gets id 0 and loses `undoable`: an id that isn't
    /// in the journal would only produce a failing `fat undo N` hint.
    fn write(&mut self, mut entry: Entry, journal: std::io::Result<File>) -> ActionRecord {
        entry.rec.id = self.entries.iter().map(|e| e.rec.id).max().unwrap_or(0) + 1;
        let line = serde_json::to_string(&entry).unwrap_or_default();
        let res = journal.and_then(|mut f| f.write_all(format!("{line}\n").as_bytes()));
        if let Err(e) = res {
            entry.rec.id = 0;
            let mut note = format!("not journaled ({e})");
            if entry.rec.undoable {
                entry.rec.undoable = false;
                note.push_str(&format!("; fat can't undo it, resume manually with `fat resume {}`", entry.rec.pid));
                if entry.rec.kind == ActionKind::Renice
                    && let Some(p) = entry.rec.prev_nice
                {
                    note = format!("not journaled ({e}); restore manually with `fat renice {} {p}`", entry.rec.pid);
                }
            }
            entry.rec.message = format!("{} ({note})", entry.rec.message);
            return entry.rec;
        }
        let rec = entry.rec.clone();
        self.entries.push(entry);
        rec
    }
}

fn same_start(a: Option<u64>, b: Option<u64>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) if a != 0 && b != 0 => a.abs_diff(b) <= START_TIME_SLACK,
        _ => true,
    }
}

/// Successful, undoable, not-yet-undone records in journal order.
fn open_entries(entries: &[Entry]) -> impl DoubleEndedIterator<Item = &Entry> {
    entries.iter().filter(|e| e.rec.ok && e.rec.undoable && !e.rec.undone && e.rec.id != 0)
}

/// Parse the journal, deriving `undone` from later records' `resolves`. Unparseable lines are
/// skipped here but stay untouched on disk, because nothing ever rewrites the file.
fn load(path: &Path) -> Vec<Entry> {
    let Ok(text) = fs::read_to_string(path) else { return Vec::new() };
    let mut entries: Vec<Entry> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .collect();
    let resolved: HashSet<u64> = entries.iter().flat_map(|e| e.resolves.iter().copied()).collect();
    for e in &mut entries {
        if resolved.contains(&e.rec.id) {
            e.rec.undone = true;
        }
    }
    entries
}

fn blank(kind: ActionKind, pid: u32, name: &str) -> ActionRecord {
    ActionRecord {
        id: 0,
        ts: now_ms(),
        kind,
        pid,
        name: name.to_string(),
        prev_nice: None,
        new_nice: None,
        pids: Vec::new(),
        undoable: false,
        undone: false,
        ok: false,
        message: String::new(),
    }
}

fn failed(kind: ActionKind, pid: u32, name: &str, message: String) -> ActionRecord {
    ActionRecord { message, ..blank(kind, pid, name) }
}

// ---- safety checks ----

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Our own pid and every ancestor up to launchd, from the live process table.
fn self_and_ancestors() -> Vec<u32> {
    let mut out = vec![std::process::id()];
    let mut cur = std::process::id();
    for _ in 0..64 {
        let Some(l) = live_proc(cur) else { break };
        if l.ppid == 0 || out.contains(&l.ppid) {
            break;
        }
        out.push(l.ppid);
        cur = l.ppid;
    }
    out
}

/// Pure name/pid policy. Err(reason) = refuse, Ok(Some(w)) = allowed with warning.
pub fn protection(pid: u32, name: &str, ours: &[u32]) -> Result<Option<String>, String> {
    if pid == 0 || pid == 1 {
        #[cfg(target_os = "linux")]
        return Err(format!("refusing: pid {pid} is the kernel/init ({name})"));
        #[cfg(not(target_os = "linux"))]
        return Err(format!("refusing: pid {pid} is the kernel/launchd"));
    }
    if pid == std::process::id() {
        return Err("refusing: that is fat itself".into());
    }
    if ours.contains(&pid) {
        return Err(format!("refusing: pid {pid} ({name}) is an ancestor of fat (your shell/terminal)"));
    }
    if PROTECTED_NAMES.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        return Err(format!("refusing: {name} is a protected system process"));
    }
    if WARN_NAMES.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        return Ok(Some(warn_text(name)));
    }
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
fn warn_text(name: &str) -> String {
    format!("{name} is part of the desktop; macOS will relaunch it")
}

#[cfg(target_os = "linux")]
fn warn_text(name: &str) -> String {
    if name.eq_ignore_ascii_case("sshd") {
        format!("{name}: the listener takes new ssh logins with it; a per-session sshd ends that session")
    } else {
        format!("{name} is a container runtime; every container it manages is affected")
    }
}

/// Linux: kernel threads (PF_KTHREAD: kthreadd and its children) can't be meaningfully
/// signalled, and pausing a kworker is never what anyone meant.
#[cfg(target_os = "linux")]
fn kernel_thread_refusal(pid: u32, name: &str) -> Result<(), String> {
    match procfs::read_stat(Path::new("/proc"), pid) {
        Some(st) if procfs::is_kernel_thread(&st) => Err(format!("refusing: pid {pid} ({name}) is a kernel thread")),
        _ => Ok(()),
    }
}

#[cfg(not(target_os = "linux"))]
fn kernel_thread_refusal(_pid: u32, _name: &str) -> Result<(), String> {
    Ok(())
}

/// Process names agree, allowing for kernel truncation (16-char p_comm vs full name).
fn names_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    !a.is_empty() && !b.is_empty() && (a == b || (a.len() >= 15 && b.starts_with(&a)) || (b.len() >= 15 && a.starts_with(&b)))
}

/// The live process is still the one the caller chose.
fn check_expect(pid: u32, live: &LiveProc, snap_name: Option<&str>, e: &Expect) -> Result<(), String> {
    if let Some(st) = e.start_time.filter(|&s| s != 0)
        && live.start_time != 0
        && st.abs_diff(live.start_time) > START_TIME_SLACK
    {
        return Err(format!(
            "refusing: pid {pid} is no longer the process you chose (it started at {}, expected {}); it exited and the pid was reused",
            live.start_time, st
        ));
    }
    if let Some(n) = e.name.as_deref().filter(|n| !n.is_empty())
        && !names_match(n, &live.name)
        && !snap_name.is_some_and(|s| names_match(n, s))
    {
        return Err(format!("refusing: pid {pid} is now {:?}, not {n:?} (pid reused?)", live.name));
    }
    Ok(())
}

/// Full target validation: protection policy, liveness, pid-reuse, ownership.
fn check_target(
    kind: ActionKind,
    pid: u32,
    live: Option<&LiveProc>,
    snap: &Snapshot,
    expect: Option<&Expect>,
) -> Result<Option<String>, String> {
    let sp = snap.proc(pid);
    let name = sp.map(|p| p.name.as_str()).or(live.map(|l| l.name.as_str())).unwrap_or("?");
    let warning = protection(pid, name, &self_and_ancestors())?;
    kernel_thread_refusal(pid, name)?;
    if let Some(r) = critical_refusal(kind, name) {
        return Err(r);
    }
    if let Some(l) = live
        && l.name != name
    {
        protection(pid, &l.name, &[])?;
        if let Some(r) = critical_refusal(kind, &l.name) {
            return Err(r);
        }
    }
    let Some(live) = live else {
        return Err(format!("pid {pid} is not running"));
    };
    if let Some(e) = expect {
        check_expect(pid, live, sp.map(|p| p.name.as_str()), e)?;
    }
    if let Some(sp) = sp
        && sp.start_time != 0
        && live.start_time != 0
        && sp.start_time.abs_diff(live.start_time) > START_TIME_SLACK
    {
        return Err(format!(
            "refusing: pid {pid} was reused (snapshot start {} != live start {}); refresh and retry",
            sp.start_time, live.start_time
        ));
    }
    if !is_root() {
        // SAFETY: getuid/geteuid have no preconditions.
        let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
        let mine = [uid, euid];
        if !mine.contains(&live.uid) && !mine.contains(&live.ruid) {
            return Err(format!("refusing: pid {pid} ({name}) belongs to uid {}, not you (run as root to act on it)", live.ruid));
        }
    }
    Ok(warning)
}

// ---- execution ----

/// Returns, for a renice, the previous nice of each thread changed (Linux; empty otherwise).
fn execute(rec: &mut ActionRecord, kind: ActionKind, pid: u32, nice: Option<i32>, snap: &Snapshot) -> Vec<(u32, i32)> {
    if kind == ActionKind::Renice {
        return renice(rec, pid, nice);
    }
    match kind {
        ActionKind::Pause => signal_one(rec, pid, libc::SIGSTOP, "paused (SIGSTOP)", true),
        ActionKind::Resume => resume(rec, pid, snap),
        ActionKind::Term => {
            signal_one(rec, pid, libc::SIGTERM, "sent SIGTERM", false);
            if rec.ok && continue_if_stopped(pid) {
                rec.message.push_str(" and SIGCONT (it was paused, and a stopped process can't act on TERM)");
            }
        }
        ActionKind::Kill => signal_one(rec, pid, libc::SIGKILL, "sent SIGKILL", false),
        ActionKind::Renice => {}
        ActionKind::KillTree => kill_tree(rec, pid, snap),
    }
    Vec::new()
}

/// A stopped process keeps TERM pending until continued; continue it so the signal lands.
/// Returns true if it was stopped.
fn continue_if_stopped(pid: u32) -> bool {
    if live_proc(pid).is_some_and(|l| l.stopped) {
        let _ = send_signal(pid, libc::SIGCONT);
        true
    } else {
        false
    }
}

fn signal_one(rec: &mut ActionRecord, pid: u32, sig: i32, ok_msg: &str, undoable: bool) {
    match send_signal(pid, sig) {
        Ok(()) => {
            rec.ok = true;
            rec.undoable = undoable;
            rec.pids = vec![pid];
            rec.message = ok_msg.to_string();
        }
        Err(e) => rec.message = e,
    }
}

fn pgid_of(pid: u32) -> Option<u32> {
    // SAFETY: getpgid has no memory preconditions.
    let g = unsafe { libc::getpgid(pid as libc::pid_t) };
    (g > 0).then_some(g as u32)
}

/// SIGCONT the process, and when it leads a process group (a `fat run` job, a shell job),
/// also the stopped members of that group: resuming only the leader leaves it waiting on
/// children that are still frozen.
fn resume(rec: &mut ActionRecord, pid: u32, snap: &Snapshot) {
    signal_one(rec, pid, libc::SIGCONT, "resumed (SIGCONT)", false);
    if !rec.ok || pgid_of(pid) != Some(pid) {
        return;
    }
    let ours = self_and_ancestors();
    let mut extra = Vec::new();
    for d in snap.descendants(pid) {
        let Some(l) = live_proc(d.pid) else { continue };
        let same = d.start_time == 0 || l.start_time.abs_diff(d.start_time) <= START_TIME_SLACK;
        if !same || !l.stopped || pgid_of(d.pid) != Some(pid) || protection(d.pid, &l.name, &ours).is_err() {
            continue;
        }
        if send_signal(d.pid, libc::SIGCONT).is_ok() {
            extra.push(d.pid);
        }
    }
    if !extra.is_empty() {
        rec.message = format!("resumed (SIGCONT) with {} stopped member(s) of its process group", extra.len());
        rec.pids.extend(extra);
    }
}

fn renice(rec: &mut ActionRecord, pid: u32, nice: Option<i32>) -> Vec<(u32, i32)> {
    let Some(new) = nice else {
        rec.message = "renice needs a nice value (-20..20)".into();
        return Vec::new();
    };
    let new = new.clamp(-20, 20);
    let prev = match get_nice(pid) {
        Ok(p) => p,
        Err(e) => {
            rec.message = e;
            return Vec::new();
        }
    };
    // Linux: every thread's own nice (they can differ); elsewhere empty.
    let threads = thread_nices(pid);
    let lowest = threads.iter().map(|&(_, n)| n).chain(std::iter::once(prev)).min().unwrap_or(prev);
    rec.prev_nice = Some(prev);
    rec.new_nice = Some(new);
    let root = nice_privileged();
    if new < prev && !root && !can_lower_nice_to(new) {
        rec.message = lower_nice_refusal(pid, prev, new);
        return Vec::new();
    }
    match set_nice(pid, new) {
        Ok(()) => {
            rec.ok = true;
            rec.pids = vec![pid];
            // Restoring a lower nice value later needs root unless we are root (or, on Linux,
            // RLIMIT_NICE / CAP_SYS_NICE allow going back down to it).
            rec.undoable = root || new <= lowest || can_lower_nice_to(lowest);
            let scope = if threads.len() > 1 { format!(" ({} threads)", threads.len()) } else { String::new() };
            rec.message = if rec.undoable {
                format!("nice {prev} -> {new}{scope}")
            } else {
                format!("nice {prev} -> {new}{scope} (undo needs {}: lowering nice is privileged)", if cfg!(target_os = "linux") { "CAP_SYS_NICE (root)" } else { "root" })
            };
        }
        Err(e) => {
            // The main thread changed but some others did not: report it as a partial
            // success (still undoable) instead of claiming nothing happened.
            if e.starts_with("partial:") && get_nice(pid) == Ok(new) {
                rec.ok = true;
                rec.pids = vec![pid];
                rec.undoable = root || new <= lowest || can_lower_nice_to(lowest);
                rec.message = format!("nice {prev} -> {new} ({e})");
            } else {
                rec.message = e;
            }
        }
    }
    threads
}

/// The (tid, nice) of every thread of `pid`. Linux only: nice is a per-thread attribute there
/// and setpriority(PRIO_PROCESS, pid) changes only the thread whose tid == pid.
#[cfg(target_os = "linux")]
fn thread_nices(pid: u32) -> Vec<(u32, i32)> {
    let mut v: Vec<(u32, i32)> = list_tids(pid).into_iter().filter_map(|t| get_nice(t).ok().map(|n| (t, n))).collect();
    v.sort_unstable();
    v
}

#[cfg(not(target_os = "linux"))]
fn thread_nices(_pid: u32) -> Vec<(u32, i32)> {
    Vec::new()
}

/// Thread ids of `pid` from /proc/<pid>/task (always includes `pid` itself while it lives).
#[cfg(target_os = "linux")]
fn list_tids(pid: u32) -> Vec<u32> {
    let mut v: Vec<u32> = fs::read_dir(format!("/proc/{pid}/task"))
        .map(|d| d.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect())
        .unwrap_or_default();
    if !v.contains(&pid) {
        v.push(pid);
    }
    v
}

/// Set one task's nice (a thread on Linux, the whole process on macOS).
fn set_nice_one(id: u32, nice: i32) -> Result<(), i32> {
    // SAFETY: setpriority has no memory preconditions.
    let r = unsafe { libc::setpriority(libc::PRIO_PROCESS, id as libc::id_t, nice) };
    if r == 0 { Ok(()) } else { Err(errno()) }
}

fn nice_error(e: i32, pid: u32, nice: i32) -> String {
    if e == libc::EACCES || e == libc::EPERM {
        format!("pid {pid}: setting nice {nice} requires root")
    } else {
        describe_errno(e, pid)
    }
}

/// Restore each thread to its recorded nice (Linux undo). Threads that exited are skipped;
/// threads created since the renice get the main thread's previous value.
#[cfg(target_os = "linux")]
fn restore_thread_nices(pid: u32, prev_main: i32, saved: &[(u32, i32)]) -> Result<(), String> {
    let tids = list_tids(pid);
    let mut failed = Vec::new();
    let mut last_err = 0;
    // Main thread first: if it fails, nothing else is attempted.
    set_nice_one(pid, prev_main).map_err(|e| nice_error(e, pid, prev_main))?;
    for &t in tids.iter().filter(|&&t| t != pid) {
        let want = saved.iter().find(|&&(s, _)| s == t).map(|&(_, n)| n).unwrap_or(prev_main);
        match set_nice_one(t, want) {
            Ok(()) => {}
            Err(e) if e == libc::ESRCH => {}
            Err(e) => {
                failed.push(t);
                last_err = e;
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("{} of {} threads not restored ({})", failed.len(), tids.len(), nice_error(last_err, pid, prev_main)))
    }
}

/// Whether we may lower any nice value. macOS: root. Linux: CAP_SYS_NICE, which root in a
/// default Docker container does not have (so euid 0 alone is not enough there).
#[cfg(not(target_os = "linux"))]
fn nice_privileged() -> bool {
    is_root()
}

#[cfg(target_os = "linux")]
fn nice_privileged() -> bool {
    has_cap_sys_nice()
}

#[cfg(not(target_os = "linux"))]
fn can_lower_nice_to(_nice: i32) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
fn lower_nice_refusal(pid: u32, prev: i32, new: i32) -> String {
    if new < 0 {
        format!("negative nice ({new}) requires root; try `sudo fat renice {pid} {new}`")
    } else {
        format!("lowering nice ({prev} -> {new}) requires root on macOS")
    }
}

/// Lowest nice an unprivileged caller may set: the kernel allows `nice` when
/// `20 - nice <= RLIMIT_NICE` (rlimit 0, the usual default, means "never lower").
#[cfg(target_os = "linux")]
fn nice_floor() -> i32 {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit writes into a valid, owned rlimit struct.
    if unsafe { libc::getrlimit(libc::RLIMIT_NICE, &mut rl) } != 0 {
        return 20;
    }
    if rl.rlim_cur == libc::RLIM_INFINITY {
        return -20;
    }
    20 - (rl.rlim_cur.min(40) as i32)
}

/// CAP_SYS_NICE (bit 23) in our effective capability set.
#[cfg(target_os = "linux")]
fn has_cap_sys_nice() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| procfs::status_field(&s, "CapEff").and_then(|v| u64::from_str_radix(v.trim(), 16).ok()))
        .is_some_and(|caps| caps & (1 << 23) != 0)
}

#[cfg(target_os = "linux")]
fn can_lower_nice_to(nice: i32) -> bool {
    nice >= nice_floor() || has_cap_sys_nice()
}

#[cfg(target_os = "linux")]
fn lower_nice_refusal(pid: u32, prev: i32, new: i32) -> String {
    let floor = nice_floor();
    let lim = if floor >= 20 { "RLIMIT_NICE is 0".to_string() } else { format!("RLIMIT_NICE allows down to {floor}") };
    if is_root() {
        return format!(
            "lowering nice ({prev} -> {new}) requires CAP_SYS_NICE, which this root lacks (e.g. a container without --cap-add SYS_NICE; {lim})"
        );
    }
    if new < 0 {
        format!("negative nice ({new}) requires root or CAP_SYS_NICE ({lim}); try `sudo fat renice {pid} {new}`")
    } else {
        format!("lowering nice ({prev} -> {new}) requires root or CAP_SYS_NICE on Linux ({lim})")
    }
}

fn kill_tree(rec: &mut ActionRecord, pid: u32, snap: &Snapshot) {
    let ours = self_and_ancestors();
    // Leaves first: order descendants by depth below `pid`, deepest first.
    let mut desc: Vec<(usize, u32, String, u64)> = snap
        .descendants(pid)
        .into_iter()
        .map(|p| (depth_below(snap, p.pid, pid), p.pid, p.name.clone(), p.start_time))
        .collect();
    desc.sort_by(|a, b| b.0.cmp(&a.0));

    let mut sent = Vec::new();
    let mut skipped = Vec::new();
    let mut continued = 0;
    for (_, cpid, cname, cstart) in desc {
        if let Err(why) = protection(cpid, &cname, &ours) {
            skipped.push(format!("{cpid} ({why})"));
            continue;
        }
        if let Some(why) = critical_refusal(ActionKind::KillTree, &cname) {
            skipped.push(format!("{cpid} ({why})"));
            continue;
        }
        if let Err(why) = kernel_thread_refusal(cpid, &cname) {
            skipped.push(format!("{cpid} ({why})"));
            continue;
        }
        match live_proc(cpid) {
            Some(l) if cstart == 0 || l.start_time.abs_diff(cstart) <= START_TIME_SLACK => {}
            _ => continue, // already exited or pid reused
        }
        match send_signal(cpid, libc::SIGTERM) {
            Ok(()) => {
                sent.push(cpid);
                continued += continue_if_stopped(cpid) as usize;
            }
            Err(e) => skipped.push(format!("{cpid} ({e})")),
        }
    }
    match send_signal(pid, libc::SIGTERM) {
        Ok(()) => {
            sent.push(pid);
            continued += continue_if_stopped(pid) as usize;
        }
        Err(e) => skipped.push(format!("{pid} ({e})")),
    }
    rec.ok = sent.contains(&pid);
    rec.message = format!(
        "sent SIGTERM to {} process(es) leaves-first: {:?}{}{}",
        sent.len(),
        sent,
        if continued > 0 { format!("; resumed {continued} paused one(s) so TERM is delivered") } else { String::new() },
        if skipped.is_empty() { String::new() } else { format!("; skipped {}", skipped.join(", ")) }
    );
    rec.pids = sent;
}

fn depth_below(snap: &Snapshot, pid: u32, root: u32) -> usize {
    let mut d = 0;
    let mut cur = pid;
    while cur != root && d < 64 {
        match snap.proc(cur) {
            Some(p) => cur = p.ppid,
            None => break,
        }
        d += 1;
    }
    d
}

// ---- syscalls ----

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn describe_errno(e: i32, pid: u32) -> String {
    match e {
        libc::ESRCH => format!("pid {pid}: no such process"),
        libc::EPERM => format!("pid {pid}: operation not permitted"),
        libc::EACCES => format!("pid {pid}: permission denied (needs root)"),
        _ => format!("pid {pid}: {}", std::io::Error::from_raw_os_error(e)),
    }
}

/// Send `sig` to a single pid (never a group: pid must be > 1).
pub fn send_signal(pid: u32, sig: i32) -> Result<(), String> {
    if pid <= 1 || pid > i32::MAX as u32 {
        return Err(format!("refusing to signal pid {pid}"));
    }
    // SAFETY: kill(2) with a positive pid targets exactly one process.
    let r = unsafe { libc::kill(pid as libc::pid_t, sig) };
    if r == 0 { Ok(()) } else { Err(describe_errno(errno(), pid)) }
}

pub fn get_nice(pid: u32) -> Result<i32, String> {
    // getpriority can legitimately return -1, so clear errno first.
    // SAFETY: writing errno for the current thread; getpriority has no memory preconditions.
    unsafe {
        #[cfg(target_os = "macos")]
        {
            *libc::__error() = 0;
        }
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = 0;
        }
        let v = libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
        let e = errno();
        if v == -1 && e != 0 { Err(describe_errno(e, pid)) } else { Ok(v) }
    }
}

/// Set the nice value of process `pid`. On Linux nice is per thread, so this sets every
/// thread in /proc/<pid>/task; an error names how many threads could not be changed.
pub fn set_nice(pid: u32, nice: i32) -> Result<(), String> {
    set_nice_one(pid, nice).map_err(|e| nice_error(e, pid, nice))?;
    #[cfg(target_os = "linux")]
    {
        let tids = list_tids(pid);
        let mut failed = 0;
        let mut last = 0;
        for &t in tids.iter().filter(|&&t| t != pid) {
            match set_nice_one(t, nice) {
                Ok(()) => {}
                Err(e) if e == libc::ESRCH => {} // thread exited meanwhile
                Err(e) => {
                    failed += 1;
                    last = e;
                }
            }
        }
        if failed > 0 {
            return Err(format!("partial: {failed} of {} threads not changed ({})", tids.len(), nice_error(last, pid, nice)));
        }
    }
    Ok(())
}

/// Read live process info straight from the kernel.
#[cfg(target_os = "macos")]
pub fn live_proc(pid: u32) -> Option<LiveProc> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: we pass a correctly sized, writable buffer for PROC_PIDTBSDINFO.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n != size {
        return None;
    }
    let cstr = |b: &[libc::c_char]| -> String {
        let bytes: Vec<u8> = b.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let name = {
        let n = cstr(&info.pbi_name);
        if n.is_empty() { cstr(&info.pbi_comm) } else { n }
    };
    const SSTOP: u32 = 4;
    const SZOMB: u32 = 5;
    if info.pbi_status == SZOMB {
        return None;
    }
    Some(LiveProc {
        pid,
        ppid: info.pbi_ppid,
        uid: info.pbi_uid,
        ruid: info.pbi_ruid,
        name,
        start_time: info.pbi_start_tvsec,
        stopped: info.pbi_status == SSTOP,
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn live_proc(pid: u32) -> Option<LiveProc> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System};
    let mut sys = System::new();
    let p = Pid::from_u32(pid);
    sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[p]), true, ProcessRefreshKind::nothing().with_user(sysinfo::UpdateKind::Always));
    let pr = sys.process(p)?;
    if pr.status() == ProcessStatus::Zombie {
        return None;
    }
    let uid = pr.user_id().map(|u| **u).unwrap_or(u32::MAX);
    Some(LiveProc {
        pid,
        ppid: pr.parent().map(|p| p.as_u32()).unwrap_or(0),
        uid,
        ruid: uid,
        name: pr.name().to_string_lossy().into_owned(),
        start_time: pr.start_time(),
        stopped: pr.status() == ProcessStatus::Stop,
    })
}

/// Linux: straight from /proc/<pid>/stat and /status (no root needed for either).
#[cfg(target_os = "linux")]
pub fn live_proc(pid: u32) -> Option<LiveProc> {
    live_proc_at(Path::new("/proc"), pid)
}

#[cfg(target_os = "linux")]
fn live_proc_at(proc_root: &Path, pid: u32) -> Option<LiveProc> {
    if pid == 0 {
        return None;
    }
    let st = procfs::read_stat(proc_root, pid)?;
    if matches!(st.state, 'Z' | 'X' | 'x') {
        return None;
    }
    let status = fs::read_to_string(proc_root.join(pid.to_string()).join("status")).unwrap_or_default();
    // /proc/<tid> also resolves thread ids (hidden from readdir); a thread is not a process
    // target, and signalling it would hit its whole thread group.
    if let Some(tgid) = procfs::status_field(&status, "Tgid").and_then(|v| v.trim().parse::<u32>().ok())
        && tgid != pid
    {
        return None;
    }
    let (ruid, euid) = procfs::uids(&status).unwrap_or((u32::MAX, u32::MAX));
    Some(LiveProc {
        pid,
        ppid: st.ppid,
        uid: euid,
        ruid,
        name: st.comm.clone(),
        start_time: procfs::start_epoch_at(proc_root, &st),
        stopped: st.state == 'T',
    })
}

/// Minimal procfs readers shared by actions and `fat run` (Linux). Never panic: every reader
/// returns None on a missing file, a permission error or an unexpected format.
#[cfg(target_os = "linux")]
pub(crate) mod procfs {
    use std::io::Read;
    use std::path::Path;
    use std::sync::OnceLock;

    /// PF_KTHREAD in /proc/<pid>/stat `flags` (include/linux/sched.h).
    pub const PF_KTHREAD: u64 = 0x0020_0000;

    /// The fields of /proc/<pid>/stat that fat uses. Times are in clock ticks.
    #[derive(Debug, Clone, Default, PartialEq)]
    pub struct Stat {
        pub pid: u32,
        pub comm: String,
        pub state: char,
        pub ppid: u32,
        pub pgrp: i32,
        pub flags: u64,
        pub utime: u64,
        pub stime: u64,
        /// Already-reaped (waited-for) children, cumulative. Signed in the kernel format.
        pub cutime: u64,
        pub cstime: u64,
        pub nice: i32,
        pub num_threads: u32,
        /// Ticks after boot.
        pub starttime: u64,
        pub rss_pages: u64,
    }

    /// Parse one /proc/<pid>/stat line, e.g. (Linux 6.x):
    /// `1234 (my (odd) prog) S 1 1234 1234 0 -1 4194560 2717 0 0 0 12 5 3 1 20 0 1 0 98765 8851456 924 18446744073709551615 ...`
    /// `comm` may contain spaces and parentheses, so fields are split after the *last* ')'.
    pub fn parse_stat(s: &str) -> Option<Stat> {
        let open = s.find('(')?;
        let close = s.rfind(')')?;
        if close < open {
            return None;
        }
        let pid: u32 = s[..open].trim().parse().ok()?;
        let comm = s[open + 1..close].to_string();
        let f: Vec<&str> = s[close + 1..].split_ascii_whitespace().collect();
        // f[0] is field 3 (state); field N is f[N - 3].
        let num = |i: usize| -> Option<i64> { f.get(i)?.parse::<i64>().ok() };
        let unum = |i: usize| -> Option<u64> { f.get(i)?.parse::<u64>().ok() };
        Some(Stat {
            pid,
            comm,
            state: f.first()?.chars().next()?,
            ppid: num(1)?.max(0) as u32,
            pgrp: num(2)? as i32,
            flags: unum(6)?,
            utime: unum(11)?,
            stime: unum(12)?,
            cutime: num(13)?.max(0) as u64,
            cstime: num(14)?.max(0) as u64,
            nice: num(16)? as i32,
            num_threads: num(17)?.max(0) as u32,
            starttime: unum(19)?,
            rss_pages: num(21)?.max(0) as u64,
        })
    }

    /// Read and parse `<proc_root>/<pid>/stat`.
    pub fn read_stat(proc_root: &Path, pid: u32) -> Option<Stat> {
        let mut buf = String::with_capacity(512);
        std::fs::File::open(proc_root.join(pid.to_string()).join("stat")).ok()?.read_to_string(&mut buf).ok()?;
        parse_stat(&buf)
    }

    pub fn is_kernel_thread(st: &Stat) -> bool {
        st.flags & PF_KTHREAD != 0
    }

    /// `Key:\tvalue` from /proc/<pid>/status.
    pub fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
        status.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
    }

    /// (real, effective) uid from the `Uid:` line (`Uid:\t1000\t1000\t1000\t1000`).
    pub fn uids(status: &str) -> Option<(u32, u32)> {
        let mut it = status_field(status, "Uid")?.split_ascii_whitespace().map(|v| v.parse::<u32>().ok());
        Some((it.next()??, it.next()??))
    }

    pub fn clk_tck() -> u64 {
        static T: OnceLock<u64> = OnceLock::new();
        // SAFETY: sysconf has no preconditions.
        *T.get_or_init(|| match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
            n if n > 0 => n as u64,
            _ => 100,
        })
    }

    pub fn page_size() -> u64 {
        static P: OnceLock<u64> = OnceLock::new();
        // SAFETY: sysconf has no preconditions.
        *P.get_or_init(|| match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
            n if n > 0 => n as u64,
            _ => 4096,
        })
    }

    pub fn ticks_to_ns(t: u64) -> u64 {
        t.saturating_mul(1_000_000_000 / clk_tck().max(1))
    }

    /// `btime` (boot time, epoch seconds) from `<proc_root>/stat`.
    pub fn read_btime(proc_root: &Path) -> Option<u64> {
        let s = std::fs::read_to_string(proc_root.join("stat")).ok()?;
        s.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())
    }

    fn btime_at(proc_root: &Path) -> Option<u64> {
        static B: OnceLock<Option<u64>> = OnceLock::new();
        if proc_root == Path::new("/proc") { *B.get_or_init(|| read_btime(proc_root)) } else { read_btime(proc_root) }
    }

    /// Process start in epoch seconds, exactly as the collector reports `Proc::start_time`:
    /// `btime + starttime / CLK_TCK` (integer seconds). 0 when btime is unreadable.
    pub fn start_epoch_at(proc_root: &Path, st: &Stat) -> u64 {
        btime_at(proc_root).map(|b| b + st.starttime / clk_tck()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Proc;
    use std::process::{Child, Command};
    use std::time::Duration;

    struct Kid(Child);
    impl Drop for Kid {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn_sleep() -> Kid {
        Kid(Command::new("sleep").arg("300").spawn().expect("spawn sleep"))
    }

    fn tmp_journal(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fat-actions-test-{}-{tag}.jsonl", std::process::id()));
        let _ = fs::remove_file(&p);
        p
    }

    fn snap_with(pid: u32) -> Snapshot {
        let l = live_proc(pid).expect("live");
        Snapshot {
            procs: vec![Proc { pid, ppid: l.ppid, name: l.name, start_time: l.start_time, ..Default::default() }],
            ..Default::default()
        }
    }

    fn wait_stopped(pid: u32, want: bool) -> bool {
        for _ in 0..40 {
            if live_proc(pid).map(|l| l.stopped) == Some(want) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    #[test]
    fn protection_policy() {
        assert!(protection(0, "kernel_task", &[]).is_err());
        assert!(protection(1, "launchd", &[]).is_err());
        assert!(protection(std::process::id(), "fat", &[]).is_err());
        assert!(protection(4242, "zsh", &[4242]).is_err());
        assert!(protection(4242, "WindowServer", &[]).is_err());
        #[cfg(not(target_os = "linux"))]
        assert!(matches!(protection(4242, "Finder", &[]), Ok(Some(_))));
        #[cfg(target_os = "linux")]
        assert!(matches!(protection(4242, "dockerd", &[]), Ok(Some(_))));
        assert_eq!(protection(4242, "node", &[]), Ok(None));
    }

    #[test]
    fn refuses_pid_1() {
        let path = tmp_journal("pid1");
        let mut a = Actions::open_at(&path);
        let snap = Snapshot::default();
        let r = a.apply(ActionKind::Kill, 1, None, &snap);
        assert!(!r.ok);
        assert!(r.message.contains("refusing"), "{}", r.message);
        let r = a.apply(ActionKind::Pause, std::process::id(), None, &snap);
        assert!(!r.ok);
        assert_eq!(a.log().len(), 2);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn refuses_reused_pid() {
        let kid = spawn_sleep();
        let pid = kid.0.id();
        let mut snap = snap_with(pid);
        snap.procs[0].start_time -= 1000;
        let path = tmp_journal("reuse");
        let mut a = Actions::open_at(&path);
        let r = a.apply(ActionKind::Term, pid, None, &snap);
        assert!(!r.ok);
        assert!(r.message.contains("reused"), "{}", r.message);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn pause_resume_undo_renice_term() {
        let kid = spawn_sleep();
        let pid = kid.0.id();
        let snap = snap_with(pid);
        let path = tmp_journal("flow");
        let mut a = Actions::open_at(&path);

        let r = a.apply(ActionKind::Pause, pid, None, &snap);
        assert!(r.ok && r.undoable, "{r:?}");
        assert!(wait_stopped(pid, true));

        let u = a.undo_last().expect("something to undo");
        assert!(u.ok, "{u:?}");
        assert!(wait_stopped(pid, false));
        assert!(a.log().iter().find(|x| x.id == r.id).unwrap().undone);
        assert!(!a.undo(r.id).ok, "double undo must fail");

        let r2 = a.apply(ActionKind::Pause, pid, None, &snap);
        assert!(r2.ok && r2.id > u.id);
        let r3 = a.apply(ActionKind::Resume, pid, None, &snap);
        assert!(r3.ok);
        assert!(wait_stopped(pid, false));

        let before = get_nice(pid).unwrap();
        let target = (before + 5).min(20);
        let n = a.apply(ActionKind::Renice, pid, Some(target), &snap);
        assert!(n.ok, "{n:?}");
        assert_eq!(n.prev_nice, Some(before));
        assert_eq!(get_nice(pid), Ok(target));
        if !is_root() {
            assert_eq!(n.undoable, target <= before || can_lower_nice_to(before));
            if !can_lower_nice_to(-5) {
                let neg = a.apply(ActionKind::Renice, pid, Some(-5), &snap);
                assert!(!neg.ok && neg.message.contains("root"), "{neg:?}");
            }
        }

        let t = a.apply(ActionKind::Term, pid, None, &snap);
        assert!(t.ok && !t.undoable);

        // Ids are monotonic and persisted.
        let log = Actions::open_at(&path).log();
        let ids: Vec<u64> = log.iter().map(|r| r.id).collect();
        assert!(ids.windows(2).all(|w| w[0] > w[1]), "{ids:?}");
        drop(kid);
        let _ = fs::remove_file(&path);
    }

    fn wait_exit(kid: &mut Kid, ms: u64) -> bool {
        for _ in 0..ms / 25 {
            if kid.0.try_wait().ok().flatten().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn critical_daemons_refused_for_freeze_and_kill() {
        for n in ["cfprefsd", "distnoted", "secd", "trustd", "usernoted", "notifyd", "WindowServer"] {
            assert!(critical_refusal(ActionKind::Pause, n).is_some(), "{n}");
            assert!(critical_refusal(ActionKind::Term, n).is_some(), "{n}");
            assert!(critical_refusal(ActionKind::KillTree, n).is_some(), "{n}");
            assert!(critical_refusal(ActionKind::Resume, n).is_none(), "{n}");
            assert!(critical_refusal(ActionKind::Renice, n).is_none(), "{n}");
        }
        assert!(critical_refusal(ActionKind::Pause, "node").is_none());
        assert!(is_critical_name("CFPREFSD"));
    }

    #[test]
    fn concurrent_writers_get_unique_ids() {
        let path = tmp_journal("concurrent");
        let threads: Vec<_> = (0..6)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let mut a = Actions::open_at(&path);
                    for _ in 0..15 {
                        // Refused (pid 1) but journaled: exercises id allocation + append only.
                        assert!(!a.apply(ActionKind::Kill, 1, None, &Snapshot::default()).ok);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let ids: Vec<u64> = Actions::open_at(&path).log().iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), 90);
        let uniq: HashSet<u64> = ids.iter().copied().collect();
        assert_eq!(uniq.len(), 90, "duplicate ids: {ids:?}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn undo_is_append_only_and_keeps_unknown_lines() {
        let kid = spawn_sleep();
        let pid = kid.0.id();
        let snap = snap_with(pid);
        let path = tmp_journal("appendonly");
        let torn = r#"{"id":77,"ts":1,"kind":"pa"#;
        let future = r#"{"id":78,"ts":2,"kind":"throttle","pid":5,"name":"x","prev_nice":null,"new_nice":null,"pids":[],"undoable":true,"undone":false,"ok":true,"message":""}"#;
        fs::write(&path, format!("{future}\n{torn}\n")).unwrap();
        let mut a = Actions::open_at(&path);
        let r = a.apply(ActionKind::Pause, pid, None, &snap);
        assert!(r.ok && r.undoable && r.id > 0, "{r:?}");
        assert!(wait_stopped(pid, true));
        let u = a.undo(r.id);
        assert!(u.ok, "{u:?}");
        assert!(wait_stopped(pid, false));
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(torn) && text.contains(future), "unparsed lines must survive an undo:\n{text}");
        assert!(a.log().iter().find(|x| x.id == r.id).unwrap().undone);
        assert!(!a.undo(r.id).ok, "double undo must fail");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn term_on_paused_process_with_handler_is_delivered() {
        let have_perl = Command::new("perl").arg("-e1").status().map(|s| s.success()).unwrap_or(false);
        if !have_perl {
            return;
        }
        let mut kid = Kid(Command::new("perl").args(["-e", "$SIG{TERM} = sub { exit 0 }; sleep 300"]).spawn().unwrap());
        let pid = kid.0.id();
        std::thread::sleep(Duration::from_millis(150)); // let perl install its handler
        let snap = snap_with(pid);
        let path = tmp_journal("termpaused");
        let mut a = Actions::open_at(&path);
        let p = a.apply(ActionKind::Pause, pid, None, &snap);
        assert!(p.ok);
        assert!(wait_stopped(pid, true));
        let t = a.apply(ActionKind::Term, pid, None, &snap);
        assert!(t.ok, "{t:?}");
        assert!(t.message.contains("SIGCONT"), "{}", t.message);
        assert!(wait_exit(&mut kid, 3000), "TERM must reach a paused process");
        // The pause is closed: undo must not "restore" (i.e. resurrect-then-kill) it.
        assert!(a.log().iter().find(|x| x.id == p.id).unwrap().undone);
        assert!(a.undo_last().is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn expect_refuses_a_different_incarnation() {
        let kid = spawn_sleep();
        let pid = kid.0.id();
        let snap = snap_with(pid); // the *new* snapshot agrees with the live process...
        let st = snap.procs[0].start_time;
        let path = tmp_journal("expect");
        let mut a = Actions::open_at(&path);
        // ...but the user chose a process that started 1000s earlier.
        let old = Expect::of(st - 1000, "sleep");
        let r = a.apply_expect(ActionKind::Term, pid, None, &snap, Some(&old));
        assert!(!r.ok && r.message.contains("no longer"), "{r:?}");
        let other = Expect::of(st, "node");
        let r = a.apply_expect(ActionKind::Pause, pid, None, &snap, Some(&other));
        assert!(!r.ok && r.message.contains("not \"node\""), "{r:?}");
        let ok = a.apply_expect(ActionKind::Pause, pid, None, &snap, Some(&Expect::of(st, "sleep")));
        assert!(ok.ok, "{ok:?}");
        assert!(a.undo(ok.id).ok);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn unwritable_journal_means_not_undoable() {
        let kid = spawn_sleep();
        let pid = kid.0.id();
        let snap = snap_with(pid);
        let mut a = Actions::open_at("/dev/null/fat-no-such-dir/actions.jsonl");
        let r = a.apply(ActionKind::Pause, pid, None, &snap);
        assert!(r.ok, "{r:?}");
        assert!(!r.undoable && r.id == 0, "{r:?}");
        assert!(r.message.contains("fat resume"), "{}", r.message);
        assert!(wait_stopped(pid, true));
        assert!(a.apply(ActionKind::Resume, pid, None, &snap).ok);
        assert!(wait_stopped(pid, false));
    }

    #[test]
    fn undo_unknown_and_kill_not_undoable() {
        let path = tmp_journal("unk");
        let mut a = Actions::open_at(&path);
        assert!(!a.undo(999).ok);
        assert!(a.undo_last().is_none());
        let _ = fs::remove_file(&path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_critical_and_warn_names() {
        for n in ["systemd", "systemd-journald", "systemd-journal", "systemd-logind", "dbus-daemon", "dbus-broker", "Xorg", "Xwayland", "gnome-shell", "kwin_wayland", "plasmashell", "gdm", "sddm", "polkitd", "NetworkManager", "kubelet"] {
            assert!(is_critical_name(n), "{n}");
            assert!(critical_refusal(ActionKind::Pause, n).is_some(), "{n}");
            assert!(critical_refusal(ActionKind::Kill, n).is_some(), "{n}");
            assert!(critical_refusal(ActionKind::Renice, n).is_none(), "{n}");
            assert!(critical_refusal(ActionKind::Resume, n).is_none(), "{n}");
        }
        // Truncated comm of dbus-broker-launch; but not every 15-char prefix of anything.
        assert!(is_critical_name("dbus-broker-lau"));
        assert!(!is_critical_name("systemd-journ"));
        for n in ["containerd-shim", "sshd-session", "node", "systemd-run"] {
            assert!(!is_critical_name(n), "{n}");
        }
        for n in ["sshd", "containerd", "dockerd"] {
            assert!(!is_critical_name(n), "{n}");
            assert!(matches!(protection(4242, n, &[]), Ok(Some(_))), "{n}");
        }
        assert!(protection(1, "systemd", &[]).unwrap_err().contains("init"));
    }

    #[cfg(target_os = "linux")]
    fn fixture_proc(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("fat-actions-procfs-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        // Real /proc/stat excerpt (Linux 6.8): cpu lines, then btime.
        fs::write(root.join("stat"), "cpu  1162 0 1460 466436 75 0 52 0 0 0\ncpu0 290 0 365 116619 18 0 13 0 0 0\nintr 1\nctxt 2\nbtime 1762650000\nprocesses 3\n").unwrap();
        root
    }

    #[cfg(target_os = "linux")]
    fn fixture_pid(root: &Path, pid: u32, stat: &str, uid_line: &str, tgid: u32) {
        let d = root.join(pid.to_string());
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("stat"), stat).unwrap();
        fs::write(d.join("status"), format!("Name:\tx\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t{tgid}\nNgid:\t0\nPid:\t{pid}\nPPid:\t1\n{uid_line}\nGid:\t1000\t1000\t1000\t1000\n")).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_procfs_parsing() {
        // comm with spaces and a ')' inside: split after the last ')'.
        let line = "4321 (tmux: server) x)) T 1 4321 4321 0 -1 4194624 300 0 0 0 250 50 -3 7 20 5 3 0 123456 9000000 1500 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 2 0 0 0 0 0\n";
        let st = procfs::parse_stat(line).unwrap();
        assert_eq!(st.pid, 4321);
        assert_eq!(st.comm, "tmux: server) x)");
        assert_eq!(st.state, 'T');
        assert_eq!((st.ppid, st.pgrp, st.utime, st.stime, st.cutime, st.cstime), (1, 4321, 250, 50, 0, 7));
        assert_eq!((st.nice, st.num_threads, st.starttime, st.rss_pages), (5, 3, 123456, 1500));
        assert!(!procfs::is_kernel_thread(&st));
        assert!(procfs::parse_stat("garbage").is_none());
        assert!(procfs::parse_stat("12 (x) S").is_none());

        let root = fixture_proc("parse");
        // kworker: flags 0x04208060 has PF_KTHREAD; ppid 2.
        let kw = "57 (kworker/0:1-events) I 2 0 0 0 -1 69238880 0 0 0 0 0 31 0 0 20 0 1 0 41 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 0 0 0 0 0\n";
        fixture_pid(&root, 57, kw, "Uid:\t0\t0\t0\t0", 57);
        let tck = procfs::clk_tck();
        let sl = format!("900 (sleep) S 1 900 900 0 -1 4194304 90 0 0 0 0 0 0 0 20 0 1 0 {} 2412544 220 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0\n", 345 * tck + tck / 2);
        fixture_pid(&root, 900, &sl, "Uid:\t1000\t1001\t1000\t1000", 900);
        // A thread id of 900: reachable as /proc/901 but not a process.
        fixture_pid(&root, 901, &sl.replacen("900", "901", 1), "Uid:\t1000\t1000\t1000\t1000", 900);
        fixture_pid(&root, 902, "902 (defunct) Z 900 900 900 0 -1 4227084 0 0 0 0 0 0 0 0 20 0 1 0 50 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0\n", "Uid:\t1000\t1000\t1000\t1000", 902);

        let l = live_proc_at(&root, 900).unwrap();
        assert_eq!((l.ppid, l.ruid, l.uid, l.name.as_str(), l.stopped), (1, 1000, 1001, "sleep", false));
        assert_eq!(l.start_time, 1_762_650_000 + 345, "btime + starttime / CLK_TCK, whole seconds");
        assert!(live_proc_at(&root, 901).is_none(), "thread ids are not processes");
        assert!(live_proc_at(&root, 902).is_none(), "zombies are gone");
        assert!(live_proc_at(&root, 0).is_none());
        assert!(live_proc_at(&root, 77777).is_none());
        let kst = procfs::read_stat(&root, 57).unwrap();
        assert!(procfs::is_kernel_thread(&kst));
        assert_eq!(kst.ppid, 2);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_live_start_time_matches_ps() {
        // Our formula agrees with procps' (which also uses btime + starttime / HZ).
        let kid = spawn_sleep();
        let pid = kid.0.id();
        let l = live_proc(pid).unwrap();
        assert_eq!(l.name, "sleep");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(l.start_time.abs_diff(now) <= 2, "{} vs now {now}", l.start_time);
        if let Ok(out) = Command::new("ps").args(["-o", "lstart=", "-p", &pid.to_string()]).env("LC_ALL", "C").env("TZ", "UTC").output()
            && let Ok(d) = Command::new("date").args(["-u", "-d", String::from_utf8_lossy(&out.stdout).trim(), "+%s"]).output()
            && let Ok(ps_start) = String::from_utf8_lossy(&d.stdout).trim().parse::<u64>()
        {
            assert!(ps_start.abs_diff(l.start_time) <= 1, "ps says {ps_start}, we say {}", l.start_time);
        }
        // Kernel threads are refused when visible (not in a container's pid namespace).
        if let Some(kt) = live_proc(2).filter(|l| l.name == "kthreadd") {
            assert!(kernel_thread_refusal(kt.pid, &kt.name).is_err());
        }
        assert!(kernel_thread_refusal(pid, "sleep").is_ok());
    }

    /// Linux nice is per thread: renice must reach every thread, and undo must restore each.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_renice_reaches_every_thread() {
        let script = "import threading,time\nfor _ in range(3): threading.Thread(target=time.sleep,args=(300,),daemon=True).start()\ntime.sleep(300)";
        let Ok(child) = Command::new("python3").args(["-c", script]).spawn() else { return };
        let kid = Kid(child);
        let pid = kid.0.id();
        let t0 = std::time::Instant::now();
        while list_tids(pid).len() < 4 && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(list_tids(pid).len() >= 4, "threads did not start");
        let snap = snap_with(pid);
        let path = tmp_journal("tnice");
        let mut a = Actions::open_at(&path);
        let before = get_nice(pid).unwrap();
        let target = (before + 7).min(19);
        let r = a.apply(ActionKind::Renice, pid, Some(target), &snap);
        assert!(r.ok, "{r:?}");
        assert!(r.message.contains("threads"), "{}", r.message);
        for (t, n) in thread_nices(pid) {
            assert_eq!(n, target, "thread {t} kept its nice");
        }
        if r.undoable {
            let u = a.undo(r.id);
            assert!(u.ok, "{u:?}");
            for (t, n) in thread_nices(pid) {
                assert_eq!(n, before, "thread {t} not restored");
            }
        }
        let _ = fs::remove_file(&path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unprivileged_cannot_lower_nice() {
        if nice_privileged() || can_lower_nice_to(0) {
            return;
        }
        let kid = spawn_sleep();
        let pid = kid.0.id();
        let snap = snap_with(pid);
        let path = tmp_journal("lnice");
        let mut a = Actions::open_at(&path);
        let up = a.apply(ActionKind::Renice, pid, Some(10), &snap);
        assert!(up.ok && !up.undoable, "{up:?}");
        assert!(up.message.contains("undo needs CAP_SYS_NICE"), "{}", up.message);
        let down = a.apply(ActionKind::Renice, pid, Some(5), &snap);
        assert!(!down.ok && down.message.contains("RLIMIT_NICE"), "{down:?}");
        assert_eq!(get_nice(pid), Ok(10));
        let _ = fs::remove_file(&path);
    }
}
