//! Safe, reversible actions with a persisted journal. OWNER: actions agent.
//!
//! Every action (including refused ones) is appended to a JSONL journal so the
//! TUI, CLI and MCP all share one audit trail. Undo marks the original record
//! `undone` (the journal is rewritten atomically) and appends the undo itself
//! as a new record.
use crate::model::{now_ms, ActionKind, ActionRecord, Snapshot};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Process names we never signal, whatever the uid.
const PROTECTED_NAMES: &[&str] = &["kernel_task", "launchd", "WindowServer", "loginwindow"];
/// Process names that are allowed but deserve a warning.
const WARN_NAMES: &[&str] = &["Finder", "Dock", "SystemUIServer"];
/// Tolerance (seconds) when comparing snapshot vs live start times.
const START_TIME_SLACK: u64 = 2;

/// One journal line: the public record plus private bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    #[serde(flatten)]
    rec: ActionRecord,
    /// Target's start time (epoch secs) when the action was applied; used to
    /// make sure undo does not hit a recycled pid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    start_time: Option<u64>,
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

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Apply an action. `nice` required for Renice. Refuses protected pids (0, 1, self, kernel_task, WindowServer, launchd, loginwindow).
    pub fn apply(&mut self, kind: ActionKind, pid: u32, nice: Option<i32>, snap: &Snapshot) -> ActionRecord {
        let snap_name = snap.proc(pid).map(|p| p.name.clone());
        let live = live_proc(pid);
        let name = snap_name
            .clone()
            .or_else(|| live.as_ref().map(|l| l.name.clone()))
            .unwrap_or_else(|| "?".into());
        let mut rec = ActionRecord {
            id: 0,
            ts: now_ms(),
            kind,
            pid,
            name: name.clone(),
            prev_nice: None,
            new_nice: None,
            pids: Vec::new(),
            undoable: false,
            undone: false,
            ok: false,
            message: String::new(),
        };
        let start_time = live.as_ref().map(|l| l.start_time);

        match check_target(pid, live.as_ref(), snap) {
            Err(msg) => rec.message = msg,
            Ok(warning) => {
                execute(&mut rec, kind, pid, nice, snap);
                if let Some(w) = warning {
                    rec.message = format!("{} (warning: {w})", rec.message);
                }
            }
        }
        self.append(Entry { rec, start_time })
    }

    /// Undo by id (pause->resume, renice->restore). Kill is not undoable.
    pub fn undo(&mut self, id: u64) -> ActionRecord {
        self.entries = load(&self.path);
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

        let mut rec = ActionRecord {
            id: 0,
            ts: now_ms(),
            kind: undo_kind,
            pid: o.pid,
            name: o.name.clone(),
            prev_nice: None,
            new_nice: None,
            pids: Vec::new(),
            undoable: false,
            undone: false,
            ok: false,
            message: String::new(),
        };

        // Targets: the pids the original touched (falls back to the main pid).
        let targets: Vec<u32> = if o.pids.is_empty() { vec![o.pid] } else { o.pids.clone() };
        let main_live = live_proc(o.pid);
        let gone = match (&main_live, orig.start_time) {
            (None, _) => true,
            (Some(l), Some(st)) => l.start_time.abs_diff(st) > START_TIME_SLACK,
            (Some(_), None) => false,
        };
        if gone {
            rec.message = format!("undo #{id}: process {} is gone (exited or pid reused); marking undone", o.pid);
            rec.ok = true;
            self.mark_undone(id);
            return self.append(Entry { rec, start_time: orig.start_time });
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
                        match set_nice(o.pid, prev) {
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
        if rec.ok {
            self.mark_undone(id);
        }
        self.append(Entry { rec, start_time: orig.start_time })
    }

    pub fn undo_last(&mut self) -> Option<ActionRecord> {
        self.entries = load(&self.path);
        let id = self
            .entries
            .iter()
            .rev()
            .find(|e| e.rec.ok && e.rec.undoable && !e.rec.undone)
            .map(|e| e.rec.id)?;
        Some(self.undo(id))
    }

    /// Most recent first.
    pub fn log(&self) -> Vec<ActionRecord> {
        let mut v: Vec<ActionRecord> = load(&self.path).into_iter().map(|e| e.rec).collect();
        v.sort_by(|a, b| b.id.cmp(&a.id));
        v
    }

    // ---- journal persistence ----

    fn append(&mut self, mut entry: Entry) -> ActionRecord {
        // Re-read so concurrent fat instances (TUI + CLI) don't reuse ids.
        self.entries = load(&self.path);
        entry.rec.id = self.entries.iter().map(|e| e.rec.id).max().unwrap_or(0) + 1;
        if let Some(dir) = self.path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let line = serde_json::to_string(&entry).unwrap_or_default();
        let res = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = res {
            entry.rec.message = format!("{} (journal write failed: {e})", entry.rec.message);
        }
        let rec = entry.rec.clone();
        self.entries.push(entry);
        rec
    }

    fn mark_undone(&mut self, id: u64) {
        self.entries = load(&self.path);
        for e in &mut self.entries {
            if e.rec.id == id {
                e.rec.undone = true;
            }
        }
        let body: String = self
            .entries
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .map(|l| l + "\n")
            .collect();
        let tmp = self.path.with_extension("jsonl.tmp");
        if fs::write(&tmp, body).is_ok() {
            let _ = fs::rename(&tmp, &self.path);
        }
    }
}

fn load(path: &Path) -> Vec<Entry> {
    let Ok(text) = fs::read_to_string(path) else { return Vec::new() };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .collect()
}

fn failed(kind: ActionKind, pid: u32, name: &str, message: String) -> ActionRecord {
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
        message,
    }
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
        return Ok(Some(format!("{name} is part of the desktop; macOS will relaunch it")));
    }
    Ok(None)
}

/// Full target validation: protection policy, liveness, pid-reuse, ownership.
fn check_target(pid: u32, live: Option<&LiveProc>, snap: &Snapshot) -> Result<Option<String>, String> {
    let sp = snap.proc(pid);
    let name = sp.map(|p| p.name.as_str()).or(live.map(|l| l.name.as_str())).unwrap_or("?");
    let warning = protection(pid, name, &self_and_ancestors())?;
    if let Some(l) = live
        && l.name != name {
            protection(pid, &l.name, &[])?;
        }
    let Some(live) = live else {
        return Err(format!("pid {pid} is not running"));
    };
    if let Some(sp) = sp
        && sp.start_time != 0 && live.start_time != 0 && sp.start_time.abs_diff(live.start_time) > START_TIME_SLACK {
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

fn execute(rec: &mut ActionRecord, kind: ActionKind, pid: u32, nice: Option<i32>, snap: &Snapshot) {
    match kind {
        ActionKind::Pause => signal_one(rec, pid, libc::SIGSTOP, "paused (SIGSTOP)", true),
        ActionKind::Resume => signal_one(rec, pid, libc::SIGCONT, "resumed (SIGCONT)", false),
        ActionKind::Term => signal_one(rec, pid, libc::SIGTERM, "sent SIGTERM", false),
        ActionKind::Kill => signal_one(rec, pid, libc::SIGKILL, "sent SIGKILL", false),
        ActionKind::Renice => renice(rec, pid, nice),
        ActionKind::KillTree => kill_tree(rec, pid, snap),
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

fn renice(rec: &mut ActionRecord, pid: u32, nice: Option<i32>) {
    let Some(new) = nice else {
        rec.message = "renice needs a nice value (-20..20)".into();
        return;
    };
    let new = new.clamp(-20, 20);
    let prev = match get_nice(pid) {
        Ok(p) => p,
        Err(e) => {
            rec.message = e;
            return;
        }
    };
    rec.prev_nice = Some(prev);
    rec.new_nice = Some(new);
    let root = is_root();
    if new < prev && !root {
        rec.message = if new < 0 {
            format!("negative nice ({new}) requires root; try `sudo fat renice {pid} {new}`")
        } else {
            format!("lowering nice ({prev} -> {new}) requires root on macOS")
        };
        return;
    }
    match set_nice(pid, new) {
        Ok(()) => {
            rec.ok = true;
            rec.pids = vec![pid];
            // Restoring a lower nice value later needs root unless we are root.
            rec.undoable = root || new <= prev;
            rec.message = if rec.undoable {
                format!("nice {prev} -> {new}")
            } else {
                format!("nice {prev} -> {new} (undo needs root: lowering nice is privileged)")
            };
        }
        Err(e) => rec.message = e,
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
    for (_, cpid, cname, cstart) in desc {
        if let Err(why) = protection(cpid, &cname, &ours) {
            skipped.push(format!("{cpid} ({why})"));
            continue;
        }
        match live_proc(cpid) {
            Some(l) if cstart == 0 || l.start_time.abs_diff(cstart) <= START_TIME_SLACK => {}
            _ => continue, // already exited or pid reused
        }
        match send_signal(cpid, libc::SIGTERM) {
            Ok(()) => sent.push(cpid),
            Err(e) => skipped.push(format!("{cpid} ({e})")),
        }
    }
    match send_signal(pid, libc::SIGTERM) {
        Ok(()) => sent.push(pid),
        Err(e) => skipped.push(format!("{pid} ({e})")),
    }
    rec.ok = sent.contains(&pid);
    rec.message = format!(
        "sent SIGTERM to {} process(es) leaves-first: {:?}{}",
        sent.len(),
        sent,
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

pub fn set_nice(pid: u32, nice: i32) -> Result<(), String> {
    // SAFETY: setpriority has no memory preconditions.
    let r = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice) };
    if r == 0 {
        Ok(())
    } else {
        let e = errno();
        if e == libc::EACCES || e == libc::EPERM {
            Err(format!("pid {pid}: setting nice {nice} requires root"))
        } else {
            Err(describe_errno(e, pid))
        }
    }
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

#[cfg(not(target_os = "macos"))]
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
        assert!(matches!(protection(4242, "Finder", &[]), Ok(Some(_))));
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
            assert_eq!(n.undoable, target <= before);
            let neg = a.apply(ActionKind::Renice, pid, Some(-5), &snap);
            assert!(!neg.ok && neg.message.contains("root"), "{neg:?}");
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

    #[test]
    fn undo_unknown_and_kill_not_undoable() {
        let path = tmp_journal("unk");
        let mut a = Actions::open_at(&path);
        assert!(!a.undo(999).ok);
        assert!(a.undo_last().is_none());
        let _ = fs::remove_file(&path);
    }
}
