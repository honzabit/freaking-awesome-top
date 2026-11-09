//! Linux Evidence::Watch: live file-change events since fat started.
//!
//! As root: fanotify with FAN_MARK_FILESYSTEM | FAN_REPORT_DFID_NAME on every real disk
//! filesystem (kernel >= 5.9): whole-filesystem coverage, exact paths, and the writing pid.
//! Otherwise: inotify on a bounded set of directories (home and its children, /tmp, /var/log,
//! then the scanner's largest dirs), non-recursive.
use super::{F_CREATED, F_DIR, F_MODIFIED, F_REMOVED, F_RENAMED, PathEv};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const MAX_WATCHES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Off,
    Fanotify,
    Inotify,
}

#[derive(Default)]
pub struct WState {
    pub paths: HashMap<String, PathEv>,
    pub mode: Mode,
    pub started: i64,
    pub overflow: u64,
    pub events: u64,
    /// fanotify: filesystems marked; inotify: watched dirs.
    pub marked: Vec<String>,
    pub errors: Vec<String>,
    /// Some filesystems only got a mount mark (no create/delete events).
    pub partial: bool,
    ino_fd: i32,
    wds: HashMap<i32, String>,
}

pub struct Watcher {
    pub state: Arc<Mutex<WState>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

const SKIP_FS: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "ramfs",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "tracefs",
    "bpf",
    "fusectl",
    "mqueue",
    "hugetlbfs",
    "configfs",
    "pstore",
    "autofs",
    "nsfs",
    "binfmt_misc",
    "efivarfs",
    "rpc_pipefs",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "sshfs",
    "9p",
    "virtiofs",
    "squashfs",
    "iso9660",
    "overlay",
    "selinuxfs",
    "fuse",
    "zonefs",
    "erofs",
];

/// Disk-backed mount points from /proc/self/mountinfo (fstype, mount point).
pub fn disk_mounts() -> Vec<(String, String)> {
    let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    parse_mounts(&text)
}

pub fn parse_mounts(text: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    for l in text.lines() {
        let Some((left, right)) = l.split_once(" - ") else {
            continue;
        };
        let mp = left.split(' ').nth(4).unwrap_or("");
        let fstype = right.split(' ').next().unwrap_or("");
        let base = fstype.split('.').next().unwrap_or(fstype);
        if mp.is_empty() || SKIP_FS.contains(&base) || base.starts_with("fuse") || super::paths::is_pseudo_path(mp) {
            continue;
        }
        let mp = mp.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\");
        out.push((fstype.to_string(), mp));
    }
    out
}

impl Watcher {
    pub fn start(exclude: Vec<String>, cap: usize, initial_dirs: Vec<String>) -> Watcher {
        let state = Arc::new(Mutex::new(WState {
            started: crate::model::now_ms(),
            ino_fd: -1,
            ..Default::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let fan = if unsafe { libc::geteuid() } == 0 {
            fanotify_setup(&state)
        } else {
            None
        };
        let fds = match fan {
            Some(fds) => fds,
            None => {
                let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
                let mut s = state.lock().unwrap();
                if fd < 0 {
                    s.errors
                        .push(format!("inotify_init1: {}", std::io::Error::last_os_error()));
                    return Watcher {
                        state: state.clone(),
                        stop,
                        thread: None,
                    };
                }
                s.mode = Mode::Inotify;
                s.ino_fd = fd;
                drop(s);
                vec![fd]
            }
        };
        let w = {
            let (st, sp) = (state.clone(), stop.clone());
            let thread = std::thread::Builder::new()
                .name("fat-fswatch".into())
                .spawn(move || run(fds, st, sp, cap, exclude))
                .ok();
            Watcher { state, stop, thread }
        };
        if w.mode() == Mode::Inotify {
            w.add_dirs(&initial_dirs);
        }
        w
    }

    pub fn mode(&self) -> Mode {
        self.state.lock().map(|s| s.mode).unwrap_or_default()
    }

    /// inotify only: watch more directories (bounded by MAX_WATCHES). Returns how many were added.
    pub fn add_dirs(&self, dirs: &[String]) -> usize {
        let mut s = self.state.lock().unwrap();
        if s.mode != Mode::Inotify {
            return 0;
        }
        let mut added = 0;
        for d in dirs {
            if s.wds.len() >= MAX_WATCHES {
                break;
            }
            if s.marked.contains(d) || super::paths::is_pseudo_path(d) {
                continue;
            }
            let Ok(c) = CString::new(d.as_str()) else { continue };
            let mask = libc::IN_MODIFY
                | libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
                | libc::IN_ONLYDIR
                | libc::IN_DONT_FOLLOW
                | libc::IN_EXCL_UNLINK;
            let wd = unsafe { libc::inotify_add_watch(s.ino_fd, c.as_ptr(), mask) };
            if wd >= 0 {
                s.wds.insert(wd, d.clone());
                s.marked.push(d.clone());
                added += 1;
            }
        }
        added
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// fsid -> fd of the mount, for open_by_handle_at.
type MountFds = HashMap<[i32; 2], i32>;

static MOUNT_FDS: Mutex<Option<MountFds>> = Mutex::new(None);

fn fsid_of(path: &str) -> Option<[i32; 2]> {
    let c = CString::new(path).ok()?;
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut sf) } != 0 {
        return None;
    }
    // SAFETY: fsid_t is two c_ints with private fields.
    Some(unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(sf.f_fsid) })
}

/// As root: one FID-mode fanotify fd with filesystem marks (paths + creates/deletes), plus a
/// classic-mode fd with mount marks for filesystems that refuse FID marks (btrfs subvolumes
/// return EXDEV): there each event carries an open fd we resolve, modifications only.
fn fanotify_setup(state: &Arc<Mutex<WState>>) -> Option<Vec<i32>> {
    let fid_fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_REPORT_DFID_NAME | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    let mut s = state.lock().unwrap();
    if fid_fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EPERM) {
            s.errors.push(format!("fanotify_init: {e} (needs CAP_SYS_ADMIN)"));
            return None;
        }
        s.errors.push(format!(
            "fanotify_init(FAN_REPORT_DFID_NAME): {e} (needs kernel >= 5.9)"
        ));
    }
    let mut classic_fd = -1;
    let mask = libc::FAN_MODIFY | libc::FAN_CREATE | libc::FAN_DELETE | libc::FAN_MOVED_FROM | libc::FAN_MOVED_TO;
    let mut fds: MountFds = HashMap::new();
    let mut seen: Vec<[i32; 2]> = vec![];
    for (fstype, mp) in disk_mounts() {
        if !std::path::Path::new(&mp).is_dir() {
            continue; // bind-mounted files (/etc/hosts in containers)
        }
        let Some(fsid) = fsid_of(&mp) else { continue };
        if seen.contains(&fsid) {
            continue;
        }
        let Ok(c) = CString::new(mp.as_str()) else { continue };
        let fid_err = if fid_fd >= 0 {
            let r = unsafe {
                libc::fanotify_mark(
                    fid_fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                    mask,
                    libc::AT_FDCWD,
                    c.as_ptr(),
                )
            };
            if r == 0 {
                let mfd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
                if mfd >= 0 {
                    fds.insert(fsid, mfd);
                }
                seen.push(fsid);
                s.marked.push(mp);
                continue;
            }
            std::io::Error::last_os_error().to_string()
        } else {
            "no FID support".to_string()
        };
        if classic_fd < 0 {
            classic_fd = unsafe {
                libc::fanotify_init(
                    libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                    (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
                )
            };
        }
        let r = if classic_fd >= 0 {
            unsafe {
                libc::fanotify_mark(
                    classic_fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                    libc::FAN_MODIFY,
                    libc::AT_FDCWD,
                    c.as_ptr(),
                )
            }
        } else {
            -1
        };
        if r != 0 {
            s.errors.push(format!(
                "fanotify_mark {mp} ({fstype}): {fid_err}; mount mark: {}",
                std::io::Error::last_os_error()
            ));
            continue;
        }
        s.errors.push(format!(
            "{mp} ({fstype}): filesystem mark refused ({fid_err}); mount mark, modifications only"
        ));
        s.partial = true;
        seen.push(fsid);
        s.marked.push(mp);
    }
    let mut out = vec![];
    for fd in [fid_fd, classic_fd] {
        if fd >= 0 {
            out.push(fd);
        }
    }
    if s.marked.is_empty() {
        for fd in out {
            unsafe { libc::close(fd) };
        }
        s.errors.push("fanotify: no filesystem could be marked".into());
        return None;
    }
    s.mode = Mode::Fanotify;
    *MOUNT_FDS.lock().unwrap() = Some(fds);
    Some(out)
}

fn run(fds: Vec<i32>, state: Arc<Mutex<WState>>, stop: Arc<AtomicBool>, cap: usize, exclude: Vec<String>) {
    let mode = state.lock().map(|s| s.mode).unwrap_or_default();
    let me = std::process::id() as i32;
    // u64-aligned read buffer.
    let mut buf = vec![0u64; 8192];
    let mut dircache: HashMap<Vec<u8>, Option<String>> = HashMap::new();
    let mut pfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    while !stop.load(Ordering::SeqCst) {
        for p in pfds.iter_mut() {
            p.revents = 0;
        }
        let r = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 500) };
        if r <= 0 {
            continue;
        }
        for &fd in &fds {
            // Drain what is queued, but keep checking `stop` under a constant event flood.
            for _ in 0..64 {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len() * 8) };
                if n <= 0 {
                    break;
                }
                let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n as usize) };
                let now = crate::model::now_ms();
                let evs = match mode {
                    Mode::Fanotify => parse_fanotify(bytes, &mut dircache, me),
                    _ => {
                        let s = state.lock().unwrap();
                        parse_inotify(bytes, &s.wds)
                    }
                };
                let mut s = state.lock().unwrap();
                for ev in evs {
                    match ev {
                        Ev::Overflow => s.overflow += 1,
                        Ev::Ignored(wd) => {
                            if let Some(p) = s.wds.remove(&wd) {
                                s.marked.retain(|m| *m != p);
                            }
                        }
                        Ev::Path { path, flags, pid } => {
                            s.events += 1;
                            if exclude.iter().any(|e| super::under_prefix(&path, e)) {
                                continue;
                            }
                            super::record_event(&mut s.paths, cap, &path, flags, now, pid);
                        }
                    }
                }
                if dircache.len() > 50_000 {
                    dircache.clear();
                }
            }
        }
    }
    for fd in fds {
        unsafe { libc::close(fd) };
    }
}

#[derive(Debug, PartialEq)]
pub enum Ev {
    Path { path: String, flags: u32, pid: u32 },
    Overflow,
    Ignored(i32),
}

fn fan_flags(mask: u64) -> u32 {
    let mut f = 0;
    if mask & libc::FAN_CREATE != 0 {
        f |= F_CREATED;
    }
    if mask & libc::FAN_DELETE != 0 {
        f |= F_REMOVED;
    }
    if mask & libc::FAN_MODIFY != 0 {
        f |= F_MODIFIED;
    }
    if mask & libc::FAN_MOVED_FROM != 0 {
        f |= F_REMOVED | F_RENAMED;
    }
    if mask & libc::FAN_MOVED_TO != 0 {
        f |= F_RENAMED;
    }
    if mask & libc::FAN_ONDIR != 0 {
        f |= F_DIR;
    }
    f
}

fn parse_fanotify(bytes: &[u8], cache: &mut HashMap<Vec<u8>, Option<String>>, me: i32) -> Vec<Ev> {
    let mut out = vec![];
    let mut off = 0usize;
    let rd_u16 = |b: &[u8], o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
    let rd_u32 = |b: &[u8], o: usize| u32::from_ne_bytes(b[o..o + 4].try_into().unwrap());
    let rd_u64 = |b: &[u8], o: usize| u64::from_ne_bytes(b[o..o + 8].try_into().unwrap());
    // struct fanotify_event_metadata { u32 event_len; u8 vers; u8 reserved; u16 metadata_len; u64 mask; i32 fd; i32 pid; }
    while off + 24 <= bytes.len() {
        let ev_len = rd_u32(bytes, off) as usize;
        let md_len = rd_u16(bytes, off + 6) as usize;
        if ev_len < 24 || off + ev_len > bytes.len() {
            break;
        }
        let mask = rd_u64(bytes, off + 8);
        let efd = rd_u32(bytes, off + 16) as i32;
        let pid = rd_u32(bytes, off + 20) as i32;
        // Classic-mode event: an open fd on the object instead of info records.
        let fd_path = if efd >= 0 {
            let p = std::fs::read_link(format!("/proc/self/fd/{efd}"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned());
            unsafe { libc::close(efd) };
            p.filter(|p| p.starts_with('/') && !p.ends_with(" (deleted)"))
        } else {
            None
        };
        if mask & libc::FAN_Q_OVERFLOW != 0 {
            out.push(Ev::Overflow);
        } else if efd >= 0 {
            if let Some(path) = fd_path
                && pid != me
            {
                out.push(Ev::Path {
                    path,
                    flags: fan_flags(mask),
                    pid: pid.max(0) as u32,
                });
            }
        } else if pid != me {
            let mut io = off + md_len;
            while io + 4 <= off + ev_len {
                let ty = bytes[io];
                let len = rd_u16(bytes, io + 2) as usize;
                if len < 4 || io + len > off + ev_len {
                    break;
                }
                if ty == libc::FAN_EVENT_INFO_TYPE_DFID_NAME || ty == libc::FAN_EVENT_INFO_TYPE_DFID {
                    // header(4) fsid(8) file_handle{u32 bytes, i32 type, data} [name\0]
                    let rec = &bytes[io..io + len];
                    if rec.len() >= 20 {
                        let fsid = [
                            i32::from_ne_bytes(rec[4..8].try_into().unwrap()),
                            i32::from_ne_bytes(rec[8..12].try_into().unwrap()),
                        ];
                        let hb = u32::from_ne_bytes(rec[12..16].try_into().unwrap()) as usize;
                        if 20 + hb <= rec.len() {
                            let key = rec[4..20 + hb].to_vec();
                            let dir = cache
                                .entry(key)
                                .or_insert_with(|| resolve_handle(fsid, &rec[12..20 + hb]))
                                .clone();
                            if let Some(dir) = dir {
                                let name = if ty == libc::FAN_EVENT_INFO_TYPE_DFID_NAME {
                                    let nb = &rec[20 + hb..];
                                    let end = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
                                    String::from_utf8_lossy(&nb[..end]).into_owned()
                                } else {
                                    String::new()
                                };
                                let path = if name.is_empty() || name == "." {
                                    dir
                                } else if dir == "/" {
                                    format!("/{name}")
                                } else {
                                    format!("{dir}/{name}")
                                };
                                out.push(Ev::Path {
                                    path,
                                    flags: fan_flags(mask),
                                    pid: pid.max(0) as u32,
                                });
                            }
                        }
                    }
                    break;
                }
                io += len;
            }
        }
        off += ev_len;
    }
    out
}

/// `fh` = struct file_handle bytes (handle_bytes, handle_type, f_handle).
fn resolve_handle(fsid: [i32; 2], fh: &[u8]) -> Option<String> {
    let mfd = *MOUNT_FDS.lock().ok()?.as_ref()?.get(&fsid)?;
    // u32-aligned copy of the handle.
    let mut h = vec![0u32; fh.len().div_ceil(4)];
    unsafe { std::ptr::copy_nonoverlapping(fh.as_ptr(), h.as_mut_ptr() as *mut u8, fh.len()) };
    let fd = unsafe {
        libc::open_by_handle_at(
            mfd,
            h.as_mut_ptr() as *mut libc::file_handle,
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let p = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
    unsafe { libc::close(fd) };
    let p = p?.to_string_lossy().into_owned();
    if !ok || p.ends_with(" (deleted)") {
        return None;
    }
    // A handle for a dir outside the marked mount's root (e.g. another btrfs subvolume of the
    // same filesystem) reads back as a bogus path like "/": keep it only if it names that dir.
    use std::os::unix::fs::MetadataExt;
    let same = std::fs::symlink_metadata(&p).is_ok_and(|m| m.dev() == st.st_dev && m.ino() == st.st_ino);
    same.then_some(p)
}

pub fn parse_inotify(bytes: &[u8], wds: &HashMap<i32, String>) -> Vec<Ev> {
    let mut out = vec![];
    let mut off = 0usize;
    // struct inotify_event { i32 wd; u32 mask; u32 cookie; u32 len; char name[len]; }
    while off + 16 <= bytes.len() {
        let wd = i32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap());
        let mask = u32::from_ne_bytes(bytes[off + 4..off + 8].try_into().unwrap());
        let len = u32::from_ne_bytes(bytes[off + 12..off + 16].try_into().unwrap()) as usize;
        if off + 16 + len > bytes.len() {
            break;
        }
        let nb = &bytes[off + 16..off + 16 + len];
        let end = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
        let name = String::from_utf8_lossy(&nb[..end]);
        off += 16 + len;
        if mask & libc::IN_Q_OVERFLOW != 0 {
            out.push(Ev::Overflow);
            continue;
        }
        if mask & libc::IN_IGNORED != 0 {
            out.push(Ev::Ignored(wd));
            continue;
        }
        let Some(dir) = wds.get(&wd) else { continue };
        let mut f = 0;
        if mask & libc::IN_CREATE != 0 {
            f |= F_CREATED;
        }
        if mask & libc::IN_DELETE != 0 {
            f |= F_REMOVED;
        }
        if mask & libc::IN_MODIFY != 0 {
            f |= F_MODIFIED;
        }
        if mask & libc::IN_MOVED_FROM != 0 {
            f |= F_REMOVED | F_RENAMED;
        }
        if mask & libc::IN_MOVED_TO != 0 {
            f |= F_RENAMED;
        }
        if mask & libc::IN_ISDIR != 0 {
            f |= F_DIR;
        }
        if f == 0 {
            continue;
        }
        let path = if name.is_empty() {
            dir.clone()
        } else {
            format!("{}/{name}", dir.trim_end_matches('/'))
        };
        out.push(Ev::Path { path, flags: f, pid: 0 });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn mountinfo_filter() {
        let t = "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
                 23 22 0:5 / /proc rw - proc proc rw\n\
                 24 22 0:6 / /tmp rw - tmpfs tmpfs rw\n\
                 25 22 8:3 / /home rw - xfs /dev/sda3 rw\n\
                 26 22 0:40 / /mnt/my\\040nfs rw - nfs4 srv:/x rw\n\
                 27 22 0:41 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw\n\
                 28 22 0:42 / /run/user/1000/doc rw - fuse.portal portal rw\n";
        assert_eq!(
            parse_mounts(t),
            vec![
                ("ext4".to_string(), "/".to_string()),
                ("xfs".to_string(), "/home".to_string())
            ]
        );
    }

    #[test]
    fn inotify_parse() {
        let mut b = vec![];
        let mut push = |wd: i32, mask: u32, name: &str| {
            let mut nb = name.as_bytes().to_vec();
            nb.push(0);
            while !nb.len().is_multiple_of(4) {
                nb.push(0);
            }
            b.extend_from_slice(&wd.to_ne_bytes());
            b.extend_from_slice(&mask.to_ne_bytes());
            b.extend_from_slice(&0u32.to_ne_bytes());
            b.extend_from_slice(&(nb.len() as u32).to_ne_bytes());
            b.extend_from_slice(&nb);
        };
        push(1, libc::IN_CREATE, "a.log");
        push(1, libc::IN_MODIFY, "a.log");
        push(2, libc::IN_IGNORED, "");
        push(9, libc::IN_MODIFY, "unknown");
        let wds: HashMap<i32, String> = [(1, "/var/log".to_string())].into();
        let v = parse_inotify(&b, &wds);
        assert_eq!(
            v,
            vec![
                Ev::Path {
                    path: "/var/log/a.log".into(),
                    flags: F_CREATED,
                    pid: 0
                },
                Ev::Path {
                    path: "/var/log/a.log".into(),
                    flags: F_MODIFIED,
                    pid: 0
                },
                Ev::Ignored(2),
            ]
        );
    }

    fn wait_for(w: &Watcher, path: &str, flag: u32) -> bool {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            if w.state
                .lock()
                .unwrap()
                .paths
                .get(path)
                .is_some_and(|e| e.flags & flag != 0)
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// Live: inotify (non-root) or fanotify (root) sees a write in a temp dir.
    #[test]
    fn live_watch_sees_write() {
        let base = std::env::var("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let d = base.join(format!("fat-gwatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let d = std::fs::canonicalize(&d).unwrap();
        let ds = d.to_string_lossy().into_owned();
        let w = Watcher::start(vec![], 10_000, vec![ds.clone()]);
        let mode = w.mode();
        {
            let s = w.state.lock().unwrap();
            eprintln!("mode={mode:?} errors={:?} marked={:?}", s.errors, s.marked);
        }
        if mode == Mode::Fanotify {
            // A filesystem the test dir lives on may be overlay/tmpfs (containers): not marked.
            let marked = w.state.lock().unwrap().marked.clone();
            use std::os::unix::fs::MetadataExt;
            let dev = |p: &str| std::fs::metadata(p).map(|m| m.dev()).ok();
            if !marked.iter().any(|m| dev(m) == dev(&ds)) {
                eprintln!("skip: {ds} not on a fanotify-marked filesystem ({marked:?})");
                return;
            }
        } else {
            assert_eq!(mode, Mode::Inotify);
        }
        std::thread::sleep(Duration::from_millis(100));
        // Write from a child process: fanotify drops fat's own events on purpose.
        let f = d.join("grow.bin");
        let fp = f.to_string_lossy().into_owned();
        let sh = |cmd: String| std::process::Command::new("sh").arg("-c").arg(cmd).status().unwrap();
        assert!(sh(format!("head -c 4096 /dev/zero > '{fp}'")).success());
        // Mount marks (btrfs subvolumes) only report modifications.
        let partial = w.state.lock().unwrap().partial;
        if !partial {
            assert!(
                wait_for(&w, &fp, F_CREATED),
                "create not seen in {mode:?}: {:?}",
                w.state.lock().unwrap().paths.keys().take(20).collect::<Vec<_>>()
            );
        }
        assert!(wait_for(&w, &fp, F_MODIFIED), "modify not seen in {mode:?}");
        assert!(sh(format!("rm '{fp}'")).success());
        if !partial {
            assert!(wait_for(&w, &fp, F_REMOVED), "delete not seen");
        }
        if mode == Mode::Fanotify {
            let pids = w.state.lock().unwrap().paths[&fp].pids.clone();
            assert!(
                !pids.is_empty() && !pids.contains(&std::process::id()),
                "writer pid recorded: {pids:?}"
            );
        }
        drop(w);
        let _ = std::fs::remove_dir_all(&d);
    }
}
