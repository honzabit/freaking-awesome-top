//! OS glue for the scanner: one-directory reads (openat/fstatat, never following symlinks),
//! the mount table, macOS privacy (TCC) rules, thread priority and thread CPU time.
#![allow(clippy::unnecessary_cast)] // stat field widths differ between macOS and Linux

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::sync::{Arc, Mutex};

/// Test hook: override the st_dev reported for a directory path (simulates a mount).
pub type DevHook = Arc<dyn Fn(&[u8]) -> Option<u64> + Send + Sync>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BigFile {
    pub name: Box<[u8]>,
    pub size: u64,
    pub apparent: u64,
    pub mtime: i64,
}

/// What to do with a subdirectory found while reading its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Normal,
    /// Another filesystem (or a macOS firmlink alias). `descend` = scan it as its own tree.
    Mount { descend: bool },
    /// macOS privacy-protected: not read in the background.
    Protected,
}

#[derive(Clone, Debug)]
pub struct Sub {
    pub name: Box<[u8]>,
    pub dev: u64,
    pub ino: u64,
    /// mtime / ctime in ns (change detection).
    pub mtime: i64,
    pub ctime: i64,
    pub size: u64,
    pub apparent: u64,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileAgg {
    pub size: u64,
    pub apparent: u64,
    pub files: u64,
    pub newest: i64,
}

#[derive(Debug, Default)]
pub struct DirRead {
    pub dev: u64,
    pub ino: u64,
    /// mtime / ctime in ns (change detection).
    pub mtime: i64,
    pub ctime: i64,
    pub self_size: u64,
    pub self_apparent: u64,
    pub files: FileAgg,
    pub big: Vec<BigFile>,
    pub subs: Vec<Sub>,
    pub errors: u32,
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(dir.len() + name.len() + 1);
    p.extend_from_slice(dir);
    if !dir.ends_with(b"/") {
        p.push(b'/');
    }
    p.extend_from_slice(name);
    p
}

/// `path` is `prefix` or below it.
pub fn under(path: &[u8], prefix: &[u8]) -> bool {
    if prefix == b"/" {
        return path.starts_with(b"/");
    }
    path.starts_with(prefix) && (path.len() == prefix.len() || path[prefix.len()] == b'/')
}

/// Read one directory: aggregate its files, list its subdirectories (classified by `policy`).
/// `keep_files`: how many of the largest files to keep by name (besides those >= `big_file`).
/// `links` dedupes hardlinked files (nlink > 1) across the whole pass.
pub fn read_dir(
    path: &[u8],
    big_file: u64,
    keep_files: usize,
    policy: &Policy,
    links: &Mutex<HashSet<(u64, u64)>>,
) -> Result<DirRead, i32> {
    let c = CString::new(path).map_err(|_| libc::EINVAL)?;
    // SAFETY: plain syscalls on a NUL-terminated path / fds we own; every exit closes them.
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(errno());
        }
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            let e = errno();
            libc::close(fd);
            return Err(e);
        }
        let dir = libc::fdopendir(fd);
        if dir.is_null() {
            let e = errno();
            libc::close(fd);
            return Err(e);
        }
        let mut out = DirRead {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            mtime: mns(&st),
            ctime: cns(&st),
            self_size: (st.st_blocks as u64).saturating_mul(512),
            self_apparent: st.st_size as u64,
            ..Default::default()
        };
        let mut kept: Vec<BigFile> = Vec::new();
        loop {
            let ent = libc::readdir(dir);
            if ent.is_null() {
                break;
            }
            let name_ptr = (*ent).d_name.as_ptr();
            let name = CStr::from_ptr(name_ptr).to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let mut s: libc::stat = std::mem::zeroed();
            if libc::fstatat(fd, name_ptr, &mut s, libc::AT_SYMLINK_NOFOLLOW) != 0 {
                if errno() != libc::ENOENT {
                    out.errors += 1;
                }
                continue;
            }
            let size = (s.st_blocks as u64).saturating_mul(512);
            let apparent = s.st_size.max(0) as u64;
            let mtime = s.st_mtime as i64;
            if (s.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                let child = join(path, name);
                let dev = s.st_dev as u64;
                let kind = policy.classify(&child, out.dev, dev);
                out.subs.push(Sub {
                    name: name.into(),
                    dev,
                    ino: s.st_ino as u64,
                    mtime: mns(&s),
                    ctime: cns(&s),
                    size,
                    apparent,
                    kind,
                });
                continue;
            }
            if s.st_nlink as u64 > 1 && (s.st_mode & libc::S_IFMT) == libc::S_IFREG {
                let key = (s.st_dev as u64, s.st_ino as u64);
                let fresh = links.lock().map(|mut l| l.insert(key)).unwrap_or(true);
                if !fresh {
                    continue;
                }
            }
            out.files.size += size;
            out.files.apparent += apparent;
            out.files.files += 1;
            out.files.newest = out.files.newest.max(mtime);
            if size >= big_file || (keep_files > 0 && size > 0) {
                kept.push(BigFile { name: name.into(), size, apparent, mtime });
                if kept.len() > 2 * keep_files.max(32) {
                    trim_files(&mut kept, big_file, keep_files);
                }
            }
        }
        libc::closedir(dir);
        trim_files(&mut kept, big_file, keep_files);
        out.big = kept;
        Ok(out)
    }
}

/// Keep files >= `big_file` (at most 64) plus the `keep` largest overall; largest first.
fn trim_files(v: &mut Vec<BigFile>, big_file: u64, keep: usize) {
    v.sort_unstable_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));
    let bigs = v.iter().take_while(|f| f.size >= big_file).count().min(64);
    v.truncate(bigs.max(keep));
}

fn mns(s: &libc::stat) -> i64 {
    (s.st_mtime as i64).saturating_mul(1_000_000_000) + s.st_mtime_nsec as i64
}
fn cns(s: &libc::stat) -> i64 {
    (s.st_ctime as i64).saturating_mul(1_000_000_000) + s.st_ctime_nsec as i64
}

/// Seconds from an ns timestamp.
pub fn secs(ns: i64) -> i64 {
    ns.div_euclid(1_000_000_000)
}

/// lstat a path: (dev, ino, mtime ns, ctime ns, is_dir).
pub fn lstat(path: &[u8]) -> Option<(u64, u64, i64, i64, bool)> {
    let c = CString::new(path).ok()?;
    // SAFETY: lstat into a zeroed stat buffer.
    unsafe {
        let mut s: libc::stat = std::mem::zeroed();
        if libc::lstat(c.as_ptr(), &mut s) != 0 {
            return None;
        }
        Some((
            s.st_dev as u64,
            s.st_ino as u64,
            mns(&s),
            cns(&s),
            (s.st_mode & libc::S_IFMT) == libc::S_IFDIR,
        ))
    }
}

/// Used bytes of the filesystem holding `path`.
pub fn fs_used(path: &[u8]) -> Option<u64> {
    let c = CString::new(path).ok()?;
    // SAFETY: statvfs into a zeroed buffer.
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut s) != 0 {
            return None;
        }
        Some((s.f_blocks as u64).saturating_sub(s.f_bfree as u64).saturating_mul(s.f_frsize as u64))
    }
}

// ------------------------------------------------------------------------------------------
// Mount table

#[derive(Clone, Debug, Default)]
pub struct MountInfo {
    pub fstype: String,
    pub source: String,
}

/// Filesystems never descended, even on explicit request (kernel pseudo fs, automounters).
const PSEUDO_FS: &[&str] = &[
    "proc", "sysfs", "devtmpfs", "devpts", "devfs", "cgroup", "cgroup2", "securityfs", "debugfs",
    "tracefs", "bpf", "fusectl", "configfs", "pstore", "efivarfs", "binfmt_misc", "autofs", "nsfs",
    "mqueue", "hugetlbfs", "rpc_pipefs", "selinuxfs", "nfsd",
];
const DISK_FS: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "bcachefs", "jfs", "reiserfs", "nilfs2"];

impl MountInfo {
    pub fn pseudo(&self) -> bool {
        PSEUDO_FS.contains(&self.fstype.as_str())
    }
}

#[cfg(target_os = "macos")]
pub fn mounts() -> HashMap<Vec<u8>, MountInfo> {
    let mut out = HashMap::new();
    // SAFETY: getmntinfo returns a buffer owned by libc, valid until the next call on this
    // thread; we copy everything out immediately.
    unsafe {
        let mut buf: *mut libc::statfs = std::ptr::null_mut();
        let n = libc::getmntinfo(&mut buf, libc::MNT_NOWAIT);
        for i in 0..n.max(0) as usize {
            let s = &*buf.add(i);
            let on = CStr::from_ptr(s.f_mntonname.as_ptr()).to_bytes().to_vec();
            let fstype = CStr::from_ptr(s.f_fstypename.as_ptr()).to_string_lossy().into_owned();
            let source = CStr::from_ptr(s.f_mntfromname.as_ptr()).to_string_lossy().into_owned();
            out.insert(on, MountInfo { fstype, source });
        }
    }
    out
}

#[cfg(not(target_os = "macos"))]
pub fn mounts() -> HashMap<Vec<u8>, MountInfo> {
    std::fs::read_to_string("/proc/self/mountinfo").map(|s| parse_mountinfo(&s)).unwrap_or_default()
}

/// Parse /proc/self/mountinfo. Later lines (over-mounts) win.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn parse_mountinfo(s: &str) -> HashMap<Vec<u8>, MountInfo> {
    let mut out = HashMap::new();
    for line in s.lines() {
        let (pre, post) = match line.split_once(" - ") {
            Some(x) => x,
            None => continue,
        };
        let pre: Vec<&str> = pre.split(' ').collect();
        let post: Vec<&str> = post.split(' ').collect();
        if pre.len() < 6 || post.len() < 2 {
            continue;
        }
        let on = unescape_octal(pre[4]);
        out.insert(on, MountInfo { fstype: post[0].to_string(), source: post[1].to_string() });
    }
    out
}

fn unescape_octal(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn is_btrfs(path: &[u8]) -> bool {
    let Ok(c) = CString::new(path) else { return false };
    // SAFETY: statfs into a zeroed buffer.
    unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        libc::statfs(c.as_ptr(), &mut s) == 0 && s.f_type as i64 == libc::BTRFS_SUPER_MAGIC as i64
    }
}
#[cfg(not(target_os = "linux"))]
fn is_btrfs(_path: &[u8]) -> bool {
    false
}

/// macOS: the Data volume paths that "/" already reaches through firmlinks
/// (/usr/share/firmlinks), so a walk of /System/Volumes/Data does not count them twice.
pub fn firmlink_aliases() -> HashSet<Vec<u8>> {
    let mut out = HashSet::new();
    if !cfg!(target_os = "macos") {
        return out;
    }
    if let Ok(s) = std::fs::read_to_string("/usr/share/firmlinks") {
        for line in s.lines() {
            if let Some((_, rel)) = line.split_once('\t') {
                let rel = rel.trim().trim_start_matches('/');
                if !rel.is_empty() {
                    out.insert(join(b"/System/Volumes/Data", rel.as_bytes()));
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------------------------------
// Policy: what a background walk may enter.

pub const PROTECTED_HINT: &str =
    "protected by macOS privacy (TCC): open it to scan (macOS may ask for permission), or grant Full Disk Access";

/// Home-relative locations macOS guards with TCC. Reading them from a terminal without Full
/// Disk Access either pops a permission dialog or fails with EPERM.
const TCC_HOME: &[&str] = &[
    "Desktop",
    "Documents",
    "Downloads",
    ".Trash",
    "Library/Mail",
    "Library/Messages",
    "Library/Safari",
    "Library/Cookies",
    "Library/Calendars",
    "Library/Reminders",
    "Library/HomeKit",
    "Library/IdentityServices",
    "Library/Suggestions",
    "Library/PersonalizationPortrait",
    "Library/Biome",
    "Library/Accounts",
    "Library/Sharing",
    "Library/Metadata/CoreSpotlight",
    "Library/Metadata/com.apple.IntelligentSuggestions",
    "Library/Mobile Documents",
    "Library/CloudStorage",
    "Library/Application Support/AddressBook",
    "Library/Application Support/CallHistoryDB",
    "Library/Application Support/CallHistoryTransactions",
    "Library/Application Support/com.apple.TCC",
    "Library/Application Support/FaceTime",
    "Library/Application Support/Knowledge",
    "Library/Application Support/MobileSync",
    "Library/Application Support/com.apple.sharedfilelist",
];

#[derive(Clone, Default)]
pub struct Policy {
    pub mounts: HashMap<Vec<u8>, MountInfo>,
    /// Full Disk Access granted: nothing is TCC-protected.
    pub fda: bool,
    /// Apply macOS TCC rules (on by default on macOS).
    pub protect: bool,
    pub home: Vec<u8>,
    /// Extra protected paths (tests).
    pub extra_protected: Vec<Vec<u8>>,
    /// Explicitly requested subtrees: protected and non-pseudo mounts may be read there.
    pub allowed: Vec<Vec<u8>>,
    pub firmlink_skip: HashSet<Vec<u8>>,
    pub dev_hook: Option<DevHook>,
}

impl Policy {
    /// The user explicitly asked for `path` or something inside it (so reading `path` is their
    /// intent). Being *below* a requested path is not enough: scanning ~ explicitly must still
    /// not open ~/Desktop or a network mount inside it.
    pub fn allowed(&self, path: &[u8]) -> bool {
        self.allowed.iter().any(|a| under(a, path))
    }

    /// Why `path` is skipped by background scans (None = not protected).
    pub fn protected(&self, path: &[u8]) -> Option<&'static str> {
        if self.extra_protected.iter().any(|p| p.as_slice() == path) {
            return Some(PROTECTED_HINT);
        }
        if !self.protect || self.fda || self.home.is_empty() {
            return None;
        }
        let mut pre = self.home.clone();
        pre.push(b'/');
        let rel = path.strip_prefix(pre.as_slice())?;
        if TCC_HOME.iter().any(|p| p.as_bytes() == rel) {
            return Some(PROTECTED_HINT);
        }
        for parent in [&b"Library/Containers/"[..], b"Library/Group Containers/"] {
            if let Some(rest) = rel.strip_prefix(parent)
                && !rest.is_empty()
                && !rest.contains(&b'/')
            {
                return Some(PROTECTED_HINT);
            }
        }
        if rel.ends_with(b".photoslibrary") {
            return Some(PROTECTED_HINT);
        }
        None
    }

    fn auto_descend(&self, path: &[u8], m: &MountInfo) -> bool {
        if cfg!(target_os = "macos") {
            return path == b"/System/Volumes/VM" || path == b"/System/Volumes/Data";
        }
        DISK_FS.contains(&m.fstype.as_str())
            && m.source.starts_with("/dev/")
            && !under(path, b"/media")
            && !under(path, b"/run/media")
    }

    /// Classify a subdirectory found while reading its parent.
    pub fn classify(&self, path: &[u8], parent_dev: u64, child_dev: u64) -> Kind {
        if self.firmlink_skip.contains(path) {
            return Kind::Mount { descend: false };
        }
        let child_dev = self.dev_hook.as_ref().and_then(|h| h(path)).unwrap_or(child_dev);
        if let Some(m) = self.mounts.get(path) {
            let descend = !m.pseudo() && (self.auto_descend(path, m) || self.allowed(path));
            return Kind::Mount { descend };
        }
        if child_dev != parent_dev && !is_btrfs(path) {
            return Kind::Mount { descend: self.allowed(path) };
        }
        if !self.allowed(path) && self.protected(path).is_some() {
            return Kind::Protected;
        }
        Kind::Normal
    }

    /// Classify a path used directly as a scan root (no parent read).
    pub fn root_kind(&self, path: &[u8]) -> Kind {
        if path == b"/" {
            return Kind::Normal;
        }
        if let Some(m) = self.mounts.get(path) {
            let descend = !m.pseudo() && (self.auto_descend(path, m) || self.allowed(path));
            return Kind::Mount { descend };
        }
        if !self.allowed(path) && self.protected(path).is_some() {
            return Kind::Protected;
        }
        Kind::Normal
    }
}

/// macOS: does this process (its responsible terminal) have Full Disk Access? Probes a file
/// only FDA can open; never triggers a permission prompt. Always true elsewhere.
pub fn full_disk_access(home: &[u8]) -> bool {
    if !cfg!(target_os = "macos") {
        return true;
    }
    let p = join(home, b"Library/Application Support/com.apple.TCC/TCC.db");
    let Ok(c) = CString::new(p) else { return false };
    // SAFETY: open/close of a path we only probe.
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd >= 0 {
            libc::close(fd);
            return true;
        }
    }
    false
}

// ------------------------------------------------------------------------------------------
// Thread priority / CPU time

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_set_qos_class_self_np(qos: u32, relative_priority: libc::c_int) -> libc::c_int;
}

/// Lower (`true`) or restore (`false`) the calling thread's CPU and I/O priority.
/// macOS: QoS background (also throttles disk I/O) vs utility. Linux: ioprio idle vs
/// best-effort/7, and nice 19 on the first lowering (nice cannot be raised back unprivileged).
pub fn set_background(on: bool) {
    #[cfg(target_os = "macos")]
    // SAFETY: changes only the calling thread's QoS class.
    unsafe {
        const QOS_CLASS_BACKGROUND: u32 = 0x09;
        const QOS_CLASS_UTILITY: u32 = 0x11;
        pthread_set_qos_class_self_np(if on { QOS_CLASS_BACKGROUND } else { QOS_CLASS_UTILITY }, 0);
    }
    #[cfg(target_os = "linux")]
    // SAFETY: setpriority/ioprio_set on our own thread id.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::c_int;
        if on {
            libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, 19);
        }
        const IOPRIO_WHO_PROCESS: libc::c_int = 1;
        let prio: libc::c_int = if on { 3 << 13 } else { (2 << 13) | 7 };
        libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, tid, prio);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = on;
}

/// CPU time consumed by the calling thread, ns.
pub fn thread_cpu_ns() -> u64 {
    // SAFETY: clock_gettime into a zeroed timespec.
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) != 0 {
            return 0;
        }
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_parse() {
        let s = "22 1 0:21 / / rw,relatime - overlay overlay rw\n\
                 23 22 0:5 / /proc rw - proc proc rw\n\
                 24 22 8:1 / /mnt/my\\040disk ro,relatime - ext4 /dev/sdb1 ro\n\
                 25 22 0:50 / /home/u/remote rw - fuse.sshfs u@h:/ rw\n";
        let m = parse_mountinfo(s);
        assert!(m[&b"/proc"[..].to_vec()].pseudo());
        let d = &m[&b"/mnt/my disk"[..].to_vec()];
        assert!(d.fstype == "ext4" && d.source == "/dev/sdb1");
        assert_eq!(m[&b"/home/u/remote"[..].to_vec()].fstype, "fuse.sshfs");
    }

    #[test]
    fn under_and_join() {
        assert!(under(b"/a/b", b"/a") && under(b"/a", b"/a") && !under(b"/ab", b"/a"));
        assert!(under(b"/x", b"/"));
        assert_eq!(join(b"/", b"x"), b"/x");
        assert_eq!(join(b"/a", b"x"), b"/a/x");
    }

    #[test]
    fn tcc_rules() {
        let p = Policy { protect: true, home: b"/Users/me".to_vec(), ..Default::default() };
        for path in [
            &b"/Users/me/Desktop"[..],
            b"/Users/me/Library/Mail",
            b"/Users/me/Library/Containers/com.foo.bar",
            b"/Users/me/Library/Group Containers/X.dev.orbstack",
            b"/Users/me/Pictures/Photos Library.photoslibrary",
        ] {
            assert!(p.protected(path).is_some(), "{}", String::from_utf8_lossy(path));
        }
        for path in [&b"/Users/me/Library/Containers"[..], b"/Users/me/Library/Caches", b"/Users/me/fat"] {
            assert!(p.protected(path).is_none(), "{}", String::from_utf8_lossy(path));
        }
        let mut allowed = p.clone();
        allowed.allowed.push(b"/Users/me/Desktop".to_vec());
        assert_eq!(allowed.classify(b"/Users/me/Desktop", 1, 1), Kind::Normal);
        assert_eq!(p.classify(b"/Users/me/Desktop", 1, 1), Kind::Protected);
        let fda = Policy { fda: true, ..p.clone() };
        assert!(fda.protected(b"/Users/me/Desktop").is_none());
    }
}
