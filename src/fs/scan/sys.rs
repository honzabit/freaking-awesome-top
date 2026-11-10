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
    Mount {
        descend: bool,
    },
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
/// `links` dedupes hardlinked files (nlink > 1): (dev, ino) -> the directory that counts it
/// ([`owner_key`] of its path). Re-reading that same directory counts the file again; any
/// other directory holding a link to it skips it.
pub fn read_dir(
    path: &[u8],
    big_file: u64,
    keep_files: usize,
    policy: &Policy,
    links: &Mutex<HashMap<(u64, u64), u64>>,
) -> Result<DirRead, i32> {
    let owner = owner_key(path);
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
        let mut here: HashSet<(u64, u64)> = HashSet::new();
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
                let mine = links.lock().map(|mut l| *l.entry(key).or_insert(owner) == owner).unwrap_or(true);
                // Two links in this same directory: once.
                if !mine || !here.insert(key) {
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

/// Stable 64-bit key (FNV-1a) of a directory path: the owner of a hardlink in `links`.
pub fn owner_key(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// lstat a file: (allocated bytes, mtime seconds). None when missing.
pub fn lstat_file(path: &[u8]) -> Option<(u64, i64)> {
    let c = CString::new(path).ok()?;
    // SAFETY: lstat into a zeroed stat buffer.
    unsafe {
        let mut s: libc::stat = std::mem::zeroed();
        if libc::lstat(c.as_ptr(), &mut s) != 0 {
            return None;
        }
        Some(((s.st_blocks as u64).saturating_mul(512), s.st_mtime as i64))
    }
}

/// A directory below `path` (at most `depth` levels down, at most `max_dirs` looked at) has an
/// mtime or ctime after `after_ns`. Only directory entries are stat'ed (d_type); symlinks and
/// other filesystems are not followed, and `skip(path, level)` dirs (kept nodes, protected
/// dirs) are neither stat'ed nor entered.
pub fn subdir_changed_after(
    path: &[u8],
    after_ns: i64,
    depth: usize,
    max_dirs: usize,
    skip: &dyn Fn(&[u8], usize) -> bool,
) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Some((dev, ..)) = lstat(path) else { return false };
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(std::ffi::OsStr::from_bytes(path).into(), 0)];
    let mut seen = 0usize;
    while let Some((dir, d)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            if !e.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let p = e.path();
            let pb = p.as_os_str().as_bytes();
            if skip(pb, d) {
                continue;
            }
            seen += 1;
            match lstat(pb) {
                Some((dv, _, m, c, true)) if dv == dev => {
                    if m > after_ns || c > after_ns {
                        return true;
                    }
                }
                _ => continue,
            }
            if seen >= max_dirs {
                return false;
            }
            if d + 1 < depth {
                stack.push((p, d + 1));
            }
        }
    }
    false
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
        Some((s.st_dev as u64, s.st_ino as u64, mns(&s), cns(&s), (s.st_mode & libc::S_IFMT) == libc::S_IFDIR))
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
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "devfs",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "tracefs",
    "bpf",
    "fusectl",
    "configfs",
    "pstore",
    "efivarfs",
    "binfmt_misc",
    "autofs",
    "nsfs",
    "mqueue",
    "hugetlbfs",
    "rpc_pipefs",
    "selinuxfs",
    "nfsd",
];
const DISK_FS: &[&str] =
    &["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "bcachefs", "jfs", "reiserfs", "nilfs2"];

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

// The TCC-protected locations themselves live in `crate::fs::tcc` (shared with the growth
// tracker).

#[derive(Clone, Default)]
pub struct Policy {
    pub mounts: HashMap<Vec<u8>, MountInfo>,
    /// Full Disk Access granted: nothing is TCC-protected.
    pub fda: bool,
    /// Apply macOS TCC rules (on by default on macOS).
    pub protect: bool,
    pub home: Vec<u8>,
    /// Other users' home directories (macOS /Users/*): the same TCC rules apply there, e.g.
    /// when fat runs as root.
    pub other_homes: Vec<Vec<u8>>,
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
        if !self.protect || self.fda {
            return None;
        }
        if crate::fs::tcc::is_protected_abs(path) {
            return Some(PROTECTED_HINT);
        }
        std::iter::once(&self.home).chain(self.other_homes.iter()).filter(|h| !h.is_empty()).find_map(|h| {
            let mut pre = h.clone();
            pre.push(b'/');
            Self::protected_rel(path.strip_prefix(pre.as_slice())?)
        })
    }

    fn protected_rel(rel: &[u8]) -> Option<&'static str> {
        crate::fs::tcc::is_protected_rel(rel).then_some(PROTECTED_HINT)
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

    /// `path` itself may not be entered by a background walk: protected, or a mount point
    /// that is not scanned on its own (network, removable, pseudo), unless explicitly asked for.
    pub fn blocks(&self, path: &[u8]) -> bool {
        if path == b"/" {
            return false;
        }
        if self.firmlink_skip.contains(path) {
            return true;
        }
        if let Some(m) = self.mounts.get(path)
            && (m.pseudo() || !(self.auto_descend(path, m) || self.allowed(path)))
        {
            return true;
        }
        !self.allowed(path) && self.protected(path).is_some()
    }

    /// The first proper ancestor of `path` (below "/") that [`Self::blocks`], if any.
    fn blocking_ancestor<'a>(&self, path: &'a [u8]) -> Option<&'a [u8]> {
        let mut i = 1;
        while let Some(off) = path[i..].iter().position(|&b| b == b'/') {
            let q = &path[..i + off];
            if self.blocks(q) {
                return Some(q);
            }
            i += off + 1;
        }
        None
    }

    /// A background job (restat, a remembered root) may read `path`: neither it nor any
    /// ancestor is protected or an unscanned mount, unless this process was asked for it.
    pub fn background_ok(&self, path: &[u8]) -> bool {
        !self.blocks(path) && self.blocking_ancestor(path).is_none()
    }

    /// Classify a path used directly as a scan root (no parent read). A path *below* a
    /// protected dir or an unscanned mount inherits its kind.
    pub fn root_kind(&self, path: &[u8]) -> Kind {
        if path == b"/" {
            return Kind::Normal;
        }
        if let Some(q) = self.blocking_ancestor(path) {
            let pseudo = self.mounts.get(q).is_some_and(|m| m.pseudo());
            return if self.mounts.contains_key(q) || self.firmlink_skip.contains(q) || pseudo {
                Kind::Mount { descend: false }
            } else {
                Kind::Protected
            };
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

/// macOS: home directories of other local users (/Users/*, /var/root), for the TCC rules.
pub fn user_homes(home: &[u8]) -> Vec<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let mut out: Vec<Vec<u8>> = std::fs::read_dir("/Users")
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.path().as_os_str().as_bytes().to_vec())
                .filter(|p| !p.ends_with(b"/Shared"))
                .collect()
        })
        .unwrap_or_default();
    out.push(b"/var/root".to_vec());
    out.push(b"/private/var/root".to_vec());
    out.retain(|p| p.as_slice() != home);
    out.sort();
    out
}

/// Lower the calling thread for an on-demand (CLI / MCP) scan: utility QoS on macOS (below
/// interactive work, I/O moderately throttled), nice 10 + best-effort/7 I/O on Linux.
pub fn set_utility() {
    set_background(false);
    #[cfg(target_os = "linux")]
    // SAFETY: setpriority on our own thread id.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::c_int;
        libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, 10);
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
