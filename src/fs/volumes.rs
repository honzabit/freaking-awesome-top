//! Mounts, capacity, per-device I/O, deleted-but-open files. OWNER: fs-volumes agent.
//!
//! * Mounts: `getmntinfo` + `statfs` (macOS), `/proc/self/mountinfo` + `statvfs` (Linux).
//!   Pseudo filesystems are dropped; noise (APFS system siblings, bind mounts of the same
//!   device, container runtime internals, snaps) is `hidden` and only returned by
//!   [`Volumes::with_all`]`(true)`. Remote mounts are never `statfs`'d with MNT_WAIT on
//!   macOS, and on Linux in a helper thread with a timeout, so a dead NFS server cannot hang us.
//! * APFS volumes of one container share free space: `total`/`avail` are container-wide and
//!   `used` is per volume. Use [`totals`] to sum without double counting.
//! * I/O: Linux `/proc/diskstats` (by mount major:minor, else source device, else its parent
//!   disk). macOS: IOKit `IOBlockStorageDriver` "Statistics" via `ioreg`, polled every 5 s in a
//!   background thread, mapped from the physical disk to every BSD node below it, so every
//!   volume of one physical disk reports the same (disk-level) rate; see `note`.
//! * `fill_bps`: least-squares slope of `used` over the last [`FILL_WINDOW_MS`].
//! * Purgeable (macOS): CoreFoundation `kCFURLVolumeAvailableCapacityForImportantUsageKey`
//!   minus `avail`, once per container per 60 s.
//!
//! Everything here is read-only.
use super::Volume;
use crate::model::{Ts, now_ms};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Window used for the fill-rate regression.
pub const FILL_WINDOW_MS: i64 = 10 * 60_000;
/// Minimum time span of samples before a fill rate is reported.
const FILL_MIN_SPAN_MS: i64 = 1_000;
/// Purgeable is comparatively slow to compute (CoreFoundation asks the APFS driver).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const PURGEABLE_EVERY: Duration = Duration::from_secs(60);
/// (pid, process name, path, bytes).
type DeletedFile = (u32, String, String, u64);
/// `deleted_open()` result cache: lsof costs ~0.25 s CPU on macOS.
const DELETED_TTL: Duration = Duration::from_secs(15);

/// Stateful so it can compute I/O and fill rates between calls.
pub struct Volumes {
    show_all: bool,
    /// mount -> (ts, used) samples within the fill window.
    fill: HashMap<String, VecDeque<(Ts, u64)>>,
    /// Last good reading per mount (used when a remote statvfs times out).
    last: HashMap<String, Volume>,
    #[cfg(target_os = "linux")]
    disk_prev: Option<(Ts, HashMap<String, DiskStat>)>,
    /// mount -> major:minor from the last mountinfo read.
    #[cfg(target_os = "linux")]
    majmin: HashMap<String, (u32, u32)>,
    #[cfg(target_os = "linux")]
    stuck: HashMap<String, std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Last statvfs of each remote mount (they are refreshed at most every REMOTE_EVERY).
    #[cfg(target_os = "linux")]
    remote_at: HashMap<String, (Instant, lx::Stat)>,
    #[cfg(target_os = "macos")]
    io: mac::IoPoller,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    purge: HashMap<String, (Instant, Option<u64>)>,
}

impl Default for Volumes {
    fn default() -> Self {
        Self::new()
    }
}

impl Volumes {
    pub fn new() -> Self {
        Self::with_all(false)
    }

    /// `all` = also return hidden volumes (APFS system siblings, duplicate bind mounts, ...).
    pub fn with_all(all: bool) -> Self {
        Volumes {
            show_all: all,
            fill: HashMap::new(),
            last: HashMap::new(),
            #[cfg(target_os = "linux")]
            disk_prev: None,
            #[cfg(target_os = "linux")]
            majmin: HashMap::new(),
            #[cfg(target_os = "linux")]
            stuck: HashMap::new(),
            #[cfg(target_os = "linux")]
            remote_at: HashMap::new(),
            #[cfg(target_os = "macos")]
            io: mac::IoPoller::start(),
            purge: HashMap::new(),
        }
    }

    /// Seed the fill-rate window from recorded history (ts, used), e.g. `History::volume_series`.
    pub fn seed(&mut self, mount: &str, pts: &[(Ts, u64)]) {
        let q = self.fill.entry(mount.to_string()).or_default();
        let mut all: Vec<(Ts, u64)> = q.iter().copied().chain(pts.iter().copied()).collect();
        all.sort_by_key(|p| p.0);
        all.dedup_by_key(|p| p.0);
        *q = all.into();
    }

    /// Current mounted volumes (pseudo filesystems like proc/sysfs/devfs/autofs excluded).
    /// fill_bps/eta use the samples seen by this instance (and recorder history if attached).
    pub fn sample(&mut self) -> Vec<Volume> {
        let now = now_ms();
        let mut vols = self.read_mounts();
        if !self.show_all {
            vols.retain(|v| !v.hidden);
        }
        self.fill_io(&mut vols, now);
        #[cfg(target_os = "macos")]
        self.fill_purgeable(&mut vols);
        for v in vols.iter_mut() {
            self.update_fill(v, now);
        }
        let seen: HashSet<&str> = vols.iter().map(|v| v.mount.as_str()).collect();
        self.fill.retain(|m, _| seen.contains(m.as_str()));
        self.last = vols.iter().map(|v| (v.mount.clone(), v.clone())).collect();
        vols
    }

    fn update_fill(&mut self, v: &mut Volume, now: Ts) {
        let q = self.fill.entry(v.mount.clone()).or_default();
        q.push_back((now, v.used));
        while q.front().is_some_and(|p| p.0 < now - FILL_WINDOW_MS) {
            q.pop_front();
        }
        let pts: Vec<(Ts, u64)> = q.iter().copied().collect();
        v.fill_bps = fill_rate(&pts);
        v.eta_full_s = eta_full(v.avail, v.fill_bps);
    }

    // ---- mounts -------------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn read_mounts(&mut self) -> Vec<Volume> {
        let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let raws = parse_mountinfo(&text);
        self.majmin = raws.iter().map(|r| (r.mount.clone(), r.majmin)).collect();
        let mut out = Vec::new();
        for (raw, vis) in classify_linux(&raws) {
            if vis.hidden && !self.show_all {
                continue;
            }
            let st = if vis.remote { self.statvfs_guarded(&raw.mount) } else { lx::statvfs(&raw.mount) };
            let mut v = Volume {
                mount: raw.mount.clone(),
                device: raw.source.clone(),
                fstype: raw.fstype.clone(),
                read_only: raw.read_only,
                remote: vis.remote,
                primary: vis.primary,
                hidden: vis.hidden,
                ..Default::default()
            };
            match st {
                Some(s) => s.apply(&mut v),
                None => match self.last.get(&raw.mount) {
                    Some(prev) => {
                        v.total = prev.total;
                        v.used = prev.used;
                        v.avail = prev.avail;
                        v.inodes_total = prev.inodes_total;
                        v.inodes_used = prev.inodes_used;
                        v.note = "statfs timed out; showing last reading".into();
                    }
                    None if vis.remote => v.note = "statfs timed out (unresponsive server?)".into(),
                    None => continue,
                },
            }
            if v.total == 0 && !self.show_all && !vis.remote {
                continue;
            }
            out.push(v);
        }
        out
    }

    /// statvfs on a network mount in a helper thread: a dead server must not hang the sampler.
    #[cfg(target_os = "linux")]
    fn statvfs_guarded(&mut self, mount: &str) -> Option<lx::Stat> {
        const REMOTE_EVERY: Duration = Duration::from_secs(10);
        if let Some((t, s)) = self.remote_at.get(mount)
            && t.elapsed() < REMOTE_EVERY
        {
            return Some(*s);
        }
        let r = self.statvfs_thread(mount);
        if let Some(s) = r {
            self.remote_at.insert(mount.to_string(), (Instant::now(), s));
        }
        r
    }

    #[cfg(target_os = "linux")]
    fn statvfs_thread(&mut self, mount: &str) -> Option<lx::Stat> {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        if self.stuck.get(mount).is_some_and(|b| b.load(Ordering::SeqCst)) {
            return None; // previous call still blocked in the kernel
        }
        let busy = Arc::new(AtomicBool::new(true));
        self.stuck.insert(mount.to_string(), busy.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        let m = mount.to_string();
        let spawned = std::thread::Builder::new().name("fat-statvfs".into()).spawn(move || {
            let r = lx::statvfs(&m);
            busy.store(false, Ordering::SeqCst);
            let _ = tx.send(r);
        });
        if spawned.is_err() {
            self.stuck.remove(mount);
            return None;
        }
        rx.recv_timeout(Duration::from_millis(500)).ok().flatten()
    }

    #[cfg(target_os = "macos")]
    fn read_mounts(&mut self) -> Vec<Volume> {
        let raws = mac::mounts();
        let mut out = Vec::new();
        for (raw, vis) in classify_macos(&raws) {
            if vis.hidden && !self.show_all {
                continue;
            }
            let mut v = Volume {
                mount: raw.mount.clone(),
                device: raw.source.clone(),
                fstype: raw.fstype.clone(),
                read_only: raw.read_only,
                remote: vis.remote,
                primary: vis.primary,
                hidden: vis.hidden,
                ..Default::default()
            };
            // Fresh numbers for local mounts; remote ones keep getmntinfo(MNT_NOWAIT)'s cached
            // values (a blocking statfs on a dead NFS server would hang).
            let s = if raw.local { mac::statfs(&raw.mount).unwrap_or(raw.stat) } else { raw.stat };
            s.apply(&mut v);
            if v.mount.starts_with("/Volumes/") && raw.local {
                v.note = "removable or disk image: not scanned automatically".into();
            }
            out.push(v);
        }
        out
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn read_mounts(&mut self) -> Vec<Volume> {
        Vec::new()
    }

    // ---- I/O ----------------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn fill_io(&mut self, vols: &mut [Volume], now: Ts) {
        let text = std::fs::read_to_string("/proc/diskstats").unwrap_or_default();
        let cur = parse_diskstats_devs(&text);
        if let Some((pts, prev)) = &self.disk_prev {
            let dt = (now - pts).max(1) as f64 / 1000.0;
            for v in vols.iter_mut() {
                let mm = self.majmin.get(&v.mount).copied();
                let Some(name) = disk_for(&cur, mm, &v.device) else {
                    if v.fstype == "overlay" && v.note.is_empty() {
                        v.note = "overlay: backing device I/O not attributed".into();
                    }
                    continue;
                };
                if let (Some(c), Some(p)) = (cur.get(&name), prev.get(&name)) {
                    v.read_bps = (c.read.saturating_sub(p.read) as f64 / dt) as u64;
                    v.write_bps = (c.written.saturating_sub(p.written) as f64 / dt) as u64;
                }
            }
        }
        self.disk_prev = Some((now, cur));
    }

    #[cfg(target_os = "macos")]
    fn fill_io(&mut self, vols: &mut [Volume], _now: Ts) {
        let rates = self.io.get();
        for v in vols.iter_mut() {
            let bsd = v.device.trim_start_matches("/dev/");
            if let Some(r) = rates.get(bsd) {
                v.read_bps = r.0;
                v.write_bps = r.1;
                if v.note.is_empty() && v.fstype == "apfs" {
                    v.note = format!("I/O is for physical disk {} (shared by its volumes)", r.2);
                }
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn fill_io(&mut self, _vols: &mut [Volume], _now: Ts) {}

    #[cfg(target_os = "macos")]
    fn fill_purgeable(&mut self, vols: &mut [Volume]) {
        // One computation per APFS container; reuse for its sibling volumes.
        let mut per_container: HashMap<String, Option<u64>> = HashMap::new();
        for v in vols.iter_mut() {
            if v.remote || v.fstype != "apfs" {
                continue;
            }
            let key = container_key(&v.device);
            let p = match per_container.get(&key) {
                Some(p) => *p,
                None => {
                    let p = match self.purge.get(&key) {
                        Some((t, p)) if t.elapsed() < PURGEABLE_EVERY => *p,
                        _ => {
                            let p = mac::important_avail(&v.mount).map(|imp| imp.saturating_sub(v.avail));
                            self.purge.insert(key.clone(), (Instant::now(), p));
                            p
                        }
                    };
                    per_container.insert(key, p);
                    p
                }
            };
            v.purgeable = p;
        }
    }
}

// ---- pure helpers (all platforms, unit-tested) ------------------------------------------------

/// Least-squares slope of used bytes over time, bytes/sec. None with < 2 points or a span
/// shorter than a second.
pub fn fill_rate(pts: &[(Ts, u64)]) -> Option<f64> {
    if pts.len() < 2 {
        return None;
    }
    let t0 = pts[0].0;
    let span = pts.iter().map(|p| p.0).max()? - pts.iter().map(|p| p.0).min()?;
    if span < FILL_MIN_SPAN_MS {
        return None;
    }
    let n = pts.len() as f64;
    let xs: Vec<f64> = pts.iter().map(|p| (p.0 - t0) as f64 / 1000.0).collect();
    let ys: Vec<f64> = pts.iter().map(|p| p.1 as f64).collect();
    let mx = xs.iter().sum::<f64>() / n;
    let my = ys.iter().sum::<f64>() / n;
    let (mut sxy, mut sxx) = (0.0, 0.0);
    for (x, y) in xs.iter().zip(&ys) {
        sxy += (x - mx) * (y - my);
        sxx += (x - mx) * (x - mx);
    }
    (sxx > 0.0).then(|| sxy / sxx).filter(|s| s.is_finite())
}

/// Seconds until `avail` reaches 0 at `fill_bps`, when filling.
pub fn eta_full(avail: u64, fill_bps: Option<f64>) -> Option<u64> {
    let f = fill_bps?;
    (f > 0.0 && avail > 0).then(|| (avail as f64 / f).min(u64::MAX as f64 / 2.0) as u64)
}

/// APFS container ("disk3" for "/dev/disk3s5", "/dev/disk3s1s1"), else the device itself.
/// Volumes with the same key share `total`/`avail`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn container_key(device: &str) -> String {
    let d = device.trim_start_matches("/dev/");
    if let Some(rest) = d.strip_prefix("disk") {
        let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !n.is_empty() {
            return format!("disk{n}");
        }
    }
    d.to_string()
}

/// (used, avail, total) over local volumes, counting shared space once: APFS siblings share
/// a container, and on Linux an overlay root / btrfs subvolumes report their backing pool.
/// Volumes count as the same pool when their container key matches, or their totals are
/// identical and free space differs by < 64 MiB. Pool-backed `used` (overlay) is counted once.
#[allow(dead_code)] // API for the TUI/CLI header
pub fn totals(vols: &[Volume]) -> (u64, u64, u64) {
    let mut pools: Vec<(String, u64, u64, bool)> = Vec::new(); // key, total, avail, apfs
    let (mut used, mut avail, mut total) = (0u64, 0u64, 0u64);
    for v in vols.iter().filter(|v| !v.remote && !v.hidden && v.fstype != "tmpfs") {
        let key = container_key(&v.device);
        let apfs = v.fstype == "apfs";
        let same = pools.iter().find(|(k, t, a, _)| *k == key || (*t == v.total && a.abs_diff(v.avail) < 64 << 20));
        match same {
            // APFS siblings have their own used; Linux views of one pool report the pool's.
            Some(&(_, _, _, papfs)) => {
                if apfs && papfs {
                    used += v.used;
                }
            }
            None => {
                used += v.used;
                avail += v.avail;
                total += v.total;
                pools.push((key, v.total, v.avail, apfs));
            }
        }
    }
    (used, avail.min(total), total)
}

/// Kernel/virtual filesystems that hold no user data.
pub fn is_pseudo(fstype: &str) -> bool {
    matches!(
        fstype,
        "proc" | "sysfs" | "devfs" | "devtmpfs" | "devpts" | "cgroup" | "cgroup2" | "autofs"
            | "securityfs" | "debugfs" | "tracefs" | "bpf" | "fusectl" | "mqueue" | "hugetlbfs"
            | "configfs" | "pstore" | "binfmt_misc" | "nsfs" | "efivarfs" | "rpc_pipefs"
            | "selinuxfs" | "nfsd" | "ramfs" | "rootfs" | "kernfs" | "fdesc" | "fuse.lxcfs"
            | "fuse.portal" | "fuse.gvfsd-fuse" | "nullfs" | "fusefs.portal"
    )
}

/// Network / FUSE filesystems: never scanned automatically, never statfs'd blocking.
pub fn is_remote_fstype(fstype: &str) -> bool {
    matches!(
        fstype,
        "nfs" | "nfs4" | "cifs" | "smb3" | "smbfs" | "afpfs" | "webdav" | "davfs" | "9p" | "virtiofs"
            | "ceph" | "glusterfs" | "lustre" | "fuse" | "fuseblk" | "osxfuse" | "macfuse" | "sshfs"
            | "ftp" | "afs" | "gpfs" | "beegfs"
    ) || fstype.starts_with("fuse.")
        || fstype.starts_with("fusefs")
        || fstype.starts_with("macfuse")
        || fstype.starts_with("osxfuse")
}

/// One raw mount before classification.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RawMount {
    pub mount: String,
    pub source: String,
    pub fstype: String,
    /// Linux: path inside the source fs that is mounted here ("/" unless a bind mount).
    pub root: String,
    pub majmin: (u32, u32),
    pub read_only: bool,
    /// macOS: MNT_LOCAL.
    pub local: bool,
    pub stat: Stat,
}

/// Capacity numbers in bytes / inodes.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Stat {
    pub total: u64,
    pub free: u64,
    pub avail: u64,
    pub files: u64,
    pub ffree: u64,
}

impl Stat {
    fn apply(&self, v: &mut Volume) {
        v.total = self.total;
        v.used = self.total.saturating_sub(self.free);
        v.avail = self.avail;
        v.inodes_total = self.files;
        v.inodes_used = self.files.saturating_sub(self.ffree);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Visibility {
    pub hidden: bool,
    pub remote: bool,
    pub primary: bool,
}

/// Decode mountinfo's octal escapes (`\040` = space, `\011` tab, `\012` newline, `\134` backslash).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `/proc/self/mountinfo`:
/// `36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_mountinfo(text: &str) -> Vec<RawMount> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((pre, post)) = line.split_once(" - ") else { continue };
        let f: Vec<&str> = pre.split(' ').collect();
        let g: Vec<&str> = post.split(' ').collect();
        if f.len() < 6 || g.len() < 2 {
            continue;
        }
        let majmin = f[2]
            .split_once(':')
            .and_then(|(a, b)| Some((a.parse().ok()?, b.parse().ok()?)))
            .unwrap_or((0, 0));
        let opts = f[5];
        let super_opts = g.get(2).copied().unwrap_or("");
        let ro = opts.split(',').any(|o| o == "ro") || super_opts.split(',').any(|o| o == "ro");
        out.push(RawMount {
            mount: unescape_mount(f[4]),
            root: unescape_mount(f[3]),
            majmin,
            fstype: g[0].to_string(),
            source: unescape_mount(g[1]),
            read_only: ro,
            local: !is_remote_fstype(g[0]),
            stat: Stat::default(),
        });
    }
    out
}

fn under(path: &str, dir: &str) -> bool {
    path == dir || path.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
}

/// Linux: drop pseudo fs, hide duplicates/noise, flag remote and primary.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn classify_linux(raws: &[RawMount]) -> Vec<(RawMount, Visibility)> {
    const NOISE: [&str; 9] = [
        "/proc", "/sys", "/dev", "/var/lib/docker", "/run/docker", "/var/lib/containers",
        "/run/containerd", "/var/lib/kubelet", "/snap",
    ];
    let kept: Vec<&RawMount> = raws.iter().filter(|r| !is_pseudo(&r.fstype)).collect();
    // Later mounts on the same mount point shadow earlier ones.
    let mut last_at: HashMap<&str, usize> = HashMap::new();
    for (i, r) in kept.iter().enumerate() {
        last_at.insert(r.mount.as_str(), i);
    }
    // Per device the representative visible mount: root "/" first, then shortest path.
    let mut best: HashMap<(u32, u32, &str), usize> = HashMap::new();
    fn devkey(r: &RawMount) -> (u32, u32, &str) {
        if r.majmin == (0, 0) { (0, 0, r.source.as_str()) } else { (r.majmin.0, r.majmin.1, "") }
    }
    let noisy = |r: &RawMount| NOISE.iter().any(|n| under(&r.mount, n)) || r.fstype == "squashfs";
    for (i, r) in kept.iter().enumerate() {
        if last_at.get(r.mount.as_str()) != Some(&i) || noisy(r) {
            continue;
        }
        let k = devkey(r);
        let better = |j: usize| {
            let o = kept[j];
            let rank = |m: &RawMount| (m.mount != "/", m.root != "/", m.mount.len());
            rank(r) < rank(o)
        };
        match best.get(&k) {
            Some(&j) if !better(j) => {}
            _ => {
                best.insert(k, i);
            }
        }
    }
    let reps: HashSet<usize> = best.values().copied().collect();
    let removable = |m: &str| under(m, "/media") || under(m, "/run/media");
    kept.iter()
        .enumerate()
        .map(|(i, r)| {
            let vis = Visibility {
                hidden: !reps.contains(&i),
                remote: is_remote_fstype(&r.fstype) || removable(&r.mount),
                primary: r.mount == "/" && last_at.get("/") == Some(&i),
            };
            ((*r).clone(), vis)
        })
        .collect()
}

/// macOS: drop pseudo fs, hide APFS system siblings, mark Data primary (else "/").
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn classify_macos(raws: &[RawMount]) -> Vec<(RawMount, Visibility)> {
    let has_data = raws.iter().any(|r| r.mount == "/System/Volumes/Data");
    raws.iter()
        .filter(|r| !is_pseudo(&r.fstype))
        .map(|r| {
            let m = r.mount.as_str();
            let system_sibling =
                under(m, "/System/Volumes") && m != "/System/Volumes/Data" && m != "/System/Volumes/VM";
            let vis = Visibility {
                hidden: system_sibling || m.starts_with("/System/Volumes/Data/"),
                remote: !r.local || is_remote_fstype(&r.fstype) || m.starts_with("/Volumes/"),
                primary: if has_data { m == "/System/Volumes/Data" } else { m == "/" },
            };
            (r.clone(), vis)
        })
        .collect()
}

/// macOS firmlinks: top-level paths on "/" that really live on the Data volume.
pub fn firmlinks() -> &'static [String] {
    static F: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    F.get_or_init(|| {
        let mut v: Vec<String> = std::fs::read_to_string("/usr/share/firmlinks")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split('\t').next())
            .filter(|p| p.starts_with('/'))
            .map(str::to_string)
            .collect();
        if v.is_empty() {
            v = DEFAULT_FIRMLINKS.iter().map(|s| s.to_string()).collect();
        }
        v
    })
}

const DEFAULT_FIRMLINKS: [&str; 10] = [
    "/Applications", "/Library", "/Users", "/Volumes", "/cores", "/opt", "/private", "/usr/local",
    "/System/Library/Caches", "/AppleInternal",
];

/// The volume containing `path` (longest mount prefix).
pub fn volume_for<'a>(vols: &'a [Volume], path: &str) -> Option<&'a Volume> {
    volume_for_with(vols, path, firmlinks())
}

/// [`volume_for`] with an explicit firmlink list. Firmlinks apply only when a
/// "/System/Volumes/Data" volume is present (i.e. on macOS).
pub fn volume_for_with<'a>(vols: &'a [Volume], path: &str, firmlinks: &[String]) -> Option<&'a Volume> {
    let path = if path.len() > 1 { path.trim_end_matches('/') } else { path };
    let best = vols
        .iter()
        .filter(|v| v.mount == "/" || under(path, &v.mount))
        .max_by_key(|v| if v.mount == "/" { 1 } else { v.mount.len() })?;
    if best.mount == "/"
        && let Some(data) = vols.iter().find(|v| v.mount == "/System/Volumes/Data")
    {
        // /etc, /tmp, /var are symlinks into /private (firmlinked).
        let on_data = ["/etc", "/tmp", "/var", "/home"].iter().any(|s| under(path, s))
            || firmlinks.iter().any(|f| under(path, f));
        if on_data {
            return Some(data);
        }
    }
    Some(best)
}

/// Per-device counters from /proc/diskstats, bytes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DiskStat {
    pub major: u32,
    pub minor: u32,
    pub read: u64,
    pub written: u64,
}

/// `/proc/diskstats` -> name -> counters (sectors are always 512 bytes there).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_diskstats_devs(text: &str) -> HashMap<String, DiskStat> {
    let mut m = HashMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let num = |i: usize| f[i].parse::<u64>().unwrap_or(0);
        m.insert(
            f[2].to_string(),
            DiskStat {
                major: num(0) as u32,
                minor: num(1) as u32,
                read: num(5).saturating_mul(512),
                written: num(9).saturating_mul(512),
            },
        );
    }
    m
}

/// "nvme0n1p2" -> "nvme0n1", "sda3" -> "sda", "mmcblk0p1" -> "mmcblk0", "vdb1" -> "vdb".
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parent_disk(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if trimmed.len() == name.len() || trimmed.is_empty() {
        return None;
    }
    if let Some(base) = trimmed.strip_suffix('p')
        && base.ends_with(|c: char| c.is_ascii_digit())
    {
        return Some(base.to_string());
    }
    // Whole disks whose names end in digits: nvme0n1, dm-0, loop0, md0.
    if trimmed.ends_with(|c: char| c.is_ascii_digit() || c == 'n' || c == '-')
        || ["loop", "md", "sr", "nbd", "zram", "ram"].contains(&trimmed)
    {
        return None;
    }
    Some(trimmed.to_string())
}

/// Which diskstats entry carries a mount's I/O.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn disk_for(stats: &HashMap<String, DiskStat>, majmin: Option<(u32, u32)>, source: &str) -> Option<String> {
    if let Some((ma, mi)) = majmin.filter(|m| m.0 != 0)
        && let Some((name, _)) = stats.iter().find(|(_, s)| s.major == ma && s.minor == mi)
    {
        return Some(name.clone());
    }
    let dev = source.strip_prefix("/dev/")?;
    let real = std::fs::canonicalize(source).ok();
    let name = real
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| dev.rsplit('/').next().unwrap_or(dev).to_string());
    if stats.contains_key(&name) {
        return Some(name);
    }
    parent_disk(&name).filter(|p| stats.contains_key(p))
}

// ---- deleted but open ---------------------------------------------------------------------------

/// Deleted files still held open: (pid, process name, path, bytes). Own processes only
/// unless root. Cheap enough to call every ~30s.
///
/// Each file (dev, inode) is listed once, under the first process seen holding it.
/// Results are cached for a few seconds.
pub fn deleted_open() -> Vec<(u32, String, String, u64)> {
    static CACHE: Mutex<Option<(Instant, Vec<DeletedFile>)>> = Mutex::new(None);
    if let Ok(c) = CACHE.lock()
        && let Some((t, v)) = c.as_ref()
        && t.elapsed() < DELETED_TTL
    {
        return v.clone();
    }
    let v = deleted_open_uncached();
    if let Ok(mut c) = CACHE.lock() {
        *c = Some((Instant::now(), v.clone()));
    }
    v
}

fn finish_deleted(mut v: Vec<(u32, String, String, u64)>) -> Vec<(u32, String, String, u64)> {
    v.sort_by(|a, b| b.3.cmp(&a.3).then(a.0.cmp(&b.0)));
    v
}

#[cfg(target_os = "linux")]
pub fn deleted_open_uncached() -> Vec<(u32, String, String, u64)> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let pdir = e.path();
        if euid != 0 && std::fs::metadata(&pdir).map(|m| m.uid() != euid).unwrap_or(true) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(pdir.join("fd")) else { continue };
        let mut name: Option<String> = None;
        for fd in fds.flatten() {
            let Ok(link) = std::fs::read_link(fd.path()) else { continue };
            let link = link.to_string_lossy();
            let Some(path) = link.strip_suffix(" (deleted)") else { continue };
            if !path.starts_with('/') || path.starts_with("/memfd:") || path.starts_with("/SYSV") || under(path, "/dev") {
                continue;
            }
            let Ok(md) = std::fs::metadata(fd.path()) else { continue };
            if !md.is_file() || md.nlink() > 0 || !seen.insert((md.dev(), md.ino())) {
                continue;
            }
            let bytes = if md.blocks() > 0 { md.blocks() * 512 } else { md.len() };
            let comm = name.get_or_insert_with(|| {
                std::fs::read_to_string(pdir.join("comm")).map(|s| s.trim().to_string()).unwrap_or_default()
            });
            out.push((pid, comm.clone(), path.to_string(), bytes));
        }
    }
    finish_deleted(out)
}

#[cfg(target_os = "macos")]
pub fn deleted_open_uncached() -> Vec<(u32, String, String, u64)> {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let uid = euid.to_string();
    let mut args: Vec<&str> = vec!["+c", "0", "-nP", "-w", "+L1"];
    if euid != 0 {
        args.extend(["-a", "-u", uid.as_str()]);
    }
    args.extend(["-F", "pcftsiDn"]);
    let Some(out) = run_timeout("lsof", &args, Duration::from_secs(5)) else { return Vec::new() };
    finish_deleted(parse_lsof_deleted(&out))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn deleted_open_uncached() -> Vec<(u32, String, String, u64)> {
    Vec::new()
}

/// Parse `lsof -F pcftsiDn +L1` output; regular files only, one entry per (dev, inode).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_lsof_deleted(text: &str) -> Vec<(u32, String, String, u64)> {
    let mut out = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let (mut pid, mut cmd) = (0u32, String::new());
    let (mut ty, mut size, mut ino, mut dev) = (String::new(), 0u64, String::new(), String::new());
    for line in text.lines() {
        let Some(tag) = line.chars().next() else { continue };
        let val = &line[tag.len_utf8()..];
        match tag {
            'p' => {
                pid = val.parse().unwrap_or(0);
                cmd.clear();
            }
            'c' => cmd = val.to_string(),
            'f' => {
                ty.clear();
                size = 0;
                ino.clear();
                dev.clear();
            }
            't' => ty = val.to_string(),
            's' => size = val.parse().unwrap_or(0),
            'i' => ino = val.to_string(),
            'D' => dev = val.to_string(),
            'n' => {
                if ty == "REG" && pid != 0 && (ino.is_empty() || seen.insert((dev.clone(), ino.clone()))) {
                    out.push((pid, cmd.clone(), val.to_string(), size));
                }
            }
            _ => {}
        }
    }
    out
}

/// Run a command we spawn ourselves, killing it after `timeout`. stdout on success.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn run_timeout(cmd: &str, args: &[&str], timeout: Duration) -> Option<String> {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = std::process::Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    // Read in a thread so a large output can't fill the pipe and deadlock the wait.
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }
    // lsof exits 1 when nothing matched; output is still valid.
    reader.join().ok()
}

// ---- ioreg parsing (pure; used on macOS) ----------------------------------------------------------

/// `ioreg -c IOBlockStorageDriver -r -d 1 -w0` -> [(registry id, bytes read, bytes written)].
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_ioreg_stats(text: &str) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        if line.starts_with("+-o ") {
            cur = ioreg_id(line);
        } else if let Some(id) = &cur
            && line.contains("\"Statistics\" = {")
        {
            let r = ioreg_num(line, "Bytes (Read)").unwrap_or(0);
            let w = ioreg_num(line, "Bytes (Write)").unwrap_or(0);
            out.push((id.clone(), r, w));
            cur = None;
        }
    }
    out
}

/// `ioreg -c IOBlockStorageDriver -r -l -w0` -> BSD name -> (driver id, whole-disk name).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_ioreg_bsd_map(text: &str) -> HashMap<String, (String, String)> {
    let mut m = HashMap::new();
    let mut cur: Option<(String, Option<String>)> = None;
    for line in text.lines() {
        if line.starts_with("+-o ") {
            cur = ioreg_id(line).map(|id| (id, None));
        } else if let Some((id, disk)) = cur.as_mut()
            && let Some(pos) = line.find("\"BSD Name\" = \"")
        {
            let rest = &line[pos + 14..];
            if let Some(name) = rest.split('"').next() {
                let whole = disk.get_or_insert_with(|| name.to_string()).clone();
                m.insert(name.to_string(), (id.clone(), whole));
            }
        }
    }
    m
}

fn ioreg_id(line: &str) -> Option<String> {
    let p = line.find(", id 0x")?;
    let rest = &line[p + 5..];
    Some(rest.split([',', '>']).next()?.trim().to_string())
}

fn ioreg_num(line: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\"=");
    let p = line.find(&pat)?;
    let rest = &line[p + pat.len()..];
    rest.split([',', '}']).next()?.trim().parse().ok()
}

// ---- Linux syscalls ------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod lx {
    pub use super::Stat;

    #[allow(clippy::unnecessary_cast)] // field widths differ across Linux targets
    pub fn statvfs(path: &str) -> Option<Stat> {
        let c = std::ffi::CString::new(path).ok()?;
        // SAFETY: zeroed statvfs is a valid out-param; c is NUL-terminated.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
            return None;
        }
        let fr = if s.f_frsize > 0 { s.f_frsize } else { s.f_bsize } as u64;
        Some(Stat {
            total: s.f_blocks as u64 * fr,
            free: s.f_bfree as u64 * fr,
            avail: s.f_bavail as u64 * fr,
            files: s.f_files as u64,
            ffree: s.f_ffree as u64,
        })
    }
}

// ---- macOS -------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod mac {
    use super::{RawMount, Stat};
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::sync::{Arc, Mutex, Weak};
    use std::time::{Duration, Instant};

    const IO_EVERY: Duration = Duration::from_secs(5);
    const MAP_EVERY: Duration = Duration::from_secs(60);
    const IDLE_AFTER: Duration = Duration::from_secs(15);

    fn cstr(b: &[libc::c_char]) -> String {
        // SAFETY: statfs name fields are NUL-terminated within their fixed-size arrays.
        unsafe { CStr::from_ptr(b.as_ptr()) }.to_string_lossy().into_owned()
    }

    fn stat_of(s: &libc::statfs) -> Stat {
        let bs = s.f_bsize as u64;
        Stat {
            total: s.f_blocks * bs,
            free: s.f_bfree * bs,
            avail: s.f_bavail * bs,
            files: s.f_files,
            ffree: s.f_ffree,
        }
    }

    pub fn mounts() -> Vec<RawMount> {
        let mut buf: *mut libc::statfs = std::ptr::null_mut();
        // SAFETY: getmntinfo fills `buf` with a pointer to a libc-owned array of `n` entries,
        // valid until the next getmntinfo call on this thread; we copy out before returning.
        let n = unsafe { libc::getmntinfo(&mut buf, libc::MNT_NOWAIT) };
        if n <= 0 || buf.is_null() {
            return Vec::new();
        }
        let arr = unsafe { std::slice::from_raw_parts(buf, n as usize) };
        arr.iter()
            .map(|s| RawMount {
                mount: cstr(&s.f_mntonname),
                source: cstr(&s.f_mntfromname),
                fstype: cstr(&s.f_fstypename),
                root: "/".into(),
                majmin: (0, 0),
                read_only: s.f_flags & libc::MNT_RDONLY as u32 != 0,
                local: s.f_flags & libc::MNT_LOCAL as u32 != 0,
                stat: stat_of(s),
            })
            .collect()
    }

    /// Fresh capacity. On APFS `f_bfree` is container-wide, so blocks - bfree would give every
    /// volume the container's used space; the volume's own used comes from ATTR_VOL_SPACEUSED
    /// (what df shows), and `free` is derived from it.
    pub fn statfs(path: &str) -> Option<Stat> {
        let c = std::ffi::CString::new(path).ok()?;
        // SAFETY: zeroed statfs is a valid out-param; c is NUL-terminated.
        let mut s: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
            return None;
        }
        let mut st = stat_of(&s);
        if cstr(&s.f_fstypename) == "apfs"
            && let Some(used) = space_used(&c)
        {
            st.free = st.total.saturating_sub(used);
        }
        Some(st)
    }

    /// getattrlist(ATTR_VOL_SPACEUSED): bytes used by this volume alone.
    fn space_used(path: &std::ffi::CStr) -> Option<u64> {
        #[repr(C, packed(4))]
        struct Buf {
            len: u32,
            used: libc::off_t,
        }
        // SAFETY: attrlist is plain data; we request exactly one volume attribute (an off_t),
        // which getattrlist writes after the u32 length into our correctly sized buffer.
        unsafe {
            let mut al: libc::attrlist = std::mem::zeroed();
            al.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
            al.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_SPACEUSED;
            let mut buf = Buf { len: 0, used: 0 };
            let r = libc::getattrlist(
                path.as_ptr(),
                &mut al as *mut libc::attrlist as *mut libc::c_void,
                &mut buf as *mut Buf as *mut libc::c_void,
                std::mem::size_of::<Buf>(),
                0,
            );
            let (len, used) = (buf.len, buf.used);
            (r == 0 && len as usize >= std::mem::size_of::<Buf>() && used >= 0).then_some(used as u64)
        }
    }

    // CoreFoundation: available capacity for important usage (= free + purgeable).
    type CFTypeRef = *const std::ffi::c_void;
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFURLVolumeAvailableCapacityForImportantUsageKey: CFTypeRef;
        fn CFURLCreateFromFileSystemRepresentation(alloc: CFTypeRef, buf: *const u8, len: isize, is_dir: u8) -> CFTypeRef;
        fn CFURLCopyResourcePropertyForKey(url: CFTypeRef, key: CFTypeRef, value: *mut CFTypeRef, err: *mut CFTypeRef) -> u8;
        fn CFNumberGetValue(n: CFTypeRef, ty: isize, out: *mut std::ffi::c_void) -> u8;
        fn CFGetTypeID(cf: CFTypeRef) -> usize;
        fn CFNumberGetTypeID() -> usize;
        fn CFRelease(cf: CFTypeRef);
    }
    const K_CF_NUMBER_SINT64: isize = 4;

    pub fn important_avail(mount: &str) -> Option<u64> {
        // SAFETY: standard CF create/copy/release pattern; every object we own is released,
        // the key is a framework constant, and type ids are checked before CFNumberGetValue.
        unsafe {
            let url = CFURLCreateFromFileSystemRepresentation(std::ptr::null(), mount.as_ptr(), mount.len() as isize, 1);
            if url.is_null() {
                return None;
            }
            let mut val: CFTypeRef = std::ptr::null();
            let ok = CFURLCopyResourcePropertyForKey(
                url,
                kCFURLVolumeAvailableCapacityForImportantUsageKey,
                &mut val,
                std::ptr::null_mut(),
            );
            CFRelease(url);
            if ok == 0 || val.is_null() {
                return None;
            }
            let mut n: i64 = 0;
            let got = CFGetTypeID(val) == CFNumberGetTypeID()
                && CFNumberGetValue(val, K_CF_NUMBER_SINT64, &mut n as *mut i64 as *mut _) != 0;
            CFRelease(val);
            (got && n > 0).then_some(n as u64)
        }
    }

    // ---- ioreg background poller ---------------------------------------------------------

    /// BSD name -> (read bps, write bps, physical disk name).
    pub type Rates = HashMap<String, (u64, u64, String)>;

    struct Shared {
        rates: Mutex<Rates>,
        last_read: Mutex<Instant>,
    }

    pub struct IoPoller {
        shared: Arc<Shared>,
    }

    impl IoPoller {
        pub fn start() -> Self {
            let shared = Arc::new(Shared { rates: Mutex::new(HashMap::new()), last_read: Mutex::new(Instant::now()) });
            let weak = Arc::downgrade(&shared);
            let _ = std::thread::Builder::new().name("fat-diskio".into()).spawn(move || poll(weak));
            IoPoller { shared }
        }

        pub fn get(&self) -> Rates {
            if let Ok(mut t) = self.shared.last_read.lock() {
                *t = Instant::now();
            }
            self.shared.rates.lock().map(|r| r.clone()).unwrap_or_default()
        }
    }

    fn poll(weak: Weak<Shared>) {
        let mut map: HashMap<String, (String, String)> = HashMap::new();
        let mut last_map: Option<Instant> = None;
        let mut prev: HashMap<String, (Instant, u64, u64)> = HashMap::new();
        let mut last_io: Option<Instant> = None;
        // The first rate needs two readings: take the second one quickly so a one-shot
        // `fat fs --volumes` (which samples ~1.3 s apart) already shows I/O.
        let mut warm = false;
        loop {
            let Some(shared) = weak.upgrade() else { return };
            let idle = shared.last_read.lock().map(|t| t.elapsed() > IDLE_AFTER).unwrap_or(false);
            let every = if warm { IO_EVERY } else { Duration::from_millis(900) };
            if !idle && last_io.is_none_or(|t| t.elapsed() >= every) {
                last_io = Some(Instant::now());
                let stats = super::run_timeout("ioreg", &["-c", "IOBlockStorageDriver", "-r", "-d", "1", "-w0"], Duration::from_secs(3))
                    .map(|s| super::parse_ioreg_stats(&s))
                    .unwrap_or_default();
                let unknown = stats.iter().any(|(id, _, _)| !map.values().any(|(i, _)| i == id));
                if last_map.is_none_or(|t| t.elapsed() >= MAP_EVERY) || (unknown && last_map.is_none_or(|t| t.elapsed() >= IO_EVERY)) {
                    last_map = Some(Instant::now());
                    if let Some(s) = super::run_timeout("ioreg", &["-c", "IOBlockStorageDriver", "-r", "-l", "-w0"], Duration::from_secs(3)) {
                        map = super::parse_ioreg_bsd_map(&s);
                    }
                }
                let now = Instant::now();
                let mut per_id: HashMap<String, (u64, u64)> = HashMap::new();
                for (id, r, w) in stats {
                    if let Some((t, pr, pw)) = prev.get(&id) {
                        let dt = now.duration_since(*t).as_secs_f64().max(0.001);
                        per_id.insert(id.clone(), ((r.saturating_sub(*pr) as f64 / dt) as u64, (w.saturating_sub(*pw) as f64 / dt) as u64));
                    }
                    prev.insert(id, (now, r, w));
                }
                warm = !per_id.is_empty();
                let rates: Rates = map
                    .iter()
                    .filter_map(|(bsd, (id, disk))| per_id.get(id).map(|(r, w)| (bsd.clone(), (*r, *w, disk.clone()))))
                    .collect();
                if let Ok(mut m) = shared.rates.lock() {
                    *m = rates;
                }
            }
            drop(shared);
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = r"356 248 0:68 / / rw,relatime - overlay overlay rw,lowerdir=/a:/b,upperdir=/c,workdir=/d
358 356 0:79 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
359 356 0:80 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
360 359 0:81 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
361 356 0:82 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
362 361 0:32 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate
363 359 0:77 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
365 356 0:36 /Users/zamanfoo/fat /src rw,relatime - virtiofs mac rw
366 356 0:38 /docker/volumes/fat-linux-target/_data /target rw,noatime master:70 - btrfs /dev/vdb1 rw,ssd,subvolid=256,subvol=/docker
367 356 0:38 /docker/containers/4108/hostname /etc/hostname rw,noatime - btrfs /dev/vdb1 rw,ssd,subvolid=256,subvol=/docker
370 356 0:38 /docker/volumes/fat-linux-cargo/_data /usr/local/cargo/registry rw,noatime master:70 - btrfs /dev/vdb1 rw,ssd
371 356 259:2 / /home rw,relatime - ext4 /dev/nvme0n1p2 rw
372 356 8:17 / /media/usb\040stick rw,relatime - vfat /dev/sdb1 rw
373 356 7:3 / /snap/core/123 ro,relatime - squashfs /dev/loop3 ro
374 356 0:90 / /var/lib/docker/overlay2/abc/merged rw - overlay overlay rw
375 356 0:91 / /run rw,nosuid - tmpfs tmpfs rw,size=1g
376 356 0:92 / /mnt/sshfs rw - fuse.sshfs me@host:/ rw
377 356 0:93 / /sys/fs/fuse/connections rw - fusectl fusectl rw
garbage line without separator
";

    fn by_mount<'a>(c: &'a [(RawMount, Visibility)], m: &str) -> Option<&'a (RawMount, Visibility)> {
        c.iter().find(|(r, _)| r.mount == m)
    }

    #[test]
    fn mountinfo_parsing() {
        let m = parse_mountinfo(MOUNTINFO);
        assert_eq!(m.len(), 18);
        let root = &m[0];
        assert_eq!((root.mount.as_str(), root.fstype.as_str(), root.source.as_str()), ("/", "overlay", "overlay"));
        assert_eq!(root.majmin, (0, 68));
        let usb = m.iter().find(|r| r.fstype == "vfat").unwrap();
        assert_eq!(usb.mount, "/media/usb stick");
        assert!(m.iter().find(|r| r.mount == "/sys").unwrap().read_only);
        assert!(m.iter().find(|r| r.mount == "/snap/core/123").unwrap().read_only);
        assert_eq!(m.iter().find(|r| r.mount == "/target").unwrap().root, "/docker/volumes/fat-linux-target/_data");
        assert_eq!(unescape_mount(r"a\134b\011c"), "a\\b\tc");
        assert_eq!(unescape_mount(r"trailing\04"), r"trailing\04");
    }

    #[test]
    fn pseudo_filtering_and_classification() {
        let c = classify_linux(&parse_mountinfo(MOUNTINFO));
        for gone in ["/proc", "/dev/pts", "/sys", "/sys/fs/cgroup", "/dev/mqueue", "/sys/fs/fuse/connections"] {
            assert!(by_mount(&c, gone).is_none(), "{gone} should be dropped");
        }
        let vis = |m: &str| by_mount(&c, m).unwrap().1;
        assert!(vis("/").primary && !vis("/").hidden && !vis("/").remote);
        assert!(vis("/src").remote && !vis("/src").hidden);
        // Same btrfs device: one representative, bind mounts hidden.
        assert!(!vis("/target").hidden);
        assert!(vis("/etc/hostname").hidden);
        assert!(vis("/usr/local/cargo/registry").hidden);
        assert!(!vis("/home").hidden && !vis("/home").primary);
        assert!(vis("/media/usb stick").remote, "removable media is not scanned automatically");
        assert!(vis("/snap/core/123").hidden);
        assert!(vis("/var/lib/docker/overlay2/abc/merged").hidden);
        assert!(vis("/dev").hidden, "tmpfs on /dev is noise");
        assert!(!vis("/run").hidden);
        assert!(vis("/mnt/sshfs").remote);
        assert!(is_pseudo("autofs") && is_pseudo("devfs") && !is_pseudo("apfs") && !is_pseudo("tmpfs"));
        assert!(is_remote_fstype("nfs") && is_remote_fstype("fuse.rclone") && is_remote_fstype("smbfs"));
        assert!(!is_remote_fstype("ext4") && !is_remote_fstype("apfs"));
    }

    fn mac_raw(mount: &str, dev: &str, fstype: &str, local: bool) -> RawMount {
        RawMount { mount: mount.into(), source: dev.into(), fstype: fstype.into(), local, ..Default::default() }
    }

    #[test]
    fn macos_classification() {
        let raws = vec![
            mac_raw("/", "/dev/disk3s1s1", "apfs", true),
            mac_raw("/dev", "devfs", "devfs", true),
            mac_raw("/System/Volumes/VM", "/dev/disk3s6", "apfs", true),
            mac_raw("/System/Volumes/Preboot", "/dev/disk3s2", "apfs", true),
            mac_raw("/System/Volumes/Update", "/dev/disk3s4", "apfs", true),
            mac_raw("/System/Volumes/xarts", "/dev/disk1s2", "apfs", true),
            mac_raw("/System/Volumes/iSCPreboot", "/dev/disk1s1", "apfs", true),
            mac_raw("/System/Volumes/Hardware", "/dev/disk1s3", "apfs", true),
            mac_raw("/System/Volumes/Data", "/dev/disk3s5", "apfs", true),
            mac_raw("/System/Volumes/Data/home", "map auto_home", "autofs", true),
            mac_raw("/Volumes/Install OrbStack v2.2.5", "/dev/disk5s1", "apfs", true),
            mac_raw("/Users/zamanfoo/OrbStack", "OrbStack:/OrbStack", "nfs", false),
        ];
        let c = classify_macos(&raws);
        assert!(by_mount(&c, "/dev").is_none());
        assert!(by_mount(&c, "/System/Volumes/Data/home").is_none());
        let vis = |m: &str| by_mount(&c, m).unwrap().1;
        assert!(vis("/System/Volumes/Data").primary && !vis("/System/Volumes/Data").hidden);
        assert!(!vis("/").primary && !vis("/").hidden);
        assert!(!vis("/System/Volumes/VM").hidden, "swap stays visible");
        for h in ["Preboot", "Update", "xarts", "iSCPreboot", "Hardware"] {
            assert!(vis(&format!("/System/Volumes/{h}")).hidden, "{h}");
        }
        assert!(vis("/Volumes/Install OrbStack v2.2.5").remote);
        assert!(vis("/Users/zamanfoo/OrbStack").remote);
        assert_eq!(container_key("/dev/disk3s1s1"), "disk3");
        assert_eq!(container_key("/dev/disk3s5"), "disk3");
        assert_eq!(container_key("/dev/nvme0n1p2"), "nvme0n1p2");
    }

    fn vol(mount: &str, dev: &str) -> Volume {
        Volume { mount: mount.into(), device: dev.into(), fstype: "apfs".into(), ..Default::default() }
    }

    #[test]
    fn volume_for_prefix_and_firmlinks() {
        let fl: Vec<String> = DEFAULT_FIRMLINKS.iter().map(|s| s.to_string()).collect();
        let mac = vec![
            vol("/", "/dev/disk3s1s1"),
            vol("/System/Volumes/Data", "/dev/disk3s5"),
            vol("/System/Volumes/VM", "/dev/disk3s6"),
            vol("/Users/zamanfoo/OrbStack", "OrbStack:/OrbStack"),
            vol("/Volumes/Ext", "/dev/disk6s1"),
        ];
        let m = |p: &str| volume_for_with(&mac, p, &fl).unwrap().mount.as_str();
        assert_eq!(m("/"), "/");
        assert_eq!(m("/bin/ls"), "/");
        assert_eq!(m("/System/Library/Frameworks"), "/");
        assert_eq!(m("/System/Library/Caches/x"), "/System/Volumes/Data");
        assert_eq!(m("/Users/zamanfoo/src"), "/System/Volumes/Data");
        assert_eq!(m("/Users"), "/System/Volumes/Data");
        assert_eq!(m("/Usersfoo"), "/", "prefix must end at a path boundary");
        assert_eq!(m("/private/var/vm"), "/System/Volumes/Data");
        assert_eq!(m("/var/log"), "/System/Volumes/Data");
        assert_eq!(m("/usr/local/bin"), "/System/Volumes/Data");
        assert_eq!(m("/usr/bin"), "/");
        assert_eq!(m("/System/Volumes/Data/Users"), "/System/Volumes/Data");
        assert_eq!(m("/System/Volumes/VM/swapfile0"), "/System/Volumes/VM");
        assert_eq!(m("/Users/zamanfoo/OrbStack/docker"), "/Users/zamanfoo/OrbStack");
        assert_eq!(m("/Volumes/Ext/"), "/Volumes/Ext");
        // Linux: no Data volume -> plain longest prefix, firmlinks ignored.
        let lin = vec![vol("/", "overlay"), vol("/home", "/dev/sda2"), vol("/home/me/nfs", "srv:/x")];
        let l = |p: &str| volume_for_with(&lin, p, &fl).unwrap().mount.as_str();
        assert_eq!(l("/home/me/x"), "/home");
        assert_eq!(l("/home/me/nfs/a"), "/home/me/nfs");
        assert_eq!(l("/Users/x"), "/");
        assert_eq!(l("/homework"), "/");
        assert!(volume_for_with(&[], "/", &fl).is_none());
    }

    #[test]
    fn fill_rate_math() {
        assert_eq!(fill_rate(&[]), None);
        assert_eq!(fill_rate(&[(0, 100)]), None);
        assert_eq!(fill_rate(&[(0, 100), (500, 200)]), None, "span too short");
        // 1 MB/s exactly.
        let pts: Vec<(Ts, u64)> = (0..10).map(|i| (i * 2000, 1_000_000_000 + i as u64 * 2_000_000)).collect();
        let r = fill_rate(&pts).unwrap();
        assert!((r - 1_000_000.0).abs() < 1e-3, "{r}");
        // Shrinking.
        let pts: Vec<(Ts, u64)> = (0..5).map(|i| (i * 1000, 5000 - i as u64 * 100)).collect();
        assert!((fill_rate(&pts).unwrap() + 100.0).abs() < 1e-9);
        // Noise around a trend still gives the trend.
        let pts: Vec<(Ts, u64)> =
            (0..100).map(|i| (i * 1000, (1_000_000 + i * 500 + if i % 2 == 0 { 300 } else { 0 }) as u64)).collect();
        assert!((fill_rate(&pts).unwrap() - 500.0).abs() < 5.0);
        assert_eq!(eta_full(1_000_000, Some(1000.0)), Some(1000));
        assert_eq!(eta_full(1_000_000, Some(-5.0)), None);
        assert_eq!(eta_full(0, Some(5.0)), None);
        assert_eq!(eta_full(10, None), None);
    }

    #[test]
    fn fill_window_and_seed() {
        let mut v = Volumes { show_all: false, fill: HashMap::new(), last: HashMap::new(), ..Volumes::new() };
        v.seed("/x", &[(0, 0), (60_000, 60_000_000)]);
        let mut vol = Volume { mount: "/x".into(), avail: 1_000_000_000, used: 120_000_000, ..Default::default() };
        v.update_fill(&mut vol, 120_000);
        let f = vol.fill_bps.unwrap();
        assert!((f - 1_000_000.0).abs() < 1e-3, "{f}");
        assert_eq!(vol.eta_full_s, Some(1000));
        // Samples older than the window fall out.
        v.update_fill(&mut vol, 120_000 + FILL_WINDOW_MS + 1);
        assert_eq!(v.fill["/x"].len(), 1);
        assert_eq!(vol.fill_bps, None);
    }

    #[test]
    fn diskstats_parsing_and_mapping() {
        let ds = "   7       0 loop0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n \
                  254      16 vdb 1442447 16831 161467890 29064 11356076 3348230 554227744 2302008 0 1900925 4150057\n \
                  259       0 nvme0n1 10 0 100 0 10 0 200 0 0 0 0\n \
                  259       2 nvme0n1p2 10 0 40 0 10 0 80 0 0 0 0\n \
                  253       0 dm-0 1 0 8 0 1 0 16 0 0 0 0\n\
                  short line\n";
        let m = parse_diskstats_devs(ds);
        assert_eq!(m.len(), 5);
        assert_eq!(m["vdb"].read, 161_467_890 * 512);
        assert_eq!(m["vdb"].written, 554_227_744 * 512);
        assert_eq!((m["nvme0n1p2"].major, m["nvme0n1p2"].minor), (259, 2));
        assert_eq!(disk_for(&m, Some((259, 2)), "/dev/whatever").as_deref(), Some("nvme0n1p2"));
        assert_eq!(disk_for(&m, Some((0, 38)), "/dev/vdb1").as_deref(), Some("vdb"), "partition missing -> parent");
        assert_eq!(disk_for(&m, Some((0, 68)), "overlay"), None);
        assert_eq!(disk_for(&m, Some((253, 0)), "/dev/mapper/vg-root").as_deref(), Some("dm-0"));
        assert_eq!(parent_disk("sda3").as_deref(), Some("sda"));
        assert_eq!(parent_disk("mmcblk0p1").as_deref(), Some("mmcblk0"));
        assert_eq!(parent_disk("nvme0n1").as_deref(), None);
        assert_eq!(parent_disk("vda").as_deref(), None);
    }

    #[test]
    fn ioreg_parsing() {
        let stats = r#"+-o IOBlockStorageDriver  <class IOBlockStorageDriver, id 0x100000bc5, registered, matched, active, busy 0 (0 ms), retain 6>
      "Statistics" = {"Operations (Write)"=0,"Bytes (Read)"=0,"Bytes (Write)"=0}
+-o IOBlockStorageDriver  <class IOBlockStorageDriver, id 0x100000a59, registered, matched, active, busy 0 (629 ms), retain 8>
      "Statistics" = {"Operations (Write)"=209788741,"Latency Time (Write)"=0,"Bytes (Read)"=2003059339264,"Errors (Write)"=0,"Bytes (Write)"=2646722306048,"Retries (Write)"=0}
"#;
        let s = parse_ioreg_stats(stats);
        assert_eq!(s, vec![("0x100000bc5".into(), 0, 0), ("0x100000a59".into(), 2_003_059_339_264, 2_646_722_306_048)]);
        let tree = r#"+-o IOBlockStorageDriver  <class IOBlockStorageDriver, id 0x100000a59, registered>
  |   "Statistics" = {"Bytes (Read)"=1,"Bytes (Write)"=2}
  +-o APPLE SSD AP1024Z Media  <class IOMedia, id 0x100000a5a, registered>
    |   "BSD Name" = "disk0"
      | |   "BSD Name" = "disk0s2"
      |   |   "Statistics" = {"Bytes (Read)"=5}
      |     |   "BSD Name" = "disk3"
      |       | |   "BSD Name" = "disk3s5"
+-o IOBlockStorageDriver  <class IOBlockStorageDriver, id 0x10004f862, registered>
    |   "BSD Name" = "disk4"
                |   "BSD Name" = "disk5s1"
"#;
        let m = parse_ioreg_bsd_map(tree);
        assert_eq!(m["disk3s5"], ("0x100000a59".into(), "disk0".into()));
        assert_eq!(m["disk0"].0, "0x100000a59");
        assert_eq!(m["disk5s1"], ("0x10004f862".into(), "disk4".into()));
    }

    #[test]
    fn lsof_parsing() {
        let t = "p161\ncKeychain Circle Notification\nftxt\ntREG\ns67496\ni100\nD0x1000010\nn/Library/x.plist-cache\n\
                 p395\ncloginwindow\nftxt\ntREG\ns67496\ni100\nD0x1000010\nn/Library/x.plist-cache\n\
                 f12\ntREG\ns999\ni200\nD0x1000010\nn/private/tmp/big\nf13\ntCHR\ns5\ni3\nn/dev/null\n";
        let v = parse_lsof_deleted(t);
        assert_eq!(v.len(), 2, "deduped by inode, regular files only: {v:?}");
        assert_eq!(v[0], (161, "Keychain Circle Notification".into(), "/Library/x.plist-cache".into(), 67496));
        assert_eq!(v[1], (395, "loginwindow".into(), "/private/tmp/big".into(), 999));
        let s = finish_deleted(v);
        assert_eq!(s[0].3, 67496);
    }

    #[test]
    fn totals_dedupe_container() {
        let mk = |m: &str, d: &str, used: u64| Volume {
            mount: m.into(),
            device: d.into(),
            fstype: "apfs".into(),
            used,
            avail: 100,
            total: 1000,
            ..Default::default()
        };
        let mut x = mk("/x", "/dev/disk6s1", 5);
        x.total = 500;
        let vols = vec![mk("/", "/dev/disk3s1s1", 10), mk("/System/Volumes/Data", "/dev/disk3s5", 600), x];
        assert_eq!(totals(&vols), (615, 200, 1500));
        // Linux: overlay root and a btrfs bind of the same pool count once.
        let lin = |m: &str, d: &str, f: &str| Volume { mount: m.into(), device: d.into(), fstype: f.into(), used: 300, avail: 700, total: 1000, ..Default::default() };
        let v = vec![lin("/", "overlay", "overlay"), lin("/target", "/dev/vdb1", "btrfs"), lin("/home", "/dev/sda2", "ext4")];
        let v = [v, vec![Volume { avail: 1500, total: 2000, ..lin("/data", "/dev/sdb1", "ext4") }]].concat();
        assert_eq!(totals(&v[..2]), (300, 700, 1000));
        assert_eq!(totals(&v[..1]), (300, 700, 1000));
        assert_eq!(totals(&[v[0].clone(), v[3].clone()]), (600, 2200, 3000));
        assert_eq!(totals(&v), (600, 2200, 3000), "same-size /home with near-equal free is merged (documented heuristic)");
    }

    /// Scratch dir inside the cargo target dir (next to the test binary), so it sits on a real
    /// local filesystem even when the source tree is a virtiofs/NFS share.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let exe = std::env::current_exe().unwrap();
        let d = exe
            .parent()
            .unwrap()
            .join("fs-volumes-test")
            .join(format!("{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn deleted_open_finds_own_file() {
        use std::io::Write;
        let dir = scratch("deleted");
        let p = dir.join("held-open.bin");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&vec![7u8; 1 << 20]).unwrap();
        f.sync_all().unwrap();
        std::fs::remove_file(&p).unwrap();
        let me = std::process::id();
        let found = deleted_open_uncached();
        let hit = found.iter().find(|(pid, _, path, _)| *pid == me && path.ends_with("held-open.bin"));
        assert!(hit.is_some(), "not found among {} entries: {:?}", found.len(), found.iter().filter(|e| e.0 == me).collect::<Vec<_>>());
        assert!(hit.unwrap().3 >= 1 << 20, "{hit:?}");
        // Sorted by bytes desc.
        assert!(found.windows(2).all(|w| w[0].3 >= w[1].3));
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Manual check: `cargo test --bin fat fs::volumes::tests::print_real -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_real() {
        let mut v = Volumes::with_all(std::env::var_os("FAT_ALL").is_some());
        let t = Instant::now();
        let _ = v.sample();
        eprintln!("first sample {:?}", t.elapsed());
        std::thread::sleep(Duration::from_secs(6));
        let t = Instant::now();
        let vols = v.sample();
        eprintln!("second sample {:?}", t.elapsed());
        for x in &vols {
            eprintln!(
                "{:<40} {:<22} {:<8} used {:>8.2}G avail {:>8.2}G tot {:>8.2}G purg {:?} ino {}/{} ro={} remote={} primary={} hidden={} r={} w={} fill={:?} eta={:?} {}",
                x.mount, x.device, x.fstype, x.used as f64 / 1e9, x.avail as f64 / 1e9, x.total as f64 / 1e9,
                x.purgeable.map(|p| p as f64 / 1e9), x.inodes_used, x.inodes_total, x.read_only, x.remote, x.primary,
                x.hidden, x.read_bps, x.write_bps, x.fill_bps, x.eta_full_s, x.note
            );
        }
        eprintln!("totals {:?}", totals(&vols));
        let t = Instant::now();
        let d = deleted_open_uncached();
        eprintln!("deleted_open: {} files, {} bytes in {:?}", d.len(), d.iter().map(|e| e.3).sum::<u64>(), t.elapsed());
        for e in d.iter().take(5) {
            eprintln!("  {e:?}");
        }
        for p in ["/", "/Users/zamanfoo", "/private/var/vm", "/System/Volumes/VM", "/tmp", "/usr/bin"] {
            eprintln!("volume_for({p}) = {:?}", volume_for(&vols, p).map(|v| &v.mount));
        }
    }

    #[test]
    fn sample_real_mounts() {
        let mut v = Volumes::new();
        let a = v.sample();
        assert!(!a.is_empty());
        assert_eq!(a.iter().filter(|x| x.primary).count(), 1, "{a:#?}");
        let p = a.iter().find(|x| x.primary).unwrap();
        assert!(p.total > 0 && p.used <= p.total, "{p:?}");
        assert!(a.iter().all(|x| !x.hidden));
        assert!(a.iter().all(|x| !is_pseudo(&x.fstype)));
        std::thread::sleep(Duration::from_millis(1100));
        let b = v.sample();
        let p = b.iter().find(|x| x.primary).unwrap();
        assert!(p.fill_bps.is_some(), "{p:?}");
        let all = Volumes::with_all(true).sample();
        assert!(all.len() >= b.len());
    }
}
