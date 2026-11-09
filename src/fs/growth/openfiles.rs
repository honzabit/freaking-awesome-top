//! Evidence::OpenFiles: regular files that disk-writing processes hold open for writing,
//! sized repeatedly so their growth can be measured and attributed to the writer.
//!
//! Linux: /proc/<pid>/fd + /proc/<pid>/fdinfo flags. macOS: libproc
//! (proc_pidinfo(PROC_PIDLISTFDS) + proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)), which returns
//! open mode, path and size straight from the kernel: no lsof subprocess, no stat of the file,
//! so it cannot trip TCC prompts either.
use super::rollup::Obs;
use crate::fs::Evidence;
use crate::model::{Snapshot, Ts};
use std::collections::HashMap;

/// Enumerate at most this often.
pub const MIN_INTERVAL_MS: i64 = 5_000;
/// Writers examined per enumeration.
pub const TOP_WRITERS: usize = 10;
const MAX_FILES: usize = 5_000;
const KEEP_MS: i64 = 70 * 60 * 1000;

/// (pid, name, write bytes/sec).
pub type Writer = (u32, String, u64);
/// Writers with the files each holds open for writing: (path, allocated bytes).
pub type Found = Vec<(Writer, Vec<(String, u64)>)>;

#[derive(Debug, Clone, Default)]
pub struct Track {
    /// (ts, allocated bytes), oldest first, thinned.
    pub samples: Vec<(Ts, u64)>,
    pub writers: Vec<(u32, String, u64)>,
    pub last_seen: Ts,
}

#[derive(Default)]
pub struct OpenFiles {
    pub last_scan: Ts,
    pub scans: u64,
    pub files: HashMap<String, Track>,
}

impl OpenFiles {
    /// Throttled: enumerate the top writers of `snap` when the last pass is >= 5 s old.
    pub fn maybe_scan(&mut self, snap: &Snapshot, exclude: &[String]) {
        let now = if snap.ts > 0 { snap.ts } else { crate::model::now_ms() };
        if now - self.last_scan < MIN_INTERVAL_MS {
            return;
        }
        let me = std::process::id();
        let mut w: Vec<(u32, String, u64)> = snap
            .procs
            .iter()
            .filter(|p| p.disk_write_bps > 0 && p.pid != me)
            .map(|p| (p.pid, p.name.clone(), p.disk_write_bps))
            .collect();
        w.sort_by(|a, b| b.2.cmp(&a.2));
        w.truncate(TOP_WRITERS);
        // A sample without rates yet (the first one) must not hold off the next for 5 s.
        if w.is_empty() {
            return;
        }
        self.last_scan = now;
        let found: Found = w
            .into_iter()
            .map(|p| {
                let f = writable_files(p.0);
                (p, f)
            })
            .collect();
        self.ingest(now, found, exclude);
    }

    pub fn ingest(&mut self, now: Ts, found: Found, exclude: &[String]) {
        self.scans += 1;
        for (writer, files) in found {
            for (path, size) in files {
                if exclude.iter().any(|e| super::under_prefix(&path, e)) {
                    continue;
                }
                let t = self.files.entry(path).or_default();
                t.last_seen = now;
                super::rollup::merge_writers(&mut t.writers, std::slice::from_ref(&writer));
                push_sample(&mut t.samples, now, size);
            }
        }
        self.files.retain(|_, t| now - t.last_seen < KEEP_MS);
        if self.files.len() > MAX_FILES {
            let mut v: Vec<(Ts, String)> = self.files.iter().map(|(k, t)| (t.last_seen, k.clone())).collect();
            v.sort();
            for (_, k) in v.into_iter().take(self.files.len() - MAX_FILES) {
                self.files.remove(&k);
            }
        }
    }

    /// Per-file deltas over [from, now]. A file seen only once has an unknown delta.
    pub fn obs(&self, from: Ts) -> Vec<Obs> {
        self.files
            .iter()
            .filter(|(_, t)| t.last_seen >= from && !t.samples.is_empty())
            .map(|(p, t)| {
                let mut o = Obs::new(p.clone(), Evidence::OpenFiles);
                let cur = t.samples.last().map(|s| s.1).unwrap_or(0);
                o.size = Some(cur);
                o.touched = 1;
                o.writers = t.writers.clone();
                if t.samples.len() >= 2 {
                    let base = baseline(&t.samples, from).unwrap_or(cur);
                    o.delta = Some(cur as i64 - base as i64);
                }
                // Created inside the window: all of it is growth, even with one sample. Linux
                // only (macOS gets creations from FSEvents, and a stat there could touch a
                // TCC-protected path).
                if cfg!(target_os = "linux")
                    && super::paths::lstat(p).is_some_and(|st| st.is_file && st.nlink <= 1 && st.birth_ms.is_some_and(|b| b >= from))
                {
                    o.delta = Some(cur as i64);
                }
                o
            })
            .collect()
    }
}

/// Keep a short, thinned size history: always the oldest and the newest.
pub fn push_sample(s: &mut Vec<(Ts, u64)>, now: Ts, size: u64) {
    if let Some(last) = s.last()
        && last.1 == size
        && s.len() >= 2
        && s[s.len() - 2].1 == size
    {
        // Flat: just move the newest stamp forward.
        let n = s.len();
        s[n - 1].0 = now;
        return;
    }
    s.push((now, size));
    if s.len() > 16 {
        s.remove(1);
    }
}

/// Size at window start: newest sample at or before `from`, else the oldest one we have.
pub fn baseline(s: &[(Ts, u64)], from: Ts) -> Option<u64> {
    s.iter().rev().find(|x| x.0 <= from).or(s.first()).map(|x| x.1)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Parse the octal `flags:` line of /proc/<pid>/fdinfo/<fd>.
pub fn parse_fdinfo_flags(text: &str) -> Option<u32> {
    text.lines()
        .find_map(|l| l.strip_prefix("flags:"))
        .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Opened O_WRONLY or O_RDWR.
pub fn is_write_flags(flags: u32) -> bool {
    matches!(flags & 0o3, 1 | 2)
}

/// Regular files `pid` holds open for writing: (path, allocated bytes).
#[cfg(target_os = "linux")]
pub fn writable_files(pid: u32) -> Vec<(String, u64)> {
    use std::os::unix::fs::MetadataExt;
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return out;
    };
    for e in rd.flatten().take(4096) {
        let name = e.file_name();
        let Some(fd) = name.to_str() else { continue };
        let Ok(target) = std::fs::read_link(e.path()) else {
            continue;
        };
        let t = target.to_string_lossy();
        if !t.starts_with('/') || t.ends_with(" (deleted)") || super::paths::is_pseudo_path(&t) {
            continue;
        }
        let Ok(info) = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) else {
            continue;
        };
        if !parse_fdinfo_flags(&info).is_some_and(is_write_flags) {
            continue;
        }
        let Ok(m) = std::fs::metadata(e.path()) else { continue };
        if m.file_type().is_file() {
            out.push((t.into_owned(), m.blocks() * 512));
        }
    }
    out
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct VnodeFdInfoWithPath {
    pfi: ProcFileInfo,
    pvip: libc::vnode_info_path,
}

#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::size_of::<VnodeFdInfoWithPath>() == 1200);

#[cfg(target_os = "macos")]
pub fn writable_files(pid: u32) -> Vec<(String, u64)> {
    const PROC_PIDFDVNODEPATHINFO: i32 = 2;
    const FWRITE: u32 = 0x2;
    const VREG: i32 = 1;
    let mut out = vec![];
    let pid = pid as i32;
    // SAFETY: libproc calls with correctly sized, zero-initialized buffers.
    unsafe {
        let need = libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
        if need <= 0 {
            return out;
        }
        let sz = std::mem::size_of::<libc::proc_fdinfo>();
        let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(need as usize / sz + 32);
        let got = libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr() as *mut _,
            (fds.capacity() * sz) as i32,
        );
        if got <= 0 {
            return out;
        }
        fds.set_len(got as usize / sz);
        for fd in fds.iter().filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_VNODE as u32) {
            let mut vi: VnodeFdInfoWithPath = std::mem::zeroed();
            let vsz = std::mem::size_of::<VnodeFdInfoWithPath>() as i32;
            let r = libc::proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDVNODEPATHINFO,
                &mut vi as *mut _ as *mut _,
                vsz,
            );
            if r != vsz || vi.pfi.fi_openflags & FWRITE == 0 || vi.pvip.vip_vi.vi_type != VREG {
                continue;
            }
            let raw = std::slice::from_raw_parts(vi.pvip.vip_path.as_ptr() as *const u8, 1024);
            let len = raw.iter().position(|&b| b == 0).unwrap_or(1024);
            let Ok(p) = std::str::from_utf8(&raw[..len]) else {
                continue;
            };
            if p.starts_with('/') && !p.starts_with("/dev/") {
                out.push((p.to_string(), vi.pvip.vip_vi.vi_stat.vst_blocks as u64 * 512));
            }
        }
    }
    out
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn writable_files(_pid: u32) -> Vec<(String, u64)> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn fdinfo_flags() {
        let t = "pos:\t0\nflags:\t0100001\nmnt_id:\t25\nino:\t123\n";
        assert_eq!(parse_fdinfo_flags(t), Some(0o100001));
        assert!(is_write_flags(0o100001)); // O_WRONLY|O_LARGEFILE
        assert!(is_write_flags(0o2)); // O_RDWR
        assert!(is_write_flags(0o2102)); // O_RDWR|O_APPEND|O_CREAT
        assert!(!is_write_flags(0o100000)); // O_RDONLY|O_LARGEFILE
        assert!(!is_write_flags(0o2000000)); // O_CLOEXEC read-only
        assert_eq!(parse_fdinfo_flags("pos: 0\n"), None);
    }

    #[test]
    fn deltas_from_samples() {
        let mut of = OpenFiles::default();
        let w = (42u32, "dd".to_string(), 1000u64);
        of.ingest(1_000, vec![(w.clone(), vec![("/v/log".into(), 100)])], &[]);
        of.ingest(
            10_000,
            vec![(w.clone(), vec![("/v/log".into(), 400), ("/v/new".into(), 7)])],
            &["/v/own".into()],
        );
        of.ingest(
            20_000,
            vec![(w.clone(), vec![("/v/log".into(), 1000), ("/v/own/db".into(), 5)])],
            &["/v/own".into()],
        );
        let mut o = of.obs(5_000);
        o.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(o.len(), 2);
        assert_eq!(o[0].path, "/v/log");
        assert_eq!(
            o[0].delta,
            Some(900),
            "baseline is the newest sample <= from (100 @ 1s)"
        );
        assert_eq!(o[0].writers, vec![w.clone()]);
        assert_eq!(o[1].delta, None, "single sample: unknown");
        let o = of.obs(15_000);
        assert_eq!(o.iter().find(|x| x.path == "/v/log").unwrap().delta, Some(600));
    }

    #[test]
    fn sample_thinning_keeps_ends() {
        let mut s = vec![];
        for i in 0..40 {
            push_sample(&mut s, i * 1000, (i as u64) * 10);
        }
        assert!(s.len() <= 16);
        assert_eq!(s[0], (0, 0));
        assert_eq!(*s.last().unwrap(), (39_000, 390));
        let mut f = vec![];
        for i in 0..10 {
            push_sample(&mut f, i, 5);
        }
        assert_eq!(f, vec![(0, 5), (9, 5)]);
    }

    /// Our own process holding a file open for writing is enumerated with its size.
    #[test]
    fn enumerates_own_writable_file() {
        let d = std::env::temp_dir().join(format!("fat-gof-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("w.bin");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&vec![3u8; 128 * 1024]).unwrap();
        f.flush().unwrap();
        let ro = std::fs::File::open(&p).unwrap();
        let files = writable_files(std::process::id());
        let canon = std::fs::canonicalize(&p).unwrap().to_string_lossy().into_owned();
        let hits: Vec<_> = files
            .iter()
            .filter(|(fp, _)| *fp == canon || fp.ends_with("/w.bin"))
            .collect();
        assert_eq!(hits.len(), 1, "write fd listed once (read-only fd ignored): {files:?}");
        assert!(hits[0].1 >= 128 * 1024, "{hits:?}");
        drop((f, ro));
        let _ = std::fs::remove_dir_all(&d);
    }
}
