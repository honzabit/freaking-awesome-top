//! macOS FSEvents journal: retroactive replay + live tail, via CoreServices FFI (no crate).
//!
//! A [`Journal`] owns one FSEvents stream on its own thread with its own CFRunLoop. The
//! stream starts at an event id looked up with `FSEventsGetLastEventIdForDeviceBeforeTime`,
//! so the journal first replays history (until `kFSEventStreamEventFlagHistoryDone`) and
//! then keeps tailing live events. Events are aggregated per path (flags OR-ed, count,
//! first/last event id) into a bounded map; past the cap, new paths fold into their parent
//! directory. FSEvents hands out paths only, never file contents, so watching "/" does not
//! touch TCC-protected data; the caller decides which returned paths it may stat.
#![allow(non_upper_case_globals)]

use super::{F_CREATED, F_DIR, F_MODIFIED, F_REMOVED, F_RENAMED, PathEv};
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type CFRef = *const c_void;
type Callback = extern "C" fn(CFRef, *mut c_void, usize, *mut c_void, *const u32, *const u64);

#[repr(C)]
struct StreamContext {
    version: isize,
    info: *mut c_void,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: CFRef,
        callback: Callback,
        context: *const StreamContext,
        paths: CFRef,
        since_when: u64,
        latency: f64,
        flags: u32,
    ) -> CFRef;
    fn FSEventStreamScheduleWithRunLoop(stream: CFRef, run_loop: CFRef, mode: CFRef);
    fn FSEventStreamStart(stream: CFRef) -> u8;
    fn FSEventStreamStop(stream: CFRef);
    fn FSEventStreamInvalidate(stream: CFRef);
    fn FSEventStreamRelease(stream: CFRef);
    fn FSEventsGetLastEventIdForDeviceBeforeTime(dev: libc::dev_t, time: f64) -> u64;
    fn FSEventsGetCurrentEventId() -> u64;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFRunLoopDefaultMode: CFRef;
    static kCFTypeArrayCallBacks: c_void;
    fn CFRunLoopGetCurrent() -> CFRef;
    fn CFRunLoopRunInMode(mode: CFRef, seconds: f64, return_after_source_handled: u8) -> i32;
    fn CFStringCreateWithCString(alloc: CFRef, s: *const c_char, encoding: u32) -> CFRef;
    fn CFArrayCreate(alloc: CFRef, values: *const CFRef, num: isize, callbacks: *const c_void) -> CFRef;
    fn CFRelease(r: CFRef);
}

const UTF8: u32 = 0x0800_0100;
const CREATE_NO_DEFER: u32 = 0x02;
const CREATE_FILE_EVENTS: u32 = 0x10;

const EV_MUST_SCAN_SUBDIRS: u32 = 0x1;
const EV_USER_DROPPED: u32 = 0x2;
const EV_KERNEL_DROPPED: u32 = 0x4;
const EV_HISTORY_DONE: u32 = 0x10;
const EV_ITEM_CREATED: u32 = 0x100;
const EV_ITEM_REMOVED: u32 = 0x200;
const EV_ITEM_RENAMED: u32 = 0x800;
const EV_ITEM_MODIFIED: u32 = 0x1000;
const EV_ITEM_IS_DIR: u32 = 0x20000;
const EV_ITEM_CLONED: u32 = 0x40_0000;
/// Content-changing item flags (metadata-only events such as xattr/owner/finder info are ignored).
const EV_INTERESTING: u32 = EV_ITEM_CREATED | EV_ITEM_REMOVED | EV_ITEM_RENAMED | EV_ITEM_MODIFIED | EV_ITEM_CLONED;

/// CFAbsoluteTime epoch (2001-01-01) in unix seconds.
const CF_EPOCH: f64 = 978_307_200.0;

/// Last FSEvents id recorded on `dev` before unix time `unix_ms` (0 when unknown: on macOS 15
/// this only works for root, it reads the root-only .fseventsd store).
pub fn id_before(dev: u64, unix_ms: i64) -> u64 {
    // SAFETY: plain C call with value arguments.
    unsafe { FSEventsGetLastEventIdForDeviceBeforeTime(dev as libc::dev_t, unix_ms as f64 / 1000.0 - CF_EPOCH) }
}

pub fn current_id() -> u64 {
    // SAFETY: plain C call.
    unsafe { FSEventsGetCurrentEventId() }
}

/// Aggregated journal state, shared with the stream thread.
#[derive(Default)]
pub struct State {
    pub paths: HashMap<String, PathEv>,
    pub history_done: bool,
    /// Events were dropped or coalesced into "rescan this dir" (user/kernel drop, MustScanSubDirs).
    pub dropped: u64,
    pub events: u64,
    pub error: Option<String>,
    /// Highest event id seen.
    pub last_id: u64,
}

struct Ctx {
    state: Arc<Mutex<State>>,
    cap: usize,
    exclude: Vec<String>,
}

pub struct Journal {
    pub state: Arc<Mutex<State>>,
    /// Event id the stream started from (history before this is not in `state`).
    pub since_id: u64,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Journal {
    /// Start a stream on `roots` from `since_id` (0 = only live events). `cap` bounds the
    /// number of distinct paths kept; `exclude` are path prefixes to ignore (fat's own files).
    pub fn start(roots: Vec<String>, since_id: u64, cap: usize, exclude: Vec<String>) -> Journal {
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (st, sp) = (state.clone(), stop.clone());
        let thread = std::thread::Builder::new()
            .name("fat-fsevents".into())
            .spawn(move || run(roots, since_id, st, sp, cap, exclude))
            .ok();
        if thread.is_none() {
            state.lock().unwrap().error = Some("could not spawn FSEvents thread".into());
        }
        Journal {
            state,
            since_id,
            stop,
            thread,
        }
    }

    /// Block until history replay finished (or `timeout`). True when done.
    pub fn wait_history(&self, timeout: Duration) -> bool {
        let t0 = Instant::now();
        loop {
            {
                let s = self.state.lock().unwrap();
                if s.history_done || s.error.is_some() {
                    return s.history_done;
                }
            }
            if t0.elapsed() >= timeout || self.thread.as_ref().is_none_or(|t| t.is_finished()) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn run(
    roots: Vec<String>,
    since_id: u64,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    cap: usize,
    exclude: Vec<String>,
) {
    let ctx = Box::into_raw(Box::new(Ctx {
        state: state.clone(),
        cap,
        exclude,
    }));
    let c_roots: Vec<CString> = roots.iter().filter_map(|r| CString::new(r.as_str()).ok()).collect();
    // SAFETY: CoreFoundation objects are created, used and released on this thread only;
    // `ctx` outlives the stream (freed after FSEventStreamRelease).
    unsafe {
        let cf_strs: Vec<CFRef> = c_roots
            .iter()
            .map(|c| CFStringCreateWithCString(std::ptr::null(), c.as_ptr(), UTF8))
            .collect();
        let arr = CFArrayCreate(
            std::ptr::null(),
            cf_strs.as_ptr(),
            cf_strs.len() as isize,
            &kCFTypeArrayCallBacks,
        );
        for s in &cf_strs {
            CFRelease(*s);
        }
        let sctx = StreamContext {
            version: 0,
            info: ctx as *mut c_void,
            retain: std::ptr::null(),
            release: std::ptr::null(),
            copy_description: std::ptr::null(),
        };
        // since_id 0 would mean "replay everything"; use "now" (u64::MAX) for live-only.
        let since = if since_id == 0 { u64::MAX } else { since_id };
        let stream = FSEventStreamCreate(
            std::ptr::null(),
            callback,
            &sctx,
            arr,
            since,
            0.05,
            CREATE_FILE_EVENTS | CREATE_NO_DEFER,
        );
        CFRelease(arr);
        if stream.is_null() {
            state.lock().unwrap().error = Some("FSEventStreamCreate failed".into());
            drop(Box::from_raw(ctx));
            return;
        }
        if since == u64::MAX {
            state.lock().unwrap().history_done = true;
        }
        FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        if FSEventStreamStart(stream) == 0 {
            state.lock().unwrap().error = Some("FSEventStreamStart failed".into());
        } else {
            while !stop.load(Ordering::SeqCst) {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.2, 0);
            }
            FSEventStreamStop(stream);
        }
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        drop(Box::from_raw(ctx));
    }
}

extern "C" fn callback(_s: CFRef, info: *mut c_void, n: usize, paths: *mut c_void, flags: *const u32, ids: *const u64) {
    if info.is_null() || paths.is_null() {
        return;
    }
    // SAFETY: FSEvents passes `n` C strings / flags / ids (no UseCFTypes flag), `info` is our Ctx.
    let (ctx, paths, flags, ids) = unsafe {
        (
            &*(info as *const Ctx),
            std::slice::from_raw_parts(paths as *const *const c_char, n),
            std::slice::from_raw_parts(flags, n),
            std::slice::from_raw_parts(ids, n),
        )
    };
    let Ok(mut st) = ctx.state.lock() else { return };
    for i in 0..n {
        let (f, id) = (flags[i], ids[i]);
        st.events += 1;
        st.last_id = st.last_id.max(id);
        if f & EV_HISTORY_DONE != 0 {
            st.history_done = true;
            continue;
        }
        if f & (EV_USER_DROPPED | EV_KERNEL_DROPPED | EV_MUST_SCAN_SUBDIRS) != 0 {
            st.dropped += 1;
        }
        if f & EV_INTERESTING == 0 || paths[i].is_null() {
            continue;
        }
        // SAFETY: non-null NUL-terminated string from FSEvents.
        let Ok(p) = (unsafe { CStr::from_ptr(paths[i]) }).to_str() else {
            continue;
        };
        if ctx.exclude.iter().any(|e| super::under_prefix(p, e)) {
            continue;
        }
        let mut nf = 0u32;
        if f & (EV_ITEM_CREATED | EV_ITEM_CLONED) != 0 {
            nf |= F_CREATED;
        }
        if f & EV_ITEM_REMOVED != 0 {
            nf |= F_REMOVED;
        }
        if f & EV_ITEM_MODIFIED != 0 {
            nf |= F_MODIFIED;
        }
        if f & EV_ITEM_RENAMED != 0 {
            nf |= F_RENAMED;
        }
        if f & EV_ITEM_IS_DIR != 0 {
            nf |= F_DIR;
        }
        super::record_event(&mut st.paths, ctx.cap, p, nf, id as i64, 0);
    }
}

/// Maps wall-clock time to FSEvents ids. `FSEventsGetLastEventIdForDeviceBeforeTime` needs
/// root (it returns 0 for normal users on macOS 15), so fat records its own (time, current id)
/// anchors, persisted in its data dir, and interpolates between them.
pub struct IdClock {
    /// (unix ms, event id), ascending.
    pub anchors: Vec<(i64, u64)>,
    file: Option<std::path::PathBuf>,
    last_persist: i64,
}

const CLOCK_KEEP_MS: i64 = 48 * 3600 * 1000;

impl IdClock {
    pub fn load(file: Option<std::path::PathBuf>) -> IdClock {
        let mut anchors = vec![];
        if let Some(f) = &file
            && let Ok(text) = std::fs::read_to_string(f)
        {
            for l in text.lines() {
                let mut it = l.split_whitespace();
                if let (Some(Ok(t)), Some(Ok(id))) =
                    (it.next().map(str::parse::<i64>), it.next().map(str::parse::<u64>))
                {
                    anchors.push((t, id));
                }
            }
        }
        let mut c = IdClock {
            anchors: vec![],
            file,
            last_persist: 0,
        };
        for (t, id) in anchors {
            c.push(t, id);
        }
        c
    }

    /// Add an anchor, keeping time and id both monotonic (an id going backwards means the
    /// journal was reset: older anchors are dropped).
    pub fn push(&mut self, t: i64, id: u64) {
        if id == 0 {
            return;
        }
        if let Some(&(lt, lid)) = self.anchors.last() {
            if t < lt {
                return;
            }
            if id < lid {
                self.anchors.clear();
            } else if t - lt < 5_000 && self.anchors.len() >= 2 {
                // Too close to the previous one: just slide it.
                let n = self.anchors.len();
                self.anchors[n - 1] = (t, id);
                return;
            }
        }
        self.anchors.push((t, id));
        let cut = t - CLOCK_KEEP_MS;
        if self.anchors.len() > 1 && self.anchors[0].0 < cut {
            self.anchors.retain(|a| a.0 >= cut);
        }
        if self.anchors.len() > 6000 {
            // Thin the older half.
            let half = self.anchors.len() / 2;
            let mut v: Vec<(i64, u64)> = self.anchors[..half].iter().step_by(2).copied().collect();
            v.extend_from_slice(&self.anchors[half..]);
            self.anchors = v;
        }
    }

    /// Insert an anchor fitted from file ctimes (may lie in the past). Ignored when it
    /// contradicts the measured anchors (time and id must both stay monotonic).
    pub fn insert_fitted(&mut self, t: i64, id: u64) {
        if id == 0 {
            return;
        }
        let i = self.anchors.partition_point(|x| x.0 < t);
        let ok_lo = i == 0 || self.anchors[i - 1].1 <= id;
        let ok_hi = i >= self.anchors.len() || self.anchors[i].1 >= id;
        if ok_lo && ok_hi && !self.anchors.iter().any(|x| x.0 == t) {
            self.anchors.insert(i, (t, id));
        }
    }

    /// Record "now" and persist (at most once a minute).
    pub fn anchor_now(&mut self) {
        let now = crate::model::now_ms();
        self.push(now, current_id());
        if now - self.last_persist >= 60_000
            && let Some(f) = &self.file
        {
            self.last_persist = now;
            if let Some(d) = f.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let body: String = self.anchors.iter().map(|(t, id)| format!("{t} {id}\n")).collect();
            let tmp = f.with_extension("tmp");
            if std::fs::write(&tmp, body).is_ok() {
                let _ = std::fs::rename(&tmp, f);
            }
        }
    }

    /// Event id at time `t`, when `t` lies within the anchored span.
    pub fn id_at(&self, t: i64) -> Option<u64> {
        let a = &self.anchors;
        if a.len() < 2 || t < a[0].0 || t > a[a.len() - 1].0 {
            return None;
        }
        let i = a.partition_point(|x| x.0 <= t);
        if i == 0 {
            return Some(a[0].1);
        }
        if i >= a.len() {
            return Some(a[a.len() - 1].1);
        }
        let (t0, i0) = a[i - 1];
        let (t1, i1) = a[i];
        // Anchors more than 10 min apart: the rate in between is unknown, stay conservative.
        if t1 - t0 > 600_000 {
            return Some(i0);
        }
        let f = (t - t0) as f64 / (t1 - t0).max(1) as f64;
        Some(i0 + ((i1 - i0) as f64 * f) as u64)
    }

    /// Recent id rate (ids per ms) from anchors spanning at least a minute.
    pub fn rate(&self) -> Option<f64> {
        let a = &self.anchors;
        let last = *a.last()?;
        let first = a.iter().find(|x| last.0 - x.0 <= 3_600_000)?;
        (last.0 - first.0 >= 60_000).then(|| (last.1 - first.1) as f64 / (last.0 - first.0) as f64)
    }
}

/// Fit the event id at which time `t` falls, from (event id, ctime ms) pairs of paths whose
/// last event is that id. Picks the split minimizing misclassified pairs. Returns the last id
/// before `t`, or None when every pair is at/after `t` (history did not reach back far enough).
pub fn fit_boundary(pairs: &mut [(u64, i64)], t: i64) -> Option<u64> {
    if pairs.is_empty() {
        return None;
    }
    pairs.sort_unstable();
    let n = pairs.len();
    // err(k) = #after-t among [0,k) + #before-t among [k,n)
    let mut err: i64 = pairs.iter().filter(|p| p.1 < t).count() as i64;
    let (mut best, mut best_k) = (err, 0usize);
    for k in 1..=n {
        if pairs[k - 1].1 >= t {
            err += 1
        } else {
            err -= 1
        }
        if err < best {
            best = err;
            best_k = k;
        }
    }
    if best_k == 0 { None } else { Some(pairs[best_k - 1].0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Live end-to-end, as the normal user: note the current event id, write a file in a temp
    /// dir, wait, then replay the journal from that id and check the file shows up as created.
    /// (FSEventsGetLastEventIdForDeviceBeforeTime returns 0 for non-root users on macOS 15, so
    /// the time->id lookup is fat's own clock; replay from an explicit id works unprivileged.)
    #[test]
    fn replay_sees_recent_write() {
        let dev = std::fs::metadata("/")
            .map(|m| std::os::unix::fs::MetadataExt::dev(&m))
            .unwrap();
        eprintln!(
            "FSEventsGetLastEventIdForDeviceBeforeTime(now-60s) = {}",
            id_before(dev, crate::model::now_ms() - 60_000)
        );
        let since = current_id();
        assert!(since > 0);
        let dir = std::env::temp_dir().join(format!("fat-fsev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let f = dir.join("grow.bin");
        let mut fh = std::fs::File::create(&f).unwrap();
        fh.write_all(&vec![7u8; 256 * 1024]).unwrap();
        fh.sync_all().unwrap();
        drop(fh);
        // Let fseventsd persist the batch, so this really is a replay.
        std::thread::sleep(Duration::from_millis(1500));
        let j = Journal::start(vec![dir.to_string_lossy().into_owned()], since, 10_000, vec![]);
        assert!(j.wait_history(Duration::from_secs(10)), "history replay did not finish");
        let st = j.state.lock().unwrap();
        let key = f.to_string_lossy().into_owned();
        let ev = st
            .paths
            .get(&key)
            .unwrap_or_else(|| panic!("{key} not in replay: {:?}", st.paths.keys().collect::<Vec<_>>()));
        assert!(ev.flags & F_CREATED != 0);
        drop(st);
        drop(j);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clock_interpolates_and_resets() {
        let mut c = IdClock::load(None);
        c.push(1_000_000, 100);
        c.push(1_060_000, 700);
        c.push(1_120_000, 1300);
        assert_eq!(c.id_at(1_030_000), Some(400));
        assert_eq!(c.id_at(999_999), None);
        assert_eq!(c.id_at(1_200_000), None);
        assert!((c.rate().unwrap() - 0.01).abs() < 1e-9);
        c.insert_fitted(990_000, 99);
        assert_eq!(c.anchors[0], (990_000, 99));
        c.insert_fitted(1_010_000, 5000); // contradicts (id beyond the next anchor): ignored
        assert_eq!(c.anchors.len(), 4);
        c.push(1_180_000, 50); // journal reset
        assert_eq!(c.anchors, vec![(1_180_000, 50)]);
    }

    #[test]
    fn clock_persists() {
        let f = std::env::temp_dir().join(format!("fat-gclock-{}.tsv", std::process::id()));
        let _ = std::fs::remove_file(&f);
        let mut c = IdClock::load(Some(f.clone()));
        c.anchor_now();
        let c2 = IdClock::load(Some(f.clone()));
        assert_eq!(c2.anchors.len(), 1);
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn boundary_fit() {
        // ids 1..=10 at times 10..=100; t=55 -> last id before is 5.
        let mut p: Vec<(u64, i64)> = (1..=10).map(|i| (i, i as i64 * 10)).collect();
        assert_eq!(fit_boundary(&mut p, 55), Some(5));
        // One noisy pair (id 8 with an old ctime) does not move the split.
        p[7].1 = 1;
        assert_eq!(fit_boundary(&mut p, 55), Some(5));
        // Everything after t: history too short.
        assert_eq!(fit_boundary(&mut p, 0), None);
        // Everything before t.
        assert_eq!(fit_boundary(&mut p, 1000), Some(10));
    }

    /// Manual measurement: replay the whole machine's last 10 minutes.
    /// `cargo test --release fsevents::tests::replay_root_10min -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn replay_root_10min() {
        let t0 = Instant::now();
        // ~10 min at the default rate assumption (2 ids/ms).
        let since = current_id() - 1_200_000;
        let j = Journal::start(vec!["/".into()], since, 200_000, vec![]);
        let done = j.wait_history(Duration::from_secs(30));
        let st = j.state.lock().unwrap();
        eprintln!(
            "since={since} cur={} done={done} events={} paths={} dropped={} in {:?}",
            current_id(),
            st.events,
            st.paths.len(),
            st.dropped,
            t0.elapsed()
        );
        let mut by_top: HashMap<String, u64> = HashMap::new();
        for (p, e) in &st.paths {
            let top: String = p.split('/').take(4).collect::<Vec<_>>().join("/");
            *by_top.entry(top).or_default() += e.count as u64;
        }
        let mut v: Vec<_> = by_top.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        for (p, c) in v.iter().take(25) {
            eprintln!("{c:8} {p}");
        }
    }
}
