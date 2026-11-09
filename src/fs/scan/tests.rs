//! Scanner tests on temp-dir fixtures (never the real "/").
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;

static N: AtomicUsize = AtomicUsize::new(0);

struct Fx {
    root: PathBuf,
}

impl Fx {
    fn new(tag: &str) -> Fx {
        let root = std::env::temp_dir()
            .join("fat-scan-tests")
            .join(format!("{tag}-{}-{}", std::process::id(), N.fetch_add(1, AO::SeqCst)));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // Canonical (macOS temp dir is behind the /var -> /private/var symlink).
        let root = std::fs::canonicalize(&root).unwrap();
        Fx { root }
    }
    fn p(&self, rel: &str) -> PathBuf {
        if rel.is_empty() { self.root.clone() } else { self.root.join(rel) }
    }
    fn s(&self, rel: &str) -> String {
        self.p(rel).to_string_lossy().into_owned()
    }
    fn file(&self, rel: &str, len: usize) {
        let p = self.p(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        // Non-zero bytes so no filesystem stores it sparse.
        std::fs::write(&p, vec![0x5au8; len]).unwrap();
    }
    fn dir(&self, rel: &str) {
        std::fs::create_dir_all(self.p(rel)).unwrap();
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        fn unlock(p: &Path) {
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    if e.file_type().is_ok_and(|t| t.is_dir()) {
                        unlock(&e.path());
                    }
                }
            }
        }
        // Restore permissions of any chmod 000 dirs, then delete.
        let _ = std::process::Command::new("chmod").args(["-R", "u+rwx"]).arg(&self.root).status();
        unlock(&self.root);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Independent du: allocated bytes, apparent bytes, files; hardlinks once; no symlink follow;
/// counts directory inodes like the scanner does.
fn du(p: &Path, seen: &mut HashSet<(u64, u64)>) -> (u64, u64, u64) {
    let md = std::fs::symlink_metadata(p).unwrap();
    let mut out = (md.blocks() * 512, md.size(), 0);
    for e in std::fs::read_dir(p).unwrap().flatten() {
        let m = std::fs::symlink_metadata(e.path()).unwrap();
        if m.is_dir() {
            let s = du(&e.path(), seen);
            out = (out.0 + s.0, out.1 + s.1, out.2 + s.2);
        } else {
            if m.nlink() > 1 && m.is_file() && !seen.insert((m.dev(), m.ino())) {
                continue;
            }
            out = (out.0 + m.blocks() * 512, out.1 + m.size(), out.2 + 1);
        }
    }
    out
}

fn opts() -> Options {
    Options {
        cache_path: None,
        threads: 2,
        budget: 0.0,
        focus_budget: 0.0,
        keep_depth: u16::MAX,
        protect: false,
        battery_check: false,
        background: false,
        ..Options::default()
    }
}

fn child<'a>(l: &'a Listing, name: &str) -> &'a DirEntry {
    l.children.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("no child {name} in {:?}", l.children))
}

/// Run queued jobs on this thread, one at a time (deterministic; no worker threads).
fn step(sc: &Scanner) -> Option<Vec<u8>> {
    let sh = sc.sh();
    let job = lock(&sh.st).pop(false)?;
    let res = sys::read_dir(&job.path, sh.opts.big_file, if job.expand { EXPAND_FILES } else { 0 }, &job.policy, &sh.links);
    lock(&sh.st).apply(&job, res, &sh.opts);
    Some(job.path)
}

fn queue_root(sc: &Scanner, path: &str) {
    let p = norm(path);
    let mut st = lock(&sc.sh().st);
    st.add_root(&p, false, 0);
    let id = st.tree.find_or_create(&p);
    assert!(st.prepare_root(id, &p));
    st.requeue(id, true, true);
}

#[test]
fn sizes_add_up() {
    let fx = Fx::new("sizes");
    fx.file("a.bin", 100_000);
    fx.file("d1/x", 5_000);
    fx.file("d1/y", 70_000);
    fx.file("d1/d2/z", 300_000);
    fx.file("d1/d2/d3/w", 1);
    fx.dir("empty");
    let sc = Scanner::with_options(opts());
    let l = sc.scan_blocking(&fx.s(""), 30_000).unwrap();
    let want = du(&fx.root, &mut HashSet::new());
    assert!(!l.dir.partial);
    assert_eq!((l.dir.size, l.dir.apparent, l.dir.files), want);
    let d1 = child(&l, "d1");
    assert_eq!((d1.size, d1.apparent, d1.files), du(&fx.p("d1"), &mut HashSet::new()));
    assert_eq!(child(&l, "empty").files, 0);
    // Children (+ the dir inode and loose files) sum to the parent.
    let sum: u64 = l.children.iter().filter(|c| c.is_dir).map(|c| c.size).sum();
    let own = std::fs::symlink_metadata(&fx.root).unwrap().blocks() * 512
        + std::fs::symlink_metadata(fx.p("a.bin")).unwrap().blocks() * 512;
    assert_eq!(sum + own, l.dir.size);
    // Listed root lets the user see the loose file too (expand keeps top files).
    assert!(l.children.iter().any(|c| c.name == "a.bin" && !c.is_dir));
    // sizes() for the recorder.
    let sz = sc.sizes(&fx.s(""), 1);
    assert!(sz.iter().any(|(p, s)| *p == fx.s("d1") && *s == d1.size));
    assert!(!sz.iter().any(|(p, _)| *p == fx.s("d1/d2")));
    assert_eq!(sc.progress().iter().find(|p| p.root == fx.s("")).unwrap().files_seen, want.2);
}

#[test]
fn hardlinks_counted_once() {
    let fx = Fx::new("hard");
    fx.file("a/big", 400_000);
    fx.dir("b");
    std::fs::hard_link(fx.p("a/big"), fx.p("b/big-link")).unwrap();
    std::fs::hard_link(fx.p("a/big"), fx.p("a/big-link2")).unwrap();
    let sc = Scanner::with_options(opts());
    let l = sc.scan_blocking(&fx.s(""), 30_000).unwrap();
    let blocks = std::fs::metadata(fx.p("a/big")).unwrap().blocks() * 512;
    let dirs: u64 = ["", "a", "b"].iter().map(|r| std::fs::symlink_metadata(fx.p(r)).unwrap().blocks() * 512).sum();
    assert_eq!(l.dir.size, blocks + dirs);
    assert_eq!(l.dir.files, 1);
}

#[test]
fn symlinks_not_followed() {
    let fx = Fx::new("sym");
    let other = Fx::new("sym-target");
    other.file("huge", 2_000_000);
    fx.file("real/f", 10_000);
    std::os::unix::fs::symlink(&other.root, fx.p("link-out")).unwrap();
    std::os::unix::fs::symlink(fx.p("real"), fx.p("link-in")).unwrap();
    let sc = Scanner::with_options(opts());
    let l = sc.scan_blocking(&fx.s(""), 30_000).unwrap();
    assert_eq!((l.dir.size, l.dir.apparent, l.dir.files), du(&fx.root, &mut HashSet::new()));
    assert!(l.dir.size < 1_000_000, "followed a symlink: {}", l.dir.size);
    assert_eq!(l.dir.files, 3); // f + two symlinks
    assert!(l.children.iter().filter(|c| c.is_dir).all(|c| c.name == "real"));
}

#[test]
fn mount_boundary_respected() {
    let fx = Fx::new("mnt");
    fx.file("local/a", 50_000);
    fx.file("mnt/inside", 900_000);
    fx.file("mnt/deeper/x", 900_000);
    let mnt = fx.p("mnt").to_string_lossy().into_owned().into_bytes();
    let hook: DevHook = Arc::new(move |p: &[u8]| (p == mnt.as_slice()).then_some(0xdead_beef));
    let sc = Scanner::with_options(Options { dev_hook: Some(hook), ..opts() });
    let l = sc.scan_blocking(&fx.s(""), 30_000).unwrap();
    let m = child(&l, "mnt");
    assert!(m.mount_point);
    assert_eq!((m.size, m.files), (0, 0));
    assert!(l.dir.size < 500_000, "descended into the mount: {}", l.dir.size);
    assert_eq!(l.dir.files, 1);
    // Not descended: nothing below it is known.
    assert!(sc.list(&fx.s("mnt/deeper")).is_none());
}

#[test]
fn denied_dirs_counted() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping denied_dirs_counted as root");
        return;
    }
    let fx = Fx::new("denied");
    fx.file("ok/a", 10_000);
    fx.file("locked/secret", 500_000);
    fx.file("deep/locked2/s", 1);
    std::fs::set_permissions(fx.p("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::set_permissions(fx.p("deep/locked2"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let sc = Scanner::with_options(opts());
    let l = sc.scan_blocking(&fx.s(""), 30_000).unwrap();
    std::fs::set_permissions(fx.p("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(fx.p("deep/locked2"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(l.dir.denied, 2);
    assert_eq!(child(&l, "locked").denied, 1);
    assert_eq!(child(&l, "deep").denied, 1);
    assert_eq!(child(&l, "ok").denied, 0);
    assert!(l.dir.size < 400_000);
    assert!(!l.dir.partial);
}

#[test]
fn protected_skipped_until_explicit() {
    let fx = Fx::new("tcc");
    fx.file("pub/a", 10_000);
    fx.file("Private/secret", 600_000);
    let sc = Scanner::with_options(Options { extra_protected: vec![fx.s("Private")], ..opts() });
    let l = sc.scan_blocking(&fx.s(""), 30_000).unwrap();
    let pr = child(&l, "Private");
    assert_eq!((pr.size, pr.denied), (0, 1));
    assert!(sc.protected_hint(&fx.s("Private")).is_some());
    let before = l.dir.size;
    // The user drills in: explicit -> read.
    let pl = sc.scan_blocking(&fx.s("Private"), 30_000).unwrap();
    assert!(pl.dir.size >= 600_000 && pl.dir.denied == 0);
    let l2 = sc.list(&fx.s("")).unwrap();
    assert_eq!(l2.dir.denied, 0);
    assert_eq!(l2.dir.size, before + pl.dir.size);
    assert!(sc.protected_hint(&fx.s("Private")).is_none());
}

#[test]
fn progressive_partial_flags() {
    let fx = Fx::new("prog");
    for d in ["a", "b", "c"] {
        fx.file(&format!("{d}/f"), 20_000);
        fx.file(&format!("{d}/sub/g"), 20_000);
    }
    let sc = Scanner::with_options(opts());
    let root = fx.s("");
    queue_root(&sc, &root);
    assert!(sc.list(&root).is_none(), "nothing known before the first read");
    step(&sc).unwrap(); // root itself
    let l = sc.list(&root).unwrap();
    assert!(l.dir.partial && l.children.len() == 3 && l.children.iter().all(|c| c.partial));
    let mut last = l.dir.size;
    let mut steps = 1;
    while step(&sc).is_some() {
        steps += 1;
        let l = sc.list(&root).unwrap();
        assert!(l.dir.size >= last, "lower bound must not shrink");
        last = l.dir.size;
        for c in l.children.iter().filter(|c| !c.partial) {
            // A finished child is no longer partial even while the root still is.
            let sub = sc.list(&c.path).unwrap();
            assert!(!sub.dir.partial && sub.children.iter().all(|g| !g.partial));
        }
    }
    assert_eq!(steps, 7);
    let l = sc.list(&root).unwrap();
    assert!(!l.dir.partial && l.children.iter().all(|c| !c.partial));
    assert_eq!((l.dir.size, l.dir.files), { let d = du(&fx.root, &mut HashSet::new()); (d.0, d.2) });

    // A refresh keeps showing the previous numbers (flagged partial) instead of dropping to 0.
    {
        let mut st = lock(&sc.sh().st);
        let id = st.tree.find(&norm(&root)).unwrap();
        st.requeue(id, true, false);
    }
    let l2 = sc.list(&root).unwrap();
    assert!(l2.dir.partial && l2.dir.size == l.dir.size);
    while step(&sc).is_some() {}
    let l3 = sc.list(&root).unwrap();
    assert!(!l3.dir.partial);
    assert_eq!((l3.dir.size, l3.dir.apparent, l3.dir.files), (l.dir.size, l.dir.apparent, l.dir.files));
    assert!(l3.dir.scanned_at >= l.dir.scanned_at);
}

#[test]
fn focus_jumps_ahead() {
    let fx = Fx::new("focus");
    for d in ["a", "b", "c", "d", "e"] {
        fx.file(&format!("{d}/x/f"), 1000);
    }
    let sc = Scanner::with_options(opts());
    let root = fx.s("");
    queue_root(&sc, &root);
    step(&sc).unwrap();
    {
        let mut st = lock(&sc.sh().st);
        st.focus = Some(norm(&fx.s("d")));
        st.rebuild_queue();
    }
    assert_eq!(step(&sc).unwrap(), norm(&fx.s("d")));
    // ...and its subtree keeps priority over the remaining siblings.
    assert_eq!(step(&sc).unwrap(), norm(&fx.s("d/x")));
    let next = step(&sc).unwrap();
    assert!(!under(&next, &norm(&fx.s("d"))));
}

#[test]
fn cache_round_trip() {
    let fx = Fx::new("cache");
    fx.file("a/f", 30_000);
    fx.file("a/b/g", 40_000);
    fx.file("c/h", 50_000);
    let db = fx.p(".index/fs-index.db");
    let o = Options { cache_path: Some(db.clone()), ..opts() };
    let root = fx.s("");
    let first = Scanner::with_options(o).scan_blocking(&root, 30_000).unwrap();
    // The index dir itself is inside the fixture; compare everything else.
    let sc2 = Scanner::with_options(Options { cache_path: Some(db.clone()), ..opts() });
    let l2 = sc2.list(&root).expect("loaded from cache");
    assert_eq!(l2.dir.size, first.dir.size);
    assert_eq!(l2.dir.files, first.dir.files);
    assert!(!l2.dir.partial);
    assert_eq!(child(&l2, "a").size, child(&first, "a").size);
    assert_eq!(
        sc2.list(&fx.s("a")).unwrap().children.iter().map(|c| c.name.clone()).collect::<Vec<_>>(),
        vec!["b".to_string()]
    );
    // Deleting a dir and rescanning drops its row too.
    std::fs::remove_dir_all(fx.p("c")).unwrap();
    sc2.scan_blocking(&root, 30_000).unwrap();
    drop(sc2);
    let sc3 = Scanner::with_options(Options { cache_path: Some(db), ..opts() });
    assert!(sc3.list(&fx.s("c")).is_none());
    assert!(sc3.list(&fx.s("a/b")).is_some());
}

/// An interrupted first scan resumes in the next process: finished subtrees come from the
/// cache (not re-read) and the parent's lower bound is never below its children.
#[test]
fn interrupted_scan_resumes_from_cache() {
    let fx = Fx::new("resume");
    fx.file("a/x/f", 30_000);
    fx.file("b/y/g", 40_000);
    fx.file("c/h", 50_000);
    let db = fx.p(".index/fs-index.db");
    let root = fx.s("");
    let total = {
        let sc = Scanner::with_options(Options { cache_path: Some(db.clone()), ..opts() });
        queue_root(&sc, &root);
        // Read the root and all of a/ (depth-first), then "quit".
        while let Some(p) = step(&sc) {
            if p == norm(&fx.s("a/x")) {
                break;
            }
        }
        assert!(!sc.list(&fx.s("a")).unwrap().dir.partial, "a/ finished");
        assert!(sc.list(&root).unwrap().dir.partial);
        flush(sc.sh());
        drop(sc);
        du(&fx.root, &mut HashSet::new()).0
    };
    let sc = Scanner::with_options(Options { cache_path: Some(db), ..opts() });
    let a = sc.list(&fx.s("a")).expect("a/ loaded from cache");
    assert!(!a.dir.partial);
    sc.ensure(&root, true);
    // The root's lower bound includes a/ from the cache even before anything is re-read.
    let l = sc.list(&root).unwrap();
    assert!(l.dir.partial && l.dir.size >= a.dir.size, "{} < {}", l.dir.size, a.dir.size);
    let fin = sc.scan_blocking(&root, 30_000).unwrap();
    assert!(!fin.dir.partial);
    assert!(!child(&fin, "a").partial);
    // Everything but the index dir, which the first run created mid-way.
    let idx = fin.children.iter().find(|c| c.name == ".index").map_or(0, |c| c.size);
    assert!(fin.dir.size >= total - idx.min(total), "{} vs du {total}", fin.dir.size);
    assert_eq!(child(&fin, "a").size, a.dir.size);
}

#[test]
fn folding_keeps_totals_and_expands_on_focus() {
    let fx = Fx::new("fold");
    for i in 0..20 {
        fx.file(&format!("many/d{i}/f"), 3_000);
    }
    fx.file("big/blob", 300_000);
    let o = Options { keep_depth: 0, fold_bytes: 200_000, big_file: 250_000, ..opts() };
    let sc = Scanner::with_options(o);
    let root = fx.s("");
    let l = sc.scan_blocking(&root, 30_000).unwrap();
    assert_eq!((l.dir.size, l.dir.files), { let d = du(&fx.root, &mut HashSet::new()); (d.0, d.2) });
    // "many" is small: its children were folded into it, but it is kept (child of the root).
    let many = sc.list(&fx.s("many")).unwrap();
    assert!(many.children.is_empty());
    assert_eq!(many.dir.files, 20);
    let before = sc.index_nodes();
    // Focusing it re-expands (without changing totals).
    {
        let mut st = lock(&sc.sh().st);
        st.focus = Some(norm(&fx.s("many")));
        let id = st.tree.find(&norm(&fx.s("many"))).unwrap();
        st.requeue(id, false, true);
    }
    while step(&sc).is_some() {}
    let many2 = sc.list(&fx.s("many")).unwrap();
    assert_eq!(many2.children.len(), 20);
    assert_eq!((many2.dir.size, many2.dir.files), (many.dir.size, many.dir.files));
    assert_eq!(sc.list(&root).unwrap().dir.size, l.dir.size);
    assert!(sc.index_nodes() > before);
    // largest(): the blob, not "big" (explained by it) nor the root.
    let top = sc.largest(&root, 3);
    assert_eq!(top[0].name, "blob");
    assert!(!top.iter().any(|e| e.name == "big"));
}

#[test]
fn materialize_folded_path() {
    let fx = Fx::new("mat");
    fx.file("p/q/r/f", 5_000);
    fx.file("p/other", 5_000);
    let o = Options { keep_depth: 0, fold_bytes: 1 << 30, ..opts() };
    let sc = Scanner::with_options(o);
    let root = fx.s("");
    let total = sc.scan_blocking(&root, 30_000).unwrap().dir.size;
    // Root keeps "p" (EXPAND), but p's subtree was folded.
    assert!(sc.list(&fx.s("p/q")).is_none());
    // Drill to a folded path: materialized without double counting.
    let l = sc.scan_blocking(&fx.s("p/q/r"), 30_000).unwrap();
    assert!(l.dir.files == 1);
    assert_eq!(sc.list(&root).unwrap().dir.size, total);
    assert_eq!(sc.list(&fx.s("p")).unwrap().dir.size, du(&fx.p("p"), &mut HashSet::new()).0);
}

#[test]
fn background_workers_and_restat() {
    let fx = Fx::new("bg");
    fx.file("a/f", 10_000);
    let sc = Scanner::with_options(Options {
        threads: 2,
        background: true,
        budget: 0.0,
        restat_interval: Duration::from_millis(1),
        ..opts()
    });
    let root = fx.s("");
    sc.ensure(&root, false);
    let t0 = Instant::now();
    while sc.progress().first().is_none_or(|p| p.completed_at == 0) {
        assert!(t0.elapsed() < Duration::from_secs(20), "background scan did not complete");
        thread::sleep(Duration::from_millis(20));
    }
    let s1 = sc.list(&root).unwrap().dir.size;
    // A new file in a kept dir is picked up by the quick re-stat (dir mtime changed).
    fx.file("a/new", 200_000);
    let t0 = Instant::now();
    loop {
        let l = sc.list(&fx.s("a")).unwrap();
        if !l.dir.partial && sc.list(&root).unwrap().dir.size > s1 + 150_000 {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "restat did not pick up the new file");
        thread::sleep(Duration::from_millis(50));
    }
    drop(sc); // threads exit
}

#[test]
fn single_background_writer_others_reload() {
    let fx = Fx::new("writer");
    fx.file("d/a", 10_000);
    let db = Fx::new("writer-db");
    let o = Options {
        cache_path: Some(db.p("fs-index.db")),
        background: true,
        flush_interval: Duration::from_millis(50),
        reload_interval: Duration::from_millis(50),
        ..opts()
    };
    let root = fx.s("");
    let wait = |what: &str, f: &dyn Fn() -> bool| {
        let t0 = Instant::now();
        while !f() {
            assert!(t0.elapsed() < Duration::from_secs(20), "timeout: {what}");
            thread::sleep(Duration::from_millis(20));
        }
    };
    let a = Scanner::with_options(o.clone());
    a.ensure(&root, false);
    wait("a scans", &|| a.progress().first().is_some_and(|p| p.completed_at > 0));
    wait("a is writer", &|| lock(&a.sh().st).writer);
    let b = Scanner::with_options(o);
    let s0 = b.list(&root).expect("b loads a's cache").dir.size;
    b.ensure(&root, false);
    fx.file("d/b", 400_000);
    a.rescan(&root);
    wait("b sees a's rescan", &|| b.list(&root).is_some_and(|l| l.dir.size > s0 + 300_000));
    assert!(!lock(&b.sh().st).writer, "only one background writer");
    // b never walked the disk itself.
    assert_eq!(b.progress()[0].files_seen, 0);
}

#[test]
fn norm_paths() {
    assert_eq!(norm("/"), b"/");
    assert_eq!(norm("/a/./b/../c/"), b"/a/c");
    assert_eq!(norm("//x//y"), b"/x/y");
    assert!(norm("rel").starts_with(b"/"));
}

/// Manual benchmark on real paths (read-only, memory-only index):
/// `FAT_BENCH_PATHS=/a:/b FAT_BENCH_DEADLINE_MS=120000 [FAT_BENCH_BG=1] cargo test --release
///  bench_real_paths -- --ignored --nocapture`
#[test]
#[ignore]
fn bench_real_paths() {
    let paths = std::env::var("FAT_BENCH_PATHS").unwrap_or_default();
    let deadline: u64 = std::env::var("FAT_BENCH_DEADLINE_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(120_000);
    let bg = std::env::var_os("FAT_BENCH_BG").is_some();
    let ru = || {
        // SAFETY: getrusage into a zeroed struct.
        unsafe {
            let mut r: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_SELF, &mut r);
            (r.ru_utime.tv_sec as f64 + r.ru_utime.tv_usec as f64 / 1e6)
                + (r.ru_stime.tv_sec as f64 + r.ru_stime.tv_usec as f64 / 1e6)
        }
    };
    for p in paths.split(':').filter(|p| !p.is_empty()) {
        let sc = Scanner::with_options(Options {
            cache_path: None,
            protect: cfg!(target_os = "macos"),
            background: false,
            battery_check: false,
            budget: std::env::var("FAT_BENCH_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(0.25),
            threads: std::env::var("FAT_BENCH_THREADS").ok().and_then(|v| v.parse().ok()).unwrap_or(Options::default().threads),
            ..Options::default()
        });
        let (t0, c0) = (Instant::now(), ru());
        let l = if bg {
            // Background path: QoS background + 0.25 core budget.
            sc.ensure(p, false);
            let mut st = lock(&sc.sh().st);
            let id = st.tree.find_or_create(&norm(p));
            st.prepare_root(id, &norm(p));
            st.requeue(id, true, false);
            drop(st);
            sc.sh().work.notify_all();
            let end = Instant::now() + Duration::from_millis(deadline);
            while Instant::now() < end && sc.list(p).is_none_or(|l| l.dir.partial) {
                thread::sleep(Duration::from_millis(200));
            }
            sc.list(p)
        } else {
            sc.scan_blocking(p, deadline)
        };
        let (dt, cpu) = (t0.elapsed().as_secs_f64(), ru() - c0);
        let pr = sc.progress().into_iter().find(|r| r.root == p);
        let (files, bytes, errs) = pr.map_or((0, 0, 0), |r| (r.files_seen, r.bytes_seen, r.errors));
        match l {
            Some(l) => println!(
                "BENCH {p}: {:.2}s wall, {:.2}s cpu ({:.0}% of a core), {} files ({:.0}/s), size {} KiB, apparent {}, files(tree) {}, denied {}, partial {}, errors {}, index nodes {}, bytes_seen {}",
                dt, cpu, 100.0 * cpu / dt, files, files as f64 / dt, l.dir.size / 1024, l.dir.apparent, l.dir.files,
                l.dir.denied, l.dir.partial, errs, sc.index_nodes(), bytes
            ),
            None => println!("BENCH {p}: no listing"),
        }
        {
            let st = lock(&sc.sh().st);
            println!(
                "  mem: node slots (high water) {} x {} B, kept {}, hardlink set {}",
                st.tree.nodes.len(),
                std::mem::size_of::<tree::Node>(),
                st.tree.kept(),
                lock(&sc.sh().links).len()
            );
        }
        let show = std::env::var("FAT_BENCH_SHOW").unwrap_or_default();
        for q in std::iter::once(p).chain(show.split(':').filter(|q| !q.is_empty())) {
            let Some(l) = sc.list(q) else { continue };
            println!("  {q}: {} KiB partial={} files={} denied={}", l.dir.size / 1024, l.dir.partial, l.dir.files, l.dir.denied);
            for c in l.children.iter().take(14) {
                println!("   {:>12} KiB  {}{}{}{}", c.size / 1024, c.name, if c.mount_point { " [mount]" } else { "" }, if c.denied > 0 { format!(" [denied {}]", c.denied) } else { String::new() }, if c.partial { " [partial]" } else { "" });
            }
        }
    }
}
