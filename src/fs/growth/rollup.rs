//! Merge per-source observations and roll them up into a short list of growers.
//!
//! Rule (contract): the list is as specific as the evidence allows and never repeats bytes.
//! A directory is broken down into the children that carry >= 10% of its delta (homes, "/"
//! and other generic directories always are); a directory none of whose children matter is
//! listed itself. A broken-down parent appears again only as "other under X"
//! ([`Grower::other`]) when the part its listed children leave unexplained is significant
//! (>= max(20% of its delta, 10 MB)). So "~/Library +1 GB" becomes "Caches +600 MB" and
//! "Logs +400 MB", while 300 one-megabyte files stay one "dir +300 MB" row.
use super::super::{Evidence, Grower};
use std::collections::HashMap;

/// One path as seen by one evidence source.
#[derive(Debug, Clone, PartialEq)]
pub struct Obs {
    pub path: String,
    pub is_dir: bool,
    /// Net allocated-bytes change in the window; None = changed, amount unknown.
    pub delta: Option<i64>,
    /// Current allocated size when known.
    pub size: Option<u64>,
    pub touched: u64,
    pub writers: Vec<(u32, String, u64)>,
    pub ev: Evidence,
    /// `delta` is the exact total for this whole directory (scan diff), not a part of it.
    pub total: bool,
}

impl Obs {
    pub fn new(path: impl Into<String>, ev: Evidence) -> Obs {
        Obs { path: path.into(), is_dir: false, delta: None, size: None, touched: 0, writers: vec![], ev, total: false }
    }
}

/// Lower = more trustworthy numbers.
pub fn rank(e: Evidence) -> u8 {
    match e {
        Evidence::ScanDiff => 0,
        Evidence::Fsevents | Evidence::Watch => 1,
        Evidence::OpenFiles => 2,
        Evidence::Mtime => 3,
    }
}

/// A path after merging all sources.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Item {
    pub path: String,
    pub is_dir: bool,
    pub delta: i64,
    pub total: bool,
    pub size: Option<u64>,
    pub touched: u64,
    pub writers: Vec<(u32, String, u64)>,
    pub evidence: Vec<Evidence>,
}

pub fn merge_writers(into: &mut Vec<(u32, String, u64)>, from: &[(u32, String, u64)]) {
    for w in from {
        match into.iter_mut().find(|x| x.0 == w.0) {
            Some(x) => x.2 = x.2.max(w.2),
            None => into.push(w.clone()),
        }
    }
    into.sort_by(|a, b| b.2.cmp(&a.2));
    into.truncate(5);
}

/// Merge observations of the same path: numbers come from the best-ranked source that has
/// them, evidence and writers are unioned.
pub fn merge(obs: Vec<Obs>) -> Vec<Item> {
    let mut by: HashMap<String, Vec<Obs>> = HashMap::new();
    for o in obs {
        let p = normalize(&o.path);
        by.entry(p).or_default().push(o);
    }
    let mut out: Vec<Item> = by
        .into_iter()
        .map(|(path, mut v)| {
            v.sort_by_key(|o| rank(o.ev));
            let mut it = Item { path, ..Default::default() };
            if let Some(best) = v.iter().find(|o| o.delta.is_some()) {
                it.delta = best.delta.unwrap_or(0);
                it.total = best.total;
            }
            it.size = v.iter().find_map(|o| o.size);
            it.is_dir = v.iter().any(|o| o.is_dir);
            it.touched = v.iter().map(|o| o.touched).max().unwrap_or(0);
            for o in &v {
                merge_writers(&mut it.writers, &o.writers);
                if !it.evidence.contains(&o.ev) {
                    it.evidence.push(o.ev);
                }
            }
            it
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

pub fn normalize(p: &str) -> String {
    if p.len() > 1 {
        let t = p.trim_end_matches('/');
        if t.is_empty() { "/".into() } else { t.to_string() }
    } else {
        p.to_string()
    }
}

fn parent(p: &str) -> Option<&str> {
    if p == "/" {
        return None;
    }
    match p.rfind('/') {
        Some(0) => Some("/"),
        Some(i) => Some(&p[..i]),
        None => None,
    }
}

#[derive(Default)]
struct Node {
    path: String,
    children: Vec<usize>,
    own: Option<Item>,
    delta: i64,
    touched: u64,
    size: Option<u64>,
    writers: Vec<(u32, String, u64)>,
    evidence: Vec<Evidence>,
    is_dir: bool,
}

/// Roll `items` (all under `root`) up into at most `cap` growers, sorted by delta desc.
/// Paths with no byte delta but touched files (e.g. TCC-protected dirs counted by events)
/// fill remaining slots after the byte growers.
pub fn rollup(root: &str, items: Vec<Item>, cap: usize) -> Vec<Grower> {
    let root = normalize(root);
    let mut nodes: Vec<Node> = vec![Node { path: root.clone(), is_dir: true, ..Default::default() }];
    let mut idx: HashMap<String, usize> = HashMap::new();
    idx.insert(root.clone(), 0);
    for it in items {
        let p = normalize(&it.path);
        if !super::under_prefix(&p, &root) {
            continue;
        }
        // Collect the missing ancestor chain, then create top-down so parents get lower indexes.
        let mut chain = vec![p.clone()];
        let mut cur = p.as_str();
        while !idx.contains_key(cur) {
            match parent(cur) {
                Some(pp) => {
                    if idx.contains_key(pp) {
                        break;
                    }
                    chain.push(pp.to_string());
                    cur = pp;
                }
                None => break,
            }
        }
        for c in chain.into_iter().rev() {
            if idx.contains_key(&c) {
                continue;
            }
            let par = parent(&c).and_then(|pp| idx.get(pp).copied()).unwrap_or(0);
            let i = nodes.len();
            nodes.push(Node { path: c.clone(), is_dir: true, ..Default::default() });
            nodes[par].children.push(i);
            idx.insert(c, i);
        }
        let i = idx[&p];
        let n = &mut nodes[i];
        n.is_dir = it.is_dir || !n.children.is_empty();
        match &mut n.own {
            Some(prev) => {
                // Same path twice (shouldn't happen after merge): keep the larger |delta|.
                if it.delta.abs() > prev.delta.abs() {
                    *prev = it;
                }
            }
            None => n.own = Some(it),
        }
    }
    // Children always have higher indexes than parents: aggregate bottom-up.
    for i in (0..nodes.len()).rev() {
        let (mut d, mut t, mut sz) = (0i64, 0u64, 0u64);
        let mut any_size = false;
        let mut w: Vec<(u32, String, u64)> = vec![];
        let mut ev: Vec<Evidence> = vec![];
        for &c in &nodes[i].children {
            let ch = &nodes[c];
            d += ch.delta;
            t += ch.touched;
            if let Some(s) = ch.size {
                sz += s;
                any_size = true;
            }
            merge_writers(&mut w, &ch.writers);
            for e in &ch.evidence {
                if !ev.contains(e) {
                    ev.push(*e);
                }
            }
        }
        let has_children = !nodes[i].children.is_empty();
        let n = &mut nodes[i];
        if has_children {
            n.is_dir = true;
        }
        if let Some(own) = &n.own {
            if own.total {
                // A scan diff is exact for the whole dir but coarse in time: it wins unless
                // the events below it already show more movement (stale scan).
                if own.delta.abs() >= d.abs() {
                    d = own.delta;
                }
            } else if !has_children || !own.is_dir {
                d += own.delta;
            }
            t += own.touched;
            merge_writers(&mut w, &own.writers);
            for e in &own.evidence {
                if !ev.contains(e) {
                    ev.push(*e);
                }
            }
            n.size = own.size.or(if any_size { Some(sz) } else { None });
            n.is_dir = n.is_dir || own.is_dir;
        } else {
            n.size = if any_size { Some(sz) } else { None };
        }
        ev.sort_by_key(|e| rank(*e));
        n.delta = d;
        n.touched = t;
        n.writers = w;
        n.evidence = ev;
    }

    select_growers(&nodes, cap)
}

/// A parent is shown as "other under X" only when what its listed children leave unexplained
/// is at least this much (and at least [`REMAINDER_SHARE`] of the parent's delta).
pub const MIN_REMAINDER: i64 = 10 << 20;
/// ... and at least this share (percent) of the parent's delta.
pub const REMAINDER_SHARE: i64 = 20;
/// A child is worth descending into when it carries at least this share (percent) of its
/// parent's delta.
const CHILD_SHARE: i64 = 10;

/// Directories that never make a useful headline on their own ("/", homes, ~/Library, ...):
/// always broken down into their children when any child moved.
fn is_generic(p: &str) -> bool {
    const FIXED: &[&str] = &[
        "/",
        "/Users",
        "/home",
        "/root",
        "/var/root",
        "/private",
        "/private/var",
        "/private/var/root",
        "/var",
        "/System",
        "/System/Volumes",
        "/System/Volumes/Data",
        "/Volumes",
        "/mnt",
        "/media",
    ];
    if FIXED.contains(&p) {
        return true;
    }
    let parts: Vec<&str> = p.trim_start_matches('/').split('/').collect();
    let p = parts.as_slice();
    let data = |p: &[&str]| -> bool {
        matches!(p, ["Users" | "home", _] | ["Users" | "home", _, "Library" | ".local" | ".cache"])
    };
    data(p) || matches!(p, ["System", "Volumes", "Data", rest @ ..] if data(rest))
}

#[derive(Debug, Clone, Copy)]
enum Pick {
    /// The node's whole subtree.
    Path(usize),
    /// What the listed children of the node leave unexplained.
    Other(usize, i64),
}

fn select_growers(nodes: &[Node], cap: usize) -> Vec<Grower> {
    let top: i64 = nodes.iter().skip(1).map(|n| n.delta.saturating_abs()).max().unwrap_or(0);
    // Ignore dust: below 0.5% of the biggest mover.
    let dust = top / 200;
    let mut picks: Vec<Pick> = vec![];
    // Iterative, so a very deep tree cannot overflow the stack.
    let mut stack: Vec<usize> = vec![0];
    while let Some(i) = stack.pop() {
        let n = &nodes[i];
        let d = n.delta;
        let always = i == 0 || is_generic(&n.path);
        let thr = if always { dust } else { dust.max(d.saturating_abs() * CHILD_SHARE / 100) };
        let mut kids: Vec<usize> = n
            .children
            .iter()
            .copied()
            .filter(|&c| nodes[c].delta != 0 && nodes[c].delta.saturating_abs() >= thr.max(1))
            .collect();
        kids.sort_by(|&a, &b| {
            nodes[b]
                .delta
                .saturating_abs()
                .cmp(&nodes[a].delta.saturating_abs())
                .then(nodes[a].path.cmp(&nodes[b].path))
        });
        kids.truncate(cap);
        if kids.is_empty() {
            // Nothing deeper explains it: the node itself is the most specific answer.
            if i != 0 && d != 0 {
                picks.push(Pick::Path(i));
            }
            continue;
        }
        let explained: i64 = kids.iter().map(|&c| nodes[c].delta).sum();
        let rest = d - explained;
        if rest != 0
            && rest.signum() == d.signum()
            && rest.saturating_abs() >= MIN_REMAINDER.max(d.saturating_abs() * REMAINDER_SHARE / 100)
        {
            picks.push(Pick::Other(i, rest));
        }
        // Reverse so the biggest child is expanded first (only matters for determinism).
        stack.extend(kids.into_iter().rev());
    }

    let listed_kids = |i: usize| -> Vec<usize> {
        picks
            .iter()
            .map(|p| match *p {
                Pick::Path(c) | Pick::Other(c, _) => c,
            })
            .filter(|&c| c != i && super::under_prefix(&nodes[c].path, &nodes[i].path))
            .collect()
    };
    let mut out: Vec<Grower> = picks
        .iter()
        .map(|p| match *p {
            Pick::Path(i) => {
                let n = &nodes[i];
                Grower {
                    path: n.path.clone(),
                    is_dir: n.is_dir,
                    delta: n.delta,
                    size: n.size.unwrap_or(0),
                    files_touched: n.touched,
                    writers: n.writers.clone(),
                    evidence: n.evidence.clone(),
                    other: false,
                }
            }
            Pick::Other(i, rest) => {
                // Writers, evidence and touched files of the part that is not listed below.
                let n = &nodes[i];
                let listed = listed_kids(i);
                let mut w: Vec<(u32, String, u64)> = vec![];
                let mut ev: Vec<Evidence> = vec![];
                let mut touched = 0u64;
                let unlisted = n.children.iter().copied().filter(|c| {
                    !listed.iter().any(|&l| l == *c || super::under_prefix(&nodes[l].path, &nodes[*c].path))
                });
                for c in unlisted {
                    merge_writers(&mut w, &nodes[c].writers);
                    touched += nodes[c].touched;
                    for e in &nodes[c].evidence {
                        if !ev.contains(e) {
                            ev.push(*e);
                        }
                    }
                }
                if let Some(own) = &n.own {
                    merge_writers(&mut w, &own.writers);
                    touched += own.touched;
                    for e in &own.evidence {
                        if !ev.contains(e) {
                            ev.push(*e);
                        }
                    }
                }
                if ev.is_empty() {
                    ev = n.evidence.clone();
                }
                ev.sort_by_key(|e| rank(*e));
                // SIZE of the remainder too, not the whole directory: the outermost listed
                // paths below it have rows of their own, so their bytes are not counted twice.
                let outer = listed.iter().filter(|&&l| {
                    !listed.iter().any(|&m| m != l && super::under_prefix(&nodes[l].path, &nodes[m].path))
                });
                let listed_size: u64 = outer.map(|&l| nodes[l].size.unwrap_or(0)).sum();
                Grower {
                    path: n.path.clone(),
                    is_dir: true,
                    delta: rest,
                    size: n.size.unwrap_or(0).saturating_sub(listed_size),
                    files_touched: touched,
                    writers: w,
                    evidence: ev,
                    other: true,
                }
            }
        })
        .collect();
    out.sort_by(|a, b| b.delta.cmp(&a.delta).then(a.other.cmp(&b.other)).then(a.path.cmp(&b.path)));
    // Keep the biggest movers either way (a big shrink beats a tiny growth).
    if out.len() > cap {
        let mut by_abs: Vec<usize> = (0..out.len()).collect();
        by_abs.sort_by(|&a, &b| out[b].delta.saturating_abs().cmp(&out[a].delta.saturating_abs()).then(a.cmp(&b)));
        let keep: std::collections::HashSet<usize> = by_abs.into_iter().take(cap).collect();
        out = out.into_iter().enumerate().filter(|(i, _)| keep.contains(i)).map(|(_, g)| g).collect();
    }

    // Touched-only paths (unknown byte deltas, e.g. protected dirs counted by events) fill the
    // remaining slots, by file count, never overlapping a listed path.
    if out.len() < cap {
        let top_t = nodes.iter().skip(1).filter(|n| n.delta == 0).map(|n| n.touched).max().unwrap_or(0);
        let mut cand: Vec<usize> = (1..nodes.len())
            .filter(|&i| {
                let n = &nodes[i];
                n.delta == 0
                    && n.touched > 0
                    && n.touched * 200 >= top_t
                    // A child carrying >= 80% of the touches is the better answer.
                    && !n.children.iter().any(|&c| nodes[c].delta == 0 && nodes[c].touched * 10 >= n.touched * 8)
                    && !(is_generic(&n.path) && n.children.iter().any(|&c| nodes[c].touched > 0))
            })
            .collect();
        cand.sort_by(|&a, &b| nodes[b].touched.cmp(&nodes[a].touched).then(nodes[a].path.cmp(&nodes[b].path)));
        for i in cand {
            if out.len() >= cap {
                break;
            }
            let p = &nodes[i].path;
            if out.iter().any(|g| super::under_prefix(p, &g.path) || super::under_prefix(&g.path, p)) {
                continue;
            }
            let n = &nodes[i];
            out.push(Grower {
                path: n.path.clone(),
                is_dir: n.is_dir,
                delta: 0,
                size: n.size.unwrap_or(0),
                files_touched: n.touched,
                writers: n.writers.clone(),
                evidence: n.evidence.clone(),
                other: false,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(p: &str, d: i64) -> Item {
        Item {
            path: p.into(),
            delta: d,
            size: Some(d.max(0) as u64),
            touched: 1,
            evidence: vec![Evidence::Fsevents],
            ..Default::default()
        }
    }
    fn paths(g: &[Grower]) -> Vec<(&str, i64)> {
        g.iter().map(|g| (g.path.as_str(), g.delta)).collect()
    }

    const MB: i64 = 1 << 20;

    fn no_overlap(g: &[Grower]) {
        // Disjoint: a path and something below it appear together only as "other under X".
        for a in g {
            for b in g {
                if a.path != b.path && super::super::under_prefix(&b.path, &a.path) {
                    assert!(a.other, "{} listed in full above {}: {:?}", a.path, b.path, paths(g));
                }
            }
        }
    }

    #[test]
    fn single_dominant_child_hides_parents() {
        let g = rollup("/", vec![item("/a/b/c/big.log", 1000 * MB), item("/a/x.txt", 10 * MB)], 50);
        // /a, /a/b, /a/b/c are all explained by big.log; x.txt is 1% of /a: not worth a row,
        // and 10 MB is below the 20% remainder share.
        assert_eq!(paths(&g), vec![("/a/b/c/big.log", 1000 * MB)]);
        no_overlap(&g);
    }

    #[test]
    fn parent_is_broken_down_without_repeating_bytes() {
        let g = rollup(
            "/",
            vec![item("/u/lib/caches/a", 500 * MB), item("/u/lib/logs/b", 400 * MB), item("/u/lib/tmp/c", 100 * MB)],
            50,
        );
        let p = paths(&g);
        // Every child carries >= 10%: all three are listed, nothing is left for "other".
        assert_eq!(p, vec![("/u/lib/caches/a", 500 * MB), ("/u/lib/logs/b", 400 * MB), ("/u/lib/tmp/c", 100 * MB)]);
        assert!(!g.iter().any(|x| x.other));
        no_overlap(&g);
    }

    #[test]
    fn significant_remainder_becomes_other_under_parent() {
        // 600 MB in one file, 400 MB spread over 100 small files of the same dir.
        let mut items = vec![item("/w/proj/out/big.bin", 600 * MB)];
        items.extend((0..100).map(|i| item(&format!("/w/proj/out/f{i}"), 4 * MB)));
        let g = rollup("/", items, 50);
        let p = paths(&g);
        assert_eq!(p[0], ("/w/proj/out/big.bin", 600 * MB));
        assert_eq!(p[1], ("/w/proj/out", 400 * MB), "{p:?}");
        assert!(g[1].other && !g[0].other);
        assert_eq!(g[1].files_touched, 100, "touches of the unlisted part only");
        // SIZE is the remainder's (1000 MB dir - the listed 600 MB file), never the whole dir:
        // summing the SIZE column must not count big.bin twice.
        assert_eq!(g[1].size, 400 * MB as u64, "other's size excludes listed rows");
        assert_eq!(g.len(), 2, "{p:?}");
        no_overlap(&g);
    }

    #[test]
    fn small_remainder_is_not_listed() {
        // 15 MB unexplained of 1 GB: below 20% of the parent.
        let mut items = vec![item("/w/a/big", 1000 * MB)];
        items.extend((0..5).map(|i| item(&format!("/w/a/s{i}"), 3 * MB)));
        let g = rollup("/", items, 50);
        assert_eq!(paths(&g), vec![("/w/a/big", 1000 * MB)]);
        // 30% unexplained but only 3 MB: below the 10 MB floor.
        let g = rollup(
            "/",
            vec![
                item("/v/k/x", 7 * MB),
                item("/v/k/y1", MB / 2),
                item("/v/k/y2", MB / 2),
                item("/v/k/y3", MB / 2),
                item("/v/k/y4", MB / 2),
                item("/v/k/y5", MB / 2),
                item("/v/k/y6", MB / 2),
            ],
            50,
        );
        assert!(!g.iter().any(|x| x.other), "{:?}", paths(&g));
    }

    #[test]
    fn home_and_root_are_never_the_headline_when_something_deeper_explains() {
        // Lots of small growers directly in a home dir, plus one project: the home dir itself
        // only shows up as "other under ~".
        let mut items = vec![item("/Users/me/code/app/target/debug/app", 300 * MB)];
        items.extend((0..40).map(|i| item(&format!("/Users/me/dl{i}.bin"), 8 * MB)));
        let g = rollup("/", items, 50);
        assert_eq!(g[0].path, "/Users/me/code/app/target/debug/app");
        assert!(
            !g.iter().any(|x| x.path == "/" || (x.path == "/Users/me" && !x.other) || x.path == "/Users"),
            "{:?}",
            paths(&g)
        );
        no_overlap(&g);
        // A home dir with many equal children is broken down into them (it is generic).
        let items: Vec<Item> = (0..5).map(|i| item(&format!("/Users/me/p{i}/f"), 100 * MB)).collect();
        let g = rollup("/", items, 50);
        assert_eq!(g.len(), 5, "{:?}", paths(&g));
        assert!(g.iter().all(|x| x.path.starts_with("/Users/me/p")));
    }

    #[test]
    fn many_small_files_collapse_into_dir() {
        let items: Vec<Item> = (0..300).map(|i| item(&format!("/d/x/f{i}"), MB)).collect();
        let g = rollup("/", items, 50);
        assert_eq!(g.len(), 1, "{:?}", paths(&g));
        assert_eq!(g[0].path, "/d/x");
        assert!(!g[0].other);
        assert_eq!(g[0].delta, 300 * MB);
        assert_eq!(g[0].files_touched, 300);
    }

    #[test]
    fn negative_deltas_sorted_last_and_cap() {
        let mut items: Vec<Item> = (0..80).map(|i| item(&format!("/p{i}/f"), 1000 + i)).collect();
        items.push(item("/gone/x", -5000));
        let g = rollup("/", items, 50);
        assert_eq!(g.len(), 50);
        assert!(g.windows(2).all(|w| w[0].delta >= w[1].delta));
        assert_eq!(g.last().unwrap().path, "/gone/x");
    }

    #[test]
    fn scan_diff_total_overrides_sum_of_children() {
        let mut d = item("/v/lib", 5000 * MB);
        d.total = true;
        d.is_dir = true;
        d.evidence = vec![Evidence::ScanDiff];
        let g = rollup("/", vec![d, item("/v/lib/a", 600 * MB), item("/v/lib/b", 400 * MB)], 50);
        let p = paths(&g);
        // a (12%) is worth a row, b (8%) is not; the scan says 5 GB in total, so 4.4 GB is
        // "other under /v/lib", with the scan as its evidence.
        assert_eq!(p, vec![("/v/lib", 4400 * MB), ("/v/lib/a", 600 * MB)]);
        assert!(g[0].other);
        assert_eq!(g[0].evidence, vec![Evidence::ScanDiff, Evidence::Fsevents]);
        no_overlap(&g);
    }

    #[test]
    fn under_filters_and_root_not_listed() {
        let g = rollup("/home/u", vec![item("/home/u/a/x", 10), item("/home/u/b/y", 10), item("/etc/z", 99)], 50);
        let p = paths(&g);
        assert!(!p.iter().any(|x| x.0 == "/home/u" || x.0 == "/etc/z"), "{p:?}");
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn touched_only_paths_fill_remaining_slots() {
        let mut prot = Item {
            path: "/Users/z/Documents".into(),
            is_dir: true,
            touched: 42,
            evidence: vec![Evidence::Fsevents],
            ..Default::default()
        };
        prot.delta = 0;
        let g = rollup("/", vec![item("/Users/z/proj/out.bin", 1 << 30), prot], 50);
        let p = paths(&g);
        assert_eq!(p[0], ("/Users/z/proj/out.bin", 1 << 30));
        assert_eq!(p[1], ("/Users/z/Documents", 0));
        assert_eq!(g[1].files_touched, 42);
    }

    #[test]
    fn merge_prefers_exact_sources() {
        let mut a = Obs::new("/x/f", Evidence::Mtime);
        a.delta = Some(900);
        a.size = Some(900);
        a.touched = 1;
        let mut b = Obs::new("/x/f/", Evidence::OpenFiles);
        b.delta = Some(300);
        b.writers = vec![(7, "dd".into(), 100)];
        let mut c = Obs::new("/x/f", Evidence::Fsevents);
        c.delta = None; // touched, amount unknown
        c.touched = 3;
        let m = merge(vec![a, b, c]);
        assert_eq!(m.len(), 1);
        let m = &m[0];
        assert_eq!(m.path, "/x/f");
        assert_eq!(m.delta, 300, "OpenFiles beats Mtime; Fsevents had no number");
        assert_eq!(m.size, Some(900));
        assert_eq!(m.touched, 3);
        assert_eq!(m.writers, vec![(7, "dd".to_string(), 100)]);
        assert_eq!(m.evidence, vec![Evidence::Fsevents, Evidence::OpenFiles, Evidence::Mtime]);

        let mut s = Obs::new("/x", Evidence::ScanDiff);
        s.delta = Some(10);
        s.total = true;
        let mut f = Obs::new("/x", Evidence::Fsevents);
        f.delta = Some(99);
        let m = merge(vec![f, s]);
        assert_eq!((m[0].delta, m[0].total), (10, true));
    }
}
