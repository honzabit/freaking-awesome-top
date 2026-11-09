//! Merge per-source observations and roll them up into a short list of growers.
//!
//! Rule (contract): a parent is listed only when no single child explains >= 80% of its
//! delta. A child of a listed path is listed too when it carries >= 20% of that parent's
//! delta (so "~/Library +1 GB" can sit above "Caches +600 MB" and "Logs +400 MB", but not
//! above 300 one-megabyte files).
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
        Obs {
            path: path.into(),
            is_dir: false,
            delta: None,
            size: None,
            touched: 0,
            writers: vec![],
            ev,
            total: false,
        }
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
            let mut it = Item {
                path,
                ..Default::default()
            };
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
    parent: Option<usize>,
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
    let mut nodes: Vec<Node> = vec![Node {
        path: root.clone(),
        is_dir: true,
        ..Default::default()
    }];
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
            nodes.push(Node {
                path: c.clone(),
                parent: Some(par),
                is_dir: true,
                ..Default::default()
            });
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

    let to_grower = |n: &Node| Grower {
        path: n.path.clone(),
        is_dir: n.is_dir,
        delta: n.delta,
        size: n.size.unwrap_or(0),
        files_touched: n.touched,
        writers: n.writers.clone(),
        evidence: n.evidence.clone(),
    };
    let dominated = |n: &Node, key: &dyn Fn(&Node) -> i128| {
        let k = key(n);
        n.children.iter().any(|&c| {
            let kc = key(&nodes[c]);
            kc.signum() == k.signum() && kc.abs() * 10 >= k.abs() * 8
        })
    };
    let mut picked: Vec<usize> = vec![];
    let select = |key: &dyn Fn(&Node) -> i128, picked: &mut Vec<usize>, limit: usize| {
        let mut cand: Vec<usize> = (1..nodes.len())
            .filter(|&i| key(&nodes[i]) != 0 && !dominated(&nodes[i], key))
            .collect();
        cand.sort_by(|&a, &b| {
            key(&nodes[b])
                .abs()
                .cmp(&key(&nodes[a]).abs())
                .then(nodes[a].path.cmp(&nodes[b].path))
        });
        let top = cand.first().map(|&i| key(&nodes[i]).abs()).unwrap_or(0);
        for i in cand {
            if picked.len() >= limit {
                break;
            }
            let k = key(&nodes[i]).abs();
            // Ignore dust: below 0.5% of the biggest mover.
            if k * 200 < top {
                break;
            }
            // Nearest picked ancestor must not dwarf this one.
            let mut a = nodes[i].parent;
            let mut ok = true;
            while let Some(ai) = a {
                if picked.contains(&ai) {
                    ok = key(&nodes[ai]).abs() <= k * 5;
                    break;
                }
                a = nodes[ai].parent;
            }
            if ok && !picked.contains(&i) {
                picked.push(i);
            }
        }
    };
    select(&|n: &Node| n.delta as i128, &mut picked, cap);
    let n_bytes = picked.len();
    if n_bytes < cap {
        // Touched-only paths (unknown byte deltas) by file count, only where bytes are zero.
        let mut extra: Vec<usize> = vec![];
        select(
            &|n: &Node| if n.delta == 0 { n.touched as i128 } else { 0 },
            &mut extra,
            cap - n_bytes,
        );
        // Skip touched-only nodes inside an already-picked byte grower.
        for e in extra {
            let mut a = nodes[e].parent;
            let mut inside = false;
            while let Some(ai) = a {
                if picked[..n_bytes].contains(&ai) {
                    inside = true;
                    break;
                }
                a = nodes[ai].parent;
            }
            if !inside {
                picked.push(e);
            }
        }
    }
    let mut out: Vec<Grower> = picked.iter().map(|&i| to_grower(&nodes[i])).collect();
    out.sort_by(|a, b| {
        b.delta
            .cmp(&a.delta)
            .then(b.files_touched.cmp(&a.files_touched))
            .then(a.path.cmp(&b.path))
    });
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

    #[test]
    fn single_dominant_child_hides_parents() {
        let g = rollup("/", vec![item("/a/b/c/big.log", 1000), item("/a/x.txt", 10)], 50);
        // /a, /a/b, /a/b/c are all explained by big.log; x.txt is dust (< 0.5%? no: 1%) but kept.
        assert_eq!(paths(&g), vec![("/a/b/c/big.log", 1000), ("/a/x.txt", 10)]);
    }

    #[test]
    fn parent_listed_when_no_child_dominates() {
        let g = rollup(
            "/",
            vec![
                item("/u/lib/caches/a", 500),
                item("/u/lib/logs/b", 400),
                item("/u/lib/tmp/c", 100),
            ],
            50,
        );
        let p = paths(&g);
        assert_eq!(p[0], ("/u/lib", 1000));
        assert!(p.contains(&("/u/lib/caches/a", 500)));
        assert!(p.contains(&("/u/lib/logs/b", 400)));
        assert!(
            !p.contains(&("/u/lib/tmp/c", 100)),
            "10% child of a listed parent is hidden: {p:?}"
        );
        // /u is dominated by /u/lib (100%)
        assert!(!p.iter().any(|x| x.0 == "/u"));
    }

    #[test]
    fn many_small_files_collapse_into_dir() {
        let items: Vec<Item> = (0..300).map(|i| item(&format!("/d/f{i}"), 1 << 20)).collect();
        let g = rollup("/", items, 50);
        assert_eq!(g.len(), 1, "{:?}", paths(&g));
        assert_eq!(g[0].path, "/d");
        assert_eq!(g[0].delta, 300 << 20);
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
        let mut d = item("/v/lib", 5000);
        d.total = true;
        d.is_dir = true;
        d.evidence = vec![Evidence::ScanDiff];
        let g = rollup("/", vec![d, item("/v/lib/a", 600), item("/v/lib/b", 400)], 50);
        let p = paths(&g);
        assert_eq!(p[0], ("/v/lib", 5000));
        assert_eq!(g[0].evidence, vec![Evidence::ScanDiff, Evidence::Fsevents]);
        // a (12%) and b (8%) are below the 20% child rule.
        assert_eq!(g.len(), 1, "{p:?}");
    }

    #[test]
    fn under_filters_and_root_not_listed() {
        let g = rollup(
            "/home/u",
            vec![item("/home/u/a/x", 10), item("/home/u/b/y", 10), item("/etc/z", 99)],
            50,
        );
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
        assert_eq!(
            m.evidence,
            vec![Evidence::Fsevents, Evidence::OpenFiles, Evidence::Mtime]
        );

        let mut s = Obs::new("/x", Evidence::ScanDiff);
        s.delta = Some(10);
        s.total = true;
        let mut f = Obs::new("/x", Evidence::Fsevents);
        f.delta = Some(99);
        let m = merge(vec![f, s]);
        assert_eq!((m[0].delta, m[0].total), (10, true));
    }
}
