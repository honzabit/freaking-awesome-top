//! Evidence::Mtime fallback: walk a few roots under a time budget and report files whose
//! mtime falls inside the window. Created-in-window files (birth time known) count their
//! full size; older files that were merely modified have an unknown delta unless a baseline
//! exists. Never crosses into other devices, pseudo trees, or TCC-protected locations.
use super::paths::{self, FileStat};
use std::time::{Duration, Instant};

pub struct Walk {
    /// (path, stat) of regular files with mtime >= from.
    pub hits: Vec<(String, FileStat)>,
    pub dirs: u64,
    pub files: u64,
    /// The budget ran out before every root was fully walked.
    pub truncated: bool,
}

/// `skip(path)` returns true for directories that must not be entered.
pub fn walk(roots: &[String], from_ms: i64, budget: Duration, max_hits: usize, skip: &dyn Fn(&str) -> bool) -> Walk {
    let t0 = Instant::now();
    let mut w = Walk {
        hits: vec![],
        dirs: 0,
        files: 0,
        truncated: false,
    };
    let from_s = from_ms / 1000;
    for root in roots {
        let Some(rs) = paths::lstat(root) else { continue };
        if !rs.is_dir {
            continue;
        }
        let dev = rs.dev;
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            if t0.elapsed() >= budget || w.hits.len() >= max_hits {
                w.truncated = true;
                return w;
            }
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            w.dirs += 1;
            for e in rd.flatten() {
                let Ok(m) = e.metadata() else { continue };
                let p = e.path().to_string_lossy().into_owned();
                let ft = m.file_type();
                if ft.is_dir() {
                    let st = paths::from_meta(&m);
                    if st.dev == dev && !skip(&p) {
                        stack.push(p);
                    }
                } else if ft.is_file() {
                    w.files += 1;
                    if std::os::unix::fs::MetadataExt::mtime(&m) >= from_s {
                        w.hits.push((p, paths::from_meta(&m)));
                    }
                }
            }
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_recent_files_and_honors_skip() {
        let d = std::env::temp_dir().join(format!("fat-gmt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("a/b")).unwrap();
        std::fs::create_dir_all(d.join("skipme")).unwrap();
        std::fs::write(d.join("a/b/new.bin"), vec![0u8; 8192]).unwrap();
        std::fs::write(d.join("skipme/hidden.bin"), vec![0u8; 8192]).unwrap();
        let old = d.join("a/old.txt");
        std::fs::write(&old, b"x").unwrap();
        let past = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(past)
            .unwrap();
        let root = d.to_string_lossy().into_owned();
        let from = crate::model::now_ms() - 60_000;
        let w = walk(&[root], from, Duration::from_secs(5), 100, &|p| p.ends_with("/skipme"));
        let names: Vec<_> = w
            .hits
            .iter()
            .map(|h| h.0.rsplit('/').next().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["new.bin"]);
        assert!(!w.truncated);
        assert!(w.hits[0].1.alloc >= 8192);
        let _ = std::fs::remove_dir_all(&d);
    }
}
