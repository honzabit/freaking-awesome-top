//! Path helpers: stat with birth time, TCC-protected locations, fat's own directories.
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    /// Allocated bytes (st_blocks * 512).
    pub alloc: u64,
    pub is_file: bool,
    pub is_dir: bool,
    /// Creation time (macOS st_birthtime, Linux statx btime) when the filesystem reports it.
    pub birth_ms: Option<i64>,
    pub mtime_ms: i64,
    pub ctime_ms: i64,
    pub dev: u64,
    pub nlink: u64,
}

pub fn lstat(path: &str) -> Option<FileStat> {
    let m = std::fs::symlink_metadata(path).ok()?;
    Some(from_meta(&m))
}

pub fn from_meta(m: &std::fs::Metadata) -> FileStat {
    let birth_ms = m
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .filter(|&b| b > 0);
    FileStat {
        alloc: m.blocks() * 512,
        is_file: m.file_type().is_file(),
        is_dir: m.file_type().is_dir(),
        birth_ms,
        mtime_ms: m.mtime() * 1000 + m.mtime_nsec() / 1_000_000,
        ctime_ms: m.ctime() * 1000 + m.ctime_nsec() / 1_000_000,
        dev: m.dev(),
        nlink: m.nlink(),
    }
}

pub fn home() -> String {
    dirs::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Directories fat itself writes (history DB, caches): their churn is never "growth".
pub fn own_dirs() -> Vec<String> {
    let mut v: Vec<String> = [
        dirs::data_local_dir(),
        dirs::cache_dir(),
        dirs::data_dir(),
        dirs::config_dir(),
    ]
    .into_iter()
    .flatten()
    .map(|d| d.join("fat").to_string_lossy().into_owned())
    .collect();
    if let Some(h) = dirs::home_dir() {
        v.push(h.join(".cache").join("fat").to_string_lossy().into_owned());
    }
    v.sort();
    v.dedup();
    v
}

/// Where fat keeps growth-tracker state (the FSEvents id clock).
pub fn state_dir() -> PathBuf {
    dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("fat")
}

/// macOS locations whose contents (or even metadata) are guarded by TCC: stat/readdir from a
/// terminal without Full Disk Access pops a permission prompt. Relative to $HOME unless absolute.
#[cfg(target_os = "macos")]
const TCC_PROTECTED: &[&str] = &[
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures/Photos Library.photoslibrary",
    "Music/Music",
    "Movies/TV",
    "Library/Mail",
    "Library/Messages",
    "Library/Calendars",
    "Library/Reminders",
    "Library/Safari",
    "Library/Cookies",
    "Library/HomeKit",
    "Library/IdentityServices",
    "Library/Metadata/CoreSpotlight",
    "Library/PersonalizationPortrait",
    "Library/Suggestions",
    "Library/Accounts",
    "Library/Containers",
    "Library/Group Containers",
    "Library/Mobile Documents",
    "Library/CloudStorage",
    "Library/Application Support/AddressBook",
    "Library/Application Support/CallHistoryDB",
    "Library/Application Support/CallHistoryTransactions",
    "Library/Application Support/com.apple.TCC",
    "Library/Application Support/Knowledge",
    "Library/Application Support/FaceTime",
    "Library/Application Support/MobileSync",
    "/Volumes",
    "/Library/Application Support/com.apple.TCC",
];

/// The TCC-protected root containing `path`, if any (always None off macOS).
pub fn protected_root(path: &str, home: &str) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        for p in TCC_PROTECTED {
            let root = if p.starts_with('/') {
                (*p).to_string()
            } else if home.is_empty() {
                continue;
            } else {
                format!("{home}/{p}")
            };
            if super::under_prefix(path, &root) {
                // /Volumes/X: the protected unit is the volume.
                if root == "/Volumes" {
                    let rest = &path["/Volumes".len()..];
                    let name = rest.trim_start_matches('/').split('/').next().unwrap_or("");
                    if name.is_empty() {
                        return None;
                    }
                    return Some(format!("/Volumes/{name}"));
                }
                return Some(root);
            }
        }
        None
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, home);
        None
    }
}

/// Full Disk Access granted to this process (macOS). Opening the per-user TCC database
/// fails with EPERM without FDA and never prompts. Always true elsewhere.
pub fn full_disk_access() -> bool {
    #[cfg(target_os = "macos")]
    {
        let h = home();
        if h.is_empty() {
            return false;
        }
        std::fs::File::open(format!("{h}/Library/Application Support/com.apple.TCC/TCC.db")).is_ok()
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

/// Linux pseudo / virtual trees never worth watching or walking.
pub fn is_pseudo_path(p: &str) -> bool {
    ["/proc", "/sys", "/dev", "/run"]
        .iter()
        .any(|r| super::under_prefix(p, r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_roots() {
        let h = "/Users/z";
        if cfg!(target_os = "macos") {
            assert_eq!(
                protected_root("/Users/z/Documents/a/b.txt", h).as_deref(),
                Some("/Users/z/Documents")
            );
            assert_eq!(
                protected_root("/Users/z/Documents", h).as_deref(),
                Some("/Users/z/Documents")
            );
            assert_eq!(protected_root("/Users/z/DocumentsX/a", h), None);
            assert_eq!(
                protected_root("/Users/z/Library/Containers/com.x/Data/f", h).as_deref(),
                Some("/Users/z/Library/Containers")
            );
            assert_eq!(
                protected_root("/Volumes/Backup/x", h).as_deref(),
                Some("/Volumes/Backup")
            );
            assert_eq!(protected_root("/Volumes", h), None);
            assert_eq!(protected_root("/Users/z/Library/Caches/x", h), None);
        } else {
            assert_eq!(protected_root("/home/z/Documents/a", "/home/z"), None);
        }
    }

    #[test]
    fn stat_reports_alloc_and_birth() {
        let d = std::env::temp_dir().join(format!("fat-gstat-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("x");
        std::fs::write(&f, vec![1u8; 64 * 1024]).unwrap();
        let s = lstat(f.to_str().unwrap()).unwrap();
        assert!(s.is_file && !s.is_dir);
        assert!(s.alloc >= 64 * 1024, "{s:?}");
        assert!(s.mtime_ms > 0 && s.ctime_ms > 0);
        let _ = std::fs::remove_dir_all(&d);
    }
}
