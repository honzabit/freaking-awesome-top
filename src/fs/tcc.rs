//! macOS privacy (TCC) protected locations: the one list the background scanner and the
//! growth tracker share.
//!
//! Reading (and for some of these, even `stat`ing) a protected location from a terminal that
//! lacks Full Disk Access either pops a "Terminal would like to access …" dialog or fails with
//! EPERM. fat never does that in the background: protected places are skipped (scanner) or only
//! counted from events (growth tracker) until the user opens one explicitly.
//!
//! The rules are pure path rules, so they are compiled on every OS (and tested everywhere);
//! callers apply them only on macOS.

/// Relative to every home directory: the directory itself and everything below it is protected.
pub const HOME: &[&str] = &[
    "Desktop",
    "Documents",
    "Downloads",
    ".Trash",
    "Music/Music",
    "Movies/TV",
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

/// Relative to every home directory: each *child* is protected (an app's sandbox container);
/// the directory itself may be listed.
pub const HOME_PER_CHILD: &[&str] = &["Library/Containers", "Library/Group Containers"];

/// Absolute protected directories.
pub const ABSOLUTE: &[&str] = &["/Library/Application Support/com.apple.TCC"];

/// Any directory with this suffix (a Photos library) is protected, wherever it is.
pub const PHOTOS_SUFFIX: &str = ".photoslibrary";

/// Removable and network volumes (`/Volumes/<name>`) are protected as a whole.
pub const VOLUMES: &str = "/Volumes";

fn under(p: &[u8], prefix: &[u8]) -> bool {
    p.starts_with(prefix) && (p.len() == prefix.len() || p.get(prefix.len()) == Some(&b'/'))
}

/// `rel` (a path relative to a home directory, no leading slash) is itself a protected
/// directory: one a background walk must not enter.
pub fn is_protected_rel(rel: &[u8]) -> bool {
    if HOME.iter().any(|p| p.as_bytes() == rel) {
        return true;
    }
    for parent in HOME_PER_CHILD {
        if let Some(rest) = rel.strip_prefix(parent.as_bytes()).and_then(|r| r.strip_prefix(b"/"))
            && !rest.is_empty()
            && !rest.contains(&b'/')
        {
            return true;
        }
    }
    rel.ends_with(PHOTOS_SUFFIX.as_bytes())
}

/// `path` (absolute) is itself one of the absolute protected directories.
pub fn is_protected_abs(path: &[u8]) -> bool {
    ABSOLUTE.iter().any(|p| p.as_bytes() == path)
}

/// The protected root that contains `path` (absolute), checking the rules relative to each of
/// `homes`. `/Volumes/X/...` yields `/Volumes/X`; a sandbox container yields its parent
/// (`~/Library/Containers`), which is how the growth tracker groups their events.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn protected_root(path: &str, homes: &[&str]) -> Option<String> {
    let p = path.as_bytes();
    for a in ABSOLUTE {
        if under(p, a.as_bytes()) {
            return Some((*a).to_string());
        }
    }
    if under(p, VOLUMES.as_bytes()) {
        let name = path[VOLUMES.len()..].trim_start_matches('/').split('/').next().unwrap_or("");
        return (!name.is_empty()).then(|| format!("{VOLUMES}/{name}"));
    }
    for h in homes.iter().map(|h| h.trim_end_matches('/')).filter(|h| !h.is_empty()) {
        let Some(rel) = path.strip_prefix(h).and_then(|r| r.strip_prefix('/')) else { continue };
        for root in HOME.iter().chain(HOME_PER_CHILD) {
            if under(rel.as_bytes(), root.as_bytes()) {
                return Some(format!("{h}/{root}"));
            }
        }
        // A Photos library anywhere in the home: the library is the unit.
        let mut acc = h.to_string();
        for c in rel.split('/') {
            acc.push('/');
            acc.push_str(c);
            if c.ends_with(PHOTOS_SUFFIX) {
                return Some(acc);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_rules_for_the_scanner() {
        for rel in [
            "Desktop",
            "Library/Mail",
            "Library/Containers/com.foo",
            "Library/Group Containers/X.dev",
            "Pictures/Photos Library.photoslibrary",
            ".Trash",
            "Music/Music",
        ] {
            assert!(is_protected_rel(rel.as_bytes()), "{rel}");
        }
        for rel in ["Library/Containers", "Library/Containers/a/b", "Library/Caches", "code", "DesktopX"] {
            assert!(!is_protected_rel(rel.as_bytes()), "{rel}");
        }
        assert!(is_protected_abs(b"/Library/Application Support/com.apple.TCC"));
        assert!(!is_protected_abs(b"/Library/Application Support"));
    }

    #[test]
    fn roots_for_the_growth_tracker() {
        let h = ["/Users/z"];
        assert_eq!(protected_root("/Users/z/Documents/a/b.txt", &h).as_deref(), Some("/Users/z/Documents"));
        assert_eq!(
            protected_root("/Users/z/Library/Containers/com.x/Data/f", &h).as_deref(),
            Some("/Users/z/Library/Containers")
        );
        assert_eq!(
            protected_root("/Users/z/Pictures/P.photoslibrary/db", &h).as_deref(),
            Some("/Users/z/Pictures/P.photoslibrary")
        );
        assert_eq!(protected_root("/Volumes/Backup/x", &h).as_deref(), Some("/Volumes/Backup"));
        assert_eq!(protected_root("/Volumes", &h), None);
        assert_eq!(protected_root("/Users/z/DocumentsX/a", &h), None);
        assert_eq!(protected_root("/Users/z/Library/Caches/x", &h), None);
        assert_eq!(protected_root("/Users/z/.Trash/x", &h).as_deref(), Some("/Users/z/.Trash"));
        assert_eq!(
            protected_root("/Library/Application Support/com.apple.TCC/TCC.db", &h).as_deref(),
            Some("/Library/Application Support/com.apple.TCC")
        );
    }

    #[test]
    fn both_views_agree() {
        // Every directory the scanner refuses to enter lies inside a root the tracker protects.
        for rel in HOME.iter().map(|r| r.to_string()).chain([
            "Library/Containers/a".into(),
            "Library/Group Containers/b".into(),
            "X/Y.photoslibrary".into(),
        ]) {
            assert!(is_protected_rel(rel.as_bytes()), "{rel}");
            assert!(protected_root(&format!("/Users/z/{rel}"), &["/Users/z"]).is_some(), "{rel}");
        }
    }
}
