//! Version check and self-update.
//!
//! - **Check**: at most once a day, in the background (TUI, recorder), fat asks GitHub which
//!   release is the latest by reading the redirect of `<repo>/releases/latest` (not the API, so no
//!   rate limit). The answer is cached in `<data dir>/fat/update.json`; nothing else is sent.
//! - **Update** (`fat update`, or automatically with `[update] auto`): download the release's
//!   `SHA256SUMS` and `SHA256SUMS.sig`, verify the signature with the Ed25519 key built into this
//!   binary (`keys/release-signing.hex`), download this platform's archive and check its SHA-256,
//!   run the new binary's `--version`, then atomically replace the running binary, keeping the
//!   previous one as `<name>.prev` (`fat update --rollback` swaps them back).
//!
//! fat never escalates: if the binary's directory isn't writable it says what to run instead, and
//! binaries installed by a package manager are left to it.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = env!("CARGO_PKG_REPOSITORY");
/// Hex of the 32-byte Ed25519 public key that signs releases' SHA256SUMS (empty: unsigned build).
const RELEASE_KEY_HEX: &str = include_str!("../keys/release-signing.hex");
/// How often the background check runs.
pub const CHECK_EVERY_MS: i64 = 24 * 3600 * 1000;
/// Largest archive or checksum file fat downloads.
const MAX_DOWNLOAD: u64 = 128 << 20;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct State {
    /// Epoch ms of the last check (successful or not).
    pub checked_at: i64,
    /// Latest released version ("0.2.0"), empty when unknown.
    pub latest: String,
    /// Why the last check or automatic update failed.
    pub error: String,
    /// A version installed by an automatic update (the running fat may be older).
    pub installed: String,
}

impl State {
    /// A released version newer than this binary, if the last check found one.
    pub fn available(&self) -> Option<&str> {
        (!self.latest.is_empty() && newer(&self.latest, VERSION)).then_some(self.latest.as_str())
    }

    /// An automatic update installed a newer fat than the one running.
    pub fn installed_newer(&self) -> Option<&str> {
        (!self.installed.is_empty() && newer(&self.installed, VERSION)).then_some(self.installed.as_str())
    }

    pub fn due(&self, now_ms: i64) -> bool {
        now_ms - self.checked_at >= CHECK_EVERY_MS || now_ms < self.checked_at
    }
}

pub fn state_path() -> PathBuf {
    if let Some(p) = std::env::var_os("FAT_UPDATE_STATE").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("fat").join("update.json")
}

pub fn load_state() -> State {
    std::fs::read_to_string(state_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_state(s: &State) {
    let path = state_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("json.tmp");
    if let Ok(text) = serde_json::to_string_pretty(s)
        && std::fs::write(&tmp, text).is_ok()
    {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Why background checks are off, if they are.
pub fn check_off_reason(cfg: &crate::config::Config, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    if env("FAT_NO_UPDATE_CHECK").is_some_and(|v| !v.trim().is_empty() && v.trim() != "0") {
        return Some("FAT_NO_UPDATE_CHECK is set".into());
    }
    if !cfg.update.check {
        return Some("[update] check = false".into());
    }
    if cfg.ask.local_only {
        return Some("[ask] local_only keeps fat off the internet".into());
    }
    None
}

/// Where releases are: `FAT_UPDATE_URL` (a mirror laid out like GitHub's releases) or the repository.
fn base() -> String {
    std::env::var("FAT_UPDATE_URL").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| REPO.to_string())
}

fn agent(timeout: Duration, redirects: u32) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeout.min(Duration::from_secs(10)))
        .timeout(timeout)
        .redirects(redirects)
        .user_agent(&format!("fat/{VERSION}"))
        .build()
}

/// The latest released version, from the redirect of `<base>/releases/latest`.
pub fn latest(timeout: Duration) -> Result<String> {
    let url = format!("{}/releases/latest", base().trim_end_matches('/'));
    let resp = match agent(timeout, 0).get(&url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => bail!("{url}: HTTP {code}"),
        Err(e) => bail!("{url}: {}", short_err(&e)),
    };
    let Some(loc) = resp.header("location").filter(|_| (300..400).contains(&resp.status())) else {
        bail!("{url}: no release found (HTTP {})", resp.status());
    };
    version_from_location(loc).with_context(|| format!("unexpected release location {loc}"))
}

fn short_err(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Transport(t) => t.message().map(str::to_string).unwrap_or_else(|| t.kind().to_string()),
        other => other.to_string(),
    }
}

fn version_from_location(loc: &str) -> Option<String> {
    let tag = loc.trim_end_matches('/').rsplit_once("/tag/")?.1;
    let v = tag.strip_prefix('v').unwrap_or(tag);
    parse(v).map(|_| v.to_string())
}

/// "1.2.3" → (1, 2, 3). Pre-releases ("1.2.3-rc1") are not offered.
fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().split('.');
    let t = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    it.next().is_none().then_some(t)
}

/// `a` is a newer release than `b`.
pub fn newer(a: &str, b: &str) -> bool {
    match (parse(a), parse(b.split('-').next().unwrap_or(b))) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// Check now and remember the answer.
pub fn check_now(timeout: Duration) -> State {
    let mut s = load_state();
    s.checked_at = crate::model::now_ms();
    match latest(timeout) {
        Ok(v) => {
            s.latest = v;
            s.error.clear();
        }
        Err(e) => s.error = format!("{e:#}"),
    }
    save_state(&s);
    s
}

/// The background job (TUI start, recorder once a day): check when due and, with
/// `[update] auto`, install a newer release. Returns the state to show, None when checks are off.
pub fn background(cfg: &crate::config::Config) -> Option<State> {
    if cfg!(test) || check_off_reason(cfg, &|k| std::env::var(k).ok()).is_some() {
        return None;
    }
    let mut s = load_state();
    if s.due(crate::model::now_ms()) {
        s = check_now(Duration::from_secs(10));
    }
    if cfg.update.auto
        && let Some(v) = s.available().map(str::to_string)
        && s.installed_newer() != Some(v.as_str())
    {
        match current_exe().and_then(|exe| install(&v, &exe)) {
            Ok(_) => {
                s.installed = v;
                s.error.clear();
            }
            Err(e) => s.error = format!("automatic update to {v} failed: {e:#}"),
        }
        save_state(&s);
    }
    Some(s)
}

/// What the TUI header shows: "⬆ 0.2.0" (available) or "0.2.0 installed: restart" (auto-updated).
pub fn header_note(s: &State) -> Option<String> {
    if let Some(v) = s.installed_newer() {
        return Some(format!("fat {v} installed · restart fat"));
    }
    s.available().map(|v| format!("⬆ fat {v} · fat update"))
}

/// This platform's release archive suffix.
pub fn target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        _ => None,
    }
}

/// The running binary's path (symlinks resolved: that is the file to replace).
pub fn current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("can't tell where this fat binary is")?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    // Linux: a replaced binary reads as "/path/fat (deleted)".
    let s = exe.to_string_lossy();
    match s.strip_suffix(" (deleted)") {
        Some(p) => Ok(PathBuf::from(p)),
        None => Ok(exe),
    }
}

/// Binaries fat must not replace itself, and why.
pub fn managed_by(exe: &Path) -> Option<&'static str> {
    let s = exe.to_string_lossy();
    if s.contains("/Cellar/") || s.contains("/homebrew/") {
        return Some("Homebrew installed it: use brew upgrade");
    }
    if s.starts_with("/nix/store/") {
        return Some("Nix installed it");
    }
    if s.starts_with("/snap/") {
        return Some("snap installed it");
    }
    if ["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"].iter().any(|p| s.starts_with(p)) {
        return Some("it is in a system directory a package manager owns");
    }
    if s.contains("/target/debug/") || s.contains("/target/release/") {
        return Some("it is a development build (cargo target directory)");
    }
    None
}

fn release_key() -> Result<ed25519_dalek::VerifyingKey> {
    let hex = RELEASE_KEY_HEX.trim();
    if hex.is_empty() {
        bail!(
            "this build has no release signing key, so it can't verify downloads; get a release from {REPO}/releases"
        );
    }
    key_from_hex(hex)
}

fn key_from_hex(hex: &str) -> Result<ed25519_dalek::VerifyingKey> {
    let bytes: [u8; 32] = unhex(hex).and_then(|b| b.try_into().ok()).context("malformed release signing key")?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).context("invalid release signing key")
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `sums` is signed by `key`, and lists `file` with this SHA-256.
fn verify(key: &ed25519_dalek::VerifyingKey, sums: &[u8], sig: &[u8], file: &str, data: &[u8]) -> Result<()> {
    let sig: [u8; 64] = sig.try_into().ok().context("SHA256SUMS.sig is not an Ed25519 signature")?;
    key.verify_strict(sums, &ed25519_dalek::Signature::from_bytes(&sig))
        .ok()
        .context("SHA256SUMS signature does not match fat's release key: refusing to install")?;
    let text = std::str::from_utf8(sums).context("SHA256SUMS is not text")?;
    let want = text
        .lines()
        .find_map(|l| {
            let (sum, name) = l.split_once(char::is_whitespace)?;
            (name.trim().trim_start_matches('*') == file).then(|| sum.to_ascii_lowercase())
        })
        .with_context(|| format!("{file} is not listed in SHA256SUMS"))?;
    use sha2::Digest;
    let got = hex(&sha2::Sha256::digest(data));
    if got != want {
        bail!("{file}: SHA-256 {got} does not match SHA256SUMS ({want}): refusing to install");
    }
    Ok(())
}

fn download(url: &str) -> Result<Vec<u8>> {
    let resp = match agent(Duration::from_secs(300), 5).get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => bail!("{url}: HTTP {code}"),
        Err(e) => bail!("{url}: {}", short_err(&e)),
    };
    let mut buf = Vec::new();
    resp.into_reader().take(MAX_DOWNLOAD + 1).read_to_end(&mut buf).with_context(|| format!("reading {url}"))?;
    if buf.len() as u64 > MAX_DOWNLOAD {
        bail!("{url}: larger than {} MB", MAX_DOWNLOAD >> 20);
    }
    Ok(buf)
}

/// Removes its directory when dropped.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What [`install`] did.
#[derive(Debug)]
pub struct Installed {
    pub version: String,
    pub previous: PathBuf,
}

pub fn prev_path(exe: &Path) -> PathBuf {
    let name = exe.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "fat".into());
    exe.with_file_name(format!("{name}.prev"))
}

/// Download, verify and install release `version` over `exe`.
pub fn install(version: &str, exe: &Path) -> Result<Installed> {
    if let Some(why) = managed_by(exe) {
        bail!("not replacing {}: {why}", exe.display());
    }
    let target = target().context("there are no fat releases for this platform")?;
    let key = release_key()?;
    let dir = exe.parent().context("binary has no directory")?;
    // Stage next to the binary so the final rename is atomic (same filesystem).
    let stage = TempDir(dir.join(format!(".fat-update-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&stage.0);
    if let Err(e) = std::fs::create_dir(&stage.0) {
        bail!(
            "can't write to {} ({e}); run `sudo {} update` or install fat somewhere you own",
            dir.display(),
            exe.display()
        );
    }
    let rel = format!("{}/releases/download/v{version}", base().trim_end_matches('/'));
    let sums = download(&format!("{rel}/SHA256SUMS"))?;
    let sig = download(&format!("{rel}/SHA256SUMS.sig")).context(
        "this release has no SHA256SUMS.sig, so it can't be verified; download it by hand from the releases page",
    )?;
    let name = format!("fat-{version}-{target}");
    let archive = download(&format!("{rel}/{name}.tar.gz"))?;
    verify(&key, &sums, &sig, &format!("{name}.tar.gz"), &archive)?;

    let tgz = stage.0.join("fat.tar.gz");
    std::fs::write(&tgz, &archive)?;
    let out = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(&tgz)
        .arg("-C")
        .arg(&stage.0)
        .output()
        .context("running tar")?;
    if !out.status.success() {
        bail!("unpacking {name}.tar.gz failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let new = stage.0.join(&name).join("fat");
    let meta = std::fs::symlink_metadata(&new).with_context(|| format!("{name}.tar.gz has no {name}/fat"))?;
    if !meta.is_file() {
        bail!("{name}/fat in the archive is not a regular file");
    }
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(exe).map(|m| m.permissions().mode() & 0o7777).unwrap_or(0o755) | 0o500;
    std::fs::set_permissions(&new, std::fs::Permissions::from_mode(mode))?;
    let ran = std::process::Command::new(&new)
        .arg("--version")
        .env("FAT_NO_UPDATE_CHECK", "1")
        .output()
        .context("the new binary doesn't run here")?;
    let said = String::from_utf8_lossy(&ran.stdout).trim().to_string();
    if !ran.status.success() || said != format!("fat {version}") {
        bail!("the new binary doesn't run here (it said {said:?})");
    }

    let prev = prev_path(exe);
    let _ = std::fs::remove_file(&prev);
    if std::fs::hard_link(exe, &prev).is_err() {
        std::fs::copy(exe, &prev).with_context(|| format!("keeping the old binary as {}", prev.display()))?;
    }
    std::fs::rename(&new, exe).with_context(|| format!("replacing {}", exe.display()))?;
    Ok(Installed { version: version.to_string(), previous: prev })
}

/// Swap `<exe>.prev` and `exe`. Returns the restored binary's version line.
pub fn rollback(exe: &Path) -> Result<String> {
    let prev = prev_path(exe);
    if !prev.is_file() {
        bail!("there is no previous fat at {}", prev.display());
    }
    let said = std::process::Command::new(&prev)
        .arg("--version")
        .env("FAT_NO_UPDATE_CHECK", "1")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .with_context(|| format!("{} doesn't run", prev.display()))?;
    let tmp = exe.with_file_name(format!(".fat-rollback-{}", std::process::id()));
    std::fs::rename(exe, &tmp).with_context(|| format!("moving {}", exe.display()))?;
    if let Err(e) = std::fs::rename(&prev, exe) {
        let _ = std::fs::rename(&tmp, exe);
        bail!("restoring {}: {e}", prev.display());
    }
    std::fs::rename(&tmp, &prev)?;
    // An automatic update is no longer installed.
    let mut s = load_state();
    s.installed.clear();
    save_state(&s);
    Ok(said)
}

/// Identity of the file at `path`, to notice it being replaced.
pub fn file_id(path: &Path) -> Option<(u64, u64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some((m.dev(), m.ino(), m.mtime()))
}

/// The binary at `path` runs and reports a version.
pub fn runs(path: &Path) -> Option<String> {
    let o = std::process::Command::new(path).arg("--version").env("FAT_NO_UPDATE_CHECK", "1").output().ok()?;
    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
    (o.status.success() && s.starts_with("fat ")).then_some(s)
}

/// An info finding when a newer release is known (from the cached check; no network).
pub fn finding(cfg: &crate::config::Config) -> Option<crate::model::Finding> {
    if check_off_reason(cfg, &|k| std::env::var(k).ok()).is_some() {
        return None;
    }
    let s = load_state();
    let v = s.available()?;
    let (title, action) = match s.installed_newer() {
        Some(i) => (format!("fat {i} is installed; restart fat to use it"), None),
        None => (format!("fat {v} is available (this is {VERSION})"), Some("fat update".to_string())),
    };
    Some(crate::model::Finding {
        severity: "info".into(),
        title,
        detail: format!("{REPO}/releases/tag/v{v}"),
        pids: vec![],
        action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(newer("0.2.0", "0.1.0"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.1.0", "0.2.0"));
        assert!(!newer("0.2.0-rc1", "0.1.0"));
        assert!(!newer("0.2.0", "0.2.0-dev"));
        assert!(!newer("garbage", "0.1.0"));
    }

    #[test]
    fn location_parsing() {
        let r = "https://github.com/o/r/releases/tag/v0.2.0";
        assert_eq!(version_from_location(r).as_deref(), Some("0.2.0"));
        assert_eq!(version_from_location("https://x/releases/tag/1.4.10/").as_deref(), Some("1.4.10"));
        // No releases yet: GitHub redirects to the releases page itself.
        assert_eq!(version_from_location("https://github.com/o/r/releases"), None);
        assert_eq!(version_from_location("https://x/releases/tag/v0.2.0-rc1"), None);
    }

    #[test]
    fn due_once_a_day() {
        let s = State { checked_at: 1_000_000, ..Default::default() };
        assert!(!s.due(1_000_000 + CHECK_EVERY_MS - 1));
        assert!(s.due(1_000_000 + CHECK_EVERY_MS));
        assert!(s.due(0), "a clock that went backwards rechecks");
    }

    #[test]
    fn package_managed_paths_are_left_alone() {
        assert!(managed_by(Path::new("/opt/homebrew/Cellar/fat/0.1.0/bin/fat")).is_some());
        assert!(managed_by(Path::new("/usr/bin/fat")).is_some());
        assert!(managed_by(Path::new("/home/u/src/fat/target/release/fat")).is_some());
        assert!(managed_by(Path::new("/usr/local/bin/fat")).is_none());
        assert!(managed_by(Path::new("/home/u/.local/bin/fat")).is_none());
    }

    fn signed(sums: &str) -> (ed25519_dalek::VerifyingKey, Vec<u8>) {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        (sk.verifying_key(), sk.sign(sums.as_bytes()).to_bytes().to_vec())
    }

    #[test]
    fn verification() {
        use sha2::Digest;
        let data = b"archive bytes";
        let sum = hex(&sha2::Sha256::digest(data));
        let sums = format!("{sum}  fat-0.2.0-x.tar.gz\n{}  other.tar.gz\n", "0".repeat(64));
        let (key, sig) = signed(&sums);
        verify(&key, sums.as_bytes(), &sig, "fat-0.2.0-x.tar.gz", data).unwrap();
        // Tampered archive.
        let e = verify(&key, sums.as_bytes(), &sig, "fat-0.2.0-x.tar.gz", b"evil").unwrap_err();
        assert!(e.to_string().contains("does not match SHA256SUMS"), "{e}");
        // Tampered SHA256SUMS (a matching sum for evil bytes) breaks the signature.
        let evil = sums.replace(&sum, &hex(&sha2::Sha256::digest(b"evil")));
        let e = verify(&key, evil.as_bytes(), &sig, "fat-0.2.0-x.tar.gz", b"evil").unwrap_err();
        assert!(e.to_string().contains("signature"), "{e}");
        // Signed by someone else.
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(verify(&other, sums.as_bytes(), &sig, "fat-0.2.0-x.tar.gz", data).is_err());
        // Not listed.
        assert!(verify(&key, sums.as_bytes(), &sig, "fat-0.2.0-y.tar.gz", data).is_err());
        // Garbage signature.
        assert!(verify(&key, sums.as_bytes(), b"short", "fat-0.2.0-x.tar.gz", data).is_err());
    }

    #[test]
    fn key_hex_round_trip() {
        let vk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let h = hex(vk.as_bytes());
        assert_eq!(key_from_hex(&format!("{}\n{}\n", &h[..32], &h[32..])).unwrap(), vk);
        assert!(key_from_hex("abc").is_err());
    }

    #[test]
    fn checks_can_be_turned_off() {
        let mut cfg = crate::config::Config::default();
        let none = |_: &str| None;
        assert_eq!(check_off_reason(&cfg, &none), None, "on by default");
        assert!(check_off_reason(&cfg, &|k| (k == "FAT_NO_UPDATE_CHECK").then(|| "1".into())).is_some());
        assert_eq!(check_off_reason(&cfg, &|k| (k == "FAT_NO_UPDATE_CHECK").then(|| "0".into())), None);
        cfg.ask.local_only = true;
        assert!(check_off_reason(&cfg, &none).is_some());
        cfg.ask.local_only = false;
        cfg.update.check = false;
        assert!(check_off_reason(&cfg, &none).is_some());
    }

    #[test]
    fn rollback_swaps() {
        let dir = std::env::temp_dir().join(format!("fat-rollback-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("fat");
        use std::os::unix::fs::PermissionsExt;
        for (p, v) in [(&exe, "0.2.0"), (&prev_path(&exe), "0.1.0")] {
            std::fs::write(p, format!("#!/bin/sh\necho fat {v}\n")).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // SAFETY: test-local env var naming a temp file; read back on this thread only.
        unsafe { std::env::set_var("FAT_UPDATE_STATE", dir.join("update.json")) };
        assert_eq!(rollback(&exe).unwrap(), "fat 0.1.0");
        assert_eq!(runs(&exe).as_deref(), Some("fat 0.1.0"));
        assert_eq!(runs(&prev_path(&exe)).as_deref(), Some("fat 0.2.0"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
