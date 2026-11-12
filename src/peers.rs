//! Who is on the other end of a connection: the peer's reverse-DNS name (checked forward,
//! since whoever owns an address chooses its PTR record) and the network (AS) it belongs to.
//!
//! Nothing here ever blocks a sample. [`who`] answers from a cache and queues addresses it
//! has not seen yet; a few worker threads ask the system resolver (`getnameinfo`, so
//! /etc/hosts, the configured DNS servers and split-horizon views all apply). Names arrive a
//! sample or two later.
//!
//! The AS comes from a local copy of the public iptoasn.com table (`ip2asn-combined.tsv.gz`,
//! public domain), downloaded and refreshed weekly in the background. Lookups are offline: no
//! peer address ever leaves the machine for it. `[peers] asn_db` or FAT_ASN_DB points at a
//! copy you provide instead (machines without internet), FAT_ASN_URL at a mirror.
//!
//! Off: `[peers] names = false` / `asn = false`, FAT_NO_PEER_NAMES=1. `[ask] local_only`
//! stops the download (the table can still be provided by path).

use crate::config::Config;
use crate::model::PeerNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

/// Where the table comes from (FAT_ASN_URL overrides: a mirror serving the same file).
const ASN_URL: &str = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";
/// The downloaded table is refreshed when older than this.
const ASN_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// The file is ~8 MB; anything far larger is not it.
const ASN_MAX_BYTES: u64 = 64 << 20;
/// A real table has hundreds of thousands of ranges; fewer than this is a broken file.
const ASN_MIN_ROWS: usize = 1000;
/// Cached names (and "no name") are asked again after these.
const NAME_TTL: Duration = Duration::from_secs(3600);
const MISS_TTL: Duration = Duration::from_secs(15 * 60);
/// A lookup still pending after this is given up and may be queued again.
const PENDING_TTL: Duration = Duration::from_secs(60);
const MAX_CACHED: usize = 20_000;
const WORKERS: usize = 4;
const QUEUE: usize = 512;

#[derive(Debug, Clone, PartialEq)]
struct Settings {
    names: bool,
    asn: bool,
    /// Where the AS table is, and whether fat may download it there.
    table: (PathBuf, bool),
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();

static ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Allow peer lookups in this process (the TUI). Without it [`who`] answers nothing, so
/// one-shot commands never pay for resolving. Nothing starts until [`activate`].
pub fn init(cfg: &Config) {
    if cfg!(test) {
        return; // no resolver threads or downloads from unit tests
    }
    let env = |k: &str| std::env::var(k).ok();
    let _ = SETTINGS.set(Settings { names: names_on(cfg, &env), asn: cfg.peers.asn, table: asn_source(cfg, &env) });
}

/// Start looking peers up: the first time someone looks at connections. Until then no DNS
/// query is made and the AS table (~12 MB in memory) is neither loaded nor downloaded.
pub fn activate() {
    use std::sync::atomic::Ordering;
    let Some(s) = SETTINGS.get() else { return };
    if ACTIVE.swap(true, Ordering::Relaxed) || !s.asn {
        return;
    }
    let (path, download) = s.table.clone();
    let _ = std::thread::Builder::new().name("fat-asn".into()).spawn(move || {
        let _ = crate::tui::guarded(|| load_asn(&path, download));
    });
}

fn names_on(cfg: &Config, env: &dyn Fn(&str) -> Option<String>) -> bool {
    cfg.peers.names && !env("FAT_NO_PEER_NAMES").is_some_and(|v| !v.trim().is_empty() && v.trim() != "0")
}

/// The table's path, and whether fat may download it there.
fn asn_source(cfg: &Config, env: &dyn Fn(&str) -> Option<String>) -> (PathBuf, bool) {
    let given = env("FAT_ASN_DB").filter(|v| !v.trim().is_empty()).or_else(|| {
        let p = cfg.peers.asn_db.trim();
        (!p.is_empty()).then(|| p.to_string())
    });
    match given {
        Some(p) => (PathBuf::from(expand_home(p.trim())), false),
        None => (default_asn_path(), !cfg.ask.local_only),
    }
}

fn expand_home(p: &str) -> String {
    match (p.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(h)) => h.join(rest).to_string_lossy().into_owned(),
        _ => p.to_string(),
    }
}

pub fn default_asn_path() -> PathBuf {
    dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("fat").join("ip2asn-combined.tsv.gz")
}

/// What is known about a peer right now.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Who {
    /// Reverse-DNS name; empty when there is none (yet).
    pub name: String,
    /// The name resolves back to the address.
    pub verified: bool,
    pub net: Option<PeerNet>,
}

/// Answer from the cache, queueing a lookup for addresses not seen yet. Never blocks.
pub fn who(ip: IpAddr) -> Who {
    let Some(s) = SETTINGS.get().filter(|_| ACTIVE.load(std::sync::atomic::Ordering::Relaxed)) else {
        return Who::default();
    };
    let ip = canonical(ip);
    let mut w = Who::default();
    if s.names
        && worth_naming(&ip)
        && let Some((name, verified)) = resolver().get(ip)
    {
        w.name = name;
        w.verified = verified;
    }
    if s.asn && is_public(&ip) {
        w.net = asn_table().and_then(|t| t.lookup(ip));
    }
    w
}

/// `::ffff:a.b.c.d` is the IPv4 address.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        ip => ip,
    }
}

/// Parse the address as shown in a connection group ("10.0.0.9", "[2001:db8::1]").
pub fn parse_shown(s: &str) -> Option<IpAddr> {
    s.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

fn worth_naming(ip: &IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || link_local(ip))
}

fn link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Routed on the internet: the only addresses the AS table knows.
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64/10
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            // Global unicast is 2000::/3; minus documentation 2001:db8::/32.
            (s0 & 0xe000) == 0x2000 && !(s0 == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

// ------------------------------------------------------------------ reverse DNS

enum Entry {
    Pending(Instant),
    Done { name: Option<String>, verified: bool, at: Instant },
}

struct Resolver {
    cache: Mutex<HashMap<IpAddr, Entry>>,
    tx: SyncSender<IpAddr>,
}

fn resolver() -> &'static Resolver {
    static R: OnceLock<Resolver> = OnceLock::new();
    R.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<IpAddr>(QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..WORKERS {
            let rx = rx.clone();
            let _ = std::thread::Builder::new().name(format!("fat-rdns-{i}")).spawn(move || worker(&rx));
        }
        Resolver { cache: Mutex::new(HashMap::new()), tx }
    })
}

fn worker(rx: &Mutex<Receiver<IpAddr>>) {
    loop {
        let ip = match rx.lock() {
            Ok(r) => match r.recv() {
                Ok(ip) => ip,
                Err(_) => return,
            },
            Err(_) => return,
        };
        let (name, verified) = match reverse(ip) {
            Some(n) => {
                let ok = forward_confirms(&n, ip);
                (Some(n), ok)
            }
            None => (None, false),
        };
        if let Ok(mut c) = resolver().cache.lock() {
            c.insert(ip, Entry::Done { name, verified, at: Instant::now() });
        }
    }
}

impl Resolver {
    fn get(&self, ip: IpAddr) -> Option<(String, bool)> {
        let now = Instant::now();
        let mut c = self.cache.lock().ok()?;
        let queue = match c.get(&ip) {
            Some(Entry::Done { name, verified, at }) => {
                let ttl = if name.is_some() { NAME_TTL } else { MISS_TTL };
                let hit = name.clone().map(|n| (n, *verified));
                if now.duration_since(*at) < ttl {
                    return hit;
                }
                // Stale: keep showing it while it is asked again.
                if self.tx.try_send(ip).is_ok() {
                    c.insert(ip, Entry::Pending(now));
                }
                return hit;
            }
            Some(Entry::Pending(at)) => now.duration_since(*at) >= PENDING_TTL,
            None => true,
        };
        if queue {
            if c.len() >= MAX_CACHED {
                prune(&mut c, now);
            }
            match self.tx.try_send(ip) {
                Ok(()) => {
                    c.insert(ip, Entry::Pending(now));
                }
                // Full: asked again on a later sample.
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
            }
        }
        None
    }
}

/// Drop expired entries; if that is not enough, everything finished.
fn prune(c: &mut HashMap<IpAddr, Entry>, now: Instant) {
    c.retain(|_, e| match e {
        Entry::Pending(at) => now.duration_since(*at) < PENDING_TTL,
        Entry::Done { name, at, .. } => now.duration_since(*at) < if name.is_some() { NAME_TTL } else { MISS_TTL },
    });
    if c.len() >= MAX_CACHED {
        c.retain(|_, e| matches!(e, Entry::Pending(_)));
    }
}

/// The address's PTR name through the system resolver (getnameinfo with NI_NAMEREQD).
fn reverse(ip: IpAddr) -> Option<String> {
    let sa: std::net::SocketAddr = (ip, 0).into();
    let mut host = [0 as libc::c_char; 1025];
    // SAFETY: the sockaddr is built from a valid SocketAddr with the right length for its
    // family; `host` is a writable buffer whose length we pass; no service buffer is used.
    let rc = unsafe {
        match sa {
            std::net::SocketAddr::V4(a) => {
                let mut s: libc::sockaddr_in = std::mem::zeroed();
                s.sin_family = libc::AF_INET as libc::sa_family_t;
                s.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
                #[cfg(target_os = "macos")]
                {
                    s.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
                }
                libc::getnameinfo(
                    &s as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            std::net::SocketAddr::V6(a) => {
                let mut s: libc::sockaddr_in6 = std::mem::zeroed();
                s.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                s.sin6_addr.s6_addr = a.ip().octets();
                #[cfg(target_os = "macos")]
                {
                    s.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
                }
                libc::getnameinfo(
                    &s as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    // SAFETY: getnameinfo succeeded, so `host` holds a NUL-terminated string.
    let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }.to_string_lossy().into_owned();
    clean_name(&name, ip)
}

/// Keep a plausible host name: printable, not just the address echoed back.
fn clean_name(name: &str, ip: IpAddr) -> Option<String> {
    let n = name.trim().trim_end_matches('.');
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && n.parse::<IpAddr>().map(|p| canonical(p) != ip).unwrap_or(true);
    ok.then(|| n.to_ascii_lowercase())
}

/// Forward-confirmed reverse DNS: the name resolves back to the address.
fn forward_confirms(name: &str, ip: IpAddr) -> bool {
    use std::net::ToSocketAddrs;
    (name, 0).to_socket_addrs().map(|mut it| it.any(|a| canonical(a.ip()) == ip)).unwrap_or(false)
}

// ------------------------------------------------------------------ AS table

/// Address ranges -> network, both families, sorted by start. Kept compact (~10 MB for the
/// full table): adjacent ranges of one network are merged, IPv6 is matched on the /64 prefix
/// (routing never splits one), and network names live in one string.
#[derive(Debug, Default)]
pub struct AsnTable {
    v4: Vec<(u32, u32, u32)>,
    v6: Vec<(u64, u64, u32)>,
    /// (asn, offset of the name in `text`, its length, country)
    nets: Vec<(u32, u32, u16, [u8; 2])>,
    text: String,
}

impl AsnTable {
    /// Parse iptoasn's TSV: `start end asn country description`. Unrouted ranges (AS 0) and
    /// malformed lines are skipped.
    pub fn parse(r: impl std::io::BufRead) -> AsnTable {
        let mut t = AsnTable::default();
        let mut idx: HashMap<u32, u32> = HashMap::new();
        for line in r.lines() {
            let Ok(line) = line else { break };
            let mut f = line.splitn(5, '\t');
            let (Some(a), Some(b), Some(n), Some(cc), Some(desc)) = (f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            let Ok(asn) = n.trim().parse::<u32>() else { continue };
            if asn == 0 {
                continue;
            }
            let (Ok(a), Ok(b)) = (a.parse::<IpAddr>(), b.parse::<IpAddr>()) else { continue };
            let i = *idx.entry(asn).or_insert_with(|| {
                let name: String = desc.trim().chars().filter(|c| !c.is_control()).take(80).collect();
                // A two-letter code, or nothing ("None", "Unknown" are not countries).
                let cc = cc.trim().as_bytes();
                let c = match cc {
                    [x, y] if x.is_ascii_alphabetic() && y.is_ascii_alphabetic() => {
                        [x.to_ascii_uppercase(), y.to_ascii_uppercase()]
                    }
                    _ => [b' '; 2],
                };
                t.nets.push((asn, t.text.len() as u32, name.len() as u16, c));
                t.text.push_str(&name);
                (t.nets.len() - 1) as u32
            });
            match (a, b) {
                (IpAddr::V4(a), IpAddr::V4(b)) if a <= b => t.v4.push((a.into(), b.into(), i)),
                (IpAddr::V6(a), IpAddr::V6(b)) if a <= b => {
                    t.v6.push(((u128::from(a) >> 64) as u64, (u128::from(b) >> 64) as u64, i))
                }
                _ => {}
            }
        }
        t.v4 = merge(t.v4);
        t.v6 = merge(t.v6);
        t.text.shrink_to_fit();
        t.nets.shrink_to_fit();
        t
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<PeerNet> {
        fn find<T: Ord + Copy>(rows: &[(T, T, u32)], x: T) -> Option<u32> {
            let i = rows.partition_point(|r| r.0 <= x).checked_sub(1)?;
            (rows[i].1 >= x).then_some(rows[i].2)
        }
        let i = match canonical(ip) {
            IpAddr::V4(v4) => find(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => find(&self.v6, (u128::from(v6) >> 64) as u64),
        }?;
        let &(asn, off, len, cc) = self.nets.get(i as usize)?;
        Some(PeerNet {
            asn,
            name: self.text.get(off as usize..off as usize + len as usize).unwrap_or("").to_string(),
            country: String::from_utf8_lossy(&cc).trim().to_string(),
        })
    }
}

/// Sort by start and join ranges of the same network that touch or overlap.
fn merge<T: Ord + Copy + num_succ::Succ>(mut rows: Vec<(T, T, u32)>) -> Vec<(T, T, u32)> {
    rows.sort_unstable_by_key(|r| r.0);
    let mut out: Vec<(T, T, u32)> = Vec::with_capacity(rows.len());
    for r in rows {
        match out.last_mut() {
            Some(l) if l.2 == r.2 && r.0 <= l.1.succ() => l.1 = l.1.max(r.1),
            _ => out.push(r),
        }
    }
    out.shrink_to_fit();
    out
}

mod num_succ {
    /// The next value, saturating (so a range ending at the top still merges correctly).
    pub trait Succ {
        fn succ(self) -> Self;
    }
    impl Succ for u32 {
        fn succ(self) -> Self {
            self.saturating_add(1)
        }
    }
    impl Succ for u64 {
        fn succ(self) -> Self {
            self.saturating_add(1)
        }
    }
}

static TABLE: RwLock<Option<Arc<AsnTable>>> = RwLock::new(None);

fn asn_table() -> Option<Arc<AsnTable>> {
    TABLE.read().ok()?.clone()
}

/// Load the table from disk (if there is one), then download a fresh one when allowed and
/// it is missing or older than a week.
fn load_asn(path: &Path, download: bool) {
    let age = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(|t| SystemTime::now().duration_since(t).unwrap_or_default());
    if age.is_some()
        && let Ok(t) = read_table(path)
    {
        set_table(t);
    }
    if download && age.is_none_or(|a| a >= ASN_MAX_AGE) {
        match fetch_table(path) {
            Ok(t) => set_table(t),
            Err(e) => eprintln_quiet(&format!("fat: AS table download failed: {e}")),
        }
    }
}

fn set_table(t: AsnTable) {
    if let Ok(mut w) = TABLE.write() {
        *w = Some(Arc::new(t));
    }
}

/// The TUI owns the terminal; a background failure must not print over it.
fn eprintln_quiet(_msg: &str) {}

pub fn read_table(path: &Path) -> anyhow::Result<AsnTable> {
    let f = std::fs::File::open(path)?;
    let gz = path.extension().is_some_and(|e| e == "gz");
    let t = if gz {
        AsnTable::parse(std::io::BufReader::new(flate2::read::GzDecoder::new(f)))
    } else {
        AsnTable::parse(std::io::BufReader::new(f))
    };
    anyhow::ensure!(t.len() >= ASN_MIN_ROWS, "{} has only {} ranges: not an ip2asn table", path.display(), t.len());
    Ok(t)
}

/// Download to a temporary file next to `path`, check it parses into a real table, then
/// rename it into place.
fn fetch_table(path: &Path) -> anyhow::Result<AsnTable> {
    use std::io::Read;
    let url = std::env::var("FAT_ASN_URL").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| ASN_URL.into());
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .user_agent(&format!("fat/{}", env!("CARGO_PKG_VERSION")))
        .build();
    let resp = agent.get(&url).call()?;
    let mut data = Vec::new();
    resp.into_reader().take(ASN_MAX_BYTES + 1).read_to_end(&mut data)?;
    anyhow::ensure!((data.len() as u64) <= ASN_MAX_BYTES, "{url} is larger than {} MB", ASN_MAX_BYTES >> 20);
    let t = AsnTable::parse(std::io::BufReader::new(flate2::read::GzDecoder::new(&data[..])));
    anyhow::ensure!(t.len() >= ASN_MIN_ROWS, "{url} did not contain an ip2asn table");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, &data)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(t)
}

/// `fat doctor`: a table you pointed fat at that it cannot use, or a downloaded one that has
/// not been refreshed for a month (the weekly download keeps failing).
pub fn finding(cfg: &Config) -> Option<crate::model::Finding> {
    let env = |k: &str| std::env::var(k).ok();
    if !cfg.peers.asn {
        return None;
    }
    let (path, download) = asn_source(cfg, &env);
    let age_days = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .map(|t| SystemTime::now().duration_since(t).unwrap_or_default().as_secs() / 86400);
    let (title, detail) = if !download {
        match read_table(&path) {
            Ok(_) => return None,
            Err(e) => ("the AS table for connection peers cannot be read".to_string(), e.to_string()),
        }
    } else {
        match age_days {
            Some(d) if d > 30 => (
                format!("the AS table for connection peers is {d} days old"),
                format!("{}: the weekly download from {ASN_URL} keeps failing", path.display()),
            ),
            _ => return None,
        }
    };
    Some(crate::model::Finding { severity: "info".into(), title, detail, pids: vec![], action: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
        1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
        8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n\
        bad line\n\
        2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n\
        9.9.9.0\t9.9.9.255\t19281\tCH\tQUAD9-AS-1\x07\n";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn asn_lookup() {
        let t = AsnTable::parse(SAMPLE.as_bytes());
        assert_eq!(t.len(), 4, "unrouted and malformed lines are skipped");
        assert_eq!(t.nets.len(), 3, "one entry per AS");
        let m = AsnTable::parse(
            "1.0.0.0\t1.0.0.255\t13335\tUS\tCF\n1.0.1.0\t1.0.1.255\t13335\tUS\tCF\n1.0.2.0\t1.0.2.255\t1\tUS\tX\n"
                .as_bytes(),
        );
        assert_eq!(m.v4.len(), 2, "adjacent ranges of one network merge");
        let g = t.lookup(ip("8.8.8.8")).unwrap();
        assert_eq!((g.asn, g.name.as_str(), g.country.as_str()), (15169, "GOOGLE", "US"));
        assert_eq!(t.lookup(ip("1.0.0.0")).unwrap().asn, 13335);
        assert_eq!(t.lookup(ip("1.0.0.255")).unwrap().asn, 13335);
        assert!(t.lookup(ip("1.0.2.1")).is_none(), "not routed");
        assert!(t.lookup(ip("8.8.9.1")).is_none(), "between ranges");
        assert!(t.lookup(ip("0.0.0.1")).is_none(), "before the first range");
        assert_eq!(t.lookup(ip("2001:4860:4860::8888")).unwrap().asn, 15169);
        assert_eq!(t.lookup(ip("::ffff:8.8.8.8")).unwrap().asn, 15169, "v4-mapped");
        assert_eq!(t.lookup(ip("9.9.9.9")).unwrap().name, "QUAD9-AS-1", "control characters dropped");
        assert_eq!(t.lookup(ip("9.9.9.9")).unwrap().country, "CH");
    }

    #[test]
    fn public_addresses() {
        for p in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public(&canonical(ip(p))), "{p}");
        }
        for p in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "255.255.255.255",
            "0.0.0.0",
        ] {
            assert!(!is_public(&canonical(ip(p))), "{p}");
        }
    }

    #[test]
    fn names_are_cleaned() {
        let a = ip("8.8.8.8");
        assert_eq!(clean_name("dns.google.", a).as_deref(), Some("dns.google"));
        assert_eq!(clean_name("Host-1.Example.COM", a).as_deref(), Some("host-1.example.com"));
        assert_eq!(clean_name("8.8.8.8", a), None, "the address echoed back");
        assert_eq!(clean_name("evil\x1b[31m.com", a), None, "escape sequences");
        assert_eq!(clean_name("", a), None);
        assert!(worth_naming(&ip("10.0.0.1")) && !worth_naming(&ip("127.0.0.1")) && !worth_naming(&ip("fe80::1")));
    }

    #[test]
    fn shown_addresses_parse() {
        assert_eq!(parse_shown("10.0.0.9"), Some(ip("10.0.0.9")));
        assert_eq!(parse_shown("[2001:db8::1]"), Some(ip("2001:db8::1")));
        assert_eq!(parse_shown("*"), None);
    }

    #[test]
    fn switches() {
        let mut cfg = Config::default();
        let none = |_: &str| None;
        assert!(names_on(&cfg, &none));
        assert!(!names_on(&cfg, &|k: &str| (k == "FAT_NO_PEER_NAMES").then(|| "1".into())));
        assert!(names_on(&cfg, &|k: &str| (k == "FAT_NO_PEER_NAMES").then(|| "0".into())));
        cfg.peers.names = false;
        assert!(!names_on(&cfg, &none));
        let cfg = Config::default();
        assert!(asn_source(&cfg, &none).1, "downloads by default");
        let mut lo = Config::default();
        lo.ask.local_only = true;
        assert!(!asn_source(&lo, &none).1, "local_only: no download");
        let (p, dl) = asn_source(&cfg, &|k: &str| (k == "FAT_ASN_DB").then(|| "/srv/ip2asn.tsv".into()));
        assert_eq!((p, dl), (PathBuf::from("/srv/ip2asn.tsv"), false), "a given table is never overwritten");
    }

    #[test]
    fn short_files_are_refused() {
        let dir = std::env::temp_dir().join(format!("fat-asn-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.tsv");
        std::fs::write(&p, SAMPLE).unwrap();
        assert!(read_table(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Network: downloads the real table (into a temporary directory) and asks the real resolver.
    #[test]
    #[ignore = "network: downloads the iptoasn.com table and does reverse DNS"]
    fn live_table_and_names() {
        let dir = std::env::temp_dir().join(format!("fat-asn-live-{}", std::process::id()));
        let path = dir.join("ip2asn-combined.tsv.gz");
        let t = fetch_table(&path).expect("download");
        assert!(t.len() > 100_000, "{} ranges", t.len());
        eprintln!(
            "ranges: v4 {} v6 {}, networks {}, names {} bytes",
            t.v4.len(),
            t.v6.len(),
            t.nets.len(),
            t.text.len()
        );
        let back = read_table(&path).expect("read back");
        assert_eq!(back.len(), t.len());
        assert_eq!(t.lookup(ip("8.8.8.8")).map(|n| n.asn), Some(15169));
        assert_eq!(t.lookup(ip("1.1.1.1")).map(|n| n.asn), Some(13335));
        assert_eq!(t.lookup(ip("2001:4860:4860::8888")).map(|n| n.asn), Some(15169));
        let name = reverse(ip("8.8.8.8")).expect("PTR for 8.8.8.8");
        assert_eq!(name, "dns.google");
        assert!(forward_confirms(&name, ip("8.8.8.8")));
        assert!(!forward_confirms(&name, ip("1.1.1.1")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
