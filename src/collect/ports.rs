//! Listening sockets -> owning pid, orphan heuristic. OWNER: ports-net agent (macOS source:
//! native-macos agent).
//!
//! macOS: no subprocess. libproc (`proc_listpids` + `PROC_PIDLISTFDS` + `PROC_PIDFDSOCKETINFO`,
//! see `sys::darwin::libproc`) lists every socket fd of every process we may inspect, with its
//! protocol, TCP state and local address; TCP sockets in LISTEN and bound UDP sockets without a
//! peer are kept. Without root that is the current user's processes, exactly what `lsof` showed.
//! Only if the native call fails does it fall back to
//! `lsof -nP -iTCP -sTCP:LISTEN -iUDP -FpcRnPT` (its `-F` field output is line-oriented: `p` pid,
//! `c` command, `R` ppid, `f` fd, `P` protocol, `n` name/address, `T` TCP info like `ST=LISTEN`).
//!
//! Linux: no subprocess. Sockets come from `/proc/net/{tcp,tcp6,udp,udp6}` (see
//! [`linux`]); owners from `/proc/<pid>/fd/*` symlinks `socket:[inode]`. Without
//! root only our own processes' fds are readable, so other users' listeners are
//! still listed but with pid 0, process "?" and a note "owner hidden (needs root)".
//! `/proc/net/*` is per network namespace, so besides our own we read
//! `/proc/<pid>/net/*` of one process per other netns we can see (`/proc/<pid>/ns/net`;
//! every container's when root), and tag those ports with their container. Socket inodes
//! are unique system-wide, so owners still come from one fd walk. That walk skips
//! processes whose fds we can't read and stops once only unreadable owners remain; on
//! Linux the scan refreshes in the background and callers get the cached list.
use crate::model::{Port, Proc, Proto};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hard deadline for the lsof fallback; the whole `ports()` must stay < 400ms.
#[cfg_attr(target_os = "linux", allow(dead_code))]
const LSOF_TIMEOUT: Duration = Duration::from_millis(350);
/// Raw socket list is reused for this long between calls. Listening sockets change rarely; the
/// native macOS scan costs a few ms of CPU (the old `lsof` run ~40ms), the Linux fd walk more.
const CACHE_TTL: Duration = Duration::from_secs(5);

/// One socket as reported by lsof, before annotation.
#[derive(Debug, Clone, PartialEq)]
struct RawSock {
    pid: u32,
    ppid: u32,
    command: String,
    proto: Proto,
    addr: String,
    port: u16,
    state: String,
    /// Linux only: socket owner uid when the owning pid could not be found
    /// (another user's process without root). None on macOS / when pid is known.
    hidden_uid: Option<u32>,
    /// Linux only: the socket lives in another network namespace than fat's (a container).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    foreign_ns: bool,
}

static CACHE: Mutex<Option<(Instant, Vec<RawSock>)>> = Mutex::new(None);

/// List TCP listeners and bound UDP sockets, annotated with notes and orphan flags.
pub fn ports(procs: &[Proc]) -> Vec<Port> {
    let raw = cached_raw();
    let by_pid: HashMap<u32, &Proc> = procs.iter().map(|p| (p.pid, p)).collect();
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let home = dirs::home_dir().map(|h| h.to_string_lossy().into_owned());
    #[cfg(target_os = "linux")]
    {
        linux::annotate(&raw, &by_pid, now, home.as_deref())
    }
    #[cfg(not(target_os = "linux"))]
    {
        annotate(&raw, &by_pid, now, home.as_deref())
    }
}

/// Fetch the raw socket list from the platform source (uncached).
#[cfg(target_os = "macos")]
fn fetch_raw() -> Vec<RawSock> {
    if !crate::sys::force_fallback()
        && let Some(l) = crate::sys::darwin::libproc::listeners()
    {
        crate::sys::note_source("ports", "libproc");
        return dedup(l.iter().map(from_listener).collect());
    }
    crate::sys::note_source("ports", "lsof");
    run_lsof().map(|out| dedup(parse_lsof(&out))).unwrap_or_default()
}

/// libproc listener -> the same RawSock the lsof parser produces ("*" wildcard, "[v6]").
#[cfg(target_os = "macos")]
fn from_listener(l: &crate::sys::darwin::libproc::Listener) -> RawSock {
    let addr = match l.addr {
        a if a.is_unspecified() => "*".to_string(),
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
    };
    RawSock {
        pid: l.pid,
        ppid: l.ppid,
        command: l.comm.clone(),
        proto: if l.tcp { Proto::Tcp } else { Proto::Udp },
        addr,
        port: l.port,
        state: if l.tcp { "LISTEN".into() } else { String::new() },
        hidden_uid: None,
        foreign_ns: false,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fetch_raw() -> Vec<RawSock> {
    run_lsof().map(|out| dedup(parse_lsof(&out))).unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn fetch_raw() -> Vec<RawSock> {
    dedup(linux::scan(std::path::Path::new("/proc")))
}

/// A background refresh of the Linux socket scan is running.
#[cfg(target_os = "linux")]
static REFRESHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg_attr(not(target_os = "linux"), allow(clippy::collapsible_if))]
fn cached_raw() -> Vec<RawSock> {
    if let Ok(guard) = CACHE.lock()
        && let Some((at, socks)) = guard.as_ref()
    {
        if at.elapsed() < CACHE_TTL {
            return socks.clone();
        }
        // Linux: the fd walk can take a while on a busy box; refresh it off the sampling
        // thread and serve the previous list meanwhile (listeners change rarely).
        #[cfg(target_os = "linux")]
        {
            use std::sync::atomic::Ordering;
            if !REFRESHING.swap(true, Ordering::SeqCst) {
                let spawned = std::thread::Builder::new().name("fat-ports".into()).spawn(|| {
                    let socks = fetch_raw();
                    if let Ok(mut guard) = CACHE.lock() {
                        *guard = Some((Instant::now(), socks));
                    }
                    REFRESHING.store(false, Ordering::SeqCst);
                });
                if spawned.is_err() {
                    REFRESHING.store(false, Ordering::SeqCst);
                }
            }
            return socks.clone();
        }
    }
    let socks = fetch_raw();
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((Instant::now(), socks.clone()));
    }
    socks
}

/// Run lsof with a deadline (fallback). None if lsof is missing or times out.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn run_lsof() -> Option<String> {
    // lsof exits 1 when some selectors match nothing; its output is still valid.
    crate::sys::run_fallback("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-FpcRnPT"], LSOF_TIMEOUT)
}

/// Parse lsof `-F` output into sockets. Unknown fields are ignored; sockets with
/// no concrete local port (e.g. UDP `*:*`) and connected UDP sockets are skipped.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn parse_lsof(out: &str) -> Vec<RawSock> {
    struct FdAcc {
        proto: Option<Proto>,
        name: Option<String>,
        state: String,
    }
    fn flush(fd: &mut Option<FdAcc>, pid: u32, ppid: u32, cmd: &str, out: &mut Vec<RawSock>) {
        let Some(f) = fd.take() else { return };
        let (Some(proto), Some(name)) = (f.proto, f.name) else { return };
        // Connected UDP sockets are clients (e.g. QUIC), not bound services.
        if proto == Proto::Udp && name.contains("->") {
            return;
        }
        let local = name.split("->").next().unwrap_or(&name);
        let Some((addr, port)) = split_addr(local) else { return };
        if proto == Proto::Tcp && f.state != "LISTEN" {
            return;
        }
        out.push(RawSock {
            pid,
            ppid,
            command: cmd.to_string(),
            proto,
            addr,
            port,
            state: if proto == Proto::Tcp { f.state } else { String::new() },
            hidden_uid: None,
            foreign_ns: false,
        });
    }

    let mut socks = Vec::new();
    let (mut pid, mut ppid, mut cmd) = (0u32, 0u32, String::new());
    let mut fd: Option<FdAcc> = None;
    for line in out.lines() {
        let mut chars = line.chars();
        let Some(tag) = chars.next() else { continue };
        let val = chars.as_str();
        match tag {
            'p' => {
                flush(&mut fd, pid, ppid, &cmd, &mut socks);
                pid = val.parse().unwrap_or(0);
                ppid = 0;
                cmd.clear();
            }
            'R' => ppid = val.parse().unwrap_or(0),
            'c' => cmd = val.to_string(),
            'f' => {
                flush(&mut fd, pid, ppid, &cmd, &mut socks);
                fd = Some(FdAcc { proto: None, name: None, state: String::new() });
            }
            'P' => {
                if let Some(f) = fd.as_mut() {
                    f.proto = match val {
                        "TCP" => Some(Proto::Tcp),
                        "UDP" => Some(Proto::Udp),
                        _ => None,
                    };
                }
            }
            'n' => {
                if let Some(f) = fd.as_mut() {
                    f.name = Some(val.to_string());
                }
            }
            'T' => {
                if let (Some(f), Some(st)) = (fd.as_mut(), val.strip_prefix("ST=")) {
                    f.state = st.to_string();
                }
            }
            _ => {}
        }
    }
    flush(&mut fd, pid, ppid, &cmd, &mut socks);
    socks
}

/// "127.0.0.1:8080" / "[::1]:5432" / "*:7000" -> (readable addr, port).
fn split_addr(s: &str) -> Option<(String, u16)> {
    let (addr, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let addr = match addr {
        "*" | "0.0.0.0" | "[::]" | "" => "*".to_string(),
        a => a.to_string(),
    };
    Some((addr, port))
}

/// Lower is more readable / more general: wildcard, then IPv4, then IPv6.
fn addr_rank(addr: &str) -> u8 {
    if addr == "*" {
        0
    } else if addr.starts_with('[') {
        2
    } else {
        1
    }
}

/// Collapse IPv4/IPv6 (and duplicate fd) entries per (proto, port, pid), keeping
/// the most readable address. Output is sorted: TCP first, then by port, pid.
fn dedup(socks: Vec<RawSock>) -> Vec<RawSock> {
    let mut best: HashMap<(Proto, u16, u32), RawSock> = HashMap::new();
    for s in socks {
        let key = (s.proto, s.port, s.pid);
        match best.get(&key) {
            Some(cur) if addr_rank(&cur.addr) <= addr_rank(&s.addr) => {}
            _ => {
                best.insert(key, s);
            }
        }
    }
    let mut out: Vec<RawSock> = best.into_values().collect();
    out.sort_by_key(|s| (s.proto == Proto::Udp, s.port, s.pid));
    out
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn annotate(raw: &[RawSock], procs: &HashMap<u32, &Proc>, now: u64, home: Option<&str>) -> Vec<Port> {
    raw.iter()
        .map(|s| {
            let p = procs.get(&s.pid).copied();
            let name = p.map(|p| p.name.as_str()).filter(|n| !n.is_empty()).unwrap_or(&s.command);
            let ppid = p.map(|p| p.ppid).unwrap_or(s.ppid);
            let cmd = p.map(|p| p.cmd.as_str()).unwrap_or("");
            let exe = p.map(|p| p.exe.as_str()).unwrap_or("");
            let cwd = p.map(|p| p.cwd.as_str()).unwrap_or("");
            let start = p.map(|p| p.start_time).unwrap_or(0);
            Port {
                proto: s.proto,
                addr: s.addr.clone(),
                port: s.port,
                pid: s.pid,
                process: name.to_string(),
                state: s.state.clone(),
                orphan: is_orphan(ppid, name, exe, cmd, home),
                note: describe(name, cmd, cwd, start, now, home),
            }
        })
        .collect()
}

/// Infer a framework / server hint from the command line. Ordered most-specific first.
fn framework_hint(name: &str, cmd: &str) -> Option<&'static str> {
    let c = if cmd.is_empty() { name.to_lowercase() } else { cmd.to_lowercase() };
    const HINTS: &[(&str, &str)] = &[
        ("next dev", "next dev"),
        ("next-server", "next server"),
        ("next start", "next start"),
        ("vite", "vite dev"),
        ("webpack", "webpack dev server"),
        ("nuxt", "nuxt"),
        ("astro", "astro dev"),
        ("remix", "remix"),
        ("storybook", "storybook"),
        ("parcel", "parcel"),
        ("esbuild", "esbuild"),
        ("nodemon", "nodemon"),
        ("ts-node", "ts-node"),
        ("tsx watch", "tsx watch"),
        ("manage.py runserver", "django runserver"),
        ("runserver", "django runserver"),
        ("uvicorn", "uvicorn"),
        ("gunicorn", "gunicorn"),
        ("hypercorn", "hypercorn"),
        ("flask", "flask"),
        ("fastapi", "fastapi"),
        ("streamlit", "streamlit"),
        ("gradio", "gradio"),
        ("http.server", "python http.server"),
        ("jupyter", "jupyter"),
        ("ipykernel", "jupyter kernel"),
        ("rails", "rails"),
        ("puma", "puma"),
        ("unicorn", "unicorn"),
        ("artisan serve", "laravel"),
        ("php -s", "php server"),
        ("hugo", "hugo"),
        ("jekyll", "jekyll"),
        ("mix phx.server", "phoenix"),
        ("spring-boot", "spring boot"),
        ("gradle", "gradle"),
        ("postgres", "postgres"),
        ("redis-server", "redis"),
        ("mysqld", "mysql"),
        ("mongod", "mongodb"),
        ("memcached", "memcached"),
        ("ollama", "ollama"),
        ("llama-server", "llama.cpp server"),
        ("docker-proxy", "docker-proxy"),
        ("com.docker", "docker"),
        ("orbstack", "orbstack"),
        ("nginx", "nginx"),
        ("caddy", "caddy"),
        ("cargo-watch", "cargo watch"),
        ("/target/debug/", "cargo debug build"),
        ("/target/release/", "cargo release build"),
    ];
    HINTS.iter().find(|(needle, _)| c.contains(needle)).map(|(_, hint)| *hint)
}

fn tilde(path: &str, home: Option<&str>) -> String {
    match home {
        Some(h) if !h.is_empty() && path == h => "~".to_string(),
        Some(h) if !h.is_empty() && path.starts_with(&format!("{h}/")) => format!("~{}", &path[h.len()..]),
        _ => path.to_string(),
    }
}

fn fmt_age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

/// "node · vite dev · ~/code/app · up 3h"
fn describe(name: &str, cmd: &str, cwd: &str, start: u64, now: u64, home: Option<&str>) -> String {
    let mut parts = vec![name.to_string()];
    if let Some(h) = framework_hint(name, cmd) {
        parts.push(h.to_string());
    }
    if !cwd.is_empty() && cwd != "/" {
        parts.push(tilde(cwd, home));
    }
    if start > 0 && now >= start {
        parts.push(format!("up {}", fmt_age(now - start)));
    }
    parts.join(" · ")
}

/// Orphan heuristic. A listener is flagged as an orphan when ALL of:
///
/// 1. `ppid == 1`: it was re-parented to launchd, i.e. the terminal, shell, IDE,
///    or agent that started it has gone away but the server kept running.
/// 2. It looks like a dev server / language runtime: the process name is a
///    known runtime (node, bun, deno, python*, ruby, java, php, beam, dotnet...),
///    OR the executable is a cargo build product (`/target/debug/`,
///    `/target/release/`), OR the executable lives inside the user's home
///    directory outside `~/Library` / `~/Applications` (e.g. a `go build`
///    binary sitting in a project dir).
/// 3. It is NOT a launchd-managed system/app agent: the executable is not
///    under `/System`, `/usr/libexec`, `/usr/sbin`, `/Library`, or inside an
///    installed app bundle (`/Applications/*.app/Contents`, `~/Applications/...`).
///    Those are legitimately parented by launchd.
///
/// Homebrew services (postgres, redis under /opt/homebrew) are also launchd
/// children but are not runtimes, so they are deliberately not flagged.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn is_orphan(ppid: u32, name: &str, exe: &str, cmd: &str, home: Option<&str>) -> bool {
    if ppid != 1 {
        return false;
    }
    const SYSTEM_PREFIXES: &[&str] = &["/System/", "/usr/libexec/", "/usr/sbin/", "/Library/"];
    // App bundles count only when installed as apps: Homebrew's Python lives in
    // `.../Python.framework/.../Python.app/Contents/MacOS/Python` and must still match.
    let in_app_bundle = exe.contains(".app/Contents/")
        && (exe.starts_with("/Applications/")
            || home.is_some_and(|h| !h.is_empty() && exe.starts_with(&format!("{h}/Applications/"))));
    if SYSTEM_PREFIXES.iter().any(|p| exe.starts_with(p)) || in_app_bundle {
        return false;
    }
    let base = exe.rsplit('/').next().filter(|b| !b.is_empty()).unwrap_or(name).to_lowercase();
    let lname = name.to_lowercase();
    const RUNTIMES: &[&str] = &["node", "bun", "deno", "ruby", "java", "php", "beam.smp", "dotnet", "elixir", "erl"];
    let is_runtime = |n: &str| {
        RUNTIMES.contains(&n) || n.starts_with("python") || n.starts_with("node") && n.len() <= 6
    };
    if is_runtime(&base) || is_runtime(&lname) {
        return true;
    }
    let path = if exe.is_empty() { cmd.split_whitespace().next().unwrap_or("") } else { exe };
    if path.contains("/target/debug/") || path.contains("/target/release/") {
        return true;
    }
    if let Some(h) = home.filter(|h| !h.is_empty()) {
        let in_home = path.starts_with(&format!("{h}/"));
        let excluded = path.starts_with(&format!("{h}/Library/")) || path.starts_with(&format!("{h}/Applications/"));
        if in_home && !excluded {
            return true;
        }
    }
    false
}

/// One pid per other network namespace (containers): (netns inode, pid). Linux only.
#[cfg(target_os = "linux")]
pub fn foreign_netns(limit: usize) -> Vec<(u64, u32)> {
    linux::foreign_netns(std::path::Path::new("/proc"), limit)
}

/// The /proc/*/fd owner walk, shared with the network sampler.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
pub(super) use linux::{can_read_all_fds, socket_owners_uid};

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux {
    //! Linux listening-socket discovery straight from procfs (no lsof, no root needed).
    //!
    //! `/proc/net/tcp` (and tcp6/udp/udp6) look like this (Linux 6.x, little-endian):
    //!
    //! ```text
    //!   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    //!    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 8713261 1 0000000000000000 100 0 0 10 0
    //!    1: 0100007F:B4B8 0100007F:46A1 01 00000000:000186A0 00:00000000 00000000     0        0 8711508 2 0000000000000000 20 8 0 10 -1
    //! ```
    //!
    //! Addresses are the in-memory `__be32` words printed with `%08X` in host byte
    //! order, so `0100007F` on little-endian is 127.0.0.1; IPv6 is four such words.
    //! The port is plain big-endian hex. TCP state `0A` = LISTEN; bound (unconnected)
    //! UDP sockets show state `07` with remote port 0. Column 7 is the owner uid and
    //! column 9 the socket inode, which we match against `/proc/<pid>/fd/*` symlinks
    //! of the form `socket:[8713261]`.
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::Path;

    const TCP_LISTEN: u8 = 0x0A;

    /// One row of /proc/net/{tcp,udp}[6].
    #[derive(Debug, Clone, PartialEq)]
    pub struct NetRow {
        pub local: IpAddr,
        pub port: u16,
        pub rem_port: u16,
        pub state: u8,
        pub uid: u32,
        pub inode: u64,
    }

    /// Decode a procfs hex address (8 hex chars for IPv4, 32 for IPv6).
    pub fn decode_addr(hex: &str) -> Option<IpAddr> {
        let word = |h: &str| u32::from_str_radix(h, 16).ok().map(u32::to_ne_bytes);
        match hex.len() {
            8 => Some(IpAddr::V4(Ipv4Addr::from(word(hex)?))),
            32 => {
                let mut b = [0u8; 16];
                for i in 0..4 {
                    b[i * 4..i * 4 + 4].copy_from_slice(&word(hex.get(i * 8..i * 8 + 8)?)?);
                }
                Some(IpAddr::V6(Ipv6Addr::from(b)))
            }
            _ => None,
        }
    }

    fn split_hex_endpoint(s: &str) -> Option<(IpAddr, u16)> {
        let (a, p) = s.split_once(':')?;
        Some((decode_addr(a)?, u16::from_str_radix(p, 16).ok()?))
    }

    /// Parse a whole /proc/net/{tcp,udp}[6] file. Header and malformed rows are skipped.
    pub fn parse_proc_net(text: &str) -> Vec<NetRow> {
        text.lines()
            .filter_map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 10 || !f[0].ends_with(':') {
                    return None;
                }
                let (local, port) = split_hex_endpoint(f[1])?;
                let (_, rem_port) = split_hex_endpoint(f[2])?;
                Some(NetRow {
                    local,
                    port,
                    rem_port,
                    state: u8::from_str_radix(f[3], 16).ok()?,
                    uid: f[7].parse().ok()?,
                    inode: f[9].parse().ok()?,
                })
            })
            .collect()
    }

    /// Same readable form as the lsof path: "*" for wildcard, IPv4-mapped IPv6 shown as
    /// IPv4 (so v4/v6 dual-stack listeners dedup), other IPv6 bracketed.
    pub fn fmt_addr(ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(v4) if v4.is_unspecified() => "*".into(),
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) if v6.is_unspecified() => "*".into(),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if v4.is_unspecified() => "*".into(),
                Some(v4) => v4.to_string(),
                None => format!("[{v6}]"),
            },
        }
    }

    /// Whether we may read any process's fds (/proc/<pid>/fd needs ptrace-read access:
    /// CAP_SYS_PTRACE, which root has except in a default container). Otherwise only
    /// processes of our own euid are readable.
    pub fn can_read_all_fds(proc_root: &Path) -> bool {
        const CAP_SYS_PTRACE: u32 = 19;
        std::fs::read_to_string(proc_root.join("self/status"))
            .ok()
            .and_then(|t| t.lines().find_map(|l| l.strip_prefix("CapEff:")).and_then(|v| u64::from_str_radix(v.trim(), 16).ok()))
            .is_some_and(|caps| caps & (1 << CAP_SYS_PTRACE) != 0)
    }

    /// Map socket inode -> owning pid by reading `/proc/<pid>/fd/*` links. `wanted` maps
    /// each inode to its socket's uid (from /proc/net/*). Pids are visited in ascending order
    /// so a socket shared after fork (gunicorn master + workers) is attributed to the lowest
    /// pid, usually the parent. `readable_uid(uid)`: whether we could read the fds of a
    /// process of that uid; processes we can't read are skipped without a syscall on their
    /// fd dir, and the walk stops as soon as every wanted inode is found *or* every one still
    /// missing belongs to a uid whose processes we can't read (e.g. root's sshd, unprivileged).
    pub fn socket_owners_uid(proc_root: &Path, wanted: &HashMap<u64, u32>, readable_uid: &dyn Fn(u32) -> bool) -> HashMap<u64, u32> {
        use std::os::unix::fs::MetadataExt;
        let mut found = HashMap::new();
        let mut left_readable = wanted.values().filter(|&&u| readable_uid(u)).count();
        if wanted.is_empty() || left_readable == 0 {
            return found;
        }
        let Ok(rd) = std::fs::read_dir(proc_root) else { return found };
        let mut pids: Vec<u32> = rd
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        pids.sort_unstable();
        for pid in pids {
            let dir = proc_root.join(pid.to_string());
            // A process of a uid we can't read: skip (its fd dir would be EACCES anyway).
            if let Ok(m) = std::fs::metadata(&dir)
                && !readable_uid(m.uid())
            {
                continue;
            }
            let Ok(fds) = std::fs::read_dir(dir.join("fd")) else { continue };
            for fd in fds.flatten() {
                let Ok(target) = std::fs::read_link(fd.path()) else { continue };
                let Some(ino) = target
                    .to_str()
                    .and_then(|t| t.strip_prefix("socket:["))
                    .and_then(|t| t.strip_suffix(']'))
                    .and_then(|t| t.parse::<u64>().ok())
                else {
                    continue;
                };
                if let Some(&uid) = wanted.get(&ino)
                    && !found.contains_key(&ino)
                {
                    found.insert(ino, pid);
                    if readable_uid(uid) {
                        left_readable -= 1;
                    }
                }
            }
            if found.len() == wanted.len() || left_readable == 0 {
                break;
            }
        }
        found
    }

    /// Map socket inode -> owning pid, reading every fd dir we can (no uid shortcut).
    #[allow(dead_code)]
    pub fn socket_owners(proc_root: &Path, wanted: &HashSet<u64>) -> HashMap<u64, u32> {
        let w: HashMap<u64, u32> = wanted.iter().map(|&i| (i, 0)).collect();
        socket_owners_uid(proc_root, &w, &|_| true)
    }

    /// One pid per network namespace other than ours whose `ns/net` link we can read
    /// (same uid, or root): (netns inode, pid), lowest pid first, at most `limit`.
    pub fn foreign_netns(proc_root: &Path, limit: usize) -> Vec<(u64, u32)> {
        let ns_of = |p: &Path| -> Option<u64> {
            let t = std::fs::read_link(p.join("ns/net")).ok()?;
            t.to_str()?.strip_prefix("net:[")?.strip_suffix(']')?.parse().ok()
        };
        let Some(ours) = ns_of(&proc_root.join("self")) else { return Vec::new() };
        let Ok(rd) = std::fs::read_dir(proc_root) else { return Vec::new() };
        let mut pids: Vec<u32> = rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect();
        pids.sort_unstable();
        let mut seen: HashSet<u64> = HashSet::from([ours]);
        let mut out = Vec::new();
        for pid in pids {
            if let Some(ns) = ns_of(&proc_root.join(pid.to_string()))
                && seen.insert(ns)
            {
                out.push((ns, pid));
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }

    /// (comm, ppid) from /proc/<pid>/stat. comm may contain spaces and ')'.
    pub fn read_stat(proc_root: &Path, pid: u32) -> Option<(String, u32)> {
        let s = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
        let open = s.find('(')?;
        let close = s.rfind(')')?;
        let comm = s.get(open + 1..close)?.to_string();
        let ppid = s.get(close + 1..)?.split_whitespace().nth(1)?.parse().ok()?;
        Some((comm, ppid))
    }

    /// cgroup v2 path ("0::/user.slice/...") from /proc/<pid>/cgroup.
    pub fn read_cgroup(proc_root: &Path, pid: u32) -> String {
        std::fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup"))
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("0::").map(str::to_string)))
            .unwrap_or_default()
    }

    /// Most other network namespaces scanned per refresh (each costs four small reads).
    const MAX_NETNS: usize = 64;

    /// Listening TCP + bound UDP sockets of our network namespace and of every other one we
    /// can see (containers), with owners.
    pub fn scan(proc_root: &Path) -> Vec<RawSock> {
        let all = can_read_all_fds(proc_root);
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        scan_with(proc_root, &|uid| all || uid == me)
    }

    /// [`scan`] with an explicit "can we read fds of a process of this uid" test.
    pub fn scan_with(proc_root: &Path, readable_uid: &dyn Fn(u32) -> bool) -> Vec<RawSock> {
        let mut rows: Vec<(Proto, NetRow, bool)> = Vec::new();
        let mut seen_ino: HashSet<u64> = HashSet::new();
        let mut read_ns = |net: &Path, foreign: bool, rows: &mut Vec<(Proto, NetRow, bool)>| {
            for (file, proto) in [("tcp", Proto::Tcp), ("tcp6", Proto::Tcp), ("udp", Proto::Udp), ("udp6", Proto::Udp)] {
                let Ok(text) = std::fs::read_to_string(net.join(file)) else { continue };
                for r in parse_proc_net(&text) {
                    let keep = match proto {
                        Proto::Tcp => r.state == TCP_LISTEN,
                        // Connected UDP sockets are clients (QUIC, DNS lookups), not services.
                        Proto::Udp => r.rem_port == 0,
                    };
                    // Inodes are unique system-wide: a row seen twice is the same socket.
                    if keep && r.port != 0 && (r.inode == 0 || seen_ino.insert(r.inode)) {
                        rows.push((proto, r, foreign));
                    }
                }
            }
        };
        read_ns(&proc_root.join("net"), false, &mut rows);
        for (_, pid) in foreign_netns(proc_root, MAX_NETNS) {
            read_ns(&proc_root.join(pid.to_string()).join("net"), true, &mut rows);
        }
        let wanted: HashMap<u64, u32> = rows.iter().filter(|(_, r, _)| r.inode != 0).map(|(_, r, _)| (r.inode, r.uid)).collect();
        let owners = socket_owners_uid(proc_root, &wanted, readable_uid);
        let mut stat_cache: HashMap<u32, Option<(String, u32)>> = HashMap::new();
        rows.into_iter()
            .map(|(proto, r, foreign_ns)| {
                let pid = owners.get(&r.inode).copied().unwrap_or(0);
                let (command, ppid) = if pid == 0 {
                    ("?".to_string(), 0)
                } else {
                    stat_cache.entry(pid).or_insert_with(|| read_stat(proc_root, pid)).clone().unwrap_or_default()
                };
                RawSock {
                    pid,
                    ppid,
                    command,
                    proto,
                    addr: fmt_addr(r.local),
                    port: r.port,
                    state: if proto == Proto::Tcp { "LISTEN".into() } else { String::new() },
                    hidden_uid: (pid == 0).then_some(r.uid),
                    foreign_ns,
                }
            })
            .collect()
    }

    /// uid -> login name from /etc/passwd (no NSS; good enough for a hint).
    fn user_of(uid: u32) -> Option<String> {
        let text = std::fs::read_to_string("/etc/passwd").ok()?;
        text.lines().find_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let id: u32 = f.nth(1)?.parse().ok()?;
            (id == uid).then(|| name.to_string())
        })
    }

    pub fn annotate(raw: &[RawSock], procs: &HashMap<u32, &Proc>, now: u64, home: Option<&str>) -> Vec<Port> {
        let root = Path::new("/proc");
        let mut users: HashMap<u32, Option<String>> = HashMap::new();
        raw.iter()
            .map(|s| {
                if s.pid == 0 {
                    // Reading another uid's /proc/<pid>/fd needs ptrace-read access: root
                    // normally has it, but not root in a default Docker container (no
                    // CAP_SYS_PTRACE), so say which one is missing.
                    // SAFETY: geteuid has no preconditions and cannot fail.
                    let root_already = unsafe { libc::geteuid() } == 0;
                    let mut note = if root_already { "owner hidden (needs CAP_SYS_PTRACE)" } else { "owner hidden (needs root)" }
                        .to_string();
                    if let Some(uid) = s.hidden_uid {
                        let name = users.entry(uid).or_insert_with(|| user_of(uid));
                        match name {
                            Some(n) => note.push_str(&format!(" · uid {uid} ({n})")),
                            None => note.push_str(&format!(" · uid {uid}")),
                        }
                    }
                    if s.foreign_ns {
                        note.push_str(" · in another network namespace");
                    }
                    return Port {
                        proto: s.proto,
                        addr: s.addr.clone(),
                        port: s.port,
                        pid: 0,
                        process: "?".into(),
                        state: s.state.clone(),
                        orphan: false,
                        note,
                    };
                }
                let p = procs.get(&s.pid).copied();
                let name = p.map(|p| p.name.as_str()).filter(|n| !n.is_empty()).unwrap_or(&s.command);
                let ppid = p.map(|p| p.ppid).unwrap_or(s.ppid);
                let link = |what: &str| {
                    std::fs::read_link(root.join(s.pid.to_string()).join(what))
                        .map(|l| l.to_string_lossy().into_owned())
                        .unwrap_or_default()
                };
                let (cmd, exe, cwd, start) = match p {
                    Some(p) => (p.cmd.clone(), p.exe.clone(), p.cwd.clone(), p.start_time),
                    None => {
                        let cmd = std::fs::read(root.join(s.pid.to_string()).join("cmdline"))
                            .map(|b| {
                                b.split(|c| *c == 0)
                                    .filter(|a| !a.is_empty())
                                    .map(|a| String::from_utf8_lossy(a).into_owned())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();
                        (cmd, link("exe"), link("cwd"), 0)
                    }
                };
                let parent_name = procs
                    .get(&ppid)
                    .map(|pp| pp.name.clone())
                    .or_else(|| (ppid > 1).then(|| read_stat(root, ppid).map(|(c, _)| c)).flatten())
                    .unwrap_or_default();
                let cgroup = match p.map(|p| p.cgroup.as_str()).filter(|c| !c.is_empty()) {
                    Some(c) => c.to_string(),
                    None => read_cgroup(root, s.pid),
                };
                Port {
                    proto: s.proto,
                    addr: s.addr.clone(),
                    port: s.port,
                    pid: s.pid,
                    process: name.to_string(),
                    state: s.state.clone(),
                    orphan: is_orphan_linux(ppid, &parent_name, name, &exe, &cmd, &cgroup, home),
                    note: {
                        let mut n = describe(name, &cmd, &cwd, start, now, home);
                        if s.foreign_ns {
                            // Not reachable on this address from fat's own netns: say where it lives.
                            let ctr = p.and_then(|p| p.container.clone()).or_else(|| crate::collect::linux::container_id(&cgroup));
                            match ctr {
                                Some(c) => n.push_str(&format!(" · in container {c} (own network namespace)")),
                                None => n.push_str(" · in another network namespace"),
                            }
                        }
                        n
                    },
                }
            })
            .collect()
    }

    /// True when the cgroup path places the process inside a systemd *service* unit
    /// (system.slice/nginx.service, user@1000.service/app.slice/run-r12.service, ...),
    /// i.e. something a unit file deliberately runs. `user@<uid>.service` itself is the
    /// per-user manager and does not count; scopes (session-3.scope for ssh/tty logins,
    /// vte-spawn-*.scope / app-*.scope for terminal windows, docker-*.scope) are not
    /// services either, so processes there can still be orphans.
    pub fn unit_managed(cgroup: &str) -> bool {
        cgroup
            .split('/')
            .any(|c| c.ends_with(".service") && !c.starts_with("user@"))
    }

    /// Linux orphan heuristic. A listener is flagged when ALL of:
    ///
    /// 1. It was re-parented: `ppid == 1` (init / the container's pid 1), OR its parent
    ///    is a subreaper named `systemd` that is not pid 1 (the `systemd --user` manager
    ///    adopts orphans of the user's session). ppid 0 means the parent is outside our
    ///    pid namespace (e.g. `docker exec`), which is alive, so it is not an orphan.
    /// 2. It is not managed by a systemd service unit ([`unit_managed`]); those are
    ///    supposed to be parented by systemd.
    /// 3. It is not a system daemon (exe under /usr/sbin, /sbin, /usr/libexec,
    ///    /usr/lib/systemd, /lib/systemd, /snap) nor an IDE remote server that
    ///    daemonizes on purpose (~/.vscode-server, ~/.cursor-server, ~/.windsurf-server...).
    /// 4. It looks like a dev server: same runtime / cargo-target / binary-in-$HOME
    ///    rules as macOS (no ~/Library exclusion; ~/.cache and ~/.local/share excluded).
    pub fn is_orphan_linux(
        ppid: u32,
        parent_name: &str,
        name: &str,
        exe: &str,
        cmd: &str,
        cgroup: &str,
        home: Option<&str>,
    ) -> bool {
        let reparented = ppid == 1 || (ppid > 1 && parent_name == "systemd");
        if !reparented || unit_managed(cgroup) {
            return false;
        }
        let path = if exe.is_empty() { cmd.split_whitespace().next().unwrap_or("") } else { exe };
        const SYSTEM_PREFIXES: &[&str] =
            &["/usr/sbin/", "/sbin/", "/usr/libexec/", "/usr/lib/systemd/", "/lib/systemd/", "/snap/"];
        const IDE_SERVERS: &[&str] =
            &["/.vscode-server/", "/.vscode-server-insiders/", "/.cursor-server/", "/.windsurf-server/", "/.vscode-remote/"];
        if SYSTEM_PREFIXES.iter().any(|p| path.starts_with(p)) || IDE_SERVERS.iter().any(|d| path.contains(d)) {
            return false;
        }
        let base = path.rsplit('/').next().filter(|b| !b.is_empty()).unwrap_or(name).to_lowercase();
        let lname = name.to_lowercase();
        const RUNTIMES: &[&str] = &["node", "bun", "deno", "ruby", "java", "php", "beam.smp", "dotnet", "elixir", "erl"];
        let is_runtime =
            |n: &str| RUNTIMES.contains(&n) || n.starts_with("python") || n.starts_with("node") && n.len() <= 6;
        if is_runtime(&base) || is_runtime(&lname) {
            return true;
        }
        if path.contains("/target/debug/") || path.contains("/target/release/") {
            return true;
        }
        if let Some(h) = home.filter(|h| !h.is_empty() && *h != "/") {
            let in_home = path.starts_with(&format!("{h}/"));
            let excluded = path.starts_with(&format!("{h}/.cache/")) || path.starts_with(&format!("{h}/.local/share/"));
            if in_home && !excluded {
                return true;
            }
        }
        false
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Real /proc/net/tcp6 from a Linux 7.2 aarch64 box: a dual-stack listener on
        /// [::]:18081, an IPv4-mapped established pair, ::1:5432 listen, a global v6.
        const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:46A1 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8711507 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:46A1 0000000000000000FFFF00000100007F:B4B8 01 00000000:00000000 00:00000000 00000000     0        0 8711509 1 0000000000000000 20 0 0 10 -1
   2: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 9001 1 0000000000000000 100 0 0 10 0
   3: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 9002 1 0000000000000000 100 0 0 10 0
   4: B80D012000000000000000000100000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9003 1 0000000000000000 100 0 0 10 0
";
        const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:46A0 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8713261 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 9004 1 0000000000000000 100 0 0 10 0
   2: 0100007F:46A0 0100007F:9E64 06 00000000:00000000 03:0000170B 00000000     0        0 0 3 0000000000000000
   3: 0100007F:B4B8 0100007F:46A1 01 00000000:000186A0 00:00000000 00000000     0        0 8711508 2 0000000000000000 20 8 0 10 -1
";
        const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  123: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 7001 2 0000000000000000 0
  200: 0F02000A:D431 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 7002 2 0000000000000000 0
  201: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 7003 2 0000000000000000 0
";

        #[test]
        #[cfg(target_endian = "little")]
        fn decodes_addresses() {
            assert_eq!(fmt_addr(decode_addr("0100007F").unwrap()), "127.0.0.1");
            assert_eq!(fmt_addr(decode_addr("00000000").unwrap()), "*");
            assert_eq!(fmt_addr(decode_addr("0F02000A").unwrap()), "10.0.2.15");
            assert_eq!(fmt_addr(decode_addr("00000000000000000000000000000000").unwrap()), "*");
            assert_eq!(fmt_addr(decode_addr("00000000000000000000000001000000").unwrap()), "[::1]");
            // IPv4-mapped IPv6 -> plain IPv4 so it dedups with the v4 socket.
            assert_eq!(fmt_addr(decode_addr("0000000000000000FFFF00000100007F").unwrap()), "127.0.0.1");
            assert_eq!(fmt_addr(decode_addr("0000000000000000FFFF000000000000").unwrap()), "*");
            // 2001:db8::1 as the kernel prints it on little-endian.
            assert_eq!(fmt_addr(decode_addr("B80D0120000000000000000001000000").unwrap()), "[2001:db8::1]");
            assert_eq!(decode_addr("zz"), None);
            assert_eq!(decode_addr("GGGGGGGG"), None);
        }

        #[test]
        #[cfg(target_endian = "little")]
        fn parses_proc_net_tcp6() {
            let rows = parse_proc_net(TCP6);
            // Row 4 has a 34-char address (malformed) and is dropped.
            assert_eq!(rows.len(), 4, "{rows:?}");
            assert_eq!((rows[0].port, rows[0].state, rows[0].inode, rows[0].uid), (18081, 0x0A, 8711507, 0));
            assert_eq!(fmt_addr(rows[0].local), "*");
            assert_eq!((rows[1].state, rows[1].rem_port), (0x01, 46264));
            assert_eq!((fmt_addr(rows[2].local).as_str(), rows[2].port, rows[2].uid), ("[::1]", 5432, 1000));
            assert_eq!((fmt_addr(rows[3].local).as_str(), rows[3].port), ("127.0.0.1", 8080));
            assert!(parse_proc_net("").is_empty());
            assert!(parse_proc_net("garbage\n  0: x y z\n").is_empty());
        }

        #[test]
        #[cfg(target_endian = "little")]
        fn parses_proc_net_udp() {
            let rows = parse_proc_net(UDP);
            assert_eq!(rows.len(), 3);
            assert_eq!((fmt_addr(rows[0].local).as_str(), rows[0].port, rows[0].rem_port), ("127.0.0.53", 53, 0));
            assert_eq!(rows[1].rem_port, 53, "connected client socket");
        }

        fn fixture() -> std::path::PathBuf {
            let root = std::env::temp_dir().join(format!("fat-ports-{}-{:?}", std::process::id(), std::thread::current().id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("net")).unwrap();
            std::fs::write(root.join("net/tcp"), TCP).unwrap();
            std::fs::write(root.join("net/tcp6"), TCP6).unwrap();
            std::fs::write(root.join("net/udp"), UDP).unwrap();
            // udp6 missing on purpose: must be tolerated.
            let mk = |pid: u32, stat: &str, fds: &[&str]| {
                let d = root.join(pid.to_string());
                std::fs::create_dir_all(d.join("fd")).unwrap();
                std::fs::write(d.join("stat"), stat).unwrap();
                for (i, t) in fds.iter().enumerate() {
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(t, d.join("fd").join(i.to_string())).unwrap();
                }
            };
            // Python dual-stack http.server holds both the [::]:18081 listener and the v4 one.
            mk(4242, "4242 (python3) S 1 4242 4242 0 -1", &["/dev/null", "socket:[8711507]", "socket:[8713261]", "pipe:[5]"]);
            // A forked worker sharing the same listener: lower pid wins attribution.
            mk(5000, "5000 (python3 worker) S 4242 4242 4242 0 -1", &["socket:[8711507]"]);
            // Postgres on ::1:5432 with a ')' in comm.
            mk(777, "777 (postgres: x) S 1 777 777 0 -1", &["socket:[9001]", "socket:[9002]"]);
            mk(888, "888 (resolved) S 1 1 1 0 -1", &["socket:[7001]"]);
            std::fs::write(root.join("self"), "not a pid dir").unwrap();
            root
        }

        #[test]
        #[cfg(all(unix, target_endian = "little"))]
        fn scans_fixture_tree() {
            let root = fixture();
            // Fixture fds belong to us whatever uid the rows say.
            let socks = dedup(scan_with(&root, &|_| true));
            let _ = std::fs::remove_dir_all(&root);
            let find = |proto, port| socks.iter().find(|s| s.proto == proto && s.port == port).unwrap();
            let web = find(Proto::Tcp, 18081);
            assert_eq!((web.pid, web.ppid, web.command.as_str(), web.addr.as_str()), (4242, 1, "python3", "*"));
            assert_eq!(find(Proto::Tcp, 18080).pid, 4242);
            let pg: Vec<_> = socks.iter().filter(|s| s.pid == 777).collect();
            assert_eq!(pg.len(), 2, "5432 on ::1 and 8080 on mapped 127.0.0.1");
            assert_eq!(pg[0].command, "postgres: x");
            // 127.0.0.1:8080 owned by uid 1000 with no visible fd: hidden owner. It shares the
            // port with pid 777's v4-mapped socket but stays separate (different pid).
            let hidden: Vec<_> = socks.iter().filter(|s| s.pid == 0).collect();
            assert_eq!(hidden.len(), 1, "{socks:?}");
            assert_eq!((hidden[0].port, hidden[0].hidden_uid, hidden[0].command.as_str()), (8080, Some(1000), "?"));
            let dns = find(Proto::Udp, 53);
            assert_eq!((dns.pid, dns.addr.as_str(), dns.state.as_str()), (888, "127.0.0.53", ""));
            assert!(!socks.iter().any(|s| s.proto == Proto::Udp && s.port != 53), "connected/unbound udp skipped");
            assert!(!socks.iter().any(|s| s.port == 46264 || s.port == 46265), "non-listen tcp skipped");
            assert!(scan(Path::new("/nonexistent/fat")).is_empty());
        }

        #[test]
        #[cfg(all(unix, target_endian = "little"))]
        fn owner_walk_skips_unreadable_uids() {
            let root = fixture();
            // Postgres's sockets, but say uid 0 owns them and we can't read uid 0: no walk.
            let wanted: HashMap<u64, u32> = [(9001, 0), (9002, 0)].into();
            let none = socket_owners_uid(&root, &wanted, &|u| u == 4_242_424);
            assert!(none.is_empty());
            // Readable owners are found; an unreadable leftover doesn't keep the walk going.
            use std::os::unix::fs::MetadataExt;
            let me = std::fs::metadata(&root).unwrap().uid();
            let wanted: HashMap<u64, u32> = [(9001, me), (424_242, 0)].into();
            let got = socket_owners_uid(&root, &wanted, &|u| u == me);
            assert_eq!(got.get(&9001), Some(&777));
            assert_eq!(got.len(), 1);
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        #[cfg(unix)]
        fn finds_one_pid_per_foreign_netns() {
            let root = std::env::temp_dir().join(format!("fat-netns-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let ns = |dir: &str, ino: u64| {
                let d = root.join(dir).join("ns");
                std::fs::create_dir_all(&d).unwrap();
                std::os::unix::fs::symlink(format!("net:[{ino}]"), d.join("net")).unwrap();
            };
            ns("self", 4026531840);
            ns("1", 4026531840);
            ns("300", 4026532999); // container A
            ns("301", 4026532999);
            ns("50", 4026533111); // container B (lower pid first)
            std::fs::create_dir_all(root.join("77")).unwrap(); // unreadable/no ns link
            assert_eq!(foreign_netns(&root, 8), vec![(4026533111, 50), (4026532999, 300)]);
            assert_eq!(foreign_netns(&root, 1).len(), 1);
            let _ = std::fs::remove_dir_all(&root);
            assert!(foreign_netns(Path::new("/nonexistent/fat"), 8).is_empty());
        }

        #[test]
        fn reads_stat_with_odd_comm() {
            let root = std::env::temp_dir().join(format!("fat-stat-{}", std::process::id()));
            std::fs::create_dir_all(root.join("9")).unwrap();
            std::fs::write(root.join("9/stat"), "9 (a) b (c)) R 42 9 9 0").unwrap();
            assert_eq!(read_stat(&root, 9), Some(("a) b (c)".into(), 42)));
            assert_eq!(read_stat(&root, 10), None);
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn unit_detection() {
            assert!(unit_managed("/system.slice/nginx.service"));
            assert!(unit_managed("/user.slice/user-1000.slice/user@1000.service/app.slice/run-r3f2.service"));
            assert!(unit_managed("/system.slice/foo.service/sub"));
            assert!(!unit_managed("/user.slice/user-1000.slice/session-3.scope"));
            assert!(!unit_managed(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-1a2b.scope"
            ));
            assert!(!unit_managed("/user.slice/user-1000.slice/user@1000.service/init.scope"));
            assert!(!unit_managed("/"));
            assert!(!unit_managed(""));
        }

        #[test]
        fn linux_orphan_heuristic() {
            let h = Some("/home/me");
            let sess = "/user.slice/user-1000.slice/session-3.scope";
            assert!(is_orphan_linux(1, "systemd", "node", "/usr/bin/node", "node vite", sess, h));
            assert!(is_orphan_linux(1, "", "python3", "/usr/bin/python3.12", "python3 -m http.server", "/", h));
            assert!(is_orphan_linux(812, "systemd", "api", "/home/me/code/api/target/debug/api", "", sess, h));
            assert!(is_orphan_linux(1, "", "server", "/home/me/go/bin/server", "", "", h));
            // systemd --user adopted it, terminal scope.
            let vte = "/user.slice/user-1000.slice/user@1000.service/app.slice/vte-spawn-1.scope";
            assert!(is_orphan_linux(1500, "systemd", "node", "/home/me/.nvm/versions/node/v22/bin/node", "", vte, h));
            // Still attached to a shell / tmux.
            assert!(!is_orphan_linux(500, "bash", "node", "/usr/bin/node", "", sess, h));
            assert!(!is_orphan_linux(500, "tmux: server", "node", "/usr/bin/node", "", sess, h));
            // Parent outside our pid namespace (docker exec).
            assert!(!is_orphan_linux(0, "", "node", "/usr/bin/node", "", "/", h));
            // systemd units.
            assert!(!is_orphan_linux(1, "", "python3", "/usr/bin/python3", "", "/system.slice/jupyter.service", h));
            assert!(!is_orphan_linux(
                1500,
                "systemd",
                "node",
                "/usr/bin/node",
                "",
                "/user.slice/user-1000.slice/user@1000.service/app.slice/run-u7.service",
                h
            ));
            // System daemons and IDE servers.
            assert!(!is_orphan_linux(1, "", "sshd", "/usr/sbin/sshd", "", sess, h));
            assert!(!is_orphan_linux(1, "", "node", "/home/me/.vscode-server/bin/abc/node", "", sess, h));
            assert!(!is_orphan_linux(1, "", "postgres", "/usr/lib/postgresql/16/bin/postgres", "", sess, h));
            assert!(!is_orphan_linux(1, "", "tool", "/home/me/.cache/x/tool", "", sess, h));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANNED: &str = "\
p606
R1
crapportd
f8
PTCP
n*:51061
TST=LISTEN
TQR=0
TQS=0
f9
PTCP
n*:51061
TST=LISTEN
f12
PTCP
n10.0.0.2:51061->10.0.0.3:443
TST=ESTABLISHED
p620
R1
cidentityservicesd
f18
PUDP
n*:*
f19
PUDP
n*:5353
f20
PUDP
n[2a14::1]:55618->[2001::]:443
p4242
R1
cnode
f22
PTCP
n[::1]:5173
TST=LISTEN
f23
PTCP
n127.0.0.1:5173
TST=LISTEN
";

    #[test]
    fn parses_and_dedups_lsof() {
        let socks = dedup(parse_lsof(CANNED));
        assert_eq!(socks.len(), 3, "{socks:?}");
        let tcp: Vec<_> = socks.iter().filter(|s| s.proto == Proto::Tcp).collect();
        assert_eq!(tcp[0].port, 5173);
        assert_eq!(tcp[0].addr, "127.0.0.1");
        assert_eq!(tcp[0].ppid, 1);
        assert_eq!(tcp[0].command, "node");
        assert_eq!(tcp[1].port, 51061);
        assert_eq!(tcp[1].addr, "*");
        assert_eq!(tcp[1].state, "LISTEN");
        let udp = socks.iter().find(|s| s.proto == Proto::Udp).unwrap();
        assert_eq!((udp.port, udp.addr.as_str(), udp.state.as_str()), (5353, "*", ""));
    }

    #[test]
    fn parses_garbage_without_panicking() {
        assert!(parse_lsof("").is_empty());
        assert!(parse_lsof("\n\nzzz\nf1\nnfoo\npabc\n").is_empty());
    }

    #[test]
    fn splits_addresses() {
        assert_eq!(split_addr("[::1]:32222"), Some(("[::1]".into(), 32222)));
        assert_eq!(split_addr("0.0.0.0:80"), Some(("*".into(), 80)));
        assert_eq!(split_addr("[::]:80"), Some(("*".into(), 80)));
        assert_eq!(split_addr("*:*"), None);
    }

    #[test]
    fn orphan_heuristic() {
        let home = Some("/Users/me");
        assert!(is_orphan(1, "node", "/opt/homebrew/bin/node", "node vite", home));
        assert!(is_orphan(1, "Python", "/usr/local/bin/python3.12", "", home));
        assert!(is_orphan(1, "api", "/Users/me/code/api/target/debug/api", "", home));
        assert!(is_orphan(1, "server", "/Users/me/code/go/server", "", home));
        let brew_py = "/opt/homebrew/Cellar/python@3.15/3.15.2/Frameworks/Python.framework/Versions/3.15/Resources/Python.app/Contents/MacOS/Python";
        assert!(is_orphan(1, "Python", brew_py, "", home));
        // Still attached to a shell.
        assert!(!is_orphan(500, "node", "/opt/homebrew/bin/node", "", home));
        // launchd-managed system / app agents.
        assert!(!is_orphan(1, "rapportd", "/usr/libexec/rapportd", "", home));
        assert!(!is_orphan(1, "ControlCenter", "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter", "", home));
        assert!(!is_orphan(1, "node", "/Applications/Foo.app/Contents/Resources/node", "", home));
        assert!(!is_orphan(1, "helper", "/Users/me/Library/Application Support/x/helper", "", home));
        // Homebrew service: launchd child but not a runtime.
        assert!(!is_orphan(1, "postgres", "/opt/homebrew/opt/postgresql/bin/postgres", "", home));
    }

    #[test]
    fn describes_process() {
        let note = describe(
            "node",
            "node /Users/me/code/app/node_modules/.bin/vite --port 5173",
            "/Users/me/code/app",
            1000,
            1000 + 3 * 3600 + 5,
            Some("/Users/me"),
        );
        assert_eq!(note, "node · vite dev · ~/code/app · up 3h");
        assert_eq!(describe("redis-server", "", "/", 0, 10, None), "redis-server · redis");
        assert_eq!(framework_hint("python3", "python3 manage.py runserver"), Some("django runserver"));
        assert_eq!(framework_hint("python3", "python3 -m http.server 8000"), Some("python http.server"));
    }

    /// Live: runs real lsof. `cargo test live_ports -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_ports() {
        let t = Instant::now();
        let ports = ports(&[]);
        let dt = t.elapsed();
        for p in &ports {
            println!("{:?} {}:{} pid={} {} orphan={} note={}", p.proto, p.addr, p.port, p.pid, p.process, p.orphan, p.note);
        }
        println!("{} ports in {:?}", ports.len(), dt);
        assert!(dt < Duration::from_millis(400));
        let t = Instant::now();
        let _ = super::ports(&[]);
        assert!(t.elapsed() < Duration::from_millis(20), "cached");
    }

    /// Our own listeners come back through the native macOS path in lsof's address format.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_finds_own_listener() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tport = tcp.local_addr().unwrap().port();
        let any = std::net::TcpListener::bind("[::]:0").ok();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let uport = udp.local_addr().unwrap().port();
        let me = std::process::id();
        let raw = dedup(crate::sys::darwin::libproc::listeners().unwrap().iter().map(from_listener).collect());
        let mine: Vec<&RawSock> = raw.iter().filter(|s| s.pid == me).collect();
        assert!(mine.iter().any(|s| s.proto == Proto::Tcp && s.port == tport && s.addr == "127.0.0.1" && s.state == "LISTEN"), "{mine:?}");
        assert!(mine.iter().any(|s| s.proto == Proto::Udp && s.port == uport && s.addr == "127.0.0.1" && s.state.is_empty()), "{mine:?}");
        if let Some(a) = &any {
            let p = a.local_addr().unwrap().port();
            assert!(mine.iter().any(|s| s.port == p && s.addr == "*"), "{mine:?}");
        }
        drop((tcp, any, udp));
    }

    /// Parity with lsof at the same moment (current user's sockets):
    /// `cargo test ports_match_lsof -- --ignored --nocapture`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore]
    fn ports_match_lsof() {
        let key = |s: &RawSock| (s.proto == Proto::Udp, s.port, s.pid, s.addr.clone());
        let t = Instant::now();
        let native: Vec<_> = dedup(crate::sys::darwin::libproc::listeners().unwrap().iter().map(from_listener).collect());
        let dn = t.elapsed();
        let t = Instant::now();
        let lsof = dedup(parse_lsof(&run_lsof().unwrap()));
        let dl = t.elapsed();
        let a: std::collections::BTreeSet<_> = native.iter().map(key).collect();
        let b: std::collections::BTreeSet<_> = lsof.iter().map(key).collect();
        println!("native {} sockets in {dn:?}, lsof {} in {dl:?}", a.len(), b.len());
        for x in a.difference(&b) {
            println!("only native: {x:?}");
        }
        for x in b.difference(&a) {
            println!("only lsof:   {x:?}");
        }
        assert_eq!(a, b);
    }

    #[test]
    fn annotate_uses_procs() {
        let raw = dedup(parse_lsof(CANNED));
        let p = Proc {
            pid: 4242,
            ppid: 1,
            name: "node".into(),
            exe: "/opt/homebrew/bin/node".into(),
            cmd: "node next dev".into(),
            cwd: "/Users/me/app".into(),
            ..Default::default()
        };
        let map: HashMap<u32, &Proc> = [(4242, &p)].into_iter().collect();
        let ports = annotate(&raw, &map, 0, Some("/Users/me"));
        let node = ports.iter().find(|x| x.pid == 4242).unwrap();
        assert!(node.orphan);
        assert_eq!(node.note, "node · next dev · ~/app");
        // rapportd isn't in procs; falls back to lsof command, no exe => not a runtime.
        let rp = ports.iter().find(|x| x.pid == 606).unwrap();
        assert_eq!(rp.process, "rapportd");
        assert!(!rp.orphan);
    }
}
