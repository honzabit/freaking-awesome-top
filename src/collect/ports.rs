//! Listening sockets -> owning pid, orphan heuristic. OWNER: ports-net agent.
//!
//! Data source: `lsof -nP -iTCP -sTCP:LISTEN -iUDP -FpcRnPT`. The `-F` field
//! output is line-oriented and designed for machine parsing: every line starts
//! with a one-letter field tag (`p` pid, `c` command, `R` ppid, `f` fd,
//! `P` protocol, `n` name/address, `T` TCP/TPI info such as `ST=LISTEN`).
//! Without root, lsof only reports the current user's sockets, which is fine.
use crate::model::{Port, Proc, Proto};
use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hard deadline for the lsof call; the whole `ports()` must stay < 400ms.
const LSOF_TIMEOUT: Duration = Duration::from_millis(350);
/// Raw socket list is reused for this long between calls.
/// Listening sockets change rarely and `lsof` costs ~40ms CPU per run, so refresh every 5s.
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
}

static CACHE: Mutex<Option<(Instant, Vec<RawSock>)>> = Mutex::new(None);

/// List TCP listeners and bound UDP sockets, annotated with notes and orphan flags.
pub fn ports(procs: &[Proc]) -> Vec<Port> {
    let raw = cached_raw();
    let by_pid: HashMap<u32, &Proc> = procs.iter().map(|p| (p.pid, p)).collect();
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let home = dirs::home_dir().map(|h| h.to_string_lossy().into_owned());
    annotate(&raw, &by_pid, now, home.as_deref())
}

fn cached_raw() -> Vec<RawSock> {
    if let Ok(guard) = CACHE.lock()
        && let Some((at, socks)) = guard.as_ref()
            && at.elapsed() < CACHE_TTL {
                return socks.clone();
            }
    let socks = run_lsof().map(|out| dedup(parse_lsof(&out))).unwrap_or_default();
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((Instant::now(), socks.clone()));
    }
    socks
}

/// Run lsof with a deadline. Returns None if lsof is missing, fails, or times out.
fn run_lsof() -> Option<String> {
    let mut child = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-FpcRnPT"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Read stdout on a helper thread so a full pipe can't deadlock the deadline loop.
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < LSOF_TIMEOUT => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                // Timed out (or wait failed): kill our own child and reap it.
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    // lsof exits 1 when some selectors match nothing; its output is still valid.
    reader.join().ok()
}

/// Parse lsof `-F` output into sockets. Unknown fields are ignored; sockets with
/// no concrete local port (e.g. UDP `*:*`) and connected UDP sockets are skipped.
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
