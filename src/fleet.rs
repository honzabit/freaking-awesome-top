//! Containers + remote hosts in one tree. OWNER: fleet agent.
//!
//! Every external command runs under a hard timeout (the docker CLI blocks forever when the
//! daemon is down). Container results are cached so the TUI can call `containers()` on every
//! refresh: a fresh cache is returned directly, a stale one is returned immediately while a
//! background thread refreshes it.
use crate::config::HostCfg;
use crate::model::{Container, Snapshot};
use serde_json::Value;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const CMD_TIMEOUT: Duration = Duration::from_millis(2500);
const SSH_TIMEOUT: Duration = Duration::from_secs(8);
const CACHE_TTL: Duration = Duration::from_secs(5);

static CACHE: Mutex<Option<(Instant, Vec<Container>)>> = Mutex::new(None);
static REFRESHING: AtomicBool = AtomicBool::new(false);

/// docker/podman containers if the CLI exists and daemon responds (timeout ~2s), else empty.
pub fn containers() -> Vec<Container> {
    let cached = CACHE.lock().ok().and_then(|g| g.clone());
    match cached {
        Some((at, list)) if at.elapsed() < CACHE_TTL => list,
        Some((_, stale)) => {
            // Stale-while-revalidate: never block the caller once we have any data.
            if !REFRESHING.swap(true, Ordering::SeqCst) {
                std::thread::spawn(|| {
                    let fresh = collect_all();
                    store(fresh);
                    REFRESHING.store(false, Ordering::SeqCst);
                });
            }
            stale
        }
        None => {
            let fresh = collect_all();
            store(fresh.clone());
            fresh
        }
    }
}

fn store(list: Vec<Container>) {
    if let Ok(mut g) = CACHE.lock() {
        *g = Some((Instant::now(), list));
    }
}

/// Query docker and podman in parallel; combine whatever responds.
fn collect_all() -> Vec<Container> {
    let docker = find_bin("docker").map(|b| std::thread::spawn(move || collect_runtime(&b, true)));
    let podman = find_bin("podman").map(|b| std::thread::spawn(move || collect_runtime(&b, false)));
    let mut out = Vec::new();
    for h in [docker, podman].into_iter().flatten() {
        if let Ok(v) = h.join() {
            out.extend(v);
        }
    }
    out
}

fn collect_runtime(bin: &PathBuf, is_docker: bool) -> Vec<Container> {
    let runtime = if is_docker { docker_runtime_name(bin) } else { "podman".to_string() };
    let ps = match run_with_timeout(bin.to_str().unwrap_or("docker"), &["ps", "--format", "{{json .}}"], CMD_TIMEOUT) {
        Ok(o) if o.success() => o.stdout,
        _ => return Vec::new(),
    };
    let mut list = parse_ps_lines(&ps, &runtime);
    if list.is_empty() {
        return list;
    }
    if let Ok(o) = run_with_timeout(bin.to_str().unwrap_or("docker"), &["stats", "--no-stream", "--format", "{{json .}}"], CMD_TIMEOUT)
        && o.success() {
            merge_stats(&mut list, &parse_stats_lines(&o.stdout));
        }
    list
}

/// "orbstack" when the active docker context is OrbStack, else "docker".
fn docker_runtime_name(bin: &PathBuf) -> String {
    if bin.to_string_lossy().contains(".orbstack") {
        return "orbstack".into();
    }
    match run_with_timeout(bin.to_str().unwrap_or("docker"), &["context", "show"], CMD_TIMEOUT) {
        Ok(o) if o.success() => runtime_from_context(o.stdout.trim()),
        _ => "docker".into(),
    }
}

fn runtime_from_context(ctx: &str) -> String {
    let c = ctx.to_ascii_lowercase();
    if c.contains("orbstack") {
        "orbstack".into()
    } else if c.contains("colima") {
        "colima".into()
    } else if c.contains("podman") {
        "podman".into()
    } else {
        "docker".into()
    }
}

/// Locate an executable on PATH, plus common install dirs (GUI launches get a minimal PATH).
fn find_bin(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    dirs.extend(["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"].map(PathBuf::from));
    if let Some(h) = dirs::home_dir() {
        dirs.push(h.join(".orbstack/bin"));
    }
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

// ---------- command runner with a hard timeout ----------

pub(crate) struct CmdOut {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOut {
    fn success(&self) -> bool {
        self.status.success()
    }
}

/// Spawn `prog args`, wait at most `timeout`, kill it on expiry. stdout/stderr are drained on
/// threads so a chatty child cannot deadlock on a full pipe.
pub(crate) fn run_with_timeout(prog: &str, args: &[&str], timeout: Duration) -> anyhow::Result<CmdOut> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot run {prog}: {e}"))?;
    let drain = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(mut r) = r {
                let mut buf = Vec::new();
                let _ = r.read_to_end(&mut buf);
                s = String::from_utf8_lossy(&buf).into_owned();
            }
            s
        })
    };
    let out_t = drain(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let err_t = drain(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait()? {
            Some(st) => break st,
            None if Instant::now() >= deadline => {
                // We spawned this child ourselves; killing it is safe.
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("{prog} timed out after {:.1}s", timeout.as_secs_f32());
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    Ok(CmdOut { status, stdout: out_t.join().unwrap_or_default(), stderr: err_t.join().unwrap_or_default() })
}

// ---------- parsing ----------

/// Case-insensitive field lookup across candidate keys (docker vs podman spell them differently).
fn field<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    let obj = v.as_object()?;
    keys.iter().find_map(|k| obj.iter().find(|(name, _)| name.eq_ignore_ascii_case(k)).map(|(_, v)| v))
}

/// Strings, string arrays (podman Names), and podman port objects all flatten to text.
fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a.iter().map(|x| text(Some(x))).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", "),
        Some(Value::Object(o)) => {
            // podman port mapping: {host_ip, container_port, host_port, protocol}
            let g = |k: &str| o.get(k).map(|v| v.to_string().trim_matches('"').to_string()).unwrap_or_default();
            let (hip, hp, cp, proto) = (g("host_ip"), g("host_port"), g("container_port"), g("protocol"));
            if cp.is_empty() {
                return String::new();
            }
            let host = if hip.is_empty() { "0.0.0.0".to_string() } else { hip };
            let proto = if proto.is_empty() { "tcp".to_string() } else { proto };
            if hp.is_empty() { format!("{cp}/{proto}") } else { format!("{host}:{hp}->{cp}/{proto}") }
        }
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Parse `docker ps --format '{{json .}}'` output (one JSON object per line).
pub(crate) fn parse_ps_lines(out: &str, runtime: &str) -> Vec<Container> {
    out.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .filter(|v| v.is_object())
        .map(|v| {
            let mut id = text(field(&v, &["ID", "Id"]));
            id.truncate(12);
            Container {
                id,
                name: text(field(&v, &["Names", "Name"])),
                image: text(field(&v, &["Image"])),
                runtime: runtime.to_string(),
                status: text(field(&v, &["Status", "State"])),
                cpu: 0.0,
                mem: 0,
                ports: text(field(&v, &["Ports"])),
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Stat {
    pub id: String,
    pub name: String,
    pub cpu: f32,
    pub mem: u64,
}

/// Parse `docker stats --no-stream --format '{{json .}}'` output.
pub(crate) fn parse_stats_lines(out: &str) -> Vec<Stat> {
    out.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .filter(|v| v.is_object())
        .map(|v| Stat {
            id: text(field(&v, &["ID", "Container"])),
            name: text(field(&v, &["Name"])),
            cpu: parse_percent(&text(field(&v, &["CPUPerc", "CPU"]))),
            mem: parse_mem_usage(&text(field(&v, &["MemUsage"]))),
        })
        .collect()
}

fn merge_stats(list: &mut [Container], stats: &[Stat]) {
    for c in list.iter_mut() {
        let hit = stats.iter().find(|s| {
            (!c.id.is_empty() && !s.id.is_empty() && (s.id.starts_with(&c.id) || c.id.starts_with(&s.id)))
                || (!c.name.is_empty() && s.name == c.name)
        });
        if let Some(s) = hit {
            c.cpu = s.cpu;
            c.mem = s.mem;
        }
    }
}

/// "12.3%" -> 12.3; garbage -> 0.
pub(crate) fn parse_percent(s: &str) -> f32 {
    s.trim().trim_end_matches('%').trim().parse().unwrap_or(0.0)
}

/// "1.2GiB / 8GiB" -> bytes of the used part.
pub(crate) fn parse_mem_usage(s: &str) -> u64 {
    parse_size(s.split('/').next().unwrap_or(""))
}

/// "342.4MiB", "1.5GB", "512kB", "100B" -> bytes. Unknown -> 0.
pub(crate) fn parse_size(s: &str) -> u64 {
    let s = s.trim();
    let split = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let Ok(n) = num.parse::<f64>() else { return 0 };
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "kib" => 1024.0,
        "kb" | "k" => 1e3,
        "mib" => 1024f64.powi(2),
        "mb" | "m" => 1e6,
        "gib" => 1024f64.powi(3),
        "gb" | "g" => 1e9,
        "tib" => 1024f64.powi(4),
        "tb" | "t" => 1e12,
        _ => return 0,
    };
    (n * mult) as u64
}

// ---------- remote hosts ----------

/// Snapshot of a remote host via ssh (BatchMode, ConnectTimeout=3). host field set to cfg.name.
pub fn remote(host: &HostCfg) -> anyhow::Result<Snapshot> {
    let dest = host.ssh.clone().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| host.name.clone());
    if dest.trim().is_empty() {
        anyhow::bail!("host has no name or ssh destination");
    }
    if dest.starts_with('-') {
        anyhow::bail!("refusing ssh destination that looks like an option: {dest}");
    }
    let remote_cmd = remote_command(host.fat_path.as_deref());
    let out = run_with_timeout("ssh", &["-o", "BatchMode=yes", "-o", "ConnectTimeout=3", &dest, &remote_cmd], SSH_TIMEOUT)?;
    if !out.success() {
        let err = out.stderr.trim().lines().last().unwrap_or("").to_string();
        anyhow::bail!("ssh {dest} failed ({}): {}", out.status, if err.is_empty() { "no output" } else { &err });
    }
    parse_remote_snapshot(&out.stdout, &host.name)
}

/// With the default "fat", fall back to ~/.cargo/bin/fat since non-login ssh shells often lack it on PATH.
fn remote_command(fat_path: Option<&str>) -> String {
    match fat_path.map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => format!("{p} snapshot --json"),
        None => "command -v fat >/dev/null 2>&1 && exec fat snapshot --json || exec ~/.cargo/bin/fat snapshot --json".into(),
    }
}

/// Parse snapshot JSON, tolerating login banners before the first '{'.
pub(crate) fn parse_remote_snapshot(stdout: &str, name: &str) -> anyhow::Result<Snapshot> {
    let start = stdout.find('{').ok_or_else(|| anyhow::anyhow!("remote fat returned no JSON"))?;
    let mut snap: Snapshot = serde_json::from_str(stdout[start..].trim_end())
        .map_err(|e| anyhow::anyhow!("cannot parse remote snapshot: {e}"))?;
    snap.host = name.to_string();
    Ok(snap)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PS: &str = r#"{"Command":"\"/usr/local/bin/dock…\"","ID":"8d0afdaef119","Image":"ghcr.io/x/app:0.15.1","Names":"app-1","Ports":"127.0.0.1:8080->8080/tcp","State":"running","Status":"Up 2 days (healthy)"}
{"ID":"f592d553371f","Image":"clickhouse/clickhouse-server:26.3","Names":"ch-1","Ports":"8123/tcp, 9000/tcp","State":"running","Status":"Up 2 days"}
not json
"#;
    const STATS: &str = r#"{"BlockIO":"7.72GB / 2.38MB","CPUPerc":"0.53%","Container":"8d0afdaef11924b5","ID":"8d0afdaef119","MemUsage":"57MiB / 512MiB","Name":"app-1","PIDs":"5"}
{"CPUPerc":"9.71%","ID":"f592d553371ffde52670af","MemUsage":"342.4MiB / 15.66GiB","Name":"ch-1"}"#;

    #[test]
    fn parses_ps_and_merges_stats() {
        let mut list = parse_ps_lines(PS, "orbstack");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "app-1");
        assert_eq!(list[0].ports, "127.0.0.1:8080->8080/tcp");
        assert_eq!(list[0].runtime, "orbstack");
        merge_stats(&mut list, &parse_stats_lines(STATS));
        assert!((list[0].cpu - 0.53).abs() < 1e-4);
        assert_eq!(list[0].mem, 57 * 1024 * 1024);
        assert!((list[1].cpu - 9.71).abs() < 1e-4);
        assert_eq!(list[1].mem, (342.4 * 1024.0 * 1024.0) as u64);
    }

    #[test]
    fn parses_podman_shapes() {
        let line = r#"{"Id":"abcdef0123456789","Image":"nginx","Names":["web"],"Ports":[{"host_ip":"","container_port":80,"host_port":8080,"protocol":"tcp"}],"State":"running","Status":"Up 1 hour"}"#;
        let c = &parse_ps_lines(line, "podman")[0];
        assert_eq!(c.id, "abcdef012345");
        assert_eq!(c.name, "web");
        assert_eq!(c.ports, "0.0.0.0:8080->80/tcp");
    }

    #[test]
    fn memory_strings() {
        assert_eq!(parse_mem_usage("1.5GiB / 8GiB"), (1.5 * 1073741824.0) as u64);
        assert_eq!(parse_size("512kB"), 512_000);
        assert_eq!(parse_size("100B"), 100);
        assert_eq!(parse_size("2MB"), 2_000_000);
        assert_eq!(parse_size("--"), 0);
        assert_eq!(parse_size("3furlongs"), 0);
        assert_eq!(parse_percent(" 12.3% "), 12.3);
        assert_eq!(parse_percent("--"), 0.0);
    }

    #[test]
    fn context_names() {
        assert_eq!(runtime_from_context("orbstack"), "orbstack");
        assert_eq!(runtime_from_context("colima"), "colima");
        assert_eq!(runtime_from_context("desktop-linux"), "docker");
    }

    #[test]
    fn remote_snapshot_with_banner() {
        let s = Snapshot { host: "local".into(), ..Default::default() };
        let out = format!("Welcome to devbox\n{}\n", serde_json::to_string(&s).unwrap());
        let parsed = parse_remote_snapshot(&out, "devbox").unwrap();
        assert_eq!(parsed.host, "devbox");
        assert!(parse_remote_snapshot("bash: fat: not found", "x").is_err());
    }

    #[test]
    fn timeout_kills_child() {
        let t = Instant::now();
        let r = run_with_timeout("sleep", &["30"], Duration::from_millis(200));
        assert!(r.is_err());
        assert!(t.elapsed() < Duration::from_secs(5));
        let ok = run_with_timeout("echo", &["hi"], Duration::from_secs(2)).unwrap();
        assert_eq!(ok.stdout.trim(), "hi");
    }

    #[test]
    fn remote_cmd_default_and_custom() {
        assert!(remote_command(None).contains("~/.cargo/bin/fat"));
        assert_eq!(remote_command(Some("/opt/fat")), "/opt/fat snapshot --json");
    }
}
