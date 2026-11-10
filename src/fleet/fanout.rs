//! Parallel, read-only fan-out to many hosts. OWNER: fleet agent.
//! A bounded std::thread worker pool (FleetCfg::concurrency) runs one Transport call per target
//! with a hard per-host timeout; `on_result` fires in completion order so the TUI and CLI can
//! render progressively. Only allowlisted read-only remote subcommands can be invoked;
//! actions need `--allow-actions` AND a single explicitly named host (no globs, groups, or
//! fleet-wide signals, ever), and go through the remote fat's own MCP action checks.
//!
//! Cost model: one poll is O(hosts / concurrency x per-host latency) wall time, and local
//! memory is bounded by `concurrency` in-flight replies of at most `max_output_bytes` each
//! (snapshots are reduced to a [`FleetHost`] row plus findings as they arrive unless the
//! caller asks to keep them).
use super::inventory::Target;
use crate::blame::FsFacts;
use crate::model::{Finding, Snapshot};
use crate::server::{FleetCfg, FleetFinding, FleetHost, FleetOutlier, FleetSummary, Profile, Severity, SevCounts};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

/// Remote fat subcommands the fleet may run.
pub const READ_ONLY_REMOTE: &[&str] = &["snapshot", "doctor", "why", "ports", "services", "kernel", "events", "what-happened", "history", "fs"];

/// Actions `fat fleet act` may forward to ONE host's `fat mcp` (which applies its own
/// `[mcp] allow_actions` gate and pid-reuse checks). Kill is deliberately absent: it cannot be
/// undone, so it is done on the host itself.
pub const REMOTE_ACTIONS: &[&str] = &["pause", "resume", "renice", "undo"];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RemoteOut {
    pub ok: bool,
    /// Exit code of the local command (ssh: 255 = ssh itself failed, anything else came from
    /// the remote command). None when killed by a signal or unknown.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub latency_ms: u64,
}

/// How a command reaches a host. Ssh in production; Local for tests and simulated fleets.
pub trait Transport: Send + Sync {
    /// Run `fat <args>` on `t` within `timeout`. Implementations kill the child on timeout.
    fn run(&self, t: &Target, args: &[String], timeout: Duration) -> anyhow::Result<RemoteOut>;
    /// Like `run`, feeding `input` on stdin (used only by `fat fleet act` to talk to the
    /// remote `fat mcp`). Transports that cannot do this refuse.
    fn run_input(&self, t: &Target, args: &[String], input: &str, timeout: Duration) -> anyhow::Result<RemoteOut> {
        let _ = (t, args, input, timeout);
        anyhow::bail!("this transport cannot send input")
    }
}

/// `ssh [ (cfg.ssh_options) -o BatchMode=yes -o ConnectTimeout=N (ControlMaster opts) ] DEST
/// -- FAT ARGS...` with each arg shell-quoted. Respects the user's ssh config; adds nothing else.
/// Operator `ssh_options` come first because ssh keeps the first value it sees for an option.
pub struct SshTransport {
    pub cfg: FleetCfg,
}

/// Runs a local command template per host ("{host}" substituted in `prefix`), e.g. for tests:
/// `LocalTransport { program: "fat".into(), prefix: vec![] }` runs fat locally for every target.
pub struct LocalTransport {
    pub program: String,
    pub prefix: Vec<String>,
}

impl SshTransport {
    /// The full ssh argv (without "ssh") for `fat <args>` on `t`.
    pub fn argv(&self, t: &Target, args: &[String]) -> anyhow::Result<Vec<String>> {
        let dir = if self.cfg.control_master { control_dir() } else { None };
        self.argv_with(t, args, dir.as_deref())
    }

    /// [`argv`](Self::argv) with the ControlPath directory given (None = no sharing).
    fn argv_with(&self, t: &Target, args: &[String], control: Option<&std::path::Path>) -> anyhow::Result<Vec<String>> {
        let dest = t.dest.trim();
        let dest = if dest.is_empty() { t.name.trim() } else { dest };
        if dest.is_empty() {
            anyhow::bail!("{}: host has no name or ssh destination", Kind::Config.as_str());
        }
        if dest.starts_with('-') || dest.contains(char::is_whitespace) {
            anyhow::bail!("{}: refusing ssh destination {dest:?}", Kind::Config.as_str());
        }
        let mut v: Vec<String> = vec!["-T".into()];
        let mut opt = |o: String| {
            v.push("-o".into());
            v.push(o);
        };
        for o in &self.cfg.ssh_options {
            let o = o.trim();
            let o = o.strip_prefix("-o").map(str::trim).unwrap_or(o);
            if !o.is_empty() {
                opt(o.to_string());
            }
        }
        opt("BatchMode=yes".into());
        opt(format!("ConnectTimeout={}", self.cfg.connect_timeout_s.max(1)));
        if let Some(dir) = control {
            opt("ControlMaster=auto".into());
            opt(format!("ControlPath={}/%C", dir.display()));
            opt(format!("ControlPersist={}", self.cfg.control_persist));
        }
        if self.cfg.compress {
            v.push("-C".into());
        }
        v.push("--".into());
        v.push(dest.to_string());
        v.push(remote_command_with_deadline(t.fat_path.as_deref(), args, Some(self.cfg.command_timeout_s.max(1))));
        Ok(v)
    }
}

impl Transport for SshTransport {
    fn run(&self, t: &Target, args: &[String], timeout: Duration) -> anyhow::Result<RemoteOut> {
        let mut c = Command::new("ssh");
        c.args(self.argv(t, args)?);
        run_capped(c, None, timeout, self.cfg.max_output_bytes)
    }
    fn run_input(&self, t: &Target, args: &[String], input: &str, timeout: Duration) -> anyhow::Result<RemoteOut> {
        let mut c = Command::new("ssh");
        c.args(self.argv(t, args)?);
        run_capped(c, Some(input), timeout, self.cfg.max_output_bytes)
    }
}

impl LocalTransport {
    fn command(&self, t: &Target, args: &[String]) -> Command {
        let mut c = Command::new(&self.program);
        c.args(self.prefix.iter().map(|a| a.replace("{host}", &t.name)));
        c.args(args);
        c
    }
}

/// Output cap for LocalTransport (it has no FleetCfg); same default as FleetCfg.
const LOCAL_MAX_OUTPUT: usize = 8 * 1024 * 1024;

impl Transport for LocalTransport {
    fn run(&self, t: &Target, args: &[String], timeout: Duration) -> anyhow::Result<RemoteOut> {
        run_capped(self.command(t, args), None, timeout, LOCAL_MAX_OUTPUT)
    }
    fn run_input(&self, t: &Target, args: &[String], input: &str, timeout: Duration) -> anyhow::Result<RemoteOut> {
        run_capped(self.command(t, args), Some(input), timeout, LOCAL_MAX_OUTPUT)
    }
}

/// ControlPath directory: `$XDG_RUNTIME_DIR/fat/ssh`, else `~/.cache/fat/ssh`, created 0700.
/// Unix socket paths are limited to ~104 bytes, so a directory too long for "<dir>/<40 hex>"
/// disables connection sharing (None) rather than failing every connection.
fn control_dir() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()).map(std::path::PathBuf::from).or_else(|| dirs::home_dir().map(|h| h.join(".cache")))?;
    let dir = base.join("fat").join("ssh");
    if dir.as_os_str().len() + 42 > 100 {
        return None;
    }
    if !dir.is_dir() {
        std::fs::create_dir_all(&dir).ok()?;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Some(dir)
}

/// The command string the remote login shell runs. With an explicit `fat_path` it is used
/// as-is (unquoted, so `~/bin/fat` or `sudo -n fat` work); otherwise a POSIX `sh -c` probe
/// tries PATH and the usual install dirs, because non-interactive ssh shells often have a
/// minimal PATH. `sh -c` keeps it independent of the remote login shell's syntax.
#[cfg_attr(not(test), allow(dead_code))]
pub fn remote_command(fat_path: Option<&str>, args: &[String]) -> String {
    remote_command_with_deadline(fat_path, args, None)
}

/// [`remote_command`] that also tells the remote fat to end itself after `deadline_s`
/// (`FAT_DEADLINE_S`, read at startup): the local timeout kills only the local ssh, and a
/// remote command without a terminal is not signalled when its session goes away. `env` keeps
/// it independent of the login shell; a fat older than this or a `fat_path` through sudo
/// (which resets the environment) ignores it.
pub fn remote_command_with_deadline(fat_path: Option<&str>, args: &[String], deadline_s: Option<u64>) -> String {
    let env = deadline_s.map(|d| format!("env {DEADLINE_ENV}={d} ")).unwrap_or_default();
    format!("{env}{}", remote_command_plain(fat_path, args))
}

/// Environment variable carrying a fleet command's self-deadline in seconds.
pub const DEADLINE_ENV: &str = "FAT_DEADLINE_S";

fn remote_command_plain(fat_path: Option<&str>, args: &[String]) -> String {
    let q: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
    match fat_path.map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => format!("{p} {}", q.join(" ")),
        None => {
            let probe = "for f in fat /usr/local/bin/fat /usr/bin/fat \"$HOME/.local/bin/fat\" \"$HOME/.cargo/bin/fat\"; do \
                         command -v \"$f\" >/dev/null 2>&1 && exec \"$f\" \"$@\"; done; \
                         echo 'fat: command not found on remote host (set fat_path)' >&2; exit 127";
            format!("sh -c {} fat {}", shell_quote(probe), q.join(" "))
        }
    }
}

enum Ev {
    Exited(std::process::ExitStatus),
    Out(Vec<u8>),
    Err(String),
    TooLarge,
}

/// Spawn `cmd`, optionally feed `input`, wait at most `timeout`, and accept at most `max`
/// bytes of stdout. The child is killed (it is ours) on timeout or oversize output. stderr is
/// waited for only briefly after exit, so a backgrounded ssh ControlMaster that inherited it
/// can never stall a poll.
fn run_capped(mut cmd: Command, input: Option<&str>, timeout: Duration, max: usize) -> anyhow::Result<RemoteOut> {
    let start = Instant::now();
    let deadline = start + timeout;
    let prog = cmd.get_program().to_string_lossy().into_owned();
    cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!("{}: cannot run {prog}: {e}", Kind::Local.as_str()))?;
    let pid = child.id() as libc::pid_t;
    if let (Some(text), Some(mut w)) = (input, child.stdin.take()) {
        let text = text.to_string();
        std::thread::spawn(move || {
            let _ = w.write_all(text.as_bytes());
        });
    }
    let (tx, rx) = mpsc::channel::<Ev>();
    if let Some(mut r) = child.stdout.take() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 64 * 1024];
            loop {
                match r.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.len() > max {
                            let _ = tx.send(Ev::TooLarge);
                            return;
                        }
                    }
                }
            }
            let _ = tx.send(Ev::Out(buf));
        });
    }
    if let Some(r) = child.stderr.take() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.take(64 * 1024).read_to_end(&mut buf);
            let _ = tx.send(Ev::Err(String::from_utf8_lossy(&buf).into_owned()));
        });
    }
    std::thread::spawn(move || {
        if let Ok(st) = child.wait() {
            let _ = tx.send(Ev::Exited(st));
        }
    });
    // SAFETY: `pid` is our own child; it cannot be reaped (and its pid reused) before the
    // waiter thread's wait() returns and reports Exited.
    let kill = || unsafe {
        libc::kill(pid, libc::SIGKILL);
    };
    let (mut status, mut stdout, mut stderr) = (None, None, None);
    let mut err_until: Option<Instant> = None;
    loop {
        if status.is_some() && stdout.is_some() {
            if stderr.is_some() {
                break;
            }
            // Exited and stdout complete: stderr gets a short grace, never the whole timeout.
            err_until.get_or_insert_with(|| Instant::now() + Duration::from_millis(300));
        }
        let until = err_until.map_or(deadline, |e| e.min(deadline));
        match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(Ev::Exited(st)) => status = Some(st),
            Ok(Ev::Out(b)) => stdout = Some(b),
            Ok(Ev::Err(e)) => stderr = Some(e),
            Ok(Ev::TooLarge) => {
                if status.is_none() {
                    kill();
                }
                anyhow::bail!("{}: reply larger than {} bytes (fleet.max_output_bytes)", Kind::TooLarge.as_str(), max);
            }
            Err(_) if err_until.is_some() => break,
            Err(_) => {
                if status.is_none() {
                    kill();
                    anyhow::bail!("{}: no answer within {:.0}s (fleet.command_timeout_s)", Kind::Timeout.as_str(), timeout.as_secs_f32());
                }
                anyhow::bail!("{}: exited but its output stayed open for {:.0}s", Kind::Timeout.as_str(), timeout.as_secs_f32());
            }
        }
    }
    let (Some(status), Some(stdout)) = (status, stdout) else { unreachable!("loop exits only with both") };
    Ok(RemoteOut { ok: status.success(), code: status.code(), stdout: String::from_utf8_lossy(&stdout).into_owned(), stderr: stderr.unwrap_or_default(), latency_ms: start.elapsed().as_millis() as u64 })
}

// ---------------------------------------------------------------------------------------------
// Structured errors
// ---------------------------------------------------------------------------------------------

/// Why a host could not be polled. `FleetHost.error` is "<kind>: <detail>".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// DNS, refused, no route, connect timeout.
    Unreachable,
    /// ssh authentication failed (BatchMode never prompts).
    Auth,
    /// Host key unknown or changed: fix known_hosts; fat never disables checking.
    HostKey,
    /// fat not installed (or not at fat_path) on the host.
    FatMissing,
    /// The remote fat is too old for the command, even after fallback.
    Version,
    Timeout,
    TooLarge,
    /// The remote answered but not with parsable output.
    BadOutput,
    /// The remote fat ran and failed.
    Remote,
    /// Bad inventory entry.
    Config,
    /// Could not start ssh locally.
    Local,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Unreachable => "unreachable",
            Kind::Auth => "auth",
            Kind::HostKey => "host-key",
            Kind::FatMissing => "fat-missing",
            Kind::Version => "version",
            Kind::Timeout => "timeout",
            Kind::TooLarge => "too-large",
            Kind::BadOutput => "bad-output",
            Kind::Remote => "remote-error",
            Kind::Config => "config",
            Kind::Local => "local",
        }
    }
    fn hint(self) -> &'static str {
        match self {
            Kind::Unreachable => "check that `ssh HOST true` works from this machine",
            Kind::Auth => "ssh runs with BatchMode=yes: load a key in your agent or ssh config",
            Kind::HostKey => "verify and accept the host key with a manual `ssh HOST` first",
            Kind::FatMissing => "copy the static fat binary to the host or set fat_path",
            Kind::Version => "upgrade fat on the host",
            Kind::Timeout => "raise fleet.command_timeout_s or check the host's load",
            _ => "",
        }
    }
}

/// The kind prefix of a FleetHost.error string ("auth: ..." -> "auth").
pub fn error_kind(err: &str) -> &str {
    err.split(':').next().unwrap_or("").trim()
}

/// ssh's own exit status for its errors (connect, auth, host key); the remote command's status
/// is passed through otherwise.
const SSH_ERROR_EXIT: i32 = 255;

/// Classify a failed remote run from ssh's exit status and stderr. Connection-level kinds
/// (host key, auth, unreachable) need ssh's own exit status: a remote "Permission denied" or
/// "connection refused" printed by the shell or by fat is the remote command failing.
fn classify(out: &RemoteOut) -> Kind {
    let e = out.stderr.to_ascii_lowercase();
    let has = |s: &str| e.contains(s);
    let ssh_failed = out.code.is_none_or(|c| c == SSH_ERROR_EXIT);
    if !ssh_failed {
        return if out.code == Some(127) || has("fat: command not found") || has("fat: not found") {
            Kind::FatMissing
        } else if is_unknown_arg(&e) {
            Kind::Version
        } else {
            Kind::Remote
        };
    }
    if has("host key verification failed") || has("remote host identification has changed") || has("no matching host key") {
        Kind::HostKey
    } else if has("permission denied") || has("too many authentication failures") || has("no supported authentication") {
        Kind::Auth
    } else if has("could not resolve hostname") || has("connection refused") || has("no route to host") || has("connection timed out") || has("operation timed out") || has("network is unreachable") || has("connection closed by") || has("connection reset") || has("kex_exchange_identification") {
        Kind::Unreachable
    } else if has("fat: command not found") || has("fat: not found") || (has("no such file") && has("fat")) || has("command not found") {
        Kind::FatMissing
    } else if is_unknown_arg(&e) {
        Kind::Version
    } else {
        Kind::Remote
    }
}

fn is_unknown_arg(stderr_lower: &str) -> bool {
    stderr_lower.contains("unexpected argument") || stderr_lower.contains("unrecognized subcommand") || stderr_lower.contains("found argument") || stderr_lower.contains("wasn't expected")
}

fn err_text(kind: Kind, out: &RemoteOut) -> String {
    let last = out.stderr.lines().map(str::trim).rfind(|l| !l.is_empty()).unwrap_or("no output");
    let hint = kind.hint();
    if hint.is_empty() { format!("{}: {last}", kind.as_str()) } else { format!("{}: {last} ({hint})", kind.as_str()) }
}

// ---------------------------------------------------------------------------------------------
// Fan-out
// ---------------------------------------------------------------------------------------------

/// Run `f` for every target with at most `concurrency` in flight; results in input order.
pub fn fan_out<T: Send>(targets: &[Target], concurrency: usize, f: impl Fn(&Target) -> T + Sync) -> Vec<T> {
    let n = targets.len();
    let next = AtomicUsize::new(0);
    let slots: Mutex<Vec<Option<T>>> = Mutex::new((0..n).map(|_| None).collect());
    let workers = concurrency.clamp(1, n.max(1));
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    // A panicking callback must not take the whole poll down.
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&targets[i])));
                    if let Ok(v) = r
                        && let Ok(mut g) = slots.lock()
                    {
                        g[i] = Some(v);
                    }
                }
            });
        }
    });
    let slots = slots.into_inner().unwrap_or_default();
    // A slot is empty only if `f` panicked; re-run it on this thread so the caller still gets
    // one result per target (and sees the panic if it is deterministic).
    slots.into_iter().enumerate().map(|(i, v)| v.unwrap_or_else(|| f(&targets[i]))).collect()
}

/// One host's poll result with its locally computed findings.
#[derive(Debug, Clone, Default)]
pub struct Polled {
    pub host: FleetHost,
    pub findings: Vec<Finding>,
    /// Present only when the caller asked to keep snapshots.
    pub snap: Option<Snapshot>,
}

/// Poll every target with `fat snapshot --json --fast` (falling back to `snapshot --json` for
/// older remotes). `on_result` is called as each host finishes (progress / streaming UI).
#[cfg_attr(not(test), allow(dead_code))] // the TUI's Fleet tab is the caller
pub fn poll(targets: &[Target], cfg: &FleetCfg, tr: &dyn Transport, on_result: &(dyn Fn(&FleetHost) + Sync)) -> Vec<(FleetHost, Option<Snapshot>)> {
    poll_detailed(targets, cfg, tr, true, on_result).into_iter().map(|p| (p.host, p.snap)).collect()
}

/// [`poll`] that also returns each host's findings, and keeps snapshots only when `keep_snaps`
/// (summaries over large fleets do not need them; dropping them bounds memory).
pub fn poll_detailed(targets: &[Target], cfg: &FleetCfg, tr: &dyn Transport, keep_snaps: bool, on_result: &(dyn Fn(&FleetHost) + Sync)) -> Vec<Polled> {
    let timeout = Duration::from_secs(cfg.command_timeout_s.max(1));
    let backoff = Duration::from_secs(cfg.timeout_backoff_s);
    fan_out(targets, cfg.concurrency, |t| {
        let p = match backoff_until(&t.name, backoff) {
            Some(left) => Polled {
                host: host_row(
                    t,
                    Err(&format!(
                        "{}: not polled: its last poll timed out; next try in {}s (fleet.timeout_backoff_s)",
                        Kind::Timeout.as_str(),
                        left.as_secs().max(1)
                    )),
                    0,
                ),
                ..Default::default()
            },
            None => {
                let p = poll_one(t, tr, timeout, keep_snaps);
                note_poll(&t.name, &p.host);
                p
            }
        };
        on_result(&p.host);
        p
    })
}

/// When each host's last poll timed out (this process): see `FleetCfg::timeout_backoff_s`.
static TIMED_OUT: Mutex<BTreeMap<String, Instant>> = Mutex::new(BTreeMap::new());

/// Time left before `host` may be polled again, if its last poll timed out within `backoff`.
fn backoff_until(host: &str, backoff: Duration) -> Option<Duration> {
    if backoff.is_zero() {
        return None;
    }
    let g = TIMED_OUT.lock().ok()?;
    let at = g.get(host)?;
    backoff.checked_sub(at.elapsed()).filter(|d| !d.is_zero())
}

fn note_poll(host: &str, row: &FleetHost) {
    let Ok(mut g) = TIMED_OUT.lock() else { return };
    if row.error.as_deref().is_some_and(|e| error_kind(e) == Kind::Timeout.as_str()) {
        g.insert(host.to_string(), Instant::now());
    } else {
        g.remove(host);
    }
}

fn sargs(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn poll_one(t: &Target, tr: &dyn Transport, timeout: Duration, keep: bool) -> Polled {
    let start = Instant::now();
    let fail = |e: String| Polled { host: host_row(t, Err(&e), start.elapsed().as_millis() as u64), ..Default::default() };
    let mut out = match tr.run(t, &sargs(&["snapshot", "--json", "--fast"]), timeout) {
        Ok(o) => o,
        Err(e) => return fail(e.to_string()),
    };
    let mut skew = false;
    if !out.ok && classify(&out) == Kind::Version {
        // A fat without --fast: take a plain (live, slower) snapshot instead.
        skew = true;
        let left = timeout.saturating_sub(start.elapsed()).max(Duration::from_secs(1));
        out = match tr.run(t, &sargs(&["snapshot", "--json"]), left) {
            Ok(o) => o,
            Err(e) => return fail(e.to_string()),
        };
    }
    if !out.ok {
        return fail(err_text(classify(&out), &out));
    }
    // [integrator] A successful exit with an empty or truncated reply is never a real answer
    // from fat (it prints one whole JSON document or fails): the session lost data in transit
    // (seen with busy ssh multiplexers and proxies). One retry within the time limit, no more.
    let mut parsed = super::parse_remote_snapshot(&out.stdout, &t.name);
    if parsed.is_err() && timeout > start.elapsed() {
        let left = timeout.saturating_sub(start.elapsed()).max(Duration::from_secs(1));
        let args = if skew { sargs(&["snapshot", "--json"]) } else { sargs(&["snapshot", "--json", "--fast"]) };
        if let Ok(o) = tr.run(t, &args, left)
            && o.ok
        {
            parsed = super::parse_remote_snapshot(&o.stdout, &t.name);
            out = o;
        }
    }
    let latency = start.elapsed().as_millis() as u64;
    let snap = match parsed {
        Ok(s) => s,
        Err(e) => return fail(format!("{}: {e} ({} bytes received)", Kind::BadOutput.as_str(), out.stdout.len())),
    };
    let findings = findings_of(&snap);
    let mut host = row_from(t, &snap, &findings, latency);
    if skew && host.version.is_empty() {
        host.version = "old".into();
    }
    Polled { host, findings, snap: keep.then_some(snap) }
}

/// Findings for a remote snapshot, computed locally (same rules whatever the remote version),
/// including the disk rules when the remote sent its volumes. A rule panicking on odd remote
/// data yields no findings rather than a failed poll.
pub fn findings_of(snap: &Snapshot) -> Vec<Finding> {
    let facts = FsFacts { volumes: snap.volumes.clone(), ..Default::default() };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::blame::diagnose_with_fs(snap, None, &facts))).unwrap_or_default()
}

/// Build a fleet row from one poll result (findings computed locally from the snapshot with
/// crate::blame::diagnose so old remotes get the same rules).
pub fn host_row(t: &Target, snap: Result<&Snapshot, &str>, latency_ms: u64) -> FleetHost {
    match snap {
        Ok(s) => row_from(t, s, &findings_of(s), latency_ms),
        Err(e) => FleetHost {
            name: t.name.clone(),
            groups: t.groups.clone(),
            tags: t.tags.clone(),
            ok: false,
            error: Some(e.to_string()),
            latency_ms,
            health: 0,
            ts: crate::model::now_ms(),
            ..Default::default()
        },
    }
}

/// Worst (fullest) local, writable, visible volume: (mount, percent used).
fn worst_disk(snap: &Snapshot) -> Option<(String, f32)> {
    snap.volumes
        .iter()
        .filter(|v| v.total > 0 && !v.remote && !v.hidden && !v.read_only)
        .map(|v| (v.mount.clone(), 100.0 * v.total.saturating_sub(v.avail) as f32 / v.total as f32))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
}

/// OOM kills in the 24 h before the snapshot. `fat snapshot --fast` includes the recorder's
/// oom_kill events of that window; older remotes report only their last interval's.
fn oom_24h(snap: &Snapshot) -> u32 {
    let from = snap.ts - 86_400_000;
    snap.events.iter().filter(|e| e.kind == crate::server::EventKind::OomKill && e.ts >= from).count() as u32
}

fn row_from(t: &Target, s: &Snapshot, findings: &[Finding], latency_ms: u64) -> FleetHost {
    let sys = &s.system;
    let (disk_worst_mount, disk_worst_pct) = worst_disk(s).unwrap_or_default();
    let mut ranked: Vec<&Finding> = findings.iter().collect();
    ranked.sort_by_key(|f| std::cmp::Reverse(Severity::parse(&f.severity)));
    FleetHost {
        name: t.name.clone(),
        groups: t.groups.clone(),
        tags: t.tags.clone(),
        ok: true,
        error: None,
        latency_ms,
        age_ms: s.meta.as_ref().map(|m| m.age_ms).unwrap_or(0),
        profile: s.meta.as_ref().map(|m| m.profile).unwrap_or(Profile::Desktop),
        health: health_score(s, findings),
        cpu: sys.cpu,
        mem_pct: if sys.mem_total > 0 { 100.0 * sys.mem_used as f32 / sys.mem_total as f32 } else { 0.0 },
        load1: sys.load[0],
        cores: sys.cores,
        disk_worst_pct,
        disk_worst_mount,
        findings: SevCounts::of(findings),
        top_finding: ranked.first().map(|f| f.title.clone()),
        units_failed: s.units.iter().filter(|u| u.is_failed()).count() as u32,
        oom_24h: oom_24h(s),
        version: s.meta.as_ref().map(|m| m.version.clone()).unwrap_or_default(),
        ts: s.ts,
    }
}

/// 0..=100: starts at 100, minus weighted crit/warn findings, failed units, recent OOMs, worst
/// disk fill, pressure; 0 when unreachable. Documented weights, no host-specific tuning:
///
/// | signal | penalty | cap |
/// |---|---|---|
/// | crit finding | 25 each | 60 |
/// | warn finding | 8 each | 30 |
/// | failed unit | 5 each | 20 |
/// | OOM kill in 24 h | 10 each | 30 |
/// | worst disk >= 90% / >= 97% (when no disk finding already counts it) | 10 / 25 | - |
/// | memory or io pressure `full` avg10 >= 10% | 10 | - |
pub fn health_score(snap: &Snapshot, findings: &[Finding]) -> u8 {
    let c = SevCounts::of(findings);
    let mut p = (c.crit * 25).min(60) + (c.warn * 8).min(30);
    p += (snap.units.iter().filter(|u| u.is_failed()).count() as u32 * 5).min(20);
    p += (oom_24h(snap) * 10).min(30);
    let disk_counted = findings.iter().any(|f| f.title.to_ascii_lowercase().contains("full"));
    if !disk_counted && let Some((_, pct)) = worst_disk(snap) {
        p += if pct >= 97.0 {
            25
        } else if pct >= 90.0 {
            10
        } else {
            0
        };
    }
    if let Some(pr) = snap.kernel.as_ref().and_then(|k| k.pressure) && (pr.mem_full >= 10.0 || pr.io_full >= 10.0) {
        p += 10;
    }
    100u32.saturating_sub(p) as u8
}

/// Grouping key for a finding title: numbers that are values become "#", so "Disk / is 93%
/// full" and "Disk / is 95% full" aggregate. Digits that are part of a name (directly after a
/// letter, digit, `@`, `_`, `-` or `/`: /data1, nvme0n1, sdb1, postgresql@14-main) are kept, so
/// different mounts, devices and units stay apart.
pub fn title_key(title: &str) -> String {
    let mut out = String::with_capacity(title.len());
    let mut in_num = false;
    let mut in_name = false;
    let mut prev: Option<char> = None;
    for ch in title.chars() {
        if ch.is_ascii_digit() || (in_num && (ch == '.' || ch == ',')) {
            if !in_num && !in_name {
                let name_part = prev.is_some_and(|p| p.is_alphanumeric() || matches!(p, '@' | '_' | '-' | '/'));
                if name_part {
                    in_name = true;
                } else {
                    in_num = true;
                    out.push('#');
                }
            }
            if in_name {
                out.push(ch);
            }
        } else {
            in_num = false;
            in_name = false;
            out.push(ch);
        }
        prev = Some(ch);
    }
    out
}

/// Aggregate rows into a summary; findings grouped by [`title_key`] (shown verbatim when every
/// host has the identical title) with host lists capped at
/// `max_hosts_per_finding` (counts exact). Unreachable hosts are grouped by error kind, and a
/// remote fat version different from this one is reported as one info finding.
pub fn summarize(rows: Vec<FleetHost>, findings: &[(String, Vec<Finding>)], max_hosts_per_finding: usize) -> FleetSummary {
    let health: BTreeMap<&str, u8> = rows.iter().map(|r| (r.name.as_str(), r.health)).collect();
    // key -> (severity, hosts with their own severity)
    // key -> (severity, hosts with their own severity, the original title while all agree)
    // ...plus each host's own title (values intact) for the worst-host example.
    type Group = (Severity, Vec<(Severity, String, String)>, Option<String>);
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for (host, fs) in findings {
        let mut seen = std::collections::HashSet::new();
        for f in fs {
            let key = title_key(&f.title);
            if !seen.insert(key.clone()) {
                continue; // one host counts once per title
            }
            let sev = Severity::parse(&f.severity);
            let e = groups.entry(key).or_insert_with(|| (sev, vec![], Some(f.title.clone())));
            e.0 = e.0.max(sev);
            e.1.push((sev, host.clone(), f.title.clone()));
            if e.2.as_deref() != Some(f.title.as_str()) {
                e.2 = None;
            }
        }
    }
    let mut errs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mine = env!("CARGO_PKG_VERSION");
    let mut skew: Vec<String> = vec![];
    for r in &rows {
        match &r.error {
            Some(e) if !r.ok => errs.entry(error_kind(e).to_string()).or_default().push(r.name.clone()),
            _ if r.ok && r.version != mine => skew.push(r.name.clone()),
            _ => {}
        }
    }
    let cap = |mut v: Vec<String>| {
        v.truncate(max_hosts_per_finding);
        v
    };
    let mut out: Vec<FleetFinding> = groups
        .into_iter()
        .map(|(key, (severity, mut hosts, same))| {
            // Identical titles everywhere are shown verbatim; differing numbers become "#".
            let title = same.clone().unwrap_or(key);
            hosts.sort_by(|a, b| b.0.cmp(&a.0).then(health.get(a.1.as_str()).cmp(&health.get(b.1.as_str()))).then(a.1.cmp(&b.1)));
            let count = hosts.len();
            let worst = if same.is_none() { hosts.first().map(|h| format!("{}: {}", h.1, h.2)).unwrap_or_default() } else { String::new() };
            FleetFinding { title, severity, count, hosts: cap(hosts.into_iter().map(|h| h.1).collect()), worst }
        })
        .collect();
    for (kind, hosts) in errs {
        out.push(FleetFinding { title: format!("not polled: {kind}"), severity: Severity::Warn, count: hosts.len(), hosts: cap(hosts), ..Default::default() });
    }
    if !skew.is_empty() {
        out.push(FleetFinding { title: format!("fat version differs from this one ({mine})"), severity: Severity::Info, count: skew.len(), hosts: cap(skew), ..Default::default() });
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.count.cmp(&a.count)).then(a.title.cmp(&b.title)));
    let mut hosts = rows;
    hosts.sort_by(|a, b| a.health.cmp(&b.health).then(a.name.cmp(&b.name)));
    let ok = hosts.iter().filter(|h| h.ok).count();
    FleetSummary { ts: crate::model::now_ms(), elapsed_ms: 0, total: hosts.len(), ok, unreachable: hosts.len() - ok, hosts, findings: out }
}

fn median(v: &mut [f32]) -> f32 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Hosts whose cpu, memory, worst-disk or load-per-core is far from their group's median:
/// robust z = 0.6745 (x - median) / MAD above `cfg.outlier_z` AND |x - median| at least
/// `cfg.outlier_min_delta` points, in groups of at least `cfg.outlier_min_group` reachable
/// hosts. Hosts without a group are compared with all ungrouped hosts ("*").
pub fn outliers(rows: &[FleetHost], cfg: &FleetCfg) -> Vec<FleetOutlier> {
    let mut by_group: BTreeMap<String, Vec<&FleetHost>> = BTreeMap::new();
    for r in rows.iter().filter(|r| r.ok) {
        if r.groups.is_empty() {
            by_group.entry("*".into()).or_default().push(r);
        }
        for g in &r.groups {
            by_group.entry(g.clone()).or_default().push(r);
        }
    }
    type Metric = (&'static str, fn(&FleetHost) -> f32);
    let metrics: [Metric; 4] = [
        ("cpu", |h| h.cpu / (h.cores.max(1) as f32)),
        ("mem_pct", |h| h.mem_pct),
        ("disk_worst_pct", |h| h.disk_worst_pct),
        ("load_per_core_pct", |h| 100.0 * h.load1 as f32 / h.cores.max(1) as f32),
    ];
    let mut out = Vec::new();
    for (g, hs) in by_group {
        if hs.len() < cfg.outlier_min_group.max(3) {
            continue;
        }
        for (name, f) in metrics {
            let mut vals: Vec<f32> = hs.iter().map(|h| f(h)).collect();
            let med = median(&mut vals);
            let mut dev: Vec<f32> = vals.iter().map(|v| (v - med).abs()).collect();
            // A MAD of 0 (most hosts identical) would make every difference infinite; floor it
            // at one point so only `outlier_min_delta` decides then.
            let mad = median(&mut dev).max(1.0);
            for h in &hs {
                let v = f(h);
                let z = 0.6745 * (v - med) / mad;
                if z.abs() >= cfg.outlier_z && (v - med).abs() >= cfg.outlier_min_delta {
                    out.push(FleetOutlier { host: h.name.clone(), group: g.clone(), metric: name.into(), value: v, median: med, z });
                }
            }
        }
    }
    out.sort_by(|a, b| b.z.abs().partial_cmp(&a.z.abs()).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// Run an allowlisted read-only fat subcommand on one host and return its stdout
/// (`fat fleet what-happened --host web-01 ...`, MCP host_what_happened). Err if `args[0]` is
/// not in READ_ONLY_REMOTE.
pub fn remote_read_only(t: &Target, args: &[String], cfg: &FleetCfg, tr: &dyn Transport) -> anyhow::Result<String> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    if !READ_ONLY_REMOTE.contains(&sub) {
        anyhow::bail!("refusing remote `fat {sub}`: only read-only commands are allowed ({})", READ_ONLY_REMOTE.join(", "));
    }
    let out = tr.run(t, args, Duration::from_secs(cfg.command_timeout_s.max(1)))?;
    if !out.ok {
        anyhow::bail!("{}: {}", t.name, err_text(classify(&out), &out));
    }
    Ok(out.stdout)
}

/// One remote action request (see [`remote_action`]).
#[derive(Debug, Clone, Default)]
pub struct ActionReq {
    /// One of [`REMOTE_ACTIONS`].
    pub action: String,
    pub pid: u32,
    pub nice: Option<i32>,
    /// The process name the operator expects at `pid`.
    pub expect_name: String,
    /// Start time (epoch s) the operator saw; None = read it live first.
    pub start_time: Option<u64>,
}

/// Run one action on ONE host through its own `fat mcp` server: the remote applies its
/// `[mcp] allow_actions` gate and refuses a pid whose start time or name no longer matches
/// `expect_name` / `start_time` (pid reuse). When `start_time` is None it is read from the
/// remote `process` tool in the same session, just before the action. Returns the remote
/// tool result (JSON). Callers enforce `--allow-actions` and an exact host name.
pub fn remote_action(t: &Target, req: &ActionReq, cfg: &FleetCfg, tr: &dyn Transport) -> anyhow::Result<serde_json::Value> {
    use serde_json::{Value, json};
    let ActionReq { action, pid, nice, expect_name, start_time } = req;
    let (action, pid, nice, expect_name, start_time) = (action.as_str(), *pid, *nice, expect_name.as_str(), *start_time);
    if !REMOTE_ACTIONS.contains(&action) {
        anyhow::bail!("`{action}` cannot be sent to a remote host (allowed: {})", REMOTE_ACTIONS.join(", "));
    }
    if super::inventory::is_glob(&t.name) {
        anyhow::bail!("actions need one exact host name");
    }
    let timeout = Duration::from_secs(cfg.command_timeout_s.max(1));
    let rpc = |id: u64, method: &str, params: Value| json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
    let init = rpc(1, "initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "fat-fleet", "version": env!("CARGO_PKG_VERSION")}}));
    let session = |lines: &[String]| -> anyhow::Result<Vec<Value>> {
        let out = tr.run_input(t, &sargs(&["mcp"]), &(lines.join("\n") + "\n"), timeout)?;
        let replies: Vec<Value> = out.stdout.lines().filter_map(|l| serde_json::from_str(l.trim()).ok()).collect();
        if replies.is_empty() {
            anyhow::bail!("{}: {}", t.name, err_text(classify(&out), &out));
        }
        Ok(replies)
    };
    let result_of = |replies: &[Value], id: u64| -> Option<Value> {
        let r = replies.iter().find(|r| r["id"] == json!(id))?;
        Some(r["result"]["structuredContent"].clone()).filter(|v| !v.is_null()).or_else(|| r.get("error").cloned())
    };
    let start_time = match (start_time, action) {
        (Some(st), _) => Some(st),
        (None, "undo") => None,
        (None, _) => {
            let r = session(&[init.clone(), rpc(2, "tools/call", json!({"name": "process", "arguments": {"pid": pid}}))])?;
            let p = result_of(&r, 2).unwrap_or_default();
            let live = p["process"]["name"].as_str().or_else(|| p["name"].as_str()).unwrap_or("").to_string();
            if !live.eq_ignore_ascii_case(expect_name) {
                anyhow::bail!("{}: pid {pid} is {live:?}, not {expect_name:?}; nothing sent", t.name);
            }
            p["process"]["start_time"].as_u64().or_else(|| p["start_time"].as_u64())
        }
    };
    let mut args = json!({});
    if action != "undo" {
        args = json!({"pid": pid, "name": expect_name});
        if let Some(st) = start_time {
            args["start_time"] = json!(st);
        }
        if let Some(n) = nice {
            args["nice"] = json!(n);
        }
    }
    let r = session(&[init, rpc(3, "tools/call", json!({"name": action, "arguments": args}))])?;
    result_of(&r, 3).ok_or_else(|| anyhow::anyhow!("{}: remote fat mcp gave no answer to {action}", t.name))
}

/// Shell-quote one argument for a POSIX remote shell.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{SnapMeta, Unit};

    fn target(n: &str) -> Target {
        Target { name: n.into(), dest: n.into(), ..Default::default() }
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("snapshot"), "snapshot");
        assert_eq!(shell_quote("--at=03:12"), "--at=03:12");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("2h ago"), "'2h ago'");
        assert_eq!(shell_quote("it's; rm -rf /"), "'it'\\''s; rm -rf /'");
        assert_eq!(shell_quote("$(x)"), "'$(x)'");
    }

    #[test]
    fn ssh_argv_respects_operator_options() {
        let mut cfg = FleetCfg { ssh_options: vec!["ConnectTimeout=2".into(), "-o Port=2222".into()], ..Default::default() };
        let tr = SshTransport { cfg: cfg.clone() };
        let cm = std::path::Path::new("/run/user/1000/fat/ssh");
        let v = tr.argv_with(&Target { fat_path: Some("/opt/fat".into()), ..target("web-01") }, &sargs(&["snapshot", "--json"]), Some(cm)).unwrap();
        assert!(v.contains(&"ControlPath=/run/user/1000/fat/ssh/%C".into()) && v.contains(&"ControlMaster=auto".into()));
        let ct = v.iter().position(|a| a == "ConnectTimeout=2").unwrap();
        assert!(ct < v.iter().position(|a| a == "ConnectTimeout=5").unwrap(), "operator options first: ssh keeps the first value");
        assert!(v.contains(&"Port=2222".into()) && v.contains(&"BatchMode=yes".into()) && v.contains(&"-C".into()));
        assert!(!v.iter().any(|a| a.contains("ProxyJump") || a.contains("ProxyCommand")));
        let dd = v.iter().position(|a| a == "--").unwrap();
        assert_eq!(&v[dd + 1..], &["web-01".to_string(), "env FAT_DEADLINE_S=20 /opt/fat snapshot --json".to_string()]);
        cfg.control_master = false;
        cfg.compress = false;
        let v = SshTransport { cfg }.argv(&target("db-01"), &sargs(&["doctor"])).unwrap(); // no ControlPath dir is made
        assert!(!v.iter().any(|a| a.starts_with("Control")) && !v.contains(&"-C".into()));
        assert!(SshTransport { cfg: FleetCfg::default() }.argv_with(&target("-oProxyCommand=x"), &[], None).is_err());
    }

    #[test]
    fn remote_command_probe_and_explicit() {
        let c = remote_command(None, &sargs(&["what-happened", "--at", "2h ago"]));
        assert!(c.starts_with("sh -c '") && c.ends_with(" fat what-happened --at '2h ago'"), "{c}");
        assert_eq!(remote_command(Some("~/bin/fat"), &sargs(&["kernel"])), "~/bin/fat kernel");
    }

    #[test]
    fn local_transport_and_capped_runner() {
        let tr = LocalTransport { program: "sh".into(), prefix: vec!["-c".into(), "echo host={host} \"$@\"; echo warn >&2".into(), "x".into()] };
        let o = tr.run(&target("web-01"), &sargs(&["a", "b"]), Duration::from_secs(5)).unwrap();
        assert!(o.ok);
        assert_eq!(o.stdout.trim(), "host=web-01 a b");
        assert_eq!(o.stderr.trim(), "warn");
        let slow = LocalTransport { program: "sleep".into(), prefix: vec!["30".into()] };
        let t0 = Instant::now();
        let e = slow.run(&target("x"), &[], Duration::from_millis(300)).unwrap_err().to_string();
        assert!(e.starts_with("timeout:") && t0.elapsed() < Duration::from_secs(3), "{e}");
        let mut big = Command::new("sh");
        big.args(["-c", "head -c 100000 /dev/zero"]);
        assert!(run_capped(big, None, Duration::from_secs(5), 1000).unwrap_err().to_string().starts_with("too-large"));
        let mut cat = Command::new("cat");
        cat.arg("-");
        assert_eq!(run_capped(cat, Some("hello"), Duration::from_secs(5), 1000).unwrap().stdout, "hello");
        // A grandchild holding stderr open (as a backgrounded ssh master can) must not stall us.
        let mut bg = Command::new("sh");
        bg.args(["-c", "sleep 3 >/dev/null & echo done"]);
        let t0 = Instant::now();
        let o = run_capped(bg, None, Duration::from_secs(10), 1000).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        assert_eq!(o.stdout.trim(), "done");
        // One holding stdout open ends as a timeout, not a hang or a bogus "too-large".
        let mut bg = Command::new("sh");
        bg.args(["-c", "sleep 3 2>/dev/null & echo x"]);
        let e = run_capped(bg, None, Duration::from_millis(500), 1000).unwrap_err().to_string();
        assert!(e.starts_with("timeout:"), "{e}");
    }

    #[test]
    fn classification() {
        let k = |e: &str| classify(&RemoteOut { stderr: e.into(), ..Default::default() });
        assert_eq!(k("ssh: Could not resolve hostname web-09: nodename nor servname provided"), Kind::Unreachable);
        assert_eq!(k("ssh: connect to host 10.0.0.9 port 22: Connection refused"), Kind::Unreachable);
        assert_eq!(k("me@web-01: Permission denied (publickey)."), Kind::Auth);
        assert_eq!(k("Host key verification failed."), Kind::HostKey);
        assert_eq!(k("sh: 1: fat: not found"), Kind::FatMissing);
        assert_eq!(k("fat: command not found on remote host (set fat_path)"), Kind::FatMissing);
        assert_eq!(k("error: unexpected argument '--fast' found"), Kind::Version);
        assert_eq!(k("Error: database is locked"), Kind::Remote);
        assert_eq!(error_kind("auth: Permission denied"), "auth");
        // ssh's own failures exit 255; anything else is the remote command's status, so a
        // remote EACCES is not an ssh key problem.
        let kc = |e: &str, code: i32| classify(&RemoteOut { stderr: e.into(), code: Some(code), ..Default::default() });
        assert_eq!(kc("me@web-01: Permission denied (publickey).", 255), Kind::Auth);
        assert_eq!(kc("sh: 1: /opt/fat/bin/fat: Permission denied", 126), Kind::Remote);
        assert_eq!(kc("Error: opening /var/lib/fat/history.db: Permission denied", 1), Kind::Remote);
        assert_eq!(kc("Error: connection refused by the remote service", 1), Kind::Remote);
        assert_eq!(kc("sh: 1: /opt/fat/bin/fat: not found", 127), Kind::FatMissing);
        assert_eq!(kc("error: unexpected argument '--fast' found", 2), Kind::Version);
        assert_eq!(kc("ssh: connect to host 10.0.0.9 port 22: Connection refused", 255), Kind::Unreachable);
    }

    /// A host whose poll timed out is not polled again until the backoff passes, so stuck
    /// remote fats do not pile up; the remote command carries its own deadline.
    #[test]
    fn timed_out_host_backs_off() {
        let slow = LocalTransport { program: "sh".into(), prefix: vec!["-c".into(), "sleep 30".into(), "x".into()] };
        let cfg = FleetCfg { command_timeout_s: 1, timeout_backoff_s: 60, ..Default::default() };
        let t = vec![target("backoff-test-01")];
        let r = poll_detailed(&t, &cfg, &slow, false, &|_| {});
        assert_eq!(error_kind(r[0].host.error.as_deref().unwrap()), "timeout");
        let t0 = Instant::now();
        let r = poll_detailed(&t, &cfg, &slow, false, &|_| {});
        let e = r[0].host.error.as_deref().unwrap();
        assert!(e.starts_with("timeout: not polled") && t0.elapsed() < Duration::from_millis(500), "{e}");
        // Backoff off: polled again.
        let cfg0 = FleetCfg { timeout_backoff_s: 0, ..cfg };
        let t0 = Instant::now();
        let r = poll_detailed(&t, &cfg0, &slow, false, &|_| {});
        assert!(t0.elapsed() >= Duration::from_millis(900), "{:?}", r[0].host.error);
        let c = remote_command_with_deadline(None, &sargs(&["doctor"]), Some(20));
        assert!(c.starts_with("env FAT_DEADLINE_S=20 sh -c "), "{c}");
        let ssh = SshTransport { cfg: FleetCfg { command_timeout_s: 7, ..Default::default() } };
        assert!(ssh.argv(&target("web-01"), &sargs(&["doctor"])).unwrap().last().unwrap().starts_with("env FAT_DEADLINE_S=7 "));
    }

    #[test]
    fn fan_out_bounded_and_ordered() {
        let ts: Vec<Target> = (0..50).map(|i| target(&format!("h{i:02}"))).collect();
        let live = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let r = fan_out(&ts, 8, |t| {
            let n = live.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(5));
            live.fetch_sub(1, Ordering::SeqCst);
            t.name.clone()
        });
        assert_eq!(r, ts.iter().map(|t| t.name.clone()).collect::<Vec<_>>());
        assert!(peak.load(Ordering::SeqCst) <= 8);
        assert!(fan_out(&[], 64, |t| t.name.clone()).is_empty());
    }

    fn snap_json(cpu: f32, version: &str) -> String {
        let mut s = Snapshot { ts: 1000, host: "local".into(), ..Default::default() };
        s.system.cpu = cpu;
        s.system.cores = 4;
        s.system.mem_total = 100;
        s.system.mem_used = 50;
        s.meta = Some(SnapMeta { version: version.into(), source: "recorder".into(), age_ms: 1200, ..Default::default() });
        serde_json::to_string(&s).unwrap()
    }

    /// A fake fleet: hosts named ok-*, old-*, auth-*, missing-*, slow-*, junk-*.
    fn fake_fleet(dir: &std::path::Path) -> LocalTransport {
        let snap = dir.join("snap.json");
        std::fs::write(&snap, snap_json(40.0, env!("CARGO_PKG_VERSION"))).unwrap();
        let script = format!(
            r#"h="$1"; shift
case "$h" in
  ok-*) cat '{s}' ;;
  old-*) case " $* " in *" --fast "*) echo "error: unexpected argument '--fast' found" >&2; exit 2;; esac; echo banner; cat '{s}' ;;
  auth-*) echo "me@$h: Permission denied (publickey)." >&2; exit 255 ;;
  missing-*) echo "fat: command not found on remote host (set fat_path)" >&2; exit 127 ;;
  slow-*) sleep 10 ;;
  junk-*) echo "not json" ;;
  flaky-*) if [ -e '{d}'/"$h.seen" ]; then cat '{s}'; else : > '{d}'/"$h.seen"; fi ;;
  empty-*) ;;
esac"#,
            s = snap.display(),
            d = dir.display()
        );
        LocalTransport { program: "sh".into(), prefix: vec!["-c".into(), script, "fake".into(), "{host}".into()] }
    }

    #[test]
    fn poll_classifies_and_streams() {
        let dir = std::env::temp_dir().join(format!("fat-fanout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tr = fake_fleet(&dir);
        let names = ["ok-1", "ok-2", "old-1", "auth-1", "missing-1", "slow-1", "junk-1", "flaky-1", "empty-1"];
        let ts: Vec<Target> = names.iter().map(|n| target(n)).collect();
        let cfg = FleetCfg { command_timeout_s: 1, ..Default::default() };
        let seen = Mutex::new(Vec::new());
        let res = poll(&ts, &cfg, &tr, &|h| seen.lock().unwrap().push(h.name.clone()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(seen.lock().unwrap().len(), names.len());
        let by: BTreeMap<&str, &FleetHost> = res.iter().map(|(h, _)| (h.name.as_str(), h)).collect();
        assert!(by["ok-1"].ok && by["ok-1"].cpu == 40.0 && by["ok-1"].age_ms == 1200 && by["ok-1"].mem_pct == 50.0);
        assert!(res[0].1.is_some(), "poll keeps snapshots");
        assert!(by["old-1"].ok, "old remotes fall back to a plain snapshot");
        assert_eq!(error_kind(by["auth-1"].error.as_deref().unwrap()), "auth");
        assert_eq!(error_kind(by["missing-1"].error.as_deref().unwrap()), "fat-missing");
        assert_eq!(error_kind(by["slow-1"].error.as_deref().unwrap()), "timeout");
        assert_eq!(error_kind(by["junk-1"].error.as_deref().unwrap()), "bad-output");
        assert!(by["flaky-1"].ok, "an empty reply lost in transit is retried once");
        assert_eq!(error_kind(by["empty-1"].error.as_deref().unwrap()), "bad-output");
        assert_eq!(by["auth-1"].health, 0);
        let s = summarize(res.into_iter().map(|(h, _)| h).collect(), &[], 2);
        assert_eq!((s.total, s.ok, s.unreachable), (9, 4, 5));
        assert!(s.findings.iter().any(|f| f.title == "not polled: timeout" && f.count == 1));
        assert_eq!(s.hosts[0].health, 0, "worst first");
    }

    #[test]
    fn health_and_summary() {
        let f = |sev: &str, t: &str| Finding { severity: sev.into(), title: t.into(), ..Default::default() };
        let s = Snapshot::default();
        assert_eq!(health_score(&s, &[]), 100);
        assert_eq!(health_score(&s, &[f("crit", "a"), f("warn", "b")]), 67);
        assert_eq!(health_score(&s, &[f("crit", "a"), f("crit", "b"), f("crit", "c"), f("warn", "x"), f("warn", "y"), f("warn", "z"), f("warn", "w")]), 10);
        let s = Snapshot { units: vec![Unit { state: "failed".into(), ..Default::default() }; 2], ..Default::default() };
        assert_eq!(health_score(&s, &[]), 90);

        let row = |n: &str, h: u8| FleetHost { name: n.into(), ok: true, health: h, version: env!("CARGO_PKG_VERSION").into(), ..Default::default() };
        let rows = vec![row("web-01", 60), row("web-02", 40), row("db-01", 90), FleetHost { name: "x".into(), error: Some("auth: no".into()), ..Default::default() }];
        let fs = vec![
            ("web-01".to_string(), vec![f("warn", "Disk / is 91% full"), f("warn", "Disk / is 91% full")]),
            ("web-02".to_string(), vec![f("crit", "Disk / is 98% full")]),
            ("db-01".to_string(), vec![f("info", "postgres is a big network user")]),
        ];
        let sum = summarize(rows, &fs, 10);
        assert_eq!(sum.findings[0].title, "Disk / is #% full");
        assert_eq!(sum.findings[0].severity, Severity::Crit);
        assert_eq!(sum.findings[0].count, 2, "a host counts once per title");
        assert_eq!(sum.findings[0].hosts, vec!["web-02", "web-01"], "worst host first");
        assert!(sum.findings.iter().any(|f| f.title == "postgres is a big network user"), "identical titles stay verbatim");
        assert!(sum.findings.iter().any(|f| f.title == "not polled: auth"));
        assert_eq!(summarize(vec![], &[("a".into(), vec![f("warn", "t")]), ("b".into(), vec![f("warn", "t")])], 1).findings[0].hosts.len(), 1);
        assert_eq!(title_key("node on :3000 uses 1,234.5 MB"), "node on :# uses # MB");
        assert_eq!(sum.findings[0].worst, "web-02: Disk / is 98% full", "the merged line keeps the worst value");
        // Names with digits stay apart; values merge.
        assert_eq!(title_key("Disk /data1 is 97% full"), "Disk /data1 is #% full");
        assert_ne!(title_key("Disk /data1 is 97% full"), title_key("Disk /data2 is 91% full"));
        assert_eq!(title_key("nvme0n1 await 120 ms"), "nvme0n1 await # ms");
        assert_eq!(title_key("postgresql@14-main.service failed"), "postgresql@14-main.service failed");
        assert_eq!(title_key("390 zombie processes"), "# zombie processes");
        assert_eq!(title_key("Disk writes at 120M/s"), "Disk writes at #M/s");
        let d = summarize(
            vec![],
            &[("a".into(), vec![f("crit", "Disk /data1 is 97% full")]), ("b".into(), vec![f("warn", "Disk /data2 is 91% full")])],
            10,
        );
        assert_eq!(d.findings.len(), 2, "{:?}", d.findings);
        assert!(d.findings.iter().all(|x| x.worst.is_empty()), "verbatim titles need no example");
    }

    #[test]
    fn group_outliers() {
        let cfg = FleetCfg::default();
        let mut rows: Vec<FleetHost> = (0..10).map(|i| FleetHost { name: format!("web-{i:02}"), ok: true, groups: vec!["web".into()], cores: 4, mem_pct: 40.0 + i as f32, disk_worst_pct: 50.0, ..Default::default() }).collect();
        rows[3].mem_pct = 95.0;
        rows[7].disk_worst_pct = 52.0; // small difference: not an outlier
        let o = outliers(&rows, &cfg);
        assert_eq!(o.len(), 1, "{o:?}");
        assert_eq!((o[0].host.as_str(), o[0].metric.as_str(), o[0].group.as_str()), ("web-03", "mem_pct", "web"));
        assert!(outliers(&rows[..3], &cfg).is_empty(), "groups below outlier_min_group are skipped");
    }

    #[test]
    fn read_only_allowlist() {
        let tr = LocalTransport { program: "echo".into(), prefix: vec![] };
        let cfg = FleetCfg::default();
        assert!(remote_read_only(&target("a"), &sargs(&["kill", "1"]), &cfg, &tr).is_err());
        assert!(remote_read_only(&target("a"), &sargs(&["mcp"]), &cfg, &tr).is_err());
        assert!(remote_read_only(&target("a"), &[], &cfg, &tr).is_err());
        assert_eq!(remote_read_only(&target("a"), &sargs(&["kernel", "--json"]), &cfg, &tr).unwrap().trim(), "kernel --json");
        let req = |a: &str| ActionReq { action: a.into(), pid: 1, expect_name: "x".into(), ..Default::default() };
        assert!(remote_action(&target("a"), &req("kill"), &cfg, &tr).is_err());
        assert!(remote_action(&target("web-*"), &req("pause"), &cfg, &tr).is_err());
    }
}
