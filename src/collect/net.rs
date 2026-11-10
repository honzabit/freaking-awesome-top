//! Per-process network rates, sampled every 2s in a background thread. OWNER: ports-net agent.
//!
//! macOS: there is no public per-process network API, so we run `nettop -P -L 1 -J
//! bytes_in,bytes_out -x` (verified on macOS 15). It prints one header line
//! `,bytes_in,bytes_out,` followed by `name.pid,in,out,` rows with CUMULATIVE byte
//! counters, and exits in ~25ms. Continuous mode (`-L 0`) is block-buffered when stdout
//! is a pipe, so we run one-shot `-L 1` and compute rates from the deltas ourselves. The
//! child runs with `LC_ALL=C` and a hard timeout; columns are located from the header row
//! (so an added or reordered column doesn't break us) and the `name.pid` identifier is
//! split from the right, so names with dots, commas or spaces still parse.
//!
//! Linux: no subprocess. A `NETLINK_SOCK_DIAG` dump (`inet_diag_req_v2` with
//! `INET_DIAG_INFO`, AF_INET and AF_INET6) returns every TCP socket's inode, uid and
//! `struct tcp_info`, whose `tcpi_bytes_received` / `tcpi_bytes_acked` are the rx / tx
//! counters (see [`diag`]). Socket inodes map to pids through `/proc/<pid>/fd/*` links;
//! the mapping is cached and only sockets with traffic and no known owner trigger a walk.
//! Counters are diffed per socket inode and summed per pid, so a socket closing between
//! samples never yields a negative rate. Without root only our own processes' fds are
//! readable, so other users' sockets are ignored. As root each other network namespace
//! (containers) is dumped too, through a netlink socket created by a short-lived thread
//! that `setns`-es into it. UDP is skipped: the kernel keeps no per-socket byte counters
//! for it. If netlink is unavailable (seccomp, no inet_diag) we fall back to
//! `ss -tinpeH` (and `nsenter -n -t <pid> ss` per netns as root), parsed by [`linux`].
use std::collections::HashMap;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(2);
/// Hard deadline for one nettop / ss / nsenter run (they normally take 10-50ms).
const CHILD_TIMEOUT: Duration = Duration::from_secs(3);
/// Linux, root: most container network namespaces sampled per interval.
#[cfg(target_os = "linux")]
const MAX_NETNS: usize = 16;
/// Linux: consecutive netlink failures before we stay on the ss fallback for good.
#[cfg(target_os = "linux")]
const NETLINK_MAX_FAILURES: u32 = 3;
/// Sleep granularity so Drop doesn't wait a full interval.
const TICK: Duration = Duration::from_millis(100);

type Rates = HashMap<u32, (u64, u64)>;

pub struct NetSampler {
    rates: Arc<Mutex<Rates>>,
    stop: Arc<AtomicBool>,
    /// The nettop / ss child currently running (if any), so Drop can kill it.
    child: Arc<Mutex<Option<Child>>>,
    handle: Option<JoinHandle<()>>,
}

impl NetSampler {
    /// Spawn background sampler. Must never block the caller; degrades to an empty map.
    pub fn start() -> Self {
        let rates = Arc::new(Mutex::new(Rates::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let child = Arc::new(Mutex::new(None));
        let handle = {
            let (rates, stop, child) = (rates.clone(), stop.clone(), child.clone());
            std::thread::Builder::new()
                .name(if cfg!(target_os = "linux") { "fat-net" } else { "fat-nettop" }.into())
                .spawn(move || sampler_loop(rates, stop, child))
                .ok()
        };
        NetSampler { rates, stop, child, handle }
    }

    /// Latest pid -> (rx_bps, tx_bps).
    pub fn latest(&self) -> HashMap<u32, (u64, u64)> {
        self.rates.lock().map(|m| m.clone()).unwrap_or_default()
    }
}

impl Drop for NetSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut slot) = self.child.lock()
            && let Some(mut c) = slot.take()
        {
            // Only ever our own child.
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn sleep_interval(stop: &AtomicBool) {
    let wait_until = Instant::now() + INTERVAL;
    while Instant::now() < wait_until && !stop.load(Ordering::SeqCst) {
        std::thread::sleep(TICK);
    }
}

#[cfg(target_os = "linux")]
fn sampler_loop(rates: Arc<Mutex<Rates>>, stop: Arc<AtomicBool>, slot: Arc<Mutex<Option<Child>>>) {
    let mut prev: Option<(Instant, linux::Sockets)> = None;
    let mut failures = 0u32;
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;
    let nsenter = root
        && std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("nsenter").is_file()));
    let mut nl: Option<diag::Sampler> = None;
    let mut nl_failures = 0u32;
    while !stop.load(Ordering::SeqCst) {
        let mut cur: Option<linux::Sockets> = None;
        if nl.is_none() && nl_failures < NETLINK_MAX_FAILURES {
            match diag::Sampler::new() {
                Ok(s) => nl = Some(s),
                Err(_) => nl_failures += 1,
            }
        }
        if let Some(s) = nl.as_mut() {
            let foreign = if root { super::ports::foreign_netns(MAX_NETNS) } else { Vec::new() };
            match s.sample(&foreign) {
                Ok((mut socks, missed)) => {
                    nl_failures = 0;
                    // A namespace we could not setns into: try nsenter + ss for it.
                    if nsenter {
                        for pid in missed {
                            let t = pid.to_string();
                            if let Some(o) =
                                run_capture(&slot, &stop, "nsenter", &["-n", "-t", &t, "ss", "-tinpeH"], CHILD_TIMEOUT)
                            {
                                socks.extend(linux::parse_ss(&o));
                            }
                        }
                    }
                    cur = Some(socks);
                }
                Err(_) => {
                    nl = None;
                    nl_failures += 1;
                }
            }
        }
        if cur.is_none() {
            cur = ss_sample(&slot, &stop, root && nsenter);
        }
        match cur {
            Some(cur) => {
                failures = 0;
                let at = Instant::now();
                if let Some((prev_at, prev_socks)) = &prev {
                    let r = linux::compute_rates(prev_socks, &cur, at.duration_since(*prev_at).as_secs_f64());
                    if let Ok(mut m) = rates.lock() {
                        *m = r;
                    }
                }
                prev = Some((at, cur));
            }
            None => {
                failures += 1;
                prev = None;
                if let Ok(mut m) = rates.lock() {
                    m.clear();
                }
                if failures >= 5 {
                    return;
                }
            }
        }
        sleep_interval(&stop);
    }
}

/// Fallback: one `ss -tinpeH` dump (plus one per container netns via nsenter as root).
#[cfg(target_os = "linux")]
fn ss_sample(slot: &Mutex<Option<Child>>, stop: &AtomicBool, netns: bool) -> Option<linux::Sockets> {
    let mut out = run_capture(slot, stop, "ss", &["-tinpeH"], CHILD_TIMEOUT)?;
    // `nsenter -n` switches only the netns, so pids stay ours.
    if netns {
        for (_, pid) in super::ports::foreign_netns(MAX_NETNS) {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let t = pid.to_string();
            if let Some(more) = run_capture(slot, stop, "nsenter", &["-n", "-t", &t, "ss", "-tinpeH"], CHILD_TIMEOUT) {
                out.push('\n');
                out.push_str(&more);
            }
        }
    }
    Some(linux::parse_ss(&out))
}

#[cfg(not(target_os = "linux"))]
fn sampler_loop(rates: Arc<Mutex<Rates>>, stop: Arc<AtomicBool>, slot: Arc<Mutex<Option<Child>>>) {
    #[allow(clippy::type_complexity)]
    let mut prev: Option<(Instant, HashMap<u32, (u64, u64)>)> = None;
    let mut failures = 0u32;
    while !stop.load(Ordering::SeqCst) {
        match run_nettop(&slot, &stop) {
            Some(out) => {
                failures = 0;
                let at = Instant::now();
                let cur = parse_output(&out);
                if let Some((prev_at, prev_counts)) = &prev {
                    let secs = at.duration_since(*prev_at).as_secs_f64();
                    let r = compute_rates(prev_counts, &cur, secs);
                    if let Ok(mut m) = rates.lock() {
                        *m = r;
                    }
                }
                prev = Some((at, cur));
            }
            None => {
                failures += 1;
                // A timed-out or failed sample breaks the delta chain.
                prev = None;
                if let Ok(mut m) = rates.lock() {
                    m.clear();
                }
                // nettop missing or broken: back off, and give up after repeated failures.
                if failures >= 5 {
                    return;
                }
            }
        }
        sleep_interval(&stop);
    }
}

/// Run one `nettop -L 1` sample.
#[cfg(not(target_os = "linux"))]
fn run_nettop(slot: &Mutex<Option<Child>>, stop: &AtomicBool) -> Option<String> {
    run_capture(slot, stop, "nettop", &["-P", "-L", "1", "-J", "bytes_in,bytes_out", "-x"], CHILD_TIMEOUT)
}

/// Most stdout we keep from one child run.
const MAX_OUTPUT: usize = 64 << 20;

/// Run `program args` (with `LC_ALL=C`) and capture stdout, killing it after `timeout`.
/// The child is parked in `slot` while running so Drop can kill it; it is always reaped
/// here (no zombies). None on spawn failure, timeout, non-zero exit or stop.
fn run_capture(
    slot: &Mutex<Option<Child>>,
    stop: &AtomicBool,
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take();
    {
        let Ok(mut s) = slot.lock() else {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        };
        if stop.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        *s = Some(child);
    }
    let out = stdout.and_then(|o| read_with_deadline(o, Instant::now() + timeout, stop));
    let taken = slot.lock().ok().and_then(|mut s| s.take());
    let status = taken.and_then(|mut c| {
        if out.is_none() {
            // Timed out or stopping: it is our own child.
            let _ = c.kill();
        }
        c.wait().ok()
    });
    match (status, out) {
        (Some(st), Some(out)) if st.success() => String::from_utf8(out).ok(),
        _ => None,
    }
}

/// Read `r` to EOF, giving up (None) at `deadline` or when `stop` is set.
fn read_with_deadline(mut r: std::process::ChildStdout, deadline: Instant, stop: &AtomicBool) -> Option<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let now = Instant::now();
        if now >= deadline || stop.load(Ordering::SeqCst) {
            return None;
        }
        let wait_ms = (deadline - now).min(TICK).as_millis().max(1) as libc::c_int;
        let mut pfd = libc::pollfd { fd: r.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd for the duration of the call.
        let n = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        if n == 0 {
            continue;
        }
        // Readable or hung up: read() won't block now.
        match r.read(&mut buf) {
            Ok(0) => return Some(out),
            Ok(k) => {
                out.extend_from_slice(&buf[..k]);
                if out.len() > MAX_OUTPUT {
                    return None;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
}

/// Where nettop's columns are, from its header row. Indices count comma-separated
/// fields of the header (trailing empty field dropped); the identifier column is the
/// one with an empty name (`,bytes_in,bytes_out,` or `time,,interface,...`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_os = "linux", allow(dead_code))]
struct NettopCols {
    ident: usize,
    bytes_in: usize,
    bytes_out: usize,
    width: usize,
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
impl NettopCols {
    /// What `-J bytes_in,bytes_out` prints today, used until a header is seen.
    const DEFAULT: NettopCols = NettopCols { ident: 0, bytes_in: 1, bytes_out: 2, width: 3 };

    fn from_header(line: &str) -> Option<Self> {
        let f = fields(line);
        let pos = |name: &str| f.iter().position(|c| c.trim() == name);
        let (bytes_in, bytes_out) = (pos("bytes_in")?, pos("bytes_out")?);
        let ident = pos("")?;
        Some(NettopCols { ident, bytes_in, bytes_out, width: f.len() })
    }
}

/// Comma-split one nettop line, dropping the line terminator and one trailing empty field.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn fields(line: &str) -> Vec<&str> {
    let line = line.trim_end_matches(['\r', '\n']);
    line.strip_suffix(',').unwrap_or(line).split(',').collect()
}

/// Parse one `name.pid,bytes_in,bytes_out,` row against `cols`. The identifier may
/// itself contain commas: any surplus fields belong to it. The pid is after its last '.',
/// so names containing '.', ',' or spaces still work.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn parse_row(line: &str, cols: &NettopCols) -> Option<(u32, u64, u64)> {
    let f = fields(line);
    let extra = f.len().checked_sub(cols.width)?;
    let at = |c: usize| if c > cols.ident { c + extra } else { c };
    let inb: u64 = f.get(at(cols.bytes_in))?.trim().parse().ok()?;
    let out: u64 = f.get(at(cols.bytes_out))?.trim().parse().ok()?;
    let ident = f[cols.ident..=cols.ident + extra].join(",");
    let (_, pid) = ident.rsplit_once('.')?;
    Some((pid.trim().parse().ok()?, inb, out))
}

/// Parse a whole nettop sample into pid -> cumulative (in, out). Rows for the
/// same pid (shouldn't happen with -P, but be safe) are summed.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn parse_output(out: &str) -> HashMap<u32, (u64, u64)> {
    let mut cols = NettopCols::DEFAULT;
    let mut m: HashMap<u32, (u64, u64)> = HashMap::new();
    for line in out.lines() {
        if let Some(c) = NettopCols::from_header(line) {
            cols = c;
            continue;
        }
        if let Some((pid, i, o)) = parse_row(line, &cols) {
            let e = m.entry(pid).or_default();
            e.0 += i;
            e.1 += o;
        }
    }
    m
}

/// Per-second rates from two cumulative samples. Pids absent from `prev` (new
/// processes) are skipped; counter decreases (pid reuse) clamp to 0.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn compute_rates(prev: &HashMap<u32, (u64, u64)>, cur: &HashMap<u32, (u64, u64)>, secs: f64) -> Rates {
    if secs <= 0.0 {
        return Rates::new();
    }
    cur.iter()
        .filter_map(|(pid, (i, o))| {
            let (pi, po) = prev.get(pid)?;
            let rx = (i.saturating_sub(*pi) as f64 / secs).round() as u64;
            let tx = (o.saturating_sub(*po) as f64 / secs).round() as u64;
            Some((*pid, (rx, tx)))
        })
        .filter(|(_, (rx, tx))| *rx > 0 || *tx > 0)
        .collect()
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod diag {
    //! `NETLINK_SOCK_DIAG` TCP dump (linux/inet_diag.h, linux/tcp.h). Request, all
    //! integers host-endian except the (unused, zero) socket id:
    //!
    //! ```text
    //! nlmsghdr        { u32 len=72; u16 type=SOCK_DIAG_BY_FAMILY(20); u16 flags=REQUEST|DUMP; u32 seq; u32 pid=0 }
    //! inet_diag_req_v2{ u8 family; u8 protocol=IPPROTO_TCP; u8 ext=1<<(INET_DIAG_INFO-1); u8 pad; u32 states; sockid[48]=0 }
    //! ```
    //!
    //! Each reply message is an `inet_diag_msg` (72 bytes: family, state, timer, retrans,
    //! sockid[48], expires, rqueue, wqueue, uid @64, inode @68) followed by rtattrs; the
    //! `INET_DIAG_INFO` attribute holds `struct tcp_info`, where `tcpi_bytes_acked` is at
    //! offset 120 and `tcpi_bytes_received` at 128 (Linux 4.1+/4.2+; older kernels send a
    //! shorter struct and we report no counters). The dump ends with `NLMSG_DONE`; a
    //! failure arrives as `NLMSG_ERROR` carrying a negative errno.
    use std::collections::HashMap;
    #[cfg(target_os = "linux")]
    use std::path::Path;

    pub const NETLINK_SOCK_DIAG: i32 = 4;
    pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
    pub const NLMSG_ERROR: u16 = 2;
    pub const NLMSG_DONE: u16 = 3;
    pub const NLM_F_REQUEST: u16 = 0x1;
    pub const NLM_F_DUMP: u16 = 0x300;
    pub const INET_DIAG_INFO: u16 = 2;
    pub const AF_INET: u8 = 2;
    pub const AF_INET6: u8 = 10;
    const IPPROTO_TCP: u8 = 6;
    const NLMSG_HDRLEN: usize = 16;
    pub const REQ_LEN: usize = NLMSG_HDRLEN + 56;
    pub const DIAG_MSG_LEN: usize = 72;
    pub const TCPI_BYTES_ACKED: usize = 120;
    pub const TCPI_BYTES_RECEIVED: usize = 128;
    /// TCP states with a live, possibly data-carrying socket: ESTABLISHED, SYN_SENT,
    /// FIN_WAIT1, FIN_WAIT2, CLOSE, CLOSE_WAIT, LAST_ACK, CLOSING. Not LISTEN (no data),
    /// SYN_RECV / TIME_WAIT (mini sockets: no inode, no tcp_info).
    pub const STATES: u32 = (1 << 1) | (1 << 2) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 11);
    /// Owner cache refresh: unresolved sockets of a readable uid are retried this often (cycles).
    const RETRY_UNOWNED: u32 = 5;
    /// Owner cache is dropped entirely this often (cycles), catching fd passing.
    const REFRESH_OWNERS: u32 = 30;

    /// One TCP socket from the dump.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DiagSock {
        pub state: u8,
        pub uid: u32,
        pub inode: u64,
        /// (bytes_received, bytes_acked), None if tcp_info was missing or too short.
        pub bytes: Option<(u64, u64)>,
    }

    fn rd_u16(b: &[u8], o: usize) -> Option<u16> {
        Some(u16::from_ne_bytes(b.get(o..o + 2)?.try_into().ok()?))
    }
    fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(b.get(o..o + 4)?.try_into().ok()?))
    }
    fn rd_u64(b: &[u8], o: usize) -> Option<u64> {
        Some(u64::from_ne_bytes(b.get(o..o + 8)?.try_into().ok()?))
    }
    const fn align4(n: usize) -> usize {
        (n + 3) & !3
    }

    /// The dump request for one address family.
    pub fn build_request(family: u8, seq: u32) -> [u8; REQ_LEN] {
        let mut b = [0u8; REQ_LEN];
        b[0..4].copy_from_slice(&(REQ_LEN as u32).to_ne_bytes());
        b[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        b[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        b[8..12].copy_from_slice(&seq.to_ne_bytes());
        // nlmsg_pid 0: the kernel. inet_diag_req_v2 follows.
        b[16] = family;
        b[17] = IPPROTO_TCP;
        b[18] = 1 << (INET_DIAG_INFO - 1);
        b[20..24].copy_from_slice(&STATES.to_ne_bytes());
        // inet_diag_sockid all zero: wildcard.
        b
    }

    /// Parse one `inet_diag_msg` payload (after the nlmsghdr).
    fn parse_diag_msg(p: &[u8]) -> Option<DiagSock> {
        if p.len() < DIAG_MSG_LEN {
            return None;
        }
        let mut s = DiagSock { state: p[1], uid: rd_u32(p, 64)?, inode: rd_u32(p, 68)? as u64, bytes: None };
        let mut a = DIAG_MSG_LEN;
        while a + 4 <= p.len() {
            let alen = rd_u16(p, a)? as usize;
            let atype = rd_u16(p, a + 2)? & 0x3fff; // strip NLA_F_NESTED / NET_BYTEORDER
            if alen < 4 || a + alen > p.len() {
                break;
            }
            let data = &p[a + 4..a + alen];
            if atype == INET_DIAG_INFO
                && let (Some(acked), Some(recv)) = (rd_u64(data, TCPI_BYTES_ACKED), rd_u64(data, TCPI_BYTES_RECEIVED))
            {
                s.bytes = Some((recv, acked));
            }
            a += align4(alen);
        }
        Some(s)
    }

    /// Parse one `recv` buffer of a dump with sequence number `seq`. Ok(true) once
    /// `NLMSG_DONE` is seen; Err(errno) on `NLMSG_ERROR` or a malformed buffer.
    /// Messages of another sequence (a stale earlier dump) are skipped.
    pub fn parse_buf(buf: &[u8], seq: u32, out: &mut Vec<DiagSock>) -> Result<bool, i32> {
        let mut off = 0;
        while off + NLMSG_HDRLEN <= buf.len() {
            let len = rd_u32(buf, off).ok_or(libc::EBADMSG)? as usize;
            if len < NLMSG_HDRLEN || off + len > buf.len() {
                return Err(libc::EBADMSG);
            }
            let typ = rd_u16(buf, off + 4).ok_or(libc::EBADMSG)?;
            let mseq = rd_u32(buf, off + 8).ok_or(libc::EBADMSG)?;
            let payload = &buf[off + NLMSG_HDRLEN..off + len];
            if mseq == seq {
                match typ {
                    NLMSG_DONE => return Ok(true),
                    NLMSG_ERROR => {
                        let e = payload
                            .get(0..4)
                            .map(|b| i32::from_ne_bytes(b.try_into().unwrap_or_default()))
                            .unwrap_or(-libc::EBADMSG);
                        return Err(if e < 0 { -e } else { libc::EBADMSG });
                    }
                    SOCK_DIAG_BY_FAMILY => out.extend(parse_diag_msg(payload)),
                    _ => {}
                }
            }
            off += align4(len);
        }
        Ok(false)
    }

    #[cfg(target_os = "linux")]
    pub use sys::*;

    #[cfg(target_os = "linux")]
    mod sys {
        use super::super::linux::{SockKey, SockStat, Sockets};
        use super::*;
        use std::collections::HashSet;
        use std::io;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
        use std::time::{Duration, Instant};

        /// Whole-dump deadline (a dump of thousands of sockets takes a few ms).
        const DUMP_TIMEOUT: Duration = Duration::from_secs(2);
        const RECV_BUF: usize = 256 * 1024;

        #[repr(C)]
        struct SockaddrNl {
            nl_family: libc::sa_family_t,
            nl_pad: u16,
            nl_pid: u32,
            nl_groups: u32,
        }

        /// A `NETLINK_SOCK_DIAG` socket in the calling thread's network namespace.
        pub fn open_socket() -> io::Result<OwnedFd> {
            // SAFETY: plain socket(2); the fd is owned below.
            let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_SOCK_DIAG) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd is a fresh descriptor we own.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
            // SAFETY: valid fd, option value points to a timeval of the given size.
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&tv as *const libc::timeval).cast(),
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            Ok(fd)
        }

        /// A sock_diag socket inside the network namespace of `pid` (needs CAP_SYS_ADMIN).
        /// A short-lived thread does the `setns`, so no thread of ours changes namespace
        /// for longer than one socket(2) call; a socket stays bound to the namespace it
        /// was created in.
        pub fn open_socket_in_netns(pid: u32) -> io::Result<OwnedFd> {
            let ns = std::fs::File::open(format!("/proc/{pid}/ns/net"))?;
            std::thread::scope(|s| {
                s.spawn(|| {
                    // SAFETY: valid ns fd; affects only this (soon exiting) thread.
                    if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    open_socket()
                })
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("netns thread panicked")))
            })
        }

        /// One full TCP dump of `family` on `fd`.
        pub fn dump(fd: RawFd, family: u8, seq: u32, buf: &mut Vec<u8>, out: &mut Vec<DiagSock>) -> io::Result<()> {
            let req = build_request(family, seq);
            let addr =
                SockaddrNl { nl_family: libc::AF_NETLINK as libc::sa_family_t, nl_pad: 0, nl_pid: 0, nl_groups: 0 };
            // SAFETY: req and addr are valid for the given lengths.
            let n = unsafe {
                libc::sendto(
                    fd,
                    req.as_ptr().cast(),
                    req.len(),
                    0,
                    (&addr as *const SockaddrNl).cast(),
                    std::mem::size_of::<SockaddrNl>() as libc::socklen_t,
                )
            };
            if n != req.len() as isize {
                return Err(io::Error::last_os_error());
            }
            buf.resize(RECV_BUF, 0);
            let deadline = Instant::now() + DUMP_TIMEOUT;
            loop {
                if Instant::now() > deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                // MSG_TRUNC: returns the real datagram length, so truncation is detectable.
                // SAFETY: buf is valid for buf.len() bytes.
                let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_TRUNC) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                let n = n as usize;
                if n > buf.len() {
                    return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
                }
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                match parse_buf(&buf[..n], seq, out) {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(errno) => return Err(io::Error::from_raw_os_error(errno)),
                }
            }
        }

        /// Netlink sampler with a persistent socket for our own netns and an inode -> pid cache.
        pub struct Sampler {
            fd: OwnedFd,
            seq: u32,
            buf: Vec<u8>,
            cycle: u32,
            owners: HashMap<u64, u32>,
            /// Readable-uid sockets whose owner the last walk didn't find -> cycle of that walk.
            unowned: HashMap<u64, u32>,
            all_fds: bool,
            me: u32,
        }

        impl Sampler {
            pub fn new() -> io::Result<Self> {
                let fd = open_socket()?;
                // SAFETY: geteuid has no preconditions.
                let me = unsafe { libc::geteuid() };
                Ok(Sampler {
                    fd,
                    seq: 0,
                    buf: Vec::new(),
                    cycle: 0,
                    owners: HashMap::new(),
                    unowned: HashMap::new(),
                    all_fds: can_read_all_fds(Path::new("/proc")),
                    me,
                })
            }

            fn dump_both(&mut self, fd: RawFd, out: &mut Vec<DiagSock>) -> io::Result<()> {
                for fam in [AF_INET, AF_INET6] {
                    self.seq = self.seq.wrapping_add(1);
                    dump(fd, fam, self.seq, &mut self.buf, out)?;
                }
                Ok(())
            }

            /// Every TCP socket with traffic and a resolvable owner, in our netns and in each
            /// `foreign` (netns inode, pid) one. Err only if our own netns dump fails; foreign
            /// namespaces we could not enter are returned by pid.
            pub fn sample(&mut self, foreign: &[(u64, u32)]) -> io::Result<(Sockets, Vec<u32>)> {
                let mut raw = Vec::new();
                let own = self.fd.as_raw_fd();
                self.dump_both(own, &mut raw)?;
                let mut missed = Vec::new();
                for &(_, pid) in foreign {
                    let mut more = Vec::new();
                    match open_socket_in_netns(pid).and_then(|fd| self.dump_both(fd.as_raw_fd(), &mut more)) {
                        Ok(()) => raw.extend(more),
                        Err(_) => missed.push(pid),
                    }
                }
                Ok((self.attribute(&raw, Path::new("/proc")), missed))
            }

            /// Map sockets with traffic to owner pids, walking `/proc/*/fd` only for sockets
            /// we have no (fresh) answer for.
            pub fn attribute(&mut self, raw: &[DiagSock], proc_root: &Path) -> Sockets {
                self.cycle = self.cycle.wrapping_add(1);
                if self.cycle.is_multiple_of(REFRESH_OWNERS) {
                    self.owners.clear();
                    self.unowned.clear();
                }
                let live: HashSet<u64> = raw.iter().map(|s| s.inode).collect();
                self.owners.retain(|ino, _| live.contains(ino));
                self.unowned.retain(|ino, at| live.contains(ino) && self.cycle.wrapping_sub(*at) < RETRY_UNOWNED);
                // Owner exited (socket inherited by a child): forget, re-resolve.
                let pids: HashSet<u32> = self.owners.values().copied().collect();
                let dead: HashSet<u32> = pids.into_iter().filter(|p| !proc_root.join(p.to_string()).exists()).collect();
                if !dead.is_empty() {
                    self.owners.retain(|_, p| !dead.contains(p));
                }
                let (all, me) = (self.all_fds, self.me);
                let readable = move |uid: u32| all || uid == me;
                let wanted: HashMap<u64, u32> = raw
                    .iter()
                    .filter(|s| s.inode != 0 && s.bytes.is_some_and(|(r, t)| r | t != 0) && readable(s.uid))
                    .filter(|s| !self.owners.contains_key(&s.inode) && !self.unowned.contains_key(&s.inode))
                    .map(|s| (s.inode, s.uid))
                    .collect();
                if !wanted.is_empty() {
                    let found = socket_owners(proc_root, &wanted, &readable);
                    for &ino in wanted.keys() {
                        match found.get(&ino) {
                            Some(&pid) => {
                                self.owners.insert(ino, pid);
                            }
                            None => {
                                self.unowned.insert(ino, self.cycle);
                            }
                        }
                    }
                }
                raw.iter()
                    .filter_map(|s| {
                        let (rx, tx) = s.bytes?;
                        let pid = *self.owners.get(&s.inode)?;
                        Some((SockKey::Ino(s.inode), SockStat { pid, rx, tx }))
                    })
                    .collect()
            }
        }
    }

    /// The /proc/*/fd owner walk and the CAP_SYS_PTRACE check are shared with `fat ports`.
    #[cfg(target_os = "linux")]
    use crate::collect::ports::can_read_all_fds;
    use crate::collect::ports::socket_owners_uid as socket_owners;

    #[cfg(test)]
    mod tests {
        use super::*;

        /// One reply message: nlmsghdr + inet_diag_msg + optional INET_DIAG_INFO (tcp_info
        /// of `info_len` bytes with the two counters filled in) + an unrelated attribute.
        pub fn diag_msg(seq: u32, state: u8, uid: u32, inode: u32, info: Option<(usize, u64, u64)>) -> Vec<u8> {
            let mut p = vec![0u8; DIAG_MSG_LEN];
            p[0] = AF_INET6;
            p[1] = state;
            p[64..68].copy_from_slice(&uid.to_ne_bytes());
            p[68..72].copy_from_slice(&inode.to_ne_bytes());
            // INET_DIAG_SHUTDOWN (8), 1 byte payload: exercises padding.
            p.extend_from_slice(&5u16.to_ne_bytes());
            p.extend_from_slice(&8u16.to_ne_bytes());
            p.extend_from_slice(&[0, 0, 0, 0]);
            if let Some((len, rx, tx)) = info {
                let mut ti = vec![0u8; len];
                if len >= 136 {
                    ti[TCPI_BYTES_ACKED..TCPI_BYTES_ACKED + 8].copy_from_slice(&tx.to_ne_bytes());
                    ti[TCPI_BYTES_RECEIVED..TCPI_BYTES_RECEIVED + 8].copy_from_slice(&rx.to_ne_bytes());
                }
                p.extend_from_slice(&((4 + len) as u16).to_ne_bytes());
                p.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
                p.extend_from_slice(&ti);
                while !p.len().is_multiple_of(4) {
                    p.push(0);
                }
            }
            nl(SOCK_DIAG_BY_FAMILY, seq, &p)
        }

        pub fn nl(typ: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
            let mut m = Vec::new();
            m.extend_from_slice(&((NLMSG_HDRLEN + payload.len()) as u32).to_ne_bytes());
            m.extend_from_slice(&typ.to_ne_bytes());
            m.extend_from_slice(&0x2u16.to_ne_bytes()); // NLM_F_MULTI
            m.extend_from_slice(&seq.to_ne_bytes());
            m.extend_from_slice(&0u32.to_ne_bytes());
            m.extend_from_slice(payload);
            while !m.len().is_multiple_of(4) {
                m.push(0);
            }
            m
        }

        #[test]
        fn builds_request() {
            let r = build_request(AF_INET6, 0x01020304);
            assert_eq!(r.len(), 72);
            assert_eq!(u32::from_ne_bytes(r[0..4].try_into().unwrap()), 72);
            assert_eq!(u16::from_ne_bytes(r[4..6].try_into().unwrap()), 20);
            assert_eq!(u16::from_ne_bytes(r[6..8].try_into().unwrap()), 0x301);
            assert_eq!(u32::from_ne_bytes(r[8..12].try_into().unwrap()), 0x01020304);
            assert_eq!(&r[12..16], &[0; 4]);
            assert_eq!(&r[16..20], &[10, 6, 2, 0], "family, IPPROTO_TCP, ext INET_DIAG_INFO, pad");
            assert_eq!(u32::from_ne_bytes(r[20..24].try_into().unwrap()), 0b1011_1011_0110);
            assert!(r[24..].iter().all(|&b| b == 0), "wildcard sockid");
        }

        #[test]
        fn parses_dump_fixture() {
            let mut buf = diag_msg(7, 1, 1000, 8711508, Some((232, 100_000, 1)));
            buf.extend(diag_msg(7, 8, 0, 8711509, Some((104, 0, 0)))); // pre-4.2 tcp_info: no counters
            buf.extend(diag_msg(7, 1, 0, 0, None)); // orphan, no info attr
            buf.extend(diag_msg(6, 1, 0, 42, Some((232, 5, 5)))); // stale seq: skipped
            let mut out = Vec::new();
            assert_eq!(parse_buf(&buf, 7, &mut out), Ok(false));
            assert_eq!(
                out,
                vec![
                    DiagSock { state: 1, uid: 1000, inode: 8711508, bytes: Some((100_000, 1)) },
                    DiagSock { state: 8, uid: 0, inode: 8711509, bytes: None },
                    DiagSock { state: 1, uid: 0, inode: 0, bytes: None },
                ]
            );
            // DONE ends the dump; anything after it is ignored.
            let mut done = nl(NLMSG_DONE, 7, &0i32.to_ne_bytes());
            done.extend(diag_msg(7, 1, 0, 99, Some((232, 1, 1))));
            out.clear();
            assert_eq!(parse_buf(&done, 7, &mut out), Ok(true));
            assert!(out.is_empty());
            // Kernel error (e.g. -ENOENT: no inet_diag for this family).
            let err = nl(NLMSG_ERROR, 7, &(-libc::ENOENT).to_ne_bytes());
            assert_eq!(parse_buf(&err, 7, &mut out), Err(libc::ENOENT));
        }

        #[test]
        fn rejects_malformed_buffers() {
            let mut out = Vec::new();
            let mut m = diag_msg(1, 1, 0, 5, Some((232, 1, 2)));
            m.truncate(m.len() - 8); // header claims more than we have
            assert_eq!(parse_buf(&m, 1, &mut out), Err(libc::EBADMSG));
            let mut tiny = nl(SOCK_DIAG_BY_FAMILY, 1, &[]);
            tiny[0..4].copy_from_slice(&4u32.to_ne_bytes()); // len < header
            assert_eq!(parse_buf(&tiny, 1, &mut out), Err(libc::EBADMSG));
            // Short payload / bad attribute lengths never panic.
            let short = nl(SOCK_DIAG_BY_FAMILY, 1, &[0u8; 10]);
            assert_eq!(parse_buf(&short, 1, &mut out), Ok(false));
            let mut p = vec![0u8; DIAG_MSG_LEN];
            p.extend_from_slice(&200u16.to_ne_bytes());
            p.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
            assert_eq!(parse_buf(&nl(SOCK_DIAG_BY_FAMILY, 1, &p), 1, &mut out), Ok(false));
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].bytes, None);
            assert_eq!(parse_buf(&[1, 2, 3], 1, &mut out), Ok(false));
        }

        #[cfg(unix)]
        #[test]
        fn owner_walk_fixture() {
            use std::os::unix::fs::symlink;
            let root = std::env::temp_dir().join(format!("fat-netowners-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            for (pid, links) in [
                (300u32, vec!["socket:[11]", "pipe:[5]"]),
                (40, vec!["socket:[11]", "socket:[12]"]),
                (7, vec!["/dev/null"]),
            ] {
                let fd = root.join(pid.to_string()).join("fd");
                std::fs::create_dir_all(&fd).unwrap();
                for (i, l) in links.iter().enumerate() {
                    symlink(l, fd.join(i.to_string())).unwrap();
                }
            }
            std::fs::create_dir_all(root.join("self")).unwrap();
            let wanted: HashMap<u64, u32> = [(11, 0), (12, 0), (13, 0)].into_iter().collect();
            let got = socket_owners(&root, &wanted, &|_| true);
            assert_eq!(got, [(11, 40), (12, 40)].into_iter().collect(), "lowest pid wins for shared sockets");
            assert!(socket_owners(&root, &wanted, &|_| false).is_empty());
            let _ = std::fs::remove_dir_all(&root);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux {
    //! Parse `ss -tinpeH` (iproute2 6.x), the fallback when netlink is unavailable. Each
    //! socket is a header line plus an indented tcp_info line:
    //!
    //! ```text
    //! ESTAB 0 0 [::ffff:127.0.0.1]:18081 [::ffff:127.0.0.1]:46264 users:(("python3",pid=6111,fd=5)) uid:1000 ino:8716493 sk:302f cgroup:/ <->
    //! \t ts sack cubic wscale:10,10 rto:206 ... bytes_sent:134464 bytes_retrans:34464 bytes_acked:100000 bytes_received:12 segs_out:4 ...
    //! ```
    //!
    //! rx = `bytes_received`, tx = `bytes_acked` (delivered payload; `bytes_sent`
    //! also counts retransmissions, so it is only a fallback).
    use super::Rates;
    use std::collections::HashMap;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum SockKey {
        Ino(u64),
        Tuple(String, String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct SockStat {
        pub pid: u32,
        pub rx: u64,
        pub tx: u64,
    }

    pub type Sockets = HashMap<SockKey, SockStat>;

    fn field<'a>(tokens: &[&'a str], key: &str) -> Option<&'a str> {
        tokens.iter().find_map(|t| t.strip_prefix(key))
    }

    /// First `pid=N` inside `users:((...))`. A socket shared by several processes
    /// (fork after accept) is attributed to the first one listed.
    fn first_pid(line: &str) -> Option<u32> {
        let users = &line[line.find("users:((")?..];
        let rest = &users[users.find("pid=")? + 4..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].parse().ok()
    }

    fn flush(header: &Option<String>, info: &str, out: &mut Sockets) {
        let Some(h) = header else { return };
        let Some(pid) = first_pid(h).filter(|&p| p > 0) else { return };
        let ht: Vec<&str> = h.split_whitespace().collect();
        let it: Vec<&str> = info.split_whitespace().collect();
        let num = |k: &str| field(&it, k).and_then(|v| v.parse::<u64>().ok());
        let rx = num("bytes_received:").unwrap_or(0);
        let tx = num("bytes_acked:").or_else(|| num("bytes_sent:")).unwrap_or(0);
        let key = match field(&ht, "ino:").and_then(|v| v.parse::<u64>().ok()).filter(|&i| i != 0) {
            Some(ino) => SockKey::Ino(ino),
            // Columns: State Recv-Q Send-Q Local Peer (no Netid column with a single -t).
            None if ht.len() >= 5 => SockKey::Tuple(ht[3].to_string(), ht[4].to_string()),
            None => return,
        };
        out.insert(key, SockStat { pid, rx, tx });
    }

    /// Parse a full `ss -tinpeH` dump. Sockets without a visible pid are dropped.
    pub fn parse_ss(out: &str) -> Sockets {
        let mut socks = Sockets::new();
        let mut header: Option<String> = None;
        let mut info = String::new();
        for line in out.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if line.starts_with(char::is_whitespace) {
                info.push(' ');
                info.push_str(line);
            } else {
                flush(&header, &info, &mut socks);
                header = Some(line.to_string());
                info.clear();
            }
        }
        flush(&header, &info, &mut socks);
        socks
    }

    /// Per-pid (rx, tx) bytes/sec. Sockets seen in both samples contribute their delta
    /// (counter decrease, e.g. inode reuse, clamps to 0); sockets new since `prev`
    /// were opened during the interval, so their whole counters count. Sockets that
    /// vanished contribute nothing (their last bytes are lost, never negative).
    pub fn compute_rates(prev: &Sockets, cur: &Sockets, secs: f64) -> Rates {
        if secs <= 0.0 {
            return Rates::new();
        }
        let mut bytes: HashMap<u32, (u64, u64)> = HashMap::new();
        for (key, c) in cur {
            let (drx, dtx) = match prev.get(key) {
                Some(p) if p.pid == c.pid => (c.rx.saturating_sub(p.rx), c.tx.saturating_sub(p.tx)),
                Some(_) => continue, // socket handed to another pid; no baseline for it
                None => (c.rx, c.tx),
            };
            let e = bytes.entry(c.pid).or_default();
            e.0 += drx;
            e.1 += dtx;
        }
        bytes
            .into_iter()
            .map(|(pid, (rx, tx))| (pid, ((rx as f64 / secs) as u64, (tx as f64 / secs) as u64)))
            .filter(|(_, (rx, tx))| *rx > 0 || *tx > 0)
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Captured from `ss -tinpeH` on Debian bookworm (iproute2 6.1, kernel 7.2) as root.
        const SAMPLE: &str = "ESTAB 100000 0               127.0.0.1:46264          127.0.0.1:18081 users:((\"python3\",pid=6111,fd=4)) ino:8711508 sk:302e cgroup:/ <->
\t ts sack cubic wscale:10,10 rto:200 rtt:0.019/0.009 ato:80 mss:32768 pmtu:65535 rcvmss:34464 advmss:65483 cwnd:10 bytes_acked:1 bytes_received:100000 segs_out:4 segs_in:5 data_segs_in:4 send 137970526316bps lastsnd:992 lastrcv:992 lastack:985 pacing_rate 275713684208bps delivered:1 app_limited rcv_rtt:0.025 rcv_space:65495 rcv_ssthresh:93736 minrtt:0.019 snd_wnd:65536
ESTAB 0      0      [::ffff:127.0.0.1]:18081 [::ffff:127.0.0.1]:46264 users:((\"python3\",pid=6112,fd=5),(\"python3\",pid=6200,fd=5)) uid:1000 ino:8711509 sk:302f cgroup:/user.slice <->
\t ts sack cubic wscale:10,10 rto:206 rtt:5.389/10.752 mss:47104 pmtu:65535 rcvmss:536 advmss:65483 cwnd:10 bytes_sent:134464 bytes_retrans:34464 bytes_acked:100000 segs_out:4 segs_in:4 data_segs_out:4 send 699261459bps lastsnd:986 lastrcv:993 lastack:950 pacing_rate 1398458040bps delivery_rate 26648808bps delivered:5 busy:43ms retrans:0/1 dsack_dups:1 rcv_space:65483 rcv_ssthresh:65483 minrtt:0.015 snd_wnd:27648
ESTAB 0      0               10.0.2.15:22             10.0.2.2:51514 ino:4242 sk:1 cgroup:/system.slice/ssh.service <->
\t ts sack cubic wscale:7,7 rto:204 bytes_sent:5000 bytes_acked:5000 bytes_received:3000
FIN-WAIT-2 0 0                 10.0.2.15:40000          1.2.3.4:443 users:((\"curl\",pid=7000,fd=3))
\t cubic bytes_acked:10 bytes_received:20
";

        #[test]
        fn parses_ss_records() {
            let s = parse_ss(SAMPLE);
            assert_eq!(s.len(), 3, "pid-less ssh socket dropped: {s:?}");
            assert_eq!(s[&SockKey::Ino(8711508)], SockStat { pid: 6111, rx: 100000, tx: 1 });
            // Shared socket -> first listed pid; tx from bytes_acked not bytes_sent.
            assert_eq!(s[&SockKey::Ino(8711509)], SockStat { pid: 6112, rx: 0, tx: 100000 });
            // No ino (older ss / no -e): keyed by 4-tuple.
            let k = SockKey::Tuple("10.0.2.15:40000".into(), "1.2.3.4:443".into());
            assert_eq!(s[&k], SockStat { pid: 7000, rx: 20, tx: 10 });
            assert!(parse_ss("").is_empty());
            assert!(parse_ss("garbage\n\tbytes_received:5\nusers:((pid=x\n").is_empty());
        }

        #[test]
        fn rates_from_socket_deltas() {
            let st = |pid, rx, tx| SockStat { pid, rx, tx };
            let prev: Sockets = [
                (SockKey::Ino(1), st(10, 1000, 100)),
                (SockKey::Ino(2), st(10, 5000, 0)),
                (SockKey::Ino(3), st(20, 9_000_000, 0)), // closes before next sample
                (SockKey::Ino(4), st(30, 500, 500)),
            ]
            .into_iter()
            .collect();
            let cur: Sockets = [
                (SockKey::Ino(1), st(10, 3000, 300)),
                (SockKey::Ino(2), st(10, 7000, 0)),
                (SockKey::Ino(5), st(20, 400, 0)),   // new socket: counted fully
                (SockKey::Ino(4), st(30, 500, 500)), // idle
            ]
            .into_iter()
            .collect();
            let r = compute_rates(&prev, &cur, 2.0);
            assert_eq!(r.get(&10), Some(&(2000, 100)));
            assert_eq!(r.get(&20), Some(&(200, 0)), "closed socket never goes negative");
            assert!(!r.contains_key(&30));
            assert!(compute_rates(&prev, &cur, 0.0).is_empty());
            // Counter reset on inode reuse clamps to zero.
            let reused: Sockets = [(SockKey::Ino(1), st(10, 5, 5))].into_iter().collect();
            assert!(compute_rates(&prev, &reused, 1.0).is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(line: &str) -> Option<(u32, u64, u64)> {
        parse_row(line, &NettopCols::DEFAULT)
    }

    #[test]
    fn parses_lines() {
        assert_eq!(row("mDNSResponder.504,37035083,15306032,"), Some((504, 37035083, 15306032)));
        assert_eq!(row("Brave Browser H.1943,107110441,20032061,"), Some((1943, 107110441, 20032061)));
        assert_eq!(row("python3.11.75535,7348,3686,"), Some((75535, 7348, 3686)));
        assert_eq!(row("weird,name.12,1,2"), Some((12, 1, 2)));
        assert_eq!(row("a, b ,c.d.5,10,20,\r\n"), Some((5, 10, 20)));
        assert_eq!(row("Code Helper (Renderer).812,0,9,"), Some((812, 0, 9)));
        assert_eq!(row(",bytes_in,bytes_out,"), None);
        assert_eq!(row(""), None);
        assert_eq!(row("nopid,1,2,"), None);
        assert_eq!(row("name.12,x,2,"), None);
        assert_eq!(row("name.12,1,"), None, "too few columns");
    }

    #[test]
    fn header_locates_columns() {
        assert_eq!(NettopCols::from_header(",bytes_in,bytes_out,"), Some(NettopCols::DEFAULT));
        // Reordered / extra columns (as printed without -J).
        let full = "time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch,";
        let c = NettopCols::from_header(full).unwrap();
        assert_eq!((c.ident, c.bytes_in, c.bytes_out, c.width), (1, 4, 5, 20));
        assert_eq!(NettopCols::from_header("mDNSResponder.504,37035083,15306032,"), None);
        assert_eq!(NettopCols::from_header("time,bytes_in,bytes_out,"), None, "no identifier column");
    }

    #[test]
    fn parses_whole_samples_with_odd_names() {
        // Header-driven: bytes_out before bytes_in, plus an unknown leading column.
        let out = "time,,bytes_out,extra,bytes_in,\n\
                   05:59:55.330036,kernel_task.0,200,x,100,\n\
                   05:59:55.330041,Google Chrome Helper (GPU).4711,5,,7,\n\
                   05:59:55.330042,odd, name,with.dots.99,1,,2,\n\
                   05:59:55.330043,garbage\n";
        let m = parse_output(out);
        assert_eq!(m.get(&0), Some(&(100, 200)));
        assert_eq!(m.get(&4711), Some(&(7, 5)));
        assert_eq!(m.get(&99), Some(&(2, 1)));
        assert_eq!(m.len(), 3);
        // Real `-J bytes_in,bytes_out -x` output (macOS 15), duplicates summed.
        let m = parse_output(
            ",bytes_in,bytes_out,\nkernel_task.0,175032304,68613412,\nlaunchd.1,0,0,\napsd.363,4395,27812,\napsd.363,5,8,\n",
        );
        assert_eq!(m.get(&363), Some(&(4400, 27820)));
        assert_eq!(m.get(&1), Some(&(0, 0)));
        assert!(parse_output("").is_empty());
    }

    #[test]
    fn computes_rates() {
        let prev = parse_output("a.1,100,200,\nb.2,50,50,\nc.3,500,500,\n");
        let cur = parse_output(",bytes_in,bytes_out,\na.1,300,600,\nb.2,50,50,\nc.3,10,10,\nd.4,999,999,\n");
        let r = compute_rates(&prev, &cur, 2.0);
        assert_eq!(r.get(&1), Some(&(100, 200)));
        assert!(!r.contains_key(&2), "idle pids omitted");
        assert!(!r.contains_key(&3), "pid reuse clamps to zero");
        assert!(!r.contains_key(&4), "new pid has no baseline");
        assert!(compute_rates(&prev, &cur, 0.0).is_empty());
    }

    #[test]
    fn capture_times_out_and_reaps() {
        let slot = Mutex::new(None);
        let stop = AtomicBool::new(false);
        let t = Instant::now();
        // Our own child; killed by the timeout.
        assert_eq!(run_capture(&slot, &stop, "sleep", &["30"], Duration::from_millis(300)), None);
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(slot.lock().unwrap().is_none());
        assert_eq!(run_capture(&slot, &stop, "sh", &["-c", "printf \"$LC_ALL\""], CHILD_TIMEOUT).as_deref(), Some("C"));
        assert_eq!(run_capture(&slot, &stop, "sh", &["-c", "echo hi; exit 3"], CHILD_TIMEOUT), None, "non-zero exit");
        assert_eq!(run_capture(&slot, &stop, "/nonexistent/fat-prog", &[], CHILD_TIMEOUT), None);
    }

    /// Live: runs real nettop / netlink. `cargo test live_net -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_net() {
        let s = NetSampler::start();
        std::thread::sleep(Duration::from_millis(4500));
        let r = s.latest();
        let mut v: Vec<_> = r.iter().collect();
        v.sort_by_key(|(_, (rx, tx))| std::cmp::Reverse(rx + tx));
        for (pid, (rx, tx)) in v.iter().take(10) {
            println!("pid {pid}: rx {rx} B/s tx {tx} B/s");
        }
        println!("{} pids with traffic", r.len());
    }

    #[test]
    fn sampler_starts_and_drops_cleanly() {
        let s = NetSampler::start();
        let _ = s.latest();
        drop(s);
    }

    #[cfg(target_os = "linux")]
    mod linux_live {
        use super::super::{diag, linux};
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        use std::time::{Duration, Instant};

        fn ino(s: &TcpStream) -> u64 {
            std::fs::metadata(format!("/proc/self/fd/{}", s.as_raw_fd())).unwrap().ino()
        }

        /// Our own loopback connection, `a2b` bytes one way and `b2a` back.
        fn pair(bind: &str, a2b: usize, b2a: usize) -> Option<(TcpStream, TcpStream)> {
            let l = TcpListener::bind(bind).ok()?;
            let mut a = TcpStream::connect(l.local_addr().ok()?).ok()?;
            let (mut b, _) = l.accept().ok()?;
            let w = std::thread::spawn(move || {
                a.write_all(&vec![7u8; a2b]).unwrap();
                a
            });
            let mut got = vec![0u8; a2b];
            b.read_exact(&mut got).unwrap();
            let mut a = w.join().unwrap();
            b.write_all(&vec![1u8; b2a]).unwrap();
            let mut got = vec![0u8; b2a];
            a.read_exact(&mut got).unwrap();
            Some((a, b))
        }

        #[test]
        fn netlink_attributes_own_traffic() {
            let mut s = diag::Sampler::new().expect("NETLINK_SOCK_DIAG socket");
            let me = std::process::id();
            for bind in ["127.0.0.1:0", "[::1]:0"] {
                let Some((a, b)) = pair(bind, 300_000, 50_000) else {
                    assert!(bind.starts_with('['), "IPv4 loopback must work");
                    continue; // no IPv6 loopback in this container
                };
                let (ia, ib) = (ino(&a), ino(&b));
                // Loopback ACKs are near-instant; allow a moment for bytes_acked to catch up.
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    let (socks, missed) = s.sample(&[]).expect("dump");
                    assert!(missed.is_empty());
                    let (sa, sb) =
                        (socks.get(&linux::SockKey::Ino(ia)).copied(), socks.get(&linux::SockKey::Ino(ib)).copied());
                    // tcpi_bytes_acked also counts the connecting side's SYN (+1).
                    let ok = matches!((sa, sb), (Some(x), Some(y)) if x.pid == me && y.pid == me
                        && (300_000..=300_001).contains(&x.tx) && x.rx == 50_000
                        && y.rx == 300_000 && (50_000..=50_001).contains(&y.tx));
                    if ok {
                        break;
                    }
                    assert!(Instant::now() < deadline, "{bind}: a={sa:?} b={sb:?}, want pid {me}");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }

        fn thread_cpu() -> Duration {
            let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: valid timespec out-pointer.
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
            Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
        }

        /// CPU of the whole process, so the setns+socket thread that `open_socket_in_netns`
        /// spawns per foreign netns is counted too (a thread clock would miss it).
        fn process_cpu() -> Duration {
            let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: valid timespec out-pointer.
            unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
            Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
        }

        fn children_cpu() -> Duration {
            // SAFETY: zeroed rusage is a valid out-buffer.
            let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
            unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut ru) };
            let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
            tv(ru.ru_utime) + tv(ru.ru_stime)
        }

        /// Cost and agreement of netlink vs ss, with traffic we generate ourselves.
        /// `cargo test bench_netlink_vs_ss -- --ignored --nocapture` (needs ss).
        #[test]
        #[ignore]
        fn bench_netlink_vs_ss() {
            let me = std::process::id();
            // ~20 MB/s loopback pump in both directions, our own sockets.
            let (mut a, b) = pair("127.0.0.1:0", 1, 1).unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let st = stop.clone();
            // Held while netlink cost is measured with the process clock, so the pump's own
            // CPU is not billed to netlink (the sink then blocks in read and costs nothing).
            let quiet = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let qt = quiet.clone();
            let mut b2 = b.try_clone().unwrap();
            let pump = std::thread::spawn(move || {
                let chunk = vec![3u8; 200_000];
                while !st.load(std::sync::atomic::Ordering::Relaxed) {
                    if qt.load(std::sync::atomic::Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    a.write_all(&chunk).unwrap();
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            let sink = std::thread::spawn(move || {
                let mut buf = vec![0u8; 1 << 16];
                while b2.read(&mut buf).map(|n| n > 0).unwrap_or(false) {}
            });
            let mut nl = diag::Sampler::new().unwrap();
            let slot = std::sync::Mutex::new(None);
            let flag = std::sync::atomic::AtomicBool::new(false);
            // As root, include every container netns, exactly as the sampler loop does.
            // SAFETY: geteuid has no preconditions.
            let root = unsafe { libc::geteuid() } == 0;
            let foreign = if root { crate::collect::ports::foreign_netns(super::super::MAX_NETNS) } else { Vec::new() };
            println!("foreign netns sampled: {}", foreign.len());
            let ss = || super::super::ss_sample(&slot, &flag, root).expect("ss");
            let n = 20;
            let (mut nl_wall, mut nl_cpu, mut ss_wall, mut ss_cpu) =
                (Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO);
            let mut nl_socks = 0;
            let mut ss_socks = 0;
            // Warm the owner cache once (first netlink sample walks /proc for every socket).
            let t = Instant::now();
            let c = thread_cpu();
            let first = nl.sample(&foreign).unwrap().0;
            println!(
                "netlink first sample (cold owner cache): {:?} wall, {:?} cpu, {} sockets",
                t.elapsed(),
                thread_cpu() - c,
                first.len()
            );
            for _ in 0..n {
                // A full sampler cycle: the sampler loop re-lists foreign netns every time and
                // spawns one setns thread per netns, so both are inside the measurement.
                quiet.store(true, std::sync::atomic::Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(20));
                let (t, c) = (Instant::now(), process_cpu());
                let foreign =
                    if root { crate::collect::ports::foreign_netns(super::super::MAX_NETNS) } else { Vec::new() };
                nl_socks = nl.sample(&foreign).unwrap().0.len();
                nl_wall += t.elapsed();
                nl_cpu += process_cpu().saturating_sub(c);
                quiet.store(false, std::sync::atomic::Ordering::Relaxed);
                let (t, c, k) = (Instant::now(), thread_cpu(), children_cpu());
                ss_socks = ss().len();
                ss_wall += t.elapsed();
                ss_cpu += (thread_cpu() - c) + (children_cpu() - k);
            }
            let per = |d: Duration| d / n;
            println!(
                "netlink: {:?} wall, {:?} cpu per cycle incl. netns walk + setns threads ({nl_socks} sockets with traffic+owner)",
                per(nl_wall),
                per(nl_cpu)
            );
            println!(
                "ss:      {:?} wall, {:?} cpu per sample incl. child ({ss_socks} sockets with pid)",
                per(ss_wall),
                per(ss_cpu)
            );
            // Agreement: both methods over the same 2s window.
            let (n0, s0, t0) = (nl.sample(&foreign).unwrap().0, ss(), Instant::now());
            std::thread::sleep(Duration::from_secs(2));
            let (n1, s1, t1) = (nl.sample(&foreign).unwrap().0, ss(), Instant::now());
            let secs = t1.duration_since(t0).as_secs_f64();
            let rn = linux::compute_rates(&n0, &n1, secs);
            let rs = linux::compute_rates(&s0, &s1, secs);
            println!("own pid {me}: netlink {:?} B/s, ss {:?} B/s", rn.get(&me), rs.get(&me));
            let mut pids: Vec<_> =
                rn.keys().chain(rs.keys()).copied().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
            pids.sort();
            for p in pids {
                println!("  pid {p}: netlink {:?} ss {:?}", rn.get(&p), rs.get(&p));
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            pump.join().unwrap();
            let _ = b.shutdown(std::net::Shutdown::Both);
            sink.join().unwrap();
            let (nrx, ntx) = rn[&me];
            let (srx, stx) = rs[&me];
            let close = |x: u64, y: u64| (x as f64 - y as f64).abs() <= 0.05 * (x.max(y) as f64) + 100_000.0;
            assert!(close(nrx, srx) && close(ntx, stx), "netlink {:?} vs ss {:?}", rn[&me], rs[&me]);
        }
    }
}
