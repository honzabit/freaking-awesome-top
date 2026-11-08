//! Per-process network rates via nettop in a background thread. OWNER: ports-net agent.
//!
//! Verified on macOS 15: `nettop -P -L 1 -J bytes_in,bytes_out -x` prints one
//! header line `,bytes_in,bytes_out,` followed by `name.pid,in,out,` rows with
//! CUMULATIVE byte counters, and exits in ~25ms. Continuous mode (`-L 0`) is
//! block-buffered when stdout is a pipe, so instead we run one-shot `-L 1` every
//! couple of seconds and compute rates from the deltas ourselves.
//!
//! Linux: `ss -tinpeH` every 2s (see [`linux`]). It prints one record per TCP socket
//! with the owning process (`users:(("python3",pid=6111,fd=4))`), the socket inode
//! (`ino:`) and tcp_info counters (`bytes_received:`, `bytes_acked:`). Counters are
//! diffed per socket (keyed by inode, else the 4-tuple) and summed per pid, so a
//! socket closing between samples never yields a negative rate. Without root, ss only
//! reports pids for our own processes; other sockets are ignored. UDP is skipped:
//! the kernel keeps no per-socket byte counters for it. If ss is missing the map
//! simply stays empty.
use std::collections::HashMap;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(2);
/// Sleep granularity so Drop doesn't wait a full interval.
const TICK: Duration = Duration::from_millis(100);

type Rates = HashMap<u32, (u64, u64)>;

pub struct NetSampler {
    rates: Arc<Mutex<Rates>>,
    stop: Arc<AtomicBool>,
    /// The nettop child currently running (if any), so Drop can kill it.
    child: Arc<Mutex<Option<Child>>>,
    handle: Option<JoinHandle<()>>,
}

impl NetSampler {
    /// Spawn background sampler. Must never block the caller; degrade to empty map if nettop missing.
    pub fn start() -> Self {
        let rates = Arc::new(Mutex::new(Rates::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let child = Arc::new(Mutex::new(None));
        let handle = {
            let (rates, stop, child) = (rates.clone(), stop.clone(), child.clone());
            std::thread::Builder::new()
                .name(if cfg!(target_os = "linux") { "fat-ss" } else { "fat-nettop" }.into())
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
            && let Some(mut c) = slot.take() {
                // Only ever our own nettop child.
                let _ = c.kill();
                let _ = c.wait();
            }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn sampler_loop(rates: Arc<Mutex<Rates>>, stop: Arc<AtomicBool>, slot: Arc<Mutex<Option<Child>>>) {
    let mut prev: Option<(Instant, linux::Sockets)> = None;
    let mut failures = 0u32;
    while !stop.load(Ordering::SeqCst) {
        match run_capture(&slot, &stop, "ss", &["-tinpeH"]) {
            Some(out) => {
                failures = 0;
                let at = Instant::now();
                let cur = linux::parse_ss(&out);
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
        let wait_until = Instant::now() + INTERVAL;
        while Instant::now() < wait_until && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(TICK);
        }
    }
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
                if let Ok(mut m) = rates.lock() {
                    m.clear();
                }
                // nettop missing or broken: back off, and give up after repeated failures.
                if failures >= 5 {
                    return;
                }
            }
        }
        let wait_until = Instant::now() + INTERVAL;
        while Instant::now() < wait_until && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(TICK);
        }
    }
}

/// Run one `nettop -L 1` sample.
#[cfg(not(target_os = "linux"))]
fn run_nettop(slot: &Mutex<Option<Child>>, stop: &AtomicBool) -> Option<String> {
    run_capture(slot, stop, "nettop", &["-P", "-L", "1", "-J", "bytes_in,bytes_out", "-x"])
}

/// Run `program args` to completion and capture stdout. The child is parked in `slot`
/// while running so Drop can kill it; it is always reaped here (no zombies).
fn run_capture(slot: &Mutex<Option<Child>>, stop: &AtomicBool, program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take();
    {
        let mut s = slot.lock().ok()?;
        if stop.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        *s = Some(child);
    }
    let mut out = String::new();
    // Reading to EOF finishes when nettop exits (or is killed by Drop).
    let read_ok = stdout.as_mut().map(|o| o.read_to_string(&mut out).is_ok()).unwrap_or(false);
    let status = slot.lock().ok().and_then(|mut s| s.take()).and_then(|mut c| c.wait().ok());
    match status {
        Some(st) if st.success() && read_ok => Some(out),
        _ => None,
    }
}

/// Parse one `name.pid,bytes_in,bytes_out,` row. Parsed from the right so
/// process names containing '.' or ',' still work.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn parse_line(line: &str) -> Option<(u32, u64, u64)> {
    let line = line.trim().trim_end_matches(',');
    let mut it = line.rsplitn(3, ',');
    let out: u64 = it.next()?.trim().parse().ok()?;
    let inb: u64 = it.next()?.trim().parse().ok()?;
    let ident = it.next()?;
    let (_, pid) = ident.rsplit_once('.')?;
    Some((pid.trim().parse().ok()?, inb, out))
}

/// Parse a whole nettop sample into pid -> cumulative (in, out). Rows for the
/// same pid (shouldn't happen with -P, but be safe) are summed.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn parse_output(out: &str) -> HashMap<u32, (u64, u64)> {
    let mut m: HashMap<u32, (u64, u64)> = HashMap::new();
    for (pid, i, o) in out.lines().filter_map(parse_line) {
        let e = m.entry(pid).or_default();
        e.0 += i;
        e.1 += o;
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
mod linux {
    //! Parse `ss -tinpeH` (iproute2 6.x). Each socket is a header line plus an indented
    //! tcp_info line:
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
                (SockKey::Ino(5), st(20, 400, 0)), // new socket: counted fully
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

    #[test]
    fn parses_lines() {
        assert_eq!(parse_line("mDNSResponder.504,37035083,15306032,"), Some((504, 37035083, 15306032)));
        assert_eq!(parse_line("Brave Browser H.1943,107110441,20032061,"), Some((1943, 107110441, 20032061)));
        assert_eq!(parse_line("python3.11.75535,7348,3686,"), Some((75535, 7348, 3686)));
        assert_eq!(parse_line("weird,name.12,1,2"), Some((12, 1, 2)));
        assert_eq!(parse_line(",bytes_in,bytes_out,"), None);
        assert_eq!(parse_line(""), None);
        assert_eq!(parse_line("nopid,1,2,"), None);
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

    /// Live: runs real nettop. `cargo test live_net -- --ignored --nocapture`
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
}
