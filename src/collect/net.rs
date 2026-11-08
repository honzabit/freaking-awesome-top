//! Per-process network rates via nettop in a background thread. OWNER: ports-net agent.
//!
//! Verified on macOS 15: `nettop -P -L 1 -J bytes_in,bytes_out -x` prints one
//! header line `,bytes_in,bytes_out,` followed by `name.pid,in,out,` rows with
//! CUMULATIVE byte counters, and exits in ~25ms. Continuous mode (`-L 0`) is
//! block-buffered when stdout is a pipe, so instead we run one-shot `-L 1` every
//! couple of seconds and compute rates from the deltas ourselves.
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
                .name("fat-nettop".into())
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

fn sampler_loop(rates: Arc<Mutex<Rates>>, stop: Arc<AtomicBool>, slot: Arc<Mutex<Option<Child>>>) {
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

/// Run one `nettop -L 1` sample. The child is parked in `slot` while running so
/// Drop can kill it; it is always reaped here (no zombies).
fn run_nettop(slot: &Mutex<Option<Child>>, stop: &AtomicBool) -> Option<String> {
    let mut child = Command::new("nettop")
        .args(["-P", "-L", "1", "-J", "bytes_in,bytes_out", "-x"])
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
