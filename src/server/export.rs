//! Prometheus text exposition (format 0.0.4) of the latest snapshot, served read-only by the
//! recorder daemon. OWNER: recorder-export agent. std::net only, one listener thread, GET
//! /metrics (and / -> short text), everything else 404, requests handled one at a time with
//! read/write timeouts and a bounded request size. Binds 127.0.0.1 by default (ServerCfg).
//!
//! Metric names (all `fat_` prefixed; labels bounded: units by ServerCfg::max_units, disks and
//! mounts by the host, kinds/severities by fat's own enums; no pid/cmd labels):
//! fat_up, fat_info{version,profile}, fat_sample_timestamp_seconds, fat_cpu_percent,
//! fat_cpu_steal_percent, fat_cpu_iowait_percent, fat_load{period="1|5|15"},
//! fat_memory_{total,used,available}_bytes, fat_swap_used_bytes,
//! fat_pressure_percent{resource="cpu|memory|io",kind="some|full"}, fat_oom_kills_total,
//! fat_procs_blocked, fat_dstate_procs, fat_fd_{used,max}, fat_conntrack_{used,max},
//! fat_ephemeral_ports_used, fat_ephemeral_ports_range_size, fat_tcp_retrans_per_second,
//! fat_listen_drops_per_second, fat_disk_util_percent{disk}, fat_disk_await_ms{disk,op},
//! fat_disk_queue_depth{disk}, fat_volume_used_ratio{mount}, fat_units{kind,state},
//! fat_unit_up{unit,kind} (1 active, 0 otherwise), fat_unit_cpu_percent{unit,kind},
//! fat_unit_memory_bytes{unit,kind}, fat_unit_memory_limit_bytes{unit,kind},
//! fat_unit_io_bytes_per_second{unit,kind,op}, fat_unit_restarts_total{unit,kind},
//! fat_unit_cpu_throttled_percent{unit,kind}, fat_unit_pressure_percent{unit,kind,resource}
//! (PSI "some", avg10), fat_unit_oom_kills_total{unit,kind}, fat_findings{severity},
//! fat_events_total{kind}.
use super::{Event, EventKind, LatestSnapshot, Severity};
use crate::model::Snapshot;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

/// State the recorder loop adds next to the snapshot: cumulative event counts since the
/// daemon started (Prometheus counters) and the volumes of the last sample.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExportExtra {
    pub events_total: BTreeMap<EventKind, u64>,
    /// (mount, used, avail).
    pub volumes: Vec<(String, u64, u64)>,
}

static EXTRA: Mutex<Option<ExportExtra>> = Mutex::new(None);

/// Called by the recorder loop after each sample: count its events, remember its volumes.
pub fn note_sample(snap: &Snapshot, vols: &[crate::fs::Volume]) {
    let Ok(mut g) = EXTRA.lock() else { return };
    let x = g.get_or_insert_with(ExportExtra::default);
    count(&mut x.events_total, &snap.events);
    x.volumes = vols
        .iter()
        .filter(|v| !v.hidden && v.used + v.avail > 0)
        .map(|v| (v.mount.clone(), v.used, v.avail))
        .collect();
}

fn count(totals: &mut BTreeMap<EventKind, u64>, events: &[Event]) {
    for e in events {
        *totals.entry(e.kind).or_default() += 1;
    }
}

/// Render the exposition text for one snapshot (label values escaped per the format), with
/// the recorder's counters and volumes.
pub fn render(snap: &Snapshot) -> String {
    let extra = EXTRA.lock().ok().and_then(|g| g.clone()).unwrap_or_default();
    // Doctor findings on the served snapshot; a failing rule must not take /metrics down.
    let findings = std::panic::catch_unwind(|| crate::blame::diagnose(snap, None)).ok();
    render_with(snap, &extra, findings.as_deref())
}

/// Escape a label value: backslash, double quote and newline.
fn esc(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
    o
}

fn num(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf".into() } else { "-Inf".into() }
    } else if v == v.trunc() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        let s = format!("{v:.3}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// One metric family: HELP and TYPE once, then its samples. Families without samples are
/// omitted entirely.
struct Out(String);

impl Out {
    fn fam(&mut self, name: &str, typ: &str, help: &str, samples: Vec<(Vec<(&str, String)>, f64)>) {
        if samples.is_empty() {
            return;
        }
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {typ}");
        for (labels, v) in samples {
            if labels.is_empty() {
                let _ = writeln!(self.0, "{name} {}", num(v));
            } else {
                let l: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{}\"", esc(v))).collect();
                let _ = writeln!(self.0, "{name}{{{}}} {}", l.join(","), num(v));
            }
        }
    }

    fn one(&mut self, name: &str, typ: &str, help: &str, v: Option<f64>) {
        self.fam(name, typ, help, v.map(|v| vec![(vec![], v)]).unwrap_or_default());
    }
}

/// Pure renderer behind [`render`] (golden-tested).
pub fn render_with(snap: &Snapshot, extra: &ExportExtra, findings: Option<&[crate::model::Finding]>) -> String {
    let mut o = Out(String::with_capacity(8192 + snap.units.len() * 1200));
    let s = &snap.system;
    let k = snap.kernel.as_ref();
    let g = "gauge";
    let c = "counter";
    o.one("fat_up", g, "1 when fat has a sample to serve.", Some(1.0));
    let (version, profile) = snap
        .meta
        .as_ref()
        .map(|m| (m.version.clone(), m.profile.as_str().to_string()))
        .unwrap_or_else(|| (env!("CARGO_PKG_VERSION").to_string(), "desktop".into()));
    o.fam("fat_info", g, "fat version and profile.", vec![(vec![("version", version), ("profile", profile)], 1.0)]);
    o.one("fat_sample_timestamp_seconds", g, "Time of the served sample (unix seconds).", Some(snap.ts as f64 / 1000.0));
    o.one("fat_cpu_percent", g, "Host CPU use, 0..100 of all cores.", Some(s.cpu as f64));
    o.one("fat_cpu_steal_percent", g, "CPU time stolen by the hypervisor, 0..100 of all cores.", k.map(|k| k.steal_pct as f64));
    o.one("fat_cpu_iowait_percent", g, "CPU time idle waiting for I/O, 0..100 of all cores.", k.map(|k| k.iowait_pct as f64));
    o.fam(
        "fat_load",
        g,
        "Load average.",
        ["1", "5", "15"].iter().zip(s.load).map(|(p, v)| (vec![("period", p.to_string())], v)).collect(),
    );
    o.one("fat_memory_total_bytes", g, "Physical memory.", Some(s.mem_total as f64));
    o.one("fat_memory_used_bytes", g, "Physical memory in use.", Some(s.mem_used as f64));
    o.one(
        "fat_memory_available_bytes",
        g,
        "Memory available for new work without swapping (MemAvailable).",
        k.map(|k| k.mem_available as f64).or(Some(s.mem_total.saturating_sub(s.mem_used) as f64)),
    );
    o.one("fat_swap_used_bytes", g, "Swap in use.", Some(s.swap_used as f64));
    let psi: Option<super::Pressure> = k.and_then(|k| k.pressure).or_else(|| {
        s.psi.map(|p| super::Pressure {
            cpu_some: p.cpu_some,
            mem_some: p.mem_some,
            mem_full: p.mem_full,
            io_some: p.io_some,
            io_full: p.io_full,
            ..Default::default()
        })
    });
    if let Some(p) = psi {
        let mut v = vec![];
        for (res, some, full) in [("cpu", p.cpu_some, p.cpu_full), ("memory", p.mem_some, p.mem_full), ("io", p.io_some, p.io_full)] {
            v.push((vec![("resource", res.to_string()), ("kind", "some".to_string())], some as f64));
            v.push((vec![("resource", res.to_string()), ("kind", "full".to_string())], full as f64));
        }
        o.fam("fat_pressure_percent", g, "Pressure stall information, avg10 percent of wall time.", v);
    }
    if let Some(k) = k {
        o.one("fat_oom_kills_total", c, "Kernel OOM kills since boot.", Some(k.oom_kills_total as f64));
        o.one("fat_procs_blocked", g, "Processes blocked on I/O (procs_blocked).", Some(k.procs_blocked as f64));
        o.one("fat_dstate_procs", g, "Processes stuck in uninterruptible sleep beyond dstate_min_s.", Some(k.d_state.len() as f64));
        o.one("fat_fd_used", g, "Allocated file handles.", k.fd_used.map(|v| v as f64));
        o.one("fat_fd_max", g, "File handle limit (fs.file-max).", k.fd_max.map(|v| v as f64));
        o.one("fat_conntrack_used", g, "Connection tracking entries.", k.conntrack_used.map(|v| v as f64));
        o.one("fat_conntrack_max", g, "Connection tracking table size.", k.conntrack_max.map(|v| v as f64));
        o.one("fat_ephemeral_ports_used", g, "Local ports in use from the ephemeral range.", k.ephemeral_used.map(|v| v as f64));
        o.one(
            "fat_ephemeral_ports_range_size",
            g,
            "Size of the ephemeral port range.",
            k.ephemeral_range.map(|(a, b)| (b as f64 - a as f64 + 1.0).max(0.0)),
        );
        o.one("fat_tcp_retrans_per_second", g, "TCP segments retransmitted per second.", Some(k.tcp_retrans_ps as f64));
        o.one("fat_listen_drops_per_second", g, "Connections dropped at listen sockets per second.", Some(k.listen_drops_ps as f64));
        o.fam(
            "fat_disk_util_percent",
            g,
            "Share of the interval the disk was busy.",
            k.disks.iter().map(|d| (vec![("disk", d.name.clone())], d.util_pct as f64)).collect(),
        );
        o.fam(
            "fat_disk_await_ms",
            g,
            "Average I/O completion time over the interval.",
            k.disks
                .iter()
                .flat_map(|d| {
                    [
                        (vec![("disk", d.name.clone()), ("op", "read".to_string())], d.r_await_ms as f64),
                        (vec![("disk", d.name.clone()), ("op", "write".to_string())], d.w_await_ms as f64),
                    ]
                })
                .collect(),
        );
        o.fam(
            "fat_disk_queue_depth",
            g,
            "Average in-flight requests.",
            k.disks.iter().map(|d| (vec![("disk", d.name.clone())], d.queue_depth as f64)).collect(),
        );
    }
    o.fam(
        "fat_volume_used_ratio",
        g,
        "Used share of a mounted volume (used / (used + available to users)).",
        extra.volumes.iter().map(|(m, u, a)| (vec![("mount", m.clone())], *u as f64 / (*u + *a).max(1) as f64)).collect(),
    );
    if !snap.units.is_empty() {
        let mut counts: BTreeMap<(&str, &str), u64> = BTreeMap::new();
        for u in &snap.units {
            *counts.entry((u.kind.as_str(), u.state.as_str())).or_default() += 1;
        }
        o.fam(
            "fat_units",
            g,
            "Units by kind and state.",
            counts.into_iter().map(|((kd, st), n)| (vec![("kind", kd.to_string()), ("state", st.to_string())], n as f64)).collect(),
        );
        let lab = |u: &super::Unit| vec![("unit", u.name.clone()), ("kind", u.kind.as_str().to_string())];
        let per = |f: &dyn Fn(&super::Unit) -> Option<f64>| -> Vec<(Vec<(&str, String)>, f64)> {
            snap.units.iter().filter_map(|u| f(u).map(|v| (lab(u), v))).collect()
        };
        o.fam("fat_unit_up", g, "1 when the unit is active.", per(&|u| Some(if u.state == "active" { 1.0 } else { 0.0 })));
        o.fam("fat_unit_cpu_percent", g, "Unit CPU use, 100 = one core.", per(&|u| Some(u.cpu as f64)));
        o.fam("fat_unit_memory_bytes", g, "Unit memory (cgroup memory.current).", per(&|u| Some(u.mem as f64)));
        o.fam("fat_unit_memory_limit_bytes", g, "Unit memory limit (memory.max), when set.", per(&|u| u.mem_limit.map(|v| v as f64)));
        o.fam(
            "fat_unit_io_bytes_per_second",
            g,
            "Unit block I/O.",
            snap.units
                .iter()
                .flat_map(|u| {
                    let mut r = lab(u);
                    r.push(("op", "read".into()));
                    let mut w = lab(u);
                    w.push(("op", "write".into()));
                    [(r, u.io_read_bps as f64), (w, u.io_write_bps as f64)]
                })
                .collect(),
        );
        o.fam("fat_unit_restarts_total", c, "Unit restarts (systemd NRestarts, container RestartCount).", per(&|u| Some(u.restarts as f64)));
        o.fam("fat_unit_cpu_throttled_percent", g, "Share of the interval the unit was throttled by its CPU quota.", per(&|u| Some(u.cpu_throttled_pct as f64)));
        o.fam(
            "fat_unit_pressure_percent",
            g,
            "Unit pressure stall information (some, avg10).",
            snap.units
                .iter()
                .filter_map(|u| u.psi.map(|p| (u, p)))
                .flat_map(|(u, p)| {
                    [("cpu", p.cpu_some), ("memory", p.mem_some), ("io", p.io_some)].map(|(res, v)| {
                        let mut l = lab(u);
                        l.push(("resource", res.to_string()));
                        (l, v as f64)
                    })
                })
                .collect(),
        );
        o.fam("fat_unit_oom_kills_total", c, "OOM kills inside the unit (memory.events oom_kill).", per(&|u| Some(u.oom_kills as f64)));
    }
    if let Some(f) = findings {
        let sc = super::SevCounts::of(f);
        o.fam(
            "fat_findings",
            g,
            "Current fat doctor findings by severity.",
            [(Severity::Info, sc.info), (Severity::Warn, sc.warn), (Severity::Crit, sc.crit)]
                .into_iter()
                .map(|(sv, n)| (vec![("severity", sv.as_str().to_string())], n as f64))
                .collect(),
        );
    }
    // Every kind is exported (0 included) so rate()/increase() work from the first event.
    o.fam(
        "fat_events_total",
        c,
        "Events recorded since the recorder started, by kind.",
        EventKind::ALL.iter().map(|kd| (vec![("kind", kd.as_str().to_string())], *extra.events_total.get(kd).unwrap_or(&0) as f64)).collect(),
    );
    o.0
}

/// Largest request head accepted; /metrics needs nothing more than a request line.
const MAX_REQUEST: usize = 8 * 1024;
/// Per-connection read/write timeout: a stalled client cannot hold the single thread longer.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Bind `addr` and serve `latest` from a background thread; returns the bound address (port 0
/// allowed for tests). Err if the bind fails (address in use, permission).
pub fn serve(addr: SocketAddr, latest: LatestSnapshot) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).map_err(|e| anyhow::anyhow!("binding {addr} for metrics: {e}"))?;
    let local = listener.local_addr()?;
    std::thread::Builder::new().name("fat-export".into()).spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let _ = handle(stream, &latest);
        }
    })?;
    Ok(local)
}

fn handle(mut stream: TcpStream, latest: &LatestSnapshot) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && !buf.windows(2).any(|w| w == b"\n\n") {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST {
            return respond(&mut stream, "431 Request Header Fields Too Large", "text/plain", b"request too large\n", false);
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = target.split('?').next().unwrap_or("");
    let head_only = method == "HEAD";
    if method != "GET" && !head_only {
        return respond(&mut stream, "405 Method Not Allowed", "text/plain", b"only GET\n", false);
    }
    match path {
        "/metrics" => {
            let snap = latest.read().ok().and_then(|g| g.clone());
            match snap {
                Some(s) => {
                    let body = render(&s);
                    respond(&mut stream, "200 OK", "text/plain; version=0.0.4; charset=utf-8", body.as_bytes(), head_only)
                }
                None => respond(&mut stream, "503 Service Unavailable", "text/plain", b"no sample yet\n", head_only),
            }
        }
        "/" => respond(&mut stream, "200 OK", "text/plain", b"fat recorder: metrics at /metrics\n", head_only),
        _ => respond(&mut stream, "404 Not Found", "text/plain", b"not found\n", head_only),
    }
}

fn respond(s: &mut TcpStream, status: &str, ctype: &str, body: &[u8], head_only: bool) -> std::io::Result<()> {
    let hdr = format!("HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    s.write_all(hdr.as_bytes())?;
    if !head_only {
        s.write_all(body)?;
    }
    s.flush()
}

/// Options for the recorder loop (`fat record`), parsed from CLI flags + ServerCfg.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RecordOpts {
    /// Force server sampling (units/kernel/events) regardless of Profile::detect.
    pub server: bool,
    /// Serve Prometheus metrics on this address.
    pub export: Option<SocketAddr>,
}

/// Parse `--listen`: "HOST:PORT", "[v6]:PORT", or a bare port (loopback). Hostnames are not
/// resolved: the address to expose metrics on is an explicit operator choice.
pub fn parse_listen(s: &str) -> anyhow::Result<SocketAddr> {
    let s = s.trim();
    if let Ok(port) = s.trim_start_matches(':').parse::<u16>() {
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    s.parse().map_err(|_| anyhow::anyhow!("--listen {s:?}: expected IP:PORT (e.g. 127.0.0.1:9877) or a port"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, System};
    use crate::server::{DiskStat, Kernel, Pressure, Profile, SnapMeta, Unit, UnitKind};

    fn snap() -> Snapshot {
        Snapshot {
            ts: 1_700_000_000_500,
            host: "local".into(),
            system: System { cores: 4, cpu: 12.5, load: [0.5, 0.25, 1.0], mem_total: 8 << 30, mem_used: 2 << 30, swap_used: 0, ..Default::default() },
            units: vec![
                Unit {
                    name: "web.service".into(),
                    kind: UnitKind::Systemd,
                    state: "active".into(),
                    cpu: 42.5,
                    mem: 104_857_600,
                    mem_limit: Some(536_870_912),
                    restarts: 2,
                    io_read_bps: 10,
                    io_write_bps: 20,
                    cpu_throttled_pct: 1.5,
                    psi: Some(Pressure { cpu_some: 3.0, mem_some: 0.0, io_some: 1.25, ..Default::default() }),
                    oom_kills: 1,
                    ..Default::default()
                },
                Unit { name: "odd\"na\\me\n".into(), kind: UnitKind::Container, state: "failed".into(), ..Default::default() },
            ],
            kernel: Some(Kernel {
                steal_pct: 0.5,
                iowait_pct: 7.0,
                procs_blocked: 3,
                mem_available: 6 << 30,
                oom_kills_total: 4,
                fd_used: Some(1000),
                fd_max: Some(100_000),
                ephemeral_range: Some((32768, 60999)),
                ephemeral_used: Some(12),
                pressure: Some(Pressure { cpu_some: 1.0, cpu_full: 0.0, mem_some: 2.0, mem_full: 0.5, io_some: 4.0, io_full: 3.0 }),
                disks: vec![DiskStat { name: "vda".into(), util_pct: 50.0, r_await_ms: 2.0, w_await_ms: 120.5, queue_depth: 1.5, ..Default::default() }],
                ..Default::default()
            }),
            meta: Some(SnapMeta { version: "9.9.9".into(), root: true, ..SnapMeta::live(Profile::Server) }),
            ..Default::default()
        }
    }

    const GOLDEN: &str = r#"# HELP fat_up 1 when fat has a sample to serve.
# TYPE fat_up gauge
fat_up 1
# HELP fat_info fat version and profile.
# TYPE fat_info gauge
fat_info{version="9.9.9",profile="server"} 1
# HELP fat_sample_timestamp_seconds Time of the served sample (unix seconds).
# TYPE fat_sample_timestamp_seconds gauge
fat_sample_timestamp_seconds 1700000000.5
# HELP fat_cpu_percent Host CPU use, 0..100 of all cores.
# TYPE fat_cpu_percent gauge
fat_cpu_percent 12.5
# HELP fat_cpu_steal_percent CPU time stolen by the hypervisor, 0..100 of all cores.
# TYPE fat_cpu_steal_percent gauge
fat_cpu_steal_percent 0.5
# HELP fat_cpu_iowait_percent CPU time idle waiting for I/O, 0..100 of all cores.
# TYPE fat_cpu_iowait_percent gauge
fat_cpu_iowait_percent 7
# HELP fat_load Load average.
# TYPE fat_load gauge
fat_load{period="1"} 0.5
fat_load{period="5"} 0.25
fat_load{period="15"} 1
# HELP fat_memory_total_bytes Physical memory.
# TYPE fat_memory_total_bytes gauge
fat_memory_total_bytes 8589934592
# HELP fat_memory_used_bytes Physical memory in use.
# TYPE fat_memory_used_bytes gauge
fat_memory_used_bytes 2147483648
# HELP fat_memory_available_bytes Memory available for new work without swapping (MemAvailable).
# TYPE fat_memory_available_bytes gauge
fat_memory_available_bytes 6442450944
# HELP fat_swap_used_bytes Swap in use.
# TYPE fat_swap_used_bytes gauge
fat_swap_used_bytes 0
# HELP fat_pressure_percent Pressure stall information, avg10 percent of wall time.
# TYPE fat_pressure_percent gauge
fat_pressure_percent{resource="cpu",kind="some"} 1
fat_pressure_percent{resource="cpu",kind="full"} 0
fat_pressure_percent{resource="memory",kind="some"} 2
fat_pressure_percent{resource="memory",kind="full"} 0.5
fat_pressure_percent{resource="io",kind="some"} 4
fat_pressure_percent{resource="io",kind="full"} 3
# HELP fat_oom_kills_total Kernel OOM kills since boot.
# TYPE fat_oom_kills_total counter
fat_oom_kills_total 4
# HELP fat_procs_blocked Processes blocked on I/O (procs_blocked).
# TYPE fat_procs_blocked gauge
fat_procs_blocked 3
# HELP fat_dstate_procs Processes stuck in uninterruptible sleep beyond dstate_min_s.
# TYPE fat_dstate_procs gauge
fat_dstate_procs 0
# HELP fat_fd_used Allocated file handles.
# TYPE fat_fd_used gauge
fat_fd_used 1000
# HELP fat_fd_max File handle limit (fs.file-max).
# TYPE fat_fd_max gauge
fat_fd_max 100000
# HELP fat_ephemeral_ports_used Local ports in use from the ephemeral range.
# TYPE fat_ephemeral_ports_used gauge
fat_ephemeral_ports_used 12
# HELP fat_ephemeral_ports_range_size Size of the ephemeral port range.
# TYPE fat_ephemeral_ports_range_size gauge
fat_ephemeral_ports_range_size 28232
# HELP fat_tcp_retrans_per_second TCP segments retransmitted per second.
# TYPE fat_tcp_retrans_per_second gauge
fat_tcp_retrans_per_second 0
# HELP fat_listen_drops_per_second Connections dropped at listen sockets per second.
# TYPE fat_listen_drops_per_second gauge
fat_listen_drops_per_second 0
# HELP fat_disk_util_percent Share of the interval the disk was busy.
# TYPE fat_disk_util_percent gauge
fat_disk_util_percent{disk="vda"} 50
# HELP fat_disk_await_ms Average I/O completion time over the interval.
# TYPE fat_disk_await_ms gauge
fat_disk_await_ms{disk="vda",op="read"} 2
fat_disk_await_ms{disk="vda",op="write"} 120.5
# HELP fat_disk_queue_depth Average in-flight requests.
# TYPE fat_disk_queue_depth gauge
fat_disk_queue_depth{disk="vda"} 1.5
# HELP fat_volume_used_ratio Used share of a mounted volume (used / (used + available to users)).
# TYPE fat_volume_used_ratio gauge
fat_volume_used_ratio{mount="/"} 0.25
# HELP fat_units Units by kind and state.
# TYPE fat_units gauge
fat_units{kind="container",state="failed"} 1
fat_units{kind="systemd",state="active"} 1
# HELP fat_unit_up 1 when the unit is active.
# TYPE fat_unit_up gauge
fat_unit_up{unit="web.service",kind="systemd"} 1
fat_unit_up{unit="odd\"na\\me\n",kind="container"} 0
# HELP fat_unit_cpu_percent Unit CPU use, 100 = one core.
# TYPE fat_unit_cpu_percent gauge
fat_unit_cpu_percent{unit="web.service",kind="systemd"} 42.5
fat_unit_cpu_percent{unit="odd\"na\\me\n",kind="container"} 0
# HELP fat_unit_memory_bytes Unit memory (cgroup memory.current).
# TYPE fat_unit_memory_bytes gauge
fat_unit_memory_bytes{unit="web.service",kind="systemd"} 104857600
fat_unit_memory_bytes{unit="odd\"na\\me\n",kind="container"} 0
# HELP fat_unit_memory_limit_bytes Unit memory limit (memory.max), when set.
# TYPE fat_unit_memory_limit_bytes gauge
fat_unit_memory_limit_bytes{unit="web.service",kind="systemd"} 536870912
# HELP fat_unit_io_bytes_per_second Unit block I/O.
# TYPE fat_unit_io_bytes_per_second gauge
fat_unit_io_bytes_per_second{unit="web.service",kind="systemd",op="read"} 10
fat_unit_io_bytes_per_second{unit="web.service",kind="systemd",op="write"} 20
fat_unit_io_bytes_per_second{unit="odd\"na\\me\n",kind="container",op="read"} 0
fat_unit_io_bytes_per_second{unit="odd\"na\\me\n",kind="container",op="write"} 0
# HELP fat_unit_restarts_total Unit restarts (systemd NRestarts, container RestartCount).
# TYPE fat_unit_restarts_total counter
fat_unit_restarts_total{unit="web.service",kind="systemd"} 2
fat_unit_restarts_total{unit="odd\"na\\me\n",kind="container"} 0
# HELP fat_unit_cpu_throttled_percent Share of the interval the unit was throttled by its CPU quota.
# TYPE fat_unit_cpu_throttled_percent gauge
fat_unit_cpu_throttled_percent{unit="web.service",kind="systemd"} 1.5
fat_unit_cpu_throttled_percent{unit="odd\"na\\me\n",kind="container"} 0
# HELP fat_unit_pressure_percent Unit pressure stall information (some, avg10).
# TYPE fat_unit_pressure_percent gauge
fat_unit_pressure_percent{unit="web.service",kind="systemd",resource="cpu"} 3
fat_unit_pressure_percent{unit="web.service",kind="systemd",resource="memory"} 0
fat_unit_pressure_percent{unit="web.service",kind="systemd",resource="io"} 1.25
# HELP fat_unit_oom_kills_total OOM kills inside the unit (memory.events oom_kill).
# TYPE fat_unit_oom_kills_total counter
fat_unit_oom_kills_total{unit="web.service",kind="systemd"} 1
fat_unit_oom_kills_total{unit="odd\"na\\me\n",kind="container"} 0
# HELP fat_findings Current fat doctor findings by severity.
# TYPE fat_findings gauge
fat_findings{severity="info"} 0
fat_findings{severity="warn"} 1
fat_findings{severity="crit"} 0
"#;

    #[test]
    fn exposition_golden() {
        let mut extra = ExportExtra { volumes: vec![("/".into(), 25, 75)], ..Default::default() };
        count(&mut extra.events_total, &[Event { kind: EventKind::OomKill, ..Default::default() }, Event { kind: EventKind::OomKill, ..Default::default() }]);
        let f = vec![Finding { severity: "warn".into(), title: "t".into(), detail: String::new(), pids: vec![], action: None }];
        let text = render_with(&snap(), &extra, Some(&f));
        let (head, events) = text.split_at(text.find("# HELP fat_events_total").expect("events family"));
        assert_eq!(head, GOLDEN, "\n--- got ---\n{head}");
        assert!(events.starts_with("# HELP fat_events_total Events recorded since the recorder started, by kind.\n# TYPE fat_events_total counter\n"));
        assert!(events.contains("fat_events_total{kind=\"oom_kill\"} 2\n"));
        assert!(events.contains("fat_events_total{kind=\"other\"} 0\n"));
        assert_eq!(events.lines().filter(|l| l.starts_with("fat_events_total{")).count(), EventKind::ALL.len());
    }

    /// Structural checks every exposition must pass: one HELP/TYPE per family, families
    /// contiguous, sample lines well-formed, no pid labels.
    #[test]
    fn exposition_is_well_formed() {
        let text = render_with(&snap(), &ExportExtra::default(), None);
        let mut seen = std::collections::HashSet::new();
        let mut current = String::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.split(' ').next().unwrap().to_string();
                assert!(seen.insert(name.clone()), "family {name} declared twice");
                current = name;
            } else if !line.starts_with('#') {
                let name = line.split(['{', ' ']).next().unwrap();
                assert_eq!(name, current, "sample outside its family: {line}");
                let value = line.rsplit(' ').next().unwrap();
                assert!(value.parse::<f64>().is_ok() || value == "NaN", "bad value in {line}");
                assert!(!line.contains("pid="), "{line}");
            }
        }
        // Desktop snapshot (no units/kernel): still valid, no unit families.
        let d = render_with(&Snapshot::default(), &ExportExtra::default(), None);
        assert!(d.contains("fat_up 1") && !d.contains("fat_unit_") && !d.contains("fat_disk_"));
    }

    #[test]
    fn serves_metrics_over_http() {
        let latest: LatestSnapshot = Default::default();
        let addr = serve("127.0.0.1:0".parse().unwrap(), latest.clone()).unwrap();
        let get = |path: &str, method: &str| -> String {
            let mut s = TcpStream::connect(addr).unwrap();
            write!(s, "{method} {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        assert!(get("/metrics", "GET").starts_with("HTTP/1.1 503"));
        *latest.write().unwrap() = Some(std::sync::Arc::new(snap()));
        let r = get("/metrics?x=1", "GET");
        assert!(r.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4"), "{r}");
        assert!(r.contains("\r\n\r\n# HELP fat_up") && r.contains("fat_unit_cpu_percent{unit=\"web.service\",kind=\"systemd\"} 42.5"));
        assert!(get("/nope", "GET").starts_with("HTTP/1.1 404"));
        assert!(get("/metrics", "POST").starts_with("HTTP/1.1 405"));
        let h = get("/metrics", "HEAD");
        assert!(h.starts_with("HTTP/1.1 200") && h.ends_with("\r\n\r\n"));
        // Oversized request heads are rejected, and the server keeps serving afterwards.
        let mut s = TcpStream::connect(addr).unwrap();
        let _ = s.write_all(format!("GET /metrics HTTP/1.1\r\nX: {}\r\n", "a".repeat(MAX_REQUEST + 10)).as_bytes());
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 431"), "{out}");
        assert!(get("/", "GET").starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn listen_parsing_defaults_to_loopback() {
        assert_eq!(parse_listen("9877").unwrap(), "127.0.0.1:9877".parse().unwrap());
        assert_eq!(parse_listen(":9100").unwrap(), "127.0.0.1:9100".parse().unwrap());
        assert_eq!(parse_listen("[::1]:9877").unwrap(), "[::1]:9877".parse().unwrap());
        assert!(parse_listen("localhost:9877").is_err());
    }
}
