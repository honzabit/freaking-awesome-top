//! Always-on flight recorder (SQLite). OWNER: history agent.
//!
//! # Storage design
//!
//! The recorder is meant to run all the time, so the on-disk format is tuned
//! for size (target < 30 MB/day at a 2 s interval) and write latency
//! (target < 5 ms per `record()`):
//!
//! * `system` — one narrow row per sample. Floats are stored as scaled
//!   integers (cpu in tenths of a percent, load ×100, power in mW) so SQLite's
//!   varint encoding keeps them to 1–3 bytes. Per-core usage is a `u8` blob.
//! * `changes` — slowly-changing data (hostname, mem_total, pressure, thermal,
//!   ports, containers) stored as JSON *only when it changes*. A reader takes
//!   the latest row at or before the sample time.
//!   Ephemeral UDP sockets (port >= 49152) are not recorded.
//! * `proc_info` — the identity of a process incarnation (name, cmd capped at
//!   256 bytes, exe, cwd, user), written once, keyed by a small row id and
//!   deduplicated by a stable FNV-1a hash.
//! * `procs` — keyframe + delta encoding of the "interesting" processes
//!   (top 40 by cpu, top 20 by mem, top 20 by power, port owners, stopped
//!   procs, and their ancestors). Every [`KEYFRAME_MS`] the full interesting
//!   set is written; in between, a process gets an entry only when its values
//!   moved noticeably, and a tombstone (`cpu10 = -1`) when it exits or leaves
//!   the set. All entries of one sample are packed into a single varint blob.
//!   `at(ts)` replays blobs from the preceding keyframe to `ts`.
//!
//! Measured on an M3 Max under heavy load (several concurrent cargo builds and
//! agents): ~630 B/sample marginal ≈ 27 MB/day at 2 s; record() ≈ 0.5 ms avg,
//! < 3 ms worst (release).
//!
//! Everything for one sample is written in a single transaction with cached
//! prepared statements, WAL journal, and `synchronous=NORMAL`.
use crate::model::{Container, Gpu, Port, Proc, Snapshot, System, Ts};
use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Point {
    pub ts: Ts,
    pub cpu: f32,
    pub mem_used: u64,
    pub power_mw: f32,
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
    /// Top process by CPU at that instant.
    pub top_name: String,
    pub top_cpu: f32,
}

/// A full set of interesting procs is written at least this often.
pub const KEYFRAME_MS: i64 = 120_000;
/// `at()` returns None when the nearest sample is further away than this.
pub const MAX_AT_GAP_MS: i64 = 15 * 60_000;

const TOP_CPU: usize = 40;
const TOP_MEM: usize = 20;
const TOP_POWER: usize = 20;
/// Minimum cpu% / power to enter the top-cpu / top-power lists.
const ENTER_CPU: f32 = 0.5;
const ENTER_POWER_MW: f32 = 5.0;
/// Hard cap on procs recorded per sample (after adding ancestors).
const MAX_RECORDED: usize = 200;
/// Command lines longer than this are truncated in storage (Electron/JVM
/// command lines can be many KB).
const MAX_CMD: usize = 256;
/// Bound on the in-memory proc_info id cache.
const INFO_CACHE_MAX: usize = 20_000;

/// Bumped whenever the on-disk layout changes.
const SCHEMA_VERSION: i64 = 2;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS system (
    ts INTEGER PRIMARY KEY,
    cpu10 INTEGER NOT NULL,
    per_core BLOB,
    load1 INTEGER, load5 INTEGER, load15 INTEGER,
    mem_used INTEGER NOT NULL,
    swap_used INTEGER,
    power INTEGER NOT NULL,
    net_rx INTEGER, net_tx INTEGER,
    disk_r INTEGER, disk_w INTEGER,
    uptime INTEGER,
    battery10 INTEGER,
    gpu TEXT,
    nprocs INTEGER,
    top_name TEXT,
    top_cpu10 INTEGER
);
CREATE TABLE IF NOT EXISTS changes (
    kind TEXT NOT NULL,
    ts INTEGER NOT NULL,
    json TEXT NOT NULL,
    PRIMARY KEY (kind, ts)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS keyframes (ts INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS proc_info (
    id INTEGER PRIMARY KEY,
    hash INTEGER NOT NULL UNIQUE,
    pid INTEGER NOT NULL,
    start_time INTEGER,
    name TEXT, cmd TEXT, exe TEXT, cwd TEXT, user TEXT,
    last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS proc_info_seen ON proc_info(last_seen);
-- One row per sample that has any proc changes; `data` is a packed list of
-- (pid, ProcRow) entries, see `encode_entry`. Packing avoids ~40 bytes of
-- per-row SQLite overhead (keys, record header, index) per process.
CREATE TABLE IF NOT EXISTS procs (
    ts INTEGER PRIMARY KEY,
    data BLOB NOT NULL
);
";

/// Quantized per-process values as stored in `procs`. Also the delta cache.
#[derive(Debug, Clone, PartialEq, Default)]
struct ProcRow {
    info: i64,
    ppid: u32,
    cpu10: i64,
    mem_kb: i64,
    power: i64,
    disk_r: i64,
    disk_w: i64,
    net_rx: i64,
    net_tx: i64,
    gpu10: Option<i64>,
    threads: i64,
    nice: i64,
    status: String,
}

impl ProcRow {
    fn from_proc(p: &Proc, info: i64) -> Self {
        ProcRow {
            info,
            ppid: p.ppid,
            cpu10: q10(p.cpu),
            mem_kb: (p.mem / 1024) as i64,
            power: p.power_mw.max(0.0).round() as i64,
            disk_r: clamp_i64(p.disk_read_bps),
            disk_w: clamp_i64(p.disk_write_bps),
            net_rx: clamp_i64(p.net_rx_bps),
            net_tx: clamp_i64(p.net_tx_bps),
            gpu10: p.gpu.map(q10),
            threads: p.threads as i64,
            nice: p.nice as i64,
            status: p.status.clone(),
        }
    }

    fn tombstone(prev: &ProcRow) -> Self {
        ProcRow { info: prev.info, ppid: prev.ppid, cpu10: -1, ..Default::default() }
    }

    fn is_tombstone(&self) -> bool {
        self.cpu10 < 0
    }

    /// Whether `self` differs enough from the last written row to be worth a new row.
    fn differs_from(&self, prev: &ProcRow) -> bool {
        self.info != prev.info
            || self.ppid != prev.ppid
            || status_differs(&self.status, &prev.status)
            || self.nice != prev.nice
            || rel_changed(self.cpu10, prev.cpu10, 0.30, 30)
            || rel_changed(self.mem_kb, prev.mem_kb, 0.02, 1024)
            || rel_changed(self.power, prev.power, 0.20, 50)
            || rel_changed(self.disk_r, prev.disk_r, 0.50, 256 * 1024)
            || rel_changed(self.disk_w, prev.disk_w, 0.50, 256 * 1024)
            || rel_changed(self.net_rx, prev.net_rx, 0.50, 64 * 1024)
            || rel_changed(self.net_tx, prev.net_tx, 0.50, 64 * 1024)
            || rel_changed(self.threads, prev.threads, 0.10, 4)
            || match (self.gpu10, prev.gpu10) {
                (Some(a), Some(b)) => (a - b).abs() >= 20,
                (None, None) => false,
                _ => true,
            }
    }
}

fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

fn get_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    let mut shift = 0;
    loop {
        let b = *data.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            v |= ((b & 0x7f) as u64) << shift;
        }
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
    }
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Append one packed proc entry. Field order: pid, info, ppid, cpu10+1 (0 =
/// tombstone), mem_kb, power, disk_r, disk_w, net_rx, net_tx, gpu10+1 (0 = None),
/// threads, zigzag(nice), status byte (0 = empty). All LEB128 varints except status.
fn encode_entry(buf: &mut Vec<u8>, pid: u32, r: &ProcRow) {
    put_varint(buf, pid as u64);
    put_varint(buf, zigzag(r.info));
    put_varint(buf, r.ppid as u64);
    put_varint(buf, if r.is_tombstone() { 0 } else { r.cpu10 as u64 + 1 });
    for v in [r.mem_kb, r.power, r.disk_r, r.disk_w, r.net_rx, r.net_tx] {
        put_varint(buf, v.max(0) as u64);
    }
    put_varint(buf, r.gpu10.map_or(0, |g| g.max(0) as u64 + 1));
    put_varint(buf, r.threads.max(0) as u64);
    put_varint(buf, zigzag(r.nice));
    buf.push(r.status.bytes().next().unwrap_or(0));
}

/// Decode a packed blob; a truncated/corrupt tail is ignored.
fn decode_entries(data: &[u8]) -> Vec<(u32, ProcRow)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let one = |pos: &mut usize| -> Option<(u32, ProcRow)> {
        let pid = get_varint(data, pos)? as u32;
        let info = unzigzag(get_varint(data, pos)?);
        let ppid = get_varint(data, pos)? as u32;
        let cpu = get_varint(data, pos)?;
        let mut n = [0i64; 6];
        for x in n.iter_mut() {
            *x = get_varint(data, pos)?.min(i64::MAX as u64) as i64;
        }
        let gpu = get_varint(data, pos)?;
        let threads = get_varint(data, pos)? as i64;
        let nice = unzigzag(get_varint(data, pos)?);
        let st = *data.get(*pos)?;
        *pos += 1;
        Some((
            pid,
            ProcRow {
                info,
                ppid,
                cpu10: cpu as i64 - 1,
                mem_kb: n[0],
                power: n[1],
                disk_r: n[2],
                disk_w: n[3],
                net_rx: n[4],
                net_tx: n[5],
                gpu10: (gpu > 0).then(|| gpu as i64 - 1),
                threads,
                nice,
                status: if st == 0 { String::new() } else { (st as char).to_string() },
            },
        ))
    };
    while pos < data.len() {
        match one(&mut pos) {
            Some(e) => out.push(e),
            None => break,
        }
    }
    out
}

/// R/S/I flicker constantly; only transitions involving stopped (T), zombie (Z)
/// or uninterruptible (U) states are worth a row.
fn status_differs(a: &str, b: &str) -> bool {
    let notable = |s: &str| matches!(s, "T" | "Z" | "U");
    a != b && (notable(a) || notable(b))
}

/// Truncate to at most `max` bytes on a char boundary.
fn cap(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Browsers and DNS/QUIC clients open and close ephemeral UDP sockets every few
/// seconds; recording them would rewrite the ports set constantly. Keep TCP and
/// UDP ports below the IANA/macOS ephemeral range (49152+).
fn keep_port(p: &Port) -> bool {
    p.proto == crate::model::Proto::Tcp || p.port < 49152
}

/// Ports minus the free-text `note` (which embeds a relative age like "3h ago"
/// and would otherwise change every sample). Used only for change detection.
fn ports_key(ports: &[&Port]) -> String {
    let mut v: Vec<(String, u16, u32, &str, bool)> = ports
        .iter()
        .map(|p| (format!("{:?}{}", p.proto, p.addr), p.port, p.pid, p.state.as_str(), p.orphan))
        .collect();
    v.sort();
    serde_json::to_string(&v).unwrap_or_default()
}

/// True when |a-b| exceeds both an absolute floor and a fraction of the larger value.
fn rel_changed(a: i64, b: i64, frac: f64, min_abs: i64) -> bool {
    let d = (a - b).abs();
    d >= min_abs && d as f64 > frac * a.abs().max(b.abs()) as f64
}

fn q10(v: f32) -> i64 {
    if v.is_finite() { (v.max(0.0) * 10.0).round() as i64 } else { 0 }
}

fn clamp_i64(v: u64) -> i64 {
    v.min(i64::MAX as u64) as i64
}

/// Stable FNV-1a hash of a process incarnation's identity (proc_info.hash).
fn info_hash(p: &Proc) -> i64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        // field separator so ("ab","c") != ("a","bc")
        h ^= 0xff;
        h = h.wrapping_mul(0x0100_0000_01b3);
    };
    eat(&p.pid.to_le_bytes());
    eat(&p.start_time.to_le_bytes());
    for s in [&p.name, &p.cmd, &p.exe, &p.cwd, &p.user] {
        eat(s.as_bytes());
    }
    h as i64
}

/// System fields that rarely change; stored in `changes` under kind "sys".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct SlowSys {
    hostname: String,
    os: String,
    cpu_model: String,
    cores: usize,
    mem_total: u64,
    swap_total: u64,
    mem_pressure: String,
    thermal: String,
    gpu_names: Vec<String>,
    on_battery: Option<bool>,
}

impl SlowSys {
    fn from_system(s: &System) -> Self {
        SlowSys {
            hostname: s.hostname.clone(),
            os: s.os.clone(),
            cpu_model: s.cpu_model.clone(),
            cores: s.cores,
            mem_total: s.mem_total,
            swap_total: s.swap_total,
            mem_pressure: s.mem_pressure.clone(),
            thermal: s.thermal.clone(),
            gpu_names: s.gpus.iter().map(|g| g.name.clone()).collect(),
            on_battery: s.on_battery,
        }
    }
}

const KIND_SYS: &str = "sys";
const KIND_PORTS: &str = "ports";
const KIND_CONTAINERS: &str = "containers";

pub struct History {
    conn: Connection,
    path: PathBuf,
    last_key: Option<Ts>,
    /// Last row written per pid since the current keyframe.
    last_rows: HashMap<u32, ProcRow>,
    /// Change-detection key of the last row written per `changes` kind.
    last_changes: HashMap<&'static str, String>,
    /// proc_info hash -> row id for incarnations known to exist in the DB.
    known_info: HashMap<i64, i64>,
    /// Exclusive writer lease (flock on `<db>.writer-lock`). The delta encoding only replays
    /// correctly from one writer's stream, so only the lease holder records.
    writer: Option<std::fs::File>,
}

/// Lock file guarding the single-writer rule for `db`.
fn writer_lock_path(db: &Path) -> PathBuf {
    let mut s = db.as_os_str().to_owned();
    s.push(".writer-lock");
    PathBuf::from(s)
}

impl History {
    /// Default DB location: `<data_local_dir>/fat/history.db`.
    pub fn default_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("fat")
            .join("history.db")
    }

    /// Path of the open database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open (create) the DB. None path -> default under dirs::data_local_dir()/fat/history.db.
    pub fn open(path: Option<&str>) -> anyhow::Result<History> {
        let path = match path {
            Some(p) if !p.is_empty() => PathBuf::from(expand_tilde(p)),
            _ => Self::default_path(),
        };
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
        let conn = Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(2))?;
        // auto_vacuum must be set before the first table is created to take effect.
        conn.execute_batch(
            "PRAGMA auto_vacuum = INCREMENTAL;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;",
        )?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != SCHEMA_VERSION {
            // Pre-release layouts are not migrated; start fresh.
            conn.execute_batch(
                "DROP TABLE IF EXISTS system; DROP TABLE IF EXISTS changes; DROP TABLE IF EXISTS keyframes;
                 DROP TABLE IF EXISTS proc_info; DROP TABLE IF EXISTS procs;",
            )?;
        }
        conn.execute_batch(SCHEMA).context("creating history schema")?;
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        Ok(History {
            conn,
            path,
            last_key: None,
            last_rows: HashMap::new(),
            last_changes: HashMap::new(),
            known_info: HashMap::new(),
            writer: None,
        })
    }

    /// True while this instance holds the writer lease.
    pub fn is_writer(&self) -> bool {
        self.writer.is_some()
    }

    /// Take the writer lease if no other process (or instance) holds it. Non-blocking; the
    /// lease is released when this History is dropped (or its process dies).
    pub fn try_become_writer(&mut self) -> bool {
        if self.writer.is_some() {
            return true;
        }
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(writer_lock_path(&self.path))
        else {
            return false;
        };
        // SAFETY: flock on a valid fd we own; LOCK_NB makes it fail instead of blocking.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return false;
        }
        let _ = f.set_len(0);
        let _ = write!(f, "{}", std::process::id());
        // Whatever another writer wrote since our last record isn't in our caches: restart
        // our stream with a keyframe.
        self.last_key = None;
        self.last_rows.clear();
        self.last_changes.clear();
        self.known_info.clear();
        self.writer = Some(f);
        true
    }

    /// Pid recorded by the current lease holder, if any (for messages).
    pub fn writer_pid(&self) -> Option<u32> {
        std::fs::read_to_string(writer_lock_path(&self.path)).ok()?.trim().parse().ok()
    }

    /// Record a sample. A no-op (Ok) while another process holds the writer lease: two
    /// interleaved delta streams would corrupt time-travel replay.
    pub fn record(&mut self, snap: &Snapshot) -> anyhow::Result<()> {
        if !self.try_become_writer() {
            return Ok(());
        }
        self.record_unchecked(snap)
    }

    fn record_unchecked(&mut self, snap: &Snapshot) -> anyhow::Result<()> {
        let ts = snap.ts;
        let is_key = match self.last_key {
            None => true,
            Some(k) => ts < k || ts - k >= KEYFRAME_MS,
        };

        // Work on copies of the caches and only commit them once the
        // transaction succeeds, so a failed write never desyncs us from disk.
        let mut rows = if is_key { HashMap::new() } else { self.last_rows.clone() };
        let mut new_changes: Vec<(&'static str, String)> = Vec::new();
        let mut new_info: Vec<(i64, i64)> = Vec::new();

        let tx = self.conn.transaction()?;
        {
            write_system_row(&tx, snap)?;

            let slow = serde_json::to_string(&SlowSys::from_system(&snap.system))?;
            let containers = serde_json::to_string(&snap.containers)?;
            let ports: Vec<&Port> = snap.ports.iter().filter(|p| keep_port(p)).collect();
            let mut chg = tx.prepare_cached(
                "INSERT OR REPLACE INTO changes (kind, ts, json) VALUES (?1, ?2, ?3)",
            )?;
            // (kind, change-detection key, json to store); json is built lazily for ports.
            let items: [(&'static str, String, Option<String>); 3] = [
                (KIND_SYS, slow.clone(), Some(slow)),
                (KIND_PORTS, ports_key(&ports), None),
                (KIND_CONTAINERS, containers.clone(), Some(containers)),
            ];
            for (kind, key, json) in items {
                if self.last_changes.get(kind) != Some(&key) {
                    let json = match json {
                        Some(j) => j,
                        None => serde_json::to_string(&ports)?,
                    };
                    chg.execute(params![kind, ts, json])?;
                    new_changes.push((kind, key));
                }
            }

            if is_key {
                tx.prepare_cached("INSERT OR REPLACE INTO keyframes (ts) VALUES (?1)")?
                    .execute(params![ts])?;
            }

            let sticky: HashSet<u32> = self.last_rows.keys().copied().collect();
            let interesting = select_interesting(snap, &sticky, is_key);
            let mut upsert_info = tx.prepare_cached(
                "INSERT INTO proc_info (hash, pid, start_time, name, cmd, exe, cwd, user, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(hash) DO UPDATE SET last_seen = excluded.last_seen
                 RETURNING id",
            )?;
            let mut touch_info = tx.prepare_cached("UPDATE proc_info SET last_seen = ?1 WHERE id = ?2")?;
            let mut packed: Vec<u8> = Vec::with_capacity(512);

            let mut present: HashSet<u32> = HashSet::with_capacity(interesting.len());
            for p in &interesting {
                present.insert(p.pid);
                let hash = info_hash(p);
                let info = match self.known_info.get(&hash) {
                    Some(&id) => {
                        // On keyframes refresh last_seen for every recorded proc (used by prune).
                        if is_key {
                            touch_info.execute(params![ts, id])?;
                        }
                        id
                    }
                    None => {
                        let id: i64 = upsert_info.query_row(
                            params![
                                hash,
                                p.pid,
                                clamp_i64(p.start_time),
                                cap(&p.name, 256),
                                cap(&p.cmd, MAX_CMD),
                                cap(&p.exe, 512),
                                cap(&p.cwd, 256),
                                cap(&p.user, 64),
                                ts
                            ],
                            |r| r.get(0),
                        )?;
                        new_info.push((hash, id));
                        id
                    }
                };
                let row = ProcRow::from_proc(p, info);
                let changed = match rows.get(&p.pid) {
                    Some(prev) if !prev.is_tombstone() => row.differs_from(prev),
                    _ => true,
                };
                if changed {
                    encode_entry(&mut packed, p.pid, &row);
                    rows.insert(p.pid, row);
                }
            }
            // Procs that left the interesting set (or exited) get a tombstone.
            let gone: Vec<u32> = rows.keys().copied().filter(|pid| !present.contains(pid)).collect();
            for pid in gone {
                let prev = rows.remove(&pid).unwrap_or_default();
                if !prev.is_tombstone() {
                    encode_entry(&mut packed, pid, &ProcRow::tombstone(&prev));
                }
            }
            if !packed.is_empty() {
                tx.prepare_cached("INSERT OR REPLACE INTO procs (ts, data) VALUES (?1, ?2)")?
                    .execute(params![ts, packed])?;
            }
        }
        tx.commit()?;

        if is_key {
            self.last_key = Some(ts);
        }
        self.last_rows = rows;
        for (k, v) in new_changes {
            self.last_changes.insert(k, v);
        }
        if self.known_info.len() > INFO_CACHE_MAX {
            self.known_info.clear();
        }
        self.known_info.extend(new_info);
        Ok(())
    }

    /// Snapshot recorded nearest to ts (procs may be a reduced set).
    pub fn at(&self, ts: Ts) -> anyhow::Result<Option<Snapshot>> {
        let before: Option<Ts> = self
            .conn
            .query_row("SELECT max(ts) FROM system WHERE ts <= ?1", [ts], |r| r.get(0))?;
        let after: Option<Ts> = self
            .conn
            .query_row("SELECT min(ts) FROM system WHERE ts >= ?1", [ts], |r| r.get(0))?;
        let sts = match (before, after) {
            (Some(b), Some(a)) => if ts - b <= a - ts { b } else { a },
            (Some(b), None) => b,
            (None, Some(a)) => a,
            (None, None) => return Ok(None),
        };
        if (sts - ts).abs() > MAX_AT_GAP_MS {
            return Ok(None);
        }

        let mut system = self.read_system(sts)?.unwrap_or_default();
        if let Some(slow) = self.change_at::<SlowSys>(KIND_SYS, sts)? {
            system.hostname = slow.hostname;
            system.os = slow.os;
            system.cpu_model = slow.cpu_model;
            system.cores = slow.cores;
            system.mem_total = slow.mem_total;
            system.swap_total = slow.swap_total;
            system.mem_pressure = slow.mem_pressure;
            system.thermal = slow.thermal;
            system.on_battery = slow.on_battery;
            for (g, name) in system.gpus.iter_mut().zip(slow.gpu_names) {
                g.name = name;
            }
        }
        let ports: Vec<Port> = self.change_at(KIND_PORTS, sts)?.unwrap_or_default();
        let containers: Vec<Container> = self.change_at(KIND_CONTAINERS, sts)?.unwrap_or_default();
        let procs = self.procs_at(sts)?;

        Ok(Some(Snapshot { ts: sts, host: "local".into(), system, procs, ports, containers }))
    }

    /// Downsampled system timeline in [from, to], at most `max_points` points.
    pub fn timeline(&self, from: Ts, to: Ts, max_points: usize) -> anyhow::Result<Vec<Point>> {
        if to < from || max_points == 0 {
            return Ok(vec![]);
        }
        // max(top_cpu10) is the only min/max aggregate, so SQLite fills the bare
        // top_name column from the row holding that max.
        let mut st = self.conn.prepare_cached(
            "SELECT CAST(avg(ts) AS INTEGER), avg(cpu10), avg(mem_used), avg(power),
                    avg(net_rx), avg(net_tx), avg(disk_r), avg(disk_w), max(top_cpu10), top_name
             FROM system WHERE ts BETWEEN ?1 AND ?2
             GROUP BY ((ts - ?1) * ?3) / (?2 - ?1 + 1)
             ORDER BY 1",
        )?;
        let n = max_points.min(1_000_000) as i64;
        let pts = st
            .query_map(params![from, to, n], |r| {
                Ok(Point {
                    ts: r.get(0)?,
                    cpu: (r.get::<_, f64>(1)? / 10.0) as f32,
                    mem_used: r.get::<_, f64>(2)? as u64,
                    power_mw: r.get::<_, f64>(3)? as f32,
                    net_rx_bps: r.get::<_, Option<f64>>(4)?.unwrap_or(0.0) as u64,
                    net_tx_bps: r.get::<_, Option<f64>>(5)?.unwrap_or(0.0) as u64,
                    disk_read_bps: r.get::<_, Option<f64>>(6)?.unwrap_or(0.0) as u64,
                    disk_write_bps: r.get::<_, Option<f64>>(7)?.unwrap_or(0.0) as u64,
                    top_cpu: r.get::<_, Option<i64>>(8)?.unwrap_or(0) as f32 / 10.0,
                    top_name: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(pts)
    }

    /// Per-process series for one pid (ts, cpu, mem).
    ///
    /// Rows are change points (delta encoded): a value holds until the next row.
    pub fn proc_series(&self, pid: u32, from: Ts, to: Ts) -> anyhow::Result<Vec<(Ts, f32, u64)>> {
        // Start from the keyframe before `from` so the value in effect at `from` is known.
        let key: Option<Ts> = self
            .conn
            .query_row("SELECT max(ts) FROM keyframes WHERE ts <= ?1", [from], |r| r.get(0))?;
        let mut st = self.conn.prepare_cached("SELECT ts, data FROM procs WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts")?;
        let mut rows = st.query(params![key.unwrap_or(from).min(from), to])?;
        let mut out: Vec<(Ts, f32, u64)> = Vec::new();
        let mut carried: Option<(f32, u64)> = None;
        while let Some(r) = rows.next()? {
            let ts: Ts = r.get(0)?;
            let data: Vec<u8> = r.get(1)?;
            let Some(row) = decode_entries(&data).into_iter().find(|(p, _)| *p == pid).map(|(_, row)| row) else {
                continue;
            };
            let v = (!row.is_tombstone()).then(|| (row.cpu10 as f32 / 10.0, row.mem_kb.max(0) as u64 * 1024));
            if ts < from {
                carried = v;
                continue;
            }
            if let Some((c, m)) = carried.take()
                && out.is_empty() && ts > from {
                    out.push((from, c, m));
                }
            if let Some((c, m)) = v {
                out.push((ts, c, m));
            }
        }
        if let (Some((c, m)), true) = (carried, out.is_empty()) {
            out.push((from, c, m));
        }
        Ok(out)
    }

    /// Times where system cpu/power/mem jumped notably in [from, to].
    ///
    /// A point is a spike when cpu is > 25 points above the trailing 30 s
    /// median, power at least doubles that median (and rises by >= 2 W), or
    /// used memory grew > 1 GiB within the trailing 60 s. A sustained condition
    /// is reported once, at its onset.
    pub fn spikes(&self, from: Ts, to: Ts) -> anyhow::Result<Vec<Point>> {
        if to < from {
            return Ok(vec![]);
        }
        let mut st = self.conn.prepare_cached(
            "SELECT ts, cpu10, mem_used, power, net_rx, net_tx, disk_r, disk_w, top_name, top_cpu10
             FROM system WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts",
        )?;
        let pts = st
            .query_map(params![from - 60_000, to], row_to_point)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(detect_spikes(&pts, from))
    }

    pub fn prune(&mut self, keep_days: u32) -> anyhow::Result<usize> {
        let cutoff = crate::model::now_ms() - keep_days as i64 * 86_400_000;
        self.prune_before(cutoff)
    }

    /// Delete everything older than `cutoff` while keeping what is needed to
    /// reconstruct samples at or after it. Returns the number of samples removed.
    pub fn prune_before(&mut self, cutoff: Ts) -> anyhow::Result<usize> {
        // Keep the keyframe that newer delta rows depend on.
        let key: Option<Ts> = self
            .conn
            .query_row("SELECT max(ts) FROM keyframes WHERE ts <= ?1", [cutoff], |r| r.get(0))?;
        let eff = key.unwrap_or(cutoff).min(cutoff);
        let tx = self.conn.transaction()?;
        let removed = tx.execute("DELETE FROM system WHERE ts < ?1", [cutoff])?;
        tx.execute("DELETE FROM procs WHERE ts < ?1", [eff])?;
        tx.execute("DELETE FROM keyframes WHERE ts < ?1", [eff])?;
        // proc_info: last_seen is refreshed at every keyframe a proc appears in,
        // and delta rows are never more than one keyframe interval after that.
        tx.execute("DELETE FROM proc_info WHERE last_seen < ?1", [eff - 2 * KEYFRAME_MS])?;
        // changes: for each kind keep the latest row at or before the cutoff.
        tx.execute(
            "DELETE FROM changes WHERE ts < (
                SELECT max(c2.ts) FROM changes c2 WHERE c2.kind = changes.kind AND c2.ts <= ?1)",
            [cutoff],
        )?;
        tx.commit()?;
        if removed > 0 {
            // Return freed pages to the filesystem; harmless if auto_vacuum is off.
            let _ = self.conn.execute_batch("PRAGMA incremental_vacuum;");
        }
        self.known_info.clear();
        Ok(removed)
    }

    /// (oldest, newest) recorded ts.
    pub fn bounds(&self) -> anyhow::Result<Option<(Ts, Ts)>> {
        let r: (Option<Ts>, Option<Ts>) = self
            .conn
            .query_row("SELECT min(ts), max(ts) FROM system", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(match r {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        })
    }

    /// Number of recorded samples.
    pub fn sample_count(&self) -> anyhow::Result<u64> {
        Ok(self.conn.query_row("SELECT count(*) FROM system", [], |r| r.get::<_, i64>(0))? as u64)
    }

    fn read_system(&self, ts: Ts) -> anyhow::Result<Option<System>> {
        let mut st = self.conn.prepare_cached(
            "SELECT cpu10, per_core, load1, load5, load15, mem_used, swap_used, power,
                    net_rx, net_tx, disk_r, disk_w, uptime, battery10, gpu
             FROM system WHERE ts = ?1",
        )?;
        let sys = st
            .query_row([ts], |r| {
                let per_core: Option<Vec<u8>> = r.get(1)?;
                let gpu: Option<String> = r.get(14)?;
                let gpus = gpu
                    .and_then(|g| serde_json::from_str::<Vec<(f32, u64)>>(&g).ok())
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(util, mem_used)| Gpu { name: String::new(), util, mem_used })
                    .collect();
                let load = |i: usize| -> rusqlite::Result<f64> {
                    Ok(r.get::<_, Option<i64>>(i)?.unwrap_or(0) as f64 / 100.0)
                };
                let u = |i: usize| -> rusqlite::Result<u64> {
                    Ok(r.get::<_, Option<i64>>(i)?.unwrap_or(0).max(0) as u64)
                };
                Ok(System {
                    cpu: r.get::<_, i64>(0)? as f32 / 10.0,
                    per_core: per_core.unwrap_or_default().into_iter().map(f32::from).collect(),
                    load: [load(2)?, load(3)?, load(4)?],
                    mem_used: u(5)?,
                    swap_used: u(6)?,
                    power_mw: r.get::<_, i64>(7)? as f32,
                    net_rx_bps: u(8)?,
                    net_tx_bps: u(9)?,
                    disk_read_bps: u(10)?,
                    disk_write_bps: u(11)?,
                    uptime: u(12)?,
                    battery_pct: r.get::<_, Option<i64>>(13)?.map(|b| b as f32 / 10.0),
                    gpus,
                    mem_pressure: "unknown".into(),
                    thermal: "unknown".into(),
                    ..Default::default()
                })
            })
            .optional()?;
        Ok(sys)
    }

    /// Latest `changes` JSON of `kind` at or before ts, decoded.
    fn change_at<T: for<'de> Deserialize<'de>>(&self, kind: &str, ts: Ts) -> anyhow::Result<Option<T>> {
        let json: Option<String> = self
            .conn
            .prepare_cached(
                "SELECT json FROM changes WHERE kind = ?1 AND ts <= ?2 ORDER BY ts DESC LIMIT 1",
            )?
            .query_row(params![kind, ts], |r| r.get(0))
            .optional()?;
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
    }

    /// Replay packed proc entries from the keyframe preceding `ts` up to `ts`.
    fn procs_at(&self, ts: Ts) -> anyhow::Result<Vec<Proc>> {
        let key: Option<Ts> = self
            .conn
            .query_row("SELECT max(ts) FROM keyframes WHERE ts <= ?1", [ts], |r| r.get(0))?;
        let from = key.unwrap_or(i64::MIN);
        let mut state: HashMap<u32, ProcRow> = HashMap::new();
        {
            let mut st = self.conn.prepare_cached("SELECT data FROM procs WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts")?;
            let mut rows = st.query(params![from, ts])?;
            while let Some(r) = rows.next()? {
                let data: Vec<u8> = r.get(0)?;
                for (pid, row) in decode_entries(&data) {
                    if row.is_tombstone() {
                        state.remove(&pid);
                    } else {
                        state.insert(pid, row);
                    }
                }
            }
        }
        let mut info_st = self.conn.prepare_cached(
            "SELECT start_time, name, cmd, exe, cwd, user FROM proc_info WHERE id = ?1",
        )?;
        let mut procs: Vec<Proc> = Vec::with_capacity(state.len());
        for (pid, r) in state {
            let info = info_st
                .query_row([r.info], |q| {
                    let s = |i: usize| -> rusqlite::Result<String> { Ok(q.get::<_, Option<String>>(i)?.unwrap_or_default()) };
                    Ok((q.get::<_, Option<i64>>(0)?.unwrap_or(0), s(1)?, s(2)?, s(3)?, s(4)?, s(5)?))
                })
                .optional()?
                .unwrap_or_default();
            procs.push(Proc {
                pid,
                ppid: r.ppid,
                cpu: r.cpu10 as f32 / 10.0,
                mem: r.mem_kb.max(0) as u64 * 1024,
                power_mw: r.power as f32,
                disk_read_bps: r.disk_r.max(0) as u64,
                disk_write_bps: r.disk_w.max(0) as u64,
                net_rx_bps: r.net_rx.max(0) as u64,
                net_tx_bps: r.net_tx.max(0) as u64,
                gpu: r.gpu10.map(|g| g as f32 / 10.0),
                threads: r.threads as u32,
                nice: r.nice as i32,
                status: r.status,
                start_time: info.0.max(0) as u64,
                name: info.1,
                cmd: info.2,
                exe: info.3,
                cwd: info.4,
                user: info.5,
                virt: 0,
                usage_unknown: false,
            });
        }
        procs.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(a.pid.cmp(&b.pid)));
        Ok(procs)
    }
}

fn write_system_row(tx: &rusqlite::Transaction, snap: &Snapshot) -> anyhow::Result<()> {
    let s = &snap.system;
    let top = snap.procs.iter().max_by(|a, b| a.cpu.total_cmp(&b.cpu));
    let per_core: Vec<u8> = s.per_core.iter().map(|c| c.clamp(0.0, 100.0).round() as u8).collect();
    let gpu = if s.gpus.is_empty() {
        None
    } else {
        let v: Vec<(f32, u64)> = s.gpus.iter().map(|g| ((g.util * 10.0).round() / 10.0, g.mem_used)).collect();
        Some(serde_json::to_string(&v)?)
    };
    let load = |x: f64| if x.is_finite() { (x * 100.0).round() as i64 } else { 0 };
    tx.prepare_cached(
        "INSERT OR REPLACE INTO system
         (ts, cpu10, per_core, load1, load5, load15, mem_used, swap_used, power, net_rx, net_tx,
          disk_r, disk_w, uptime, battery10, gpu, nprocs, top_name, top_cpu10)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
    )?
    .execute(params![
        snap.ts,
        q10(s.cpu),
        per_core,
        load(s.load[0]),
        load(s.load[1]),
        load(s.load[2]),
        clamp_i64(s.mem_used),
        clamp_i64(s.swap_used),
        s.power_mw.max(0.0).round() as i64,
        clamp_i64(s.net_rx_bps),
        clamp_i64(s.net_tx_bps),
        clamp_i64(s.disk_read_bps),
        clamp_i64(s.disk_write_bps),
        clamp_i64(s.uptime),
        s.battery_pct.map(q10),
        gpu,
        snap.procs.len() as i64,
        top.map(|p| p.name.as_str()).unwrap_or(""),
        top.map(|p| q10(p.cpu)).unwrap_or(0),
    ])?;
    Ok(())
}

fn row_to_point(r: &rusqlite::Row) -> rusqlite::Result<Point> {
    let u = |i: usize| -> rusqlite::Result<u64> { Ok(r.get::<_, Option<i64>>(i)?.unwrap_or(0).max(0) as u64) };
    Ok(Point {
        ts: r.get(0)?,
        cpu: r.get::<_, i64>(1)? as f32 / 10.0,
        mem_used: u(2)?,
        power_mw: r.get::<_, i64>(3)? as f32,
        net_rx_bps: u(4)?,
        net_tx_bps: u(5)?,
        disk_read_bps: u(6)?,
        disk_write_bps: u(7)?,
        top_name: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
        top_cpu: r.get::<_, Option<i64>>(9)?.unwrap_or(0) as f32 / 10.0,
    })
}

/// Pick the procs worth recording: top by cpu/mem/power, port owners,
/// stopped procs, plus their ancestors (for historical blame chains).
///
/// Between keyframes the set only grows (procs leave it only by exiting), which
/// avoids tombstone/re-entry churn at the rank boundary; keyframes re-select and
/// keep previously recorded procs only while they are still somewhat active.
fn select_interesting<'a>(snap: &'a Snapshot, sticky: &HashSet<u32>, is_key: bool) -> Vec<&'a Proc> {
    let procs = &snap.procs;
    let mut idx: Vec<usize> = (0..procs.len()).collect();
    let mut chosen: Vec<usize> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();
    let mut take = |i: usize, chosen: &mut Vec<usize>| {
        if seen.insert(procs[i].pid) {
            chosen.push(i);
        }
    };

    // Near-idle procs are excluded from the top lists: on a real machine dozens of
    // them flicker between 0.0% and 0.4%, and recording that churn costs space.
    idx.sort_by(|&a, &b| procs[b].cpu.total_cmp(&procs[a].cpu));
    idx.iter()
        .take(TOP_CPU)
        .filter(|&&i| procs[i].cpu >= ENTER_CPU)
        .for_each(|&i| take(i, &mut chosen));
    idx.sort_by(|&a, &b| procs[b].power_mw.total_cmp(&procs[a].power_mw));
    idx.iter()
        .take(TOP_POWER)
        .filter(|&&i| procs[i].power_mw >= ENTER_POWER_MW)
        .for_each(|&i| take(i, &mut chosen));
    idx.sort_by(|&a, &b| procs[b].mem.cmp(&procs[a].mem));
    idx.iter().take(TOP_MEM).for_each(|&i| take(i, &mut chosen));
    // Hysteresis: procs recorded last time stay while they are still somewhat
    // active or memory-heavy, so the set doesn't churn at the rank boundary.
    for (rank, &i) in idx.iter().enumerate() {
        let p = &procs[i];
        if sticky.contains(&p.pid) && (!is_key || p.cpu >= 0.2 || p.power_mw >= 2.0 || rank < 2 * TOP_MEM) {
            take(i, &mut chosen);
        }
    }

    let port_pids: HashSet<u32> = snap.ports.iter().map(|p| p.pid).collect();
    for (i, p) in procs.iter().enumerate() {
        if port_pids.contains(&p.pid) || p.status == "T" {
            take(i, &mut chosen);
        }
    }

    // Ancestors of everything chosen so far.
    let by_pid: HashMap<u32, usize> = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
    let base = chosen.clone();
    for i in base {
        let mut cur = procs[i].ppid;
        let mut guard = 0;
        while cur != 0 && guard < 64 {
            guard += 1;
            let Some(&j) = by_pid.get(&cur) else { break };
            take(j, &mut chosen);
            if procs[j].ppid == cur {
                break;
            }
            cur = procs[j].ppid;
        }
    }

    chosen.truncate(MAX_RECORDED);
    chosen.into_iter().map(|i| &procs[i]).collect()
}

/// Pure spike detection over time-ordered points. Only points with ts >= `from`
/// are reported; earlier points serve as the trailing baseline.
fn detect_spikes(pts: &[Point], from: Ts) -> Vec<Point> {
    const CPU_WIN: i64 = 30_000;
    const MEM_WIN: i64 = 60_000;
    const GIB: u64 = 1 << 30;

    let mut out: Vec<Point> = Vec::new();
    // Per-signal refractory: a sustained condition is reported once, not every sample.
    // Memory growth stays "true" for a whole 60s window after a step, so it waits longer.
    let (mut last_cpu, mut last_pow, mut last_mem): (Option<Ts>, Option<Ts>, Option<Ts>) = (None, None, None);
    let fresh = |last: Option<Ts>, now: Ts, gap: i64| last.is_none_or(|t| now - t >= gap);
    let mut lo = 0usize; // start of 30s window
    let mut mlo = 0usize; // start of 60s window
    for (i, p) in pts.iter().enumerate() {
        while lo < i && pts[lo].ts < p.ts - CPU_WIN {
            lo += 1;
        }
        while mlo < i && pts[mlo].ts < p.ts - MEM_WIN {
            mlo += 1;
        }
        if p.ts < from {
            continue;
        }
        let window = &pts[lo..i];
        let (mut cpu_hit, mut pow_hit, mut mem_hit) = (false, false, false);
        if window.len() >= 3 {
            let cpu_med = median(window.iter().map(|w| w.cpu));
            let pow_med = median(window.iter().map(|w| w.power_mw));
            cpu_hit = p.cpu - cpu_med > 25.0;
            pow_hit = p.power_mw >= 2.0 * pow_med && p.power_mw - pow_med >= 2000.0;
        }
        if let Some(min_mem) = pts[mlo..i].iter().map(|w| w.mem_used).min() {
            mem_hit = p.mem_used.saturating_sub(min_mem) > GIB;
        }
        let mut report = false;
        if cpu_hit {
            report |= fresh(last_cpu, p.ts, CPU_WIN);
            last_cpu = Some(p.ts);
        }
        if pow_hit {
            report |= fresh(last_pow, p.ts, CPU_WIN);
            last_pow = Some(p.ts);
        }
        if mem_hit {
            report |= fresh(last_mem, p.ts, MEM_WIN);
            last_mem = Some(p.ts);
        }
        if report {
            out.push(p.clone());
        }
    }
    out
}

fn median(it: impl Iterator<Item = f32>) -> f32 {
    let mut v: Vec<f32> = it.collect();
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    p.to_string()
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    // Only async-signal-safe work here: flip a flag.
    STOP.store(true, Ordering::SeqCst);
}

fn install_stop_handlers() {
    // SAFETY: `on_signal` is an `extern "C" fn(c_int)` that only performs an
    // atomic store, which is async-signal-safe.
    unsafe {
        let h = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGINT, h);
        libc::signal(libc::SIGTERM, h);
    }
}

/// `fat record`: sample forever, writing to history. Blocks.
pub fn record_forever(cfg: &crate::config::Config) -> anyhow::Result<()> {
    let interval = Duration::from_millis(cfg.interval_ms.max(1000));
    let keep_days = cfg.history_days.max(1);
    let mut hist = History::open(cfg.history_path.as_deref())?;
    install_stop_handlers();
    STOP.store(false, Ordering::SeqCst);

    let pruned = hist.prune(keep_days).unwrap_or(0);
    println!(
        "fat record: writing to {} every {}ms, keeping {}d{} (Ctrl-C to stop)",
        hist.path().display(),
        interval.as_millis(),
        keep_days,
        if pruned > 0 { format!(", pruned {pruned} old samples") } else { String::new() }
    );

    let mut collector = crate::collect::Collector::new();
    let mut last_prune = Instant::now();
    let mut recorded: u64 = 0;
    let mut errors: u64 = 0;
    let mut waiting = false;
    while !STOP.load(Ordering::SeqCst) {
        let started = Instant::now();
        if !hist.try_become_writer() {
            if !waiting {
                waiting = true;
                let who = hist.writer_pid().map(|p| format!(" (pid {p})")).unwrap_or_default();
                eprintln!(
                    "fat record: another fat{who} is already recording to {}; waiting for it to stop",
                    hist.path().display()
                );
            }
            while !STOP.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(2) {
                std::thread::sleep(Duration::from_millis(100));
            }
            continue;
        }
        if std::mem::take(&mut waiting) {
            eprintln!("fat record: recording");
        }
        let snap = collector.sample();
        match hist.record(&snap) {
            Ok(()) => recorded += 1,
            Err(e) => {
                errors += 1;
                // Don't flood the terminal if the disk is full or the DB is locked.
                if errors <= 5 || errors.is_multiple_of(100) {
                    eprintln!("fat record: write failed ({errors} total): {e:#}");
                }
            }
        }
        if last_prune.elapsed() >= Duration::from_secs(3600) {
            if let Err(e) = hist.prune(keep_days) {
                eprintln!("fat record: prune failed: {e:#}");
            }
            last_prune = Instant::now();
        }
        // Sleep in short slices so Ctrl-C is handled promptly.
        while !STOP.load(Ordering::SeqCst) && started.elapsed() < interval {
            let left = interval.saturating_sub(started.elapsed());
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }
    println!("fat record: stopped after {recorded} samples ({errors} errors)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Proto;

    fn tmp_db(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("fat-hist-{tag}-{}-{n}.db", std::process::id()))
    }

    fn cleanup(p: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", p.display(), suffix));
        }
    }

    /// Deterministic xorshift for synthetic noise.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> f32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % 10_000) as f32 / 10_000.0
        }
    }

    /// A machine with `n` procs: a few busy ones with noisy cpu, the rest idle.
    fn synth(ts: Ts, n: u32, cpu: f32, power: f32, mem_used: u64, rng: &mut Rng) -> Snapshot {
        let mut procs = vec![Proc { pid: 1, ppid: 0, name: "launchd".into(), status: "S".into(), ..Default::default() }];
        for pid in 2..=n {
            let busy = pid % 25 == 0;
            procs.push(Proc {
                pid,
                ppid: if pid % 7 == 0 { 1 } else { (pid / 7).max(1) },
                name: format!("proc{pid}"),
                cmd: format!("/usr/bin/proc{pid} --flag value"),
                exe: format!("/usr/bin/proc{pid}"),
                user: "me".into(),
                cpu: if busy { (pid % 40) as f32 + 3.0 + rng.next() * 4.0 } else if rng.next() < 0.02 { rng.next() * 0.4 } else { 0.0 },
                mem: (pid as u64 * 1_000_000) + (rng.next() * 50_000.0) as u64,
                power_mw: if busy { pid as f32 + rng.next() * 30.0 } else { 0.0 },
                threads: 4,
                status: "S".into(),
                start_time: 1_700_000_000 + pid as u64,
                ..Default::default()
            });
        }
        // The "hog" whose cpu drives the system spike.
        procs.push(Proc { pid: 9999, ppid: 1, name: "hog".into(), cpu: cpu * 2.0 + 50.0, status: "R".into(), ..Default::default() });
        Snapshot {
            ts,
            host: "local".into(),
            system: System {
                hostname: "mac".into(),
                cores: 16,
                per_core: vec![cpu; 16],
                cpu,
                load: [2.5, 2.0, 1.5],
                mem_total: 64 << 30,
                mem_used,
                power_mw: power,
                mem_pressure: "normal".into(),
                thermal: "nominal".into(),
                ..Default::default()
            },
            procs,
            ports: vec![Port {
                proto: Proto::Tcp,
                addr: "127.0.0.1".into(),
                port: 5173,
                pid: 3,
                process: "proc3".into(),
                state: "LISTEN".into(),
                orphan: false,
                note: "vite".into(),
            }],
            containers: vec![],
        }
    }

    const T0: Ts = 1_700_000_000_000;

    #[test]
    fn record_at_timeline_and_latency() {
        let path = tmp_db("main");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut rng = Rng(42);
        let mut worst = Duration::ZERO;
        let mut total = Duration::ZERO;
        for i in 0..200 {
            let s = synth(T0 + i * 2000, 400, 10.0 + (i % 5) as f32, 5000.0, 20 << 30, &mut rng);
            let t = Instant::now();
            h.record(&s).unwrap();
            let el = t.elapsed();
            total += el;
            worst = worst.max(el);
        }
        let avg = total / 200;
        eprintln!("record(): avg {avg:?}, worst {worst:?}");
        // Generous bound for debug builds on CI; release is well under 5ms.
        assert!(avg < Duration::from_millis(25), "avg record latency {avg:?}");

        assert_eq!(h.bounds().unwrap(), Some((T0, T0 + 199 * 2000)));
        assert_eq!(h.sample_count().unwrap(), 200);

        // at(): nearest sample, reconstructed.
        let s = h.at(T0 + 101 * 2000 + 700).unwrap().unwrap();
        assert_eq!(s.ts, T0 + 101 * 2000);
        assert_eq!(s.host, "local");
        assert_eq!(s.system.hostname, "mac");
        assert_eq!(s.system.mem_total, 64 << 30);
        assert_eq!(s.system.per_core.len(), 16);
        assert_eq!(s.system.thermal, "nominal");
        assert_eq!(s.ports.len(), 1);
        assert!(s.proc(3).is_some(), "port owner is recorded");
        assert!(s.proc(1).is_some(), "ancestor launchd is recorded");
        let hog = s.proc(9999).expect("top cpu proc recorded");
        assert_eq!(hog.name, "hog");
        assert!(s.procs.len() >= 40 && s.procs.len() <= MAX_RECORDED, "{}", s.procs.len());
        // Recorded procs match the original within delta-encoding tolerance.
        let orig = synth(T0 + 101 * 2000, 400, 11.0, 5000.0, 20 << 30, &mut Rng(1));
        let o = orig.proc(50).unwrap();
        let r = s.proc(50).unwrap();
        assert_eq!(r.cmd, o.cmd);
        assert!((r.mem as i64 - o.mem as i64).abs() < (o.mem / 20) as i64);

        // Far away from any sample -> None.
        assert!(h.at(T0 - 3_600_000).unwrap().is_none());

        // timeline(): bucket count.
        let tl = h.timeline(T0, T0 + 199 * 2000, 20).unwrap();
        assert_eq!(tl.len(), 20);
        assert!(tl.windows(2).all(|w| w[0].ts < w[1].ts));
        assert_eq!(tl[0].top_name, "hog");
        assert!(tl[0].cpu >= 10.0 && tl[0].cpu <= 14.0);
        let tl = h.timeline(T0, T0 + 199 * 2000, 1000).unwrap();
        assert_eq!(tl.len(), 200);

        // proc_series
        let ser = h.proc_series(9999, T0, T0 + 400_000).unwrap();
        assert!(!ser.is_empty());

        drop(h);
        cleanup(&path);
    }

    #[test]
    fn tombstones_remove_exited_procs() {
        let path = tmp_db("tomb");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut rng = Rng(7);
        let s = synth(T0, 50, 10.0, 1000.0, 1 << 30, &mut rng);
        h.record(&s).unwrap();
        let mut s2 = synth(T0 + 2000, 50, 10.0, 1000.0, 1 << 30, &mut rng);
        s2.procs.retain(|p| p.pid != 9999);
        h.record(&s2).unwrap();
        assert!(h.at(T0).unwrap().unwrap().proc(9999).is_some());
        assert!(h.at(T0 + 2000).unwrap().unwrap().proc(9999).is_none());
        drop(h);
        cleanup(&path);
    }

    #[test]
    fn spikes_detected() {
        let path = tmp_db("spike");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut rng = Rng(9);
        for i in 0..200i64 {
            let ts = T0 + i * 2000;
            let cpu = if (100..105).contains(&i) { 80.0 } else { 10.0 };
            let power = if (150..152).contains(&i) { 12_000.0 } else { 4_000.0 };
            let mem = if i >= 180 { 22u64 << 30 } else { 20u64 << 30 };
            h.record(&synth(ts, 30, cpu, power, mem, &mut rng)).unwrap();
        }
        let sp = h.spikes(T0, T0 + 400_000).unwrap();
        let ts: Vec<i64> = sp.iter().map(|p| (p.ts - T0) / 2000).collect();
        assert_eq!(ts, vec![100, 150, 180], "{ts:?}");
        assert_eq!(sp[0].top_name, "hog");
        assert!((sp[0].top_cpu - 210.0).abs() < 0.5);
        drop(h);
        cleanup(&path);
    }

    #[test]
    fn single_writer_lease() {
        let path = tmp_db("lease");
        let p = path.to_str().unwrap();
        let mut a = History::open(Some(p)).unwrap();
        let mut b = History::open(Some(p)).unwrap();
        let mut snap = Snapshot { ts: 1_000_000, ..Default::default() };
        a.record(&snap).unwrap();
        assert!(a.is_writer());
        snap.ts += 1000;
        b.record(&snap).unwrap(); // skipped: a holds the lease
        assert!(!b.is_writer());
        assert_eq!(a.sample_count().unwrap(), 1, "a second writer must not interleave its delta stream");
        assert_eq!(b.writer_pid(), Some(std::process::id()));
        drop(a);
        snap.ts += 1000;
        b.record(&snap).unwrap();
        assert!(b.is_writer());
        assert_eq!(b.sample_count().unwrap(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prune_keeps_reconstructable_tail() {
        let path = tmp_db("prune");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut rng = Rng(3);
        for i in 0..200i64 {
            h.record(&synth(T0 + i * 2000, 60, 10.0, 1000.0, 1 << 30, &mut rng)).unwrap();
        }
        let cutoff = T0 + 115 * 2000; // mid keyframe interval
        let removed = h.prune_before(cutoff).unwrap();
        assert_eq!(removed, 115);
        assert_eq!(h.bounds().unwrap(), Some((cutoff, T0 + 199 * 2000)));
        let s = h.at(cutoff).unwrap().unwrap();
        assert!(s.proc(9999).is_some());
        assert_eq!(s.ports.len(), 1, "ports change row before cutoff kept");
        assert_eq!(s.system.hostname, "mac");
        // prune(days) with fake old timestamps removes everything.
        assert_eq!(h.prune(1).unwrap(), 85);
        assert_eq!(h.bounds().unwrap(), None);
        drop(h);
        cleanup(&path);
    }

    #[test]
    fn bytes_per_day_estimate() {
        let path = tmp_db("size");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut rng = Rng(11);
        let n = 600; // 20 minutes at 2s
        for i in 0..n {
            h.record(&synth(T0 + i * 2000, 500, 15.0, 6000.0, 30 << 30, &mut rng)).unwrap();
        }
        h.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        let bytes = std::fs::metadata(&path).unwrap().len();
        let per_day = bytes as f64 / n as f64 * 43_200.0 / 1e6;
        eprintln!("db {bytes} bytes for {n} samples -> {per_day:.1} MB/day at 2s");
        assert!(per_day < 30.0, "{per_day:.1} MB/day");
        drop(h);
        if std::env::var_os("FAT_KEEP_DB").is_none() { cleanup(&path); } else { eprintln!("kept {}", path.display()); }
    }

    #[test]
    fn codec_roundtrip() {
        let a = ProcRow {
            info: 12345,
            ppid: 1,
            cpu10: 0,
            mem_kb: 1 << 40,
            power: 1234,
            disk_r: 5,
            disk_w: 0,
            net_rx: u32::MAX as i64,
            net_tx: 7,
            gpu10: Some(0),
            threads: 300,
            nice: -20,
            status: "T".into(),
        };
        let b = ProcRow { gpu10: None, status: String::new(), nice: 19, ..a.clone() };
        let t = ProcRow::tombstone(&a);
        let mut buf = Vec::new();
        encode_entry(&mut buf, 42, &a);
        encode_entry(&mut buf, 7, &b);
        encode_entry(&mut buf, u32::MAX, &t);
        let d = decode_entries(&buf);
        assert_eq!(d, vec![(42, a), (7, b), (u32::MAX, t)]);
        // Truncated tail: complete entries survive.
        assert_eq!(decode_entries(&buf[..buf.len() - 1]).len(), 2);
        assert_eq!(unzigzag(zigzag(i64::MIN)), i64::MIN);
    }

    #[test]
    fn delta_thresholds() {
        let a = ProcRow { cpu10: 100, mem_kb: 100_000, status: "S".into(), ..Default::default() };
        let mut b = a.clone();
        b.cpu10 = 115;
        assert!(!b.differs_from(&a));
        b.cpu10 = 150;
        assert!(b.differs_from(&a));
        let mut c = a.clone();
        c.mem_kb = 101_000;
        assert!(!c.differs_from(&a));
        c.mem_kb = 110_000;
        assert!(c.differs_from(&a));
        let mut d = a.clone();
        d.status = "T".into();
        assert!(d.differs_from(&a));
    }

    #[test]
    fn median_and_spike_logic() {
        assert_eq!(median([3.0, 1.0, 2.0].into_iter()), 2.0);
        assert_eq!(median([4.0, 1.0, 2.0, 3.0].into_iter()), 2.5);
        let pts: Vec<Point> = (0..20)
            .map(|i| Point { ts: i * 2000, cpu: if i == 10 { 60.0 } else { 20.0 }, ..Default::default() })
            .collect();
        let s = detect_spikes(&pts, 0);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].ts, 20_000);
        // Baseline-only points before `from` aren't reported.
        assert!(detect_spikes(&pts, 30_000).is_empty());
    }

    /// Real-machine size/latency check: `cargo test --bin fat history::tests::real_machine -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_machine_size() {
        let path = tmp_db("real");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut c = crate::collect::Collector::new();
        let n: usize = std::env::var("FAT_SAMPLES").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
        let interval: u64 = std::env::var("FAT_INTERVAL").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
        let mut worst = Duration::ZERO;
        let mut total = Duration::ZERO;
        let warm = n / 4;
        let mut warm_bytes = 0u64;
        for i in 0..n {
            if i == warm {
                h.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
                warm_bytes = std::fs::metadata(&path).unwrap().len();
            }
            let s = c.sample();
            let t = Instant::now();
            h.record(&s).unwrap();
            let el = t.elapsed();
            total += el;
            worst = worst.max(el);
            std::thread::sleep(Duration::from_millis(interval));
        }
        h.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        let rows: i64 = {
            let mut st = h.conn.prepare("SELECT data FROM procs").unwrap();
            let blobs = st.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap();
            blobs.map(|b| decode_entries(&b.unwrap()).len() as i64).sum()
        };
        let bytes = std::fs::metadata(&path).unwrap().len();
        eprintln!(
            "real: marginal {:.0} B/sample -> {:.1} MB/day at 2s",
            (bytes - warm_bytes) as f64 / (n - warm) as f64,
            (bytes - warm_bytes) as f64 / (n - warm) as f64 * 43_200.0 / 1e6
        );
        eprintln!(
            "real: {n} samples, {rows} proc rows ({:.1}/sample), {bytes} bytes -> {:.1} MB/day at 2s; record avg {:?} worst {worst:?}",
            rows as f64 / n as f64,
            bytes as f64 / n as f64 * 43_200.0 / 1e6,
            total / n as u32
        );
        let s = h.at(crate::model::now_ms()).unwrap().unwrap();
        eprintln!("at(now): {} procs, {} ports", s.procs.len(), s.ports.len());
        drop(h);
        if std::env::var_os("FAT_KEEP_DB").is_none() {
            cleanup(&path);
        } else {
            eprintln!("kept {}", path.display());
        }
    }
}
