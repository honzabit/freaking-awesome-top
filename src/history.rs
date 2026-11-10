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
//! * `volume_ids` / `volumes` — per-volume (used, avail, total, read/write bps) change points:
//!   a row when used/avail moves >= 1 MiB, I/O changes notably, or every 60 s.
//! * `fs_snaps` / `fs_dirs` — directory sizes from the background scanner every 5 min
//!   (depth <= 3 plus anything >= 1% of its volume, <= 2000 paths), delta encoded against a
//!   daily key snapshot. `proc_writes` integrates the procs' recorded disk write rates (the top
//!   disk writers are always part of the recorded set).
//!
//! Measured on an M3 Max under heavy load (several concurrent cargo builds and
//! agents): ~630 B/sample marginal ≈ 27 MB/day at 2 s; record() ≈ 0.5 ms avg,
//! < 3 ms worst (release).
//!
//! Everything for one sample is written in a single transaction with cached
//! prepared statements, WAL journal, and `synchronous=NORMAL`.
use crate::model::{Container, Gpu, Port, Proc, Snapshot, System, Ts};
use crate::server::{
    ContainerMeta, DStateProc, DiskStat, Event, EventKind, FsErrorStat, Kernel, MdArray, NumaNode, Pressure, Profile,
    ServerCfg, Severity, SnapMeta, Unit, UnitKind, UnitPoint,
};
use anyhow::Context;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
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
/// Every unit and disk gets a row at least this often (and at the start of every writer
/// stream); in between only changes, departures ("gone" rows) and busy disks are written.
/// Units outnumber busy processes on servers and mostly sit idle, so a long key interval is
/// what keeps their cost near zero. Readers look back at most this far for a unit's value.
pub const SERVER_KEY_MS: i64 = 15 * 60_000;
/// `at()` returns None when the nearest sample is further away than this.
pub const MAX_AT_GAP_MS: i64 = 15 * 60_000;

const TOP_CPU: usize = 40;
const TOP_MEM: usize = 20;
const TOP_POWER: usize = 20;
/// Top disk writers are recorded so `proc_writes` can answer "who filled the disk".
const TOP_DISK: usize = 10;
const ENTER_DISK_BPS: u64 = 64 * 1024;
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
-- Storage (fs). Additive tables: older DBs simply gain them, no version bump needed.
CREATE TABLE IF NOT EXISTS volume_ids (
    id INTEGER PRIMARY KEY,
    mount TEXT NOT NULL UNIQUE
);
-- Change points per volume (a value holds until the next row; rows at least every
-- VOLUME_EVERY_MS while recording). Bytes and bytes/sec.
CREATE TABLE IF NOT EXISTS volumes (
    vid INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    used INTEGER NOT NULL,
    avail INTEGER NOT NULL,
    total INTEGER NOT NULL,
    read_bps INTEGER,
    write_bps INTEGER,
    PRIMARY KEY (vid, ts)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS volumes_ts ON volumes(ts);
-- One row per directory-size snapshot; key = 1 for a full snapshot, 0 for a delta.
CREATE TABLE IF NOT EXISTS fs_snaps (
    ts INTEGER PRIMARY KEY,
    key INTEGER NOT NULL
);
-- Directory sizes, delta encoded against the preceding key snapshot: a path gets a row
-- when it is new or its size moved by >= DIR_MIN_DELTA; size = -1 means 'no longer tracked'.
CREATE TABLE IF NOT EXISTS fs_dirs (
    path TEXT NOT NULL,
    ts INTEGER NOT NULL,
    size INTEGER NOT NULL,
    files INTEGER,
    PRIMARY KEY (path, ts)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS fs_dirs_ts ON fs_dirs(ts);
";

/// Server-mode tables (recorder-export). Additive like the fs tables: older DBs gain them on
/// open, no version bump, nothing dropped.
const SERVER_SCHEMA: &str = "
-- Everything that happened at an instant. Deduplicated on (ts, kind, subject); the unique
-- index also serves time-range scans.
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    severity INTEGER NOT NULL,
    subject TEXT NOT NULL,
    unit TEXT,
    pid INTEGER,
    value REAL,
    detail TEXT NOT NULL,
    source TEXT NOT NULL,
    extra TEXT,
    UNIQUE (ts, kind, subject)
);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events(kind, ts);
-- Interned unit identities; meta = latest slow-changing JSON (description, cgroup, container).
CREATE TABLE IF NOT EXISTS unit_ids (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    meta TEXT,
    last_seen INTEGER NOT NULL,
    UNIQUE (name, kind)
);
-- Every unit and disk gets a row at each server keyframe (SERVER_KEY_MS, and when a writer
-- starts); in between only on change.
CREATE TABLE IF NOT EXISTS server_keys (ts INTEGER PRIMARY KEY);
-- Unit change points. state: 0 unknown, 1 active, 2 activating, 3 deactivating, 4 reloading,
-- 5 inactive, 6 failed, -1 gone. cpu/throttle in tenths of a percent, memory in KiB,
-- psi = 'cs,cf,ms,mf,is,if' in tenths.
CREATE TABLE IF NOT EXISTS units (
    uid INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    state INTEGER NOT NULL,
    sub TEXT, result TEXT, exit_code INTEGER, main_pid INTEGER, since INTEGER,
    restarts INTEGER, recent INTEGER, flags INTEGER,
    cpu10 INTEGER, mem_kb INTEGER, limit_kb INTEGER, peak_kb INTEGER, pids INTEGER,
    io_r INTEGER, io_w INTEGER, thr10 INTEGER, quota100 INTEGER, psi TEXT, oom INTEGER,
    PRIMARY KEY (uid, ts)
) WITHOUT ROWID;
-- One row per sample: the scalar part of Kernel (percentages and rates in tenths).
CREATE TABLE IF NOT EXISTS kernel (
    ts INTEGER PRIMARY KEY,
    steal10 INTEGER, iowait10 INTEGER, irq10 INTEGER, softirq10 INTEGER,
    running INTEGER, blocked INTEGER, psi TEXT, avail_kb INTEGER,
    swin10 INTEGER, swout10 INTEGER, oom_total INTEGER,
    fd_used INTEGER, fd_max INTEGER, ct_used INTEGER, ct_max INTEGER,
    eph_used INTEGER, eph_lo INTEGER, eph_hi INTEGER,
    retrans10 INTEGER, overflows10 INTEGER, drops10 INTEGER,
    taint INTEGER, ntp INTEGER, dstate TEXT
);
-- Per-disk rows, written while a disk is busy (and once when it goes idle), and at keyframes.
CREATE TABLE IF NOT EXISTS disks (
    ts INTEGER NOT NULL,
    name TEXT NOT NULL,
    util10 INTEGER, r_await10 INTEGER, w_await10 INTEGER, qd10 INTEGER,
    r_iops10 INTEGER, w_iops10 INTEGER, r_bps INTEGER, w_bps INTEGER, errors INTEGER,
    PRIMARY KEY (ts, name)
) WITHOUT ROWID;
";

/// Every table `open` must find for the schema to count as current.
const ALL_TABLES: &str = "'system','changes','keyframes','proc_info','procs','volume_ids','volumes','fs_snaps','fs_dirs',\
    'events','unit_ids','server_keys','units','kernel','disks'";
const ALL_TABLES_N: i64 = 15;

/// System-wide recorder database (Linux, root, server profile). FHS location for variable
/// state, present on every distribution.
pub const SYSTEM_DB: &str = "/var/lib/fat/history.db";

/// Last volume row written: (ts, used, avail, read_bps, write_bps).
type VolRow = (Ts, i64, i64, i64, i64);
/// A directory-size snapshot: its ts and (path, bytes), largest first.
pub type DirSnapshot = (Ts, Vec<(String, u64)>);

/// A volume row is written at least this often even when nothing changed.
pub const VOLUME_EVERY_MS: i64 = 60_000;
/// ...and sooner when used/avail moved by at least this much.
const VOLUME_MIN_DELTA: i64 = 1 << 20;
/// Directory-size snapshots: a full (key) snapshot at least this often.
pub const DIR_KEY_MS: i64 = 24 * 3_600_000;
/// Smallest size change that gets a delta row.
const DIR_MIN_DELTA: i64 = 1 << 20;
/// Hard cap on rows per directory-size snapshot.
pub const DIR_MAX_ROWS: usize = 2000;

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
    let mut v: Vec<(String, u16, u32, &str, bool)> =
        ports.iter().map(|p| (format!("{:?}{}", p.proto, p.addr), p.port, p.pid, p.state.as_str(), p.orphan)).collect();
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
    /// Last volume row written per mount: (ts, used, avail, read_bps, write_bps).
    last_vols: HashMap<String, VolRow>,
    /// mount -> volume_ids.id.
    vol_ids: HashMap<String, i64>,
    /// Dir sizes in effect since the last key snapshot (path -> size), and that key's ts.
    last_dirs: HashMap<String, i64>,
    last_dir_key: Option<Ts>,
    /// Opened with [`History::open_read_only`]: never takes the lease, never writes.
    read_only: bool,
    /// Server tables (units/kernel/disks) write caches; see [`History::record_server`].
    srv: ServerCache,
}

/// Lock file guarding the single-writer rule for `db`.
fn writer_lock_path(db: &Path) -> PathBuf {
    let mut s = db.as_os_str().to_owned();
    s.push(".writer-lock");
    PathBuf::from(s)
}

impl History {
    /// Default DB location. On Linux, when a system-wide recorder exists ([`SYSTEM_DB`], made by
    /// `fat record` running as root in the server profile) every user reads that one;
    /// otherwise `<data_local_dir>/fat/history.db`.
    pub fn default_path() -> PathBuf {
        if cfg!(target_os = "linux") && Path::new(SYSTEM_DB).exists() {
            return PathBuf::from(SYSTEM_DB);
        }
        Self::user_path()
    }

    /// Per-user DB location: `<data_local_dir>/fat/history.db`.
    pub fn user_path() -> PathBuf {
        dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("fat").join("history.db")
    }

    /// Path of the open database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The DB path `path` (or the default) resolves to.
    pub fn resolve(path: Option<&str>) -> PathBuf {
        match path {
            Some(p) if !p.is_empty() => PathBuf::from(expand_tilde(p)),
            _ => Self::default_path(),
        }
    }

    fn with_conn(conn: Connection, path: PathBuf, read_only: bool) -> History {
        History {
            conn,
            path,
            last_key: None,
            last_rows: HashMap::new(),
            last_changes: HashMap::new(),
            known_info: HashMap::new(),
            writer: None,
            last_vols: HashMap::new(),
            vol_ids: HashMap::new(),
            last_dirs: HashMap::new(),
            last_dir_key: None,
            read_only,
            srv: ServerCache::default(),
        }
    }

    /// Open (create) the DB. None path -> [`History::default_path`]. Older databases of the
    /// current schema gain missing tables in place (additive, no data loss). When the schema is
    /// already current the open performs no write, so readers of a DB they cannot write (another
    /// user's recorder) still work.
    ///
    /// A database written by a different fat version (another `user_version`) is never touched:
    /// this returns Err, so a mismatched CLI (rolling upgrade, an older binary first on PATH)
    /// cannot destroy a recorder's history. Only [`History::open_recorder`] with `may_reset`
    /// starts over, and it keeps the old file.
    pub fn open(path: Option<&str>) -> anyhow::Result<History> {
        Self::open_inner(Self::resolve(path), false)
    }

    /// Open for recording. With `may_reset`, a database of another schema version is moved
    /// aside to `<db>.schema-v<N>` (kept, never deleted) and a fresh one is created, but only
    /// while no other process holds the writer lease. Without it this is [`History::open`].
    pub fn open_recorder(path: Option<&str>, may_reset: bool) -> anyhow::Result<History> {
        Self::open_inner(Self::resolve(path), may_reset)
    }

    /// (user_version, number of our tables) of an open connection.
    fn schema_of(conn: &Connection) -> anyhow::Result<(i64, i64)> {
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let tables: i64 = conn.query_row(
            &format!("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ({})", ALL_TABLES),
            [],
            |r| r.get(0),
        )?;
        Ok((version, tables))
    }

    fn open_inner(path: PathBuf, may_reset: bool) -> anyhow::Result<History> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
            && !dir.exists()
        {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut conn = Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(2))?;
        conn.execute_batch("PRAGMA synchronous = NORMAL; PRAGMA temp_store = MEMORY;")?;
        let (mut version, mut tables) = Self::schema_of(&conn)?;
        // An empty file (fresh, or user_version 0 with none of our tables) is ours to set up.
        let foreign = version != SCHEMA_VERSION && !(version == 0 && tables == 0);
        if foreign {
            if !may_reset {
                anyhow::bail!(
                    "{} was written by a different fat version (schema v{version}; this fat uses v{SCHEMA_VERSION}); \
                     left untouched. Use the matching fat, or point history_path elsewhere",
                    path.display()
                );
            }
            drop(conn);
            let kept = Self::move_aside(&path, version)?;
            eprintln!(
                "fat: {} had schema v{version} (this fat uses v{SCHEMA_VERSION}); kept it as {} and started a new one",
                path.display(),
                kept.display()
            );
            conn = Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
            conn.busy_timeout(Duration::from_secs(2))?;
            conn.execute_batch("PRAGMA synchronous = NORMAL; PRAGMA temp_store = MEMORY;")?;
            (version, tables) = Self::schema_of(&conn)?;
        }
        if version != SCHEMA_VERSION || tables != ALL_TABLES_N {
            // auto_vacuum must be set before the first table is created to take effect.
            conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; PRAGMA journal_mode = WAL;")?;
            conn.execute_batch(SCHEMA).context("creating history schema")?;
            conn.execute_batch(SERVER_SCHEMA).context("creating server history schema")?;
            conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        }
        Ok(Self::with_conn(conn, path, false))
    }

    /// Rename `db` (and its -wal/-shm) to `<db>.schema-v<version>[.N]`, holding the writer lease
    /// so a recorder still writing to it is never pulled from under. Returns the new name.
    fn move_aside(db: &Path, version: i64) -> anyhow::Result<PathBuf> {
        use std::os::fd::AsRawFd;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(writer_lock_path(db))
            .with_context(|| format!("locking {}", db.display()))?;
        // SAFETY: flock on a valid fd we own; LOCK_NB makes it fail instead of blocking.
        anyhow::ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "{} has schema v{version} and another fat is recording to it; left untouched",
            db.display()
        );
        let base = format!("{}.schema-v{version}", db.display());
        let mut dest = PathBuf::from(&base);
        let mut n = 1;
        while dest.exists() {
            dest = PathBuf::from(format!("{base}.{n}"));
            n += 1;
        }
        std::fs::rename(db, &dest).with_context(|| format!("renaming {} to {}", db.display(), dest.display()))?;
        for ext in ["-wal", "-shm"] {
            let mut from = db.as_os_str().to_owned();
            from.push(ext);
            let mut to = dest.as_os_str().to_owned();
            to.push(ext);
            if Path::new(&from).exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }
        Ok(dest)
    }

    /// Open an existing DB strictly read-only: no schema changes, no writer lease, no file
    /// creation. For queries that must not disturb (or wait for) a running recorder, e.g.
    /// `fat snapshot --fast`. Err when the file does not exist.
    pub fn open_read_only(path: Option<&str>) -> anyhow::Result<History> {
        let path = Self::resolve(path);
        anyhow::ensure!(path.exists(), "no recorder database at {}", path.display());
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI,
        )
        .with_context(|| format!("opening {} read-only", path.display()))?;
        conn.busy_timeout(Duration::from_millis(500))?;
        let (version, _) = Self::schema_of(&conn)?;
        anyhow::ensure!(
            version == SCHEMA_VERSION,
            "{} was written by a different fat version (schema v{version}; this fat reads v{SCHEMA_VERSION})",
            path.display()
        );
        Ok(Self::with_conn(conn, path, true))
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
        if self.read_only {
            return false;
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
        self.last_vols.clear();
        self.last_dirs.clear();
        self.last_dir_key = None;
        self.srv.reset();
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
            let mut chg = tx.prepare_cached("INSERT OR REPLACE INTO changes (kind, ts, json) VALUES (?1, ?2, ?3)")?;
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
                tx.prepare_cached("INSERT OR REPLACE INTO keyframes (ts) VALUES (?1)")?.execute(params![ts])?;
            }

            let sticky: HashSet<u32> = self.last_rows.keys().copied().collect();
            let server_top = if snap.units.is_empty() { None } else { self.srv.top_procs };
            let interesting = select_interesting(snap, &sticky, is_key, server_top);
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
        let before: Option<Ts> =
            self.conn.query_row("SELECT max(ts) FROM system WHERE ts <= ?1", [ts], |r| r.get(0))?;
        let after: Option<Ts> = self.conn.query_row("SELECT min(ts) FROM system WHERE ts >= ?1", [ts], |r| r.get(0))?;
        let sts = match (before, after) {
            (Some(b), Some(a)) => {
                if ts - b <= a - ts {
                    b
                } else {
                    a
                }
            }
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
        let units = self.units_at_sample(sts)?;
        let kernel = self.kernel_at(sts)?;

        Ok(Some(Snapshot {
            ts: sts,
            host: "local".into(),
            system,
            procs,
            ports,
            containers,
            units,
            kernel,
            ..Default::default()
        }))
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
        let key: Option<Ts> =
            self.conn.query_row("SELECT max(ts) FROM keyframes WHERE ts <= ?1", [from], |r| r.get(0))?;
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
                && out.is_empty()
                && ts > from
            {
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
        let pts = st.query_map(params![from - 60_000, to], row_to_point)?.collect::<Result<Vec<_>, _>>()?;
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
        let key: Option<Ts> =
            self.conn.query_row("SELECT max(ts) FROM keyframes WHERE ts <= ?1", [cutoff], |r| r.get(0))?;
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
        tx.execute("DELETE FROM volumes WHERE ts < ?1", [cutoff])?;
        // Dir sizes: keep the key snapshot that newer deltas depend on.
        let dkey: Option<Ts> =
            tx.query_row("SELECT max(ts) FROM fs_snaps WHERE key = 1 AND ts <= ?1", [cutoff], |r| r.get(0))?;
        let deff = dkey.unwrap_or(cutoff).min(cutoff);
        tx.execute("DELETE FROM fs_dirs WHERE ts < ?1", [deff])?;
        tx.execute("DELETE FROM fs_snaps WHERE ts < ?1", [deff])?;
        // Server tables: unit/disk rows are change points against the server keyframe.
        let skey: Option<Ts> =
            tx.query_row("SELECT max(ts) FROM server_keys WHERE ts <= ?1", [cutoff], |r| r.get(0))?;
        let seff = skey.unwrap_or(cutoff).min(cutoff);
        tx.execute("DELETE FROM units WHERE ts < ?1", [seff])?;
        tx.execute("DELETE FROM disks WHERE ts < ?1", [seff])?;
        tx.execute("DELETE FROM server_keys WHERE ts < ?1", [seff])?;
        tx.execute("DELETE FROM unit_ids WHERE last_seen < ?1", [seff - 2 * SERVER_KEY_MS])?;
        tx.execute("DELETE FROM kernel WHERE ts < ?1", [cutoff])?;
        tx.execute("DELETE FROM events WHERE ts < ?1", [cutoff])?;
        tx.commit()?;
        if removed > 0 {
            // Return freed pages to the filesystem; harmless if auto_vacuum is off.
            let _ = self.conn.execute_batch("PRAGMA incremental_vacuum;");
        }
        self.known_info.clear();
        self.srv.uids.clear();
        Ok(removed)
    }

    /// (oldest, newest) recorded ts.
    pub fn bounds(&self) -> anyhow::Result<Option<(Ts, Ts)>> {
        let r: (Option<Ts>, Option<Ts>) =
            self.conn.query_row("SELECT min(ts), max(ts) FROM system", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(match r {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        })
    }

    /// Timestamps of the samples in [from, to], oldest first (finding holes in coverage).
    pub fn sample_times(&self, from: Ts, to: Ts) -> anyhow::Result<Vec<Ts>> {
        let mut st = self.conn.prepare_cached("SELECT ts FROM system WHERE ts >= ?1 AND ts <= ?2 ORDER BY ts")?;
        let v = st.query_map([from, to], |r| r.get::<_, Ts>(0))?.collect::<Result<Vec<_>, _>>()?;
        Ok(v)
    }

    /// Number of recorded samples.
    #[allow(dead_code)]
    pub fn sample_count(&self) -> anyhow::Result<u64> {
        Ok(self.conn.query_row("SELECT count(*) FROM system", [], |r| r.get::<_, i64>(0))? as u64)
    }

    // ---- storage (fs) -------------------------------------------------------------------------

    /// Record mounted volumes (hidden ones are skipped). Change-point encoded: a volume gets a
    /// row when used/avail moved by >= 1 MiB, its I/O rate changed notably, or
    /// [`VOLUME_EVERY_MS`] passed. A no-op while another process holds the writer lease.
    pub fn record_volumes(&mut self, ts: Ts, vols: &[crate::fs::Volume]) -> anyhow::Result<()> {
        if !self.try_become_writer() {
            return Ok(());
        }
        let mut wrote: Vec<(String, VolRow)> = Vec::new();
        let mut new_ids: Vec<(String, i64)> = Vec::new();
        let tx = self.conn.transaction()?;
        {
            let mut get_id = tx.prepare_cached(
                "INSERT INTO volume_ids (mount) VALUES (?1)
                 ON CONFLICT(mount) DO UPDATE SET mount = excluded.mount RETURNING id",
            )?;
            let mut ins = tx.prepare_cached(
                "INSERT OR REPLACE INTO volumes (vid, ts, used, avail, total, read_bps, write_bps)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for v in vols.iter().filter(|v| !v.hidden) {
                let cur = (ts, clamp_i64(v.used), clamp_i64(v.avail), clamp_i64(v.read_bps), clamp_i64(v.write_bps));
                let due = match self.last_vols.get(&v.mount) {
                    None => true,
                    Some(&(lt, u, a, r, w)) => {
                        ts < lt
                            || ts - lt >= VOLUME_EVERY_MS
                            || (cur.1 - u).abs() >= VOLUME_MIN_DELTA
                            || (cur.2 - a).abs() >= VOLUME_MIN_DELTA
                            || rel_changed(cur.3, r, 0.5, 256 * 1024)
                            || rel_changed(cur.4, w, 0.5, 256 * 1024)
                    }
                };
                if !due {
                    continue;
                }
                let id = match self.vol_ids.get(&v.mount) {
                    Some(&id) => id,
                    None => {
                        let id: i64 = get_id.query_row([&v.mount], |r| r.get(0))?;
                        new_ids.push((v.mount.clone(), id));
                        id
                    }
                };
                ins.execute(params![id, ts, cur.1, cur.2, clamp_i64(v.total), cur.3, cur.4])?;
                wrote.push((v.mount.clone(), cur));
            }
        }
        tx.commit()?;
        self.vol_ids.extend(new_ids);
        self.last_vols.extend(wrote);
        Ok(())
    }

    /// Recorded (ts, used, avail) of one volume in [from, to], oldest first. Rows are change
    /// points; the value in effect at `from` (a row at most 2 x VOLUME_EVERY_MS earlier) is
    /// included as a point at `from`.
    pub fn volume_series(&self, mount: &str, from: Ts, to: Ts) -> anyhow::Result<Vec<(Ts, u64, u64)>> {
        if to < from {
            return Ok(vec![]);
        }
        let Some(vid): Option<i64> = self
            .conn
            .prepare_cached("SELECT id FROM volume_ids WHERE mount = ?1")?
            .query_row([mount], |r| r.get(0))
            .optional()?
        else {
            return Ok(vec![]);
        };
        let u = |v: i64| v.max(0) as u64;
        let mut out: Vec<(Ts, u64, u64)> = Vec::new();
        let carry: Option<(Ts, i64, i64)> = self
            .conn
            .prepare_cached("SELECT ts, used, avail FROM volumes WHERE vid = ?1 AND ts < ?2 ORDER BY ts DESC LIMIT 1")?
            .query_row(params![vid, from], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()?;
        let mut st = self.conn.prepare_cached(
            "SELECT ts, used, avail FROM volumes WHERE vid = ?1 AND ts BETWEEN ?2 AND ?3 ORDER BY ts",
        )?;
        let rows = st
            .query_map(params![vid, from, to], |r| Ok((r.get::<_, Ts>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        if let Some((t, us, av)) = carry
            && from - t <= 2 * VOLUME_EVERY_MS
            && rows.first().is_none_or(|r| r.0 > from)
        {
            out.push((from, u(us), u(av)));
        }
        out.extend(rows.into_iter().map(|(t, us, av)| (t, u(us), u(av))));
        Ok(out)
    }

    /// Seed a [`crate::fs::volumes::Volumes`] fill-rate window from recorded volume use, so a
    /// short-lived caller (CLI, MCP, a new TUI) reports a real 10-minute rate, not noise.
    pub fn seed_volumes(&self, v: &mut crate::fs::volumes::Volumes, now: Ts) {
        for m in self.volume_mounts().unwrap_or_default() {
            if let Ok(s) = self.volume_series(&m, now - crate::fs::volumes::FILL_WINDOW_MS, now) {
                let pts: Vec<(Ts, u64)> = s.into_iter().filter(|p| p.0 <= now).map(|(t, u, _)| (t, u)).collect();
                v.seed(&m, &pts);
            }
        }
    }

    /// Mounts that have recorded volume rows.
    pub fn volume_mounts(&self) -> anyhow::Result<Vec<String>> {
        let mut st = self.conn.prepare_cached("SELECT mount FROM volume_ids ORDER BY mount")?;
        let v = st.query_map([], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
        Ok(v)
    }

    /// Record a directory-size snapshot: (path, allocated bytes, files). Delta encoded against
    /// the last key snapshot (a full one every [`DIR_KEY_MS`]); at most [`DIR_MAX_ROWS`] paths
    /// (largest kept). A no-op while another process holds the writer lease.
    pub fn record_dir_sizes(&mut self, ts: Ts, dirs: &[(String, u64, u64)]) -> anyhow::Result<()> {
        if !self.try_become_writer() {
            return Ok(());
        }
        let mut dirs: Vec<&(String, u64, u64)> = dirs.iter().collect();
        if dirs.len() > DIR_MAX_ROWS {
            dirs.sort_by(|a, b| b.1.cmp(&a.1));
            dirs.truncate(DIR_MAX_ROWS);
        }
        let is_key = match self.last_dir_key {
            None => true,
            Some(k) => ts < k || ts - k >= DIR_KEY_MS,
        };
        let mut state = if is_key { HashMap::new() } else { self.last_dirs.clone() };
        let tx = self.conn.transaction()?;
        {
            tx.prepare_cached("INSERT OR REPLACE INTO fs_snaps (ts, key) VALUES (?1, ?2)")?
                .execute(params![ts, is_key as i64])?;
            let mut ins =
                tx.prepare_cached("INSERT OR REPLACE INTO fs_dirs (path, ts, size, files) VALUES (?1, ?2, ?3, ?4)")?;
            let mut present: HashSet<&str> = HashSet::with_capacity(dirs.len());
            for (path, size, files) in dirs {
                if !present.insert(path.as_str()) {
                    continue;
                }
                let size = clamp_i64(*size);
                let changed = match state.get(path) {
                    Some(&prev) if prev >= 0 => (size - prev).abs() >= DIR_MIN_DELTA,
                    _ => true,
                };
                if changed {
                    ins.execute(params![path, ts, size, clamp_i64(*files)])?;
                    state.insert(path.clone(), size);
                }
            }
            let gone: Vec<String> = state
                .iter()
                .filter(|(p, s)| **s >= 0 && !present.contains(p.as_str()))
                .map(|(p, _)| p.clone())
                .collect();
            for p in gone {
                ins.execute(params![p, ts, -1i64, 0i64])?;
                state.insert(p, -1);
            }
        }
        tx.commit()?;
        if is_key {
            self.last_dir_key = Some(ts);
        }
        self.last_dirs = state;
        Ok(())
    }

    /// Directory sizes from the nearest snapshot at or before `ts`, limited to `under` and
    /// its descendants ("/" = all), sorted by size desc. Paths no longer tracked are omitted.
    pub fn dir_sizes_near(&self, ts: Ts, under: &str) -> anyhow::Result<Option<DirSnapshot>> {
        let snap: Option<Ts> =
            self.conn.query_row("SELECT max(ts) FROM fs_snaps WHERE ts <= ?1", [ts], |r| r.get(0))?;
        let Some(snap) = snap else { return Ok(None) };
        let key: Option<Ts> =
            self.conn.query_row("SELECT max(ts) FROM fs_snaps WHERE key = 1 AND ts <= ?1", [snap], |r| r.get(0))?;
        let key = key.unwrap_or(i64::MIN);
        let under = if under.len() > 1 { under.trim_end_matches('/') } else { under };
        // Prefix range: `under` itself plus everything in [under + "/", under + "0") ('0' = '/' + 1).
        let (lo, hi) = if under == "/" || under.is_empty() {
            (String::new(), char::MAX.to_string())
        } else {
            (format!("{under}/"), format!("{under}0"))
        };
        // Bare `size` comes from the row holding max(ts) (SQLite min/max semantics).
        let mut st = self.conn.prepare_cached(
            "SELECT path, size, max(ts) FROM fs_dirs
             WHERE ts BETWEEN ?1 AND ?2 AND (path = ?3 OR (path >= ?4 AND path < ?5))
             GROUP BY path",
        )?;
        let mut v: Vec<(String, u64)> = st
            .query_map(params![key, snap, under, lo, hi], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .filter_map(|r| r.ok())
            .filter(|(_, s)| *s >= 0)
            .map(|(p, s)| (p, s as u64))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Ok(Some((snap, v)))
    }

    /// Bytes written per recorded process in [from, to]: (pid, name, bytes), largest first.
    /// Integrates the recorded per-process disk write rate over sample intervals (gaps longer
    /// than 60 s, i.e. the recorder was off, are not integrated). Only processes the recorder
    /// kept (top cpu/mem/power/disk writers ...) appear.
    pub fn proc_writes(&self, from: Ts, to: Ts) -> anyhow::Result<Vec<(u32, String, u64)>> {
        const MAX_GAP_MS: i64 = 60_000;
        if to <= from {
            return Ok(vec![]);
        }
        let prev_tick: Option<Ts> =
            self.conn.query_row("SELECT max(ts) FROM system WHERE ts < ?1", [from], |r| r.get(0))?;
        let ticks: Vec<Ts> = {
            let mut st = self.conn.prepare_cached("SELECT ts FROM system WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts")?;
            st.query_map(params![from, to], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?
        };
        let Some(&first) = ticks.first() else { return Ok(vec![]) };
        let key: Option<Ts> =
            self.conn.query_row("SELECT max(ts) FROM keyframes WHERE ts <= ?1", [first], |r| r.get(0))?;
        let mut blobs: Vec<(Ts, Vec<u8>)> = {
            let mut st =
                self.conn.prepare_cached("SELECT ts, data FROM procs WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts")?;
            st.query_map(params![key.unwrap_or(first).min(first), to], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?
        };
        blobs.reverse(); // pop from the end in ts order
        let mut state: HashMap<u32, (i64, i64)> = HashMap::new(); // pid -> (info, disk_w)
        let mut bytes: HashMap<(u32, i64), f64> = HashMap::new();
        let mut last = prev_tick;
        for &t in &ticks {
            while blobs.last().is_some_and(|b| b.0 <= t) {
                let (_, data) = blobs.pop().unwrap_or_default();
                for (pid, row) in decode_entries(&data) {
                    if row.is_tombstone() {
                        state.remove(&pid);
                    } else {
                        state.insert(pid, (row.info, row.disk_w));
                    }
                }
            }
            if let Some(l) = last {
                // The rate recorded at `t` is the average over (l, t]; clip to the window.
                let start = l.max(from);
                if t - l <= MAX_GAP_MS && t > start {
                    let dt = (t - start) as f64 / 1000.0;
                    for (&pid, &(info, w)) in &state {
                        if w > 0 {
                            *bytes.entry((pid, info)).or_default() += w as f64 * dt;
                        }
                    }
                }
            }
            last = Some(t);
        }
        let mut name_st = self.conn.prepare_cached("SELECT name FROM proc_info WHERE id = ?1")?;
        let mut out: Vec<(u32, String, u64)> = Vec::with_capacity(bytes.len());
        for ((pid, info), b) in bytes {
            let b = b.round() as u64;
            if b == 0 {
                continue;
            }
            let name: Option<String> = name_st.query_row([info], |r| r.get(0)).optional()?.flatten();
            out.push((pid, name.unwrap_or_default(), b));
        }
        out.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
        Ok(out)
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
                let load =
                    |i: usize| -> rusqlite::Result<f64> { Ok(r.get::<_, Option<i64>>(i)?.unwrap_or(0) as f64 / 100.0) };
                let u =
                    |i: usize| -> rusqlite::Result<u64> { Ok(r.get::<_, Option<i64>>(i)?.unwrap_or(0).max(0) as u64) };
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
            .prepare_cached("SELECT json FROM changes WHERE kind = ?1 AND ts <= ?2 ORDER BY ts DESC LIMIT 1")?
            .query_row(params![kind, ts], |r| r.get(0))
            .optional()?;
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
    }

    /// Replay packed proc entries from the keyframe preceding `ts` up to `ts`.
    fn procs_at(&self, ts: Ts) -> anyhow::Result<Vec<Proc>> {
        let key: Option<Ts> =
            self.conn.query_row("SELECT max(ts) FROM keyframes WHERE ts <= ?1", [ts], |r| r.get(0))?;
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
        let mut info_st =
            self.conn.prepare_cached("SELECT start_time, name, cmd, exe, cwd, user FROM proc_info WHERE id = ?1")?;
        let mut procs: Vec<Proc> = Vec::with_capacity(state.len());
        for (pid, r) in state {
            let info = info_st
                .query_row([r.info], |q| {
                    let s = |i: usize| -> rusqlite::Result<String> {
                        Ok(q.get::<_, Option<String>>(i)?.unwrap_or_default())
                    };
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
                cgroup: String::new(),
                container: None,
            });
        }
        procs.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(a.pid.cmp(&b.pid)));
        Ok(procs)
    }
}

// ---- server mode (recorder-export) --------------------------------------------------------------

/// Write-side caches for the server tables. Like the proc caches they are only valid for the
/// current writer stream and are reset whenever the lease is (re)taken.
#[derive(Default)]
struct ServerCache {
    /// Last server keyframe written.
    last_key: Option<Ts>,
    /// (kind, name) -> unit_ids.id.
    uids: HashMap<(UnitKind, String), i64>,
    /// uid -> meta JSON last written.
    meta: HashMap<i64, String>,
    /// uid -> last row written since the current keyframe.
    rows: HashMap<i64, UnitRow>,
    /// disk -> whether its last written row was busy.
    disks: HashMap<String, bool>,
    /// Bounds (from ServerCfg): units per sample, events per sample.
    max_units: Option<usize>,
    max_events: Option<usize>,
    /// `ServerCfg::record_top_procs`: in server snapshots the top-N by cpu/mem/io plus every
    /// unit's main pid are always recorded (see [`crate::server::top_procs`]).
    top_procs: Option<usize>,
}

impl ServerCache {
    fn reset(&mut self) {
        let (mu, me, tp) = (self.max_units, self.max_events, self.top_procs);
        *self = ServerCache { max_units: mu, max_events: me, top_procs: tp, ..Default::default() };
    }
}

const STATES: [&str; 7] = ["unknown", "active", "activating", "deactivating", "reloading", "inactive", "failed"];
const STATE_GONE: i64 = -1;

fn state_code(s: &str) -> i64 {
    STATES.iter().position(|x| *x == s).map_or(0, |i| i as i64)
}

fn state_name(c: i64) -> &'static str {
    if c == STATE_GONE { "gone" } else { STATES.get(c as usize).copied().unwrap_or("unknown") }
}

fn kind_name(k: UnitKind) -> &'static str {
    k.as_str()
}

fn kind_parse(s: &str) -> UnitKind {
    match s {
        "container" => UnitKind::Container,
        "k8s-pod" => UnitKind::Pod,
        "cgroup" => UnitKind::Cgroup,
        _ => UnitKind::Systemd,
    }
}

fn psi_enc(p: &Option<Pressure>) -> Option<String> {
    p.map(|p| {
        [p.cpu_some, p.cpu_full, p.mem_some, p.mem_full, p.io_some, p.io_full]
            .iter()
            .map(|v| q10(*v).to_string())
            .collect::<Vec<_>>()
            .join(",")
    })
}

fn psi_dec(s: Option<String>) -> Option<Pressure> {
    let v: Vec<f32> = s?.split(',').map(|x| x.parse::<i64>().unwrap_or(0) as f32 / 10.0).collect();
    (v.len() == 6).then(|| Pressure {
        cpu_some: v[0],
        cpu_full: v[1],
        mem_some: v[2],
        mem_full: v[3],
        io_some: v[4],
        io_full: v[5],
    })
}

/// Slow-changing per-unit fields, stored once per change in unit_ids.meta.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
struct UnitMeta {
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    cgroup: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    container: Option<ContainerMeta>,
}

/// Quantized unit values as stored in `units` (also the change-detection cache).
#[derive(Debug, Clone, Default, PartialEq)]
struct UnitRow {
    state: i64,
    sub: String,
    result: String,
    exit_code: Option<i64>,
    main_pid: Option<i64>,
    since: Option<i64>,
    restarts: i64,
    recent: i64,
    flags: i64,
    cpu10: i64,
    mem_kb: i64,
    limit_kb: Option<i64>,
    peak_kb: Option<i64>,
    pids: i64,
    io_r: i64,
    io_w: i64,
    thr10: i64,
    quota100: Option<i64>,
    psi: Option<String>,
    oom: i64,
}

impl UnitRow {
    fn from_unit(u: &Unit) -> UnitRow {
        let kb = |b: u64| clamp_i64(b / 1024);
        UnitRow {
            state: state_code(&u.state),
            sub: cap(&u.sub_state, 64).to_string(),
            result: cap(&u.result, 64).to_string(),
            exit_code: u.exit_code.map(i64::from),
            main_pid: u.main_pid.map(i64::from),
            since: u.since,
            restarts: u.restarts as i64,
            recent: u.recent_restarts as i64,
            flags: u.flapping as i64,
            cpu10: q10(u.cpu),
            mem_kb: kb(u.mem),
            limit_kb: u.mem_limit.map(kb),
            peak_kb: u.mem_peak.map(kb),
            pids: u.pids as i64,
            io_r: clamp_i64(u.io_read_bps),
            io_w: clamp_i64(u.io_write_bps),
            thr10: q10(u.cpu_throttled_pct),
            quota100: u.cpu_quota.map(|q| (q.max(0.0) * 100.0).round() as i64),
            psi: psi_enc(&u.psi),
            oom: clamp_i64(u.oom_kills),
        }
    }

    fn gone() -> UnitRow {
        UnitRow { state: STATE_GONE, ..Default::default() }
    }

    /// Worth a new change-point row? Identity/state fields on any change; resource numbers
    /// only when they moved noticeably (same thresholds spirit as ProcRow).
    fn differs_from(&self, p: &UnitRow) -> bool {
        let psi_moved = match (&self.psi, &p.psi) {
            (Some(a), Some(b)) => a
                .split(',')
                .zip(b.split(','))
                .any(|(x, y)| (x.parse::<i64>().unwrap_or(0) - y.parse::<i64>().unwrap_or(0)).abs() >= 50),
            (None, None) => false,
            _ => true,
        };
        self.state != p.state
            || self.sub != p.sub
            || self.result != p.result
            || self.exit_code != p.exit_code
            || self.main_pid != p.main_pid
            || self.since != p.since
            || self.restarts != p.restarts
            || self.recent != p.recent
            || self.flags != p.flags
            || self.limit_kb != p.limit_kb
            || self.quota100 != p.quota100
            || self.oom != p.oom
            || rel_changed(self.cpu10, p.cpu10, 0.30, 30)
            || rel_changed(self.mem_kb, p.mem_kb, 0.05, 4096)
            || rel_changed(self.peak_kb.unwrap_or(0), p.peak_kb.unwrap_or(0), 0.05, 4096)
            || rel_changed(self.pids, p.pids, 0.20, 2)
            || rel_changed(self.io_r, p.io_r, 0.50, 256 * 1024)
            || rel_changed(self.io_w, p.io_w, 0.50, 256 * 1024)
            || (self.thr10 - p.thr10).abs() >= 50
            || psi_moved
    }
}

const UNIT_COLS: &str = "state, sub, result, exit_code, main_pid, since, restarts, recent, flags, cpu10, mem_kb, \
    limit_kb, peak_kb, pids, io_r, io_w, thr10, quota100, psi, oom";

/// Read a UnitRow from columns starting at `o` (in UNIT_COLS order).
fn unit_row_at(r: &rusqlite::Row, o: usize) -> rusqlite::Result<UnitRow> {
    let i = |k: usize| -> rusqlite::Result<i64> { Ok(r.get::<_, Option<i64>>(o + k)?.unwrap_or(0)) };
    Ok(UnitRow {
        state: i(0)?,
        sub: r.get::<_, Option<String>>(o + 1)?.unwrap_or_default(),
        result: r.get::<_, Option<String>>(o + 2)?.unwrap_or_default(),
        exit_code: r.get(o + 3)?,
        main_pid: r.get(o + 4)?,
        since: r.get(o + 5)?,
        restarts: i(6)?,
        recent: i(7)?,
        flags: i(8)?,
        cpu10: i(9)?,
        mem_kb: i(10)?,
        limit_kb: r.get(o + 11)?,
        peak_kb: r.get(o + 12)?,
        pids: i(13)?,
        io_r: i(14)?,
        io_w: i(15)?,
        thr10: i(16)?,
        quota100: r.get(o + 17)?,
        psi: r.get(o + 18)?,
        oom: i(19)?,
    })
}

fn unit_from_row(name: String, kind: UnitKind, meta: UnitMeta, r: UnitRow) -> Unit {
    let b = |kb: i64| kb.max(0) as u64 * 1024;
    Unit {
        name,
        kind,
        state: state_name(r.state).into(),
        sub_state: r.sub,
        description: meta.description,
        result: r.result,
        exit_code: r.exit_code.map(|c| c as i32),
        restarts: r.restarts.max(0) as u32,
        recent_restarts: r.recent.max(0) as u32,
        flapping: r.flags & 1 != 0,
        since: r.since,
        cgroup: meta.cgroup,
        main_pid: r.main_pid.map(|p| p as u32),
        pids: r.pids.max(0) as u32,
        cpu: r.cpu10 as f32 / 10.0,
        mem: b(r.mem_kb),
        mem_limit: r.limit_kb.map(b),
        mem_peak: r.peak_kb.map(b),
        io_read_bps: r.io_r.max(0) as u64,
        io_write_bps: r.io_w.max(0) as u64,
        cpu_throttled_pct: r.thr10 as f32 / 10.0,
        cpu_quota: r.quota100.map(|q| q as f32 / 100.0),
        psi: psi_dec(r.psi),
        oom_kills: r.oom.max(0) as u64,
        container: meta.container,
        notes: vec![],
    }
}

fn unit_point(ts: Ts, r: &UnitRow) -> UnitPoint {
    UnitPoint {
        ts,
        state: state_name(r.state).into(),
        restarts: r.restarts.max(0) as u32,
        cpu: r.cpu10 as f32 / 10.0,
        mem: r.mem_kb.max(0) as u64 * 1024,
        mem_limit: r.limit_kb.map(|k| k.max(0) as u64 * 1024),
        pids: r.pids.max(0) as u32,
        io_read_bps: r.io_r.max(0) as u64,
        io_write_bps: r.io_w.max(0) as u64,
        cpu_throttled_pct: r.thr10 as f32 / 10.0,
        psi: psi_dec(r.psi.clone()),
        oom_kills: r.oom.max(0) as u64,
    }
}

/// Kernel fields that rarely change; stored in `changes` under kind "kernel".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
struct KernelSlow {
    numa: Vec<NumaNode>,
    ro_remounts: Vec<String>,
    fs_errors: Vec<FsErrorStat>,
    taint_flags: String,
    mdraid: Vec<MdArray>,
    notes: Vec<String>,
}

const KIND_KERNEL: &str = "kernel";
const KIND_META: &str = "meta";

const KERNEL_COLS: &str = "steal10, iowait10, irq10, softirq10, running, blocked, psi, avail_kb, swin10, swout10, \
    oom_total, fd_used, fd_max, ct_used, ct_max, eph_used, eph_lo, eph_hi, retrans10, overflows10, drops10, taint, ntp, dstate";

/// Kernel scalars from columns starting at `o` (KERNEL_COLS order).
fn kernel_row_at(r: &rusqlite::Row, o: usize) -> rusqlite::Result<Kernel> {
    let i = |k: usize| -> rusqlite::Result<i64> { Ok(r.get::<_, Option<i64>>(o + k)?.unwrap_or(0)) };
    let opt =
        |k: usize| -> rusqlite::Result<Option<u64>> { Ok(r.get::<_, Option<i64>>(o + k)?.map(|v| v.max(0) as u64)) };
    let t = |k: usize| -> rusqlite::Result<f32> { Ok(i(k)? as f32 / 10.0) };
    let range = match (r.get::<_, Option<i64>>(o + 16)?, r.get::<_, Option<i64>>(o + 17)?) {
        (Some(a), Some(b)) => Some((a.clamp(0, 65535) as u16, b.clamp(0, 65535) as u16)),
        _ => None,
    };
    let dstate: Option<String> = r.get(o + 23)?;
    Ok(Kernel {
        steal_pct: t(0)?,
        iowait_pct: t(1)?,
        irq_pct: t(2)?,
        softirq_pct: t(3)?,
        procs_running: i(4)?.max(0) as u32,
        procs_blocked: i(5)?.max(0) as u32,
        pressure: psi_dec(r.get(o + 6)?),
        mem_available: i(7)?.max(0) as u64 * 1024,
        swap_in_ps: t(8)?,
        swap_out_ps: t(9)?,
        oom_kills_total: i(10)?.max(0) as u64,
        fd_used: opt(11)?,
        fd_max: opt(12)?,
        conntrack_used: opt(13)?,
        conntrack_max: opt(14)?,
        ephemeral_used: opt(15)?,
        ephemeral_range: range,
        tcp_retrans_ps: t(18)?,
        listen_overflows_ps: t(19)?,
        listen_drops_ps: t(20)?,
        taint: i(21)?.max(0) as u64,
        ntp_synced: r.get::<_, Option<i64>>(o + 22)?.map(|v| v != 0),
        d_state: dstate.and_then(|j| serde_json::from_str::<Vec<DStateProc>>(&j).ok()).unwrap_or_default(),
        ..Default::default()
    })
}

fn disk_busy(d: &DiskStat) -> bool {
    d.r_iops > 0.0 || d.w_iops > 0.0 || d.util_pct > 0.0 || d.queue_depth > 0.0 || d.r_bps > 0 || d.w_bps > 0
}

const DISK_COLS: &str = "name, util10, r_await10, w_await10, qd10, r_iops10, w_iops10, r_bps, w_bps, errors";

fn disk_row_at(r: &rusqlite::Row, o: usize) -> rusqlite::Result<DiskStat> {
    let t = |k: usize| -> rusqlite::Result<f32> { Ok(r.get::<_, Option<i64>>(o + k)?.unwrap_or(0) as f32 / 10.0) };
    let u = |k: usize| -> rusqlite::Result<u64> { Ok(r.get::<_, Option<i64>>(o + k)?.unwrap_or(0).max(0) as u64) };
    Ok(DiskStat {
        name: r.get(o)?,
        util_pct: t(1)?,
        r_await_ms: t(2)?,
        w_await_ms: t(3)?,
        queue_depth: t(4)?,
        r_iops: t(5)?,
        w_iops: t(6)?,
        r_bps: u(7)?,
        w_bps: u(8)?,
        io_errors: r.get::<_, Option<i64>>(o + 9)?.map(|v| v.max(0) as u64),
    })
}

fn sev_code(s: Severity) -> i64 {
    match s {
        Severity::Info => 0,
        Severity::Warn => 1,
        Severity::Crit => 2,
    }
}

fn sev_of(c: i64) -> Severity {
    match c {
        2 => Severity::Crit,
        1 => Severity::Warn,
        _ => Severity::Info,
    }
}

/// Insert events (deduplicated on (ts, kind, subject)); returns rows inserted.
fn insert_events(tx: &rusqlite::Transaction, events: &[Event]) -> anyhow::Result<usize> {
    let mut st = tx.prepare_cached(
        "INSERT OR IGNORE INTO events (ts, kind, severity, subject, unit, pid, value, detail, source, extra)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    let mut n = 0;
    for e in events {
        let extra = if e.extra.is_empty() { None } else { Some(serde_json::to_string(&e.extra)?) };
        n += st.execute(params![
            e.ts,
            e.kind.as_str(),
            sev_code(e.severity),
            cap(&e.subject, 256),
            e.unit.as_deref().map(|u| cap(u, 256)),
            e.pid,
            e.value.filter(|v| v.is_finite()),
            cap(&e.detail, 1024),
            cap(&e.source, 32),
            extra
        ])?;
    }
    Ok(n)
}

fn event_from_row(r: &rusqlite::Row) -> rusqlite::Result<Event> {
    let kind: String = r.get(1)?;
    let extra: Option<String> = r.get(9)?;
    Ok(Event {
        ts: r.get(0)?,
        kind: EventKind::parse(&kind).unwrap_or(EventKind::Other),
        severity: sev_of(r.get(2)?),
        subject: r.get(3)?,
        unit: r.get(4)?,
        pid: r.get::<_, Option<i64>>(5)?.map(|p| p as u32),
        value: r.get(6)?,
        detail: r.get(7)?,
        source: r.get(8)?,
        extra: extra.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default(),
    })
}

/// Events kept per sample: the most severe first, then oldest; the rest are summarised.
fn cap_events(mut ev: Vec<Event>, max: usize, ts: Ts) -> Vec<Event> {
    if ev.len() <= max {
        return ev;
    }
    let total = ev.len();
    ev.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.ts.cmp(&b.ts)));
    let keep = max.saturating_sub(1);
    let dropped = ev.split_off(keep);
    let mut kinds: Vec<&str> = dropped.iter().map(|e| e.kind.as_str()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    ev.push(Event {
        ts,
        kind: EventKind::Other,
        severity: Severity::Warn,
        subject: "host".into(),
        detail: format!(
            "{} of {total} events in one sample not recorded (cap {max}): {}",
            dropped.len(),
            kinds.join(", ")
        ),
        value: Some(dropped.len() as f64),
        source: "recorder".into(),
        ..Default::default()
    });
    ev.sort_by_key(|e| e.ts);
    ev
}

/// Keep at most `max` units: active/failed ones first (failed always kept), inactive dropped first.
fn cap_units(units: &[Unit], max: usize) -> Vec<&Unit> {
    let mut v: Vec<&Unit> = units.iter().collect();
    if v.len() > max {
        let rank = |u: &Unit| match u.state.as_str() {
            "failed" => 0,
            "inactive" | "unknown" => 2,
            _ => 1,
        };
        v.sort_by(|a, b| rank(a).cmp(&rank(b)).then(b.cpu.total_cmp(&a.cpu)).then(b.mem.cmp(&a.mem)));
        v.truncate(max);
    }
    v
}

impl History {
    /// Apply the recorder bounds of `[server]` (units and events per sample).
    pub fn set_server_limits(&mut self, cfg: &ServerCfg) {
        self.srv.max_units = Some(cfg.max_units.max(1));
        self.srv.max_events = Some(cfg.max_events_per_sample.max(1));
        self.srv.top_procs = Some(cfg.record_top_procs);
    }

    /// Persist units, kernel and events of a snapshot filled by ServerSampler. Cheap no-op when
    /// snap.units/kernel/events are all empty (desktop profile). Events are de-duplicated on
    /// (ts, kind, subject). A no-op while another process holds the writer lease.
    ///
    /// Units and disks are change-point encoded against a keyframe every [`SERVER_KEY_MS`]
    /// and at the start of each writer stream (every unit and disk gets a row there); in between a unit gets a row only when its state
    /// changed or its numbers moved noticeably, and a "gone" row when it disappears. Idle disks
    /// get no rows between keyframes. The kernel's scalars get one narrow row per sample; its
    /// slow parts (numa, mdraid, notes...) and the snapshot meta go to `changes` on change.
    pub fn record_server(&mut self, snap: &Snapshot) -> anyhow::Result<()> {
        if snap.units.is_empty() && snap.kernel.is_none() && snap.events.is_empty() {
            return Ok(());
        }
        if !self.try_become_writer() {
            return Ok(());
        }
        let ts = snap.ts;
        let is_key = match self.srv.last_key {
            None => true,
            Some(k) => ts < k || ts - k >= SERVER_KEY_MS,
        };
        let max_units = self.srv.max_units.unwrap_or(ServerCfg::default().max_units);
        let max_events = self.srv.max_events.unwrap_or(ServerCfg::default().max_events_per_sample);
        let mut rows = if is_key { HashMap::new() } else { self.srv.rows.clone() };
        let mut disks_state = if is_key { HashMap::new() } else { self.srv.disks.clone() };
        let mut new_uids: Vec<((UnitKind, String), i64)> = Vec::new();
        let mut new_meta: Vec<(i64, String)> = Vec::new();
        let mut new_changes: Vec<(&'static str, String)> = Vec::new();

        let tx = self.conn.transaction()?;
        {
            if is_key {
                tx.prepare_cached("INSERT OR REPLACE INTO server_keys (ts) VALUES (?1)")?.execute(params![ts])?;
            }
            // ---- units
            let mut get_uid = tx.prepare_cached(
                "INSERT INTO unit_ids (name, kind, last_seen) VALUES (?1, ?2, ?3)
                 ON CONFLICT(name, kind) DO UPDATE SET last_seen = excluded.last_seen RETURNING id",
            )?;
            let mut touch = tx.prepare_cached("UPDATE unit_ids SET last_seen = ?1 WHERE id = ?2")?;
            let mut set_meta = tx.prepare_cached("UPDATE unit_ids SET meta = ?1 WHERE id = ?2")?;
            let mut ins = tx.prepare_cached(&format!(
                "INSERT OR REPLACE INTO units (uid, ts, {UNIT_COLS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)"
            ))?;
            let write = |ins: &mut rusqlite::CachedStatement, uid: i64, r: &UnitRow| -> rusqlite::Result<usize> {
                ins.execute(params![
                    uid,
                    ts,
                    r.state,
                    r.sub,
                    r.result,
                    r.exit_code,
                    r.main_pid,
                    r.since,
                    r.restarts,
                    r.recent,
                    r.flags,
                    r.cpu10,
                    r.mem_kb,
                    r.limit_kb,
                    r.peak_kb,
                    r.pids,
                    r.io_r,
                    r.io_w,
                    r.thr10,
                    r.quota100,
                    r.psi,
                    r.oom
                ])
            };
            let mut present: HashSet<i64> = HashSet::new();
            for u in cap_units(&snap.units, max_units) {
                let key = (u.kind, cap(&u.name, 512).to_string());
                let uid = match self.srv.uids.get(&key) {
                    Some(&id) => {
                        if is_key {
                            touch.execute(params![ts, id])?;
                        }
                        id
                    }
                    None => {
                        let id: i64 = get_uid.query_row(params![key.1, kind_name(u.kind), ts], |r| r.get(0))?;
                        new_uids.push((key, id));
                        id
                    }
                };
                if !present.insert(uid) {
                    continue; // duplicate name within one sample
                }
                let meta = UnitMeta {
                    description: cap(&u.description, 256).into(),
                    cgroup: cap(&u.cgroup, 512).into(),
                    container: u.container.clone(),
                };
                let mj = serde_json::to_string(&meta)?;
                if self.srv.meta.get(&uid) != Some(&mj) {
                    set_meta.execute(params![mj, uid])?;
                    new_meta.push((uid, mj));
                }
                let row = UnitRow::from_unit(u);
                let changed = match rows.get(&uid) {
                    Some(prev) if prev.state != STATE_GONE => row.differs_from(prev),
                    _ => true,
                };
                if changed {
                    write(&mut ins, uid, &row)?;
                    rows.insert(uid, row);
                }
            }
            // Departed units get a "gone" row (also across a keyframe, where `rows` restarts
            // empty, so a series shows where the unit ended).
            let gone: Vec<i64> = rows
                .iter()
                .chain(self.srv.rows.iter())
                .filter(|(id, r)| r.state != STATE_GONE && !present.contains(id))
                .map(|(id, _)| *id)
                .collect::<HashSet<i64>>()
                .into_iter()
                .collect();
            for uid in gone {
                write(&mut ins, uid, &UnitRow::gone())?;
                rows.remove(&uid);
            }

            // ---- kernel
            if let Some(k) = &snap.kernel {
                let opt = |v: Option<u64>| v.map(clamp_i64);
                let dstate = if k.d_state.is_empty() { None } else { Some(serde_json::to_string(&k.d_state)?) };
                tx.prepare_cached(&format!(
                    "INSERT OR REPLACE INTO kernel (ts, {KERNEL_COLS})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)"
                ))?
                .execute(params![
                    ts,
                    q10(k.steal_pct),
                    q10(k.iowait_pct),
                    q10(k.irq_pct),
                    q10(k.softirq_pct),
                    k.procs_running,
                    k.procs_blocked,
                    psi_enc(&k.pressure),
                    clamp_i64(k.mem_available / 1024),
                    q10(k.swap_in_ps),
                    q10(k.swap_out_ps),
                    clamp_i64(k.oom_kills_total),
                    opt(k.fd_used),
                    opt(k.fd_max),
                    opt(k.conntrack_used),
                    opt(k.conntrack_max),
                    opt(k.ephemeral_used),
                    k.ephemeral_range.map(|r| r.0),
                    k.ephemeral_range.map(|r| r.1),
                    q10(k.tcp_retrans_ps),
                    q10(k.listen_overflows_ps),
                    q10(k.listen_drops_ps),
                    clamp_i64(k.taint),
                    k.ntp_synced.map(i64::from),
                    dstate
                ])?;
                let mut dins = tx.prepare_cached(&format!(
                    "INSERT OR REPLACE INTO disks (ts, {DISK_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
                ))?;
                for d in &k.disks {
                    let busy = disk_busy(d);
                    let was_busy = disks_state.get(&d.name).copied();
                    if is_key || busy || was_busy != Some(false) {
                        dins.execute(params![
                            ts,
                            cap(&d.name, 64),
                            q10(d.util_pct),
                            q10(d.r_await_ms),
                            q10(d.w_await_ms),
                            q10(d.queue_depth),
                            q10(d.r_iops),
                            q10(d.w_iops),
                            clamp_i64(d.r_bps),
                            clamp_i64(d.w_bps),
                            d.io_errors.map(clamp_i64)
                        ])?;
                        disks_state.insert(d.name.clone(), busy);
                    }
                }
                let slow = KernelSlow {
                    numa: k.numa.clone(),
                    ro_remounts: k.ro_remounts.clone(),
                    fs_errors: k.fs_errors.clone(),
                    taint_flags: k.taint_flags.clone(),
                    mdraid: k.mdraid.clone(),
                    notes: k.notes.clone(),
                };
                new_changes.push((KIND_KERNEL, serde_json::to_string(&slow)?));
            }
            if let Some(m) = &snap.meta {
                // Only the identity of the writer; per-serve fields (age, source...) are not stored.
                let m = serde_json::json!({ "version": m.version, "profile": m.profile, "root": m.root });
                new_changes.push((KIND_META, m.to_string()));
            }
            new_changes.retain(|(k, j)| self.last_changes.get(k) != Some(j));
            let mut chg = tx.prepare_cached("INSERT OR REPLACE INTO changes (kind, ts, json) VALUES (?1, ?2, ?3)")?;
            for (k, j) in &new_changes {
                chg.execute(params![k, ts, j])?;
            }

            // ---- events
            if !snap.events.is_empty() {
                insert_events(&tx, &cap_events(snap.events.clone(), max_events, ts))?;
            }
        }
        tx.commit()?;
        if is_key {
            self.srv.last_key = Some(ts);
        }
        self.srv.rows = rows;
        self.srv.disks = disks_state;
        if self.srv.uids.len() > INFO_CACHE_MAX {
            self.srv.uids.clear();
            self.srv.meta.clear();
        }
        self.srv.uids.extend(new_uids);
        self.srv.meta.extend(new_meta);
        for (k, j) in new_changes {
            self.last_changes.insert(k, j);
        }
        Ok(())
    }

    /// Append events directly (kmsg backlog import on daemon start). Returns rows inserted
    /// (duplicates of recorded events are skipped). A no-op (0) without the writer lease.
    pub fn record_events(&mut self, events: &[Event]) -> anyhow::Result<usize> {
        if events.is_empty() || !self.try_become_writer() {
            return Ok(0);
        }
        let tx = self.conn.transaction()?;
        let n = insert_events(&tx, events)?;
        tx.commit()?;
        Ok(n)
    }

    /// Events with from <= ts <= to, oldest first; `kinds` empty = all kinds. When more than
    /// `limit` match, the newest `limit` are returned (still oldest first).
    pub fn events(&self, from: Ts, to: Ts, kinds: &[EventKind], limit: usize) -> anyhow::Result<Vec<Event>> {
        if to < from || limit == 0 {
            return Ok(vec![]);
        }
        let kind_filter = if kinds.is_empty() {
            String::new()
        } else {
            let names: Vec<String> = kinds.iter().map(|k| format!("'{}'", k.as_str())).collect();
            format!(" AND kind IN ({})", names.join(","))
        };
        let mut st = self.conn.prepare_cached(&format!(
            "SELECT ts, kind, severity, subject, unit, pid, value, detail, source, extra FROM events
             WHERE ts BETWEEN ?1 AND ?2{kind_filter} ORDER BY ts DESC, id DESC LIMIT ?3"
        ))?;
        let mut v = st
            .query_map(params![from, to, limit.min(i64::MAX as usize) as i64], event_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        v.reverse();
        Ok(v)
    }

    /// Count of events of `kind` since `from` (header gauges: OOM kills in 24h).
    pub fn event_count(&self, kind: EventKind, from: Ts) -> anyhow::Result<u64> {
        let n: i64 = self
            .conn
            .prepare_cached("SELECT count(*) FROM events WHERE kind = ?1 AND ts >= ?2")?
            .query_row(params![kind.as_str(), from], |r| r.get(0))?;
        Ok(n.max(0) as u64)
    }

    /// uids recorded under `name` (any kind).
    fn uids_named(&self, name: &str) -> anyhow::Result<Vec<i64>> {
        let mut st = self.conn.prepare_cached("SELECT id FROM unit_ids WHERE name = ?1")?;
        let v = st.query_map([name], |r| r.get(0))?.collect::<Result<Vec<i64>, _>>()?;
        Ok(v)
    }

    /// One unit over time, oldest first. Rows are change points (a value holds until the next
    /// point); the value in effect at `from` is included as a point at `from`. A point with
    /// state "gone" means the unit disappeared there.
    pub fn unit_series(&self, name: &str, from: Ts, to: Ts) -> anyhow::Result<Vec<UnitPoint>> {
        if to < from {
            return Ok(vec![]);
        }
        let mut out: Vec<UnitPoint> = Vec::new();
        for uid in self.uids_named(name)? {
            let carry: Option<(Ts, UnitRow)> = self
                .conn
                .prepare_cached(&format!(
                    "SELECT ts, {UNIT_COLS} FROM units WHERE uid = ?1 AND ts < ?2 ORDER BY ts DESC LIMIT 1"
                ))?
                .query_row(params![uid, from], |r| Ok((r.get(0)?, unit_row_at(r, 1)?)))
                .optional()?;
            let mut st = self.conn.prepare_cached(&format!(
                "SELECT ts, {UNIT_COLS} FROM units WHERE uid = ?1 AND ts BETWEEN ?2 AND ?3 ORDER BY ts"
            ))?;
            let rows = st
                .query_map(params![uid, from, to], |r| Ok((r.get::<_, Ts>(0)?, unit_row_at(r, 1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            if let Some((t, r)) = carry
                && r.state != STATE_GONE
                && from - t <= SERVER_KEY_MS + KEYFRAME_MS
                && rows.first().is_none_or(|x| x.0 > from)
            {
                out.push(unit_point(from, &r));
            }
            out.extend(rows.iter().map(|(t, r)| unit_point(*t, r)));
        }
        out.sort_by_key(|p| p.ts);
        Ok(out)
    }

    /// All units as recorded at the sample nearest to `ts` (within [`KEYFRAME_MS`]), else empty.
    pub fn units_at(&self, ts: Ts) -> anyhow::Result<Vec<Unit>> {
        match self.nearest_sample(ts, KEYFRAME_MS)? {
            Some(sts) => self.units_at_sample(sts),
            None => Ok(vec![]),
        }
    }

    /// Nearest recorded sample (system or kernel row) to `ts`, if within `max_gap`.
    fn nearest_sample(&self, ts: Ts, max_gap: i64) -> anyhow::Result<Option<Ts>> {
        let q = |sql: &str| -> anyhow::Result<Option<Ts>> {
            Ok(self.conn.prepare_cached(sql)?.query_row([ts], |r| r.get(0))?)
        };
        let before = [q("SELECT max(ts) FROM system WHERE ts <= ?1")?, q("SELECT max(ts) FROM kernel WHERE ts <= ?1")?]
            .into_iter()
            .flatten()
            .max();
        let after = [q("SELECT min(ts) FROM system WHERE ts >= ?1")?, q("SELECT min(ts) FROM kernel WHERE ts >= ?1")?]
            .into_iter()
            .flatten()
            .min();
        let best = match (before, after) {
            (Some(b), Some(a)) => Some(if ts - b <= a - ts { b } else { a }),
            (b, a) => b.or(a),
        };
        Ok(best.filter(|s| (s - ts).abs() <= max_gap))
    }

    /// Units in effect at exactly the recorded sample `sts`.
    fn units_at_sample(&self, sts: Ts) -> anyhow::Result<Vec<Unit>> {
        let key: Option<Ts> = self
            .conn
            .prepare_cached("SELECT max(ts) FROM server_keys WHERE ts <= ?1")?
            .query_row([sts], |r| r.get(0))?;
        let Some(key) = key else { return Ok(vec![]) };
        let ids: Vec<(i64, String, String, Option<String>)> = {
            let mut st = self.conn.prepare_cached("SELECT id, name, kind, meta FROM unit_ids WHERE last_seen >= ?1")?;
            st.query_map([key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<Vec<_>, _>>()?
        };
        let mut st = self.conn.prepare_cached(&format!(
            "SELECT ts, {UNIT_COLS} FROM units WHERE uid = ?1 AND ts <= ?2 ORDER BY ts DESC LIMIT 1"
        ))?;
        let mut out = Vec::new();
        for (uid, name, kind, meta) in ids {
            let Some((t, row)) =
                st.query_row(params![uid, sts], |r| Ok((r.get::<_, Ts>(0)?, unit_row_at(r, 1)?))).optional()?
            else {
                continue;
            };
            if t < key || row.state == STATE_GONE {
                continue;
            }
            let meta: UnitMeta = meta.and_then(|m| serde_json::from_str(&m).ok()).unwrap_or_default();
            out.push(unit_from_row(name, kind_parse(&kind), meta, row));
        }
        out.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.name.cmp(&b.name)));
        Ok(out)
    }

    /// Kernel state recorded at exactly `sts` (scalars, slow parts, disks), if any.
    fn kernel_at(&self, sts: Ts) -> anyhow::Result<Option<Kernel>> {
        let k = self
            .conn
            .prepare_cached(&format!("SELECT {KERNEL_COLS} FROM kernel WHERE ts = ?1"))?
            .query_row([sts], |r| kernel_row_at(r, 0))
            .optional()?;
        let Some(mut k) = k else { return Ok(None) };
        if let Some(slow) = self.change_at::<KernelSlow>(KIND_KERNEL, sts)? {
            k.numa = slow.numa;
            k.ro_remounts = slow.ro_remounts;
            k.fs_errors = slow.fs_errors;
            k.taint_flags = slow.taint_flags;
            k.mdraid = slow.mdraid;
            k.notes = slow.notes;
        }
        // Disks: the latest row per disk since the keyframe; idle disks read as zero.
        let key: Option<Ts> = self
            .conn
            .prepare_cached("SELECT max(ts) FROM server_keys WHERE ts <= ?1")?
            .query_row([sts], |r| r.get(0))?;
        if let Some(key) = key {
            let mut st = self.conn.prepare_cached(&format!(
                "SELECT max(ts), {DISK_COLS} FROM disks WHERE ts BETWEEN ?1 AND ?2 GROUP BY name ORDER BY name"
            ))?;
            k.disks =
                st.query_map(params![key, sts], |r| Ok((r.get::<_, Ts>(0)?, disk_row_at(r, 1)?)))?
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .map(|(t, d)| {
                        if t == sts {
                            d
                        } else {
                            DiskStat { name: d.name, io_errors: d.io_errors, ..Default::default() }
                        }
                    })
                    .collect();
        }
        Ok(Some(k))
    }

    /// Kernel state over time, oldest first, downsampled to at most `max_points` buckets:
    /// rates and gauges averaged, counters (oom total, taint) and procs_blocked / await /
    /// util maxed per bucket so short spikes survive downsampling. Disks per bucket; slow
    /// parts (numa, mdraid, notes) and D-state lists are not part of the series.
    pub fn kernel_series(&self, from: Ts, to: Ts, max_points: usize) -> anyhow::Result<Vec<(Ts, Kernel)>> {
        if to < from || max_points == 0 {
            return Ok(vec![]);
        }
        let n = max_points.min(1_000_000) as i128;
        let span = (to - from) as i128 + 1;
        let bucket = |ts: Ts| (((ts - from) as i128 * n) / span) as i64;
        let rows: Vec<(Ts, Kernel)> = {
            let mut st = self.conn.prepare_cached(&format!(
                "SELECT ts, {KERNEL_COLS} FROM kernel WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts"
            ))?;
            st.query_map(params![from, to], |r| Ok((r.get(0)?, kernel_row_at(r, 1)?)))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut out: Vec<(Ts, Kernel)> = Vec::new();
        let mut group: Vec<(Ts, Kernel)> = Vec::new();
        let flush = |group: &mut Vec<(Ts, Kernel)>, out: &mut Vec<(Ts, Kernel)>| {
            if group.is_empty() {
                return;
            }
            let c = group.len() as f32;
            let avg = |f: &dyn Fn(&Kernel) -> f32| group.iter().map(|(_, k)| f(k)).sum::<f32>() / c;
            let last = group.last().map(|g| g.1.clone()).unwrap_or_default();
            let ts = group.iter().map(|g| g.0 as i128).sum::<i128>() / group.len() as i128;
            let psi = last.pressure.map(|_| Pressure {
                cpu_some: avg(&|k| k.pressure.map_or(0.0, |p| p.cpu_some)),
                cpu_full: avg(&|k| k.pressure.map_or(0.0, |p| p.cpu_full)),
                mem_some: avg(&|k| k.pressure.map_or(0.0, |p| p.mem_some)),
                mem_full: avg(&|k| k.pressure.map_or(0.0, |p| p.mem_full)),
                io_some: avg(&|k| k.pressure.map_or(0.0, |p| p.io_some)),
                io_full: avg(&|k| k.pressure.map_or(0.0, |p| p.io_full)),
            });
            let k = Kernel {
                steal_pct: avg(&|k| k.steal_pct),
                iowait_pct: avg(&|k| k.iowait_pct),
                irq_pct: avg(&|k| k.irq_pct),
                softirq_pct: avg(&|k| k.softirq_pct),
                procs_running: avg(&|k| k.procs_running as f32).round() as u32,
                procs_blocked: group.iter().map(|g| g.1.procs_blocked).max().unwrap_or(0),
                pressure: psi,
                mem_available: group.iter().map(|g| g.1.mem_available).min().unwrap_or(0),
                swap_in_ps: avg(&|k| k.swap_in_ps),
                swap_out_ps: avg(&|k| k.swap_out_ps),
                tcp_retrans_ps: avg(&|k| k.tcp_retrans_ps),
                listen_overflows_ps: avg(&|k| k.listen_overflows_ps),
                listen_drops_ps: avg(&|k| k.listen_drops_ps),
                fd_used: group.iter().filter_map(|g| g.1.fd_used).max(),
                conntrack_used: group.iter().filter_map(|g| g.1.conntrack_used).max(),
                ephemeral_used: group.iter().filter_map(|g| g.1.ephemeral_used).max(),
                d_state: vec![],
                ..last
            };
            out.push((ts as Ts, k));
            group.clear();
        };
        for (ts, k) in rows {
            if group.last().is_some_and(|g| bucket(g.0) != bucket(ts)) {
                flush(&mut group, &mut out);
            }
            group.push((ts, k));
        }
        flush(&mut group, &mut out);
        // Disks: per bucket and name, max await/util/queue, average rates.
        let mut st = self
            .conn
            .prepare_cached(&format!("SELECT ts, {DISK_COLS} FROM disks WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts"))?;
        let disk_rows = st.query_map(params![from, to], |r| Ok((r.get::<_, Ts>(0)?, disk_row_at(r, 1)?)))?;
        let mut per: HashMap<(i64, String), (DiskStat, u32)> = HashMap::new();
        for d in disk_rows {
            let (ts, d) = d?;
            let e = per
                .entry((bucket(ts), d.name.clone()))
                .or_insert_with(|| (DiskStat { name: d.name.clone(), ..Default::default() }, 0));
            let a = &mut e.0;
            a.util_pct = a.util_pct.max(d.util_pct);
            a.r_await_ms = a.r_await_ms.max(d.r_await_ms);
            a.w_await_ms = a.w_await_ms.max(d.w_await_ms);
            a.queue_depth = a.queue_depth.max(d.queue_depth);
            a.r_iops += d.r_iops;
            a.w_iops += d.w_iops;
            a.r_bps += d.r_bps;
            a.w_bps += d.w_bps;
            a.io_errors = d.io_errors.or(a.io_errors);
            e.1 += 1;
        }
        for (ts, k) in out.iter_mut() {
            let b = bucket(*ts);
            let mut ds: Vec<DiskStat> = per
                .iter()
                .filter(|((bb, _), _)| *bb == b)
                .map(|(_, (d, c))| {
                    let c = (*c).max(1);
                    DiskStat {
                        r_iops: d.r_iops / c as f32,
                        w_iops: d.w_iops / c as f32,
                        r_bps: d.r_bps / c as u64,
                        w_bps: d.w_bps / c as u64,
                        ..d.clone()
                    }
                })
                .collect();
            ds.sort_by(|a, b| a.name.cmp(&b.name));
            k.disks = ds;
        }
        Ok(out)
    }

    /// The newest recorded sample as a full Snapshot (system, recorded procs, ports, units,
    /// kernel, events of the last interval) if it is younger than `max_age_ms`; used by
    /// `fat snapshot --fast` so a fleet poll costs one SQLite read instead of a live sample.
    /// meta.source = "recorder", meta.age_ms = now - ts.
    pub fn latest(&self, max_age_ms: i64) -> anyhow::Result<Option<Snapshot>> {
        let newest: Option<Ts> = self.conn.query_row("SELECT max(ts) FROM system", [], |r| r.get(0))?;
        let Some(ts) = newest else { return Ok(None) };
        let now = crate::model::now_ms();
        if now - ts > max_age_ms {
            return Ok(None);
        }
        let Some(mut s) = self.at(ts)? else { return Ok(None) };
        let prev: Option<Ts> = self.conn.query_row("SELECT max(ts) FROM system WHERE ts < ?1", [ts], |r| r.get(0))?;
        let since = prev.map_or(ts - KEYFRAME_MS, |p| p.max(ts - KEYFRAME_MS)) + 1;
        s.events = self.events(since, ts, &[], 1000)?;
        let recorded: Option<SnapMeta> = self.change_at(KIND_META, ts)?;
        let mut meta = recorded.unwrap_or_else(|| SnapMeta {
            version: env!("CARGO_PKG_VERSION").into(),
            profile: if s.units.is_empty() && s.kernel.is_none() { Profile::Desktop } else { Profile::Server },
            ..Default::default()
        });
        meta.source = "recorder".into();
        meta.age_ms = (now - ts).max(0);
        s.meta = Some(meta);
        Ok(Some(s))
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
///
/// `server_top` (server profile): also the union of the top N by cpu/mem/io and every unit's
/// main pid, and the per-sample cap grows to fit 3N so the configured N is honoured.
fn select_interesting<'a>(
    snap: &'a Snapshot,
    sticky: &HashSet<u32>,
    is_key: bool,
    server_top: Option<usize>,
) -> Vec<&'a Proc> {
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
    idx.iter().take(TOP_CPU).filter(|&&i| procs[i].cpu >= ENTER_CPU).for_each(|&i| take(i, &mut chosen));
    idx.sort_by(|&a, &b| procs[b].power_mw.total_cmp(&procs[a].power_mw));
    idx.iter().take(TOP_POWER).filter(|&&i| procs[i].power_mw >= ENTER_POWER_MW).for_each(|&i| take(i, &mut chosen));
    idx.sort_by(|&a, &b| procs[b].disk_write_bps.cmp(&procs[a].disk_write_bps));
    idx.iter()
        .take(TOP_DISK)
        .filter(|&&i| procs[i].disk_write_bps >= ENTER_DISK_BPS)
        .for_each(|&i| take(i, &mut chosen));
    idx.sort_by(|&a, &b| procs[b].mem.cmp(&procs[a].mem));
    idx.iter().take(TOP_MEM).for_each(|&i| take(i, &mut chosen));
    if let Some(n) = server_top {
        let pos: HashMap<u32, usize> = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
        for p in crate::server::top_procs(procs, &snap.units, n) {
            if let Some(&i) = pos.get(&p.pid) {
                take(i, &mut chosen);
            }
        }
    }
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
        // Linux: also keep processes in uninterruptible sleep (D, shown as "U") so `fat doctor`
        // can tell how long one has been stuck even when it uses no CPU.
        if port_pids.contains(&p.pid) || p.status == "T" || (cfg!(target_os = "linux") && p.status == "U") {
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

    chosen.truncate(MAX_RECORDED.max(server_top.map_or(0, |n| n.saturating_mul(3))));
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
        && let Some(home) = dirs::home_dir()
    {
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

/// Directory-size snapshots are taken this often by the recorder.
pub const DIR_SNAPSHOT_EVERY: Duration = Duration::from_secs(5 * 60);
/// Deeper than [`DIR_SNAPSHOT_DEPTH`], a dir/file is recorded only when it holds at least
/// 1/DIR_BIG_FRACTION of its volume's used space.
const DIR_SNAPSHOT_DEPTH: usize = 3;
const DIR_BIG_FRACTION: u64 = 100;
const DIR_MAX_DEPTH: usize = 24;

/// Storage side of the recorder: volumes every sample, directory sizes every
/// [`DIR_SNAPSHOT_EVERY`] from the background scanner (only once a scan has completed).
pub struct FsRecorder {
    vols: crate::fs::volumes::Volumes,
    scanner: Option<crate::fs::scan::Scanner>,
    last_dirs: Option<Instant>,
    /// Volumes of the last tick (for the fs_fill detector and the exporter).
    last: Vec<crate::fs::Volume>,
}

impl FsRecorder {
    /// `with_scanner` = also run the background scanner on "/" (low priority, TCC-safe) and
    /// record directory sizes. `FAT_NO_FS_SCAN=1` turns it off.
    pub fn new(with_scanner: bool) -> Self {
        let scanner = (with_scanner && std::env::var_os("FAT_NO_FS_SCAN").is_none())
            .then(|| {
                // Guard: a scanner failure must never take the recorder down.
                std::panic::catch_unwind(|| {
                    let s = crate::fs::scan::Scanner::new();
                    s.ensure("/", false);
                    s
                })
                .ok()
            })
            .flatten();
        FsRecorder { vols: crate::fs::volumes::Volumes::new(), scanner, last_dirs: None, last: Vec::new() }
    }

    /// Seed fill-rate windows from recorded history so ETAs are available right after start.
    pub fn seed_from(&mut self, hist: &History, now: Ts) {
        hist.seed_volumes(&mut self.vols, now);
    }

    /// Volumes sampled by the last [`FsRecorder::tick`].
    pub fn volumes(&self) -> &[crate::fs::Volume] {
        &self.last
    }

    pub fn tick(&mut self, hist: &mut History, ts: Ts) -> anyhow::Result<()> {
        self.last = self.vols.sample();
        let vols = &self.last;
        hist.record_volumes(ts, vols)?;
        if self.last_dirs.is_none_or(|t| t.elapsed() >= DIR_SNAPSHOT_EVERY)
            && let Some(sc) = &self.scanner
        {
            let sc = sc.clone();
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dir_snapshot(&sc, vols))) {
                Ok(Some(rows)) => {
                    self.last_dirs = Some(Instant::now());
                    if !rows.is_empty() {
                        hist.record_dir_sizes(ts, &rows)?;
                    }
                }
                Ok(None) => {} // no completed scan yet; try again next sample
                Err(_) => self.scanner = None,
            }
        }
        Ok(())
    }
}

/// Directory sizes worth recording from the scanner: everything to depth 3 below each
/// completed scan root, plus deeper entries holding >= 1% of their volume. None until some
/// scan root has completed. Bounded by [`DIR_MAX_ROWS`].
pub fn dir_snapshot(sc: &crate::fs::scan::Scanner, vols: &[crate::fs::Volume]) -> Option<Vec<(String, u64, u64)>> {
    let roots: Vec<String> = sc.progress().into_iter().filter(|p| p.completed_at > 0).map(|p| p.root).collect();
    if roots.is_empty() {
        return None;
    }
    let mut out: Vec<(String, u64, u64)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: std::collections::VecDeque<(String, usize)> = roots.into_iter().map(|r| (r, 0)).collect();
    while let Some((path, depth)) = queue.pop_front() {
        if out.len() >= DIR_MAX_ROWS {
            break;
        }
        let Some(l) = sc.list(&path) else { continue };
        // A dir being re-read (restat, rescan, a full pass) is `partial` but still shows its
        // previous complete numbers: record those. Leaving it out would record it as gone
        // and turn into a fake "freed" scan diff.
        let ok = |e: &crate::fs::DirEntry| !e.partial || sc.measured(&e.path);
        if seen.insert(l.dir.path.clone()) && ok(&l.dir) {
            out.push((l.dir.path.clone(), l.dir.size, l.dir.files));
        }
        if depth >= DIR_MAX_DEPTH {
            continue;
        }
        let big = crate::fs::volumes::volume_for(vols, &path).map_or(u64::MAX, |v| (v.used / DIR_BIG_FRACTION).max(1));
        for c in l.children {
            if !ok(&c) || c.mount_point || seen.contains(&c.path) {
                continue;
            }
            let shallow = depth < DIR_SNAPSHOT_DEPTH;
            if !(shallow || c.size >= big) {
                continue;
            }
            if c.is_dir {
                queue.push_back((c.path, depth + 1));
            } else if c.size >= big && seen.insert(c.path.clone()) {
                out.push((c.path, c.size, c.files));
            }
        }
    }
    out.truncate(DIR_MAX_ROWS);
    Some(out)
}

/// `fat record` with default options (profile from config/auto-detection, no export). Blocks.
/// Kept as the stable entry point for embedders; the CLI calls [`record_with`].
#[allow(dead_code)]
pub fn record_forever(cfg: &crate::config::Config) -> anyhow::Result<()> {
    record_with(cfg, &crate::server::export::RecordOpts::default())
}

/// Consecutive sampler panics after which server sampling is switched off for this run.
const MAX_SAMPLER_PANICS: u32 = 5;

/// `fat record` loop with server options. Desktop profile: exactly the classic recorder
/// (`interval_ms`, procs/system/ports/volumes, directory scanner). Server profile (auto-detected,
/// configured, or `--server`): additionally units, kernel and events via ServerSampler, the
/// recorder-side detectors ([`SpikeDetector`]), `record_interval_ms`, no directory scanner
/// unless `[server] fs_scan`, and the system-wide DB ([`SYSTEM_DB`]) when running as root
/// without a configured `history_path`. With `opts.export` (or `[server] export_enabled`) the
/// newest sample is also served as Prometheus metrics. Blocks until SIGINT/SIGTERM.
pub fn record_with(cfg: &crate::config::Config, opts: &crate::server::export::RecordOpts) -> anyhow::Result<()> {
    use crate::server::{LatestSnapshot, ServerSampler, export};
    let profile = if opts.server { Profile::Server } else { Profile::detect(&cfg.server) };
    let server = profile == Profile::Server;
    let interval =
        Duration::from_millis(if server { cfg.server.record_interval_ms } else { cfg.interval_ms }.max(1000));
    let keep_days = cfg.history_days.max(1);
    let configured = cfg.history_path.as_deref().filter(|p| !p.is_empty()).map(str::to_string);
    let path = configured.or_else(|| {
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        let dir = Path::new(SYSTEM_DB).parent()?;
        (server && cfg!(target_os = "linux") && root && std::fs::create_dir_all(dir).is_ok())
            .then(|| SYSTEM_DB.to_string())
    });
    let mut hist = History::open_recorder(path.as_deref(), true)?;
    hist.set_server_limits(&cfg.server);
    install_stop_handlers();
    STOP.store(false, Ordering::SeqCst);

    let latest: LatestSnapshot = Default::default();
    let export_addr =
        opts.export.or_else(|| cfg.server.export_enabled.then(|| cfg.server.export_listen.parse().ok()).flatten());
    if let Some(addr) = export_addr {
        if !addr.ip().is_loopback() {
            eprintln!(
                "fat record: WARNING: metrics on {addr} are reachable from other hosts (process names, units, \
                 disk and mount names). Bind 127.0.0.1 unless that is intended."
            );
        }
        let bound = export::serve(addr, latest.clone())?;
        println!("fat record: Prometheus metrics on http://{bound}/metrics");
    }

    let pruned = hist.prune(keep_days).unwrap_or(0);
    println!(
        "fat record: {} profile, writing to {} every {}ms, keeping {}d{} (Ctrl-C to stop)",
        profile.as_str(),
        hist.path().display(),
        interval.as_millis(),
        keep_days,
        if pruned > 0 { format!(", pruned {pruned} old samples") } else { String::new() }
    );

    let mut collector = crate::collect::Collector::new();
    let mut fsrec = FsRecorder::new(if server { cfg.server.fs_scan } else { true });
    fsrec.seed_from(&hist, crate::model::now_ms());
    let mut sampler = server.then(|| ServerSampler::new(&cfg.server));
    let mut detector = server.then(|| SpikeDetector::new(&cfg.server));
    let mut sampler_panics: u32 = 0;
    let mut kmsg_imported = !(server && cfg.server.kmsg);
    let mut last_prune = Instant::now();
    let mut recorded: u64 = 0;
    let mut errors: u64 = 0;
    let mut waiting = false;
    // FAT_RECORD_PROFILE=1: print the average wall time of each phase every 60 samples
    // (sizing the daemon on a new kind of host without a profiler).
    let mut prof = std::env::var_os("FAT_RECORD_PROFILE").map(|_| PhaseProfile::default());
    let report = |what: &str, e: &anyhow::Error, errors: &mut u64| {
        *errors += 1;
        // Don't flood the terminal/journal if the disk is full or the DB is locked.
        if *errors <= 5 || errors.is_multiple_of(100) {
            eprintln!("fat record: {what} failed ({errors} total): {e:#}");
        }
    };
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
        if !kmsg_imported {
            kmsg_imported = true;
            match import_kmsg_backlog(&mut hist) {
                Ok(n) if n > 0 => println!("fat record: imported {n} kernel log events"),
                Ok(_) => {}
                Err(e) => eprintln!("fat record: kernel log not imported: {e:#}"),
            }
        }
        let t_collect = Instant::now();
        let mut snap = collector.sample();
        let t_server = Instant::now();
        if let Some(s) = sampler.as_mut() {
            let filled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.fill(&mut snap)));
            if filled.is_ok() {
                sampler_panics = 0;
            } else {
                sampler_panics += 1;
                eprintln!("fat record: server sampler failed ({sampler_panics} in a row)");
                // Start over with fresh state; give up on server data after repeated failures
                // (the classic recorder keeps running either way).
                sampler = (sampler_panics < MAX_SAMPLER_PANICS).then(|| ServerSampler::new(&cfg.server));
            }
        }
        let t_fs = Instant::now();
        if let Err(e) = fsrec.tick(&mut hist, snap.ts) {
            report("storage write", &e, &mut errors);
        }
        let t_detect = Instant::now();
        if let Some(d) = detector.as_mut() {
            let mut ev = std::mem::take(&mut snap.events);
            ev.extend(d.detect(&snap, fsrec.volumes()));
            snap.events = d.filter(ev);
        }
        let t_write = Instant::now();
        match hist.record(&snap).and_then(|_| hist.record_server(&snap)) {
            Ok(()) => recorded += 1,
            Err(e) => report("write", &e, &mut errors),
        }
        if let Some(p) = prof.as_mut() {
            p.add([t_server - t_collect, t_fs - t_server, t_detect - t_fs, t_write - t_detect, t_write.elapsed()]);
        }
        if export_addr.is_some() {
            export::note_sample(&snap, fsrec.volumes());
            if let Ok(mut w) = latest.write() {
                *w = Some(std::sync::Arc::new(snap));
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

/// Average wall time per recorder phase (FAT_RECORD_PROFILE=1).
#[derive(Default)]
struct PhaseProfile {
    sum: [Duration; 5],
    n: u32,
}

impl PhaseProfile {
    fn add(&mut self, d: [Duration; 5]) {
        for (s, d) in self.sum.iter_mut().zip(d) {
            *s += d;
        }
        self.n += 1;
        if self.n == 60 {
            let avg = |i: usize| self.sum[i] / self.n;
            eprintln!(
                "fat record: avg per sample over 60: collect {:?}, server {:?}, volumes {:?}, detect {:?}, write {:?}",
                avg(0),
                avg(1),
                avg(2),
                avg(3),
                avg(4)
            );
            *self = PhaseProfile::default();
        }
    }
}

/// Import kernel log events newer than the newest recorded one (the whole ring buffer on a
/// fresh DB), so OOM kills and I/O errors from before the daemon started are on the timeline.
/// Duplicates are skipped by the events table's (ts, kind, subject) key.
fn import_kmsg_backlog(hist: &mut History) -> anyhow::Result<usize> {
    let since: Option<Ts> =
        hist.conn.query_row("SELECT max(ts) FROM events WHERE source = 'kmsg'", [], |r| r.get(0))?;
    let ev = std::panic::catch_unwind(|| crate::server::kernel::read_kmsg_since(since))
        .map_err(|_| anyhow::anyhow!("kernel log reader panicked"))??;
    hist.record_events(&ev)
}

/// A live snapshot: two samples `gap` apart (rates need an interval), filled by ServerSampler
/// in the server profile (a failing sampler leaves units/kernel empty instead of failing).
/// Used when no recorder sample covers the moment asked about.
pub fn live_snapshot(cfg: &crate::config::Config, gap: Duration) -> Snapshot {
    let profile = Profile::detect(&cfg.server);
    let mut c = crate::collect::Collector::new();
    let mut first = c.sample();
    let mut sampler = (profile == Profile::Server).then(|| crate::server::ServerSampler::new(&cfg.server));
    let fill = |s: &mut Snapshot, sampler: &mut Option<crate::server::ServerSampler>| {
        if let Some(sm) = sampler.as_mut()
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sm.fill(s))).is_err()
        {
            *sampler = None;
        }
    };
    fill(&mut first, &mut sampler);
    std::thread::sleep(gap);
    let mut s = c.sample();
    fill(&mut s, &mut sampler);
    s.meta = Some(SnapMeta::live(profile));
    s
}

/// Trailing window of the per-unit spike detectors.
const SPIKE_WINDOW_MS: i64 = 60_000;

/// Recorder-side detectors that need state across samples: per-unit CPU and memory spikes,
/// disk latency (when the kernel sampler did not report it itself) and volumes filling up.
/// Also rate-limits "level" events per subject (`[server] spike_cooldown_s`).
pub struct SpikeDetector {
    cfg: ServerCfg,
    cpu: HashMap<String, std::collections::VecDeque<(Ts, f32)>>,
    mem: HashMap<String, std::collections::VecDeque<(Ts, u64)>>,
    /// Current fs_fill level per mount (events fire on entering or escalating).
    fs: HashMap<String, Severity>,
    /// Cooldown key -> (last recorded ts, severity).
    fired: HashMap<String, (Ts, Severity)>,
}

fn unit_subject(u: &Unit) -> String {
    let p = match u.kind {
        UnitKind::Container => "container",
        UnitKind::Pod => "pod",
        UnitKind::Systemd | UnitKind::Cgroup => "unit",
    };
    format!("{p}:{}", u.name)
}

fn fmt_b(b: u64) -> String {
    let f = b as f64;
    match b {
        0..=1023 => format!("{b} B"),
        1024..=1_048_575 => format!("{:.0} KiB", f / 1024.0),
        1_048_576..=1_073_741_823 => format!("{:.0} MiB", f / 1_048_576.0),
        _ => format!("{:.1} GiB", f / 1_073_741_824.0),
    }
}

fn fmt_dur(s: u64) -> String {
    match s {
        0..=119 => format!("{s}s"),
        120..=7199 => format!("{}m", s / 60),
        _ => format!("{:.1}h", s as f64 / 3600.0),
    }
}

/// Kinds that describe a persisting condition (subject to the cooldown) rather than a
/// transition (always recorded).
fn is_level_kind(k: EventKind) -> bool {
    matches!(
        k,
        EventKind::DiskLatencySpike
            | EventKind::Throttle
            | EventKind::PressureSpike
            | EventKind::Exhaustion
            | EventKind::ProcSpike
            | EventKind::FsFill
            | EventKind::ClockUnsynced
    )
}

impl SpikeDetector {
    pub fn new(cfg: &ServerCfg) -> SpikeDetector {
        SpikeDetector {
            cfg: cfg.clone(),
            cpu: HashMap::new(),
            mem: HashMap::new(),
            fs: HashMap::new(),
            fired: HashMap::new(),
        }
    }

    /// New events for this sample (not yet cooldown-filtered).
    pub fn detect(&mut self, snap: &Snapshot, vols: &[crate::fs::Volume]) -> Vec<Event> {
        let ts = snap.ts;
        let mut out = Vec::new();
        let ev = |kind, severity, subject: String, u: Option<&Unit>, detail: String, value: f64, metric: &str| {
            let mut extra = std::collections::BTreeMap::new();
            if !metric.is_empty() {
                extra.insert("metric".to_string(), metric.to_string());
            }
            Event {
                ts,
                kind,
                severity,
                subject,
                unit: u.map(|u| u.name.clone()),
                pid: u.and_then(|u| u.main_pid),
                detail,
                value: Some(value),
                source: "recorder".into(),
                extra,
            }
        };
        // ---- per-unit cpu / memory spikes, relative to host capacity
        let capacity = snap.system.cores.max(1) as f32 * 100.0;
        let cpu_thr = (self.cfg.spike_cpu_pct / 100.0 * capacity).max(50.0);
        let mem_thr = (self.cfg.spike_mem_pct.max(0.0) as f64 / 100.0 * snap.system.mem_total as f64) as u64;
        let mut seen: HashSet<String> = HashSet::with_capacity(snap.units.len());
        for u in &snap.units {
            let key = unit_subject(u);
            let w = self.cpu.entry(key.clone()).or_default();
            while w.front().is_some_and(|x| x.0 < ts - SPIKE_WINDOW_MS || x.0 >= ts) {
                w.pop_front();
            }
            if w.len() >= 3 {
                let med = median(w.iter().map(|x| x.1));
                if u.cpu - med >= cpu_thr {
                    out.push(ev(
                        EventKind::ProcSpike,
                        Severity::Warn,
                        key.clone(),
                        Some(u),
                        format!("{} CPU jumped to {:.0}% (median {:.0}% over the previous minute)", u.name, u.cpu, med),
                        u.cpu as f64,
                        "cpu",
                    ));
                }
            }
            w.push_back((ts, u.cpu));
            let m = self.mem.entry(key.clone()).or_default();
            while m.front().is_some_and(|x| x.0 < ts - SPIKE_WINDOW_MS || x.0 >= ts) {
                m.pop_front();
            }
            if mem_thr > 0
                && let Some(&(t0, low)) = m.iter().min_by_key(|x| x.1)
                && u.mem.saturating_sub(low) >= mem_thr
            {
                out.push(ev(
                    EventKind::ProcSpike,
                    Severity::Warn,
                    key.clone(),
                    Some(u),
                    format!(
                        "{} memory grew {} in {}s to {}",
                        u.name,
                        fmt_b(u.mem - low),
                        (ts - t0) / 1000,
                        fmt_b(u.mem)
                    ),
                    u.mem as f64,
                    "mem",
                ));
            }
            m.push_back((ts, u.mem));
            seen.insert(key);
        }
        self.cpu.retain(|k, _| seen.contains(k));
        self.mem.retain(|k, _| seen.contains(k));

        // ---- disk latency the kernel sampler did not already report
        if let Some(k) = &snap.kernel {
            let thr = self.cfg.disk_await_warn_ms.max(1.0);
            for d in &k.disks {
                let aw = d.r_await_ms.max(d.w_await_ms);
                let subject = format!("disk:{}", d.name);
                if aw >= thr
                    && !snap.events.iter().any(|e| e.kind == EventKind::DiskLatencySpike && e.subject == subject)
                {
                    let sev = if aw >= 5.0 * thr { Severity::Crit } else { Severity::Warn };
                    out.push(ev(
                        EventKind::DiskLatencySpike,
                        sev,
                        subject,
                        None,
                        format!(
                            "disk {} await {:.0} ms (read {:.0}, write {:.0}; threshold {:.0}), util {:.0}%, queue {:.1}",
                            d.name, aw, d.r_await_ms, d.w_await_ms, thr, d.util_pct, d.queue_depth
                        ),
                        aw as f64,
                        "",
                    ));
                }
            }
        }

        // ---- volumes filling: projected time to full, or nearly full
        let eta_warn = self.cfg.fs_fill_eta_s.max(1);
        let mut mounts: HashSet<&str> = HashSet::new();
        for v in vols.iter().filter(|v| !v.hidden && !v.read_only && v.used + v.avail > 0) {
            mounts.insert(&v.mount);
            let pct = v.used as f64 * 100.0 / (v.used + v.avail) as f64;
            let eta = v.eta_full_s;
            let level = if pct >= 95.0 || eta.is_some_and(|e| e < eta_warn / 6) {
                Some(Severity::Crit)
            } else if eta.is_some_and(|e| e < eta_warn) {
                Some(Severity::Warn)
            } else {
                None
            };
            let prev = self.fs.get(&v.mount).copied();
            match level {
                Some(l) if prev.is_none_or(|p| l > p) => {
                    let rate = v
                        .fill_bps
                        .filter(|r| *r > 0.0)
                        .map(|r| format!(", growing {}/s", fmt_b(r as u64)))
                        .unwrap_or_default();
                    let when = eta.map(|e| format!(", full in ~{}", fmt_dur(e))).unwrap_or_default();
                    out.push(ev(
                        EventKind::FsFill,
                        l,
                        format!("mount:{}", v.mount),
                        None,
                        format!("{} {:.0}% full ({} free){rate}{when}", v.mount, pct, fmt_b(v.avail)),
                        pct,
                        "",
                    ));
                    self.fs.insert(v.mount.clone(), l);
                }
                Some(_) => {}
                // Hysteresis: the condition clears only well below the thresholds.
                None if prev.is_some() && pct < 93.0 && eta.is_none_or(|e| e > eta_warn * 3 / 2) => {
                    self.fs.remove(&v.mount);
                }
                None => {}
            }
        }
        self.fs.retain(|m, _| mounts.contains(m.as_str()));
        out
    }

    /// Apply the per-subject cooldown to level events (an escalation in severity always
    /// passes); transitions pass unchanged. Returns events sorted by ts.
    pub fn filter(&mut self, events: Vec<Event>) -> Vec<Event> {
        let cool = self.cfg.spike_cooldown_s as i64 * 1000;
        let mut out = Vec::with_capacity(events.len());
        for e in events {
            if !is_level_kind(e.kind) {
                out.push(e);
                continue;
            }
            let key = format!(
                "{}|{}|{}",
                e.kind.as_str(),
                e.subject,
                e.extra.get("metric").map(String::as_str).unwrap_or("")
            );
            let pass = match self.fired.get(&key) {
                Some(&(t, sev)) => e.ts - t >= cool || e.ts < t || e.severity > sev,
                None => true,
            };
            if pass {
                self.fired.insert(key, (e.ts, e.severity));
                out.push(e);
            }
        }
        if let Some(newest) = out.iter().map(|e| e.ts).max() {
            self.fired.retain(|_, (t, _)| newest - *t < cool.max(1));
        }
        out.sort_by_key(|e| e.ts);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Proto;

    fn tmp_db(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
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
        let mut procs =
            vec![Proc { pid: 1, ppid: 0, name: "launchd".into(), status: "S".into(), ..Default::default() }];
        for pid in 2..=n {
            let busy = pid % 25 == 0;
            procs.push(Proc {
                pid,
                ppid: if pid % 7 == 0 { 1 } else { (pid / 7).max(1) },
                name: format!("proc{pid}"),
                cmd: format!("/usr/bin/proc{pid} --flag value"),
                exe: format!("/usr/bin/proc{pid}"),
                user: "me".into(),
                cpu: if busy {
                    (pid % 40) as f32 + 3.0 + rng.next() * 4.0
                } else if rng.next() < 0.02 {
                    rng.next() * 0.4
                } else {
                    0.0
                },
                mem: (pid as u64 * 1_000_000) + (rng.next() * 50_000.0) as u64,
                power_mw: if busy { pid as f32 + rng.next() * 30.0 } else { 0.0 },
                threads: 4,
                status: "S".into(),
                start_time: 1_700_000_000 + pid as u64,
                ..Default::default()
            });
        }
        // The "hog" whose cpu drives the system spike.
        procs.push(Proc {
            pid: 9999,
            ppid: 1,
            name: "hog".into(),
            cpu: cpu * 2.0 + 50.0,
            status: "R".into(),
            ..Default::default()
        });
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
            ..Default::default()
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
        // A process spawned concurrently by another test (lsof, ioreg, ...) briefly inherits
        // a's lock fd until its exec, so the lease can stay taken for a moment after the drop.
        let t = Instant::now();
        while !b.try_become_writer() && t.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(10));
        }
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
        if std::env::var_os("FAT_KEEP_DB").is_none() {
            cleanup(&path);
        } else {
            eprintln!("kept {}", path.display());
        }
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

    fn fsvol(mount: &str, used: u64, w: u64) -> crate::fs::Volume {
        crate::fs::Volume {
            mount: mount.into(),
            device: "/dev/disk3s5".into(),
            fstype: "apfs".into(),
            total: 1 << 40,
            used,
            avail: (1u64 << 40) - used,
            write_bps: w,
            ..Default::default()
        }
    }

    #[test]
    fn volumes_roundtrip_change_points_and_prune() {
        let path = tmp_db("vols");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let hidden = crate::fs::Volume { hidden: true, ..fsvol("/System/Volumes/Preboot", 5, 0) };
        // 2 s samples for 10 min, +768 KiB per sample (384 KiB/s): every other sample crosses
        // the 1 MiB delta.
        for i in 0..300i64 {
            let used = (100u64 << 30) + i as u64 * 768 * 1024;
            let vols = [fsvol("/data", used, 0), fsvol("/static", 7 << 30, 0), hidden.clone()];
            h.record_volumes(T0 + i * 2000, &vols).unwrap();
        }
        let n = |m: &str| -> i64 {
            h.conn
                .query_row(
                    "SELECT count(*) FROM volumes v JOIN volume_ids i ON i.id = v.vid WHERE i.mount = ?1",
                    [m],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(n("/System/Volumes/Preboot"), 0, "hidden volumes not recorded");
        // Unchanging volume: first row + one per VOLUME_EVERY_MS.
        assert_eq!(n("/static"), 10);
        assert!(n("/data") >= 145 && n("/data") <= 160, "{}", n("/data"));
        let s = h.volume_series("/data", T0, T0 + 299 * 2000).unwrap();
        assert_eq!(s.first().unwrap().0, T0);
        assert!(s.windows(2).all(|w| w[0].0 < w[1].0 && w[0].1 <= w[1].1));
        // Fill rate from the recorded change points.
        let pts: Vec<(Ts, u64)> = s.iter().map(|p| (p.0, p.1)).collect();
        let f = crate::fs::volumes::fill_rate(&pts).unwrap();
        assert!((f / 1024.0 - 384.0).abs() < 4.0, "fill {f}");
        // Carry: a window starting between rows gets the value in effect at `from`.
        let s = h.volume_series("/static", T0 + 61_000, T0 + 70_000).unwrap();
        assert_eq!(s, vec![(T0 + 61_000, 7 << 30, (1u64 << 40) - (7 << 30))]);
        // Far from any row: no carry.
        assert!(h.volume_series("/static", T0 + 10_000_000, T0 + 10_001_000).unwrap().is_empty());
        assert!(h.volume_series("/nope", T0, T0 + 1000).unwrap().is_empty());
        assert_eq!(h.volume_mounts().unwrap(), vec!["/data".to_string(), "/static".to_string()]);
        // Prune drops old volume rows.
        h.prune_before(T0 + 300_000).unwrap();
        assert!(h.volume_series("/data", T0, T0 + 299_999).unwrap().is_empty());
        assert!(!h.volume_series("/data", T0 + 300_000, T0 + 600_000).unwrap().is_empty());
        drop(h);
        cleanup(&path);
    }

    #[test]
    fn dir_sizes_roundtrip_delta_and_prune() {
        let path = tmp_db("dirs");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mb = 1u64 << 20;
        let snap = |users: u64, extra: bool| {
            let mut v = vec![
                ("/".to_string(), 500 * mb + users, 1000),
                ("/Users".to_string(), 100 * mb + users, 500),
                ("/Users/me".to_string(), 90 * mb + users, 400),
                ("/Library".to_string(), 300 * mb, 300),
                ("/Usersfoo".to_string(), 5 * mb, 1),
            ];
            if extra {
                v.push(("/Users/me/big.iso".to_string(), 40 * mb, 1));
            }
            v
        };
        let q = 15 * 60_000;
        h.record_dir_sizes(T0, &snap(0, false)).unwrap();
        h.record_dir_sizes(T0 + q, &snap(mb / 2, true)).unwrap(); // sub-threshold change + new path
        h.record_dir_sizes(T0 + 2 * q, &snap(10 * mb, false)).unwrap(); // big.iso gone
        let rows: i64 = h.conn.query_row("SELECT count(*) FROM fs_dirs", [], |r| r.get(0)).unwrap();
        // 5 key rows, +1 new, then 3 grown + 1 tombstone.
        assert_eq!(rows, 10);
        assert!(h.dir_sizes_near(T0 - 1, "/").unwrap().is_none());
        let (ts, v) = h.dir_sizes_near(T0 + q + 5, "/Users").unwrap().unwrap();
        assert_eq!(ts, T0 + q);
        assert_eq!(
            v,
            vec![
                ("/Users".to_string(), 100 * mb),
                ("/Users/me".to_string(), 90 * mb),
                ("/Users/me/big.iso".to_string(), 40 * mb)
            ],
            "sub-MiB changes are not rewritten; /Usersfoo is not under /Users"
        );
        let (_, v) = h.dir_sizes_near(T0 + 3 * q, "/Users/").unwrap().unwrap();
        assert_eq!(v.len(), 2, "tombstoned path omitted: {v:?}");
        assert_eq!(v[0].1, 110 * mb);
        let (_, all) = h.dir_sizes_near(T0 + 3 * q, "/").unwrap().unwrap();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].0, "/");
        // Prune keeps the key snapshot later deltas need.
        h.prune_before(T0 + q + 1).unwrap();
        let (_, v) = h.dir_sizes_near(T0 + 3 * q, "/").unwrap().unwrap();
        assert_eq!(v, all);
        // A new writer (lease takeover) starts with a fresh key snapshot.
        drop(h);
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        // (a concurrently spawned child may hold the old lock fd for a moment; see single_writer_lease)
        let t = Instant::now();
        while !h.try_become_writer() && t.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(10));
        }
        h.record_dir_sizes(T0 + 3 * q, &snap(10 * mb, false)).unwrap();
        let key: i64 = h.conn.query_row("SELECT key FROM fs_snaps WHERE ts = ?1", [T0 + 3 * q], |r| r.get(0)).unwrap();
        assert_eq!(key, 1);
        // Row cap.
        let many: Vec<(String, u64, u64)> =
            (0..DIR_MAX_ROWS as u64 + 50).map(|i| (format!("/d{i}"), i * mb, 1)).collect();
        h.record_dir_sizes(T0 + DIR_KEY_MS * 2, &many).unwrap();
        let (_, v) = h.dir_sizes_near(T0 + DIR_KEY_MS * 2, "/").unwrap().unwrap();
        assert_eq!(v.len(), DIR_MAX_ROWS);
        assert_eq!(v.last().unwrap().0, "/d50", "smallest dropped");
        drop(h);
        cleanup(&path);
    }

    #[test]
    fn proc_writes_integrates_disk_write() {
        let path = tmp_db("pwrites");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut rng = Rng(9);
        let mb = 1u64 << 20;
        for i in 0..150i64 {
            let mut s = synth(T0 + i * 2000, 40, 10.0, 1000.0, 1 << 30, &mut rng);
            // A low-cpu writer (would not be "interesting" without the disk-writer rule).
            s.procs.push(Proc {
                pid: 4242,
                ppid: 1,
                name: "writer".into(),
                disk_write_bps: 4 * mb,
                status: "S".into(),
                start_time: 5,
                ..Default::default()
            });
            // Writes only during the second half.
            if i >= 75 {
                s.procs.push(Proc {
                    pid: 4343,
                    ppid: 1,
                    name: "late".into(),
                    disk_write_bps: mb,
                    status: "S".into(),
                    start_time: 6,
                    ..Default::default()
                });
            }
            h.record(&s).unwrap();
        }
        let w = h.proc_writes(T0 + 100_000, T0 + 200_000).unwrap();
        let get = |pid: u32| w.iter().find(|e| e.0 == pid).cloned();
        let (_, name, b) = get(4242).unwrap();
        assert_eq!(name, "writer");
        assert_eq!(b, 100 * 4 * mb, "4 MiB/s over 100 s");
        let (_, _, late) = get(4343).unwrap();
        // first sample of "late" is at T0+150s; its rate covers (148 s, 150 s].
        assert_eq!(late, 52 * mb, "{late}");
        assert_eq!(w[0].0, 4242);
        // Gap (recorder off): no integration across it.
        let mut s = synth(T0 + 1_000_000, 40, 10.0, 1000.0, 1 << 30, &mut rng);
        s.procs.push(Proc {
            pid: 4242,
            ppid: 1,
            name: "writer".into(),
            disk_write_bps: 4 * mb,
            status: "S".into(),
            start_time: 5,
            ..Default::default()
        });
        h.record(&s).unwrap();
        let w = h.proc_writes(T0 + 298_000, T0 + 1_000_000).unwrap();
        assert!(w.is_empty(), "{w:?}");
        assert!(h.proc_writes(T0, T0).unwrap().is_empty());
        drop(h);
        cleanup(&path);
    }

    #[test]
    fn dir_snapshot_from_scanner_fixture() {
        use crate::fs::scan::{Options, Scanner};
        let root =
            std::env::current_exe().unwrap().parent().unwrap().join(format!("fs-hist-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let deep = root.join("a/b/c/d/e");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::create_dir_all(root.join("a/b/c/d/small")).unwrap();
        std::fs::create_dir_all(root.join("x/y")).unwrap();
        std::fs::write(deep.join("big.bin"), vec![1u8; 3 << 20]).unwrap();
        std::fs::write(root.join("a/b/c/d/small/s.txt"), b"hi").unwrap();
        std::fs::write(root.join("x/y/z.txt"), vec![2u8; 10_000]).unwrap();
        let sc = Scanner::with_options(Options {
            cache_path: None,
            threads: 2,
            background: false,
            protect: false,
            budget: 0.0,
            battery_check: false,
            keep_depth: u16::MAX,
            big_file: 1 << 20,
            ..Options::default()
        });
        let rp = root.to_str().unwrap().to_string();
        let vols = vec![crate::fs::Volume { mount: "/".into(), used: 100 << 20, total: 1 << 30, ..Default::default() }];
        assert!(dir_snapshot(&sc, &vols).is_none(), "nothing completed yet");
        sc.ensure(&rp, true);
        assert!(sc.scan_blocking(&rp, 20_000).is_some());
        eprintln!("progress {:?}", sc.progress());
        let rows = dir_snapshot(&sc, &vols).expect("completed scan");
        let paths: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
        let has = |p: &str| paths.contains(&format!("{rp}/{p}").as_str());
        assert!(paths.contains(&rp.as_str()), "{paths:?}");
        assert!(has("a") && has("a/b") && has("a/b/c") && has("x") && has("x/y"), "depth <= 3: {paths:?}");
        assert!(has("a/b/c/d") && has("a/b/c/d/e"), ">= 1% of volume below depth 3: {paths:?}");
        assert!(!has("a/b/c/d/small"), "small deep dir skipped: {paths:?}");
        let rootrow = rows.iter().find(|r| r.0 == rp).unwrap();
        assert!(rootrow.1 >= 3 << 20 && rootrow.2 >= 3, "{rootrow:?}");
        // Round-trip into history.
        let path = tmp_db("dirsnap");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        h.record_dir_sizes(T0, &rows).unwrap();
        let (_, back) = h.dir_sizes_near(T0, &format!("{rp}/a")).unwrap().unwrap();
        assert_eq!(back[0].0, format!("{rp}/a"));
        drop(h);
        cleanup(&path);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fs_recorder_volumes_only() {
        let path = tmp_db("fsrec");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut r = FsRecorder::new(false);
        let t = Instant::now();
        r.tick(&mut h, crate::model::now_ms()).unwrap();
        let first = t.elapsed();
        let t = Instant::now();
        for i in 1..=20 {
            r.tick(&mut h, crate::model::now_ms() + i).unwrap();
        }
        eprintln!("FsRecorder::tick first {first:?}, then avg {:?}", t.elapsed() / 20);
        let mounts = h.volume_mounts().unwrap();
        assert!(!mounts.is_empty());
        drop(h);
        cleanup(&path);
    }

    // ---- server mode (recorder-export) ----

    /// A server with `n_units` units (a few busy), kernel state with two disks, and `nprocs` procs.
    #[test]
    fn server_top_procs_are_recorded() {
        let procs: Vec<Proc> = (1..=400u32)
            .map(|i| Proc { pid: i, ppid: 0, cpu: 0.3, mem: i as u64 * 1_000_000, ..Default::default() })
            .collect();
        let snap = Snapshot {
            procs,
            units: vec![Unit { name: "idle.service".into(), main_pid: Some(7), ..Default::default() }],
            ..Default::default()
        };
        let none = HashSet::new();
        let desktop = select_interesting(&snap, &none, true, None);
        assert!(!desktop.iter().any(|p| p.pid == 7));
        let server = select_interesting(&snap, &none, true, Some(100));
        assert!(server.iter().any(|p| p.pid == 7), "unit main pid kept");
        assert!(server.iter().any(|p| p.pid == 301), "top 100 by mem kept");
        assert!(server.len() >= 100 && server.len() <= 300, "{}", server.len());
    }

    fn server_snap(ts: Ts, n_units: usize, nprocs: u32, rng: &mut Rng) -> Snapshot {
        let mut s = synth(ts, nprocs, 20.0, 0.0, 6 << 30, rng);
        s.system.mem_total = 16 << 30;
        s.units = (0..n_units)
            .map(|i| Unit {
                name: format!("svc{i}.service"),
                kind: if i % 10 == 9 { UnitKind::Container } else { UnitKind::Systemd },
                state: if i % 17 == 16 { "failed".into() } else { "active".into() },
                sub_state: "running".into(),
                description: format!("Service number {i}"),
                cgroup: format!("/system.slice/svc{i}.service"),
                main_pid: Some(1000 + i as u32),
                pids: 3,
                cpu: if i % 20 == 0 { 30.0 + rng.next() * 20.0 } else { 0.0 },
                mem: (50 << 20)
                    + (i as u64) * 1_000_000
                    + if i % 20 == 0 { (rng.next() * 4_000_000.0) as u64 } else { 0 },
                mem_limit: (i % 5 == 0).then_some(1 << 30),
                restarts: (i % 7) as u32,
                psi: (i % 3 == 0).then_some(Pressure { cpu_some: 0.0, ..Default::default() }),
                container: (i % 10 == 9).then(|| ContainerMeta {
                    id: format!("{i:012}"),
                    name: format!("svc{i}"),
                    runtime: "docker".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .collect();
        s.kernel = Some(Kernel {
            steal_pct: 0.5,
            iowait_pct: rng.next() * 3.0,
            procs_running: 2,
            procs_blocked: 0,
            pressure: Some(Pressure { cpu_some: 1.0, io_some: 2.0, ..Default::default() }),
            mem_available: 10 << 30,
            oom_kills_total: 1,
            fd_used: Some(3000),
            fd_max: Some(1 << 20),
            ephemeral_range: Some((32768, 60999)),
            ephemeral_used: Some(40),
            disks: vec![
                DiskStat {
                    name: "vda".into(),
                    util_pct: 3.0 + rng.next(),
                    w_await_ms: 1.5,
                    w_iops: 20.0,
                    w_bps: 400_000,
                    ..Default::default()
                },
                DiskStat { name: "vdb".into(), ..Default::default() },
            ],
            taint_flags: String::new(),
            notes: vec!["no conntrack module".into()],
            ..Default::default()
        });
        s.meta = Some(SnapMeta::live(Profile::Server));
        s
    }

    fn ev(ts: Ts, kind: EventKind, subject: &str) -> Event {
        Event {
            ts,
            kind,
            severity: Severity::Warn,
            subject: subject.into(),
            detail: format!("{} {subject}", kind.as_str()),
            source: "test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn server_record_roundtrip() {
        let path = tmp_db("srv");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut rng = Rng(5);
        let n = 120i64; // 4 minutes at 2 s: two server keyframes
        for i in 0..n {
            let ts = T0 + i * 2000;
            let mut s = server_snap(ts, 40, 80, &mut rng);
            if i >= 60 {
                // svc3 restarts and fails at 2 min; svc4 disappears.
                s.units[3].state = "failed".into();
                s.units[3].result = "exit-code".into();
                s.units[3].exit_code = Some(1);
                s.units[3].restarts = 9;
                s.units.retain(|u| u.name != "svc4.service");
            }
            if i == 61 {
                s.events = vec![
                    ev(ts, EventKind::UnitFailed, "unit:svc3.service"),
                    ev(ts, EventKind::UnitFailed, "unit:svc3.service"),
                ];
                let mut oom = ev(ts, EventKind::OomKill, "unit:svc5.service");
                oom.extra.insert("victim".into(), "worker".into());
                oom.pid = Some(4242);
                oom.value = Some(1.5e9);
                s.events.push(oom);
            }
            h.record(&s).unwrap();
            h.record_server(&s).unwrap();
        }
        // Units at a time before and after the change.
        let before = h.units_at(T0 + 30 * 2000).unwrap();
        assert_eq!(before.len(), 40);
        let u3 = before.iter().find(|u| u.name == "svc3.service").unwrap();
        assert_eq!((u3.state.as_str(), u3.restarts), ("active", 3));
        let u9 = before.iter().find(|u| u.name == "svc9.service").unwrap();
        assert_eq!(u9.kind, UnitKind::Container);
        assert_eq!(u9.container.as_ref().unwrap().runtime, "docker");
        assert_eq!(u9.description, "Service number 9");
        let after = h.units_at(T0 + 100 * 2000).unwrap();
        assert_eq!(after.len(), 39, "svc4 is gone");
        let u3 = after.iter().find(|u| u.name == "svc3.service").unwrap();
        assert_eq!(
            (u3.state.as_str(), u3.result.as_str(), u3.exit_code, u3.restarts),
            ("failed", "exit-code", Some(1), 9)
        );
        let u0 = after.iter().find(|u| u.name == "svc0.service").unwrap();
        assert!(u0.cpu >= 20.0 && u0.mem_limit == Some(1 << 30) && u0.psi.is_some());
        assert!(h.units_at(T0 - 10 * 60_000).unwrap().is_empty(), "nothing recorded then");

        // Series: change points with the restart visible, plus a "gone" point.
        let s3 = h.unit_series("svc3.service", T0 + 10_000, T0 + n * 2000).unwrap();
        assert_eq!(s3.first().unwrap().ts, T0 + 10_000, "value in effect at `from`");
        assert!(s3.iter().any(|p| p.state == "failed" && p.restarts == 9));
        assert!(s3.len() < 10, "idle unit is change-point encoded: {} points", s3.len());
        let s4 = h.unit_series("svc4.service", T0, T0 + n * 2000).unwrap();
        assert_eq!(s4.last().unwrap().state, "gone");
        assert!(h.unit_series("nope.service", T0, T0 + n * 2000).unwrap().is_empty());

        // Kernel through at(): scalars, slow parts, both disks (idle one reads zero).
        let snap = h.at(T0 + 50 * 2000).unwrap().unwrap();
        let k = snap.kernel.as_ref().unwrap();
        assert_eq!(k.fd_used, Some(3000));
        assert_eq!(k.ephemeral_range, Some((32768, 60999)));
        assert_eq!(k.notes, vec!["no conntrack module".to_string()]);
        assert_eq!(k.pressure.unwrap().io_some, 2.0);
        assert_eq!(k.disks.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["vda", "vdb"]);
        assert!(k.disks[0].w_bps == 400_000 && k.disks[1].w_bps == 0);
        assert_eq!(snap.units.len(), 40);

        // Events: dedup, kind filter, limit keeps the newest, count.
        let all = h.events(T0, T0 + n * 2000, &[], 100).unwrap();
        assert_eq!(all.len(), 2, "duplicate (ts, kind, subject) stored once");
        let oom = h.events(T0, T0 + n * 2000, &[EventKind::OomKill], 10).unwrap();
        assert_eq!(oom.len(), 1);
        assert_eq!(
            (oom[0].pid, oom[0].value, oom[0].extra.get("victim").map(String::as_str)),
            (Some(4242), Some(1.5e9), Some("worker"))
        );
        assert_eq!(h.event_count(EventKind::OomKill, T0).unwrap(), 1);
        assert_eq!(h.event_count(EventKind::OomKill, T0 + n * 2000).unwrap(), 0);
        let lim = h.events(T0, T0 + n * 2000, &[], 1).unwrap();
        assert_eq!(lim.len(), 1);
        assert_eq!(
            h.record_events(&[
                ev(T0 + 5, EventKind::KernelWarn, "kernel"),
                ev(T0 + 61 * 2000, EventKind::UnitFailed, "unit:svc3.service")
            ])
            .unwrap(),
            1
        );

        // Kernel series downsampled.
        let ks = h.kernel_series(T0, T0 + n * 2000, 10).unwrap();
        assert!(ks.len() <= 10 && ks.len() >= 9, "{}", ks.len());
        assert!(ks.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(ks[0].1.disks.iter().any(|d| d.name == "vda" && d.w_bps > 0));

        // Prune keeps what later samples need.
        let cutoff = T0 + 70 * 2000;
        h.prune_before(cutoff).unwrap();
        assert_eq!(h.units_at(cutoff + 2000).unwrap().len(), 39);
        assert!(h.events(T0, cutoff - 1, &[], 100).unwrap().is_empty());
        drop(h);
        cleanup(&path);
    }

    #[test]
    fn server_tables_migrate_into_existing_db() {
        let path = tmp_db("migrate");
        {
            // A database as written by the previous release: schema v2 without server tables.
            let c = Connection::open(&path).unwrap();
            c.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.execute_batch("PRAGMA user_version = 2;").unwrap();
            c.execute("INSERT INTO system (ts, cpu10, mem_used, power) VALUES (?1, 123, 456, 0)", [T0]).unwrap();
        }
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(h.read_system(T0).unwrap().unwrap().cpu, 12.3, "old data kept");
        let n: i64 = h
            .conn
            .query_row(
                &format!("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ({ALL_TABLES})"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, ALL_TABLES_N);
        let mut rng = Rng(1);
        let s = server_snap(T0 + 2000, 5, 10, &mut rng);
        h.record(&s).unwrap();
        h.record_server(&s).unwrap();
        assert_eq!(h.units_at(T0 + 2000).unwrap().len(), 5);
        drop(h);
        // A current DB opens without any write (works for readers without write access).
        let c = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let v: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        drop(c);
        cleanup(&path);
    }

    #[test]
    fn desktop_snapshots_write_no_server_rows() {
        let path = tmp_db("desk");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut rng = Rng(2);
        let s = synth(T0, 20, 5.0, 100.0, 1 << 30, &mut rng);
        h.record(&s).unwrap();
        h.record_server(&s).unwrap();
        let rows: i64 = h.conn.query_row("SELECT (SELECT count(*) FROM units) + (SELECT count(*) FROM kernel) + (SELECT count(*) FROM server_keys)", [], |r| r.get(0)).unwrap();
        assert_eq!(rows, 0);
        let at = h.at(T0).unwrap().unwrap();
        assert!(at.units.is_empty() && at.kernel.is_none());
        let v = serde_json::to_value(&at).unwrap();
        assert!(v.get("units").is_none() && v.get("kernel").is_none(), "desktop JSON unchanged");
        drop(h);
        cleanup(&path);
    }

    #[test]
    fn read_only_open_and_latest() {
        let path = tmp_db("ro");
        let p = path.to_str().unwrap();
        assert!(History::open_read_only(Some(p)).is_err(), "no file: no creation");
        assert!(!path.exists());
        let mut h = History::open(Some(p)).unwrap();
        let mut rng = Rng(9);
        let now = crate::model::now_ms();
        for i in 0..5 {
            let mut s = server_snap(now - (4 - i) * 2000, 10, 30, &mut rng);
            if i == 4 {
                s.events = vec![ev(s.ts, EventKind::UnitRestart, "unit:svc1.service")];
            }
            if i == 3 {
                s.events = vec![ev(s.ts, EventKind::UnitStart, "unit:svc2.service")];
            }
            h.record(&s).unwrap();
            h.record_server(&s).unwrap();
        }
        let r = History::open_read_only(Some(p)).unwrap();
        let mut r2 = History::open_read_only(Some(p)).unwrap();
        assert!(!r2.try_become_writer(), "read-only never takes the lease");
        let l = r.latest(60_000).unwrap().expect("fresh sample");
        assert_eq!(l.ts, now);
        let m = l.meta.as_ref().unwrap();
        assert_eq!((m.source.as_str(), m.profile), ("recorder", Profile::Server));
        assert!(m.age_ms >= 0 && m.age_ms < 60_000);
        assert_eq!(l.units.len(), 10);
        assert!(l.kernel.is_some() && !l.procs.is_empty());
        assert_eq!(l.events.len(), 1, "only the last interval's events");
        assert_eq!(l.events[0].kind, EventKind::UnitRestart);
        assert!(r.latest(-1).unwrap().is_none(), "too old");
        drop((h, r, r2));
        cleanup(&path);
    }

    /// `fat snapshot --fast` budget: open read-only + latest + JSON for a server with 600 procs
    /// and 150 units must stay far below a live sample (< 50 ms release; debug is slower).
    #[test]
    fn latest_is_fast() {
        let path = tmp_db("fast");
        let p = path.to_str().unwrap();
        let mut h = History::open(Some(p)).unwrap();
        let mut rng = Rng(21);
        let now = crate::model::now_ms();
        let n = 150i64; // 5 min at 2 s: replay crosses a keyframe
        for i in 0..n {
            let s = server_snap(now - (n - 1 - i) * 2000, 150, 600, &mut rng);
            h.record(&s).unwrap();
            h.record_server(&s).unwrap();
        }
        drop(h);
        let mut best = Duration::MAX;
        for _ in 0..5 {
            let t = Instant::now();
            let r = History::open_read_only(Some(p)).unwrap();
            let s = r.latest(600_000).unwrap().unwrap();
            let json = serde_json::to_string(&s).unwrap();
            best = best.min(t.elapsed());
            assert!(json.len() > 10_000 && s.units.len() == 150);
        }
        let budget = if cfg!(debug_assertions) { Duration::from_millis(400) } else { Duration::from_millis(50) };
        eprintln!("latest(): open + query + json best of 5: {best:?}");
        assert!(best < budget, "{best:?}");
        cleanup(&path);
    }

    /// Server tables' disk cost: 100 units (5 busy), kernel + 2 disks, 300 procs, at 5 s.
    #[test]
    fn server_bytes_per_day() {
        let path = tmp_db("srvsize");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        let mut rng = Rng(77);
        let n = 360i64; // 30 min at 5 s
        let mut base = 0;
        for i in 0..n {
            if i == 60 {
                h.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
                base = std::fs::metadata(&path).unwrap().len();
            }
            let s = server_snap(T0 + i * 5000, 100, 300, &mut rng);
            h.record(&s).unwrap();
            h.record_server(&s).unwrap();
        }
        h.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        let bytes = std::fs::metadata(&path).unwrap().len() - base;
        let per_day = bytes as f64 / (n - 60) as f64 * 17_280.0 / 1e6;
        let unit_rows: i64 = h.conn.query_row("SELECT count(*) FROM units", [], |r| r.get(0)).unwrap();
        eprintln!("server profile: {per_day:.1} MB/day at 5 s ({unit_rows} unit rows for {n} samples x 100 units)");
        assert!(unit_rows < n * 100 / 4, "units are change-point encoded: {unit_rows}");
        assert!(per_day < 40.0, "{per_day:.1} MB/day");
        drop(h);
        cleanup(&path);
    }

    #[test]
    fn caps_bound_units_and_events() {
        let path = tmp_db("caps");
        let mut h = History::open(Some(path.to_str().unwrap())).unwrap();
        h.set_server_limits(&ServerCfg { max_units: 10, max_events_per_sample: 5, ..Default::default() });
        let mut rng = Rng(4);
        let mut s = server_snap(T0, 50, 10, &mut rng);
        s.events = (0..40).map(|i| ev(T0 + i, EventKind::KernelWarn, &format!("pid:{i}"))).collect();
        s.events[7].severity = Severity::Crit;
        h.record(&s).unwrap();
        h.record_server(&s).unwrap();
        let units = h.units_at(T0).unwrap();
        assert_eq!(units.len(), 10);
        assert!(units.iter().filter(|u| u.state == "failed").count() >= 2, "failed units kept first");
        let evs = h.events(T0, T0 + 100, &[], 100).unwrap();
        assert_eq!(evs.len(), 5);
        assert!(evs.iter().any(|e| e.severity == Severity::Crit && e.subject == "pid:7"));
        assert!(evs.iter().any(|e| e.kind == EventKind::Other && e.detail.contains("36 of 40")));
        drop(h);
        cleanup(&path);
    }

    fn unit(name: &str, cpu: f32, mem: u64) -> Unit {
        Unit { name: name.into(), state: "active".into(), cpu, mem, main_pid: Some(7), ..Default::default() }
    }

    #[test]
    fn spike_detector() {
        let cfg = ServerCfg::default();
        let mut d = SpikeDetector::new(&cfg);
        let base = |ts: Ts, units: Vec<Unit>| Snapshot {
            ts,
            system: System { cores: 4, mem_total: 8 << 30, ..Default::default() },
            units,
            ..Default::default()
        };
        // Quiet minute, then a CPU jump of 2 cores (threshold: 25% of 400 = 100) and +1 GiB (10% of 8 GiB = 819 MiB).
        for i in 0..6 {
            assert!(d.detect(&base(T0 + i * 5000, vec![unit("a.service", 5.0, 1 << 30)]), &[]).is_empty());
        }
        let e = d.detect(&base(T0 + 30_000, vec![unit("a.service", 210.0, 2 << 30)]), &[]);
        assert_eq!(e.len(), 2, "{e:?}");
        assert!(e.iter().all(|e| e.kind == EventKind::ProcSpike && e.subject == "unit:a.service" && e.pid == Some(7)));
        assert!(
            e.iter().any(|e| e.extra.get("metric").map(String::as_str) == Some("cpu") && e.detail.contains("210%"))
        );
        assert!(
            e.iter().any(|e| e.extra.get("metric").map(String::as_str) == Some("mem") && e.detail.contains("1.0 GiB"))
        );
        // Cooldown: a repeat right after is dropped, a different metric/subject is not.
        let f = d.filter(e.clone());
        assert_eq!(f.len(), 2);
        let mut again = e.clone();
        for x in again.iter_mut() {
            x.ts += 5000;
        }
        assert!(d.filter(again.clone()).is_empty());
        let mut escalated = again[0].clone();
        escalated.severity = Severity::Crit;
        assert_eq!(d.filter(vec![escalated]).len(), 1, "escalation passes the cooldown");
        let mut later = again[1].clone();
        later.ts += cfg.spike_cooldown_s as i64 * 1000;
        assert_eq!(d.filter(vec![later]).len(), 1);
        let transition = ev(T0 + 40_000, EventKind::UnitRestart, "unit:a.service");
        assert_eq!(d.filter(vec![transition.clone(), transition]).len(), 2, "transitions never suppressed");

        // Disk latency: reported unless the kernel sampler already did.
        let mut s = base(T0 + 50_000, vec![]);
        s.kernel = Some(Kernel {
            disks: vec![DiskStat { name: "sdb".into(), w_await_ms: 700.0, ..Default::default() }],
            ..Default::default()
        });
        let e = d.detect(&s, &[]);
        assert_eq!((e.len(), e[0].kind, e[0].severity), (1, EventKind::DiskLatencySpike, Severity::Crit));
        s.events = vec![ev(s.ts, EventKind::DiskLatencySpike, "disk:sdb")];
        assert!(d.detect(&s, &[]).is_empty());

        // Volumes: fires on entering a level and on escalation only.
        let vol = |used: u64, avail: u64, eta: Option<u64>| crate::fs::Volume {
            mount: "/data".into(),
            total: used + avail,
            used,
            avail,
            fill_bps: Some(1e6),
            eta_full_s: eta,
            ..Default::default()
        };
        let s = base(T0 + 60_000, vec![]);
        assert!(d.detect(&s, &[vol(50, 50, None)]).is_empty());
        let e = d.detect(&s, &[vol(50, 50, Some(3 * 3600))]);
        assert_eq!(
            (e.len(), e[0].kind, e[0].severity, e[0].subject.as_str()),
            (1, EventKind::FsFill, Severity::Warn, "mount:/data")
        );
        assert!(d.detect(&s, &[vol(51, 49, Some(3 * 3600))]).is_empty(), "same level: no repeat");
        let e = d.detect(&s, &[vol(96, 4, Some(600))]);
        assert_eq!(e[0].severity, Severity::Crit);
        assert!(d.detect(&s, &[vol(50, 50, None)]).is_empty(), "clearing is silent");
        assert_eq!(d.detect(&s, &[vol(50, 50, Some(3600))]).len(), 1, "re-arms after clearing");
    }

    /// CPU per recorder component on a real host (self + children, via getrusage):
    /// `FAT_SAMPLES=60 cargo test --release --bin fat history::tests::real_server_cpu -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_server_cpu() {
        fn cpu() -> (Duration, Duration) {
            let get = |who| {
                // SAFETY: getrusage writes into a zeroed rusage we own.
                let mut r: libc::rusage = unsafe { std::mem::zeroed() };
                unsafe { libc::getrusage(who, &mut r) };
                let tv =
                    |t: libc::timeval| Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64);
                tv(r.ru_utime) + tv(r.ru_stime)
            };
            (get(libc::RUSAGE_SELF), get(libc::RUSAGE_CHILDREN))
        }
        let n: u32 = std::env::var("FAT_SAMPLES").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
        let cfg = ServerCfg::default();
        let mut c = crate::collect::Collector::new();
        let mut sv = crate::server::services::Services::new(&cfg);
        let mut k = crate::server::kernel::KernelSampler::new(&cfg);
        let mut acc = [(Duration::ZERO, Duration::ZERO); 3];
        let mut units = 0;
        for _ in 0..n {
            let mut step = |i: usize, f: &mut dyn FnMut()| {
                let a = cpu();
                f();
                let b = cpu();
                acc[i].0 += b.0 - a.0;
                acc[i].1 += b.1 - a.1;
            };
            let mut snap = Snapshot::default();
            step(0, &mut || snap = c.sample());
            step(1, &mut || snap.units = sv.sample(&snap.procs));
            step(2, &mut || snap.kernel = k.sample(&snap.procs, &snap.units));
            units = snap.units.len();
            std::thread::sleep(Duration::from_millis(200));
        }
        for (i, name) in ["collect", "services", "kernel"].iter().enumerate() {
            eprintln!("{name}: self {:?}/sample, children {:?}/sample", acc[i].0 / n, acc[i].1 / n);
        }
        eprintln!("({units} units)");
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

    /// A DB of another schema version (another fat on PATH, a rolling upgrade) must never be
    /// dropped by a reader: open and open_read_only refuse; only the recorder moves it aside,
    /// keeping its data, and only when nobody else holds the writer lease.
    #[test]
    fn foreign_schema_is_never_dropped() {
        let path = tmp_db("foreign");
        let p = path.to_str().unwrap();
        let now = crate::model::now_ms();
        {
            let mut h = History::open(Some(p)).unwrap();
            let mut rng = Rng(3);
            h.record(&server_snap(now, 3, 5, &mut rng)).unwrap();
            h.conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION + 1)).unwrap();
        }
        let rows = |p: &Path| -> i64 {
            let c = Connection::open(p).unwrap();
            c.query_row("SELECT count(*) FROM system", [], |r| r.get(0)).unwrap()
        };
        assert!(History::open(Some(p)).is_err(), "plain open refuses a foreign schema");
        assert!(History::open_read_only(Some(p)).is_err());
        assert!(History::open_recorder(Some(p), false).is_err());
        assert_eq!(rows(&path), 1, "data untouched");
        // A live writer (lease held) blocks the reset too.
        let lock =
            std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(writer_lock_path(&path)).unwrap();
        {
            use std::os::fd::AsRawFd;
            // SAFETY: flock on a valid fd we own.
            assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        }
        assert!(History::open_recorder(Some(p), true).is_err());
        drop(lock);
        let h = History::open_recorder(Some(p), true).unwrap();
        let kept = PathBuf::from(format!("{}.schema-v{}", p, SCHEMA_VERSION + 1));
        assert!(kept.exists(), "old DB kept aside");
        assert_eq!(rows(&kept), 1, "old data preserved");
        assert_eq!(h.conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), SCHEMA_VERSION);
        drop(h);
        assert!(History::open_read_only(Some(p)).is_ok());
        cleanup(&path);
        cleanup(&kept);
        let _ = std::fs::remove_file(writer_lock_path(&path));
    }
}
