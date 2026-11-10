//! Storage: where space goes, and what is eating it right now.
//!
//! CONTRACT (shared by the fs agents and every consumer: tui, cli, mcp, blame, history).
//! Types and function signatures in this file are fixed; implementations live in the
//! submodules. Add optional fields only with `#[serde(default)]`.
//!
//! Three questions, three engines:
//! - "What eats my storage?"       -> [`scan`]: background du over a volume tree, cached.
//! - "What is filling it so fast?" -> [`growth`]: per-volume fill rate + which paths grew
//!   in a window (FSEvents replay on macOS, fanotify/inotify on Linux, process-write
//!   attribution through open files, and scan-to-scan diffs), each tagged with its evidence.
//! - "Which disk/volume?"          -> [`volumes`]: mounts, capacity, purgeable, per-device I/O,
//!   deleted-but-still-open files.
//!
//! Everything here is READ-ONLY. fat never deletes files.

pub mod growth;
pub mod scan;
pub mod tcc;
pub mod volumes;

use crate::model::Ts;
use serde::{Deserialize, Serialize};

/// A mounted filesystem.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Volume {
    /// Mount point, e.g. "/" or "/System/Volumes/Data" or "/home".
    pub mount: String,
    /// Device, e.g. "/dev/disk3s5", "/dev/nvme0n1p2", "overlay".
    pub device: String,
    /// "apfs" | "ext4" | "xfs" | "btrfs" | "nfs" | "tmpfs" ...
    pub fstype: String,
    pub total: u64,
    /// Bytes in use (total - free).
    pub used: u64,
    /// Bytes available to an unprivileged user.
    pub avail: u64,
    /// macOS: space the OS can reclaim on demand (caches, local snapshots). None if unknown.
    #[serde(default)]
    pub purgeable: Option<u64>,
    pub inodes_total: u64,
    pub inodes_used: u64,
    pub read_only: bool,
    /// Network / FUSE / removable: never scanned unless the user drills in explicitly.
    pub remote: bool,
    /// The volume holding user data ("/" on Linux, "/System/Volumes/Data" on macOS).
    pub primary: bool,
    /// Device I/O since last sample, bytes/sec (0 when unknown).
    pub read_bps: u64,
    pub write_bps: u64,
    /// Bytes/sec change of `used` over the recent window (positive = filling). None until 2 samples.
    #[serde(default)]
    pub fill_bps: Option<f64>,
    /// Seconds until `avail` hits 0 at `fill_bps`, when filling. None otherwise.
    #[serde(default)]
    pub eta_full_s: Option<u64>,
    /// Noise a default listing leaves out (APFS system siblings like Preboot/Update, duplicate
    /// bind mounts of one device, container-runtime internals). Only set with `Volumes::with_all(true)`.
    #[serde(default)]
    pub hidden: bool,
    /// Caveats about these numbers, e.g. "I/O is for physical disk disk0 (shared by its volumes)".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// One directory (or file) node in a scanned tree.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DirEntry {
    /// Absolute path.
    pub path: String,
    /// Last path component ("/" for the root).
    pub name: String,
    pub is_dir: bool,
    /// Allocated bytes on disk (st_blocks * 512), hardlinks counted once, recursive for dirs.
    pub size: u64,
    /// Apparent size (st_size sum), recursive.
    pub apparent: u64,
    /// Files below (recursive). 1 for a file.
    pub files: u64,
    /// Newest mtime below, epoch seconds.
    pub newest_mtime: i64,
    /// Subdirectories we could not read (permission denied / TCC protected). Their size is unknown.
    pub denied: u32,
    /// Another filesystem is mounted here (not descended). `size` is 0.
    pub mount_point: bool,
    /// Still being scanned: numbers are a lower bound.
    pub partial: bool,
    /// When this node's numbers were measured (epoch ms).
    pub scanned_at: Ts,
}

/// Children of one directory, as the TUI/CLI/MCP shows them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Listing {
    pub dir: DirEntry,
    /// Sorted by size desc.
    pub children: Vec<DirEntry>,
    /// Scan progress for the tree containing `dir`.
    pub progress: ScanProgress,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScanProgress {
    pub root: String,
    pub running: bool,
    pub files_seen: u64,
    pub bytes_seen: u64,
    /// Rough completion 0..1 (bytes_seen / volume used), None when unknown.
    #[serde(default)]
    pub fraction: Option<f32>,
    pub started_at: Ts,
    /// When the last complete scan of this root finished (0 = never).
    pub completed_at: Ts,
    pub errors: u64,
}

/// Where a growth number came from. Shown to the user so they know how much to trust it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// macOS FSEvents journal replay (exact paths, retroactive).
    Fsevents,
    /// Linux fanotify / inotify watch (exact paths, only since fat started watching).
    Watch,
    /// Files a writing process holds open, sized now vs earlier (attributed).
    OpenFiles,
    /// Difference between two scans of the tree (exact, coarse in time).
    ScanDiff,
    /// mtime within the window, current size (upper bound of growth).
    Mtime,
}

/// A path that grew (or shrank) during the window.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Grower {
    pub path: String,
    pub is_dir: bool,
    /// Net allocated-bytes change over the window (negative = freed).
    pub delta: i64,
    /// Current allocated size.
    pub size: u64,
    /// Files created / modified in the window under this path (0 when unknown).
    pub files_touched: u64,
    /// Processes seen writing here: (pid, name, write bytes/sec at last sample).
    pub writers: Vec<(u32, String, u64)>,
    pub evidence: Vec<Evidence>,
    /// "other under `path`": `delta` is only what the growers listed below `path` leave
    /// unexplained (a parent never repeats its listed children's bytes).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub other: bool,
}

/// Answer to "what is eating my space in the last N minutes?".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Growth {
    pub from: Ts,
    pub to: Ts,
    /// Per-volume used delta in the window.
    pub volumes: Vec<(String, i64)>,
    /// Paths with the largest |delta|, as specific as the evidence allows and disjoint: a
    /// parent appears only as "other under X" (`Grower::other`) carrying what its listed
    /// children leave unexplained. Sorted by delta desc.
    pub growers: Vec<Grower>,
    /// Top writing processes in the window: (pid, name, bytes written in window).
    pub writers: Vec<(u32, String, u64)>,
    /// Space held by deleted-but-open files: (pid, name, path, bytes).
    pub deleted_open: Vec<(u32, String, String, u64)>,
    /// Human notes: what evidence was unavailable and why (e.g. "fanotify needs root").
    pub notes: Vec<String>,
    /// The directory the report covers ("/" for the whole machine); empty in older reports.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub root: String,
}

/// Default growth window.
pub const DEFAULT_WINDOW_MS: i64 = 10 * 60 * 1000;
