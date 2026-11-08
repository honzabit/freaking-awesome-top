//! Always-on flight recorder (SQLite). OWNER: history agent.
use crate::model::{Snapshot, Ts};
use serde::{Deserialize, Serialize};

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

pub struct History {}

impl History {
    /// Open (create) the DB. None path -> default under dirs::data_local_dir()/fat/history.db.
    pub fn open(_path: Option<&str>) -> anyhow::Result<History> { todo!() }
    pub fn record(&mut self, _snap: &Snapshot) -> anyhow::Result<()> { todo!() }
    /// Snapshot recorded nearest to ts (procs may be a reduced set).
    pub fn at(&self, _ts: Ts) -> anyhow::Result<Option<Snapshot>> { todo!() }
    /// Downsampled system timeline in [from, to], at most `max_points` points.
    pub fn timeline(&self, _from: Ts, _to: Ts, _max_points: usize) -> anyhow::Result<Vec<Point>> { todo!() }
    /// Per-process series for one pid (ts, cpu, mem).
    pub fn proc_series(&self, _pid: u32, _from: Ts, _to: Ts) -> anyhow::Result<Vec<(Ts, f32, u64)>> { todo!() }
    /// Times where system cpu/power/mem jumped notably in [from, to].
    pub fn spikes(&self, _from: Ts, _to: Ts) -> anyhow::Result<Vec<Point>> { todo!() }
    pub fn prune(&mut self, _keep_days: u32) -> anyhow::Result<usize> { todo!() }
    /// (oldest, newest) recorded ts.
    pub fn bounds(&self) -> anyhow::Result<Option<(Ts, Ts)>> { todo!() }
}

/// `fat record`: sample forever, writing to history. Blocks.
pub fn record_forever(_cfg: &crate::config::Config) -> anyhow::Result<()> { todo!() }
