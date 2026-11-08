//! Per-process network rates via nettop in a background thread. OWNER: ports-net agent.
use std::collections::HashMap;

pub struct NetSampler {}

impl NetSampler {
    /// Spawn background sampler. Must never block the caller; degrade to empty map if nettop missing.
    pub fn start() -> Self { todo!() }
    /// Latest pid -> (rx_bps, tx_bps).
    pub fn latest(&self) -> HashMap<u32, (u64, u64)> { todo!() }
}
