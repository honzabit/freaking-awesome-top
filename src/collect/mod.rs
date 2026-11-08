//! Local sampling. OWNER: collect-core agent (mod.rs, procs.rs, system.rs).
pub mod net;
pub mod ports;
pub mod procs;
pub mod system;

use crate::model::Snapshot;

/// Stateful sampler: CPU%, disk rates, energy and net need deltas between samples.
pub struct Collector {
    // implementation-defined fields
}

impl Collector {
    pub fn new() -> Self { todo!() }
    /// Take one snapshot of the local machine (host = "local"). First call may have zero rates.
    pub fn sample(&mut self) -> Snapshot { todo!() }
}
