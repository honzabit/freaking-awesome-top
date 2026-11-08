//! Containers + remote hosts in one tree. OWNER: fleet agent.
use crate::config::HostCfg;
use crate::model::{Container, Snapshot};

/// docker/podman containers if the CLI exists and daemon responds (timeout ~2s), else empty.
pub fn containers() -> Vec<Container> { todo!() }
/// Snapshot of a remote host via ssh (BatchMode, ConnectTimeout=3). host field set to cfg.name.
pub fn remote(_host: &HostCfg) -> anyhow::Result<Snapshot> { todo!() }
