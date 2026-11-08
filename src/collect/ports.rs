//! Listening sockets -> owning pid, orphan heuristic. OWNER: ports-net agent.
use crate::model::{Port, Proc};

/// List TCP listeners and bound UDP sockets, annotated with notes and orphan flags.
pub fn ports(_procs: &[Proc]) -> Vec<Port> { todo!() }
