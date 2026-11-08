//! Blame chains ("why") and whole-machine diagnosis ("doctor"). OWNER: blame agent.
use crate::history::History;
use crate::model::{Explanation, Finding, Snapshot};

pub fn explain(_snap: &Snapshot, _pid: u32, _hist: Option<&History>) -> Explanation { todo!() }
/// Ranked findings, most severe first.
pub fn diagnose(_snap: &Snapshot, _hist: Option<&History>) -> Vec<Finding> { todo!() }
/// Human explanation for well-known system daemons (mds_stores, kernel_task, ...).
pub fn known(_name: &str) -> Option<&'static str> { todo!() }
