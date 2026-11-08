//! `fat run --cpu 200 --mem 2G --time 10m -- cmd`: supervise a process tree under a budget. OWNER: actions agent.
use crate::model::Budget;

/// Parse "2G", "512M", "1.5g" -> bytes.
pub fn parse_bytes(_s: &str) -> anyhow::Result<u64> { todo!() }
/// Parse "90s", "10m", "2h", "30" -> seconds.
pub fn parse_duration(_s: &str) -> anyhow::Result<u64> { todo!() }
/// Run cmd, enforce budget on its whole tree, print violations to stderr. Returns child's exit code.
pub fn run(_cmd: &[String], _budget: &Budget) -> anyhow::Result<i32> { todo!() }
