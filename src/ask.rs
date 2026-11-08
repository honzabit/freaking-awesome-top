//! Natural-language questions about the machine. OWNER: fleet agent.
use crate::model::{Finding, Snapshot};

/// Answer a question. Uses Claude API if ANTHROPIC_API_KEY is set (cfg.ask.enabled), else a
/// rule-based answer built from findings. Never panics; errors become explanatory text.
pub fn ask(_question: &str, _snap: &Snapshot, _findings: &[Finding], _cfg: &crate::config::AskCfg) -> String { todo!() }
