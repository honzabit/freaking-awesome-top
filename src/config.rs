//! ~/.config/fat/config.toml. OWNER: fleet agent.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Sample interval for TUI and recorder.
    pub interval_ms: u64,
    /// Remote hosts reachable via `ssh <host> fat snapshot --json`.
    pub hosts: Vec<HostCfg>,
    /// Include docker/podman containers.
    pub containers: bool,
    /// History DB path override.
    pub history_path: Option<String>,
    /// Days of history to keep.
    pub history_days: u32,
    pub ask: AskCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostCfg {
    pub name: String,
    /// ssh destination, e.g. "user@devbox". Defaults to name.
    pub ssh: Option<String>,
    /// Path to fat on the remote. Defaults to "fat".
    pub fat_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AskCfg {
    pub model: String,
    pub enabled: bool,
}

impl Default for AskCfg {
    fn default() -> Self { Self { model: "claude-opus-5-5".into(), enabled: true } }
}

impl Default for Config {
    fn default() -> Self {
        Self { interval_ms: 1500, hosts: vec![], containers: true, history_path: None, history_days: 3, ask: AskCfg::default() }
    }
}

impl Config {
    pub fn path() -> std::path::PathBuf { todo!() }
    pub fn load() -> Config { Config::default() }
}
