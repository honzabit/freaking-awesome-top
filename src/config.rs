//! ~/.config/fat/config.toml. OWNER: fleet agent.
//!
//! Location (first match wins):
//! 1. `$XDG_CONFIG_HOME/fat/config.toml` if `XDG_CONFIG_HOME` is set
//! 2. `~/.config/fat/config.toml` if that file exists (preferred on macOS too)
//! 3. the platform config dir (`~/Library/Application Support/fat/config.toml` on macOS)
//!    if that file exists
//! 4. otherwise `~/.config/fat/config.toml` (where we tell people to create it)
//!
//! Example:
//!
//! ```toml
//! # Sample interval for TUI and recorder (milliseconds).
//! interval_ms = 1500
//! # Include docker/podman/orbstack containers.
//! containers = true
//! # Days of flight-recorder history to keep.
//! history_days = 3
//! # history_path = "/Users/me/.local/share/fat/history.db"
//!
//! [ask]
//! model = "claude-opus-5-5"
//! enabled = true          # uses ANTHROPIC_API_KEY when set
//!
//! [[hosts]]
//! name = "web-01"
//! ssh = "admin@web-01.example.com" # defaults to name; passed to ssh verbatim
//! fat_path = "/usr/local/bin/fat"  # default: probe PATH and the usual install dirs
//! groups = ["web"]
//! tags = ["prod"]
//!
//! [fleet]                          # all optional; see server::FleetCfg for every key
//! hosts_file = "~/fleet.txt"       # lines: name [ssh=DEST] [fat=PATH] [groups=a,b] [tags=x,y]
//! concurrency = 64
//!
//! [fleet.groups]
//! db = ["db-*"]
//! ```
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    /// `[server]`: server-mode sampling, recorder bounds, Prometheus export.
    pub server: crate::server::ServerCfg,
    /// `[fleet]`: inventory sources and fan-out limits.
    pub fleet: crate::server::FleetCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostCfg {
    pub name: String,
    /// ssh destination, e.g. "user@devbox". Defaults to name.
    pub ssh: Option<String>,
    /// Path to fat on the remote. Defaults to "fat".
    pub fat_path: Option<String>,
    /// Fleet groups/tags for selection (`fat fleet --group web`).
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
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
        Self { interval_ms: 1500, hosts: vec![], containers: true, history_path: None, history_days: 3, ask: AskCfg::default(), server: Default::default(), fleet: Default::default() }
    }
}

impl Config {
    pub fn path() -> std::path::PathBuf {
        if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(x).join("fat").join("config.toml");
        }
        let dot_config = dirs::home_dir().map(|h| h.join(".config").join("fat").join("config.toml"));
        if let Some(p) = &dot_config
            && p.exists() {
                return p.clone();
            }
        if let Some(p) = dirs::config_dir().map(|d| d.join("fat").join("config.toml"))
            && p.exists() {
                return p;
            }
        dot_config
            .or_else(|| dirs::config_dir().map(|d| d.join("fat").join("config.toml")))
            .unwrap_or_else(|| PathBuf::from("fat-config.toml"))
    }

    pub fn load() -> Config {
        let path = Self::path();
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).unwrap_or_else(|e| {
                eprintln!("fat: ignoring malformed config {}: {e}", path.display());
                Config::default()
            }),
            Err(_) => Config::default(),
        }
    }

    /// Parse TOML text into a config; missing keys take defaults.
    pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
        let mut c: Config = toml::from_str(text)?;
        if c.interval_ms < 100 {
            c.interval_ms = 100;
        }
        if c.ask.model.trim().is_empty() {
            c.ask.model = AskCfg::default().model;
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_partial_uses_defaults() {
        let c = Config::parse("interval_ms = 2000\n[[hosts]]\nname = \"devbox\"\n").unwrap();
        assert_eq!(c.interval_ms, 2000);
        assert!(c.containers);
        assert_eq!(c.history_days, 3);
        assert_eq!(c.hosts.len(), 1);
        assert_eq!(c.hosts[0].name, "devbox");
        assert!(c.hosts[0].ssh.is_none());
        assert_eq!(c.ask.model, "claude-opus-5-5");
    }

    #[test]
    fn parse_ask_section() {
        let c = Config::parse("[ask]\nenabled = false\n").unwrap();
        assert!(!c.ask.enabled);
        assert_eq!(c.ask.model, "claude-opus-5-5");
    }

    #[test]
    fn parse_fleet_section() {
        let c = Config::parse("[[hosts]]\nname = \"web-01\"\ngroups = [\"web\"]\ntags = [\"prod\"]\n[fleet]\nconcurrency = 8\nssh_options = [\"ServerAliveInterval=5\"]\n[fleet.groups]\ndb = [\"db-*\"]\n").unwrap();
        assert_eq!(c.hosts[0].groups, vec!["web"]);
        assert_eq!(c.hosts[0].tags, vec!["prod"]);
        assert_eq!(c.fleet.concurrency, 8);
        assert_eq!(c.fleet.connect_timeout_s, 5, "unset keys keep their defaults");
        assert_eq!(c.fleet.groups["db"], vec!["db-*"]);
        assert_eq!(c.fleet.ssh_options, vec!["ServerAliveInterval=5"]);
        assert!(c.fleet.control_master);
    }

    #[test]
    fn malformed_is_error() {
        assert!(Config::parse("interval_ms = \"fast\"").is_err());
        assert!(Config::parse("[[[").is_err());
    }

    #[test]
    fn path_ends_with_config_toml() {
        assert!(Config::path().ends_with("fat/config.toml"));
    }
}
