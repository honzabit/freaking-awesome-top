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
    /// `[update]`: version check and self-update.
    pub update: UpdateCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UpdateCfg {
    /// Check once a day whether a newer release exists (TUI, recorder). Off with
    /// FAT_NO_UPDATE_CHECK=1 or `[ask] local_only`.
    pub check: bool,
    /// Install newer releases by itself (verified against fat's release key).
    pub auto: bool,
    /// `fat record` restarts itself into a newly installed binary between samples.
    pub restart_recorder: bool,
}

impl Default for UpdateCfg {
    fn default() -> Self {
        Self { check: true, auto: false, restart_recorder: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
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
    pub enabled: bool,
    /// "anthropic" (default), "openai" (any OpenAI-compatible chat server: LM Studio, vLLM,
    /// llama.cpp, LocalAI, LiteLLM, Ollama's /v1) or "ollama" (Ollama's own API).
    /// Env: FAT_ASK_PROVIDER.
    pub provider: String,
    /// Server base URL. Empty: the Anthropic API (or ANTHROPIC_BASE_URL). Required for
    /// "openai" and "ollama". Env: FAT_ASK_URL.
    pub url: String,
    /// Model name. Empty: claude-opus-5-5 for "anthropic"; required otherwise. Env: FAT_ASK_MODEL.
    pub model: String,
    /// Name of the environment variable holding the API key (the key itself never goes in
    /// the config). Empty: ANTHROPIC_API_KEY for "anthropic", FAT_ASK_KEY otherwise (optional there).
    pub key_env: String,
    /// Refuse to send anything to an address outside loopback / private / link-local networks,
    /// checked on the addresses the name resolves to when connecting. Env: FAT_ASK_LOCAL_ONLY.
    pub local_only: bool,
    /// "full" (default) or "minimal": no command lines, paths cut to two components,
    /// hostname and container names replaced. Env: FAT_ASK_DETAIL.
    pub detail: String,
    /// Upper bound on the machine digest sent, bytes. 0: 20000.
    pub context_bytes: usize,
    /// Ollama context window (num_ctx). 0: sized to fit the digest.
    pub num_ctx: u32,
    /// Seconds to wait for an answer. 0: 90 for the Anthropic API, 300 for self-hosted servers.
    pub timeout_s: u64,
    /// provider = "command": the program to run, with its arguments ("my-llm --model big");
    /// it reads the question on stdin and prints the answer.
    pub command: String,
    /// Send short excerpts of recent threads on this host with a new question.
    pub memory: bool,
    /// Delete threads untouched for this many days (0: keep forever).
    pub keep_days: u32,
}

impl Default for AskCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: "anthropic".into(),
            url: String::new(),
            model: String::new(),
            key_env: String::new(),
            local_only: false,
            detail: "full".into(),
            context_bytes: 0,
            num_ctx: 0,
            timeout_s: 0,
            command: String::new(),
            memory: true,
            keep_days: 90,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval_ms: 1500,
            hosts: vec![],
            containers: true,
            history_path: None,
            history_days: 3,
            ask: AskCfg::default(),
            server: Default::default(),
            fleet: Default::default(),
            update: Default::default(),
        }
    }
}

impl Config {
    pub fn path() -> std::path::PathBuf {
        if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(x).join("fat").join("config.toml");
        }
        let dot_config = dirs::home_dir().map(|h| h.join(".config").join("fat").join("config.toml"));
        if let Some(p) = &dot_config
            && p.exists()
        {
            return p.clone();
        }
        if let Some(p) = dirs::config_dir().map(|d| d.join("fat").join("config.toml"))
            && p.exists()
        {
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
        assert_eq!(c.ask.provider, "anthropic");
        assert!(c.ask.model.is_empty() && c.ask.url.is_empty() && !c.ask.local_only);
    }

    #[test]
    fn parse_ask_section() {
        let c = Config::parse("[ask]\nenabled = false\n").unwrap();
        assert!(!c.ask.enabled);
        let c = Config::parse("[ask]\nprovider = \"ollama\"\nurl = \"http://127.0.0.1:11434\"\nmodel = \"m\"\nlocal_only = true\ndetail = \"minimal\"\n").unwrap();
        assert_eq!((c.ask.provider.as_str(), c.ask.model.as_str(), c.ask.detail.as_str()), ("ollama", "m", "minimal"));
        assert!(c.ask.enabled && c.ask.local_only);
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
        assert!(!c.fleet.control_master, "connection sharing is left to the ssh config by default");
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
