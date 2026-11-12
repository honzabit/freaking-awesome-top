//! The settings screen's model: which settings exist, their current values, where each value
//! comes from (default, config file, environment), and writing a change back to config.toml
//! without disturbing the rest of the file (comments, order, layout).
//!
//! Secrets never pass through here: the API key is shown only as "set" / "not set" for the
//! environment variable `[ask] key_env` names.
use crate::config::Config;
use anyhow::{Context, Result, bail};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Default,
    File,
    /// Overridden by this environment variable: not editable here.
    Env(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Bool,
    Choice(&'static [&'static str]),
    Text,
    /// Whole number in this range.
    Number(u64, u64),
    /// Decimal number in this range.
    Float(f64, f64),
    /// Comma-separated strings ("a, b").
    List,
    /// "name=pat1,pat2; name2=pat3" (a table of string lists, like [fleet.groups]).
    Map,
    /// A subset of these options, comma-separated ("pause, resume").
    Multi(&'static [&'static str]),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// TOML table ("" = top level).
    pub section: String,
    pub key: String,
    /// Sidebar group.
    pub group: &'static str,
    pub label: String,
    pub help: String,
    pub kind: Kind,
    pub value: String,
    pub source: Source,
    /// Empty text removes the key (the default applies) rather than storing "".
    pub optional: bool,
    /// Takes effect at once in a running fat (otherwise: the next time fat starts).
    pub live: bool,
    /// Ask only: "connect" (chosen from the list of options, not shown as a field),
    /// "details", "privacy" or "advanced".
    pub sub: &'static str,
}

impl Field {
    pub fn editable(&self) -> bool {
        !matches!(self.source, Source::Env(_))
    }

    /// Changing it lets agents act on this machine: confirm first.
    pub fn sensitive(&self) -> bool {
        self.section == "mcp" && self.key == "allow_actions"
    }
}

/// Where an `[ask]` key goes on the Ask page (see [`Field::sub`]).
pub fn ask_sub(key: &str) -> &'static str {
    match key {
        "provider" | "enabled" => "connect",
        "local_only" | "detail" | "memory" | "keep_days" => "privacy",
        "context_bytes" | "num_ctx" | "timeout_s" => "advanced",
        _ => "details",
    }
}

/// Whether a details/advanced `[ask]` key matters for `provider`.
pub fn ask_relevant(key: &str, provider: &str) -> bool {
    let tool = crate::llm_cli::Tool::from_key(provider);
    match key {
        "url" => matches!(provider, "ollama" | "openai" | "openai-compatible" | "lmstudio" | "vllm"),
        "model" => tool != Some(crate::llm_cli::Tool::Command),
        "key_env" => tool.is_none(),
        "command" => tool == Some(crate::llm_cli::Tool::Command),
        "num_ctx" => provider == "ollama",
        _ => true,
    }
}

/// Sidebar groups, in order.
pub const GROUPS: &[&str] = &["Ask", "Recording", "Server", "Fleet", "Hosts", "Agents", "Peers", "Updates"];

const PROVIDERS: &[&str] = &["anthropic", "openai", "ollama"];
const DETAILS: &[&str] = &["full", "minimal"];
const PROFILES: &[&str] = &["auto", "desktop", "server"];

/// Short explanations for keys of [server] and [fleet] (the rest show their key).
const HELP: &[(&str, &str)] = &[
    ("profile", "auto detects (headless Linux = server); FAT_PROFILE overrides"),
    ("record_top_procs", "processes recorded per sample in server mode"),
    ("max_units", "units sampled per host at most (transient-unit churn guard)"),
    ("unit_refresh_s", "seconds between full unit refreshes"),
    ("flap_restarts", "restarts within the flap window that make a unit \"flapping\""),
    ("flap_window_s", "flap window, seconds"),
    ("kmsg", "read the kernel log (OOM kills, hung tasks, I/O errors); needs root or dmesg_restrict=0"),
    ("dstate_min_s", "report processes stuck in D state at least this long"),
    ("disk_await_warn_ms", "disk await (ms) that counts as a latency spike"),
    ("exhaustion_warn", "fraction of a limit (fds, conntrack, ports, memory.max) that is \"near exhaustion\""),
    ("burst_procs", "new processes in one unit within one interval that count as a deploy burst"),
    ("pressure_full_warn", "PSI full avg10 % that counts as a pressure spike"),
    ("export_listen", "Prometheus /metrics address (loopback by default)"),
    ("export_enabled", "serve /metrics from fat record without the --export flag"),
    ("record_interval_ms", "fat record's sample interval in the server profile"),
    ("max_events_per_sample", "events recorded per sample at most"),
    ("spike_cooldown_s", "seconds between repeats of the same level event"),
    ("spike_cpu_pct", "unit CPU rise (% of host) above its median that is a spike"),
    ("spike_mem_pct", "unit memory growth (% of host RAM per minute) that is a spike"),
    ("concurrency", "parallel ssh sessions"),
    ("connect_timeout_s", "ssh ConnectTimeout, seconds"),
    ("command_timeout_s", "wall-clock limit per remote command, seconds"),
    ("control_master", "reuse ssh connections (ControlMaster) between polls"),
    ("control_persist", "how long a shared ssh connection stays open"),
    ("ssh_options", "extra ssh -o options, comma-separated (e.g. ServerAliveInterval=5)"),
    ("hosts_file", "file listing hosts: name [ssh=DEST] [fat=PATH] [groups=a,b] [tags=x,y]"),
    ("ssh_config_hosts", "also use Host entries from your ssh config"),
    ("ssh_config_filter", "only ssh-config hosts matching these patterns"),
    ("groups", "host groups by name pattern: \"db=db-*,pg-*; web=web-*\""),
    ("max_output_bytes", "bytes read from one host's answer at most"),
    ("fast_max_age_ms", "how old a recorder sample may be for snapshot --fast"),
    ("default_fat_path", "fat's path on hosts that don't set their own"),
    ("tui_refresh_s", "seconds between Fleet tab polls"),
    ("compress", "compress ssh traffic"),
    ("cache_ttl_s", "seconds a host's answer is reused"),
    ("max_hosts_per_finding", "hosts listed per fleet finding at most"),
    ("outlier_min_group", "hosts a group needs before outliers are flagged"),
    ("outlier_z", "z-score that makes a host an outlier in its group"),
    ("outlier_min_delta", "smallest absolute difference that counts as an outlier"),
    ("timeout_backoff_s", "seconds to skip a host after it timed out"),
];

fn help_for(key: &str) -> String {
    HELP.iter().find(|(k, _)| *k == key).map(|(_, h)| h.to_string()).unwrap_or_default()
}

fn label_for(key: &str) -> String {
    let s = key.replace('_', " ");
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

fn list_str(a: &[toml::Value]) -> String {
    a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", ")
}

/// Every setting the screen shows, for the effective config `cfg` (as loaded), the config
/// file's text (to tell file values from defaults) and the environment.
pub fn fields(cfg: &Config, file_text: &str, env: &dyn Fn(&str) -> Option<String>) -> Vec<Field> {
    let doc: toml_edit::DocumentMut = file_text.parse().unwrap_or_default();
    let in_file = |section: &str, key: &str| -> bool {
        if section.is_empty() { doc.get(key).is_some() } else { doc.get(section).and_then(|t| t.get(key)).is_some() }
    };
    let env_set = |var: &str| env(var).is_some_and(|v| !v.trim().is_empty());
    let a = crate::llm::settings_with(&cfg.ask, |k| env(k));
    let mut out: Vec<Field> = Vec::new();
    #[allow(clippy::too_many_arguments)]
    let mut push = |group: &'static str,
                    section: &str,
                    key: &str,
                    label: &str,
                    help: &str,
                    kind: Kind,
                    value: String,
                    env_var: Option<&'static str>,
                    optional: bool,
                    live: bool| {
        let source = match env_var {
            Some(v) if env_set(v) => Source::Env(v),
            _ if in_file(section, key) => Source::File,
            _ => Source::Default,
        };
        out.push(Field {
            section: section.into(),
            key: key.into(),
            group,
            label: label.into(),
            help: help.into(),
            kind,
            value,
            source,
            optional,
            live,
            sub: "",
        });
    };
    let n = |v: u64| v.to_string();
    let g = "Ask";
    push(
        g,
        "ask",
        "enabled",
        "Enabled",
        "off: always answer offline, send nothing",
        Kind::Bool,
        a.enabled.to_string(),
        None,
        false,
        true,
    );
    push(
        g,
        "ask",
        "provider",
        "Provider",
        "anthropic (Claude API) · openai (LM Studio, vLLM, llama.cpp, LiteLLM…) · ollama",
        Kind::Choice(PROVIDERS),
        if a.provider.is_empty() { "anthropic".into() } else { a.provider.clone() },
        Some("FAT_ASK_PROVIDER"),
        false,
        true,
    );
    push(
        g,
        "ask",
        "url",
        "Server URL",
        "required for openai/ollama, e.g. http://HOST:11434; empty = the Anthropic API",
        Kind::Text,
        a.url.clone(),
        Some("FAT_ASK_URL"),
        true,
        true,
    );
    push(
        g,
        "ask",
        "model",
        "Model",
        "m picks from the server's models; empty = claude-opus-5-5 for anthropic",
        Kind::Text,
        a.model.clone(),
        Some("FAT_ASK_MODEL"),
        true,
        true,
    );
    push(
        g,
        "ask",
        "key_env",
        "Key variable",
        "name of the environment variable holding the key (the key itself never goes in the file)",
        Kind::Text,
        a.key_env.clone(),
        None,
        true,
        true,
    );
    push(
        g,
        "ask",
        "local_only",
        "Local only",
        "refuse any server address outside loopback / private / link-local networks",
        Kind::Bool,
        a.local_only.to_string(),
        Some("FAT_ASK_LOCAL_ONLY"),
        false,
        true,
    );
    push(
        g,
        "ask",
        "detail",
        "Detail",
        "minimal: no command lines, paths cut to two parts, hostnames replaced",
        Kind::Choice(DETAILS),
        if a.detail.is_empty() { "full".into() } else { a.detail.clone() },
        Some("FAT_ASK_DETAIL"),
        false,
        true,
    );
    push(
        g,
        "ask",
        "memory",
        "Memory",
        "send excerpts of recent threads on this host with a question",
        Kind::Bool,
        a.memory.to_string(),
        None,
        false,
        true,
    );
    push(
        g,
        "ask",
        "keep_days",
        "Keep threads (days)",
        "delete threads untouched this long; 0 = keep",
        Kind::Number(0, 3650),
        n(a.keep_days as u64),
        None,
        false,
        true,
    );
    push(
        g,
        "ask",
        "context_bytes",
        "Digest size (bytes)",
        "0 = 20000; about 6000 for CPU-only or small models",
        Kind::Number(0, 1_000_000),
        n(a.context_bytes as u64),
        None,
        false,
        true,
    );
    push(
        g,
        "ask",
        "num_ctx",
        "Ollama context (tokens)",
        "0 = sized to the digest",
        Kind::Number(0, 1_048_576),
        n(a.num_ctx as u64),
        None,
        false,
        true,
    );
    push(
        g,
        "ask",
        "timeout_s",
        "Timeout (s)",
        "0 = 90 for anthropic, 300 for self-hosted",
        Kind::Number(0, 3600),
        n(a.timeout_s),
        None,
        false,
        true,
    );

    push(
        g,
        "ask",
        "command",
        "Command",
        "a program that reads the question on stdin and prints the answer, e.g. a CLI for another model",
        Kind::Text,
        a.command.clone(),
        None,
        true,
        true,
    );

    let g = "Recording";
    push(
        g,
        "",
        "history_days",
        "Keep history (days)",
        "flight-recorder retention (fat record picks it up when restarted)",
        Kind::Number(1, 3650),
        n(cfg.history_days as u64),
        None,
        false,
        false,
    );
    push(
        g,
        "",
        "interval_ms",
        "Sample interval (ms)",
        "TUI and desktop recorder sample interval",
        Kind::Number(100, 600_000),
        n(cfg.interval_ms),
        None,
        false,
        false,
    );
    push(
        g,
        "",
        "containers",
        "Containers",
        "include docker / podman / OrbStack containers",
        Kind::Bool,
        cfg.containers.to_string(),
        None,
        false,
        false,
    );
    push(
        g,
        "",
        "history_path",
        "History file",
        "empty = the default location",
        Kind::Text,
        cfg.history_path.clone().unwrap_or_default(),
        None,
        true,
        false,
    );

    // [server] and [fleet]: every scalar and list, from the effective values.
    for (group, section, value) in [
        ("Server", "server", toml::Value::try_from(&cfg.server).ok()),
        ("Fleet", "fleet", toml::Value::try_from(&cfg.fleet).ok()),
    ] {
        let Some(toml::Value::Table(t)) = value else { continue };
        let mut keys: Vec<&String> = t.keys().collect();
        // Known keys in HELP order first, then the rest alphabetically.
        keys.sort_by_key(|k| (HELP.iter().position(|(h, _)| h == k).unwrap_or(usize::MAX), k.to_string()));
        for key in keys {
            let v = &t[key];
            let (kind, val) = match (section, key.as_str(), v) {
                ("server", "profile", toml::Value::String(s)) => (Kind::Choice(PROFILES), s.clone()),
                (_, _, toml::Value::Boolean(b)) => (Kind::Bool, b.to_string()),
                (_, _, toml::Value::Integer(i)) => (Kind::Number(0, i64::MAX as u64), i.to_string()),
                (_, _, toml::Value::Float(x)) => (Kind::Float(0.0, 1e12), format!("{x}")),
                (_, _, toml::Value::String(s)) => (Kind::Text, s.clone()),
                (_, _, toml::Value::Array(a)) => (Kind::List, list_str(a)),
                (_, "groups", toml::Value::Table(m)) => {
                    let s = m
                        .iter()
                        .map(|(name, pats)| {
                            format!(
                                "{name}={}",
                                pats.as_array().map(|a| list_str(a)).unwrap_or_default().replace(", ", ",")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    (Kind::Map, s)
                }
                _ => continue,
            };
            let env_var = (section == "server" && key == "profile").then_some("FAT_PROFILE");
            let optional = matches!(key.as_str(), "hosts_file" | "default_fat_path");
            push(group, section, key, &label_for(key), &help_for(key), kind, val, env_var, optional, false);
        }
        // Optional keys serde leaves out when unset.
        if section == "fleet" {
            for key in ["hosts_file", "default_fat_path"] {
                if !t.contains_key(key) {
                    push(
                        "Fleet",
                        "fleet",
                        key,
                        &label_for(key),
                        &help_for(key),
                        Kind::Text,
                        String::new(),
                        None,
                        true,
                        false,
                    );
                }
            }
        }
    }

    let allowed = allowed_in(&doc);
    push(
        "Agents",
        "mcp",
        "allow_actions",
        "Agents may",
        "tools agents (MCP) may use that change this machine; nothing = read-only. Kill always needs a preview first.",
        Kind::Multi(crate::mcp::ACTION_TOOLS),
        allowed.join(", "),
        None,
        false,
        false,
    );
    let g = "Peers";
    push(
        g,
        "peers",
        "names",
        "Names for connection peers",
        "reverse DNS through the system resolver, checked forward; unconfirmed names get a ?",
        Kind::Bool,
        cfg.peers.names.to_string(),
        Some("FAT_NO_PEER_NAMES"),
        false,
        false,
    );
    push(
        g,
        "peers",
        "asn",
        "Network (AS) of public peers",
        "looked up offline in the iptoasn.com table, downloaded weekly (not under [ask] local_only)",
        Kind::Bool,
        cfg.peers.asn.to_string(),
        None,
        false,
        false,
    );
    push(
        g,
        "peers",
        "asn_db",
        "AS table file",
        "use this ip2asn-combined.tsv(.gz) instead of downloading one; empty = download",
        Kind::Text,
        cfg.peers.asn_db.clone(),
        Some("FAT_ASN_DB"),
        false,
        false,
    );
    let g = "Updates";
    push(
        g,
        "update",
        "check",
        "Check for new releases",
        "once a day, in the background: one request to GitHub, nothing else sent. Off under [ask] local_only.",
        Kind::Bool,
        cfg.update.check.to_string(),
        Some("FAT_NO_UPDATE_CHECK"),
        false,
        false,
    );
    push(
        g,
        "update",
        "auto",
        "Install updates automatically",
        "only releases signed with fat's release key; the previous binary is kept (fat update --rollback)",
        Kind::Bool,
        cfg.update.auto.to_string(),
        None,
        false,
        false,
    );
    push(
        g,
        "update",
        "restart_recorder",
        "Recorder restarts into a new binary",
        "fat record notices its binary was replaced and restarts itself between samples",
        Kind::Bool,
        cfg.update.restart_recorder.to_string(),
        None,
        false,
        false,
    );
    for f in out.iter_mut().filter(|f| f.section == "ask") {
        f.sub = ask_sub(&f.key);
    }
    out
}

/// [mcp] allow_actions as written ("all" expanded), without logging.
fn allowed_in(doc: &toml_edit::DocumentMut) -> Vec<String> {
    let all = || crate::mcp::ACTION_TOOLS.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let Some(v) = doc.get("mcp").and_then(|t| t.get("allow_actions")) else { return vec![] };
    let names: Vec<String> = if let Some(s) = v.as_str() {
        vec![s.to_string()]
    } else if let Some(a) = v.as_array() {
        a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()
    } else {
        vec![]
    };
    let mut out = Vec::new();
    for n in names {
        let n = n.trim().to_ascii_lowercase();
        if n == "all" {
            return all();
        }
        if crate::mcp::ACTION_TOOLS.contains(&n.as_str()) && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

/// "set" / "not set" for the variable holding the API key (never its value).
pub fn key_status(cfg: &Config, env: &dyn Fn(&str) -> Option<String>) -> String {
    match crate::llm::resolve(&cfg.ask) {
        Ok(ep) => {
            let set = env(&ep.key_env).is_some_and(|v| !v.trim().is_empty());
            let needed = ep.provider == crate::llm::Provider::Anthropic;
            match (set, needed) {
                (true, _) => format!("{}: set ✓", ep.key_env),
                (false, true) => format!("{}: not set (needed for the Claude API)", ep.key_env),
                (false, false) => format!("{}: not set (fine if the server needs no key)", ep.key_env),
            }
        }
        Err(e) => e,
    }
}

/// Parse `input` for `f` into a TOML value (None: remove the key so the default applies),
/// or say what is wrong.
pub fn parse_input(f: &Field, input: &str) -> Result<Option<toml_edit::Value>, String> {
    let t = input.trim();
    let strings =
        |s: &str| -> Vec<String> { s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect() };
    let array = |items: Vec<String>| -> toml_edit::Value {
        let mut a = toml_edit::Array::new();
        for i in items {
            a.push(i);
        }
        toml_edit::Value::Array(a)
    };
    match &f.kind {
        Kind::Bool => match t {
            "true" | "on" | "yes" | "1" => Ok(Some(true.into())),
            "false" | "off" | "no" | "0" => Ok(Some(false.into())),
            _ => Err(format!("{}: true or false", f.label)),
        },
        Kind::Choice(opts) => {
            if opts.contains(&t) {
                Ok(Some(t.into()))
            } else {
                Err(format!("{}: one of {}", f.label, opts.join(", ")))
            }
        }
        Kind::Number(lo, hi) => match t.parse::<u64>() {
            Ok(v) if v >= *lo && v <= *hi => Ok(Some((v.min(i64::MAX as u64) as i64).into())),
            _ if *hi >= i64::MAX as u64 => Err(format!("{}: a whole number, {lo} or more", f.label)),
            _ => Err(format!("{}: a whole number from {lo} to {hi}", f.label)),
        },
        Kind::Float(lo, hi) => match t.parse::<f64>() {
            Ok(v) if v.is_finite() && v >= *lo && v <= *hi => Ok(Some(v.into())),
            _ => Err(format!("{}: a number from {lo} to {hi}", f.label)),
        },
        Kind::Text => {
            if f.key == "url" && !t.is_empty() && !(t.starts_with("http://") || t.starts_with("https://")) {
                return Err("Server URL: must start with http:// or https://".into());
            }
            if t.contains('\n') {
                return Err(format!("{}: one line", f.label));
            }
            if t.is_empty() && f.optional {
                return Ok(None);
            }
            Ok(Some(t.into()))
        }
        Kind::List => Ok(Some(array(strings(t)))),
        Kind::Map => {
            let mut table = toml_edit::InlineTable::new();
            for entry in t.split(';').map(str::trim).filter(|e| !e.is_empty()) {
                let Some((name, pats)) = entry.split_once('=') else {
                    return Err(format!("{}: name=pattern,pattern; name2=pattern (got \"{entry}\")", f.label));
                };
                let name = name.trim();
                if name.is_empty() || name.contains(char::is_whitespace) {
                    return Err(format!("{}: group names have no spaces (got \"{name}\")", f.label));
                }
                table.insert(name, array(strings(pats)));
            }
            Ok(Some(toml_edit::Value::InlineTable(table)))
        }
        Kind::Multi(opts) => {
            let items = strings(t);
            if let Some(bad) = items.iter().find(|i| !opts.contains(&i.as_str()) && *i != "all") {
                return Err(format!("{}: {bad} is not one of {}", f.label, opts.join(", ")));
            }
            Ok(Some(array(items)))
        }
    }
}

/// Set (or with `value` None, remove so the default applies) `section.key` in the config file
/// at `path`, keeping everything else in it as written. The result must still load; nothing
/// is written otherwise. Returns the new config.
pub fn write(path: &Path, section: &str, key: &str, value: Option<toml_edit::Value>) -> Result<Config> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    save(path, &edit(&text, section, key, value)?)
}

/// [`write`] on text.
pub fn edit(text: &str, section: &str, key: &str, value: Option<toml_edit::Value>) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = text.parse().context("the config file is not valid TOML; fix it first")?;
    let table = if section.is_empty() {
        doc.as_table_mut()
    } else {
        if doc.get(section).is_none() {
            if value.is_none() {
                return Ok(doc.to_string());
            }
            doc[section] = toml_edit::table();
        }
        match doc[section].as_table_mut() {
            Some(t) => t,
            None => bail!("[{section}] in the config file is not a table"),
        }
    };
    match value {
        Some(v) => {
            // Replace the value but keep any comment written after it on the same line.
            match table.get_mut(key).and_then(|i| i.as_value_mut()) {
                Some(old) => {
                    let decor = old.decor().clone();
                    *old = v;
                    *old.decor_mut() = decor;
                }
                None => {
                    table.insert(key, toml_edit::value(v));
                }
            }
        }
        None => {
            table.remove(key);
        }
    }
    Ok(doc.to_string())
}

// ---------- [[hosts]] ----------

/// Check a host before saving it.
pub fn check_host(h: &crate::config::HostCfg) -> Result<(), String> {
    let bad = |s: &str| s.is_empty() || s.chars().any(|c| c.is_whitespace() || c.is_control());
    if bad(h.name.trim()) {
        return Err("Host: a name without spaces is required".into());
    }
    if let Some(d) = &h.ssh
        && (bad(d) || d.starts_with('-'))
    {
        return Err("ssh destination: one word, like user@host or an ssh config alias".into());
    }
    if let Some(p) = &h.fat_path
        && bad(p)
    {
        return Err("fat path: a path without spaces".into());
    }
    Ok(())
}

/// Replace host `index` (None: add one; `host` None: remove it) in config text.
pub fn edit_host(text: &str, index: Option<usize>, host: Option<&crate::config::HostCfg>) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = text.parse().context("the config file is not valid TOML; fix it first")?;
    if doc.get("hosts").is_none() {
        if host.is_none() {
            return Ok(doc.to_string());
        }
        doc["hosts"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    let Some(arr) = doc["hosts"].as_array_of_tables_mut() else {
        bail!("hosts in the config file is not a [[hosts]] list; edit it there");
    };
    let to_table = |h: &crate::config::HostCfg, mut t: toml_edit::Table| {
        let list = |v: &[String]| {
            let mut a = toml_edit::Array::new();
            for x in v {
                a.push(x.as_str());
            }
            toml_edit::value(a)
        };
        t["name"] = toml_edit::value(h.name.trim());
        for (k, v) in [("ssh", &h.ssh), ("fat_path", &h.fat_path)] {
            match v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(v) => t[k] = toml_edit::value(v),
                None => {
                    t.remove(k);
                }
            }
        }
        for (k, v) in [("groups", &h.groups), ("tags", &h.tags)] {
            if v.is_empty() {
                t.remove(k);
            } else {
                t[k] = list(v);
            }
        }
        t
    };
    match (index, host) {
        (Some(i), Some(h)) => {
            let Some(t) = arr.get_mut(i) else { bail!("no host #{i}") };
            let old = std::mem::take(t);
            *t = to_table(h, old);
        }
        (None, Some(h)) => arr.push(to_table(h, toml_edit::Table::new())),
        (Some(i), None) => {
            if i >= arr.len() {
                bail!("no host #{i}");
            }
            arr.remove(i);
        }
        (None, None) => {}
    }
    Ok(doc.to_string())
}

/// [`edit_host`] on the config file at `path`, written like [`write`].
pub fn write_host(path: &Path, index: Option<usize>, host: Option<&crate::config::HostCfg>) -> Result<Config> {
    if let Some(h) = host {
        check_host(h).map_err(|e| anyhow::anyhow!(e))?;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let new_text = edit_host(&text, index, host)?;
    save(path, &new_text)
}

/// Validate and atomically replace the config file.
fn save(path: &Path, new_text: &str) -> Result<Config> {
    let cfg = Config::parse(new_text).map_err(|e| anyhow::anyhow!("the change would make the config invalid: {e}"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Write next to it and rename: a crash never leaves half a config. Keep its permissions.
    let tmp = path.with_extension("toml.fat-tmp");
    std::fs::write(&tmp, new_text).with_context(|| format!("writing {}", tmp.display()))?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(cfg)
}

/// Can we reach `h` over ssh and run its fat? One `fat --version`, with the user's own ssh
/// config, batch mode (never prompts), short timeouts.
pub fn test_host(h: &crate::config::HostCfg, connect_timeout_s: u64) -> Result<String, String> {
    check_host(h)?;
    let dest = h.ssh.clone().unwrap_or_else(|| h.name.clone());
    let fat = h.fat_path.clone().unwrap_or_else(|| "fat".into());
    let mut child = std::process::Command::new("ssh")
        .args(["-o", "BatchMode=yes", "-o", &format!("ConnectTimeout={}", connect_timeout_s.clamp(1, 30)), "--"])
        .arg(&dest)
        .arg(format!("{fat} --version"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("ssh: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(connect_timeout_s.clamp(1, 30) + 10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{dest}: no answer in time"));
            }
        }
    }
    let out = child.wait_with_output().map_err(|e| format!("ssh: {e}"))?;
    let text = |b: &[u8]| String::from_utf8_lossy(b).lines().next().unwrap_or("").trim().to_string();
    if out.status.success() {
        Ok(format!("{dest}: {}", text(&out.stdout)))
    } else {
        let err = text(&out.stderr);
        Err(format!("{dest}: {}", if err.is_empty() { format!("exit {}", out.status) } else { err }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# my settings\ninterval_ms = 2000 # fast\n\n[ask]\n# local model\nprovider = \"ollama\"   # LAN box\nmodel = \"m\"\n\n[[hosts]]\nname = \"web-01\"\n";

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn edits_keep_comments_and_layout() {
        let out = edit(FILE, "ask", "provider", Some("openai".into())).unwrap();
        assert!(out.contains("provider = \"openai\"   # LAN box"), "{out}");
        assert!(out.contains("# my settings") && out.contains("# local model") && out.contains("[[hosts]]"), "{out}");
        let out = edit(&out, "ask", "url", Some("http://10.0.0.5:1234".into())).unwrap();
        assert!(out.contains("url = \"http://10.0.0.5:1234\""), "{out}");
        let out = edit(&out, "", "history_days", Some(7i64.into())).unwrap();
        let c = Config::parse(&out).unwrap();
        assert_eq!((c.ask.provider.as_str(), c.history_days, c.interval_ms), ("openai", 7, 2000));
        assert_eq!(c.hosts[0].name, "web-01");
        // Reset: the key goes, the default applies.
        let out = edit(&out, "ask", "model", None).unwrap();
        assert!(Config::parse(&out).unwrap().ask.model.is_empty());
        // A new section appears when needed; removing from a missing one is a no-op.
        let out = edit("", "ask", "memory", Some(false.into())).unwrap();
        assert!(!Config::parse(&out).unwrap().ask.memory);
        assert_eq!(edit("x = 1\n", "ask", "memory", None).unwrap(), "x = 1\n");
        assert!(edit("not [valid", "ask", "x", Some(1i64.into())).is_err());
    }

    #[test]
    fn write_is_atomic_and_refuses_invalid_results() {
        let dir = std::env::temp_dir().join(format!("fat-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("fat").join("config.toml");
        // No file yet: created.
        let c = write(&p, "ask", "local_only", Some(true.into())).unwrap();
        assert!(c.ask.local_only);
        std::fs::write(&p, FILE).unwrap();
        let c = write(&p, "ask", "detail", Some("minimal".into())).unwrap();
        assert_eq!(c.ask.detail, "minimal");
        assert!(std::fs::read_to_string(&p).unwrap().contains("# LAN box"));
        // A wrongly typed value would make the file unloadable: refused, file untouched.
        let before = std::fs::read_to_string(&p).unwrap();
        assert!(write(&p, "ask", "memory", Some("yes".into())).unwrap_err().to_string().contains("invalid"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before);
        assert!(!p.with_extension("toml.fat-tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fields_show_values_and_where_they_come_from() {
        let cfg = Config::parse(FILE).unwrap();
        let env = |k: &str| (k == "FAT_ASK_MODEL").then(|| "from-env".to_string());
        let f = fields(&cfg, FILE, &env);
        let get = |k: &str| f.iter().find(|x| x.key == k).unwrap().clone();
        assert_eq!((get("provider").value.as_str(), get("provider").source), ("ollama", Source::File));
        assert_eq!(get("interval_ms").source, Source::File);
        assert_eq!(get("history_days").source, Source::Default);
        let m = get("model");
        assert_eq!((m.value.as_str(), m.source.clone()), ("from-env", Source::Env("FAT_ASK_MODEL")));
        assert!(!m.editable(), "an environment override is not editable here");
        assert!(get("provider").editable() && get("allow_actions").editable() && get("allow_actions").sensitive());
        assert_eq!(get("allow_actions").value, "");
        assert_eq!((get("provider").group, get("history_days").group), ("Ask", "Recording"));
        // Every [server] and [fleet] scalar is there, typed.
        assert_eq!(
            (get("record_top_procs").group, get("record_top_procs").kind.clone()),
            ("Server", Kind::Number(0, i64::MAX as u64))
        );
        assert_eq!(get("profile").kind, Kind::Choice(PROFILES));
        assert_eq!(get("exhaustion_warn").kind, Kind::Float(0.0, 1e12));
        assert_eq!((get("ssh_options").kind.clone(), get("groups").kind.clone()), (Kind::List, Kind::Map));
        assert!(get("hosts_file").optional && get("hosts_file").group == "Fleet");
        assert!(get("model").live && !get("concurrency").live);
        let _ = no_env("x");
    }

    #[test]
    fn inputs_are_checked() {
        let f = fields(&Config::default(), "", &no_env);
        let get = |k: &str| f.iter().find(|x| x.key == k).unwrap();
        let v = |k: &str, s: &str| parse_input(get(k), s).unwrap().unwrap();
        assert_eq!(v("keep_days", "30").as_integer(), Some(30));
        assert!(parse_input(get("keep_days"), "-1").is_err());
        assert!(parse_input(get("interval_ms"), "10").unwrap_err().contains("100"));
        assert!(parse_input(get("url"), "llm:11434").unwrap_err().contains("http://"));
        assert!(parse_input(get("url"), "").unwrap().is_none(), "empty optional text = back to the default");
        assert_eq!(v("provider", "ollama").as_str(), Some("ollama"));
        assert!(parse_input(get("provider"), "gpt").is_err());
        assert_eq!(v("memory", "off").as_bool(), Some(false));
        assert_eq!(v("exhaustion_warn", "0.8").as_float(), Some(0.8));
        assert_eq!(v("ssh_options", "ServerAliveInterval=5, Compression=no").as_array().unwrap().len(), 2);
        let g = v("groups", "db=db-*,pg-*; web=web-*");
        assert_eq!(g.as_inline_table().unwrap().get("db").unwrap().as_array().unwrap().len(), 2);
        assert!(parse_input(get("groups"), "db db-*").is_err());
        assert_eq!(v("allow_actions", "pause, resume").as_array().unwrap().len(), 2);
        assert!(parse_input(get("allow_actions"), "pause, format-disk").is_err());
        // Whole-file round trip through Config for the new kinds.
        let mut text = String::new();
        for (k, s) in [("groups", "db=db-*"), ("ssh_options", "A=1"), ("exhaustion_warn", "0.5")] {
            text = edit(&text, "fleet", k, parse_input(get(k), s).unwrap()).unwrap_or(text);
        }
        let text = edit(&text, "server", "exhaustion_warn", Some(0.5.into())).unwrap();
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.fleet.groups.get("db").unwrap(), &vec!["db-*".to_string()]);
        assert_eq!(c.fleet.ssh_options, vec!["A=1"]);
        assert_eq!(c.server.exhaustion_warn, 0.5);
    }

    #[test]
    fn key_status_never_shows_the_key() {
        let env = |k: &str| (k == "ANTHROPIC_API_KEY").then(|| "sk-ant-secret".to_string());
        let s = key_status(&Config::default(), &env);
        assert_eq!(s, "ANTHROPIC_API_KEY: set ✓");
        assert!(key_status(&Config::default(), &no_env).contains("not set (needed"));
        let mut c = Config::default();
        c.ask.provider = "ollama".into();
        c.ask.url = "http://h:1".into();
        c.ask.model = "m".into();
        assert!(key_status(&c, &no_env).contains("FAT_ASK_KEY: not set (fine"));
    }

    #[test]
    fn hosts_are_added_edited_and_removed_keeping_the_file() {
        use crate::config::HostCfg;
        let h = |name: &str, ssh: Option<&str>| HostCfg {
            name: name.into(),
            ssh: ssh.map(str::to_string),
            ..Default::default()
        };
        let t = edit_host(FILE, None, Some(&h("db-01", Some("ops@db-01")))).unwrap();
        let c = Config::parse(&t).unwrap();
        assert_eq!(c.hosts.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), vec!["web-01", "db-01"]);
        assert!(t.contains("# my settings") && t.contains("# LAN box"));
        let mut e = h("web-02", None);
        e.groups = vec!["web".into()];
        let t = edit_host(&t, Some(0), Some(&e)).unwrap();
        let c = Config::parse(&t).unwrap();
        assert_eq!((c.hosts[0].name.as_str(), c.hosts[0].groups.clone()), ("web-02", vec!["web".to_string()]));
        let t = edit_host(&t, Some(1), None).unwrap();
        assert_eq!(Config::parse(&t).unwrap().hosts.len(), 1);
        assert!(edit_host(&t, Some(5), None).is_err());
        assert!(check_host(&h("bad name", None)).is_err());
        assert!(check_host(&h("ok", Some("-oProxyCommand=x"))).is_err(), "no ssh options through the destination");
        assert!(check_host(&h("ok", Some("me@ok"))).is_ok());
    }
}
