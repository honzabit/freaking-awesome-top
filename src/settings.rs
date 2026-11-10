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
    /// Shown, not edited here (with how to change it in `help`).
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// TOML table ("" = top level).
    pub section: &'static str,
    pub key: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub kind: Kind,
    pub value: String,
    pub source: Source,
}

impl Field {
    pub fn editable(&self) -> bool {
        self.kind != Kind::ReadOnly && !matches!(self.source, Source::Env(_))
    }

    /// Group heading shown above the field.
    pub fn group(&self) -> &'static str {
        match self.section {
            "ask" => "Ask: the model",
            "" if matches!(self.key, "interval_ms" | "history_days" | "history_path") => "Recording",
            _ => "Other (edit the config file)",
        }
    }
}

const PROVIDERS: &[&str] = &["anthropic", "openai", "ollama"];
const DETAILS: &[&str] = &["full", "minimal"];

/// Every setting the screen shows, for the effective config `cfg` (as loaded), the config
/// file's text (to tell file values from defaults) and the environment.
pub fn fields(cfg: &Config, file_text: &str, env: &dyn Fn(&str) -> Option<String>) -> Vec<Field> {
    let doc: toml_edit::DocumentMut = file_text.parse().unwrap_or_default();
    let in_file = |section: &str, key: &str| -> bool {
        if section.is_empty() { doc.get(key).is_some() } else { doc.get(section).and_then(|t| t.get(key)).is_some() }
    };
    let env_set = |var: &str| env(var).is_some_and(|v| !v.trim().is_empty());
    let a = crate::llm::settings_with(&cfg.ask, |k| env(k));
    let mut out = Vec::new();
    let mut push = |section: &'static str,
                    key: &'static str,
                    label: &'static str,
                    help: &'static str,
                    kind: Kind,
                    value: String,
                    env_var: Option<&'static str>| {
        let source = match env_var {
            Some(v) if env_set(v) => Source::Env(v),
            _ if in_file(section, key) => Source::File,
            _ => Source::Default,
        };
        out.push(Field { section, key, label, help, kind, value, source });
    };
    let n = |v: u64| v.to_string();
    push(
        "ask",
        "enabled",
        "Enabled",
        "off: always answer offline, send nothing",
        Kind::Bool,
        a.enabled.to_string(),
        None,
    );
    push(
        "ask",
        "provider",
        "Provider",
        "anthropic (Claude API) · openai (LM Studio, vLLM, llama.cpp, LiteLLM…) · ollama",
        Kind::Choice(PROVIDERS),
        if a.provider.is_empty() { "anthropic".into() } else { a.provider.clone() },
        Some("FAT_ASK_PROVIDER"),
    );
    push(
        "ask",
        "url",
        "Server URL",
        "required for openai/ollama, e.g. http://HOST:11434; empty = the Anthropic API",
        Kind::Text,
        a.url.clone(),
        Some("FAT_ASK_URL"),
    );
    push(
        "ask",
        "model",
        "Model",
        "m picks from the server's models; empty = claude-opus-5-5 for anthropic",
        Kind::Text,
        a.model.clone(),
        Some("FAT_ASK_MODEL"),
    );
    push(
        "ask",
        "key_env",
        "Key variable",
        "name of the environment variable holding the key (the key itself never goes in the file)",
        Kind::Text,
        a.key_env.clone(),
        None,
    );
    push(
        "ask",
        "local_only",
        "Local only",
        "refuse any server address outside loopback / private / link-local networks",
        Kind::Bool,
        a.local_only.to_string(),
        Some("FAT_ASK_LOCAL_ONLY"),
    );
    push(
        "ask",
        "detail",
        "Detail",
        "minimal: no command lines, paths cut to two parts, hostnames replaced",
        Kind::Choice(DETAILS),
        if a.detail.is_empty() { "full".into() } else { a.detail.clone() },
        Some("FAT_ASK_DETAIL"),
    );
    push(
        "ask",
        "memory",
        "Memory",
        "send excerpts of recent threads on this host with a question",
        Kind::Bool,
        a.memory.to_string(),
        None,
    );
    push(
        "ask",
        "keep_days",
        "Keep threads (days)",
        "delete threads untouched this long; 0 = keep",
        Kind::Number(0, 3650),
        n(a.keep_days as u64),
        None,
    );
    push(
        "ask",
        "context_bytes",
        "Digest size (bytes)",
        "0 = 20000; about 6000 for CPU-only or small models",
        Kind::Number(0, 1_000_000),
        n(a.context_bytes as u64),
        None,
    );
    push(
        "ask",
        "num_ctx",
        "Ollama context (tokens)",
        "0 = sized to the digest",
        Kind::Number(0, 1_048_576),
        n(a.num_ctx as u64),
        None,
    );
    push(
        "ask",
        "timeout_s",
        "Timeout (s)",
        "0 = 90 for anthropic, 300 for self-hosted",
        Kind::Number(0, 3600),
        n(a.timeout_s),
        None,
    );
    push(
        "",
        "history_days",
        "Keep history (days)",
        "flight-recorder retention; a running `fat record` picks it up when restarted",
        Kind::Number(1, 3650),
        n(cfg.history_days as u64),
        None,
    );
    push(
        "",
        "interval_ms",
        "Sample interval (ms)",
        "TUI and recorder; applies the next time they start",
        Kind::Number(100, 600_000),
        n(cfg.interval_ms),
        None,
    );
    push(
        "",
        "history_path",
        "History file",
        "history_path in the config file",
        Kind::ReadOnly,
        crate::history::History::resolve(cfg.history_path.as_deref()).display().to_string(),
        None,
    );
    push(
        "server",
        "profile",
        "Profile",
        "[server] profile (auto | desktop | server) or FAT_PROFILE",
        Kind::ReadOnly,
        cfg.server.profile.clone(),
        Some("FAT_PROFILE"),
    );
    push(
        "fleet",
        "concurrency",
        "Fleet: parallel ssh",
        "[fleet] concurrency",
        Kind::ReadOnly,
        n(cfg.fleet.concurrency as u64),
        None,
    );
    push(
        "fleet",
        "command_timeout_s",
        "Fleet: command timeout (s)",
        "[fleet] command_timeout_s",
        Kind::ReadOnly,
        n(cfg.fleet.command_timeout_s),
        None,
    );
    let allowed = crate::mcp::allowed_actions(file_text);
    push(
        "mcp",
        "allow_actions",
        "Agents may act",
        "[mcp] allow_actions: side-effect tools agents may use; edit the file deliberately",
        Kind::ReadOnly,
        if allowed.is_empty() { "nothing (read-only)".into() } else { allowed.join(", ") },
        None,
    );
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

/// Parse `input` for `f` into a TOML value, or say what is wrong.
pub fn parse_input(f: &Field, input: &str) -> Result<toml_edit::Value, String> {
    let t = input.trim();
    match &f.kind {
        Kind::Bool => match t {
            "true" | "on" | "yes" | "1" => Ok(true.into()),
            "false" | "off" | "no" | "0" => Ok(false.into()),
            _ => Err(format!("{}: true or false", f.label)),
        },
        Kind::Choice(opts) => {
            if opts.contains(&t) {
                Ok(t.into())
            } else {
                Err(format!("{}: one of {}", f.label, opts.join(", ")))
            }
        }
        Kind::Number(lo, hi) => match t.parse::<u64>() {
            Ok(v) if v >= *lo && v <= *hi => Ok((v as i64).into()),
            _ => Err(format!("{}: a whole number from {lo} to {hi}", f.label)),
        },
        Kind::Text => {
            if f.key == "url" && !t.is_empty() && !(t.starts_with("http://") || t.starts_with("https://")) {
                return Err("Server URL: must start with http:// or https://".into());
            }
            if t.contains('\n') {
                return Err(format!("{}: one line", f.label));
            }
            Ok(t.into())
        }
        Kind::ReadOnly => Err(format!("{}: {}", f.label, f.help)),
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
    let new_text = edit(&text, section, key, value)?;
    let cfg = Config::parse(&new_text).map_err(|e| anyhow::anyhow!("the change would make the config invalid: {e}"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Write next to it and rename: a crash never leaves half a config. Keep its permissions.
    let tmp = path.with_extension("toml.fat-tmp");
    std::fs::write(&tmp, &new_text).with_context(|| format!("writing {}", tmp.display()))?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(cfg)
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
        assert!(get("provider").editable() && !get("allow_actions").editable());
        assert_eq!(get("allow_actions").value, "nothing (read-only)");
        assert_eq!(get("provider").group(), "Ask: the model");
        assert_eq!(get("history_days").group(), "Recording");
        let _ = no_env("x");
    }

    #[test]
    fn inputs_are_checked() {
        let f = fields(&Config::default(), "", &no_env);
        let get = |k: &str| f.iter().find(|x| x.key == k).unwrap();
        assert_eq!(parse_input(get("keep_days"), "30").unwrap().as_integer(), Some(30));
        assert!(parse_input(get("keep_days"), "-1").is_err());
        assert!(parse_input(get("interval_ms"), "10").unwrap_err().contains("100"));
        assert!(parse_input(get("url"), "llm:11434").unwrap_err().contains("http://"));
        assert_eq!(parse_input(get("url"), "").unwrap().as_str(), Some(""));
        assert_eq!(parse_input(get("provider"), "ollama").unwrap().as_str(), Some("ollama"));
        assert!(parse_input(get("provider"), "gpt").is_err());
        assert_eq!(parse_input(get("memory"), "off").unwrap().as_bool(), Some(false));
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
}
