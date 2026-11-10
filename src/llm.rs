//! Where `fat ask` sends its question, and how to talk to it.
//!
//! Three providers:
//! - "anthropic": the Claude Messages API (default; needs ANTHROPIC_API_KEY).
//! - "openai": any server speaking the OpenAI chat-completions API: LM Studio, vLLM,
//!   llama.cpp's server, LocalAI, LiteLLM, Ollama's /v1. Key optional.
//! - "ollama": Ollama's own /api/chat, so the context window (`num_ctx`) can be sized to the
//!   digest. Through /v1 Ollama keeps its small default window and silently drops most of it.
//!
//! Settings come from `[ask]` in the config, overridden by FAT_ASK_PROVIDER, FAT_ASK_URL,
//! FAT_ASK_MODEL, FAT_ASK_LOCAL_ONLY and FAT_ASK_DETAIL. The key is only ever read from the
//! environment variable `key_env` names.
//!
//! `local_only` is enforced where the connection is made: the name is resolved and every
//! address must be loopback, private (RFC 1918, CGNAT 100.64/10, IPv6 ULA) or link-local, or
//! nothing is sent. Redirects are not followed.
use crate::config::AskCfg;
use serde_json::{Value, json};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

pub const DEFAULT_CLAUDE_MODEL: &str = "claude-opus-5-5";
pub const DEFAULT_CONTEXT_BYTES: usize = 20_000;
/// Room in the model's window for the system prompt and the answer, in tokens.
const PROMPT_TOKENS: usize = 1_200;
const ANSWER_TOKENS: usize = 4_096;
/// Digest bytes per token: the JSON (numbers, pids, short keys) measured at ~2.2 on a
/// Qwen tokenizer; 2 keeps a margin.
const BYTES_PER_TOKEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Anthropic,
    OpenAi,
    Ollama,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAi => "openai",
            Provider::Ollama => "ollama",
        }
    }
}

/// A resolved destination for `ask`.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub provider: Provider,
    /// Full request URL.
    pub url: String,
    pub model: String,
    pub key: Option<String>,
    /// Which environment variable the key comes from (for messages).
    pub key_env: String,
    pub local_only: bool,
    pub minimal: bool,
    /// Digest size bound, bytes.
    pub context_bytes: usize,
    /// Ollama only: the context window to request.
    pub num_ctx: u32,
    pub timeout: Duration,
}

/// `[ask]` with the FAT_ASK_* environment overrides applied.
pub fn settings(cfg: &AskCfg) -> AskCfg {
    settings_with(cfg, |k| std::env::var(k).ok())
}

fn settings_with(cfg: &AskCfg, env: impl Fn(&str) -> Option<String>) -> AskCfg {
    let mut c = cfg.clone();
    let get = |k: &str| env(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    if let Some(v) = get("FAT_ASK_PROVIDER") {
        c.provider = v;
    }
    if let Some(v) = get("FAT_ASK_URL") {
        c.url = v;
    }
    if let Some(v) = get("FAT_ASK_MODEL") {
        c.model = v;
    }
    if let Some(v) = get("FAT_ASK_DETAIL") {
        c.detail = v;
    }
    if let Some(v) = get("FAT_ASK_LOCAL_ONLY") {
        c.local_only = matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
    }
    c
}

/// Resolve the settings into an endpoint. Errors are configuration mistakes, worded for the
/// user ("[ask] provider = \"ollama\" needs url").
pub fn resolve(cfg: &AskCfg) -> Result<Endpoint, String> {
    resolve_with(&settings(cfg), |k| std::env::var(k).ok())
}

fn resolve_with(c: &AskCfg, env: impl Fn(&str) -> Option<String>) -> Result<Endpoint, String> {
    let provider = match c.provider.trim().to_ascii_lowercase().as_str() {
        "" | "anthropic" | "claude" => Provider::Anthropic,
        "openai" | "openai-compatible" | "lmstudio" | "lm-studio" | "vllm" | "llamacpp" | "llama.cpp" => {
            Provider::OpenAi
        }
        "ollama" => Provider::Ollama,
        other => return Err(format!("[ask] provider = \"{other}\" is not known (anthropic, openai or ollama)")),
    };
    let base = c.url.trim().trim_end_matches('/').to_string();
    let base = match provider {
        Provider::Anthropic if base.is_empty() => env("ANTHROPIC_BASE_URL")
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "https://api.anthropic.com".into()),
        _ if base.is_empty() => {
            return Err(format!(
                "[ask] provider = \"{}\" needs url (or FAT_ASK_URL), e.g. http://HOST:PORT",
                provider.name()
            ));
        }
        _ => base,
    };
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(format!("[ask] url must start with http:// or https:// (got {base})"));
    }
    let url = match provider {
        Provider::Anthropic => format!("{base}/v1/messages"),
        Provider::Ollama => {
            if base.ends_with("/api/chat") {
                base.clone()
            } else {
                format!("{}/api/chat", base.trim_end_matches("/api"))
            }
        }
        Provider::OpenAi => {
            if base.ends_with("/chat/completions") {
                base.clone()
            } else if base.ends_with("/v1") {
                format!("{base}/chat/completions")
            } else {
                format!("{base}/v1/chat/completions")
            }
        }
    };
    let model = match (provider, c.model.trim()) {
        (Provider::Anthropic, "") => DEFAULT_CLAUDE_MODEL.to_string(),
        (_, "") => return Err(format!("[ask] provider = \"{}\" needs model (or FAT_ASK_MODEL)", provider.name())),
        (_, m) => m.to_string(),
    };
    let key_env = match (provider, c.key_env.trim()) {
        (Provider::Anthropic, "") => "ANTHROPIC_API_KEY".to_string(),
        (_, "") => "FAT_ASK_KEY".to_string(),
        (_, k) => k.to_string(),
    };
    let key = env(&key_env).map(|k| k.trim().to_string()).filter(|k| !k.is_empty());
    let minimal = match c.detail.trim().to_ascii_lowercase().as_str() {
        "" | "full" => false,
        "minimal" => true,
        other => return Err(format!("[ask] detail = \"{other}\" is not known (full or minimal)")),
    };
    let mut context_bytes = if c.context_bytes > 0 { c.context_bytes.max(2_000) } else { DEFAULT_CONTEXT_BYTES };
    let mut num_ctx = 0;
    if provider == Provider::Ollama {
        if c.num_ctx > 0 {
            // A fixed window: shrink the digest to fit it.
            num_ctx = c.num_ctx.max(2_048);
            let room = (num_ctx as usize).saturating_sub(PROMPT_TOKENS + ANSWER_TOKENS) * BYTES_PER_TOKEN;
            context_bytes = context_bytes.min(room.max(2_000));
        } else {
            let tokens = context_bytes / BYTES_PER_TOKEN + PROMPT_TOKENS + ANSWER_TOKENS;
            num_ctx = (tokens.div_ceil(1024) * 1024).max(8_192) as u32;
        }
    }
    let timeout = Duration::from_secs(match (c.timeout_s, provider) {
        (0, Provider::Anthropic) => 90,
        (0, _) => 300,
        (t, _) => t,
    });
    Ok(Endpoint {
        provider,
        url,
        model,
        key,
        key_env,
        local_only: c.local_only,
        minimal,
        context_bytes,
        num_ctx,
        timeout,
    })
}

impl Endpoint {
    /// Whether `ask` can use this endpoint (the Anthropic API needs a key; self-hosted
    /// servers may not).
    pub fn usable(&self) -> bool {
        self.provider != Provider::Anthropic || self.key.is_some()
    }

    /// "ollama · qwen3:32b · http://llm.internal:11434 · local only", without credentials.
    pub fn describe(&self) -> String {
        let mut s = format!("{} · {} · {}", self.provider.name(), self.model, origin(&self.url));
        if self.local_only {
            s.push_str(" · local only");
        }
        if self.minimal {
            s.push_str(" · minimal detail");
        }
        s
    }

    /// Request body for the OpenAI-compatible and Ollama APIs (the Anthropic body is built
    /// by `ask`, which owns the Messages API specifics).
    pub fn body(&self, system: &str, conversation: Vec<Value>) -> Value {
        let mut messages = vec![json!({"role": "system", "content": system})];
        messages.extend(conversation);
        match self.provider {
            Provider::Ollama => json!({
                "model": self.model,
                "messages": messages,
                "stream": false,
                // Reasoning models would otherwise think at length first: minutes on a CPU.
                "think": false,
                "options": {"num_ctx": self.num_ctx, "temperature": 0.2, "num_predict": ANSWER_TOKENS},
            }),
            _ => json!({
                "model": self.model,
                "messages": messages,
                "stream": false,
                "temperature": 0.2,
                "max_tokens": ANSWER_TOKENS,
            }),
        }
    }

    /// POST `body` and return the answer text.
    pub fn send(&self, body: &str, extra_headers: &[(&str, &str)]) -> Result<String, String> {
        let who = self.describe();
        let mut b = ureq::AgentBuilder::new().timeout(self.timeout).redirects(0);
        if self.local_only {
            b = b.resolver(LocalOnly);
        }
        let mut req = b.build().post(&self.url).set("content-type", "application/json");
        if let Some(k) = &self.key {
            req = match self.provider {
                Provider::Anthropic => req.set("x-api-key", k),
                _ => req.set("authorization", &format!("Bearer {k}")),
            };
        }
        for (h, v) in extra_headers {
            req = req.set(h, v);
        }
        match req.send_string(body) {
            Ok(r) => {
                let v: Value = r.into_json().map_err(|e| format!("{who} returned unreadable JSON: {e}"))?;
                match self.provider {
                    Provider::Anthropic => crate::ask::parse_response(&v),
                    Provider::OpenAi => parse_openai(&v),
                    Provider::Ollama => parse_ollama(&v),
                }
            }
            Err(ureq::Error::Status(code, r)) => {
                let text = r.into_string().unwrap_or_default();
                Err(match self.provider {
                    Provider::Anthropic => crate::ask::http_error_message(code, &text),
                    _ => status_message(&who, code, &text),
                })
            }
            Err(ureq::Error::Transport(t)) => {
                let why = t.to_string();
                if self.local_only && why.contains(LOCAL_ONLY_REFUSAL) {
                    Err(format!(
                        "refused to send: {} resolves outside private networks and [ask] local_only is set",
                        origin(&self.url)
                    ))
                } else {
                    Err(format!("Could not reach {who}: {why}"))
                }
            }
        }
    }
}

/// What `ask` would use, for the TUI and CLI to show before anything is sent.
pub fn destination(cfg: &AskCfg) -> String {
    match resolve(cfg) {
        Ok(ep) if !cfg.enabled => format!("offline ([ask] enabled = false; would use {})", ep.describe()),
        Ok(ep) if ep.usable() => ep.describe(),
        Ok(ep) => format!("offline ({} is not set)", ep.key_env),
        Err(e) => format!("offline ({e})"),
    }
}

/// scheme://host[:port], credentials dropped.
pub fn origin(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if scheme.is_empty() { host.to_string() } else { format!("{scheme}://{host}") }
}

const LOCAL_ONLY_REFUSAL: &str = "fat-local-only";

/// Resolves like the system does, then refuses unless every address is local.
struct LocalOnly;

impl ureq::Resolver for LocalOnly {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
        if addrs.is_empty() || addrs.iter().any(|a| !is_local(a.ip())) {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, LOCAL_ONLY_REFUSAL));
        }
        Ok(addrs)
    }
}

/// Loopback, private (RFC 1918, CGNAT 100.64.0.0/10, IPv6 ULA fc00::/7) or link-local.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback() || v.is_private() || v.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_local(IpAddr::V4(v4));
            }
            let s = v.segments();
            v.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Reasoning models put their scratch work in <think>…</think>; the answer is what follows.
fn strip_think(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(a) = out.find("<think>") {
        match out[a..].find("</think>") {
            Some(b) => out.replace_range(a..a + b + "</think>".len(), ""),
            None => out.truncate(a),
        }
    }
    out.trim().to_string()
}

fn finish(text: &str, truncated: bool, who: &str) -> Result<String, String> {
    let mut answer = strip_think(text);
    if answer.is_empty() {
        return Err(format!("{who} returned no answer text"));
    }
    if truncated {
        answer.push_str("\n\n[answer truncated]");
    }
    Ok(answer)
}

fn parse_openai(v: &Value) -> Result<String, String> {
    if let Some(e) = v.get("error") {
        let msg = e.get("message").and_then(Value::as_str).or_else(|| e.as_str()).unwrap_or("unknown error");
        return Err(format!("the model server reported an error: {msg}"));
    }
    let choice = v.pointer("/choices/0").ok_or("the model server returned no choices")?;
    let text = choice.pointer("/message/content").and_then(Value::as_str).unwrap_or("");
    let truncated = choice.get("finish_reason").and_then(Value::as_str) == Some("length");
    let reasoned = ["/message/reasoning", "/message/reasoning_content"]
        .iter()
        .any(|p| choice.pointer(p).and_then(Value::as_str).is_some_and(|r| !r.trim().is_empty()));
    if strip_think(text).is_empty() && truncated && reasoned {
        return Err("the model used its whole answer budget reasoning and gave no answer; use a non-reasoning \
                    model, or for Ollama set provider = \"ollama\" (fat turns thinking off there)"
            .into());
    }
    finish(text, truncated, "the model server")
}

fn parse_ollama(v: &Value) -> Result<String, String> {
    if let Some(msg) = v.get("error").and_then(Value::as_str) {
        return Err(format!("ollama reported an error: {msg}"));
    }
    let text = v.pointer("/message/content").and_then(Value::as_str).unwrap_or("");
    let truncated = v.get("done_reason").and_then(Value::as_str) == Some("length");
    finish(text, truncated, "ollama")
}

fn status_message(who: &str, code: u16, body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let msg = v
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| v.get("error").and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_else(|| body.chars().take(200).collect());
    let hint = match code {
        401 | 403 => " (check the key in the variable [ask] key_env names)",
        404 => " (check [ask] url and that the model is installed on the server)",
        _ => "",
    };
    format!("{who}: HTTP {code}: {}{hint}", if msg.is_empty() { "no details".into() } else { msg })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(provider: &str, url: &str, model: &str) -> AskCfg {
        AskCfg { provider: provider.into(), url: url.into(), model: model.into(), ..AskCfg::default() }
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn providers_resolve_to_their_endpoints() {
        let ep = resolve_with(&AskCfg::default(), no_env).unwrap();
        assert_eq!(
            (ep.provider, ep.url.as_str(), ep.model.as_str()),
            (Provider::Anthropic, "https://api.anthropic.com/v1/messages", DEFAULT_CLAUDE_MODEL)
        );
        assert!(!ep.usable(), "anthropic without a key answers offline");
        let ep = resolve_with(&AskCfg::default(), |k| (k == "ANTHROPIC_API_KEY").then(|| "sk".into())).unwrap();
        assert!(ep.usable());

        for (url, want) in [
            ("http://h:1234", "http://h:1234/v1/chat/completions"),
            ("http://h:1234/v1/", "http://h:1234/v1/chat/completions"),
            ("https://h/openai/v1/chat/completions", "https://h/openai/v1/chat/completions"),
        ] {
            let ep = resolve_with(&cfg("openai", url, "m"), no_env).unwrap();
            assert_eq!(ep.url, want);
            assert!(ep.usable() && ep.key.is_none(), "self-hosted needs no key");
        }
        for url in ["http://h:11434", "http://h:11434/api", "http://h:11434/api/chat"] {
            assert_eq!(resolve_with(&cfg("ollama", url, "m"), no_env).unwrap().url, "http://h:11434/api/chat");
        }
        let ep = resolve_with(&cfg("lmstudio", "http://h:1234", "m"), |k| (k == "FAT_ASK_KEY").then(|| " k ".into()))
            .unwrap();
        assert_eq!((ep.provider, ep.key.as_deref()), (Provider::OpenAi, Some("k")));
    }

    #[test]
    fn configuration_mistakes_are_explained() {
        assert!(resolve_with(&cfg("ollama", "", "m"), no_env).unwrap_err().contains("needs url"));
        assert!(resolve_with(&cfg("openai", "http://h", ""), no_env).unwrap_err().contains("needs model"));
        assert!(resolve_with(&cfg("gpt", "http://h", "m"), no_env).unwrap_err().contains("not known"));
        assert!(resolve_with(&cfg("openai", "h:1234", "m"), no_env).unwrap_err().contains("http://"));
        let mut c = cfg("openai", "http://h", "m");
        c.detail = "some".into();
        assert!(resolve_with(&c, no_env).unwrap_err().contains("full or minimal"));
    }

    #[test]
    fn env_overrides_the_config() {
        let env = |k: &str| match k {
            "FAT_ASK_PROVIDER" => Some("ollama".to_string()),
            "FAT_ASK_URL" => Some("http://10.0.0.5:11434".to_string()),
            "FAT_ASK_MODEL" => Some("m2".to_string()),
            "FAT_ASK_LOCAL_ONLY" => Some("true".to_string()),
            "FAT_ASK_DETAIL" => Some("minimal".to_string()),
            _ => None,
        };
        let c = settings_with(&cfg("openai", "http://x", "m1"), env);
        assert_eq!((c.provider.as_str(), c.url.as_str(), c.model.as_str()), ("ollama", "http://10.0.0.5:11434", "m2"));
        assert!(c.local_only && c.detail == "minimal");
        let c = settings_with(&cfg("openai", "http://x", "m1"), |k| (k == "FAT_ASK_URL").then(|| "  ".into()));
        assert_eq!(c.url, "http://x", "blank env values are ignored");
    }

    #[test]
    fn ollama_context_window_fits_the_digest() {
        let ep = resolve_with(&cfg("ollama", "http://h:11434", "m"), no_env).unwrap();
        assert!(ep.num_ctx as usize >= DEFAULT_CONTEXT_BYTES / BYTES_PER_TOKEN + PROMPT_TOKENS + ANSWER_TOKENS);
        assert_eq!(ep.num_ctx % 1024, 0);
        assert_eq!(ep.body("s", vec![json!({"role": "user", "content": "u"})])["options"]["num_ctx"], ep.num_ctx);
        // A fixed small window shrinks the digest instead.
        let mut c = cfg("ollama", "http://h:11434", "m");
        c.num_ctx = 8192;
        let ep = resolve_with(&c, no_env).unwrap();
        assert_eq!(ep.num_ctx, 8192);
        assert!(ep.context_bytes <= (8192 - PROMPT_TOKENS - ANSWER_TOKENS) * BYTES_PER_TOKEN, "{}", ep.context_bytes);
        let b = resolve_with(&cfg("openai", "http://h", "m"), no_env)
            .unwrap()
            .body("sys", vec![json!({"role": "user", "content": "usr"})]);
        assert_eq!(b["messages"][0]["role"], "system");
        assert_eq!(b["messages"][1]["content"], "usr");
        assert_eq!(b["stream"], false);
    }

    #[test]
    fn describe_never_shows_credentials() {
        let mut c = cfg("openai", "https://user:pw@llm.example:8443/v1", "m");
        c.local_only = true;
        let ep = resolve_with(&c, no_env).unwrap();
        assert_eq!(ep.describe(), "openai · m · https://llm.example:8443 · local only");
        assert_eq!(origin("http://127.0.0.1:11434/api/chat"), "http://127.0.0.1:11434");
    }

    #[test]
    fn local_networks() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_local(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "1.1.1.1", "2001:4860::8888", "::ffff:8.8.8.8"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip}");
        }
        use ureq::Resolver;
        assert!(LocalOnly.resolve("127.0.0.1:80").is_ok());
        assert!(LocalOnly.resolve("8.8.8.8:443").unwrap_err().to_string().contains(LOCAL_ONLY_REFUSAL));
    }

    #[test]
    fn local_only_refuses_public_addresses_before_sending() {
        let mut c = cfg("openai", "http://1.1.1.1:9/v1", "m");
        c.local_only = true;
        c.timeout_s = 2;
        let ep = resolve_with(&c, no_env).unwrap();
        let e = ep.send("{}", &[]).unwrap_err();
        assert!(e.contains("refused to send") && e.contains("local_only"), "{e}");
    }

    #[test]
    fn responses_parse_and_thinking_is_dropped() {
        let v =
            json!({"choices": [{"message": {"content": "<think>hmm</think>\n**Answer**"}, "finish_reason": "stop"}]});
        assert_eq!(parse_openai(&v).unwrap(), "**Answer**");
        let v = json!({"choices": [{"message": {"content": "partial"}, "finish_reason": "length"}]});
        assert!(parse_openai(&v).unwrap().ends_with("[answer truncated]"));
        assert!(
            parse_openai(&json!({"error": {"message": "model not found"}})).unwrap_err().contains("model not found")
        );
        assert!(parse_openai(&json!({"choices": []})).is_err());
        let v =
            json!({"choices": [{"message": {"content": "", "reasoning": "let me think"}, "finish_reason": "length"}]});
        assert!(parse_openai(&v).unwrap_err().contains("provider = \"ollama\""));
        let v = json!({"message": {"role": "assistant", "content": "ok"}, "done": true, "done_reason": "stop"});
        assert_eq!(parse_ollama(&v).unwrap(), "ok");
        assert!(parse_ollama(&json!({"error": "model 'x' not found"})).unwrap_err().contains("not found"));
        assert!(parse_ollama(&json!({"message": {"content": "<think>only thinking"}})).is_err());
        assert!(status_message("ollama", 404, r#"{"error":"model 'x' not found"}"#).contains("installed"));
    }
}
