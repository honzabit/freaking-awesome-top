//! Natural-language questions about the machine. OWNER: fleet agent.
//!
//! With `ANTHROPIC_API_KEY` set (and `[ask] enabled = true`), the question plus a compact JSON
//! digest of the snapshot goes to the Claude Messages API. Every string in that request is
//! redacted first ([`redact`]: API keys and tokens, password/token/secret arguments, URLs with
//! credentials, long hex/base64 blobs; the home directory becomes `~`, the user name "me").
//! `fat ask --dry-run` prints the exact body without sending it. Without a key, a rule-based
//! answerer assembles a reply from findings and top consumers.
use crate::model::{Finding, Proc, Snapshot};
use serde_json::{Value, json};
use std::time::Duration;

const API_VERSION: &str = "2026-10-21";
const API_BETA: &str = "server-side-fallback-2026-07-01";
const MAX_CONTEXT_BYTES: usize = 20_000;
const KEY_HINT: &str = "(set ANTHROPIC_API_KEY for richer answers)";

const SYSTEM_PROMPT: &str = "You are fat's diagnostic assistant. fat is a process monitor (like htop) \
for macOS and Linux. You receive a JSON digest of one machine snapshot (system summary, top processes \
by CPU, memory and estimated power, listening ports, and rule-based findings) followed by the user's \
question. Answer concisely and concretely from that data: name the processes responsible, with their \
pid and numbers. When an action would help, recommend fat commands such as `fat pause PID` \
(reversible SIGSTOP), `fat resume PID`, `fat renice PID 10`, `fat why PID`, `fat ports`, or \
`fat kill PID` (not undoable), preferring the undoable ones first. Only mention pids that appear in the data; never \
invent pids, processes or numbers. If the data cannot answer the question, say what is missing. \
Tailor advice to the operating system in system.os: macOS-only remedies (Spotlight, launchctl, Activity Monitor) \
do not apply on Linux, and Linux ones (systemctl, journalctl, cgroup limits, docker update) do not apply on macOS. \
Linux digests may add: system.psi (pressure stall information, avg10 % of time tasks waited on cpu, memory or io; \
above ~10% means real contention, and mem_full or io_full above a few % means the machine is thrashing), \
system.temp_c (hottest sensor), system.power_source (rapl = measured package energy, estimate = CPU-time model, \
rusage = macOS per-task energy), and per process `ctr` (the container it runs in) and `cgroup` (systemd unit or slice). \
Attribute load to containers or systemd units when the processes involved share one.";

/// Answer a question. Uses Claude API if ANTHROPIC_API_KEY is set (cfg.ask.enabled), else a
/// rule-based answer built from findings. Never panics; errors become explanatory text.
pub fn ask(question: &str, snap: &Snapshot, findings: &[Finding], cfg: &crate::config::AskCfg) -> String {
    let key = std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.trim().is_empty());
    match key {
        Some(key) if cfg.enabled => match call_claude(question, snap, findings, &cfg.model, key.trim()) {
            Ok(answer) => answer,
            Err(e) => format!("{e}\n\nOffline answer instead:\n{}", offline_answer(question, snap, findings)),
        },
        _ => offline_answer(question, snap, findings),
    }
}

// ---------- Claude API ----------

pub(crate) fn request_body(question: &str, context: &str, model: &str) -> Value {
    let model = if model.trim().is_empty() { "claude-opus-5-5" } else { model };
    let (home, user) = identity();
    let mut q = Value::String(question.trim().to_string());
    redact_value(&mut q, home.as_deref(), user.as_deref());
    let question = q.as_str().unwrap_or_default().to_string();
    json!({
        "model": model,
        "max_tokens": 16000,
        "fallbacks": "default",
        "output_config": { "effort": "low" },
        "system": SYSTEM_PROMPT,
        "messages": [{
            "role": "user",
            "content": format!("<snapshot>\n{context}\n</snapshot>\n\nQuestion: {question}"),
        }],
    })
}

/// The exact bytes `ask` would POST for this question (redacted; see [`redact`]).
pub fn request_json(question: &str, snap: &Snapshot, findings: &[Finding], model: &str) -> String {
    request_body(question, &build_context(snap, findings), model).to_string()
}

/// Where the request goes.
pub fn endpoint() -> String {
    let base = std::env::var("ANTHROPIC_BASE_URL").unwrap_or_else(|_| "https://api.anthropic.com".into());
    format!("{}/v1/messages", base.trim_end_matches('/'))
}

/// `fat ask --dry-run`: the request body that would be sent, and nothing is sent.
pub fn dry_run(question: &str, snap: &Snapshot, findings: &[Finding], cfg: &crate::config::AskCfg) -> (String, String) {
    let key = std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.trim().is_empty());
    let note = match (key.is_some(), cfg.enabled) {
        (true, true) => format!("dry run: this body would be POSTed to {} (headers x-api-key, anthropic-version {API_VERSION}); nothing was sent", endpoint()),
        (_, false) => "dry run: [ask] enabled = false, so `fat ask` answers offline and sends nothing; this is what it would send if enabled".to_string(),
        (false, true) => "dry run: ANTHROPIC_API_KEY is not set, so `fat ask` answers offline and sends nothing; this is what it would send with a key".to_string(),
    };
    (request_json(question, snap, findings, &cfg.model), note)
}

fn call_claude(question: &str, snap: &Snapshot, findings: &[Finding], model: &str, key: &str) -> Result<String, String> {
    // Sent as these exact bytes, so `fat ask --dry-run` shows precisely what leaves the machine.
    let body = request_json(question, snap, findings, model);
    let url = endpoint();
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(90)).build();
    let resp = agent
        .post(&url)
        .set("x-api-key", key)
        .set("anthropic-version", API_VERSION)
        .set("anthropic-beta", API_BETA)
        .set("content-type", "application/json")
        .send_string(&body);
    match resp {
        Ok(r) => {
            let v: Value = r.into_json().map_err(|e| format!("Claude API returned unreadable JSON: {e}"))?;
            parse_response(&v)
        }
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            Err(http_error_message(code, &text))
        }
        Err(ureq::Error::Transport(t)) => Err(format!("Could not reach the Claude API: {t}")),
    }
}

/// Turn a non-2xx response into "Claude API error 401 (authentication_error): invalid x-api-key".
pub(crate) fn http_error_message(code: u16, body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let msg = v.pointer("/error/message").and_then(Value::as_str);
    let kind = v.pointer("/error/type").and_then(Value::as_str);
    match (msg, kind) {
        (Some(m), Some(k)) => format!("Claude API error {code} ({k}): {m}"),
        (Some(m), None) => format!("Claude API error {code}: {m}"),
        _ => {
            let snippet: String = body.chars().take(200).collect();
            format!("Claude API error {code}: {}", if snippet.is_empty() { "no details" } else { &snippet })
        }
    }
}

/// Extract the answer from a Messages API response. Checks stop_reason first; keeps only
/// `text` blocks (thinking / fallback / other blocks are ignored).
pub(crate) fn parse_response(v: &Value) -> Result<String, String> {
    if let Some(msg) = v.pointer("/error/message").and_then(Value::as_str) {
        return Err(format!("Claude API error: {msg}"));
    }
    let stop = v.get("stop_reason").and_then(Value::as_str).unwrap_or("");
    if stop == "refusal" {
        let why = v.pointer("/stop_details/explanation").and_then(Value::as_str).unwrap_or("");
        let mut out = "Claude declined to answer this question.".to_string();
        if !why.is_empty() {
            out.push_str(&format!(" ({why})"));
        }
        out.push_str(" Try rephrasing, or unset ANTHROPIC_API_KEY for the offline answer.");
        return Ok(out);
    }
    let text: Vec<&str> = v
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let mut answer = text.join("").trim().to_string();
    if answer.is_empty() {
        return Err(format!("Claude returned no text (stop_reason: {})", if stop.is_empty() { "unknown" } else { stop }));
    }
    if stop == "max_tokens" {
        answer.push_str("\n\n[answer truncated]");
    }
    Ok(answer)
}

// ---------- context builder ----------

fn r1(x: f32) -> f64 {
    ((x as f64) * 10.0).round() / 10.0
}

fn mb(b: u64) -> f64 {
    ((b as f64) / 1_048_576.0 * 10.0).round() / 10.0
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n).collect::<String>()) }
}

// ---------- redaction ----------
//
// Everything in the request except fat's own system prompt is passed through [`redact`]:
// command lines, cwd and other paths, port notes, container names, findings, the question.

const MASK: &str = "***";

/// Whether a `key=value` / `--flag value` / `Header: value` name says the value is secret.
/// Judged per word part (split on `-`, `_`, `.`), so `--passphrase`, `BORG_PASSPHRASE`,
/// `PGPASSWORD`, `x-api-key` and `GITHUB_TOKEN` are secret while `--bypass-cache`, `--compass`,
/// `--author`, `--keychain` and `$PWD` (the working directory) are not.
fn secret_name(name: &str) -> bool {
    let raw = name.trim_start_matches('-');
    // The shell's working-directory variables, not a password.
    if raw == "PWD" || raw == "OLDPWD" {
        return false;
    }
    let l = raw.to_ascii_lowercase();
    // A file descriptor or file holding the secret is not the secret (`--passphrase-fd 0`).
    if l.is_empty() || l.ends_with("-fd") || l.ends_with("_fd") {
        return false;
    }
    // Words that end in these letters without being about secrets.
    const NOT_PASS: &[&str] = &["bypass", "compass", "encompass", "surpass", "trespass", "overpass", "underpass", "impass"];
    const NOT_KEY: &[&str] = &["monkey", "hotkey", "turkey", "donkey", "hockey", "jockey", "whiskey"];
    l.split(['-', '_', '.']).filter(|w| !w.is_empty()).any(|w| {
        const CONTAINS: &[&str] = &["token", "secret", "passw", "passphrase", "credential", "cookie", "signature", "apikey", "privatekey"];
        CONTAINS.iter().any(|c| w.contains(c))
            || matches!(w, "pw" | "pin" | "bearer" | "private")
            || w.starts_with("session")
            || (w.ends_with("pass") && !NOT_PASS.contains(&w))
            || (w.ends_with("pwd") && w != "cwd")
            || (w.ends_with("key") && !NOT_KEY.contains(&w))
            || (w.ends_with("auth") || (w.starts_with("auth") && !w.starts_with("author")) || w == "authorization")
    })
}

/// Short flags whose next argument is a password for one program: `sshpass -p X`,
/// `redis-cli -a X`. Elsewhere `-p 8080` is a port and `-a` means "all".
fn program_secret_flag(prog: &str, flag: &str) -> bool {
    matches!((prog, flag), ("sshpass", "-p") | ("redis-cli", "-a"))
}

/// Known credential shapes: provider API keys and tokens, AWS key ids, JWTs.
fn known_secret(w: &str) -> bool {
    const PREFIXES: [(&str, usize); 12] = [
        ("sk-", 16),
        ("ghp_", 20),
        ("gho_", 20),
        ("ghu_", 20),
        ("ghs_", 20),
        ("ghr_", 20),
        ("github_pat_", 20),
        ("glpat-", 16),
        ("npm_", 30),
        ("xoxb-", 10),
        ("xoxp-", 10),
        ("AIza", 30),
    ];
    let tail_ok = |t: &str, n: usize| t.len() >= n && t.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c));
    if PREFIXES.iter().any(|(p, n)| w.strip_prefix(p).is_some_and(|t| tail_ok(t, *n))) {
        return true;
    }
    // Slack: xoxa-, xoxr-, xoxs-, xapp-...
    if (w.starts_with("xox") || w.starts_with("xapp-")) && w.len() >= 15 && w.contains('-') {
        return true;
    }
    // AWS access key ids.
    if (w.starts_with("AKIA") || w.starts_with("ASIA")) && w.len() == 20 && w.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return true;
    }
    // JWT: three base64url parts, the first two starting with '{"' encoded.
    let parts: Vec<&str> = w.split('.').collect();
    if parts.len() == 3 && parts[0].starts_with("eyJ") && parts[1].starts_with("eyJ") && parts.iter().all(|p| !p.is_empty()) {
        return true;
    }
    false
}

/// A long opaque blob (hex or base64): probably a token, a key or a hash of one.
fn blob(w: &str) -> bool {
    let w = w.trim_end_matches('=');
    if w.len() < 32 || w.contains('.') {
        return false;
    }
    let hex = w.chars().all(|c| c.is_ascii_hexdigit());
    let b64 = w.chars().all(|c| c.is_ascii_alphanumeric() || "+/_-".contains(c))
        && w.chars().any(|c| c.is_ascii_digit())
        && w.chars().any(|c| c.is_ascii_alphabetic());
    hex || b64
}

/// Mask word-like runs inside one whitespace-free token.
fn mask_words(tok: &str) -> String {
    let is_word = |c: char| c.is_ascii_alphanumeric() || "-_.+=".contains(c);
    let mut out = String::with_capacity(tok.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            // `KEY=abc` keeps its key: only the value part is judged.
            let (head, val) = match word.split_once('=') {
                Some((k, v)) if !k.is_empty() => (format!("{k}="), v.to_string()),
                _ => (String::new(), word.clone()),
            };
            if known_secret(&val) || blob(&val) || known_secret(word) {
                out.push_str(&head);
                out.push_str(MASK);
            } else {
                out.push_str(word);
            }
            word.clear();
        }
    };
    for c in tok.chars() {
        if is_word(c) {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// `scheme://user:pass@host` -> `scheme://***@host`.
fn mask_userinfo(tok: &str) -> String {
    let Some(i) = tok.find("://") else { return tok.to_string() };
    let rest = &tok[i + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..end].rfind('@') {
        Some(at) => format!("{}{MASK}{}", &tok[..i + 3], &rest[at..]),
        None => tok.to_string(),
    }
}

/// `a=1&token=x;password=y` style pairs inside a token: mask the secret ones' values.
fn mask_pairs(tok: &str) -> String {
    let mut out = String::with_capacity(tok.len());
    let mut rest = tok;
    while let Some(eq) = rest.find(['=', ':']) {
        let (before, after) = rest.split_at(eq);
        let sep = &after[..1];
        let after = &after[1..];
        // The key is the trailing name-like run before the separator.
        let kstart = before.rfind(|c: char| !(c.is_ascii_alphanumeric() || "-_.".contains(c))).map_or(0, |i| i + 1);
        let key = &before[kstart..];
        let vend = after.find(['&', ';', ',', '"', '\'', ' ', ')', ']', '}']).unwrap_or(after.len());
        let value = &after[..vend];
        out.push_str(before);
        out.push_str(sep);
        // ':' only counts for "Header:value" shapes, not URLs ("https://") or ports ("host:80").
        let pair = sep == "=" || !value.starts_with('/') && !value.chars().all(|c| c.is_ascii_digit());
        if pair && !value.is_empty() && secret_name(key) && value != MASK {
            out.push_str(MASK);
            rest = &after[vend..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Redact secrets from free text (a command line, a path, a note): API keys and tokens,
/// `password=` / `token=` style pairs, `--token X` / `--password X` / `-pX` arguments,
/// `Bearer X`, URLs with credentials, and long hex / base64 blobs.
pub(crate) fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut mask_next = false;
    let mut user_next = false;
    // Basename of the most recent program word (the first token, or one after `|`, `;`, `&&`, sudo, env).
    let mut prog = String::new();
    let mut want_prog = true;
    let mut i = 0;
    let b = text.as_bytes();
    while i < b.len() {
        // Copy whitespace as-is.
        let ws_end = text[i..].find(|c: char| !c.is_whitespace()).map_or(text.len(), |j| i + j);
        out.push_str(&text[i..ws_end]);
        i = ws_end;
        if i >= b.len() {
            break;
        }
        let end = text[i..].find(char::is_whitespace).map_or(text.len(), |j| i + j);
        let tok = &text[i..end];
        i = end;
        if want_prog && !tok.starts_with('-') && !tok.contains('=') {
            prog = tok.rsplit('/').next().unwrap_or(tok).to_string();
            want_prog = matches!(prog.as_str(), "sudo" | "env" | "exec" | "nohup" | "time" | "nice");
        } else if matches!(tok, "|" | ";" | "&&" | "||") {
            want_prog = true;
        }
        if mask_next {
            // "Authorization: Bearer X": the scheme stays, the credential after it goes.
            let scheme = ["bearer", "basic", "token", "digest"].contains(&tok.to_ascii_lowercase().trim_start_matches(['"', '\'']));
            if scheme {
                out.push_str(tok);
            } else {
                out.push_str(MASK);
                mask_next = false;
            }
            continue;
        }
        if user_next {
            // curl -u user:password
            user_next = false;
            if let Some((u, _)) = tok.split_once(':') {
                out.push_str(&format!("{u}:{MASK}"));
                continue;
            }
        }
        let lower = tok.to_ascii_lowercase();
        if lower == "bearer" || tok == "Basic" || tok == "Token" {
            out.push_str(tok);
            mask_next = true;
            continue;
        }
        if tok.starts_with('-') && !tok.contains('=') {
            if tok == "-u" || tok == "--user" {
                out.push_str(tok);
                user_next = true;
                continue;
            }
            if program_secret_flag(&prog, tok) {
                out.push_str(tok);
                mask_next = true;
                continue;
            }
            // mysql -pSECRET (attached). Ports (-p8080) and well-known flags that happen to
            // start with -p (find -print, cc -pthread) stay.
            const P_FLAGS: [&str; 12] = ["-print", "-print0", "-printf", "-prune", "-path", "-perm", "-pthread", "-pipe", "-pedantic", "-pie", "-pg", "-pic"];
            if tok.len() > 2 && tok.starts_with("-p") && !tok[2..].chars().all(|c| c.is_ascii_digit()) && !P_FLAGS.contains(&tok) {
                out.push_str("-p");
                out.push_str(MASK);
                continue;
            }
            if secret_name(tok) {
                out.push_str(tok);
                mask_next = true;
                continue;
            }
        }
        // "Authorization:" / "X-Api-Key:" header names: the value is the next token.
        if let Some(k) = tok.strip_suffix(':').or_else(|| tok.strip_suffix('=')).filter(|k| !k.is_empty())
            && secret_name(k.trim_start_matches(['"', '\'']))
        {
            out.push_str(tok);
            mask_next = true;
            continue;
        }
        out.push_str(&mask_words(&mask_pairs(&mask_userinfo(tok))));
    }
    out
}

/// Kept for callers that only redact command lines.
pub(crate) fn redact_cmd(cmd: &str) -> String {
    redact(cmd)
}

/// The home directory and user name to hide from requests (None if unknown).
fn identity() -> (Option<String>, Option<String>) {
    let home = dirs::home_dir().map(|h| h.to_string_lossy().trim_end_matches('/').to_string()).filter(|h| h.len() > 1);
    let user = std::env::var("USER").ok().or_else(|| std::env::var("LOGNAME").ok()).filter(|u| !u.is_empty());
    (home, user)
}

/// `text` with every occurrence of `word` that is not part of a longer alphanumeric run replaced.
fn replace_word(text: &str, word: &str, with: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(word) {
        let before = rest[..i].chars().next_back();
        let after = rest[i + word.len()..].chars().next();
        let bounded = !before.is_some_and(|c| c.is_alphanumeric()) && !after.is_some_and(|c| c.is_alphanumeric());
        out.push_str(&rest[..i]);
        out.push_str(if bounded { with } else { word });
        rest = &rest[i + word.len()..];
    }
    out.push_str(rest);
    out
}

/// Redact every string in a JSON value, replace the home directory with `~` and the user
/// name (as a whole value or a /Users/<name> or /home/<name> path part) with "me".
pub(crate) fn redact_value(v: &mut Value, home: Option<&str>, user: Option<&str>) {
    match v {
        Value::String(s) => {
            let mut t = redact(s);
            if let Some(h) = home {
                t = t.replace(h, "~");
            }
            if let Some(u) = user {
                if t == u {
                    t = "me".into();
                }
                for base in ["/Users/", "/home/"] {
                    t = t.replace(&format!("{base}{u}/"), &format!("{base}me/"));
                    if t.ends_with(&format!("{base}{u}")) {
                        let n = t.len() - u.len();
                        t.replace_range(n.., "me");
                    }
                }
                // Elsewhere (encoded paths like "-Users-alice-code"), as a whole word only, and
                // only for names long enough not to be a common word ("dev", "app").
                if u.len() >= 4 {
                    t = replace_word(&t, u, "me");
                }
            }
            *s = t;
        }
        Value::Array(a) => a.iter_mut().for_each(|x| redact_value(x, home, user)),
        Value::Object(o) => o.values_mut().for_each(|x| redact_value(x, home, user)),
        _ => {}
    }
}

fn proc_json(snap: &Snapshot, p: &Proc, cmd_len: usize) -> Value {
    proc_json_in(snap, &snap.containers, p, cmd_len)
}

/// Compact cgroup label: the systemd unit or slice that matters ("nginx.service",
/// "user@1000.service/app.slice/code.scope"), not the whole hierarchy.
fn cgroup_label(cg: &str) -> String {
    let parts: Vec<&str> = cg.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    match parts.as_slice() {
        [] => String::new(),
        [only] => only.to_string(),
        _ => {
            // Skip leading *.slice levels; keep from the first unit-ish component.
            let start = parts.iter().position(|s| !s.ends_with(".slice")).unwrap_or(parts.len() - 1);
            trunc(&parts[start..].join("/"), 60)
        }
    }
}

fn proc_json_in(snap: &Snapshot, containers: &[crate::model::Container], p: &Proc, cmd_len: usize) -> Value {
    let parent = snap.proc(p.ppid).map(|pp| pp.name.as_str()).unwrap_or("");
    let mut v = json!({
        "pid": p.pid,
        "name": trunc(&p.name, 40),
        "cpu": r1(p.cpu),
        "mem_mb": mb(p.mem),
        "power_mw": r1(p.power_mw),
        "user": p.user,
        "ppid": p.ppid,
        "parent": parent,
    });
    if cmd_len > 0 && !p.cmd.is_empty() {
        v["cmd"] = json!(trunc(&redact_cmd(&p.cmd), cmd_len));
    }
    if p.status == "T" {
        v["stopped"] = json!(true);
    }
    if let Some(id) = &p.container {
        v["ctr"] = json!(crate::fleet::container_label(containers, id));
    } else if cmd_len > 0 && !p.cgroup.is_empty() {
        let cg = cgroup_label(&p.cgroup);
        if !cg.is_empty() && cg != "init.scope" {
            v["cgroup"] = json!(cg);
        }
    }
    v
}

fn top_by<F: Fn(&Proc) -> f64>(snap: &Snapshot, n: usize, key: F) -> Vec<&Proc> {
    let mut v: Vec<&Proc> = snap.procs.iter().filter(|p| key(p) > 0.0).collect();
    v.sort_by(|a, b| key(b).partial_cmp(&key(a)).unwrap_or(std::cmp::Ordering::Equal));
    v.truncate(n);
    v
}

fn context_with(snap: &Snapshot, findings: &[Finding], scale: usize, cmd_len: usize) -> Value {
    let s = &snap.system;
    let lim = |n: usize| (n * scale / 4).max(1);
    let list = |ps: Vec<&Proc>| ps.into_iter().map(|p| proc_json(snap, p, cmd_len)).collect::<Vec<_>>();
    let ctr_procs = |c: &crate::model::Container| {
        snap.procs.iter().filter(|p| p.container.as_deref().is_some_and(|id| !c.id.is_empty() && (id.starts_with(&c.id) || c.id.starts_with(id)))).count()
    };
    let mut v = json!({
        "host": snap.host,
        "system": {
            "hostname": s.hostname, "os": s.os, "cpu_model": s.cpu_model, "cores": s.cores,
            "cpu_pct": r1(s.cpu), "load": s.load,
            "mem_used_mb": mb(s.mem_used), "mem_total_mb": mb(s.mem_total),
            "swap_used_mb": mb(s.swap_used), "swap_total_mb": mb(s.swap_total),
            "mem_pressure": s.mem_pressure, "thermal": s.thermal,
            "power_w": r1(s.power_mw / 1000.0),
            "battery_pct": s.battery_pct, "on_battery": s.on_battery,
            "gpus": s.gpus.iter().map(|g| json!({"name": g.name, "util": r1(g.util)})).collect::<Vec<_>>(),
            "net_rx_kbps": s.net_rx_bps / 1024, "net_tx_kbps": s.net_tx_bps / 1024,
            "disk_read_kbps": s.disk_read_bps / 1024, "disk_write_kbps": s.disk_write_bps / 1024,
            "uptime_s": s.uptime, "process_count": snap.procs.len(),
        },
        "top_cpu": list(top_by(snap, lim(25), |p| p.cpu as f64)),
        "top_mem": list(top_by(snap, lim(15), |p| p.mem as f64)),
        "top_power": list(top_by(snap, lim(10), |p| p.power_mw as f64)),
        "top_disk": list(top_by(snap, lim(5), |p| (p.disk_read_bps + p.disk_write_bps) as f64)),
        "top_net": list(top_by(snap, lim(5), |p| (p.net_rx_bps + p.net_tx_bps) as f64)),
        "ports": snap.ports.iter().take(lim(40)).map(|p| json!({
            "proto": p.proto, "addr": p.addr, "port": p.port, "pid": p.pid, "process": trunc(&p.process, 30),
            "orphan": p.orphan, "note": trunc(&p.note, 80),
        })).collect::<Vec<_>>(),
        "containers": snap.containers.iter().take(lim(20)).map(|c| {
            let mut cv = json!({
                "name": c.name, "image": trunc(&c.image, 50), "runtime": c.runtime, "cpu": r1(c.cpu), "mem_mb": mb(c.mem), "status": c.status,
            });
            let n = ctr_procs(c);
            if n > 0 {
                cv["id"] = json!(c.id);
                cv["procs"] = json!(n);
            }
            cv
        }).collect::<Vec<_>>(),
        "findings": findings.iter().take(lim(20)).map(|f| json!({
            "severity": f.severity, "title": f.title, "detail": trunc(&f.detail, 300), "pids": f.pids, "action": f.action,
        })).collect::<Vec<_>>(),
    });
    // Linux-only fields: added only when present so macOS digests stay as they were.
    if let Some(psi) = &s.psi {
        v["system"]["psi"] = json!({
            "cpu_some": r1(psi.cpu_some), "mem_some": r1(psi.mem_some), "mem_full": r1(psi.mem_full),
            "io_some": r1(psi.io_some), "io_full": r1(psi.io_full),
        });
    }
    if let Some(t) = s.temp_c {
        v["system"]["temp_c"] = json!(r1(t));
    }
    if !s.power_source.is_empty() {
        v["system"]["power_source"] = json!(s.power_source);
    }
    v
}

/// Compact JSON digest of the snapshot, kept under ~20KB by shrinking lists if needed.
/// Every string in it is redacted (secrets, home directory, user name) before it is measured.
pub fn build_context(snap: &Snapshot, findings: &[Finding]) -> String {
    let (home, user) = identity();
    let render = |mut v: Value| {
        redact_value(&mut v, home.as_deref(), user.as_deref());
        v.to_string()
    };
    for (scale, cmd_len) in [(4, 80), (4, 40), (3, 0), (2, 0), (1, 0)] {
        let s = render(context_with(snap, findings, scale, cmd_len));
        if s.len() <= MAX_CONTEXT_BYTES {
            return s;
        }
    }
    let s = render(context_with(snap, &findings[..findings.len().min(3)], 1, 0));
    s.chars().take(MAX_CONTEXT_BYTES).collect()
}

// ---------- offline answerer ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Topic {
    Cpu,
    Power,
    Memory,
    Ports,
    Disk,
    Network,
    Containers,
}

pub(crate) fn topics(question: &str) -> Vec<Topic> {
    let q = question.to_ascii_lowercase();
    let words: Vec<&str> = q.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| !w.is_empty()).collect();
    let has = |keys: &[&str]| words.iter().any(|w| keys.iter().any(|k| w.starts_with(k)));
    let mut t = Vec::new();
    if has(&["slow", "hot", "fan", "cpu", "lag", "heat", "thermal", "load", "busy", "sluggish", "spin"]) {
        t.push(Topic::Cpu);
    }
    if has(&["battery", "power", "energy", "drain", "watt", "charge"]) {
        t.push(Topic::Power);
    }
    if has(&["memory", "ram", "swap", "pressure", "leak", "mem"]) {
        t.push(Topic::Memory);
    }
    if has(&["port", "listen", "orphan", "server", "socket", "bind"]) {
        t.push(Topic::Ports);
    }
    if has(&["disk", "io", "write", "read", "storage", "ssd"]) {
        t.push(Topic::Disk);
    }
    if has(&["network", "net", "bandwidth", "upload", "download", "traffic", "internet"]) {
        t.push(Topic::Network);
    }
    if has(&["container", "docker", "podman", "pod", "k8s", "kubernetes", "cgroup", "compose", "nerdctl"]) {
        t.push(Topic::Containers);
    }
    t
}

fn human(b: u64) -> String {
    let f = b as f64;
    match b {
        0..=1023 => format!("{b}B"),
        1024..=1_048_575 => format!("{:.1}K", f / 1024.0),
        1_048_576..=1_073_741_823 => format!("{:.1}M", f / 1_048_576.0),
        _ => format!("{:.2}G", f / 1_073_741_824.0),
    }
}

fn proc_line(p: &Proc, metric: String) -> String {
    format!("  {:>7}  {:<24} {}", p.pid, trunc(&p.name, 24), metric)
}

/// Rule-based answer from findings + top consumers.
pub fn offline_answer(question: &str, snap: &Snapshot, findings: &[Finding]) -> String {
    let s = &snap.system;
    let mut topics = topics(question);
    let overview = topics.is_empty();
    if overview {
        topics = vec![Topic::Cpu, Topic::Memory];
    }
    let mut out = Vec::new();

    let mut sorted: Vec<&Finding> = findings.iter().collect();
    let rank = |f: &Finding| match f.severity.as_str() {
        "crit" => 0,
        "warn" => 1,
        _ => 2,
    };
    sorted.sort_by_key(|f| rank(f));
    if !sorted.is_empty() {
        out.push("What stands out:".to_string());
        for f in sorted.iter().take(6) {
            out.push(format!("  [{}] {} — {}", f.severity, f.title, f.detail));
            if let Some(a) = &f.action {
                out.push(format!("      → fat {a}"));
            }
        }
        out.push(String::new());
    }

    for t in &topics {
        match t {
            Topic::Cpu => {
                let thermal = match s.temp_c {
                    Some(t) if s.thermal.is_empty() || s.thermal == "unknown" => format!("{t:.0}°C"),
                    Some(t) => format!("{} ({t:.0}°C)", s.thermal),
                    None => or_unknown(&s.thermal).to_string(),
                };
                out.push(format!(
                    "CPU {:.0}% across {} cores, load {:.2} {:.2} {:.2}, thermal {thermal}.",
                    s.cpu, s.cores, s.load[0], s.load[1], s.load[2]
                ));
                if let Some(psi) = &s.psi {
                    out.push(format!("CPU pressure: tasks waited for a CPU {:.1}% of the last 10s{}.", psi.cpu_some, stall_hint(psi.cpu_some)));
                }
                push_top(&mut out, "Top CPU:", top_by(snap, 5, |p| p.cpu as f64), |p| format!("{:.1}% cpu", p.cpu));
            }
            Topic::Power => {
                let batt = match (s.battery_pct, s.on_battery) {
                    (Some(pct), Some(true)) => format!("on battery at {pct:.0}%"),
                    (Some(pct), _) => format!("battery {pct:.0}% (plugged in)"),
                    _ => "battery unknown".to_string(),
                };
                let what = match s.power_source.as_str() {
                    "rapl" => "Measured CPU package power (RAPL)",
                    "estimate" => "Estimated power (CPU-time model)",
                    _ => "Estimated process power",
                };
                out.push(format!("{what} {:.1} W, {batt}.", s.power_mw / 1000.0));
                push_top(&mut out, "Top power:", top_by(snap, 5, |p| p.power_mw as f64), |p| {
                    format!("{:.0} mW, {:.1}% cpu", p.power_mw, p.cpu)
                });
            }
            Topic::Memory => {
                out.push(format!(
                    "Memory {}/{} used, swap {}/{}, pressure {}.",
                    human(s.mem_used),
                    human(s.mem_total),
                    human(s.swap_used),
                    human(s.swap_total),
                    or_unknown(&s.mem_pressure)
                ));
                if let Some(psi) = &s.psi {
                    out.push(format!(
                        "Memory pressure: some tasks stalled {:.1}%, all tasks stalled {:.1}% of the last 10s{}.",
                        psi.mem_some,
                        psi.mem_full,
                        stall_hint(psi.mem_some.max(psi.mem_full * 4.0))
                    ));
                }
                push_top(&mut out, "Top memory:", top_by(snap, 5, |p| p.mem as f64), |p| format!("{} rss", human(p.mem)));
            }
            Topic::Ports => {
                let listening: Vec<_> = snap.ports.iter().filter(|p| p.state == "LISTEN" || p.state.is_empty()).collect();
                out.push(format!("{} listening sockets.", listening.len()));
                let orphans: Vec<_> = listening.iter().filter(|p| p.orphan).collect();
                if !orphans.is_empty() {
                    out.push(format!("{} look orphaned (dev servers whose parent went away):", orphans.len()));
                    for p in orphans.iter().take(8) {
                        out.push(format!("  :{:<6} pid {:<7} {}  {}", p.port, p.pid, p.process, p.note));
                    }
                    out.push(format!("  → pause one with `fat pause {}`, or see `fat ports`", orphans[0].pid));
                }
                for p in listening.iter().filter(|p| !p.orphan).take(10) {
                    out.push(format!("  :{:<6} pid {:<7} {}", p.port, p.pid, p.process));
                }
            }
            Topic::Disk => {
                out.push(format!("Disk read {}/s, write {}/s.", human(s.disk_read_bps), human(s.disk_write_bps)));
                if let Some(psi) = &s.psi {
                    out.push(format!("IO pressure: some tasks waited on io {:.1}%, all {:.1}% of the last 10s{}.", psi.io_some, psi.io_full, stall_hint(psi.io_some)));
                }
                push_top(&mut out, "Top disk:", top_by(snap, 5, |p| (p.disk_read_bps + p.disk_write_bps) as f64), |p| {
                    format!("r {}/s w {}/s", human(p.disk_read_bps), human(p.disk_write_bps))
                });
            }
            Topic::Network => {
                out.push(format!("Network in {}/s, out {}/s.", human(s.net_rx_bps), human(s.net_tx_bps)));
                push_top(&mut out, "Top network:", top_by(snap, 5, |p| (p.net_rx_bps + p.net_tx_bps) as f64), |p| {
                    format!("in {}/s out {}/s", human(p.net_rx_bps), human(p.net_tx_bps))
                });
            }
            Topic::Containers => container_section(&mut out, snap),
        }
        out.push(String::new());
    }

    if let Some(p) = top_by(snap, 1, |p| p.cpu as f64).first().filter(|p| p.cpu >= 50.0) {
        out.push(format!(
            "Suggestion: `fat why {}` to see what started {}; `fat pause {}` stops it reversibly (`fat resume {}`).",
            p.pid, p.name, p.pid, p.pid
        ));
    }
    out.push(KEY_HINT.to_string());
    out.join("\n")
}

fn stall_hint(pct: f32) -> &'static str {
    if pct >= 20.0 {
        " — heavy contention"
    } else if pct >= 5.0 {
        " — noticeable contention"
    } else {
        ""
    }
}

/// Containers and the host processes attributed to each (Linux cgroups).
fn container_section(out: &mut Vec<String>, snap: &Snapshot) {
    use std::collections::BTreeMap;
    let mut by_ctr: BTreeMap<String, (f32, u64, usize)> = BTreeMap::new();
    for p in &snap.procs {
        if let Some(id) = &p.container {
            let e = by_ctr.entry(crate::fleet::container_label(&snap.containers, id)).or_default();
            e.0 += p.cpu;
            e.1 += p.mem;
            e.2 += 1;
        }
    }
    if snap.containers.is_empty() && by_ctr.is_empty() {
        out.push("No containers found (no reachable docker / podman / nerdctl, and no process in a container cgroup).".into());
        return;
    }
    if !snap.containers.is_empty() {
        out.push(format!("{} running containers:", snap.containers.len()));
        let mut cs: Vec<_> = snap.containers.iter().collect();
        cs.sort_by(|a, b| b.cpu.total_cmp(&a.cpu));
        for c in cs.iter().take(10) {
            out.push(format!("  {:<24} {:>6.1}% cpu {:>8}  {} ({})", trunc(&c.name, 24), c.cpu, human(c.mem), trunc(&c.image, 40), c.runtime));
        }
    }
    if !by_ctr.is_empty() {
        let mut v: Vec<_> = by_ctr.into_iter().collect();
        v.sort_by(|a, b| b.1.0.total_cmp(&a.1.0));
        out.push("Host processes by container:".into());
        for (name, (cpu, mem, n)) in v.iter().take(10) {
            out.push(format!("  {:<24} {:>6.1}% cpu {:>8}  {n} procs", trunc(name, 24), cpu, human(*mem)));
        }
        out.push(format!("  → `fat snapshot --json` lists them; in the TUI type /{} to filter", v[0].0));
    }
}

fn or_unknown(s: &str) -> &str {
    if s.is_empty() { "unknown" } else { s }
}

fn push_top(out: &mut Vec<String>, title: &str, procs: Vec<&Proc>, metric: impl Fn(&Proc) -> String) {
    if procs.is_empty() {
        out.push(format!("{title} (no data)"));
        return;
    }
    out.push(title.to_string());
    for p in procs {
        out.push(proc_line(p, metric(p)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Port, Proto, System};

    fn snap() -> Snapshot {
        let mk = |pid, ppid, name: &str, cpu, mem, power| Proc {
            pid,
            ppid,
            name: name.into(),
            cpu,
            mem,
            power_mw: power,
            user: "me".into(),
            status: "R".into(),
            ..Default::default()
        };
        let mut procs = vec![mk(1, 0, "launchd", 0.1, 10 << 20, 1.0), mk(500, 1, "node", 180.0, 900 << 20, 4200.0)];
        procs[1].cmd = "node server.js --api-key sk-abc123 TOKEN=hunter2".into();
        for i in 0..200 {
            procs.push(mk(1000 + i, 500, &format!("worker{i}"), i as f32 / 10.0, (i as u64 + 1) << 20, i as f32));
        }
        Snapshot {
            host: "local".into(),
            system: System { cores: 12, cpu: 40.0, thermal: "fair".into(), mem_pressure: "warn".into(), ..Default::default() },
            procs,
            ports: vec![Port {
                proto: Proto::Tcp,
                addr: "127.0.0.1".into(),
                port: 5173,
                pid: 500,
                process: "node".into(),
                state: "LISTEN".into(),
                orphan: true,
                note: "vite dev server".into(),
            }],
            ..Default::default()
        }
    }

    fn findings() -> Vec<Finding> {
        vec![Finding {
            severity: "warn".into(),
            title: "node is burning 1.8 cores".into(),
            detail: "pid 500 for 20 min".into(),
            pids: vec![500],
            action: Some("pause 500".into()),
        }]
    }

    #[test]
    fn context_is_compact_and_limited() {
        let ctx = build_context(&snap(), &findings());
        assert!(ctx.len() <= MAX_CONTEXT_BYTES, "{}", ctx.len());
        let v: Value = serde_json::from_str(&ctx).unwrap();
        assert_eq!(v["top_cpu"].as_array().unwrap().len(), 25);
        assert_eq!(v["top_mem"].as_array().unwrap().len(), 15);
        assert_eq!(v["top_power"].as_array().unwrap().len(), 10);
        assert_eq!(v["top_cpu"][0]["pid"], 500);
        assert_eq!(v["top_cpu"][0]["parent"], "launchd");
        assert_eq!(v["ports"][0]["orphan"], true);
        assert_eq!(v["findings"][0]["action"], "pause 500");
        assert!(!ctx.contains("hunter2") && !ctx.contains("sk-abc123"));
    }

    #[test]
    fn context_shrinks_when_huge() {
        let mut s = snap();
        for p in s.procs.iter_mut() {
            p.name = "x".repeat(200);
            p.cmd = "y ".repeat(500);
        }
        let many: Vec<Finding> = (0..50).map(|_| Finding { detail: "z".repeat(400), ..findings()[0].clone() }).collect();
        assert!(build_context(&s, &many).len() <= MAX_CONTEXT_BYTES);
    }

    fn linux_snap() -> Snapshot {
        let mut s = snap();
        s.system.os = "Ubuntu 24.04".into();
        s.system.psi = Some(crate::model::Psi { cpu_some: 23.0, mem_some: 1.0, mem_full: 0.5, io_some: 7.0, io_full: 2.0 });
        s.system.temp_c = Some(81.0);
        s.system.thermal = String::new();
        s.system.power_source = "rapl".into();
        s.system.power_mw = 61_000.0;
        s.procs[1].cgroup = "/system.slice/docker-410892b21be2ffda.scope".into();
        s.procs[1].container = Some("410892b21be2".into());
        s.procs[2].cgroup = "/user.slice/user-1000.slice/user@1000.service/app.slice/code.scope".into();
        s.containers = vec![crate::model::Container { id: "410892b21be2".into(), name: "api-1".into(), image: "node:22".into(), runtime: "docker".into(), cpu: 180.0, ..Default::default() }];
        s
    }

    #[test]
    fn context_carries_linux_fields_compactly() {
        let ctx = build_context(&linux_snap(), &findings());
        let v: Value = serde_json::from_str(&ctx).unwrap();
        assert_eq!(v["system"]["psi"]["cpu_some"], 23.0);
        assert_eq!(v["system"]["temp_c"], 81.0);
        assert_eq!(v["system"]["power_source"], "rapl");
        assert_eq!(v["top_cpu"][0]["ctr"], "api-1");
        assert!(v["top_cpu"][0].get("cgroup").is_none(), "container procs skip the long cgroup");
        let w = v["top_cpu"].as_array().unwrap().iter().find(|p| p["pid"] == 1000).cloned();
        // worker0 has cpu 0 so it is not in top_cpu; check top_mem instead
        let w = w.or_else(|| v["top_mem"].as_array().unwrap().iter().find(|p| p["pid"] == 1000).cloned());
        if let Some(w) = w {
            assert_eq!(w["cgroup"], "user@1000.service/app.slice/code.scope");
        }
        assert_eq!(v["containers"][0]["procs"], 1);
        // macOS digest is unchanged: no Linux keys
        let m: Value = serde_json::from_str(&build_context(&snap(), &findings())).unwrap();
        assert!(m["system"].get("psi").is_none() && m["system"].get("temp_c").is_none() && m["system"].get("power_source").is_none());
        assert!(m["top_cpu"][0].get("ctr").is_none() && m["top_cpu"][0].get("cgroup").is_none());
    }

    #[test]
    fn cgroup_labels() {
        assert_eq!(cgroup_label("/system.slice/nginx.service"), "nginx.service");
        assert_eq!(cgroup_label("/user.slice/user-1000.slice/session-3.scope"), "session-3.scope");
        assert_eq!(cgroup_label("/init.scope"), "init.scope");
        assert_eq!(cgroup_label("/"), "");
        assert_eq!(cgroup_label("/a.slice/b.slice"), "b.slice");
    }

    #[test]
    fn offline_linux_answers_use_psi_and_containers() {
        let s = linux_snap();
        let a = offline_answer("why is the cpu so slow", &s, &[]);
        assert!(a.contains("CPU pressure") && a.contains("23.0%") && a.contains("heavy contention"), "{a}");
        assert!(a.contains("81°C"), "{a}");
        let a = offline_answer("battery power?", &s, &[]);
        assert!(a.contains("RAPL") && a.contains("61.0 W"), "{a}");
        let a = offline_answer("which docker container is busy", &s, &[]);
        assert!(a.contains("api-1") && a.contains("Host processes by container"), "{a}");
        assert!(topics("is a pod hogging io").contains(&Topic::Containers));
        // macOS answers keep their wording
        let m = offline_answer("battery power?", &snap(), &[]);
        assert!(m.contains("Estimated process power") && !m.contains("pressure:"));
    }

    #[test]
    fn redaction() {
        assert_eq!(redact_cmd("curl -H x --token abc PASSWORD=x run"), "curl -H x --token *** PASSWORD=*** run");
        assert_eq!(redact_cmd("ls -la /tmp"), "ls -la /tmp");
        let cases = [
            ("node app.js --api-key=sk-ant-api03-AbCdEfGhIjKlMnOpQrSt", "node app.js --api-key=***"),
            ("git clone https://ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/x/y", "git clone https://***@github.com/x/y"),
            ("psql postgres://admin:s3cr3t@db:5432/app", "psql postgres://***@db:5432/app"),
            ("mysql -uroot -phunter2 db", "mysql -uroot -p*** db"),
            ("mysql --password hunter2", "mysql --password ***"),
            ("curl -u bob:hunter2 -H Authorization: Bearer abc.def", "curl -u bob:*** -H Authorization: Bearer ***"),
            ("curl -H 'Authorization: Bearer xyz123'", "curl -H 'Authorization: Bearer ***"),
            ("env AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE x", "env AWS_SECRET_ACCESS_KEY=*** AWS_ACCESS_KEY_ID=*** x"),
            ("bot --slack xoxb-1234567890-abcdefghij", "bot --slack ***"),
            ("gh --with github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "gh --with ***"),
            ("app --jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "app --jwt ***"),
            ("wget https://x.io/f?a=1&token=abc123&b=2", "wget https://x.io/f?a=1&token=***&b=2"),
            ("run --session-id 0123456789abcdef0123456789abcdef", "run --session-id ***"),
            ("sha 0123456789abcdef0123456789abcdef0123", "sha ***"),
            ("cc -pthread -O2 -p8080 x.c", "cc -pthread -O2 -p8080 x.c"),
            ("find . -print -prune", "find . -print -prune"),
            ("vite --port 5173 --host 0.0.0.0", "vite --port 5173 --host 0.0.0.0"),
            // Passphrases and program-specific short password flags.
            ("gpg --batch --passphrase hunterPHRASE1 -d f", "gpg --batch --passphrase *** -d f"),
            ("BORG_PASSPHRASE=borgSECRET2 borg create", "BORG_PASSPHRASE=*** borg create"),
            ("RESTIC_PASSWORD=r3st1c restic backup", "RESTIC_PASSWORD=*** restic backup"),
            ("sshpass -p sshSECRET3 ssh h", "sshpass -p *** ssh h"),
            ("/usr/bin/sshpass -p sshSECRET3 ssh h", "/usr/bin/sshpass -p *** ssh h"),
            ("redis-cli -a redisSECRET4 ping", "redis-cli -a *** ping"),
            ("PGPASS=x psql", "PGPASS=*** psql"),
            ("gpg --passphrase-fd 0 -d f", "gpg --passphrase-fd 0 -d f"),
            // Ports and "all" flags elsewhere stay.
            ("ssh -p 2222 host", "ssh -p 2222 host"),
            ("ls -a /tmp", "ls -a /tmp"),
            // Flags that only contain "pass", "auth" or "key" keep their values.
            ("x --bypass-cache foo", "x --bypass-cache foo"),
            ("x --compass foo", "x --compass foo"),
            ("git log --author bob", "git log --author bob"),
            ("security --keychain login", "security --keychain login"),
            ("PWD=/Users/x/code OLDPWD=/tmp sh", "PWD=/Users/x/code OLDPWD=/tmp sh"),
            ("curl -H x-api-key: k3y", "curl -H x-api-key: ***"),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), want, "{input}");
        }
    }

    #[test]
    fn built_request_never_contains_secrets() {
        let secrets = [
            "sk-ant-api03-SECRETSECRETSECRET01",
            "ghp_SECRETsecretSECRETsecret0123456",
            "hunter2pw",
            "AKIAZZZZZZZZZZZZZZZZ",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SIGNATURExyz",
            "s3cr3tpass",
            "xoxp-111-222-333-SECRETSLACK",
            "deadbeefdeadbeefdeadbeefdeadbeef00",
            "tok_in_url_123",
        ];
        let mut s = snap();
        s.procs[1].cmd = format!(
            "node server.js --api-key {} GITHUB_TOKEN={} --password {} -p{} https://u:{}@h/x",
            secrets[0], secrets[1], secrets[2], secrets[5], secrets[5]
        );
        s.procs[2].cmd = format!("aws s3 ls AWS_ACCESS_KEY_ID={} Authorization: Bearer {} {}", secrets[3], secrets[4], secrets[6]);
        s.procs[2].cpu = 500.0;
        s.ports[0].note = format!("vite dev · ~/code/app?token={} · {}", secrets[8], secrets[7]);
        s.containers = vec![crate::model::Container { name: "db".into(), image: format!("reg.io/x:{}", secrets[7]), status: "up".into(), ..Default::default() }];
        let f = vec![Finding {
            severity: "warn".into(),
            title: format!("node --password {} is hot", secrets[2]),
            detail: format!("cwd /tmp/x  cmd: curl -H 'Authorization: Bearer {}'", secrets[4]),
            pids: vec![500],
            action: Some("pause 500".into()),
        }];
        let q = format!("why is my key {} slow", secrets[0]);
        let body = request_json(&q, &s, &f, "claude-opus-5-5");
        for sec in secrets {
            if let Some(i) = body.find(sec) {
                panic!("{sec} leaked into the request: …{}…", &body[i.saturating_sub(120)..(i + 40).min(body.len())]);
            }
        }
        // Still useful: names, pids, the question's intent.
        assert!(body.contains("server.js") && body.contains(r#"pid\":500"#) && body.contains("slow"), "{body}");
        // dry run prints exactly that body and sends nothing (no key in tests).
        let (dry, note) = dry_run(&q, &s, &f, &crate::config::AskCfg::default());
        assert_eq!(dry, body);
        assert!(note.contains("dry run"), "{note}");
    }

    #[test]
    fn home_and_user_name_are_replaced() {
        let mut v = json!({"cwd": "/Users/alice/code/app", "user": "alice", "h": "/home/alice", "n": "alicex", "e": "/tmp/-Users-alice-x"});
        redact_value(&mut v, Some("/Users/alice"), Some("alice"));
        assert_eq!(v, json!({"cwd": "~/code/app", "user": "me", "h": "/home/me", "n": "alicex", "e": "/tmp/-Users-me-x"}));
    }

    #[test]
    fn body_shape() {
        let b = request_body("why slow?", "{}", "");
        assert_eq!(b["model"], "claude-opus-5-5");
        assert_eq!(b["max_tokens"], 16000);
        assert_eq!(b["fallbacks"], "default");
        assert_eq!(b["output_config"]["effort"], "low");
        assert!(b.get("thinking").is_none() && b.get("temperature").is_none());
        assert!(b["messages"][0]["content"].as_str().unwrap().ends_with("Question: why slow?"));
    }

    #[test]
    fn parses_text_ignoring_thinking() {
        let v: Value = serde_json::from_str(
            r#"{"stop_reason":"end_turn","content":[{"type":"thinking","thinking":"","signature":"x"},
            {"type":"text","text":"node (pid 500) "},{"type":"fallback","model":"m"},{"type":"text","text":"is the culprit."}]}"#,
        )
        .unwrap();
        assert_eq!(parse_response(&v).unwrap(), "node (pid 500) is the culprit.");
    }

    #[test]
    fn parses_refusal() {
        let v: Value = serde_json::from_str(
            r#"{"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"policy"},"content":[{"type":"text","text":"partial"}]}"#,
        )
        .unwrap();
        let out = parse_response(&v).unwrap();
        assert!(out.contains("declined") && out.contains("policy") && !out.contains("partial"));
    }

    #[test]
    fn parses_empty_and_errors() {
        let v: Value = serde_json::from_str(r#"{"stop_reason":"end_turn","content":[]}"#).unwrap();
        assert!(parse_response(&v).is_err());
        let m = http_error_message(401, r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#);
        assert_eq!(m, "Claude API error 401 (authentication_error): invalid x-api-key");
        assert!(http_error_message(502, "<html>bad gateway</html>").contains("502"));
    }

    #[test]
    fn topic_detection() {
        assert_eq!(topics("why is my fan so loud"), vec![Topic::Cpu]);
        assert_eq!(topics("what's draining my battery?"), vec![Topic::Power]);
        assert_eq!(topics("who is using port 5173"), vec![Topic::Ports]);
        assert!(topics("RAM usage").contains(&Topic::Memory));
        assert!(topics("what is going on").is_empty());
    }

    #[test]
    fn offline_answers() {
        let s = snap();
        let a = offline_answer("why is it slow", &s, &findings());
        assert!(a.contains("node is burning"));
        assert!(a.contains("fat pause 500"));
        assert!(a.contains("Top CPU"));
        assert!(a.trim_end().ends_with(KEY_HINT));
        let p = offline_answer("any orphan ports?", &s, &[]);
        assert!(p.contains("5173") && p.contains("orphaned"));
        let o = offline_answer("what's up", &s, &[]);
        assert!(o.contains("Top CPU") && o.contains("Top memory"));
    }

    #[test]
    fn ask_without_key_is_offline() {
        let cfg = crate::config::AskCfg { enabled: false, ..Default::default() };
        let a = ask("battery?", &snap(), &[], &cfg);
        assert!(a.contains(KEY_HINT));
    }
}
