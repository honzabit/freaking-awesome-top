//! Natural-language questions about the machine. OWNER: fleet agent.
//!
//! With `ANTHROPIC_API_KEY` set (and `[ask] enabled = true`), the question plus a compact JSON
//! digest of the snapshot goes to the Claude Messages API. Without a key, a rule-based answerer
//! assembles a reply from findings and top consumers.
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
`fat kill PID`, preferring reversible actions first. Only mention pids that appear in the data; never \
invent pids, processes or numbers. If the data cannot answer the question, say what is missing.";

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
    json!({
        "model": model,
        "max_tokens": 16000,
        "fallbacks": "default",
        "output_config": { "effort": "low" },
        "system": SYSTEM_PROMPT,
        "messages": [{
            "role": "user",
            "content": format!("<snapshot>\n{context}\n</snapshot>\n\nQuestion: {}", question.trim()),
        }],
    })
}

fn call_claude(question: &str, snap: &Snapshot, findings: &[Finding], model: &str, key: &str) -> Result<String, String> {
    let body = request_body(question, &build_context(snap, findings), model);
    let base = std::env::var("ANTHROPIC_BASE_URL").unwrap_or_else(|_| "https://api.anthropic.com".into());
    let url = format!("{}/v1/messages", base.trim_end_matches('/'));
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(90)).build();
    let resp = agent
        .post(&url)
        .set("x-api-key", key)
        .set("anthropic-version", API_VERSION)
        .set("anthropic-beta", API_BETA)
        .set("content-type", "application/json")
        .send_json(body);
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

/// Mask values that look like secrets before command lines leave the machine.
pub(crate) fn redact_cmd(cmd: &str) -> String {
    const SECRET: [&str; 7] = ["key", "token", "secret", "passw", "auth", "credential", "bearer"];
    let is_secret = |s: &str| {
        let l = s.to_ascii_lowercase();
        SECRET.iter().any(|w| l.contains(w))
    };
    let mut out = Vec::new();
    let mut mask_next = false;
    for tok in cmd.split_whitespace() {
        if mask_next {
            out.push("***".to_string());
            mask_next = false;
            continue;
        }
        if let Some((k, _)) = tok.split_once('=').filter(|(k, _)| is_secret(k)) {
            out.push(format!("{k}=***"));
        } else if tok.starts_with('-') && is_secret(tok) {
            out.push(tok.to_string());
            mask_next = true;
        } else if tok.len() >= 32 && tok.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)) && tok.chars().any(|c| c.is_ascii_digit()) {
            out.push("***".to_string()); // long opaque blob: probably a token
        } else {
            out.push(tok.to_string());
        }
    }
    out.join(" ")
}

fn proc_json(snap: &Snapshot, p: &Proc, cmd_len: usize) -> Value {
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
    json!({
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
        "containers": snap.containers.iter().take(lim(20)).map(|c| json!({
            "name": c.name, "image": trunc(&c.image, 50), "runtime": c.runtime, "cpu": r1(c.cpu), "mem_mb": mb(c.mem), "status": c.status,
        })).collect::<Vec<_>>(),
        "findings": findings.iter().take(lim(20)).map(|f| json!({
            "severity": f.severity, "title": f.title, "detail": trunc(&f.detail, 300), "pids": f.pids, "action": f.action,
        })).collect::<Vec<_>>(),
    })
}

/// Compact JSON digest of the snapshot, kept under ~20KB by shrinking lists if needed.
pub fn build_context(snap: &Snapshot, findings: &[Finding]) -> String {
    for (scale, cmd_len) in [(4, 80), (4, 40), (3, 0), (2, 0), (1, 0)] {
        let s = context_with(snap, findings, scale, cmd_len).to_string();
        if s.len() <= MAX_CONTEXT_BYTES {
            return s;
        }
    }
    let s = context_with(snap, &findings[..findings.len().min(3)], 1, 0).to_string();
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
                out.push(format!(
                    "CPU {:.0}% across {} cores, load {:.2} {:.2} {:.2}, thermal {}.",
                    s.cpu, s.cores, s.load[0], s.load[1], s.load[2], or_unknown(&s.thermal)
                ));
                push_top(&mut out, "Top CPU:", top_by(snap, 5, |p| p.cpu as f64), |p| format!("{:.1}% cpu", p.cpu));
            }
            Topic::Power => {
                let batt = match (s.battery_pct, s.on_battery) {
                    (Some(pct), Some(true)) => format!("on battery at {pct:.0}%"),
                    (Some(pct), _) => format!("battery {pct:.0}% (plugged in)"),
                    _ => "battery unknown".to_string(),
                };
                out.push(format!("Estimated process power {:.1} W, {batt}.", s.power_mw / 1000.0));
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

    #[test]
    fn redaction() {
        assert_eq!(redact_cmd("curl -H x --token abc PASSWORD=x run"), "curl -H x --token *** PASSWORD=*** run");
        assert_eq!(redact_cmd("ls -la /tmp"), "ls -la /tmp");
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
