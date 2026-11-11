//! Ask through an AI command-line tool that is already signed in on this machine (Claude
//! Code, OpenAI Codex, Cursor), or any command the user names. fat runs the tool's official
//! non-interactive mode and reads the answer back; it never reads the tool's credentials.
//!
//! Each tool runs from a fresh empty folder, with its tools off or sandboxed read-only, so it
//! answers instead of acting:
//! - Claude Code: `claude -p --tools "" --strict-mcp-config --no-session-persistence
//!   --output-format text --system-prompt …`, the question on stdin.
//! - Codex: `codex exec --sandbox read-only --skip-git-repo-check --ephemeral --color never
//!   -C <dir> -o <dir>/answer.txt -`, the question on stdin, the answer from the file.
//! - Cursor: `cursor-agent -p --output-format text --sandbox enabled --workspace <dir> <question>`
//!   (no `--force`, so it can't approve commands for itself).
//! - A custom command: the question on stdin, the answer on stdout.
//!
//! These tools send the question to their vendor's cloud, through the user's own account.
use serde_json::Value;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    ClaudeCode,
    Codex,
    Cursor,
    /// `[ask] command`: any program reading the question on stdin and printing the answer.
    Command,
}

impl Tool {
    pub const PRESETS: [Tool; 3] = [Tool::ClaudeCode, Tool::Codex, Tool::Cursor];

    /// The `[ask] provider` value.
    pub fn key(self) -> &'static str {
        match self {
            Tool::ClaudeCode => "claude-code",
            Tool::Codex => "codex",
            Tool::Cursor => "cursor",
            Tool::Command => "command",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tool::ClaudeCode => "Claude Code",
            Tool::Codex => "Codex",
            Tool::Cursor => "Cursor",
            Tool::Command => "Custom command",
        }
    }

    pub fn binary(self) -> Option<&'static str> {
        match self {
            Tool::ClaudeCode => Some("claude"),
            Tool::Codex => Some("codex"),
            Tool::Cursor => Some("cursor-agent"),
            Tool::Command => None,
        }
    }

    /// Whose cloud the question goes to (for messages; None for a custom command).
    pub fn vendor(self) -> Option<&'static str> {
        match self {
            Tool::ClaudeCode => Some("Anthropic"),
            // Codex's own config decides (OpenAI by default); local_only refuses it either way.
            Tool::Codex => Some("Codex's configured provider"),
            Tool::Cursor => Some("Cursor"),
            Tool::Command => None,
        }
    }

    /// "your Claude login".
    pub fn account(self) -> &'static str {
        match self {
            Tool::ClaudeCode => "your Claude login",
            Tool::Codex => "your Codex setup",
            Tool::Cursor => "your Cursor login",
            Tool::Command => "your command",
        }
    }

    pub fn from_key(k: &str) -> Option<Tool> {
        match k {
            "claude-code" | "claude_code" | "claudecode" => Some(Tool::ClaudeCode),
            "codex" | "chatgpt" => Some(Tool::Codex),
            "cursor" | "cursor-agent" => Some(Tool::Cursor),
            "command" | "cli" => Some(Tool::Command),
            _ => None,
        }
    }
}

/// Where `bin` is: PATH, then the usual per-user and package-manager folders (a TUI started
/// from a launcher may have a short PATH).
pub fn which(bin: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> =
        std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    if let Some(h) = dirs::home_dir() {
        dirs.extend([h.join(".local/bin"), h.join("bin"), h.join(".npm-global/bin"), h.join(".cargo/bin")]);
    }
    dirs.extend(["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"].map(PathBuf::from));
    dirs.into_iter().map(|d| d.join(bin)).find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Split a command line like a shell would for plain words and quotes (no expansion).
pub fn split_command(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut have = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                have = true;
            }
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    have = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if have || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if quote.is_some() {
        return Err("[ask] command has an unclosed quote".into());
    }
    if have || !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

/// The conversation as one text: earlier turns, then the question with its digest.
pub fn conversation_text(conversation: &[Value]) -> String {
    let content = |m: &Value| m.get("content").and_then(Value::as_str).unwrap_or("").to_string();
    let (last, earlier) = match conversation.split_last() {
        Some((l, e)) => (content(l), e),
        None => (String::new(), &[][..]),
    };
    let mut out = String::new();
    if !earlier.is_empty() {
        out.push_str("Earlier in this conversation:\n\n");
        for m in earlier {
            let who = if m.get("role").and_then(Value::as_str) == Some("assistant") { "Assistant" } else { "User" };
            out.push_str(&format!("{who}: {}\n\n", content(m)));
        }
        out.push_str("Now:\n\n");
    }
    out.push_str(&last);
    out
}

/// Placeholder for the run's empty working folder in an argv.
pub const DIR: &str = "{fat-ask-dir}";

/// The argv and stdin for one question. `program`: the tool's path (or the custom command).
pub fn invocation(
    tool: Tool,
    program: &[String],
    model: &str,
    system: &str,
    conversation: &[Value],
) -> (Vec<String>, String) {
    let text = conversation_text(conversation);
    let with_system = format!("{system}\n\n{text}");
    let mut argv: Vec<String> = program.to_vec();
    let push = |argv: &mut Vec<String>, xs: &[&str]| argv.extend(xs.iter().map(|s| s.to_string()));
    let model = model.trim();
    match tool {
        Tool::ClaudeCode => {
            push(&mut argv, &["-p", "--tools", "", "--strict-mcp-config", "--no-session-persistence"]);
            push(&mut argv, &["--output-format", "text", "--system-prompt", system]);
            if !model.is_empty() {
                push(&mut argv, &["--model", model]);
            }
            (argv, text)
        }
        Tool::Codex => {
            push(&mut argv, &["exec", "--sandbox", "read-only", "--skip-git-repo-check", "--ephemeral"]);
            argv.extend(["--color", "never", "-C", DIR, "-o"].map(String::from));
            argv.push(format!("{DIR}/answer.txt"));
            if !model.is_empty() {
                push(&mut argv, &["-m", model]);
            }
            argv.push("-".into());
            (argv, with_system)
        }
        Tool::Cursor => {
            push(&mut argv, &["-p", "--output-format", "text", "--sandbox", "enabled", "--workspace", DIR]);
            if !model.is_empty() {
                push(&mut argv, &["--model", model]);
            }
            argv.push(with_system);
            (argv, String::new())
        }
        Tool::Command => (argv, with_system),
    }
}

/// Run one invocation from a fresh empty folder; the answer text, or why there is none.
pub fn run(tool: Tool, argv: &[String], stdin: &str, timeout: Duration) -> Result<String, String> {
    let label = tool.label();
    let dir = std::env::temp_dir().join(format!(
        "fat-ask-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{label}: can't make a working folder: {e}"))?;
    let dir_s = dir.to_string_lossy().into_owned();
    let argv: Vec<String> = argv.iter().map(|a| a.replace(DIR, &dir_s)).collect();
    let result = (|| {
        let (prog, args) = argv.split_first().ok_or_else(|| format!("{label}: no command"))?;
        let mut cmd = Command::new(prog);
        cmd.args(args)
            .current_dir(&dir)
            .stdin(if stdin.is_empty() { Stdio::null() } else { Stdio::piped() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // A tool started from inside another one's session may refuse to nest.
            .env_remove("CLAUDECODE")
            .env_remove("CLAUDE_CODE_ENTRYPOINT")
            .env("NO_COLOR", "1");
        let mut child = cmd.spawn().map_err(|e| format!("{label}: can't run {prog}: {e}"))?;
        if let Some(mut w) = child.stdin.take() {
            let input = stdin.to_string();
            std::thread::spawn(move || {
                let _ = w.write_all(input.as_bytes());
            });
        }
        let read = |r: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(r) = r {
                    let _ = r.take(4 << 20).read_to_end(&mut buf);
                }
                String::from_utf8_lossy(&buf).into_owned()
            })
        };
        let out = read(child.stdout.take().map(|r| Box::new(r) as Box<dyn Read + Send>));
        let err = read(child.stderr.take().map(|r| Box::new(r) as Box<dyn Read + Send>));
        let t0 = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if t0.elapsed() < timeout => std::thread::sleep(Duration::from_millis(50)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{label} gave no answer within {}s", timeout.as_secs()));
                }
                Err(e) => return Err(format!("{label}: {e}")),
            }
        };
        let (stdout, stderr) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
        let tail = |s: &str| {
            let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
            strip_ansi(&lines[lines.len().saturating_sub(4)..].join(" · "))
        };
        if !status.success() {
            let why = if stderr.trim().is_empty() { tail(&stdout) } else { tail(&stderr) };
            return Err(format!(
                "{label} failed ({status}){}",
                if why.is_empty() { String::new() } else { format!(": {why}") }
            ));
        }
        let answer = if tool == Tool::Codex {
            std::fs::read_to_string(dir.join("answer.txt")).unwrap_or_default()
        } else {
            stdout
        };
        let answer = strip_ansi(answer.trim());
        if answer.is_empty() {
            return Err(format!(
                "{label} returned no answer{}",
                if stderr.trim().is_empty() { String::new() } else { format!(": {}", tail(&stderr)) }
            ));
        }
        Ok(answer)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            if it.peek() == Some(&'[') {
                it.next();
                for n in it.by_ref() {
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Whether the tool is installed and signed in, asked of the tool itself (its status
/// command; never its credential files). (ready, what to show).
pub fn status(tool: Tool) -> (bool, String) {
    let Some(bin) = tool.binary() else { return (false, String::new()) };
    let Some(path) = which(bin) else { return (false, format!("not installed ({bin} not found)")) };
    let quick = |args: &[&str]| -> Option<(bool, String)> {
        let mut child = Command::new(&path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_remove("CLAUDECODE")
            .env("NO_COLOR", "1")
            .spawn()
            .ok()?;
        let t0 = Instant::now();
        let ok = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s.success(),
                Ok(None) if t0.elapsed() < Duration::from_secs(6) => std::thread::sleep(Duration::from_millis(50)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        };
        let out = child.wait_with_output().ok()?;
        Some((ok, format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))))
    };
    match tool {
        Tool::ClaudeCode => match quick(&["auth", "status", "--json"]) {
            Some((_, text)) => {
                let v: Value = serde_json::from_str(text.trim()).unwrap_or(Value::Null);
                if v.get("loggedIn").and_then(Value::as_bool) == Some(true) {
                    let how = match v.get("authMethod").and_then(Value::as_str) {
                        Some("claude.ai") => "your Claude subscription",
                        Some(m) if !m.is_empty() => m,
                        _ => "your account",
                    };
                    (true, format!("signed in · {how}"))
                } else {
                    (false, "installed · not signed in (run: claude auth login)".into())
                }
            }
            None => (true, "installed · sign-in not checked".into()),
        },
        Tool::Codex => match quick(&["login", "status"]) {
            Some((true, text)) if text.to_ascii_lowercase().contains("logged in") => {
                let how = text.lines().find(|l| l.to_ascii_lowercase().contains("logged in")).unwrap_or("").trim();
                (true, format!("signed in · {}", how.trim_start_matches("Logged in ").trim_start_matches("using ")))
            }
            Some(_) => (false, "installed · not signed in (run: codex login)".into()),
            None => (true, "installed · sign-in not checked".into()),
        },
        // Its status command prompts on a terminal; sign-in shows when testing (t).
        Tool::Cursor => (false, "installed · sign-in is checked when testing (t)".into()),
        Tool::Command => (false, String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn commands_split_like_a_shell() {
        assert_eq!(split_command("my-llm --model 'big one' -x").unwrap(), vec!["my-llm", "--model", "big one", "-x"]);
        assert_eq!(split_command(r#"a "b \"c\"" '' d\ e"#).unwrap(), vec!["a", "b \"c\"", "", "d e"]);
        assert!(split_command("a 'b").is_err());
        assert!(split_command("   ").unwrap().is_empty());
    }

    #[test]
    fn invocations_keep_tools_off_and_work_in_an_empty_folder() {
        let conv = vec![
            json!({"role": "user", "content": "why slow?"}),
            json!({"role": "assistant", "content": "node is busy"}),
            json!({"role": "user", "content": "<snapshot>…</snapshot>\n\nQuestion: since when?"}),
        ];
        let p = |s: &str| vec![s.to_string()];
        let (a, stdin) = invocation(Tool::ClaudeCode, &p("/bin/claude"), "", "SYS", &conv);
        assert_eq!(&a[..4], &["/bin/claude", "-p", "--tools", ""]);
        assert!(a.contains(&"--strict-mcp-config".to_string()) && a.contains(&"--no-session-persistence".to_string()));
        assert_eq!(a[a.iter().position(|x| x == "--system-prompt").unwrap() + 1], "SYS");
        assert!(stdin.starts_with("Earlier in this conversation:") && stdin.contains("Assistant: node is busy"));
        assert!(stdin.ends_with("Question: since when?") && !stdin.contains("SYS"));
        let (a, stdin) = invocation(Tool::Codex, &p("codex"), "gpt-x", "SYS", &conv);
        assert!(a.windows(2).any(|w| w == ["--sandbox", "read-only"]) && a.last().unwrap() == "-");
        assert!(a.contains(&format!("{DIR}/answer.txt")) && a.windows(2).any(|w| w == ["-m", "gpt-x"]));
        assert!(stdin.starts_with("SYS\n\n"));
        let (a, stdin) = invocation(Tool::Cursor, &p("cursor-agent"), "", "SYS", &conv);
        assert!(a.windows(2).any(|w| w == ["--sandbox", "enabled"]) && !a.contains(&"--force".to_string()));
        assert!(a.last().unwrap().starts_with("SYS") && stdin.is_empty());
    }

    #[test]
    fn a_custom_command_answers_through_stdin_and_stdout() {
        // `sh -c` stands in for a model: it echoes what it got, so the plumbing is visible.
        let argv: Vec<String> =
            ["sh", "-c", "pwd > where.txt; printf 'answer: '; tr a-z A-Z; ls -a | wc -l | tr -d ' '"]
                .map(String::from)
                .to_vec();
        let out = run(Tool::Command, &argv, "hello", Duration::from_secs(10)).unwrap();
        assert!(out.starts_with("answer: HELLO"), "{out}");
        assert!(out.ends_with('3'), "ran in an empty folder (., .., where.txt): {out}");
        let e = run(
            Tool::Command,
            &["sh".into(), "-c".into(), "echo boom >&2; exit 3".into()],
            "",
            Duration::from_secs(10),
        )
        .unwrap_err();
        assert!(e.contains("failed") && e.contains("boom"), "{e}");
        let e = run(Tool::Command, &["sh".into(), "-c".into(), "sleep 5".into()], "", Duration::from_millis(300))
            .unwrap_err();
        assert!(e.contains("no answer within"), "{e}");
        let e = run(Tool::Command, &["true".into()], "", Duration::from_secs(5)).unwrap_err();
        assert!(e.contains("no answer"), "{e}");
        assert_eq!(strip_ansi("\u{1b}[1mbold\u{1b}[0m ok"), "bold ok");
    }
}
