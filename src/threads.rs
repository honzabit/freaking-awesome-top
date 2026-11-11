//! Ask threads: a question and its follow-ups, with the answers. Kept per user in
//! `<data_local_dir>/fat/threads.db` (FAT_THREADS_DB overrides), readable only by that user,
//! pruned after `[ask] keep_days`. Only questions asked by a person (TUI, `fat ask`) are kept;
//! agents asking through MCP are not.
//!
//! A follow-up sends its thread's earlier turns along; a new question may carry short
//! excerpts of recent threads on the same host (`[ask] memory`), so the model can connect
//! "this happened before".
use crate::model::Ts;
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Thread {
    pub id: i64,
    pub started: Ts,
    pub updated: Ts,
    pub host: String,
    /// The first question, shortened.
    pub title: String,
    pub turns: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Turn {
    pub id: i64,
    pub thread: i64,
    pub ts: Ts,
    pub question: String,
    pub answer: String,
    /// Where it was answered: "anthropic · … · https://…", "ollama · … " (older versions also
    /// kept rule-based "offline (…)" answers).
    pub via: String,
}

/// A short excerpt of a past thread, for the model's context.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Memory {
    pub ts: Ts,
    pub question: String,
    pub answer: String,
}

pub struct Store {
    conn: Connection,
}

pub fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("FAT_THREADS_DB").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("fat").join("threads.db")
}

fn title_of(question: &str) -> String {
    let q = question.split_whitespace().collect::<Vec<_>>().join(" ");
    if q.chars().count() > 80 { format!("{}…", q.chars().take(79).collect::<String>()) } else { q }
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.busy_timeout(std::time::Duration::from_secs(3))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS threads (
                 id INTEGER PRIMARY KEY, started INTEGER NOT NULL, updated INTEGER NOT NULL,
                 host TEXT NOT NULL, title TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS turns (
                 id INTEGER PRIMARY KEY, thread INTEGER NOT NULL,
                 ts INTEGER NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL, via TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS turns_thread ON turns(thread, ts);",
        )?;
        Ok(Store { conn })
    }

    /// Record a turn; `thread` None (or a thread that no longer exists) starts a new one,
    /// titled by the question. Returns the thread id.
    pub fn add_turn(
        &self,
        thread: Option<i64>,
        host: &str,
        ts: Ts,
        question: &str,
        answer: &str,
        via: &str,
    ) -> Result<i64> {
        let id = match thread {
            Some(id) if self.exists(id)? => {
                self.conn.execute("UPDATE threads SET updated = ?1 WHERE id = ?2", params![ts, id])?;
                id
            }
            _ => {
                self.conn.execute(
                    "INSERT INTO threads (started, updated, host, title) VALUES (?1, ?1, ?2, ?3)",
                    params![ts, host, title_of(question)],
                )?;
                self.conn.last_insert_rowid()
            }
        };
        self.conn.execute(
            "INSERT INTO turns (thread, ts, question, answer, via) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, ts, question, answer, via],
        )?;
        Ok(id)
    }

    pub fn exists(&self, id: i64) -> Result<bool> {
        Ok(self.conn.query_row("SELECT count(*) FROM threads WHERE id = ?1", [id], |r| r.get::<_, i64>(0))? > 0)
    }

    /// Most recently updated first.
    pub fn threads(&self, limit: usize) -> Result<Vec<Thread>> {
        let mut st = self.conn.prepare(
            "SELECT s.id, s.started, s.updated, s.host, s.title, count(t.id)
             FROM threads s LEFT JOIN turns t ON t.thread = s.id
             GROUP BY s.id ORDER BY s.updated DESC, s.id DESC LIMIT ?1",
        )?;
        let rows = st.query_map([limit as i64], |r| {
            Ok(Thread {
                id: r.get(0)?,
                started: r.get(1)?,
                updated: r.get(2)?,
                host: r.get(3)?,
                title: r.get(4)?,
                turns: r.get::<_, i64>(5)? as u32,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn turns(&self, thread: i64) -> Result<Vec<Turn>> {
        let mut st = self
            .conn
            .prepare("SELECT id, thread, ts, question, answer, via FROM turns WHERE thread = ?1 ORDER BY ts, id")?;
        let rows = st.query_map([thread], |r| {
            Ok(Turn {
                id: r.get(0)?,
                thread: r.get(1)?,
                ts: r.get(2)?,
                question: r.get(3)?,
                answer: r.get(4)?,
                via: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn latest(&self) -> Result<Option<i64>> {
        Ok(self.threads(1)?.first().map(|s| s.id))
    }

    pub fn delete(&self, thread: i64) -> Result<()> {
        self.conn.execute("DELETE FROM turns WHERE thread = ?1", [thread])?;
        self.conn.execute("DELETE FROM threads WHERE id = ?1", [thread])?;
        Ok(())
    }

    /// Drop threads not touched since `before`. Returns how many.
    pub fn prune(&self, before: Ts) -> Result<usize> {
        self.conn.execute("DELETE FROM turns WHERE thread IN (SELECT id FROM threads WHERE updated < ?1)", [before])?;
        Ok(self.conn.execute("DELETE FROM threads WHERE updated < ?1", [before])?)
    }

    /// Excerpts of recent threads on `host` (one per thread: its first question and the start
    /// of its last answer), newest first, leaving out `exclude` and offline answers.
    pub fn memory(
        &self,
        host: &str,
        exclude: Option<i64>,
        since: Ts,
        limit: usize,
        answer_chars: usize,
    ) -> Result<Vec<Memory>> {
        let mut out = Vec::new();
        for s in self.threads(limit * 4 + 1)? {
            if out.len() >= limit || s.updated < since {
                break;
            }
            if Some(s.id) == exclude || s.host != host {
                continue;
            }
            let turns = self.turns(s.id)?;
            let (Some(first), Some(last)) = (turns.first(), turns.last()) else { continue };
            if last.via.starts_with("offline") {
                continue;
            }
            let mut answer: String = last.answer.chars().take(answer_chars).collect();
            if last.answer.chars().count() > answer_chars {
                answer.push('…');
            }
            out.push(Memory { ts: last.ts, question: first.question.clone(), answer });
        }
        Ok(out)
    }
}

/// What asking within a thread produced.
#[derive(Debug, Clone, Default)]
pub struct Asked {
    pub question: String,
    pub answer: String,
    pub via: String,
    /// The thread the turn was saved in (None: it could not be saved, see `error`).
    pub thread: Option<i64>,
    pub turns: Vec<Turn>,
    pub threads: Vec<Thread>,
    pub error: Option<String>,
    /// A model answered (otherwise `answer` says why not, and nothing was saved).
    pub answered: bool,
}

/// Past threads sent along with a question, at most; how far back; how much of each answer.
const MEMORY_THREADS: usize = 3;
const MEMORY_DAYS: i64 = 30;
const MEMORY_ANSWER_CHARS: usize = 400;

/// Ask `question` in `thread` (None: a new thread) and save the turn in the store at `path`
/// (None: don't keep it). The thread's earlier turns and, with `[ask] memory`, excerpts of
/// recent threads on this host go along with the question.
pub fn ask_and_save(
    path: Option<&Path>,
    thread: Option<i64>,
    question: &str,
    snap: &crate::model::Snapshot,
    findings: &[crate::model::Finding],
    storage: Option<&crate::ask::Storage>,
    cfg: &crate::config::AskCfg,
) -> Asked {
    let now = crate::model::now_ms();
    let host = if snap.system.hostname.is_empty() { snap.host.clone() } else { snap.system.hostname.clone() };
    let mut out = Asked { question: question.to_string(), ..Default::default() };
    let store = path.map(|p| Store::open(p).map_err(|e| format!("threads are not saved: {e:#}")));
    let store = match store {
        Some(Ok(s)) => Some(s),
        Some(Err(e)) => {
            out.error = Some(e);
            None
        }
        None => None,
    };
    let mut conv = crate::ask::Conversation::default();
    if let Some(st) = &store {
        if cfg.keep_days > 0 {
            let _ = st.prune(now - cfg.keep_days as i64 * 86_400_000);
        }
        if let Some(t) = thread {
            conv.prior = st.turns(t).unwrap_or_default().into_iter().map(|t| (t.question, t.answer)).collect();
        }
        if cfg.memory {
            let since = now - MEMORY_DAYS * 86_400_000;
            conv.memory = st.memory(&host, thread, since, MEMORY_THREADS, MEMORY_ANSWER_CHARS).unwrap_or_default();
        }
    }
    match crate::ask::ask_in(question, &conv, snap, findings, storage, cfg) {
        Ok((answer, via)) => {
            out.answer = answer;
            out.via = via;
            out.answered = true;
        }
        Err(why) => {
            // Not an answer: shown, never kept in a thread.
            out.answer = why;
            out.via = "not answered".into();
            return out;
        }
    }
    if let Some(st) = &store {
        match st.add_turn(thread, &host, now, question, &out.answer, &out.via) {
            Ok(id) => {
                out.thread = Some(id);
                out.turns = st.turns(id).unwrap_or_default();
                out.threads = st.threads(500).unwrap_or_default();
            }
            Err(e) => out.error = Some(format!("the answer was not saved: {e:#}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> (Store, PathBuf) {
        let p = std::env::temp_dir().join(format!("fat-threads-{}-{name}.db", std::process::id()));
        let _ = std::fs::remove_file(&p);
        (Store::open(&p).unwrap(), p)
    }

    #[test]
    fn threads_turns_and_follow_ups() {
        let (s, p) = store("flow");
        let a =
            s.add_turn(None, "local", 1_000, "what writes under /var?", "prometheus", "ollama · m · http://h").unwrap();
        assert_eq!(s.add_turn(Some(a), "local", 2_000, "since when?", "an hour", "ollama · m · http://h").unwrap(), a);
        let b = s.add_turn(None, "local", 3_000, "  why\n slow  ", "node", "offline (x)").unwrap();
        assert_ne!(a, b);
        let list = s.threads(10).unwrap();
        assert_eq!(list.iter().map(|x| (x.id, x.turns)).collect::<Vec<_>>(), vec![(b, 1), (a, 2)]);
        assert_eq!(list[0].title, "why slow");
        let t = s.turns(a).unwrap();
        assert_eq!(
            t.iter().map(|x| x.question.as_str()).collect::<Vec<_>>(),
            vec!["what writes under /var?", "since when?"]
        );
        assert_eq!(s.latest().unwrap(), Some(b));
        // A follow-up to a deleted thread starts a new one.
        s.delete(a).unwrap();
        assert!(s.turns(a).unwrap().is_empty() && !s.exists(a).unwrap());
        let c = s.add_turn(Some(a), "local", 4_000, "again", "x", "v").unwrap();
        assert_ne!(c, a);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn memory_is_recent_same_host_answered_threads() {
        let (s, p) = store("mem");
        let a = s.add_turn(None, "local", 1_000, "disk filling?", "yes: /var/log/app grew 2G", "ollama").unwrap();
        s.add_turn(Some(a), "local", 1_500, "who?", "app.service wrote it", "ollama").unwrap();
        s.add_turn(None, "other", 2_000, "elsewhere", "x", "ollama").unwrap();
        s.add_turn(None, "local", 3_000, "offline one", "rules", "offline (no key)").unwrap();
        let cur = s.add_turn(None, "local", 4_000, "now", "y", "ollama").unwrap();
        let m = s.memory("local", Some(cur), 0, 5, 10).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].question, "disk filling?");
        assert_eq!(m[0].answer, "app.servic…");
        assert!(s.memory("local", Some(cur), 2_000, 5, 100).unwrap().is_empty(), "too old");
        assert_eq!(s.prune(2_000).unwrap(), 1);
        assert_eq!(s.threads(10).unwrap().len(), 3);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn unanswered_questions_are_not_kept() {
        let (_, p) = store("unanswered");
        let cfg = crate::config::AskCfg { enabled: false, ..Default::default() };
        let r = ask_and_save(Some(&p), None, "why slow?", &Default::default(), &[], None, &cfg);
        assert!(!r.answered && r.thread.is_none() && r.answer.contains("turned off"), "{r:?}");
        assert!(Store::open(&p).unwrap().threads(10).unwrap().is_empty());
        let _ = std::fs::remove_file(&p);
    }
}
