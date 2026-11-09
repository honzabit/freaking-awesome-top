//! On-disk index: completed directory aggregates in SQLite (`~/.cache/fat/fs-index.db`), so
//! a new process shows numbers instantly. Any process may upsert what it measured (newer
//! `scanned_at` wins); background scanning is guarded by a writer lock file so only one
//! process walks the disk.

use super::sys::BigFile;
use super::tree::Agg;
use crate::model::Ts;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use std::time::Duration;

const SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Row {
    pub path: Vec<u8>,
    pub total: Agg,
    pub own: Agg,
    pub flags: u16,
    pub at: Ts,
    pub dev: u64,
    pub ino: u64,
    pub mtime: i64,
    pub ctime: i64,
    pub self_size: u64,
    pub self_apparent: u64,
    pub big: Vec<BigFile>,
}

pub struct Db {
    conn: Connection,
    path: PathBuf,
    lock: Option<std::fs::File>,
}

pub fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("FAT_FS_INDEX").filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("fat").join("fs-index.db")
}

fn enc_big(v: &[BigFile]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in v {
        let n = f.name.len().min(u16::MAX as usize);
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(&f.name[..n]);
        out.extend_from_slice(&f.size.to_le_bytes());
        out.extend_from_slice(&f.apparent.to_le_bytes());
        out.extend_from_slice(&f.mtime.to_le_bytes());
    }
    out
}

fn dec_big(b: &[u8]) -> Vec<BigFile> {
    let mut out = Vec::new();
    let mut i = 0;
    let u64_at = |i: usize| -> Option<u64> { Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?)) };
    while i + 2 <= b.len() {
        let n = u16::from_le_bytes([b[i], b[i + 1]]) as usize;
        i += 2;
        let Some(name) = b.get(i..i + n) else { break };
        i += n;
        let (Some(size), Some(apparent), Some(mtime)) = (u64_at(i), u64_at(i + 8), u64_at(i + 16)) else { break };
        i += 24;
        out.push(BigFile { name: name.into(), size, apparent, mtime: mtime as i64 });
    }
    out
}

/// Upper bound (exclusive) of the key range holding `p`'s descendants: "p/" .. "p0".
fn range_end(p: &[u8]) -> Vec<u8> {
    let mut e = p.to_vec();
    if e != b"/" {
        e.push(b'0'); // '0' == '/' + 1
    } else {
        e = b"0".to_vec();
    }
    e
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Db> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
            // fat's own cache dir: private (it lists every directory on the disk, and names
            // from inside privacy-protected folders the user opened).
            if dir.file_name().is_some_and(|n| n == "fat") {
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        // Create the file 0600 before SQLite opens it (its -wal/-shm copy this mode).
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path);
        }
        for suffix in ["", "-wal", "-shm", ".writer-lock"] {
            let mut p = path.as_os_str().to_owned();
            p.push(suffix);
            let p = PathBuf::from(p);
            if std::fs::metadata(&p).is_ok_and(|m| m.permissions().mode() & 0o077 != 0) {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(3))?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if v != SCHEMA_VERSION {
            conn.execute_batch("DROP TABLE IF EXISTS dirs; DROP TABLE IF EXISTS meta;")?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS dirs (
                path BLOB PRIMARY KEY,
                size INTEGER, apparent INTEGER, files INTEGER, newest INTEGER, denied INTEGER,
                own_size INTEGER, own_apparent INTEGER, own_files INTEGER, own_newest INTEGER, own_denied INTEGER,
                flags INTEGER, scanned_at INTEGER, written_at INTEGER,
                dev INTEGER, ino INTEGER, mtime INTEGER, ctime INTEGER, self_size INTEGER, self_apparent INTEGER,
                big BLOB
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS dirs_written ON dirs(written_at);
             CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER);
             -- Subtrees deleted by a writer, so other processes drop them too.
             CREATE TABLE IF NOT EXISTS gone (path BLOB PRIMARY KEY, written_at INTEGER);",
        )?;
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        Ok(Db { conn, path: path.to_path_buf(), lock: None })
    }

    /// Take the background-scanner lock (non-blocking). Released when the Db is dropped.
    pub fn try_lock(&mut self) -> bool {
        if self.lock.is_some() {
            return true;
        }
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let mut p = self.path.as_os_str().to_owned();
        p.push(".writer-lock");
        use std::os::unix::fs::OpenOptionsExt;
        let Ok(mut f) = std::fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).mode(0o600).open(p)
        else {
            return false;
        };
        // SAFETY: flock on an fd we own; LOCK_NB = fail instead of blocking.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return false;
        }
        let _ = f.set_len(0);
        let _ = write!(f, "{}", std::process::id());
        self.lock = Some(f);
        true
    }

    pub fn is_locked(&self) -> bool {
        self.lock.is_some()
    }

    fn rows(&self, sql: &str, since: Ts) -> anyhow::Result<Vec<Row>> {
        let mut st = self.conn.prepare(sql)?;
        let it = st.query_map(params![since], |r| {
            let g = |i: usize| -> rusqlite::Result<i64> { r.get::<_, Option<i64>>(i).map(|v| v.unwrap_or(0)) };
            Ok(Row {
                path: r.get(0)?,
                total: Agg { size: g(1)? as u64, apparent: g(2)? as u64, files: g(3)? as u64, newest: g(4)?, denied: g(5)? as u32 },
                own: Agg { size: g(6)? as u64, apparent: g(7)? as u64, files: g(8)? as u64, newest: g(9)?, denied: g(10)? as u32 },
                flags: g(11)? as u16,
                at: g(12)?,
                dev: g(13)? as u64,
                ino: g(14)? as u64,
                mtime: g(15)?,
                ctime: g(16)?,
                self_size: g(17)? as u64,
                self_apparent: g(18)? as u64,
                big: r.get::<_, Option<Vec<u8>>>(19)?.map(|b| dec_big(&b)).unwrap_or_default(),
            })
        })?;
        Ok(it.filter_map(Result::ok).collect())
    }

    const COLS: &'static str = "path, size, apparent, files, newest, denied, own_size, own_apparent, own_files, own_newest, own_denied,
         flags, scanned_at, dev, ino, mtime, ctime, self_size, self_apparent, big";

    /// All rows, parents before children.
    pub fn load_all(&self) -> anyhow::Result<Vec<Row>> {
        self.rows(&format!("SELECT {} FROM dirs WHERE written_at >= ?1 ORDER BY path", Self::COLS), i64::MIN)
    }

    /// Rows written after `since` (epoch ms), parents before children.
    pub fn load_since(&self, since: Ts) -> anyhow::Result<Vec<Row>> {
        self.rows(&format!("SELECT {} FROM dirs WHERE written_at > ?1 ORDER BY path", Self::COLS), since)
    }

    /// Upsert `rows` (older measurements never overwrite newer ones) and delete `removed`
    /// subtrees, in one transaction.
    pub fn write(&mut self, rows: &[Row], removed: &[Vec<u8>], now: Ts) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut del = tx.prepare("DELETE FROM dirs WHERE path = ?1 OR (path > ?2 AND path < ?3)")?;
            let mut gone = tx.prepare(
                "INSERT INTO gone(path, written_at) VALUES (?1, ?2) ON CONFLICT(path) DO UPDATE SET written_at = excluded.written_at",
            )?;
            for p in removed {
                let mut lo = p.clone();
                if lo != b"/" {
                    lo.push(b'/');
                }
                del.execute(params![p, lo, range_end(p)])?;
                gone.execute(params![p, now])?;
            }
            // Readers re-read the cache every few seconds; a day of tombstones is plenty.
            tx.execute("DELETE FROM gone WHERE written_at < ?1", params![now - 86_400_000])?;
            let mut ins = tx.prepare(
                "INSERT INTO dirs (path, size, apparent, files, newest, denied, own_size, own_apparent, own_files, own_newest,
                    own_denied, flags, scanned_at, written_at, dev, ino, mtime, ctime, self_size, self_apparent, big)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)
                 ON CONFLICT(path) DO UPDATE SET size=excluded.size, apparent=excluded.apparent, files=excluded.files,
                    newest=excluded.newest, denied=excluded.denied, own_size=excluded.own_size,
                    own_apparent=excluded.own_apparent, own_files=excluded.own_files, own_newest=excluded.own_newest,
                    own_denied=excluded.own_denied, flags=excluded.flags, scanned_at=excluded.scanned_at,
                    written_at=excluded.written_at, dev=excluded.dev, ino=excluded.ino, mtime=excluded.mtime,
                    ctime=excluded.ctime, self_size=excluded.self_size, self_apparent=excluded.self_apparent, big=excluded.big
                 WHERE excluded.scanned_at >= dirs.scanned_at",
            )?;
            for r in rows {
                let big = if r.big.is_empty() { None } else { Some(enc_big(&r.big)) };
                ins.execute(params![
                    r.path,
                    r.total.size as i64,
                    r.total.apparent as i64,
                    r.total.files as i64,
                    r.total.newest,
                    r.total.denied as i64,
                    r.own.size as i64,
                    r.own.apparent as i64,
                    r.own.files as i64,
                    r.own.newest,
                    r.own.denied as i64,
                    r.flags as i64,
                    r.at,
                    now,
                    r.dev as i64,
                    r.ino as i64,
                    r.mtime,
                    r.ctime,
                    r.self_size as i64,
                    r.self_apparent as i64,
                    big
                ])?;
            }
            tx.execute("INSERT INTO meta(k, v) VALUES ('updated', ?1) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![now])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn meta(&self, k: &str) -> Option<i64> {
        self.conn.query_row("SELECT v FROM meta WHERE k = ?1", params![k], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn set_meta(&self, k: &str, v: i64) -> anyhow::Result<()> {
        self.conn.execute("INSERT INTO meta(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![k, v])?;
        Ok(())
    }

    pub fn del_meta(&self, k: &str) -> anyhow::Result<()> {
        self.conn.execute("DELETE FROM meta WHERE k = ?1", params![k])?;
        Ok(())
    }

    /// Roots other processes asked the background scanner to keep fresh ("want:<root>"),
    /// with when they last asked.
    pub fn wants(&self) -> Vec<(String, i64)> {
        let Ok(mut st) = self.conn.prepare("SELECT k, v FROM meta WHERE k LIKE 'want:%'") else { return Vec::new() };
        st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?.unwrap_or(0))))
            .map(|it| it.filter_map(Result::ok).map(|(k, v)| (k[5..].to_string(), v)).collect())
            .unwrap_or_default()
    }

    /// Subtrees a writer deleted after `since` (epoch ms): (path, when).
    pub fn gone_since(&self, since: Ts) -> Vec<(Vec<u8>, Ts)> {
        let Ok(mut st) = self.conn.prepare("SELECT path, written_at FROM gone WHERE written_at > ?1") else {
            return Vec::new();
        };
        st.query_map(params![since], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))
            .map(|it| it.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_codec_and_range() {
        let v = vec![
            BigFile { name: b"a.img".to_vec().into(), size: 1 << 30, apparent: 5, mtime: -3 },
            BigFile { name: b"\xff\xfe".to_vec().into(), size: 7, apparent: 8, mtime: 9 },
        ];
        assert_eq!(dec_big(&enc_big(&v)), v);
        assert_eq!(range_end(b"/a"), b"/a0");
        assert!(b"/a/zzz".as_slice() < range_end(b"/a").as_slice());
        assert!(b"/a0".as_slice() >= range_end(b"/a").as_slice());
    }
}
