//! Fleet inventory: who the hosts are, and which ones a command targets. OWNER: fleet agent.
//! Sources, merged and de-duplicated by name: `[[hosts]]` in the config, FleetCfg::hosts_file,
//! and (opt-in) non-wildcard `Host` entries of ~/.ssh/config. No source is required; fat never
//! invents hosts and never rewrites ssh destinations: `dest` goes to ssh verbatim, so the
//! operator's ssh config (users, ports, keys, proxies, whatever they already use) decides how
//! a host is reached.
use crate::config::Config;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Target {
    pub name: String,
    /// ssh destination (alias, user@host, host); defaults to `name`. Passed to ssh verbatim so
    /// the operator's ssh config decides how to reach it.
    pub dest: String,
    pub fat_path: Option<String>,
    pub groups: Vec<String>,
    pub tags: Vec<String>,
}

/// Which targets a command applies to. Empty selector = all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selector {
    /// Host name globs (`*`, `?`, `[a-z]`).
    pub hosts: Vec<String>,
    pub groups: Vec<String>,
    pub tags: Vec<String>,
    pub exclude: Vec<String>,
}

/// All configured targets, sorted by name. Errors only when a configured `hosts_file` cannot
/// be read (a typo there should not silently shrink the fleet); a missing ~/.ssh/config is fine.
pub fn inventory(cfg: &Config) -> anyhow::Result<Vec<Target>> {
    let mut by_name: BTreeMap<String, Target> = BTreeMap::new();
    let mut add = |t: Target| {
        if t.name.trim().is_empty() {
            return;
        }
        match by_name.get_mut(&t.name) {
            // First source wins for dest/fat_path; groups and tags are merged.
            Some(e) => {
                union(&mut e.groups, &t.groups);
                union(&mut e.tags, &t.tags);
                if e.fat_path.is_none() {
                    e.fat_path = t.fat_path;
                }
            }
            None => {
                by_name.insert(t.name.clone(), t);
            }
        }
    };
    for h in &cfg.hosts {
        let dest = h.ssh.clone().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| h.name.clone());
        let fat_path = h.fat_path.clone().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        add(Target { name: h.name.trim().to_string(), dest, fat_path, groups: h.groups.clone(), tags: h.tags.clone() });
    }
    if let Some(path) = cfg.fleet.hosts_file.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        let path = expand_home(path);
        let text = std::fs::read_to_string(&path).map_err(|e| anyhow::anyhow!("fleet.hosts_file {path}: {e}"))?;
        for t in parse_hosts_file(&text) {
            add(t);
        }
    }
    if cfg.fleet.ssh_config_hosts
        && let Some(p) = dirs::home_dir().map(|h| h.join(".ssh").join("config"))
        && let Ok(text) = std::fs::read_to_string(p)
    {
        for name in parse_ssh_config_hosts(&text) {
            if cfg.fleet.ssh_config_filter.is_empty() || cfg.fleet.ssh_config_filter.iter().any(|g| glob_match(g, &name)) {
                add(Target { dest: name.clone(), name, ..Default::default() });
            }
        }
    }
    let default_fat = cfg.fleet.default_fat_path.clone().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    Ok(by_name
        .into_values()
        .map(|mut t| {
            if t.fat_path.is_none() {
                t.fat_path = default_fat.clone();
            }
            t
        })
        .collect())
}

fn union(into: &mut Vec<String>, from: &[String]) {
    for x in from {
        if !into.contains(x) {
            into.push(x.clone());
        }
    }
}

fn expand_home(p: &str) -> String {
    match (p.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(h)) => h.join(rest).display().to_string(),
        _ => p.to_string(),
    }
}

/// Is `t` in group `g`, either by its own `groups` or by a `[fleet.groups]` glob list?
pub fn in_group(t: &Target, g: &str, cfg: &Config) -> bool {
    t.groups.iter().any(|x| x == g) || cfg.fleet.groups.get(g).is_some_and(|globs| globs.iter().any(|p| glob_match(p, &t.name)))
}

/// Every group a target belongs to (own + configured), sorted.
pub fn groups_of(t: &Target, cfg: &Config) -> Vec<String> {
    let mut g = t.groups.clone();
    for (name, globs) in &cfg.fleet.groups {
        if globs.iter().any(|p| glob_match(p, &t.name)) && !g.contains(name) {
            g.push(name.clone());
        }
    }
    g.sort();
    g
}

/// Targets matching `sel` (groups from FleetCfg::groups and per-host groups both count).
/// Semantics: a host matches when it matches ANY `hosts` glob (or none are given), is in ANY
/// of `groups` (or none given), carries ALL of `tags`, and matches no `exclude` glob.
/// Returned targets carry their full group list (own + configured).
pub fn select(all: &[Target], sel: &Selector, cfg: &Config) -> Vec<Target> {
    all.iter()
        .filter(|t| sel.hosts.is_empty() || sel.hosts.iter().any(|g| glob_match(g, &t.name)))
        .filter(|t| sel.groups.is_empty() || sel.groups.iter().any(|g| in_group(t, g, cfg)))
        .filter(|t| sel.tags.iter().all(|tag| t.tags.iter().any(|x| x == tag)))
        .filter(|t| !sel.exclude.iter().any(|g| glob_match(g, &t.name)))
        .map(|t| Target { groups: groups_of(t, cfg), ..t.clone() })
        .collect()
}

/// True when `s` contains glob metacharacters (an exact host name has none).
pub fn is_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// Shell-style glob match on host names: `*` (any run), `?` (one char), `[abc]`, `[a-z]`,
/// `[!x]` / `[^x]`. Case-sensitive, like ssh_config patterns. A malformed `[` matches itself.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    // Backtrack point: position after the last '*' and the name index it is trying.
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        let step = match p.get(pi) {
            Some('*') => {
                star = Some((pi + 1, ni));
                pi += 1;
                continue;
            }
            Some('?') => Some(1),
            Some('[') => match class_match(&p[pi..], n[ni]) {
                Some((true, len)) => Some(len),
                Some((false, _)) => None,
                None => (n[ni] == '[').then_some(1),
            },
            Some(c) => (*c == n[ni]).then_some(1),
            None => None,
        };
        match step {
            Some(len) => {
                pi += len;
                ni += 1;
            }
            None => match star {
                Some((sp, sn)) => {
                    pi = sp;
                    ni = sn + 1;
                    star = Some((sp, sn + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Match `c` against the bracket class at the start of `p`. Returns (matched, class length),
/// or None when the class is not terminated.
fn class_match(p: &[char], c: char) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = matches!(p.get(1), Some('!') | Some('^'));
    if negate {
        i += 1;
    }
    let start = i;
    let mut hit = false;
    while i < p.len() {
        if p[i] == ']' && i > start {
            return Some((hit != negate, i + 1));
        }
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            hit |= p[i] <= c && c <= p[i + 2];
            i += 3;
        } else {
            hit |= p[i] == c;
            i += 1;
        }
    }
    None
}

/// Parse the hosts file format documented on FleetCfg::hosts_file:
/// `name [ssh=DEST] [fat=PATH] [groups=a,b] [tags=x,y]`, `#` comments, blank lines ignored.
/// Unknown `key=value` words are ignored (forward compatible); a bare second word is taken as
/// the ssh destination.
pub fn parse_hosts_file(text: &str) -> Vec<Target> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { continue };
        let mut t = Target { name: name.to_string(), dest: name.to_string(), ..Default::default() };
        for w in words {
            let list = |v: &str| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect::<Vec<_>>();
            match w.split_once('=') {
                Some(("ssh", v)) if !v.is_empty() => t.dest = v.to_string(),
                Some(("fat", v)) if !v.is_empty() => t.fat_path = Some(v.to_string()),
                Some(("groups" | "group", v)) => t.groups = list(v),
                Some(("tags" | "tag", v)) => t.tags = list(v),
                Some(_) => {}
                None => t.dest = w.to_string(),
            }
        }
        out.push(t);
    }
    out
}

/// Non-wildcard, non-negated `Host` aliases from ssh_config text (Include is not followed).
pub fn parse_ssh_config_hosts(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        // "Host a b", "Host=a b", "host a" (keywords are case-insensitive).
        let (kw, rest) = match line.find(|c: char| c.is_whitespace() || c == '=') {
            Some(i) => (&line[..i], line[i..].trim_start_matches(|c: char| c.is_whitespace() || c == '=')),
            None => continue,
        };
        if !kw.eq_ignore_ascii_case("host") {
            continue;
        }
        for alias in rest.split_whitespace().map(|a| a.trim_matches('"')) {
            if alias.is_empty() || alias.starts_with('!') || is_glob(alias) || out.iter().any(|x| x == alias) {
                continue;
            }
            out.push(alias.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HostCfg;

    #[test]
    fn globs() {
        assert!(glob_match("web-*", "web-01"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("web-*", "db-01"));
        assert!(glob_match("web-0?", "web-07"));
        assert!(!glob_match("web-0?", "web-10"));
        assert!(glob_match("db-[0-2]*", "db-1.example.com"));
        assert!(!glob_match("db-[!0-2]*", "db-1"));
        assert!(glob_match("db-[!0-2]*", "db-7"));
        assert!(glob_match("*.example.com", "a.b.example.com"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
        assert!(glob_match("x[", "x["), "unterminated class matches literally");
        assert!(glob_match("exact", "exact") && !glob_match("exact", "exactly"));
    }

    #[test]
    fn hosts_file() {
        let t = parse_hosts_file("# fleet\nweb-01 ssh=admin@web-01.example.com groups=web,edge tags=prod\n\ndb-01 fat=/opt/fat/fat # primary\ncache-01 cache-01.example.com unknown=1\n");
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].dest, "admin@web-01.example.com");
        assert_eq!(t[0].groups, vec!["web", "edge"]);
        assert_eq!(t[0].tags, vec!["prod"]);
        assert_eq!(t[1].dest, "db-01");
        assert_eq!(t[1].fat_path.as_deref(), Some("/opt/fat/fat"));
        assert_eq!(t[2].dest, "cache-01.example.com");
    }

    #[test]
    fn ssh_config() {
        let cfg = "Host *\n  ServerAliveInterval 30\nHost web-01 web-02\n  HostName 10.0.0.1\nhost=db-01\nHost !bad ok-? good\n# Host commented\nMatch host x\nHost web-01\n";
        assert_eq!(parse_ssh_config_hosts(cfg), vec!["web-01", "web-02", "db-01", "good"]);
    }

    fn cfg() -> Config {
        let mut c = Config { hosts: vec![
            HostCfg { name: "web-01".into(), groups: vec!["web".into()], tags: vec!["prod".into()], ..Default::default() },
            HostCfg { name: "web-02".into(), ssh: Some("me@web-02.example.com".into()), groups: vec!["web".into()], ..Default::default() },
            HostCfg { name: "db-01".into(), tags: vec!["prod".into(), "primary".into()], ..Default::default() },
        ], ..Default::default() };
        c.fleet.groups.insert("data".into(), vec!["db-*".into()]);
        c
    }

    #[test]
    fn inventory_and_select() {
        let dir = std::env::temp_dir().join(format!("fat-inv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hf = dir.join("hosts");
        std::fs::write(&hf, "db-01 groups=sql\nqueue-01 tags=prod\n").unwrap();
        let mut c = cfg();
        c.fleet.hosts_file = Some(hf.display().to_string());
        c.fleet.default_fat_path = Some("/usr/local/bin/fat".into());
        let all = inventory(&c).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(all.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), vec!["db-01", "queue-01", "web-01", "web-02"]);
        let db = &all[0];
        assert_eq!(db.groups, vec!["sql"], "groups merged across sources");
        assert_eq!(db.fat_path.as_deref(), Some("/usr/local/bin/fat"));
        assert_eq!(all[3].dest, "me@web-02.example.com");

        let names = |s: &Selector| select(&all, s, &c).into_iter().map(|t| t.name).collect::<Vec<_>>();
        assert_eq!(names(&Selector::default()).len(), 4);
        assert_eq!(names(&Selector { groups: vec!["web".into()], ..Default::default() }), vec!["web-01", "web-02"]);
        assert_eq!(names(&Selector { groups: vec!["data".into()], ..Default::default() }), vec!["db-01"]);
        assert_eq!(names(&Selector { tags: vec!["prod".into()], ..Default::default() }), vec!["db-01", "queue-01", "web-01"]);
        assert_eq!(names(&Selector { tags: vec!["prod".into(), "primary".into()], ..Default::default() }), vec!["db-01"]);
        assert_eq!(names(&Selector { hosts: vec!["web-*".into()], exclude: vec!["*-02".into()], ..Default::default() }), vec!["web-01"]);
        let sel = select(&all, &Selector { hosts: vec!["db-01".into()], ..Default::default() }, &c);
        assert_eq!(sel[0].groups, vec!["data", "sql"], "configured glob groups are attached");
    }

    #[test]
    fn missing_hosts_file_is_an_error() {
        let mut c = Config::default();
        c.fleet.hosts_file = Some("/nonexistent/fat-hosts".into());
        assert!(inventory(&c).is_err());
        assert!(inventory(&Config::default()).unwrap().is_empty());
    }
}
