//! "What happened at 03:12 and who did it?" — timelines and incident explanations built from the
//! recorder (events, units, kernel, procs) with a live fallback. OWNER: doctor-incident agent.
//!
//! Classic incidents explained end to end, each a chain symptom -> mechanism -> culprit:
//! OOM kill (victim, constraint host vs memcg, who held the memory at that moment from the
//! nearest recorded sample, what grew), restart loop / failed unit (result, exit code, restarts,
//! what changed just before), load high but CPU idle (D state + wchan, iowait, steal), disk
//! latency (await/queue by disk -> the unit/process whose io rose), disk full (fs growth),
//! fd/conntrack/ephemeral port exhaustion, noisy neighbour (cgroup throttling and PSI by unit).
//!
//! The engine reads through the small [`Recorded`] trait so the same code explains a recorder
//! window (`History`), a live snapshot (no recorder) and synthetic histories in tests.
//! Suggestions are text for a human or agent to run; fat never runs them.
use super::{ContainerMeta, Culprit, Event, EventKind, Incident, Kernel, ServerCfg, Severity, Unit, UnitKind, UnitPoint};
use crate::history::{History, Point};
use crate::model::{Proc, Snapshot, Ts};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};

/// Upper bound on events one timeline/incident query reads. A pathological host (a unit
/// restarting every second for a day) must not make `what-happened` slow or huge; the newest
/// events in the window are the ones that matter for an explanation.
const MAX_EVENTS: usize = 10_000;
/// Events attached to an Incident (the rest are summarised by count).
const MAX_INCIDENT_EVENTS: usize = 200;
/// How far before the anomaly onset a change counts as "just before" when the window is wider.
const CAUSE_LOOKBACK_MS: i64 = 15 * 60_000;
/// Units / processes compared when attributing a resource rise.
const TOP_N: usize = 5;

// ---------------------------------------------------------------------------------------------
// Data access
// ---------------------------------------------------------------------------------------------

/// What the incident engine reads. Implemented for [`History`] (the flight recorder) and for a
/// live snapshot; tests implement it over synthetic data.
pub trait Recorded {
    fn events(&self, from: Ts, to: Ts, kinds: &[EventKind], limit: usize) -> Result<Vec<Event>>;
    fn units_at(&self, ts: Ts) -> Result<Vec<Unit>>;
    fn unit_series(&self, name: &str, from: Ts, to: Ts) -> Result<Vec<UnitPoint>>;
    fn kernel_series(&self, from: Ts, to: Ts, max_points: usize) -> Result<Vec<(Ts, Kernel)>>;
    /// Snapshot (system + recorded procs) nearest to `ts`.
    fn snapshot_at(&self, ts: Ts) -> Result<Option<Snapshot>>;
    /// Oldest and newest sample.
    fn bounds(&self) -> Result<Option<(Ts, Ts)>>;
    fn spikes(&self, from: Ts, to: Ts) -> Result<Vec<Point>>;
    fn volume_mounts(&self) -> Result<Vec<String>>;
    fn volume_series(&self, mount: &str, from: Ts, to: Ts) -> Result<Vec<(Ts, u64, u64)>>;
    /// Bytes written per process in [from, to], largest first.
    fn proc_writes(&self, from: Ts, to: Ts) -> Result<Vec<(u32, String, u64)>>;
}

impl Recorded for History {
    fn events(&self, from: Ts, to: Ts, kinds: &[EventKind], limit: usize) -> Result<Vec<Event>> {
        History::events(self, from, to, kinds, limit)
    }
    fn units_at(&self, ts: Ts) -> Result<Vec<Unit>> {
        History::units_at(self, ts)
    }
    fn unit_series(&self, name: &str, from: Ts, to: Ts) -> Result<Vec<UnitPoint>> {
        History::unit_series(self, name, from, to)
    }
    fn kernel_series(&self, from: Ts, to: Ts, max_points: usize) -> Result<Vec<(Ts, Kernel)>> {
        History::kernel_series(self, from, to, max_points)
    }
    fn snapshot_at(&self, ts: Ts) -> Result<Option<Snapshot>> {
        History::at(self, ts)
    }
    fn bounds(&self) -> Result<Option<(Ts, Ts)>> {
        History::bounds(self)
    }
    fn spikes(&self, from: Ts, to: Ts) -> Result<Vec<Point>> {
        History::spikes(self, from, to)
    }
    fn volume_mounts(&self) -> Result<Vec<String>> {
        History::volume_mounts(self)
    }
    fn volume_series(&self, mount: &str, from: Ts, to: Ts) -> Result<Vec<(Ts, u64, u64)>> {
        History::volume_series(self, mount, from, to)
    }
    fn proc_writes(&self, from: Ts, to: Ts) -> Result<Vec<(u32, String, u64)>> {
        History::proc_writes(self, from, to)
    }
}

/// A live snapshot seen as a one-sample "recorder", plus kernel-log events and events derived
/// from the current state (failed units, ro mounts...).
struct Live<'a> {
    snap: &'a Snapshot,
    events: Vec<Event>,
}

impl Recorded for Live<'_> {
    fn events(&self, from: Ts, to: Ts, kinds: &[EventKind], limit: usize) -> Result<Vec<Event>> {
        let mut v: Vec<Event> =
            self.events.iter().filter(|e| e.ts >= from && e.ts <= to && (kinds.is_empty() || kinds.contains(&e.kind))).cloned().collect();
        v.sort_by_key(|e| e.ts);
        let n = v.len();
        Ok(v.into_iter().skip(n.saturating_sub(limit)).collect())
    }
    fn units_at(&self, _ts: Ts) -> Result<Vec<Unit>> {
        Ok(self.snap.units.clone())
    }
    fn unit_series(&self, name: &str, from: Ts, to: Ts) -> Result<Vec<UnitPoint>> {
        let ts = self.snap.ts;
        Ok(self
            .snap
            .units
            .iter()
            .filter(|u| u.name == name && ts >= from && ts <= to)
            .map(|u| point_of(ts, u))
            .collect())
    }
    fn kernel_series(&self, from: Ts, to: Ts, _max: usize) -> Result<Vec<(Ts, Kernel)>> {
        let ts = self.snap.ts;
        Ok(self.snap.kernel.clone().filter(|_| ts >= from && ts <= to).map(|k| vec![(ts, k)]).unwrap_or_default())
    }
    fn snapshot_at(&self, _ts: Ts) -> Result<Option<Snapshot>> {
        Ok(Some(self.snap.clone()))
    }
    fn bounds(&self) -> Result<Option<(Ts, Ts)>> {
        Ok(Some((self.snap.ts, self.snap.ts)))
    }
    fn spikes(&self, _: Ts, _: Ts) -> Result<Vec<Point>> {
        Ok(vec![])
    }
    fn volume_mounts(&self) -> Result<Vec<String>> {
        Ok(vec![])
    }
    fn volume_series(&self, _: &str, _: Ts, _: Ts) -> Result<Vec<(Ts, u64, u64)>> {
        Ok(vec![])
    }
    fn proc_writes(&self, _: Ts, _: Ts) -> Result<Vec<(u32, String, u64)>> {
        Ok(vec![])
    }
}

fn point_of(ts: Ts, u: &Unit) -> UnitPoint {
    UnitPoint {
        ts,
        state: u.state.clone(),
        restarts: u.restarts,
        cpu: u.cpu,
        mem: u.mem,
        mem_limit: u.mem_limit,
        pids: u.pids,
        io_read_bps: u.io_read_bps,
        io_write_bps: u.io_write_bps,
        cpu_throttled_pct: u.cpu_throttled_pct,
        psi: u.psi,
        oom_kills: u.oom_kills,
    }
}

// ---------------------------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------------------------

/// Recorded events in [from, to] (filtered by `kinds`, empty = all) merged with events derived
/// from recorded series (proc spikes via History::spikes, fs fill from volume series), sorted
/// oldest first, de-duplicated.
pub fn timeline(hist: &History, from: Ts, to: Ts, kinds: &[EventKind]) -> anyhow::Result<Vec<Event>> {
    timeline_of(hist, from, to, kinds)
}

/// [`timeline`] over any [`Recorded`] source.
pub fn timeline_of(src: &dyn Recorded, from: Ts, to: Ts, kinds: &[EventKind]) -> Result<Vec<Event>> {
    if to < from {
        bail!("empty time range: 'from' is after 'to'");
    }
    let mut v = src.events(from, to, kinds, MAX_EVENTS)?;
    let want = |k: EventKind| kinds.is_empty() || kinds.contains(&k);
    if want(EventKind::ProcSpike) {
        v.extend(src.spikes(from, to).unwrap_or_default().iter().map(spike_event));
    }
    if want(EventKind::FsFill) {
        let have: HashSet<String> = v.iter().filter(|e| e.kind == EventKind::FsFill).map(|e| e.subject.clone()).collect();
        for m in src.volume_mounts().unwrap_or_default() {
            let subject = format!("mount:{m}");
            if have.contains(&subject) {
                continue;
            }
            let series = src.volume_series(&m, from, to).unwrap_or_default();
            v.extend(fill_events(&m, &series));
        }
    }
    Ok(dedup_sorted(v))
}

fn dedup_sorted(mut v: Vec<Event>) -> Vec<Event> {
    v.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.kind.cmp(&b.kind)).then(a.subject.cmp(&b.subject)));
    let mut seen = HashSet::new();
    v.retain(|e| seen.insert((e.ts / 1000, e.kind, e.subject.clone())));
    v
}

fn spike_event(p: &Point) -> Event {
    let mut extra = std::collections::BTreeMap::new();
    if !p.top_name.is_empty() {
        extra.insert("top".into(), p.top_name.clone());
    }
    Event {
        ts: p.ts,
        kind: EventKind::ProcSpike,
        severity: Severity::Info,
        subject: "host".into(),
        detail: if p.top_name.is_empty() {
            format!("system CPU jumped to {:.0}%", p.cpu)
        } else {
            format!("system CPU jumped to {:.0}% (top: {} at {:.0}%)", p.cpu, p.top_name, p.top_cpu)
        },
        value: Some(p.cpu as f64),
        source: "recorder".into(),
        extra,
        ..Default::default()
    }
}

/// fs_fill events from one volume's (ts, used, avail) series: crossing 90% / 97% full, or
/// growing by at least 5% of its size inside the series.
fn fill_events(mount: &str, s: &[(Ts, u64, u64)]) -> Vec<Event> {
    let pct = |u: u64, a: u64| if u + a == 0 { 0.0 } else { u as f64 * 100.0 / (u + a) as f64 };
    let mut out = Vec::new();
    let mut prev: Option<f64> = None;
    for &(ts, u, a) in s {
        let p = pct(u, a);
        if let Some(q) = prev {
            for (thr, sev) in [(97.0, Severity::Crit), (90.0, Severity::Warn)] {
                if q < thr && p >= thr {
                    out.push(Event {
                        ts,
                        kind: EventKind::FsFill,
                        severity: sev,
                        subject: format!("mount:{mount}"),
                        detail: format!("{mount} reached {p:.0}% full ({} free)", human_bytes(a)),
                        value: Some(p),
                        source: "recorder".into(),
                        ..Default::default()
                    });
                    break;
                }
            }
        }
        prev = Some(p);
    }
    if out.is_empty()
        && let (Some(f), Some(l)) = (s.first(), s.last())
    {
        let total = (l.1 + l.2).max(1);
        if l.1 > f.1 && (l.1 - f.1) as f64 / total as f64 >= 0.05 {
            out.push(Event {
                ts: l.0,
                kind: EventKind::FsFill,
                severity: Severity::Info,
                subject: format!("mount:{mount}"),
                detail: format!(
                    "{mount} grew {} in {} (now {:.0}% full)",
                    human_bytes(l.1 - f.1),
                    human_dur(l.0 - f.0),
                    pct(l.1, l.2)
                ),
                value: Some(pct(l.1, l.2)),
                source: "recorder".into(),
                ..Default::default()
            });
        }
    }
    out
}

/// Explain one event (e.g. an OOM kill selected in the TUI).
pub fn explain_event(hist: Option<&History>, live: &Snapshot, ev: &Event) -> Incident {
    let w = default_window_for(ev.kind);
    let (from, to) = (ev.ts - w, ev.ts + w / 3);
    let r = match hist {
        Some(h) => analyze(h, &cfg(), ev.ts, true, from, to, Some(ev)).map(|mut i| {
            recorder_gaps(h, &mut i);
            i
        }),
        None => {
            let src = Live { snap: live, events: live_events(live, &cfg()) };
            analyze(&src, &cfg(), ev.ts, true, from, to, Some(ev)).map(|mut i| {
                i.gaps.push("no flight recorder: explained from the live snapshot only (run `fat record --server`)".into());
                i
            })
        }
    };
    let mut inc = r.unwrap_or_else(|e| Incident {
        at: ev.ts,
        from,
        to,
        severity: ev.severity,
        headline: ev.detail.clone(),
        chain: vec![ev.detail.clone()],
        events: vec![ev.clone()],
        gaps: vec![format!("recorder query failed: {e:#}")],
        ..Default::default()
    });
    if inc.host.is_empty() {
        inc.host = host_of(live);
    }
    inc
}

/// Entry point for CLI/MCP/TUI. `at` None = "the last `window_ms`". Uses the recorder when one
/// has data for the window; otherwise the live snapshot plus kernel::read_kmsg_since and unit
/// state, and says so in Incident.gaps. Never errors for missing data, only for bad input.
pub fn what_happened(hist: Option<&History>, live: &Snapshot, at: Option<Ts>, window_ms: i64) -> anyhow::Result<Incident> {
    what_happened_with(hist.map(|h| h as &dyn Recorded), live, at, window_ms, &cfg(), |since| {
        super::kernel::read_kmsg_since(Some(since))
    })
}

/// [`what_happened`] with an explicit source, config and kernel-log reader (tests).
pub fn what_happened_with(
    src: Option<&dyn Recorded>,
    live: &Snapshot,
    at: Option<Ts>,
    window_ms: i64,
    cfg: &ServerCfg,
    kmsg: impl Fn(Ts) -> Result<Vec<Event>>,
) -> Result<Incident> {
    if window_ms <= 0 {
        bail!("window must be positive");
    }
    let now = if live.ts > 0 { live.ts } else { crate::model::now_ms() };
    let explicit = at.is_some();
    let at = at.unwrap_or(now);
    if at > now + 60_000 {
        bail!("--at {} is in the future", fmt_ts(at, now));
    }
    let (from, to) = if explicit { (at - window_ms, (at + window_ms / 3).min(now)) } else { (now - window_ms, now) };

    // Prefer the recorder when it has samples in the window.
    let covered = src.and_then(|s| s.bounds().ok().flatten()).filter(|&(a, b)| b >= from && a <= to);
    if let (Some(s), Some((oldest, newest))) = (src, covered) {
        let mut inc = analyze(s, cfg, at, explicit, from, to, None)?;
        if oldest > from + 60_000 {
            inc.gaps.push(format!("recorder data starts at {}; nothing recorded before that", fmt_ts(oldest, now)));
        }
        if newest < to - 120_000 {
            inc.gaps.push(format!("recorder data ends at {} (is `fat record` still running?)", fmt_ts(newest, now)));
        }
        if !explicit && newest < now - 120_000 {
            // Current failures the recorder has not seen.
            let live_only: Vec<Event> =
                live_events(live, cfg).into_iter().filter(|e| !inc.events.iter().any(|x| x.kind == e.kind && x.subject == e.subject)).collect();
            if !live_only.is_empty() {
                inc.evidence.push(format!("live now: {}", live_only.iter().map(|e| e.detail.as_str()).collect::<Vec<_>>().join("; ")));
            }
        }
        if inc.host.is_empty() {
            inc.host = host_of(live);
        }
        return Ok(inc);
    }

    // Live fallback.
    let mut gaps = Vec::new();
    match src {
        None => gaps.push("no flight recorder: only the live snapshot and the kernel log were used (start one with `fat record --server`)".into()),
        Some(s) => match s.bounds().ok().flatten() {
            Some((a, b)) => gaps.push(format!(
                "the recorder has no samples between {} and {} (it holds {} .. {})",
                fmt_ts(from, now),
                fmt_ts(to, now),
                fmt_ts(a, now),
                fmt_ts(b, now)
            )),
            None => gaps.push("the flight recorder is empty (start it with `fat record --server`)".into()),
        },
    }
    let mut events = live_events(live, cfg);
    if cfg.kmsg && cfg!(target_os = "linux") {
        match kmsg(from) {
            Ok(k) => events.extend(k),
            Err(e) => gaps.push(format!("kernel log unreadable: {e:#}")),
        }
    } else if !cfg!(target_os = "linux") {
        gaps.push("no kernel log on this OS".into());
    }
    if explicit && now - at > window_ms {
        gaps.push(format!("{} is in the past and only the kernel log covers it; unit and resource data are from now", fmt_ts(at, now)));
    }
    let lv = Live { snap: live, events };
    let mut inc = analyze(&lv, cfg, at, explicit, from, to, None)?;
    inc.gaps.splice(0..0, gaps);
    if inc.host.is_empty() {
        inc.host = host_of(live);
    }
    Ok(inc)
}

/// Parse `--at`: "03:12" / "03:12:30" (today, local time; yesterday if in the future),
/// "2026-11-10 03:12", RFC 3339, epoch seconds, or a relative "-2h"/"2h ago".
pub fn parse_at(s: &str, now: Ts) -> anyhow::Result<Ts> {
    use chrono::{Local, NaiveDate, NaiveDateTime, NaiveTime, TimeZone};
    let t = s.trim();
    if t.is_empty() {
        bail!("empty time");
    }
    if t.eq_ignore_ascii_case("now") {
        return Ok(now);
    }
    let rel = t.strip_prefix('-').or_else(|| t.strip_suffix("ago").map(str::trim));
    if let Some(r) = rel {
        return Ok(now - parse_duration(r)?);
    }
    if t.bytes().all(|b| b.is_ascii_digit()) {
        let n: i64 = t.parse()?;
        // 11+ digits are milliseconds (epoch seconds pass 10^11 only in the year 5138).
        return Ok(if n >= 100_000_000_000 { n } else { n * 1000 });
    }
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(t) {
        return Ok(d.timestamp_millis());
    }
    let local = |ndt: NaiveDateTime| -> Result<Ts> {
        Local
            .from_local_datetime(&ndt)
            .earliest()
            .map(|d| d.timestamp_millis())
            .ok_or_else(|| anyhow::anyhow!("{t}: no such local time (DST gap)"))
    };
    for f in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(t, f) {
            return local(ndt);
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(t, "%Y-%m-%d") {
        return local(d.and_hms_opt(0, 0, 0).unwrap_or_default());
    }
    for f in ["%H:%M:%S", "%H:%M"] {
        if let Ok(tm) = NaiveTime::parse_from_str(t, f) {
            let today = Local.timestamp_millis_opt(now).single().map(|d| d.date_naive()).unwrap_or_default();
            let mut ts = local(today.and_time(tm))?;
            if ts > now + 60_000 {
                let y = today.pred_opt().unwrap_or(today);
                ts = local(y.and_time(tm))?;
            }
            return Ok(ts);
        }
    }
    bail!("can't read time {t:?}: use 03:12, 03:12:30, YYYY-MM-DD HH:MM, RFC 3339, epoch seconds, -2h or \"2h ago\"")
}

/// Parse a duration: "90s", "15m", "2h", "1d", "1h30m", "500ms"; a bare number is minutes.
pub fn parse_duration(s: &str) -> Result<i64> {
    let t = s.trim().to_ascii_lowercase();
    if t.is_empty() {
        bail!("empty duration");
    }
    if let Ok(n) = t.parse::<f64>() {
        if n < 0.0 {
            bail!("negative duration {s:?}");
        }
        return Ok((n * 60_000.0) as i64);
    }
    let mut total = 0f64;
    let mut num = String::new();
    let mut chars = t.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        if c.is_whitespace() {
            continue;
        }
        let mut unit = String::from(c);
        while let Some(&n) = chars.peek() {
            if n.is_ascii_alphabetic() {
                unit.push(n);
                chars.next();
            } else {
                break;
            }
        }
        let v: f64 = num.parse().map_err(|_| anyhow::anyhow!("bad duration {s:?}"))?;
        num.clear();
        let ms = match unit.as_str() {
            "ms" => 1.0,
            "s" | "sec" | "secs" | "second" | "seconds" => 1000.0,
            "m" | "min" | "mins" | "minute" | "minutes" => 60_000.0,
            "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000.0,
            "d" | "day" | "days" => 86_400_000.0,
            "w" | "week" | "weeks" => 604_800_000.0,
            _ => bail!("bad duration unit {unit:?} in {s:?} (use ms, s, m, h, d, w)"),
        };
        total += v * ms;
        any = true;
    }
    if !num.is_empty() || !any {
        bail!("bad duration {s:?}: add a unit, e.g. 15m or 2h");
    }
    Ok(total as i64)
}

/// Plain-text rendering used by `fat what-happened` and the TUI explain pane.
pub fn render(inc: &Incident) -> String {
    let now = crate::model::now_ms();
    let mut s = String::new();
    let host = if inc.host.is_empty() { "local" } else { &inc.host };
    s.push_str(&format!("{host} · {} · {}\n", fmt_ts(inc.at, now), inc.severity.as_str().to_uppercase()));
    s.push_str(&format!("{}\n", inc.headline));
    s.push_str(&format!("window {} .. {}\n", fmt_ts(inc.from, now), fmt_ts(inc.to, now)));
    if !inc.chain.is_empty() {
        s.push_str("\nWhat happened (symptom first, cause last):\n");
        for (i, c) in inc.chain.iter().enumerate() {
            s.push_str(&format!("  {}. {c}\n", i + 1));
        }
    }
    if !inc.culprits.is_empty() {
        s.push_str("\nWho:\n");
        for c in &inc.culprits {
            let pid = c.pid.map(|p| format!(" (pid {p})")).unwrap_or_default();
            s.push_str(&format!("  - {} {}{pid}: {}\n", c.kind, c.name, c.why));
        }
    }
    if !inc.evidence.is_empty() {
        s.push_str("\nEvidence:\n");
        for e in &inc.evidence {
            s.push_str(&format!("  - {e}\n"));
        }
    }
    if !inc.suggestions.is_empty() {
        s.push_str("\nNext steps (fat does not run these):\n");
        for x in &inc.suggestions {
            let prompt = if looks_like_command(x) { "$" } else { "-" };
            s.push_str(&format!("  {prompt} {x}\n"));
        }
    }
    if !inc.events.is_empty() {
        let shown = timeline_digest(&inc.events, 25);
        s.push_str(&format!("\nTimeline ({} event{}):\n", inc.events.len(), if inc.events.len() == 1 { "" } else { "s" }));
        for (e, n, last) in &shown {
            let rep = if *n > 1 { format!("  (x{n} until {})", fmt_ts(*last, now)) } else { String::new() };
            s.push_str(&format!("  {}  {:<4} {:<20} {}{rep}\n", fmt_ts(e.ts, now), e.severity.as_str(), e.kind.as_str(), e.detail));
        }
        let covered: usize = shown.iter().map(|x| x.1).sum();
        if covered < inc.events.len() {
            s.push_str(&format!("  ... {} more (fat events --json)\n", inc.events.len() - covered));
        }
    }
    if !inc.gaps.is_empty() {
        s.push_str("\nGaps:\n");
        for g in &inc.gaps {
            s.push_str(&format!("  - {g}\n"));
        }
    }
    s
}

/// A suggestion that is a shell command (rendered after "$") rather than advice.
fn looks_like_command(s: &str) -> bool {
    const CMDS: &[&str] = &[
        "systemctl", "journalctl", "docker", "podman", "crictl", "kubectl", "nerdctl", "ctr", "cat", "iostat", "pidstat", "smartctl",
        "conntrack", "ss", "fat", "for", "find", "timedatectl", "coredumpctl", "ls", "mdadm", "sysctl", "dmesg",
    ];
    s.split_whitespace().next().is_some_and(|w| CMDS.contains(&w))
}

/// At most `n` rows for display: repeats of one (kind, subject) collapse into their first
/// event with a count and the last time; warn/crit rows are kept first, shown in time order.
fn timeline_digest(ev: &[Event], n: usize) -> Vec<(&Event, usize, Ts)> {
    let mut rows: Vec<(&Event, usize, Ts)> = Vec::new();
    let mut at: HashMap<(EventKind, &str), usize> = HashMap::new();
    for e in ev {
        match at.get(&(e.kind, e.subject.as_str())) {
            Some(&i) => {
                rows[i].1 += 1;
                rows[i].2 = e.ts;
            }
            None => {
                at.insert((e.kind, e.subject.as_str()), rows.len());
                rows.push((e, 1, e.ts));
            }
        }
    }
    let mut idx: Vec<usize> = (0..rows.len()).collect();
    idx.sort_by_key(|&i| (std::cmp::Reverse(rows[i].0.severity), std::cmp::Reverse(rows[i].0.ts)));
    idx.truncate(n);
    idx.sort();
    idx.into_iter().map(|i| rows[i]).collect()
}

// ---------------------------------------------------------------------------------------------
// CLI / MCP glue
// ---------------------------------------------------------------------------------------------

/// Longest `--since` / `--window` accepted: older data is pruned by `history_days` anyway, and
/// a bounded window keeps one query cheap.
const MAX_SPAN_MS: i64 = 31 * 86_400_000;
/// Events printed by `fat events` without --json (all of them go to JSON, up to MAX_EVENTS).
const CLI_EVENT_ROWS: usize = 500;

/// A live snapshot with units, kernel and events filled regardless of the detected profile
/// (`FAT_PROFILE` still wins), sampled over 600 ms.
pub fn live_server_snapshot(cfg: &crate::config::Config) -> Snapshot {
    let mut c = cfg.clone();
    c.server.profile = "server".into();
    crate::history::live_snapshot(&c, std::time::Duration::from_millis(600))
}

/// `--since`: a duration ("2h") or a point in time accepted by [`parse_at`]. Returns `from`.
pub fn parse_since(s: &str, now: Ts) -> Result<Ts> {
    let from = match parse_duration(s) {
        Ok(d) => now - d,
        Err(_) => parse_at(s, now)?,
    };
    if from > now || now - from > MAX_SPAN_MS {
        bail!("--since {s:?} must be in the past and within 31 days");
    }
    Ok(from)
}

/// Kind names, '-' or '_' separated; an unknown one is an error listing the valid ones.
pub fn parse_kinds<S: AsRef<str>>(v: &[S]) -> Result<Vec<EventKind>> {
    v.iter()
        .flat_map(|k| k.as_ref().split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect::<Vec<_>>())
        .map(|k| {
            EventKind::parse(&k).ok_or_else(|| {
                anyhow::anyhow!("unknown event kind {k:?}; one of: {}", EventKind::ALL.iter().map(|k| k.as_str().replace('_', "-")).collect::<Vec<_>>().join(", "))
            })
        })
        .collect()
}

/// Events for [from, now]: (source, events, gaps). Recorder first; without one (or when it has
/// nothing for the window), the live snapshot's state plus the kernel log.
pub fn events_report(cfg: &crate::config::Config, from: Ts, kinds: &[EventKind], limit: usize) -> (String, Vec<Event>, Vec<String>) {
    let now = crate::model::now_ms();
    let mut gaps = Vec::new();
    let hist = crate::history::History::open_read_only(cfg.history_path.as_deref());
    if let Ok(h) = &hist {
        match h.bounds() {
            Ok(Some((a, b))) if b >= from => {
                let mut v = timeline(h, from, now, kinds).unwrap_or_else(|e| {
                    gaps.push(format!("recorder query failed: {e:#}"));
                    vec![]
                });
                if a > from + 60_000 {
                    gaps.push(format!("recorder data starts at {}", fmt_ts(a, now)));
                }
                if b < now - 120_000 {
                    gaps.push(format!("recorder data ends at {} (is `fat record` running?)", fmt_ts(b, now)));
                }
                let n = v.len();
                v.drain(..n.saturating_sub(limit));
                return ("recorder".into(), v, gaps);
            }
            _ => gaps.push("the flight recorder has nothing for this window (start it with `fat record --server`)".into()),
        }
    } else {
        gaps.push("no flight recorder database (start one with `fat record --server`)".into());
    }
    let live = live_server_snapshot(cfg);
    let mut v = live_events(&live, &cfg.server);
    if cfg.server.kmsg && cfg!(target_os = "linux") {
        match super::kernel::read_kmsg_since(Some(from)) {
            Ok(k) => v.extend(k),
            Err(e) => gaps.push(format!("kernel log unreadable: {e:#}")),
        }
    }
    v.retain(|e| e.ts >= from && (kinds.is_empty() || kinds.contains(&e.kind)));
    let mut v = dedup_sorted(v);
    let n = v.len();
    v.drain(..n.saturating_sub(limit));
    ("live".into(), v, gaps)
}

/// `fat events [--since 2h] [--kind K]... [--json]`.
pub fn cli_events(cfg: &crate::config::Config, since: &str, kinds: &[String], json: bool) -> Result<()> {
    let now = crate::model::now_ms();
    let from = parse_since(since, now)?;
    let kinds = parse_kinds(kinds)?;
    let (source, ev, gaps) = events_report(cfg, from, &kinds, MAX_EVENTS);
    if json {
        let v = serde_json::json!({ "source": source, "from": from, "to": now, "count": ev.len(), "events": ev, "gaps": gaps });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let src = if source == "recorder" { "the flight recorder" } else { "the live state and kernel log" };
    println!("{} event{} since {} (from {src})", ev.len(), if ev.len() == 1 { "" } else { "s" }, fmt_ts(from, now));
    let skip = ev.len().saturating_sub(CLI_EVENT_ROWS);
    if skip > 0 {
        println!("  ... {skip} older events not shown (--json lists all, --since narrows)");
    }
    for e in &ev[skip..] {
        println!("  {}  {:<4}  {:<20}  {:<28}  {}", fmt_ts(e.ts, now), e.severity.as_str(), e.kind.as_str(), trunc(&e.subject, 28), e.detail);
    }
    for g in &gaps {
        println!("  note: {g}");
    }
    Ok(())
}

/// `fat what-happened [--at TIME] [--window 15m] [--json]`.
pub fn cli_what_happened(cfg: &crate::config::Config, at: Option<&str>, window: &str, json: bool) -> Result<()> {
    let inc = what_happened_for(cfg, at, window)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&inc)?);
    } else {
        print!("{}", render(&inc));
    }
    Ok(())
}

/// Parse CLI/MCP arguments and run [`what_happened`] against the recorder (if any) and a live
/// server snapshot.
pub fn what_happened_for(cfg: &crate::config::Config, at: Option<&str>, window: &str) -> Result<Incident> {
    let now = crate::model::now_ms();
    let at = at.map(|a| parse_at(a, now)).transpose()?;
    let window_ms = parse_duration(window)?;
    if !(1000..=MAX_SPAN_MS).contains(&window_ms) {
        bail!("--window must be between 1s and 31d");
    }
    let hist = crate::history::History::open_read_only(cfg.history_path.as_deref()).ok();
    let live = live_server_snapshot(cfg);
    what_happened_with(hist.as_ref().map(|h| h as &dyn Recorded), &live, at, window_ms, &cfg.server, |since| {
        super::kernel::read_kmsg_since(Some(since))
    })
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n - 1).collect::<String>()) }
}

// ---------------------------------------------------------------------------------------------
// Live-state events
// ---------------------------------------------------------------------------------------------

/// Events implied by the current state (used without a recorder): failed and flapping units,
/// read-only remounts, fs errors, degraded arrays, slow disks, exhaustion, clock unsynced.
pub fn live_events(snap: &Snapshot, cfg: &ServerCfg) -> Vec<Event> {
    let ts = if snap.ts > 0 { snap.ts } else { crate::model::now_ms() };
    let mut v: Vec<Event> = snap.events.clone();
    let ev = |kind, severity, subject: String, unit: Option<String>, detail: String, value: Option<f64>| Event {
        ts,
        kind,
        severity,
        subject,
        unit,
        detail,
        value,
        source: "sampler".into(),
        ..Default::default()
    };
    for u in &snap.units {
        if u.is_failed() {
            let mut e = ev(EventKind::UnitFailed, Severity::Crit, subject_of(u), Some(u.name.clone()), failed_text(u), u.exit_code.map(f64::from));
            e.ts = u.since.unwrap_or(ts);
            if !u.result.is_empty() {
                e.extra.insert("result".into(), u.result.clone());
            }
            v.push(e);
        } else if u.flapping {
            v.push(ev(
                EventKind::UnitFlapping,
                Severity::Warn,
                subject_of(u),
                Some(u.name.clone()),
                format!("{} restarted {} times recently ({} total)", u.name, u.recent_restarts, u.restarts),
                Some(u.recent_restarts as f64),
            ));
        }
    }
    if let Some(k) = &snap.kernel {
        for m in &k.ro_remounts {
            v.push(ev(EventKind::RoRemount, Severity::Crit, format!("mount:{m}"), None, format!("{m} is now read-only (remounted after errors?)"), None));
        }
        for f in k.fs_errors.iter().filter(|f| f.errors > 0) {
            let subject = f.mount.as_ref().map(|m| format!("mount:{m}")).unwrap_or_else(|| format!("disk:{}", f.device));
            v.push(ev(EventKind::DiskError, Severity::Crit, subject, None, format!("{} reports {} filesystem errors", f.device, f.errors), Some(f.errors as f64)));
        }
        for md in k.mdraid.iter().filter(|m| m.degraded) {
            v.push(ev(EventKind::DiskError, Severity::Crit, format!("disk:{}", md.name), None, format!("RAID {} ({}) is degraded: {}", md.name, md.level, md.state), None));
        }
        for d in &k.disks {
            let aw = d.r_await_ms.max(d.w_await_ms);
            if aw >= cfg.disk_await_warn_ms {
                let mut e = ev(
                    EventKind::DiskLatencySpike,
                    Severity::Warn,
                    format!("disk:{}", d.name),
                    None,
                    format!("{} await {:.0} ms (r {:.0} / w {:.0}), queue {:.1}, util {:.0}%", d.name, aw, d.r_await_ms, d.w_await_ms, d.queue_depth, d.util_pct),
                    Some(aw as f64),
                );
                e.extra.insert("disk".into(), d.name.clone());
                v.push(e);
            }
        }
        for (what, used, max) in exhaustion_list(k) {
            let r = used as f64 / max.max(1) as f64;
            if r >= cfg.exhaustion_warn as f64 {
                let mut e = ev(
                    EventKind::Exhaustion,
                    if r >= 0.95 { Severity::Crit } else { Severity::Warn },
                    "host".into(),
                    None,
                    format!("{what}: {used} of {max} in use ({:.0}%)", r * 100.0),
                    Some(r * 100.0),
                );
                e.extra.insert("resource".into(), what.into());
                v.push(e);
            }
        }
        if k.ntp_synced == Some(false) {
            v.push(ev(EventKind::ClockUnsynced, Severity::Warn, "host".into(), None, "system clock is not synchronised".into(), None));
        }
    }
    v
}

/// (name, used, max) for each exhaustible kernel resource that is known.
pub(crate) fn exhaustion_list(k: &Kernel) -> Vec<(&'static str, u64, u64)> {
    let mut v = Vec::new();
    if let (Some(u), Some(m)) = (k.fd_used, k.fd_max)
        && m > 0
    {
        v.push(("file descriptors", u, m));
    }
    if let (Some(u), Some(m)) = (k.conntrack_used, k.conntrack_max)
        && m > 0
    {
        v.push(("conntrack entries", u, m));
    }
    if let (Some(u), Some((lo, hi))) = (k.ephemeral_used, k.ephemeral_range)
        && hi > lo
    {
        v.push(("ephemeral ports", u, (hi - lo) as u64 + 1));
    }
    v
}

// ---------------------------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------------------------

fn cfg() -> ServerCfg {
    static CFG: std::sync::OnceLock<ServerCfg> = std::sync::OnceLock::new();
    CFG.get_or_init(|| crate::config::Config::load().server).clone()
}

fn default_window_for(k: EventKind) -> i64 {
    match k {
        EventKind::FsFill => 60 * 60_000,
        _ => 15 * 60_000,
    }
}

fn recorder_gaps(h: &dyn Recorded, inc: &mut Incident) {
    match h.bounds() {
        Ok(Some((a, _))) if a > inc.from + 60_000 => {
            inc.gaps.push(format!("recorder data starts at {}", fmt_ts(a, crate::model::now_ms())))
        }
        Ok(None) => inc.gaps.push("the flight recorder is empty".into()),
        _ => {}
    }
}

fn host_of(s: &Snapshot) -> String {
    if !s.system.hostname.is_empty() {
        s.system.hostname.clone()
    } else if s.host.is_empty() {
        "local".into()
    } else {
        s.host.clone()
    }
}

/// Work-in-progress explanation.
#[derive(Default)]
struct Story {
    headline: String,
    chain: Vec<String>,
    evidence: Vec<String>,
    culprits: Vec<Culprit>,
    suggestions: Vec<String>,
    gaps: Vec<String>,
    /// 0..1, see [`confidence_label`].
    confidence: f32,
}

impl Story {
    fn suggest(&mut self, s: impl Into<String>) {
        let s = s.into();
        if !self.suggestions.contains(&s) {
            self.suggestions.push(s);
        }
    }
    fn culprit(&mut self, c: Culprit) {
        if !self.culprits.iter().any(|x| x.kind == c.kind && x.name == c.name) {
            self.culprits.push(c);
        }
    }
}

struct Cx<'a> {
    src: &'a dyn Recorded,
    cfg: &'a ServerCfg,
    from: Ts,
    to: Ts,
    now: Ts,
    events: Vec<Event>,
}

fn analyze(src: &dyn Recorded, cfg: &ServerCfg, at: Ts, explicit: bool, from: Ts, to: Ts, focus: Option<&Event>) -> Result<Incident> {
    let now = crate::model::now_ms().max(to);
    let mut events = timeline_of(src, from, to, &[])?;
    if let Some(f) = focus
        && !events.iter().any(|e| e.ts / 1000 == f.ts / 1000 && e.kind == f.kind && e.subject == f.subject)
    {
        events.push(f.clone());
        events.sort_by_key(|e| e.ts);
    }
    let cx = Cx { src, cfg, from, to, now, events };
    // "Near --at": a tenth of the window, at least two minutes.
    let band = ((to - from) / 10).max(120_000);
    let focus = focus.cloned().or_else(|| pick_focus(&cx.events, at, explicit, band));
    let mut st = Story::default();
    let (sev, at) = match &focus {
        Some(f) => {
            explain_focus(&cx, f, &mut st);
            (f.severity, f.ts)
        }
        None => match series_anomaly(&cx, &mut st) {
            Some((sev, ts)) => (sev, ts),
            None => {
                st.headline = format!("Nothing notable recorded between {} and {}", fmt_ts(from, now), fmt_ts(to, now));
                // Still say what changed most around the moment asked about.
                let lo = if explicit { at - 60_000 } else { from + (to - from) / 2 };
                for r in [Res::Io, Res::Cpu, Res::Mem] {
                    if let Some(x) = risers(&cx, lo, at.min(to), r).into_iter().find(|x| x.peak > x.before * 2.0 && x.peak - x.before >= significant(r)) {
                        st.evidence.push(format!(
                            "biggest {} rise: {} {} -> {} at {}",
                            match r {
                                Res::Io => "I/O",
                                Res::Cpu => "CPU",
                                Res::Mem => "memory",
                            },
                            x.unit.name,
                            fmt_res(x.before, r),
                            fmt_res(x.peak, r),
                            fmt_ts(x.peak_ts, now)
                        ));
                    }
                }
                (Severity::Info, at)
            }
        },
    };
    // Other notable things in the window, not already part of the story.
    let mentioned: HashSet<&str> = focus.iter().map(|f| f.subject.as_str()).collect();
    let mut others: Vec<&Event> =
        cx.events.iter().filter(|e| e.severity >= Severity::Warn && !mentioned.contains(e.subject.as_str())).collect();
    others.sort_by_key(|e| (std::cmp::Reverse(e.severity), e.ts));
    let mut seen = HashSet::new();
    for e in others.into_iter().filter(|e| seen.insert((e.kind, e.subject.clone()))).take(5) {
        st.evidence.push(format!("also: {} {} {}", fmt_ts(e.ts, now), e.kind.as_str(), e.detail));
    }
    let severity = cx.events.iter().map(|e| e.severity).max().unwrap_or(sev).max(sev);
    st.confidence = st.confidence.clamp(0.0, 1.0);
    if focus.is_some() || !st.chain.is_empty() {
        st.evidence.push(format!("confidence: {} ({:.1})", confidence_label(st.confidence), st.confidence));
    }
    let mut events = cx.events;
    if events.len() > MAX_INCIDENT_EVENTS {
        let keep: HashSet<usize> = {
            let mut idx: Vec<usize> = (0..events.len()).collect();
            idx.sort_by_key(|&i| (std::cmp::Reverse(events[i].severity), (events[i].ts - at).abs()));
            idx.into_iter().take(MAX_INCIDENT_EVENTS).collect()
        };
        let dropped = events.len() - keep.len();
        events = events.into_iter().enumerate().filter(|(i, _)| keep.contains(i)).map(|(_, e)| e).collect();
        st.gaps.push(format!("{dropped} lower-priority events in the window omitted (fat events --since ... --json lists all)"));
    }
    Ok(Incident {
        host: String::new(),
        from,
        to,
        at,
        severity,
        headline: st.headline,
        chain: st.chain,
        evidence: st.evidence,
        culprits: st.culprits,
        suggestions: st.suggestions,
        events,
        gaps: st.gaps,
    })
}

pub(crate) fn confidence_label(c: f32) -> &'static str {
    if c >= 0.7 {
        "high"
    } else if c >= 0.4 {
        "medium"
    } else {
        "low"
    }
}

/// How much an event kind explains on its own (ties between equally severe events).
fn kind_weight(k: EventKind) -> u8 {
    use EventKind::*;
    match k {
        OomKill => 10,
        RoRemount | DiskError => 9,
        UnitFailed => 8,
        HungTask => 7,
        UnitFlapping => 7,
        DiskLatencySpike => 6,
        Exhaustion => 6,
        FsFill => 5,
        PressureSpike => 5,
        Throttle => 4,
        UnitRestart => 4,
        KernelWarn => 3,
        ClockUnsynced => 2,
        ProcessExitNotable | ProcSpike => 1,
        DeployBurst | UnitStart | UnitStop | Other => 0,
    }
}

/// The event the story is about. With --at: events within `band_ms` of `at` first (an
/// operator asking about 03:12 means 03:12, not the worst thing earlier in the window), then
/// events already under way by then, then severity, explanatory kind, nearness. Without: severity, kind, newest.
fn pick_focus(ev: &[Event], at: Ts, explicit: bool, band_ms: i64) -> Option<Event> {
    /// An event is recorded up to one sample interval (plus kernel-log or systemctl refresh
    /// delay) after it happened; a minute covers the default intervals with room to spare.
    const AFTER_SLACK_MS: i64 = 60_000;
    ev.iter()
        .filter(|e| e.severity >= Severity::Warn || kind_weight(e.kind) >= 4)
        .max_by_key(|e| {
            let d = (e.ts - at).abs();
            // A filling-but-not-full volume is a forecast; what already happened comes first.
            let sev = if e.kind == EventKind::FsFill && e.value.is_some_and(|v| v < 90.0) { e.severity.min(Severity::Warn) } else { e.severity };
            // What was already happening at `at` (or surfaced within AFTER_SLACK_MS of it, the
            // delay of a sample or the kernel log) explains that moment better than something
            // worse that happened later in the band.
            // Within the band, what is close to `at` (half the band, at least the slack) beats
            // a more explanatory kind further away: a throttle 50 s before the moment asked
            // about is the story, not a disk spike two minutes earlier.
            let by_then = e.ts <= at + AFTER_SLACK_MS;
            let near = d <= (band_ms / 2).max(AFTER_SLACK_MS);
            if explicit { (d <= band_ms, by_then, near, sev, kind_weight(e.kind), -d) } else { (true, true, true, sev, kind_weight(e.kind), e.ts) }
        })
        .cloned()
}

fn explain_focus(cx: &Cx, f: &Event, st: &mut Story) {
    use EventKind::*;
    match f.kind {
        OomKill => explain_oom(cx, f, st),
        UnitFailed | UnitFlapping | UnitRestart | UnitStop => explain_unit(cx, f, st),
        DiskLatencySpike | HungTask => explain_io(cx, f, st),
        PressureSpike if f.extra.get("resource").is_some_and(|r| r == "io") || f.detail.contains("io") => explain_io(cx, f, st),
        PressureSpike | Throttle => explain_contention(cx, f, st),
        Exhaustion => explain_exhaustion(cx, f, st),
        FsFill => explain_fs_fill(cx, f, st),
        RoRemount | DiskError => explain_disk_error(cx, f, st),
        _ => explain_generic(cx, f, st),
    }
}

// ---------------------------------------------------------------------------------------------
// Shared analysis helpers
// ---------------------------------------------------------------------------------------------

fn unit_name_of(e: &Event) -> Option<String> {
    e.unit.clone().or_else(|| {
        let (p, rest) = e.subject.split_once(':')?;
        matches!(p, "unit" | "container" | "pod").then(|| rest.to_string())
    })
}

/// The event subject for a unit ("unit:nginx.service", "container:web", "pod:ns/name").
pub(crate) fn subject_of(u: &Unit) -> String {
    match u.kind {
        UnitKind::Container => format!("container:{}", u.name),
        UnitKind::Pod => format!("pod:{}", u.name),
        _ => format!("unit:{}", u.name),
    }
}

fn find_unit<'a>(units: &'a [Unit], name: &str) -> Option<&'a Unit> {
    units.iter().find(|u| u.name == name).or_else(|| units.iter().find(|u| u.container.as_ref().is_some_and(|c| c.id == name || c.name == name)))
}

/// The unit owning a cgroup path, by exact cgroup or by unit_of_cgroup key.
fn unit_for_cgroup<'a>(units: &'a [Unit], cg: &str) -> Option<&'a Unit> {
    if cg.is_empty() {
        return None;
    }
    if let Some(u) = units.iter().find(|u| !u.cgroup.is_empty() && (u.cgroup == cg || cg.starts_with(&format!("{}/", u.cgroup)))) {
        return Some(u);
    }
    let r = super::unit_of_cgroup(cg)?;
    units.iter().find(|u| {
        u.kind == r.kind
            && (u.name == r.key
                || u.container.as_ref().is_some_and(|c| c.id == r.key || c.pod_uid.as_deref() == Some(r.key.as_str()))
                || u.cgroup == r.key)
    })
}

/// Read-only next steps for one unit: logs and status in the unit's own tooling.
pub(crate) fn unit_next_steps(name: &str, kind: UnitKind, meta: Option<&ContainerMeta>, since: Option<Ts>) -> Vec<String> {
    let since_arg = since.map(|t| format!(" --since \"{}\"", fmt_abs(t))).unwrap_or_default();
    match kind {
        UnitKind::Systemd => vec![
            format!("systemctl status {name} --no-pager"),
            format!("journalctl -u {name}{since_arg} -n 100 --no-pager"),
        ],
        UnitKind::Container => {
            let rt = meta.map(|m| m.runtime.as_str()).unwrap_or("");
            if let Some((ns, pod)) = meta.and_then(|m| Some((m.namespace.as_deref()?, m.pod.as_deref()?))) {
                return vec![format!("kubectl -n {ns} describe pod {pod}"), format!("kubectl -n {ns} logs {pod} --all-containers --previous")];
            }
            let cli = match rt {
                "podman" => "podman",
                "containerd" | "cri-o" | "crio" | "kubernetes" => "crictl",
                _ => "docker",
            };
            let since = since.map(|t| format!(" --since {}", t / 1000)).unwrap_or_default();
            vec![format!("{cli} logs{since} --tail 100 {name}"), format!("{cli} inspect {name}")]
        }
        UnitKind::Pod => {
            let (ns, pod) = name.split_once('/').unwrap_or(("default", name));
            vec![format!("kubectl -n {ns} describe pod {pod}"), format!("kubectl -n {ns} logs {pod} --all-containers --previous")]
        }
        UnitKind::Cgroup => vec![format!("cat /sys/fs/cgroup{name}/cgroup.procs"), format!("cat /sys/fs/cgroup{name}/memory.events")],
    }
}

fn failed_text(u: &Unit) -> String {
    let mut s = format!("{} failed", u.name);
    let mut why = Vec::new();
    if !u.result.is_empty() && u.result != "success" {
        why.push(u.result.clone());
    }
    if let Some(c) = u.exit_code.filter(|c| *c != 0) {
        why.push(format!("status {c}"));
    }
    if !why.is_empty() {
        s.push_str(&format!(" ({})", why.join(", ")));
    }
    if u.restarts > 0 {
        s.push_str(&format!(" after {} restarts", u.restarts));
    }
    s
}

/// Units nearest before `ts` (the recorder returns the nearest sample; try a little earlier
/// first so an OOM victim is seen while it still held memory).
fn units_before(cx: &Cx, ts: Ts) -> Vec<Unit> {
    for back in [2_000, 0, -5_000] {
        if let Ok(u) = cx.src.units_at(ts - back)
            && !u.is_empty()
        {
            return u;
        }
    }
    vec![]
}

fn snapshot_before(cx: &Cx, ts: Ts) -> Option<Snapshot> {
    for back in [2_000, 10_000, 0] {
        if let Ok(Some(s)) = cx.src.snapshot_at(ts - back)
            && (s.ts <= ts || back == 0)
        {
            return Some(s);
        }
    }
    None
}

/// A change shortly before an anomaly: unit start/restart, deploy-like burst, cron/timer job,
/// backup, package manager, or a new heavy process.
#[derive(Debug, Clone)]
struct Change {
    ts: Ts,
    what: String,
    label: &'static str,
    unit: Option<String>,
    pid: Option<u32>,
}

fn is_backup_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    ["backup", "pg_dump", "pg_basebackup", "mysqldump", "mariadb-dump", "xtrabackup", "mariabackup", "mongodump", "rsync", "restic", "borg", "duplicity", "rclone", "tar", "rsnapshot", "bacula", "snapshot"]
        .iter()
        .any(|k| if *k == "tar" { l == "tar" || l.starts_with("tar ") } else { l.contains(k) })
}

fn is_cron_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    l.ends_with(".timer") || matches!(l.as_str(), "cron" | "crond" | "anacron" | "atd" | "fcron" | "cronie") || l.starts_with("cron.") || l.starts_with("crond.")
}

fn is_pkg_name(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    matches!(l.as_str(), "apt" | "apt-get" | "aptitude" | "dnf" | "yum" | "rpm" | "zypper" | "pacman" | "apk" | "snapd" | "flatpak")
        || l.starts_with("dpkg")
        || l.starts_with("unattended-upgr")
        || l.starts_with("packagekit")
        || l.contains("apt-daily")
        || l.contains("dnf-makecache")
}

fn label_for(name: &str, kind: EventKind) -> &'static str {
    if is_backup_name(name) {
        "backup"
    } else if is_cron_name(name) {
        "scheduled job"
    } else if is_pkg_name(name) {
        "package update"
    } else if kind == EventKind::DeployBurst {
        "deploy-like burst"
    } else if kind == EventKind::UnitRestart {
        "restart"
    } else {
        "start"
    }
}

/// Changes in [onset - lookback, onset + slack], newest first.
fn changes_before(cx: &Cx, onset: Ts, exclude_unit: Option<&str>) -> Vec<Change> {
    let lookback = CAUSE_LOOKBACK_MS.min((onset - cx.from).max(60_000));
    let lo = onset - lookback;
    let hi = onset + 5_000;
    let mut out: Vec<Change> = Vec::new();
    for e in cx.events.iter().filter(|e| e.ts >= lo && e.ts <= hi) {
        if !matches!(e.kind, EventKind::UnitStart | EventKind::UnitRestart | EventKind::DeployBurst) {
            continue;
        }
        let unit = unit_name_of(e);
        if unit.is_some() && unit.as_deref() == exclude_unit {
            continue;
        }
        // A unit that keeps restarting is its own incident, not a change that caused this one.
        if e.kind == EventKind::UnitRestart
            && cx.events.iter().filter(|x| matches!(x.kind, EventKind::UnitRestart | EventKind::UnitFlapping) && x.subject == e.subject).count()
                >= cx.cfg.flap_restarts.max(2) as usize
        {
            continue;
        }
        let name = unit.clone().unwrap_or_else(|| e.subject.clone());
        // A timer firing a service: name the timer when the event says so.
        let label = match e.extra.get("trigger") {
            Some(t) if is_cron_name(t) => "scheduled job",
            _ => label_for(&name, e.kind),
        };
        let what = match e.kind {
            EventKind::DeployBurst => format!("{} ({})", e.detail, label),
            _ => format!("{} {} at {}", name, if e.kind == EventKind::UnitRestart { "restarted" } else { "started" }, fmt_ts(e.ts, cx.now)),
        };
        out.push(Change { ts: e.ts, what, label, unit, pid: e.pid });
    }
    // New processes from the recorded proc set (cron jobs, backups, package managers).
    if let Some(s) = cx.src.snapshot_at(onset + 2_000).ok().flatten() {
        let units = units_before(cx, onset);
        for p in s.procs.iter().filter(|p| {
            let st = p.start_time as i64 * 1000;
            p.start_time > 0 && st >= lo && st <= hi
        }) {
            let anc_cron = s.ancestors(p.pid).iter().any(|a| is_cron_name(&a.name));
            let unit = unit_for_cgroup(&units, &p.cgroup).map(|u| u.name.clone());
            if unit.is_some() && unit.as_deref() == exclude_unit {
                continue;
            }
            let label = if is_backup_name(&p.name) || is_backup_name(&p.cmd) {
                "backup"
            } else if anc_cron || unit.as_deref().is_some_and(is_cron_name) || p.cgroup.contains("cron") {
                "scheduled job"
            } else if is_pkg_name(&p.name) {
                "package update"
            } else if p.cpu >= 50.0 || p.disk_read_bps + p.disk_write_bps >= 10 * MB || p.mem >= GB {
                "new heavy process"
            } else {
                continue;
            };
            if out.iter().any(|c| c.unit.is_some() && c.unit == unit && c.label != "start") {
                continue;
            }
            let st = p.start_time as i64 * 1000;
            out.push(Change {
                ts: st,
                what: format!(
                    "{} (pid {}) started at {}{}",
                    short_cmd(p),
                    p.pid,
                    fmt_ts(st, cx.now),
                    unit.as_ref().map(|u| format!(" in {u}")).unwrap_or_default()
                ),
                label,
                unit,
                pid: Some(p.pid),
            });
        }
    }
    out.sort_by_key(|c| std::cmp::Reverse(c.ts));
    out.truncate(8);
    out
}

fn short_cmd(p: &Proc) -> String {
    let c = if p.cmd.is_empty() { p.name.as_str() } else { p.cmd.as_str() };
    let mut s: String = c.chars().take(60).collect();
    if c.chars().count() > 60 {
        s.push('…');
    }
    s
}

/// Which resource a unit is compared on.
#[derive(Clone, Copy, PartialEq)]
enum Res {
    Io,
    Mem,
    Cpu,
}

fn res_of_point(p: &UnitPoint, r: Res) -> f64 {
    match r {
        Res::Io => (p.io_read_bps + p.io_write_bps) as f64,
        Res::Mem => p.mem as f64,
        Res::Cpu => p.cpu as f64,
    }
}

fn res_of_unit(u: &Unit, r: Res) -> f64 {
    match r {
        Res::Io => (u.io_read_bps + u.io_write_bps) as f64,
        Res::Mem => u.mem as f64,
        Res::Cpu => u.cpu as f64,
    }
}

fn fmt_res(v: f64, r: Res) -> String {
    match r {
        Res::Io => human_rate(v as u64),
        Res::Mem => human_bytes(v as u64),
        Res::Cpu => format!("{v:.0}% cpu"),
    }
}

/// A unit whose resource use rose around `onset`: (unit, before, peak, peak ts).
struct Riser {
    unit: Unit,
    before: f64,
    peak: f64,
    peak_ts: Ts,
    first_ts: Ts,
}

/// Units ranked by how much `r` rose from before `onset` to the peak in [onset, until].
fn risers(cx: &Cx, onset: Ts, until: Ts, r: Res) -> Vec<Riser> {
    let mut cand: Vec<Unit> = units_before(cx, until);
    for u in units_before(cx, onset) {
        if !cand.iter().any(|c| c.name == u.name) {
            cand.push(u);
        }
    }
    cand.sort_by(|a, b| res_of_unit(b, r).total_cmp(&res_of_unit(a, r)));
    // Look at the units that are biggest at either end, bounded.
    let mut names: Vec<String> = cand.iter().take(TOP_N * 2).map(|u| u.name.clone()).collect();
    for e in cx.events.iter().filter(|e| e.ts >= onset - CAUSE_LOOKBACK_MS && e.ts <= until) {
        if let Some(n) = unit_name_of(e)
            && !names.contains(&n)
            && names.len() < TOP_N * 4
        {
            names.push(n);
        }
    }
    let lo = (onset - CAUSE_LOOKBACK_MS).max(cx.from);
    let mut out = Vec::new();
    for n in names {
        let u = cand.iter().find(|u| u.name == n).cloned().unwrap_or_else(|| Unit { name: n.clone(), ..Default::default() });
        let s = cx.src.unit_series(&n, lo, until).unwrap_or_default();
        if s.is_empty() {
            let v = res_of_unit(&u, r);
            out.push(Riser { unit: u, before: 0.0, peak: v, peak_ts: until, first_ts: until });
            continue;
        }
        let pre: Vec<f64> = s.iter().filter(|p| p.ts < onset).map(|p| res_of_point(p, r)).collect();
        let before = if pre.is_empty() { 0.0 } else { median(&pre) };
        let (peak_ts, peak) =
            s.iter().filter(|p| p.ts >= onset - 2_000).map(|p| (p.ts, res_of_point(p, r))).fold((until, 0.0), |a, b| if b.1 > a.1 { b } else { a });
        let first_ts = s.iter().find(|p| p.ts >= lo && res_of_point(p, r) > before.max(1.0) * 2.0).map(|p| p.ts).unwrap_or(peak_ts);
        out.push(Riser { unit: u, before, peak, peak_ts, first_ts });
    }
    out.sort_by(|a, b| (b.peak - b.before).total_cmp(&(a.peak - a.before)));
    out.retain(|x| x.peak > 0.0);
    out.truncate(TOP_N);
    out
}

/// A rise worth mentioning when nothing crossed a threshold.
fn significant(r: Res) -> f64 {
    match r {
        Res::Io => MB as f64,
        Res::Cpu => 20.0,
        Res::Mem => (256 * MB) as f64,
    }
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    s[s.len() / 2]
}

fn add_changes(cx: &Cx, onset: Ts, exclude: Option<&str>, st: &mut Story) -> Vec<Change> {
    let ch = changes_before(cx, onset, exclude);
    if !ch.is_empty() {
        st.evidence.push(format!(
            "changes before onset: {}",
            ch.iter().take(4).map(|c| format!("{} [{}]", c.what, c.label)).collect::<Vec<_>>().join("; ")
        ));
    }
    ch
}

// ---------------------------------------------------------------------------------------------
// Explainers
// ---------------------------------------------------------------------------------------------

fn explain_oom(cx: &Cx, f: &Event, st: &mut Story) {
    let x = &f.extra;
    let victim = x.get("victim").cloned().or_else(|| x.get("victim_name").cloned()).unwrap_or_else(|| {
        f.pid.map(|p| format!("pid {p}")).unwrap_or_else(|| "a process".into())
    });
    let pid = f.pid.or_else(|| x.get("victim_pid").and_then(|p| p.parse().ok()));
    let memcg = x.get("memcg").cloned().unwrap_or_default();
    let constraint = x.get("constraint").cloned().unwrap_or_default();
    let rss_kb: u64 = ["rss_kb", "anon_rss_kb"].iter().find_map(|k| x.get(*k).and_then(|v| v.parse().ok())).unwrap_or(0);
    let units = units_before(cx, f.ts);
    let vunit = f
        .unit
        .clone()
        .or_else(|| unit_for_cgroup(&units, &memcg).map(|u| u.name.clone()))
        .or_else(|| super::unit_of_cgroup(&memcg).map(|r| r.key));
    let memcg_limited = constraint.contains("MEMCG") || (!memcg.is_empty() && memcg != "/" && constraint.is_empty() && vunit.as_ref().and_then(|n| find_unit(&units, n)).is_some_and(|u| u.mem_limit.is_some()));
    let at = fmt_ts(f.ts, cx.now);
    let pid_s = pid.map(|p| format!(" (pid {p})")).unwrap_or_default();
    let in_unit = vunit.as_ref().map(|u| format!(" in {u}")).unwrap_or_default();
    st.chain.push(format!(
        "{victim}{pid_s}{in_unit} was killed by the kernel OOM killer at {at}{}",
        if rss_kb > 0 { format!(", holding {}", human_bytes(rss_kb * 1024)) } else { String::new() }
    ));
    st.confidence = 0.4;
    if !x.is_empty() {
        st.confidence += 0.1;
    }

    // Who held the memory.
    let lo = (f.ts - CAUSE_LOOKBACK_MS).max(cx.from);
    let mut by_mem: Vec<&Unit> = units.iter().filter(|u| u.mem > 0).collect();
    by_mem.sort_by_key(|u| std::cmp::Reverse(u.mem));
    let snap = snapshot_before(cx, f.ts);
    let mem_total = snap.as_ref().map(|s| s.system.mem_total).unwrap_or(0);
    let share = |b: u64| if mem_total > 0 { format!(" ({:.0}% of RAM)", b as f64 * 100.0 / mem_total as f64) } else { String::new() };

    if memcg_limited {
        let lim_unit = vunit.as_ref().and_then(|n| find_unit(&units, n));
        let limit = lim_unit.and_then(|u| u.mem_limit).or_else(|| x.get("limit").and_then(|v| v.parse().ok()));
        st.chain.push(format!(
            "{} hit its own memory limit{} (cgroup {}), so the kernel killed inside it; the rest of the host was not short of memory",
            vunit.clone().unwrap_or_else(|| "its cgroup".into()),
            limit.map(|l| format!(" of {}", human_bytes(l))).unwrap_or_default(),
            if memcg.is_empty() { "?".to_string() } else { memcg.clone() }
        ));
        if let Some(n) = &vunit {
            let s = cx.src.unit_series(n, lo, f.ts).unwrap_or_default();
            if let (Some(first), Some(peak)) = (s.first(), s.iter().max_by_key(|p| p.mem)) {
                st.evidence.push(format!(
                    "{n} memory {} at {} -> {} at {}{}",
                    human_bytes(first.mem),
                    fmt_ts(first.ts, cx.now),
                    human_bytes(peak.mem),
                    fmt_ts(peak.ts, cx.now),
                    peak.mem_limit.map(|l| format!(" (limit {})", human_bytes(l))).unwrap_or_default()
                ));
                if peak.mem > first.mem.saturating_mul(3) / 2 {
                    st.chain.push(format!("{n} grew {} in {} before the kill", human_bytes(peak.mem - first.mem), human_dur(peak.ts - first.ts)));
                }
                st.confidence += 0.3;
            }
            st.culprit(Culprit {
                kind: "unit".into(),
                name: n.clone(),
                pid,
                unit: Some(n.clone()),
                why: format!("its memory limit was reached{}", limit.map(|l| format!(" ({})", human_bytes(l))).unwrap_or_default()),
                mem: lim_unit.map(|u| u.mem),
                cpu: None,
            });
        }
        if let Some(n) = &vunit {
            let kind = find_unit(&units, n).map(|u| u.kind).unwrap_or(UnitKind::Systemd);
            if kind == UnitKind::Systemd {
                st.suggest(format!("systemctl show {n} -p MemoryMax,MemoryHigh,MemoryPeak"));
            }
            for s in unit_next_steps(n, kind, find_unit(&units, n).and_then(|u| u.container.as_ref()), Some(f.ts - 300_000)) {
                st.suggest(s);
            }
        }
        st.suggest("raise the unit's memory limit only after checking for a leak (MemoryMax= for systemd, --memory for containers, resources.limits.memory for pods)");
    } else {
        let avail = cx.src.kernel_series(lo, f.ts, 60).unwrap_or_default();
        let min_avail = avail.iter().filter(|(_, k)| k.mem_available > 0).map(|(t, k)| (*t, k.mem_available)).min_by_key(|x| x.1);
        st.chain.push(format!(
            "the whole host ran out of memory{}",
            min_avail.map(|(t, a)| format!(" (MemAvailable fell to {} at {})", human_bytes(a), fmt_ts(t, cx.now))).unwrap_or_default()
        ));
        if let Some(s) = &snap
            && s.system.swap_total > 0
        {
            st.evidence.push(format!("swap {} of {} used at {}", human_bytes(s.system.swap_used), human_bytes(s.system.swap_total), fmt_ts(s.ts, cx.now)));
        }
    }

    // Biggest memory holders at that moment (units, then processes).
    if !by_mem.is_empty() {
        st.evidence.push(format!(
            "memory by unit just before {}: {}",
            at,
            by_mem.iter().take(TOP_N).map(|u| format!("{} {}", u.name, human_bytes(u.mem))).collect::<Vec<_>>().join(", ")
        ));
        let top = by_mem[0];
        let s = cx.src.unit_series(&top.name, lo, f.ts).unwrap_or_default();
        let growth = match (s.first(), s.iter().max_by_key(|p| p.mem)) {
            (Some(a), Some(b)) if b.mem > a.mem + 64 * MB => format!(", grew {} in {}", human_bytes(b.mem - a.mem), human_dur(b.ts - a.ts)),
            _ => String::new(),
        };
        if !memcg_limited {
            let is_victim = vunit.as_deref() == Some(top.name.as_str());
            st.chain.push(format!(
                "{} held the most memory: {}{}{growth}{}",
                top.name,
                human_bytes(top.mem),
                share(top.mem),
                if is_victim { " (the victim itself: a leak or an undersized host)" } else { "" }
            ));
            st.culprit(Culprit {
                kind: "unit".into(),
                name: top.name.clone(),
                pid: top.main_pid,
                unit: Some(top.name.clone()),
                why: format!("used {}{} at {}{growth}", human_bytes(top.mem), share(top.mem), fmt_ts(f.ts, cx.now)),
                cpu: Some(top.cpu),
                mem: Some(top.mem),
            });
            st.confidence += if s.len() > 1 { 0.3 } else { 0.15 };
            if !is_victim {
                for x in unit_next_steps(&top.name, top.kind, top.container.as_ref(), Some(f.ts - 600_000)) {
                    st.suggest(x);
                }
            }
        }
    }
    if let Some(s) = &snap {
        let mut ps: Vec<&Proc> = s.procs.iter().filter(|p| p.mem > 0).collect();
        ps.sort_by_key(|p| std::cmp::Reverse(p.mem));
        if !ps.is_empty() {
            st.evidence.push(format!(
                "top processes by memory at {}: {}",
                fmt_ts(s.ts, cx.now),
                ps.iter().take(TOP_N).map(|p| format!("{} (pid {}) {}", p.name, p.pid, human_bytes(p.mem))).collect::<Vec<_>>().join(", ")
            ));
            if by_mem.is_empty() && !memcg_limited {
                let p = ps[0];
                st.chain.push(format!("{} (pid {}) held the most memory: {}{}", p.name, p.pid, human_bytes(p.mem), share(p.mem)));
                st.culprit(Culprit { kind: "process".into(), name: p.name.clone(), pid: Some(p.pid), unit: None, why: format!("{} resident at {}", human_bytes(p.mem), fmt_ts(s.ts, cx.now)), cpu: Some(p.cpu), mem: Some(p.mem) });
                st.confidence += 0.15;
            }
        }
    } else if by_mem.is_empty() {
        st.gaps.push("no recorded sample near the kill: who held the memory is unknown".into());
        st.confidence -= 0.1;
    }
    if let Some(inv) = x.get("invoker") {
        st.evidence.push(format!("allocation that triggered it came from {inv}"));
    }
    // What happened to the victim's unit afterwards.
    if let Some(n) = &vunit
        && let Some(after) = cx.events.iter().find(|e| {
            e.ts >= f.ts && unit_name_of(e).as_deref() == Some(n.as_str()) && matches!(e.kind, EventKind::UnitFailed | EventKind::UnitRestart | EventKind::UnitStop)
        })
    {
        st.chain.insert(1, format!("then {} at {}", after.detail, fmt_ts(after.ts, cx.now)));
    }
    let changes = add_changes(cx, f.ts, None, st);
    if let Some(c) = changes.iter().find(|c| matches!(c.label, "backup" | "scheduled job" | "deploy-like burst" | "new heavy process")) {
        st.chain.push(format!("just before: {} [{}]", c.what, c.label));
    }
    if crate::blame::is_protected_server_name(&victim) {
        st.suggest(format!("{victim} is a database/system service: investigate its memory settings and workload before restarting or raising limits"));
    }
    st.suggest(format!("journalctl -k --since \"{}\" --until \"{}\" --no-pager | grep -iE -A25 'invoked oom-killer'", fmt_abs(f.ts - 120_000), fmt_abs(f.ts + 60_000)));
    let culprit = st.culprits.first().map(|c| c.name.clone());
    st.headline = match culprit {
        Some(c) if memcg_limited => format!("{victim} OOM-killed at {at}: {c} hit its memory limit"),
        Some(c) if Some(&c) != vunit.as_ref() => format!("{victim} OOM-killed at {at}: host out of memory, {c} held the most"),
        Some(c) => format!("{victim} OOM-killed at {at}: {c} grew until the host ran out of memory"),
        None => format!("{victim} OOM-killed at {at}"),
    };
}

fn explain_unit(cx: &Cx, f: &Event, st: &mut Story) {
    let name = unit_name_of(f).unwrap_or_else(|| f.subject.clone());
    let units = units_before(cx, f.ts + 1_000);
    let u = find_unit(&units, &name).cloned();
    let kind = u.as_ref().map(|u| u.kind).unwrap_or_else(|| match (f.extra.get("kind").map(String::as_str), f.subject.split_once(':').map(|x| x.0)) {
        (Some("container"), _) | (_, Some("container")) => UnitKind::Container,
        (Some("k8s-pod"), _) | (_, Some("pod")) => UnitKind::Pod,
        (Some("cgroup"), _) => UnitKind::Cgroup,
        _ => UnitKind::Systemd,
    });
    let mine: Vec<&Event> = cx.events.iter().filter(|e| unit_name_of(e).as_deref() == Some(name.as_str())).collect();
    // One event may stand for several restarts (coalesced while a unit flaps).
    let restarts: usize = mine.iter().filter(|e| e.kind == EventKind::UnitRestart).map(|e| e.value.map_or(1, |v| (v as usize).max(1))).sum();
    let fails = mine.iter().filter(|e| e.kind == EventKind::UnitFailed).count();
    let troubled = |e: &&&Event| matches!(e.kind, EventKind::UnitFailed | EventKind::UnitRestart | EventKind::UnitFlapping | EventKind::UnitStop);
    let first = mine.iter().find(troubled).map(|e| e.ts).unwrap_or(f.ts);
    let last = mine.iter().rev().find(troubled).map(|e| e.ts).unwrap_or(f.ts);
    let at = fmt_ts(f.ts, cx.now);
    let flapping = f.kind == EventKind::UnitFlapping || u.as_ref().is_some_and(|u| u.flapping) || restarts >= cx.cfg.flap_restarts as usize;
    st.confidence = 0.4;
    st.chain.push(match f.kind {
        EventKind::UnitFailed => format!("{} at {at}", f.detail),
        _ if flapping => format!(
            "{name} is in a restart loop: {} between {} and {}",
            {
                // The recorded restart counter is exact; events are what the sampler saw.
                let series = cx.src.unit_series(&name, cx.from, cx.to).unwrap_or_default();
                let delta = match (series.first(), series.last()) {
                    (Some(a), Some(b)) if b.restarts > a.restarts => (b.restarts - a.restarts) as usize,
                    _ => 0,
                };
                if delta > 0 {
                    format!("{delta} restart{}", if delta == 1 { "" } else { "s" })
                } else {
                    let n = restarts.max(u.as_ref().map(|u| u.recent_restarts as usize).unwrap_or(0));
                    format!("{n} restart{} seen", if n == 1 { "" } else { "s" })
                }
            },
            fmt_ts(first, cx.now),
            fmt_ts(last.max(f.ts), cx.now)
        ),
        _ => format!("{} at {at}", f.detail),
    });
    // Exit reason: the unit's current properties, else the newest one its events carried (a
    // restarting unit is usually "active" again by the time it is sampled).
    let from_events = |key: &str| mine.iter().rev().find_map(|e| e.extra.get(key).filter(|v| !v.is_empty() && *v != "success").cloned());
    let result = u.as_ref().map(|u| u.result.clone()).filter(|r| !r.is_empty() && r != "success").or_else(|| from_events("result")).unwrap_or_default();
    let exit_code: Option<i32> =
        u.as_ref().and_then(|u| u.exit_code).filter(|c| *c != 0).or_else(|| from_events("exit_code").and_then(|c| c.parse().ok()));
    let mut facts = Vec::new();
    if !result.is_empty() {
        facts.push(format!("result {result}"));
    }
    if let Some(c) = exit_code {
        facts.push(format!("exit status {c}"));
    }
    if let Some(u) = &u {
        facts.push(format!("state {}/{}", u.state, u.sub_state));
        facts.push(format!("{} restarts total", u.restarts));
    }
    if !facts.is_empty() {
        st.evidence.push(format!("{name}: {}", facts.join(", ")));
    }
    match result.as_str() {
        "oom-kill" => st.chain.push(format!("{name} was killed for exceeding memory (result oom-kill)")),
        "core-dump" | "signal" => st.chain.push(format!("{name} crashed (result {result}): check for a core dump with `coredumpctl list {name}`")),
        "timeout" => st.chain.push(format!("{name} did not start or stop within its timeout")),
        "start-limit-hit" => st.chain.push(format!("{name} restarted too often and systemd stopped retrying (start-limit-hit)")),
        "exit-code" => st.chain.push(format!("{name}'s main process exited with status {} (an application error: the logs say why)", exit_code.unwrap_or(1))),
        "" if exit_code.is_some() => st.chain.push(format!("{name}'s main process exited with status {}", exit_code.unwrap_or(1))),
        _ => {}
    }
    if let Some(u) = &u
        && let (Some(l), true) = (u.mem_limit, u.mem > 0)
    {
        let r = u.mem as f64 / l as f64;
        if r >= cx.cfg.exhaustion_warn as f64 {
            st.chain.push(format!("{name} was at {:.0}% of its memory limit ({} of {})", r * 100.0, human_bytes(u.mem), human_bytes(l)));
        }
    }
    // OOM kills in the unit around the failure.
    if let Some(o) = cx.events.iter().find(|e| e.kind == EventKind::OomKill && (e.ts - first).abs() <= 120_000 && (unit_name_of(e).as_deref() == Some(name.as_str()) || e.extra.get("memcg").is_some_and(|m| m.contains(&name)))) {
        st.chain.push(format!("the kernel OOM-killed {} in it at {}", o.extra.get("victim").cloned().unwrap_or_else(|| "a process".into()), fmt_ts(o.ts, cx.now)));
        st.confidence += 0.2;
    }
    if fails > 1 {
        st.evidence.push(format!("{fails} failures of {name} in the window"));
    }
    // Something that changed just before the first failure.
    let ch = add_changes(cx, first, Some(&name), st);
    if let Some(c) = ch.iter().find(|c| c.label == "package update") {
        st.chain.push(format!("a package update ran just before: {}", c.what));
        st.culprit(Culprit { kind: "process".into(), name: c.what.clone(), pid: c.pid, unit: c.unit.clone(), why: "package changes right before the first failure".into(), ..Default::default() });
        st.confidence += 0.15;
    } else if let Some(c) = ch.iter().find(|c| c.label != "start" || (0..=60_000).contains(&(first - c.ts))) {
        // A plain start of some other unit minutes earlier is noise; a backup, scheduled job,
        // deploy burst or a start right before is worth naming.
        st.chain.push(format!("just before the first failure: {} [{}]", c.what, c.label));
        st.confidence += 0.05;
    }
    // A deploy of this unit itself (start burst / start events of this unit).
    if let Some(d) = mine.iter().find(|e| e.kind == EventKind::DeployBurst && e.ts <= first + 5_000) {
        st.chain.push(format!("{name} was being (re)deployed: {}", d.detail));
    }
    st.culprit(Culprit {
        kind: "unit".into(),
        name: name.clone(),
        pid: u.as_ref().and_then(|u| u.main_pid),
        unit: Some(name.clone()),
        why: if flapping { format!("restarting repeatedly since {}", fmt_ts(first, cx.now)) } else { "failed".into() },
        cpu: u.as_ref().map(|u| u.cpu),
        mem: u.as_ref().map(|u| u.mem),
    });
    for s in unit_next_steps(&name, kind, u.as_ref().and_then(|u| u.container.as_ref()), Some(first - 60_000)) {
        st.suggest(s);
    }
    if kind == UnitKind::Systemd {
        if crate::blame::is_protected_server_name(name.trim_end_matches(".service")) {
            st.suggest(format!("{name} is a database/system service: read its own log and the journal before restarting it"));
        } else {
            st.suggest(format!("after fixing the cause: systemctl reset-failed {name} && systemctl restart {name}"));
        }
    }
    st.headline = if flapping {
        format!("{name} restart loop since {}", fmt_ts(first, cx.now))
    } else {
        format!("{} at {at}", f.detail)
    };
    if st.chain.len() <= 1 {
        st.gaps.push(format!("no exit reason recorded for {name}: its logs hold the answer"));
    } else {
        st.confidence += 0.2;
    }
}

fn explain_io(cx: &Cx, f: &Event, st: &mut Story) {
    let ks = cx.src.kernel_series(cx.from, cx.to, 400).unwrap_or_default();
    let disk_hint = f.extra.get("disk").cloned().or_else(|| f.subject.strip_prefix("disk:").map(str::to_string));
    let aw = |k: &Kernel, d: &str| k.disks.iter().find(|x| x.name == d).map(|x| x.r_await_ms.max(x.w_await_ms)).unwrap_or(0.0);
    // Worst disk in the window.
    let mut worst: Option<(String, Ts, f32)> = None;
    for (t, k) in &ks {
        for d in &k.disks {
            let a = d.r_await_ms.max(d.w_await_ms);
            if disk_hint.as_ref().is_none_or(|h| *h == d.name) && worst.as_ref().is_none_or(|w| a > w.2) {
                worst = Some((d.name.clone(), *t, a));
            }
        }
    }
    let thr = cx.cfg.disk_await_warn_ms;
    let mut onset = f.ts;
    st.confidence = 0.3;
    if let Some((disk, peak_ts, peak)) = &worst {
        // Onset: first sample at/above half the threshold walking back from the peak.
        let pre: Vec<f64> = ks.iter().filter(|(t, _)| *t < *peak_ts).map(|(_, k)| aw(k, disk) as f64).collect();
        let mut on = *peak_ts;
        for (t, k) in ks.iter().rev().filter(|(t, _)| *t <= *peak_ts) {
            if aw(k, disk) >= thr / 2.0 {
                on = *t;
            } else {
                break;
            }
        }
        onset = on.min(f.ts);
        let base = if pre.is_empty() { None } else { Some(median(&pre)) };
        let at_peak = ks.iter().find(|(t, _)| t == peak_ts).map(|(_, k)| k);
        let q = at_peak.and_then(|k| k.disks.iter().find(|x| &x.name == disk)).map(|d| (d.queue_depth, d.util_pct)).unwrap_or_default();
        st.chain.push(format!(
            "{disk} latency rose{} to {:.0} ms at {} (queue {:.1}, util {:.0}%)",
            base.map(|b| format!(" from {b:.0} ms")).unwrap_or_default(),
            peak,
            fmt_ts(*peak_ts, cx.now),
            q.0,
            q.1
        ));
        if let Some(k) = at_peak {
            describe_stall(cx, k, st);
        }
        st.confidence += 0.1;
    } else {
        st.chain.push(format!("{} at {}", f.detail, fmt_ts(f.ts, cx.now)));
        if let Some((_, k)) = ks.iter().min_by_key(|(t, _)| (t - f.ts).abs()) {
            describe_stall(cx, k, st);
        }
    }
    if f.kind == EventKind::HungTask {
        st.evidence.push(format!("kernel: {}", f.detail));
    }
    // Who did the I/O.
    let peak_ts = worst.as_ref().map(|w| w.1).unwrap_or(f.ts);
    let rs = risers(cx, onset, peak_ts.max(onset) + 1_000, Res::Io);
    if let Some(r) = rs.first().filter(|r| r.peak >= MB as f64) {
        let n = &r.unit.name;
        st.chain.push(format!(
            "{n} I/O rose from {} to {} at {}",
            human_rate(r.before as u64),
            human_rate(r.peak as u64),
            fmt_ts(r.peak_ts, cx.now)
        ));
        let total: f64 = rs.iter().map(|x| x.peak).sum::<f64>().max(1.0);
        st.culprit(Culprit {
            kind: "unit".into(),
            name: n.clone(),
            pid: r.unit.main_pid,
            unit: Some(n.clone()),
            why: format!("{} of I/O at {} ({:.0}% of unit I/O), up from {}", human_rate(r.peak as u64), fmt_ts(r.peak_ts, cx.now), r.peak * 100.0 / total, human_rate(r.before as u64)),
            cpu: Some(r.unit.cpu),
            mem: Some(r.unit.mem),
        });
        if rs.len() > 1 {
            st.evidence.push(format!("unit I/O at peak: {}", rs.iter().map(|x| format!("{} {}", x.unit.name, human_rate(x.peak as u64))).collect::<Vec<_>>().join(", ")));
        }
        st.confidence += if r.before == 0.0 || r.peak >= r.before * 3.0 { 0.3 } else { 0.15 };
        for s in unit_next_steps(n, r.unit.kind, r.unit.container.as_ref(), Some(onset - 60_000)) {
            st.suggest(s);
        }
        if r.first_ts < onset {
            onset = onset.min(r.first_ts.max(onset - CAUSE_LOOKBACK_MS));
        }
    }
    // Units whose processes were stuck in D state on it (hung_task events carry the unit).
    let mut blocked: HashMap<String, usize> = HashMap::new();
    for e in cx.events.iter().filter(|e| e.kind == EventKind::HungTask && e.ts >= onset - 30_000 && e.ts <= peak_ts + 120_000) {
        if let Some(u) = &e.unit {
            *blocked.entry(u.clone()).or_default() += 1;
        }
    }
    let mut blocked: Vec<(String, usize)> = blocked.into_iter().collect();
    blocked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    if !blocked.is_empty() {
        st.evidence.push(format!("blocked in D state, by unit: {}", blocked.iter().take(TOP_N).map(|(u, n)| format!("{u} x{n}")).collect::<Vec<_>>().join(", ")));
        if st.culprits.is_empty() {
            let (u, n) = &blocked[0];
            st.culprit(Culprit { kind: "unit".into(), name: u.clone(), unit: Some(u.clone()), why: format!("{n} of its processes were waiting on the disk (doing the I/O, or starved by it)"), ..Default::default() });
            st.confidence += 0.1;
            let units = units_before(cx, peak_ts);
            let found = find_unit(&units, u);
            for x in unit_next_steps(u, found.map(|f| f.kind).unwrap_or(UnitKind::Systemd), found.and_then(|f| f.container.as_ref()), Some(onset - 60_000)) {
                st.suggest(x);
            }
        }
    }
    // Process level.
    let writers = cx.src.proc_writes(onset - 30_000, peak_ts + 1_000).unwrap_or_default();
    if !writers.is_empty() {
        st.evidence.push(format!(
            "bytes written {}..{}: {}",
            fmt_ts(onset - 30_000, cx.now),
            fmt_ts(peak_ts, cx.now),
            writers.iter().take(TOP_N).map(|(p, n, b)| format!("{n} (pid {p}) {}", human_bytes(*b))).collect::<Vec<_>>().join(", ")
        ));
        if st.culprits.is_empty() {
            let (p, n, b) = &writers[0];
            st.culprit(Culprit { kind: "process".into(), name: n.clone(), pid: Some(*p), unit: None, why: format!("wrote {} around the spike", human_bytes(*b)), ..Default::default() });
            st.confidence += 0.15;
        }
    } else if let Some(s) = snapshot_before(cx, peak_ts + 2_000) {
        let mut ps: Vec<&Proc> = s.procs.iter().filter(|p| p.disk_read_bps + p.disk_write_bps > 0).collect();
        ps.sort_by_key(|p| std::cmp::Reverse(p.disk_read_bps + p.disk_write_bps));
        if !ps.is_empty() {
            st.evidence.push(format!(
                "top disk users at {}: {}",
                fmt_ts(s.ts, cx.now),
                ps.iter().take(TOP_N).map(|p| format!("{} (pid {}) {}", p.name, p.pid, human_rate(p.disk_read_bps + p.disk_write_bps))).collect::<Vec<_>>().join(", ")
            ));
            if st.culprits.is_empty() {
                let p = ps[0];
                st.culprit(Culprit { kind: "process".into(), name: p.name.clone(), pid: Some(p.pid), unit: None, why: format!("{} disk I/O at {}", human_rate(p.disk_read_bps + p.disk_write_bps), fmt_ts(s.ts, cx.now)), cpu: Some(p.cpu), mem: Some(p.mem) });
                st.confidence += 0.1;
            }
        }
    }
    let ch = add_changes(cx, onset, None, st);
    let culprit_unit = st.culprits.first().and_then(|c| c.unit.clone());
    if let Some(c) = ch.iter().find(|c| c.unit.is_some() && c.unit == culprit_unit).or_else(|| ch.iter().find(|c| matches!(c.label, "backup" | "scheduled job" | "package update"))).or(ch.first()) {
        st.chain.push(format!("it began with: {} [{}]", c.what, c.label));
        st.confidence += if c.unit.is_some() && c.unit == culprit_unit { 0.2 } else { 0.1 };
        if st.culprits.is_empty() {
            st.culprit(Culprit { kind: if c.unit.is_some() { "unit" } else { "process" }.into(), name: c.unit.clone().unwrap_or_else(|| c.what.clone()), pid: c.pid, unit: c.unit.clone(), why: format!("{} right before the latency rose", c.label), ..Default::default() });
        }
    }
    if let Some((d, _, _)) = &worst {
        st.suggest(format!("iostat -x 1 5 {d}   # or: cat /sys/block/{d}/stat"));
        st.suggest("pidstat -d 1 5   # live per-process I/O (sysstat)");
    }
    let disk = worst.as_ref().map(|w| w.0.clone()).unwrap_or_else(|| "disk".into());
    st.headline = match st.culprits.first() {
        Some(c) => format!("{disk} I/O latency spike at {}: {} ({})", fmt_ts(peak_ts, cx.now), c.name, c.kind),
        None => format!("{disk} I/O latency spike at {}", fmt_ts(peak_ts, cx.now)),
    };
}

/// "load high but CPU idle": D-state processes, iowait, steal.
fn describe_stall(cx: &Cx, k: &Kernel, st: &mut Story) {
    if k.procs_blocked > 0 || !k.d_state.is_empty() {
        let mut w: HashMap<&str, usize> = HashMap::new();
        for d in &k.d_state {
            *w.entry(d.wchan.as_str()).or_default() += 1;
        }
        let mut wv: Vec<_> = w.into_iter().filter(|(k, _)| !k.is_empty()).collect();
        wv.sort_by_key(|x| std::cmp::Reverse(x.1));
        st.chain.push(format!(
            "{} processes blocked in uninterruptible I/O wait (D){}",
            k.procs_blocked.max(k.d_state.len() as u32),
            if wv.is_empty() { String::new() } else { format!(", waiting in {}", wv.iter().take(3).map(|(w, n)| format!("{w} x{n}")).collect::<Vec<_>>().join(", ")) }
        ));
        if !k.d_state.is_empty() {
            st.evidence.push(format!(
                "D state: {}",
                k.d_state.iter().take(TOP_N).map(|d| format!("{} (pid {}) {}s{}", d.name, d.pid, d.seconds, d.unit.as_ref().map(|u| format!(" in {u}")).unwrap_or_default())).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    if k.iowait_pct >= 5.0 || k.steal_pct >= 5.0 {
        st.evidence.push(format!("iowait {:.0}%, steal {:.0}%", k.iowait_pct, k.steal_pct));
    }
    if k.steal_pct >= 10.0 {
        st.chain.push(format!("the hypervisor withheld {:.0}% of CPU time (steal): a neighbour VM or an exhausted CPU credit", k.steal_pct));
        st.culprit(Culprit { kind: "external".into(), name: "hypervisor".into(), why: format!("{:.0}% CPU steal", k.steal_pct), ..Default::default() });
    }
    if let Some(p) = &k.pressure
        && p.io_full >= 5.0
    {
        st.evidence.push(format!("PSI io {:.0}% some / {:.0}% full", p.io_some, p.io_full));
    }
    let _ = cx;
}

fn explain_contention(cx: &Cx, f: &Event, st: &mut Story) {
    let name = unit_name_of(f);
    let units = units_before(cx, f.ts + 1_000);
    st.confidence = 0.35;
    let mem = f.extra.get("resource").is_some_and(|r| r == "memory") || f.detail.to_ascii_lowercase().contains("memory");
    st.chain.push(format!("{} at {}", f.detail, fmt_ts(f.ts, cx.now)));
    if let Some(n) = &name
        && let Some(u) = find_unit(&units, n)
        && f.kind == EventKind::Throttle
    {
        let quota = u.cpu_quota.map(|q| format!("{q:.1} cores")).unwrap_or_else(|| "?".into());
        st.chain.push(format!(
            "{n} was throttled {:.0}% of the time by its CPU quota ({quota}) while using {:.0}% cpu",
            u.cpu_throttled_pct, u.cpu
        ));
        let at_quota = u.cpu_quota.is_some_and(|q| u.cpu >= q * 100.0 * 0.8);
        st.chain.push(if at_quota {
            format!("{n} needs more CPU than its quota allows: raise CPUQuota=/cpu.max or reduce its work")
        } else {
            format!("{n} uses less than its quota on average but bursts past it: a short cpu.max period or bursty threads")
        });
        st.culprit(Culprit { kind: "unit".into(), name: n.clone(), pid: u.main_pid, unit: Some(n.clone()), why: format!("throttled {:.0}% (quota {quota})", u.cpu_throttled_pct), cpu: Some(u.cpu), mem: Some(u.mem) });
        st.confidence += 0.3;
        if u.kind == UnitKind::Systemd {
            st.suggest(format!("systemctl show {n} -p CPUQuotaPerSecUSec,CPUWeight"));
        }
        st.suggest(format!("cat /sys/fs/cgroup{}/cpu.stat", u.cgroup));
    }
    // Neighbours: units whose cpu (or memory) rose at the same time.
    let r = if mem { Res::Mem } else { Res::Cpu };
    let onset = cx.events.iter().filter(|e| e.kind == f.kind && e.subject == f.subject && e.ts <= f.ts && f.ts - e.ts <= CAUSE_LOOKBACK_MS).map(|e| e.ts).min().unwrap_or(f.ts);
    let rs = risers(cx, onset, f.ts + 1_000, r);
    if let Some(x) = rs.iter().find(|x| Some(&x.unit.name) != name.as_ref() && x.peak > x.before * 1.5 && x.peak - x.before >= if mem { 256.0 * MB as f64 } else { 50.0 }) {
        st.chain.push(format!(
            "noisy neighbour: {} rose from {} to {} at {}",
            x.unit.name,
            fmt_res(x.before, r),
            fmt_res(x.peak, r),
            fmt_ts(x.peak_ts, cx.now)
        ));
        st.culprit(Culprit {
            kind: "unit".into(),
            name: x.unit.name.clone(),
            pid: x.unit.main_pid,
            unit: Some(x.unit.name.clone()),
            why: format!("{} -> {} while others stalled", fmt_res(x.before, r), fmt_res(x.peak, r)),
            cpu: Some(x.unit.cpu),
            mem: Some(x.unit.mem),
        });
        st.confidence += 0.3;
        for s in unit_next_steps(&x.unit.name, x.unit.kind, x.unit.container.as_ref(), Some(onset - 60_000)) {
            st.suggest(s);
        }
    }
    let mut psi: Vec<&Unit> = units.iter().filter(|u| u.psi.is_some_and(|p| if mem { p.mem_full >= 5.0 } else { p.cpu_some >= 20.0 })).collect();
    psi.sort_by(|a, b| {
        let k = |u: &Unit| u.psi.map(|p| if mem { p.mem_full } else { p.cpu_some }).unwrap_or(0.0);
        k(b).total_cmp(&k(a))
    });
    if !psi.is_empty() {
        st.evidence.push(format!(
            "units stalled ({} PSI): {}",
            if mem { "memory full" } else { "cpu some" },
            psi.iter().take(TOP_N).map(|u| {
                let p = u.psi.unwrap_or_default();
                format!("{} {:.0}%", u.name, if mem { p.mem_full } else { p.cpu_some })
            }).collect::<Vec<_>>().join(", ")
        ));
    }
    if mem {
        let ks = cx.src.kernel_series(onset - 60_000, f.ts + 1_000, 60).unwrap_or_default();
        if let Some((t, k)) = ks.iter().max_by(|a, b| (a.1.swap_in_ps + a.1.swap_out_ps).total_cmp(&(b.1.swap_in_ps + b.1.swap_out_ps)))
            && k.swap_in_ps + k.swap_out_ps >= 100.0
        {
            st.chain.push(format!("the host was swapping {:.0} pages/s in, {:.0} out at {}", k.swap_in_ps, k.swap_out_ps, fmt_ts(*t, cx.now)));
        }
    }
    add_changes(cx, onset, name.as_deref(), st);
    st.headline = match st.culprits.iter().find(|c| Some(&c.name) != name.as_ref()).or(st.culprits.first()) {
        Some(c) => format!("{} at {}: {}", if f.kind == EventKind::Throttle { "CPU throttling" } else if mem { "memory pressure" } else { "CPU pressure" }, fmt_ts(f.ts, cx.now), c.name),
        None => format!("{} at {}", f.detail, fmt_ts(f.ts, cx.now)),
    };
}

fn explain_exhaustion(cx: &Cx, f: &Event, st: &mut Story) {
    let res = f.extra.get("resource").cloned().unwrap_or_else(|| f.detail.split(':').next().unwrap_or("resource").to_string());
    st.confidence = 0.35;
    st.chain.push(format!("{} at {}", f.detail, fmt_ts(f.ts, cx.now)));
    let l = res.to_ascii_lowercase();
    let (mech, cmds): (&str, &[&str]) = if l.contains("file") || l.contains("fd") {
        (
            "new files and sockets fail with EMFILE/ENFILE (\"Too many open files\") once the limit is hit",
            &["for p in /proc/[0-9]*; do echo \"$(ls $p/fd 2>/dev/null | wc -l) $(cat $p/comm 2>/dev/null) ${p#/proc/}\"; done | sort -rn | head", "cat /proc/sys/fs/file-nr"],
        )
    } else if l.contains("conntrack") {
        ("new connections are dropped (\"nf_conntrack: table full, dropping packet\") once the table is full", &["conntrack -S", "conntrack -L -o extended 2>/dev/null | awk '{print $3}' | sort | uniq -c | sort -rn | head"])
    } else if l.contains("port") {
        ("outgoing connections fail with EADDRNOTAVAIL once every local port toward a destination is used (often TIME_WAIT from short-lived connections)", &["ss -s", "ss -tan state time-wait | awk '{print $4}' | sort | uniq -c | sort -rn | head"])
    } else if l.contains("memory") {
        ("the unit will be OOM-killed when it reaches memory.max", &[])
    } else {
        ("requests needing more of it fail", &[])
    };
    st.chain.push(mech.to_string());
    for c in cmds {
        st.suggest(*c);
    }
    if let Some(n) = unit_name_of(f) {
        let units = units_before(cx, f.ts);
        if let Some(u) = find_unit(&units, &n) {
            st.culprit(Culprit { kind: "unit".into(), name: n.clone(), pid: u.main_pid, unit: Some(n.clone()), why: f.detail.clone(), cpu: Some(u.cpu), mem: Some(u.mem) });
            for s in unit_next_steps(&n, u.kind, u.container.as_ref(), Some(f.ts - 600_000)) {
                st.suggest(s);
            }
            st.confidence += 0.2;
        }
    }
    // Growth of the resource across the window.
    let ks = cx.src.kernel_series(cx.from, f.ts + 1_000, 120).unwrap_or_default();
    let pick = |k: &Kernel| -> Option<u64> {
        if l.contains("file") || l.contains("fd") {
            k.fd_used
        } else if l.contains("conntrack") {
            k.conntrack_used
        } else if l.contains("port") {
            k.ephemeral_used
        } else {
            None
        }
    };
    let vals: Vec<(Ts, u64)> = ks.iter().filter_map(|(t, k)| pick(k).map(|v| (*t, v))).collect();
    if let (Some(a), Some(b)) = (vals.first(), vals.last())
        && b.1 > a.1
    {
        st.evidence.push(format!("{res}: {} at {} -> {} at {}", a.1, fmt_ts(a.0, cx.now), b.1, fmt_ts(b.0, cx.now)));
        let onset = vals.iter().find(|v| v.1 > a.1 + (b.1 - a.1) / 4).map(|v| v.0).unwrap_or(a.0);
        // Units with the most new processes/pids at the same time are the usual leakers.
        let rs = risers(cx, onset, f.ts + 1_000, Res::Cpu);
        let ch = add_changes(cx, onset, None, st);
        if let Some(c) = ch.first() {
            st.chain.push(format!("growth started around {}; just before: {} [{}]", fmt_ts(onset, cx.now), c.what, c.label));
            st.confidence += 0.1;
        }
        if st.culprits.is_empty()
            && let Some(x) = rs.first().filter(|x| x.peak > x.before * 2.0 && x.peak >= 20.0)
        {
            st.culprit(Culprit { kind: "unit".into(), name: x.unit.name.clone(), pid: x.unit.main_pid, unit: Some(x.unit.name.clone()), why: format!("became busy as {res} grew ({} -> {})", fmt_res(x.before, Res::Cpu), fmt_res(x.peak, Res::Cpu)), cpu: Some(x.unit.cpu), mem: Some(x.unit.mem) });
        }
    }
    if st.culprits.is_empty() {
        st.gaps.push(format!("fat does not record per-process {res} counts: use the commands below to see who holds them"));
    }
    st.headline = format!("{res} near exhaustion at {}", fmt_ts(f.ts, cx.now));
}

fn explain_fs_fill(cx: &Cx, f: &Event, st: &mut Story) {
    let mount = f.subject.strip_prefix("mount:").unwrap_or(&f.subject).to_string();
    st.confidence = 0.4;
    st.chain.push(format!("{} at {}", f.detail, fmt_ts(f.ts, cx.now)));
    let s = cx.src.volume_series(&mount, cx.from, f.ts + 1_000).unwrap_or_default();
    let mut onset = cx.from;
    if let (Some(a), Some(b)) = (s.first(), s.last())
        && b.1 > a.1
    {
        let dt = (b.0 - a.0).max(1);
        let rate = (b.1 - a.1) as f64 / (dt as f64 / 1000.0);
        st.evidence.push(format!("{mount} used {} at {} -> {} at {} ({}/min)", human_bytes(a.1), fmt_ts(a.0, cx.now), human_bytes(b.1), fmt_ts(b.0, cx.now), human_bytes((rate * 60.0) as u64)));
        if rate > 0.0 && b.2 > 0 {
            st.chain.push(format!("at {}/min the remaining {} lasts about {}", human_bytes((rate * 60.0) as u64), human_bytes(b.2), human_dur((b.2 as f64 / rate * 1000.0) as i64)));
        }
        onset = s.iter().find(|p| p.1 > a.1 + (b.1 - a.1) / 10).map(|p| p.0).unwrap_or(a.0);
        st.confidence += 0.1;
    }
    let mut writers = cx.src.proc_writes(onset, f.ts + 1_000).unwrap_or_default();
    // Writers whose command line names a path on this mount are the likely fillers (proc_writes
    // counts bytes to any filesystem); group them by name ("8 x dd").
    if mount != "/"
        && let Some(snap) = cx.src.snapshot_at(f.ts).ok().flatten()
    {
        let on_mount = |pid: u32| snap.proc(pid).is_some_and(|p| p.cmd.contains(&format!("{mount}/")) || p.cmd.ends_with(&mount) || p.cwd.starts_with(&mount));
        let mut grouped: Vec<(u32, String, u64)> = Vec::new();
        for (p, n, b) in writers.iter().filter(|w| on_mount(w.0)) {
            match grouped.iter_mut().find(|g| &g.1 == n || g.1.ends_with(&format!(" x {n}"))) {
                Some(g) => {
                    g.2 += b;
                    let k = g.1.split(" x ").next().and_then(|c| c.parse::<usize>().ok()).unwrap_or(1) + 1;
                    g.1 = format!("{k} x {n}");
                }
                None => grouped.push((*p, n.clone(), *b)),
            }
        }
        if !grouped.is_empty() {
            grouped.sort_by_key(|g| std::cmp::Reverse(g.2));
            writers.retain(|w| !on_mount(w.0));
            grouped.extend(writers);
            writers = grouped;
        }
    }
    if let Some((p, n, b)) = writers.first() {
        let units = units_before(cx, f.ts);
        let unit = cx.src.snapshot_at(f.ts).ok().flatten().and_then(|s| s.proc(*p).and_then(|q| unit_for_cgroup(&units, &q.cgroup)).map(|u| u.name.clone()));
        let in_unit = unit.as_ref().map(|u| format!(" in {u}")).unwrap_or_default();
        st.chain.push(format!("{n} (pid {p}){in_unit} wrote {} since {}", human_bytes(*b), fmt_ts(onset, cx.now)));
        st.culprit(Culprit { kind: "process".into(), name: n.clone(), pid: Some(*p), unit, why: format!("wrote {} in the window", human_bytes(*b)), ..Default::default() });
        st.evidence.push(format!("top writers: {}", writers.iter().take(TOP_N).map(|(p, n, b)| format!("{n} (pid {p}) {}", human_bytes(*b))).collect::<Vec<_>>().join(", ")));
        st.confidence += 0.2;
    }
    let rs = risers(cx, onset, f.ts + 1_000, Res::Io);
    if let Some(x) = rs.first().filter(|x| x.peak >= MB as f64) {
        st.culprit(Culprit { kind: "unit".into(), name: x.unit.name.clone(), pid: x.unit.main_pid, unit: Some(x.unit.name.clone()), why: format!("I/O up to {} in the window", human_rate(x.peak as u64)), cpu: Some(x.unit.cpu), mem: Some(x.unit.mem) });
    }
    if let Some(c) = add_changes(cx, onset, None, st).first() {
        st.chain.push(format!("growth began around {}: {} [{}]", fmt_ts(onset, cx.now), c.what, c.label));
    }
    st.suggest(format!("fat fs {mount} --growth"));
    st.suggest(format!("fat fs {mount} --largest 20"));
    st.suggest("check deleted-but-open files: fat doctor (lists them), or: find /proc/*/fd -lname '*(deleted)' 2>/dev/null | head");
    st.headline = match st.culprits.first() {
        Some(c) => format!("{mount} filling at {}: {}", fmt_ts(f.ts, cx.now), c.name),
        None => format!("{mount} filling at {}", fmt_ts(f.ts, cx.now)),
    };
}

fn explain_disk_error(cx: &Cx, f: &Event, st: &mut Story) {
    st.confidence = 0.6;
    st.chain.push(format!("{} at {}", f.detail, fmt_ts(f.ts, cx.now)));
    let related: Vec<&Event> = cx
        .events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::DiskError | EventKind::RoRemount | EventKind::KernelWarn | EventKind::HungTask) && (e.ts - f.ts).abs() <= 600_000 && e.subject != f.subject)
        .take(6)
        .collect();
    for e in &related {
        st.evidence.push(format!("{} {}", fmt_ts(e.ts, cx.now), e.detail));
    }
    if f.kind == EventKind::RoRemount {
        st.chain.push("the filesystem went read-only to protect itself after an error: every write to it now fails".into());
    }
    if let Some(e) = cx.events.iter().find(|e| e.kind == EventKind::DiskError && e.ts <= f.ts && f.ts - e.ts <= 600_000 && e.subject != f.subject) {
        st.chain.push(format!("caused by: {} at {}", e.detail, fmt_ts(e.ts, cx.now)));
    }
    st.culprit(Culprit { kind: "kernel".into(), name: f.subject.clone(), why: "I/O or filesystem errors reported by the kernel (hardware, storage backend or filesystem corruption)".into(), ..Default::default() });
    st.suggest(format!("journalctl -k --since \"{}\" --no-pager | grep -iE 'error|fail|remount|EXT4-fs|XFS|blk_update|I/O'", fmt_abs(f.ts - 600_000)));
    if let Some(d) = f.subject.strip_prefix("disk:") {
        st.suggest(format!("smartctl -a /dev/{d}   # needs root and smartmontools"));
    }
    st.suggest("back up what you can before any fsck; schedule fsck/xfs_repair on the unmounted filesystem");
    st.headline = format!("Storage errors at {}: {}", fmt_ts(f.ts, cx.now), f.detail);
}

fn explain_generic(cx: &Cx, f: &Event, st: &mut Story) {
    st.confidence = 0.3;
    st.chain.push(format!("{} at {}", f.detail, fmt_ts(f.ts, cx.now)));
    if let Some(n) = unit_name_of(f) {
        let units = units_before(cx, f.ts);
        let u = find_unit(&units, &n);
        for s in unit_next_steps(&n, u.map(|u| u.kind).unwrap_or(UnitKind::Systemd), u.and_then(|u| u.container.as_ref()), Some(f.ts - 300_000)) {
            st.suggest(s);
        }
    }
    if matches!(f.kind, EventKind::KernelWarn | EventKind::Other) && f.source == "kmsg" {
        st.suggest(format!("journalctl -k --since \"{}\" --no-pager", fmt_abs(f.ts - 300_000)));
    }
    if f.kind == EventKind::ClockUnsynced {
        st.chain.push("time-dependent things (TLS, logs, distributed locks, cron) may misbehave".into());
        st.suggest("timedatectl status   # or: chronyc tracking / ntpq -p");
    }
    // Who wrote to disk around it, and which volume grew: a spike in one resource often has a
    // disk side (page cache from a writer, a filling volume) that no threshold flagged.
    let (a, b) = (f.ts - GENERIC_SPAN_MS, (f.ts + GENERIC_SPAN_MS).min(cx.to.max(f.ts)));
    let writers = cx.src.proc_writes(a, b).unwrap_or_default();
    if !writers.is_empty() {
        st.evidence.push(format!(
            "bytes written {}..{}: {}",
            fmt_ts(a, cx.now),
            fmt_ts(b, cx.now),
            writers.iter().take(TOP_N).map(|(p, n, by)| format!("{n} (pid {p}) {}", human_bytes(*by))).collect::<Vec<_>>().join(", ")
        ));
    }
    let mut grew: Vec<(u64, String)> = cx
        .src
        .volume_mounts()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| {
            let v = cx.src.volume_series(&m, a, b).ok()?;
            let (lo, hi) = (v.iter().map(|p| p.1).min()?, v.iter().map(|p| p.1).max()?);
            let first_hi = v.iter().find(|p| p.1 == hi)?.0;
            let first_lo = v.iter().find(|p| p.1 == lo)?.0;
            (hi > lo + GENERIC_GROWTH_MIN && first_hi > first_lo).then(|| (hi - lo, m))
        })
        .collect();
    grew.sort_by(|x, y| y.cmp(x));
    if !grew.is_empty() {
        st.evidence.push(format!(
            "volumes that grew {}..{}: {}",
            fmt_ts(a, cx.now),
            fmt_ts(b, cx.now),
            grew.iter().take(3).map(|(by, m)| format!("{m} +{}", human_bytes(*by))).collect::<Vec<_>>().join(", ")
        ));
    }
    add_changes(cx, f.ts, unit_name_of(f).as_deref(), st);
    st.headline = format!("{} at {}", f.detail, fmt_ts(f.ts, cx.now));
}

/// The generic explainer looks this far either side of the event for disk writers and volume
/// growth: long enough to span a few samples at any sensible interval.
const GENERIC_SPAN_MS: i64 = 120_000;
/// Volume growth below this is ordinary churn (logs, caches), not worth an evidence line.
const GENERIC_GROWTH_MIN: u64 = 64 * MB;

/// No events: look for anomalies in the kernel series ("load high but CPU idle", iowait, steal).
fn series_anomaly(cx: &Cx, st: &mut Story) -> Option<(Severity, Ts)> {
    let ks = cx.src.kernel_series(cx.from, cx.to, 400).unwrap_or_default();
    let (t, k) = ks.iter().max_by(|a, b| stall_score(&a.1).total_cmp(&stall_score(&b.1)))?;
    if stall_score(k) < 1.0 {
        return None;
    }
    let detail = match cx.src.snapshot_at(*t).ok().flatten().filter(|s| s.system.cores > 0) {
        Some(s) => format!("load {:.1} on {} cores while CPU was {:.0}% busy", s.system.load[0], s.system.cores, s.system.cpu),
        None => "processes stalled".into(),
    };
    let f = Event { ts: *t, kind: EventKind::DiskLatencySpike, severity: Severity::Warn, subject: "host".into(), detail, ..Default::default() };
    explain_io(cx, &f, st);
    if k.steal_pct >= 10.0 && k.steal_pct >= k.iowait_pct {
        st.headline = format!("CPU steal {:.0}% at {}: the hypervisor withheld CPU time", k.steal_pct, fmt_ts(*t, cx.now));
    } else {
        st.headline = format!("I/O stall at {}{}", fmt_ts(*t, cx.now), st.culprits.first().map(|c| format!(": {}", c.name)).unwrap_or_default());
    }
    Some((Severity::Warn, *t))
}

fn stall_score(k: &Kernel) -> f32 {
    k.procs_blocked as f32 / 4.0 + k.iowait_pct / 20.0 + k.steal_pct / 15.0 + k.d_state.len() as f32 / 2.0
}

// ---------------------------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------------------------

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

pub(crate) fn human_bytes(b: u64) -> String {
    let f = b as f64;
    if b >= GB {
        format!("{:.1} GiB", f / GB as f64)
    } else if b >= MB {
        format!("{:.0} MiB", f / MB as f64)
    } else if b >= KB {
        format!("{:.0} KiB", f / KB as f64)
    } else {
        format!("{b} B")
    }
}

pub(crate) fn human_rate(b: u64) -> String {
    format!("{}/s", human_bytes(b))
}

pub(crate) fn human_dur(ms: i64) -> String {
    let s = (ms / 1000).max(0);
    if s < 90 {
        format!("{s}s")
    } else if s < 90 * 60 {
        format!("{}m", (s + 30) / 60)
    } else if s < 48 * 3600 {
        format!("{:.1}h", s as f64 / 3600.0)
    } else {
        format!("{}d", s / 86_400)
    }
}

/// Local wall-clock time; the date is added when `ts` is not within a day of `now`.
pub(crate) fn fmt_ts(ts: Ts, now: Ts) -> String {
    use chrono::{Local, TimeZone};
    let Some(d) = Local.timestamp_millis_opt(ts).single() else { return ts.to_string() };
    if (now - ts).abs() < 20 * 3_600_000 { d.format("%H:%M:%S").to_string() } else { d.format("%Y-%m-%d %H:%M:%S").to_string() }
}

/// Absolute local time for command lines ("2026-11-10 03:07:00").
pub(crate) fn fmt_abs(ts: Ts) -> String {
    use chrono::{Local, TimeZone};
    Local.timestamp_millis_opt(ts).single().map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_else(|| ts.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{DStateProc, DiskStat, Pressure};
    use crate::model::System;
    use std::collections::BTreeMap;

    const T0: Ts = 1_800_000_000_000;
    const S: i64 = 1000;
    const MIN: i64 = 60_000;

    type VolSeries = Vec<(Ts, u64, u64)>;

    /// Synthetic recorder: everything in memory, sampled every 5 s.
    #[derive(Default)]
    struct Mem {
        events: Vec<Event>,
        units: Vec<(Ts, Vec<Unit>)>,
        kernel: Vec<(Ts, Kernel)>,
        snaps: Vec<Snapshot>,
        writes: Vec<(u32, String, u64)>,
        vols: Vec<(String, VolSeries)>,
    }

    impl Recorded for Mem {
        fn events(&self, from: Ts, to: Ts, kinds: &[EventKind], limit: usize) -> Result<Vec<Event>> {
            Ok(self.events.iter().filter(|e| e.ts >= from && e.ts <= to && (kinds.is_empty() || kinds.contains(&e.kind))).take(limit).cloned().collect())
        }
        fn units_at(&self, ts: Ts) -> Result<Vec<Unit>> {
            Ok(self.units.iter().min_by_key(|(t, _)| (t - ts).abs()).filter(|(t, _)| (t - ts).abs() <= 10 * S).map(|x| x.1.clone()).unwrap_or_default())
        }
        fn unit_series(&self, name: &str, from: Ts, to: Ts) -> Result<Vec<UnitPoint>> {
            Ok(self.units.iter().filter(|(t, _)| *t >= from && *t <= to).filter_map(|(t, us)| us.iter().find(|u| u.name == name).map(|u| point_of(*t, u))).collect())
        }
        fn kernel_series(&self, from: Ts, to: Ts, _: usize) -> Result<Vec<(Ts, Kernel)>> {
            Ok(self.kernel.iter().filter(|(t, _)| *t >= from && *t <= to).cloned().collect())
        }
        fn snapshot_at(&self, ts: Ts) -> Result<Option<Snapshot>> {
            Ok(self.snaps.iter().min_by_key(|s| (s.ts - ts).abs()).cloned())
        }
        fn bounds(&self) -> Result<Option<(Ts, Ts)>> {
            let ts: Vec<Ts> = self.units.iter().map(|x| x.0).chain(self.kernel.iter().map(|x| x.0)).collect();
            Ok(ts.iter().min().map(|a| (*a, *ts.iter().max().unwrap())))
        }
        fn spikes(&self, _: Ts, _: Ts) -> Result<Vec<Point>> {
            Ok(vec![])
        }
        fn volume_mounts(&self) -> Result<Vec<String>> {
            Ok(self.vols.iter().map(|v| v.0.clone()).collect())
        }
        fn volume_series(&self, m: &str, from: Ts, to: Ts) -> Result<Vec<(Ts, u64, u64)>> {
            Ok(self.vols.iter().find(|v| v.0 == m).map(|v| v.1.iter().filter(|p| p.0 >= from && p.0 <= to).copied().collect()).unwrap_or_default())
        }
        fn proc_writes(&self, _: Ts, _: Ts) -> Result<Vec<(u32, String, u64)>> {
            Ok(self.writes.clone())
        }
    }

    fn unit(name: &str, mem: u64, io: u64, cpu: f32) -> Unit {
        Unit { name: name.into(), kind: UnitKind::Systemd, state: "active".into(), sub_state: "running".into(), mem, io_write_bps: io, cpu, cgroup: format!("/system.slice/{name}"), main_pid: Some(100), ..Default::default() }
    }

    fn ev(ts: Ts, kind: EventKind, sev: Severity, unit: Option<&str>, detail: &str) -> Event {
        Event {
            ts,
            kind,
            severity: sev,
            subject: unit.map(|u| format!("unit:{u}")).unwrap_or_else(|| "host".into()),
            unit: unit.map(str::to_string),
            detail: detail.into(),
            source: "test".into(),
            ..Default::default()
        }
    }

    fn sys_snap(ts: Ts, procs: Vec<Proc>) -> Snapshot {
        Snapshot { ts, host: "web-01".into(), system: System { hostname: "web-01".into(), cores: 4, mem_total: 8 * GB, load: [9.0, 6.0, 3.0], cpu: 12.0, ..Default::default() }, procs, ..Default::default() }
    }

    fn run(m: &Mem, at: Option<Ts>, window: i64) -> Incident {
        let live = sys_snap(T0 + 30 * MIN, vec![]);
        what_happened_with(Some(m), &live, at, window, &ServerCfg::default(), |_| Ok(vec![])).unwrap()
    }

    #[test]
    fn oom_host_wide_names_the_memory_hog() {
        let mut m = Mem::default();
        // backup.service grows 1 GiB -> 6 GiB over 5 minutes; postgres steady 1.5 GiB.
        for i in 0..=60 {
            let t = T0 + i * 5 * S;
            let b = GB + (i as u64) * 5 * GB / 60;
            m.units.push((t, vec![unit("backup.service", b, 0, 30.0), unit("postgresql.service", 3 * GB / 2, 0, 5.0)]));
        }
        let kill = T0 + 300 * S + 1_000;
        let mut e = ev(kill, EventKind::OomKill, Severity::Crit, Some("postgresql.service"), "postgres (pid 4242) OOM-killed");
        e.pid = Some(4242);
        e.extra = BTreeMap::from([("victim".into(), "postgres".into()), ("constraint".into(), "CONSTRAINT_NONE".into()), ("rss_kb".into(), "1500000".into())]);
        m.events.push(e);
        m.events.push(ev(T0 + 10 * S, EventKind::UnitStart, Severity::Info, Some("backup.service"), "backup.service started"));
        m.snaps.push(sys_snap(kill - 2_000, vec![Proc { pid: 77, name: "pg_dump".into(), mem: 5 * GB, start_time: ((T0 + 10 * S) / 1000) as u64, ..Default::default() }]));
        let inc = run(&m, Some(kill), 15 * MIN);
        assert_eq!(inc.severity, Severity::Crit);
        assert!(inc.headline.contains("postgres OOM-killed"), "{}", inc.headline);
        assert!(inc.headline.contains("backup.service"), "{}", inc.headline);
        assert_eq!(inc.culprits[0].name, "backup.service");
        assert!(inc.culprits[0].why.contains("grew"), "{:?}", inc.culprits[0]);
        assert!(inc.chain.iter().any(|c| c.contains("whole host ran out of memory")), "{:?}", inc.chain);
        assert!(inc.evidence.iter().any(|c| c.contains("confidence: high")), "{:?}", inc.evidence);
        let text = render(&inc);
        assert!(text.contains("journalctl -k"), "{text}");
        assert!(text.contains("investigate"), "databases get 'investigate', not restart: {text}");
    }

    #[test]
    fn oom_in_memcg_blames_the_limit() {
        let mut m = Mem::default();
        for i in 0..=20 {
            let t = T0 + i * 5 * S;
            let mut w = unit("worker.service", 100 * MB + i as u64 * 20 * MB, 0, 50.0);
            w.mem_limit = Some(512 * MB);
            m.units.push((t, vec![w, unit("api.service", 2 * GB, 0, 10.0)]));
        }
        let mut e = ev(T0 + 100 * S, EventKind::OomKill, Severity::Crit, None, "python3 OOM-killed");
        e.extra = BTreeMap::from([("victim".into(), "python3".into()), ("constraint".into(), "CONSTRAINT_MEMCG".into()), ("memcg".into(), "/system.slice/worker.service".into())]);
        m.events.push(e);
        let inc = run(&m, None, 30 * MIN);
        assert!(inc.headline.contains("worker.service hit its memory limit"), "{}", inc.headline);
        assert_eq!(inc.culprits[0].name, "worker.service");
        assert!(inc.chain.iter().any(|c| c.contains("512 MiB")), "{:?}", inc.chain);
        assert!(inc.suggestions.iter().any(|s| s.contains("MemoryMax")), "{:?}", inc.suggestions);
    }

    #[test]
    fn restart_loop_with_exit_code() {
        let mut m = Mem::default();
        let mut u = unit("api.service", 50 * MB, 0, 1.0);
        u.state = "activating".into();
        u.result = "exit-code".into();
        u.exit_code = Some(3);
        u.restarts = 7;
        u.flapping = true;
        for i in 0..=40 {
            m.units.push((T0 + i * 5 * S, vec![u.clone()]));
        }
        m.events.push(ev(T0 + 5 * S, EventKind::UnitStart, Severity::Info, Some("dpkg-daily.service"), "dpkg-daily.service started"));
        for i in 0..5 {
            m.events.push(ev(T0 + 20 * S + i * 30 * S, EventKind::UnitRestart, Severity::Warn, Some("api.service"), "api.service restarted (exit-code 3)"));
        }
        m.events.push(ev(T0 + 160 * S, EventKind::UnitFlapping, Severity::Warn, Some("api.service"), "api.service flapping"));
        let inc = run(&m, None, 30 * MIN);
        assert!(inc.headline.contains("api.service restart loop"), "{}", inc.headline);
        assert!(inc.chain.iter().any(|c| c.contains("exited with status 3")), "{:?}", inc.chain);
        assert!(inc.chain.iter().any(|c| c.contains("package update")), "{:?}", inc.chain);
        assert!(inc.suggestions.iter().any(|s| s.starts_with("journalctl -u api.service")), "{:?}", inc.suggestions);
    }

    #[test]
    fn restart_loop_exit_reason_from_events() {
        // Sampled between restarts the unit looks healthy; the events carry the exit status.
        let mut m = Mem::default();
        for i in 0..=20 {
            m.units.push((T0 + i * 5 * S, vec![Unit { result: "success".into(), restarts: 9, ..unit("queue.service", MB, 0, 0.0) }]));
        }
        for i in 0..4 {
            let mut e = ev(T0 + 10 * S + i * 15 * S, EventKind::UnitRestart, Severity::Warn, Some("queue.service"), "queue.service restarted");
            if i == 1 {
                e.extra = BTreeMap::from([("result".into(), "exit-code".into()), ("exit_code".into(), "75".into())]);
            }
            m.events.push(e);
        }
        let inc = run(&m, None, 40 * MIN);
        assert!(inc.headline.contains("queue.service restart loop"), "{}", inc.headline);
        assert!(inc.chain.iter().any(|c| c.contains("exited with status 75")), "{:?}", inc.chain);
        assert!(inc.evidence.iter().any(|c| c.contains("result exit-code, exit status 75")), "{:?}", inc.evidence);
    }

    #[test]
    fn focus_prefers_what_was_under_way_at_the_moment_asked() {
        let at = T0 + 600 * S;
        let flap = ev(at - 46 * S, EventKind::UnitFlapping, Severity::Crit, Some("api.service"), "api.service is flapping");
        let oom = ev(at + 79 * S, EventKind::OomKill, Severity::Crit, Some("batch.service"), "OOM killer killed worker");
        let evs = vec![flap.clone(), oom.clone()];
        assert_eq!(pick_focus(&evs, at, true, 120 * S).map(|e| e.kind), Some(EventKind::UnitFlapping));
        // Within the slack (a late sample), the more explanatory event still wins.
        assert_eq!(pick_focus(&evs, at + 30 * S, true, 120 * S).map(|e| e.kind), Some(EventKind::OomKill));
        // Near the moment beats a more explanatory kind further away in the band.
        let thr = ev(at - 52 * S, EventKind::Throttle, Severity::Warn, Some("cpu.service"), "throttled");
        let disk = ev(at - 119 * S, EventKind::DiskLatencySpike, Severity::Warn, None, "disk await 136 ms");
        assert_eq!(pick_focus(&[disk, thr], at, true, 120 * S).map(|e| e.kind), Some(EventKind::Throttle));
        // Without --at: the worst, most explanatory event.
        assert_eq!(pick_focus(&evs, at, false, 120 * S).map(|e| e.kind), Some(EventKind::OomKill));
    }

    #[test]
    fn disk_latency_attributed_to_rising_unit_and_its_start() {
        let mut m = Mem::default();
        let start = T0 + 120 * S;
        for i in 0..=72 {
            let t = T0 + i * 5 * S;
            let hot = t >= start + 10 * S;
            let mut k = Kernel { iowait_pct: if hot { 35.0 } else { 1.0 }, procs_blocked: if hot { 7 } else { 0 }, ..Default::default() };
            k.disks.push(DiskStat { name: "sda".into(), w_await_ms: if hot { 85.0 } else { 2.0 }, queue_depth: if hot { 12.0 } else { 0.1 }, util_pct: if hot { 99.0 } else { 3.0 }, ..Default::default() });
            if hot {
                k.d_state.push(DStateProc { pid: 900, name: "api".into(), wchan: "io_schedule".into(), seconds: 12, unit: Some("api.service".into()) });
            }
            m.kernel.push((t, k));
            let b = if t >= start { 180 * MB } else { 0 };
            m.units.push((t, vec![unit("backup.service", 200 * MB, b, 20.0), unit("api.service", GB, 2 * MB, 40.0)]));
        }
        m.events.push(ev(start, EventKind::UnitStart, Severity::Info, Some("backup.service"), "backup.service started"));
        let mut spike = ev(start + 10 * S, EventKind::DiskLatencySpike, Severity::Warn, None, "sda await 85 ms");
        spike.subject = "disk:sda".into();
        m.events.push(spike);
        m.snaps.push(sys_snap(start + 30 * S, vec![]));
        // A worse but older incident elsewhere in the window must not steal --at's focus.
        m.events.push(ev(T0 + 5 * S, EventKind::UnitFlapping, Severity::Crit, Some("other.service"), "other.service flapping"));
        let inc = run(&m, Some(start + 30 * S), 10 * MIN);
        assert!(inc.headline.contains("sda"), "{}", inc.headline);
        assert_eq!(inc.culprits[0].name, "backup.service", "{:?}", inc.culprits);
        let chain = inc.chain.join(" | ");
        assert!(chain.contains("from 2 ms to 85 ms"), "{chain}");
        assert!(chain.contains("blocked in uninterruptible"), "{chain}");
        assert!(chain.contains("backup.service started"), "{chain}");
        assert!(chain.contains("io_schedule"), "{chain}");
    }

    #[test]
    fn load_high_cpu_idle_without_events_uses_series() {
        let mut m = Mem::default();
        for i in 0..=12 {
            let t = T0 + i * 5 * S;
            let k = Kernel { steal_pct: if i > 6 { 40.0 } else { 0.0 }, procs_blocked: 0, ..Default::default() };
            m.kernel.push((t, k));
            m.units.push((t, vec![unit("app.service", GB, 0, 10.0)]));
        }
        m.snaps.push(sys_snap(T0 + 40 * S, vec![]));
        let inc = run(&m, Some(T0 + 50 * S), 5 * MIN);
        assert!(inc.chain.iter().any(|c| c.contains("steal")), "{:?}", inc.chain);
        assert!(inc.culprits.iter().any(|c| c.kind == "external"), "{:?}", inc.culprits);
    }

    #[test]
    fn throttle_and_noisy_neighbour() {
        let mut m = Mem::default();
        for i in 0..=24 {
            let t = T0 + i * 5 * S;
            let mut a = unit("api.service", GB, 0, 95.0);
            a.cpu_quota = Some(1.0);
            a.cpu_throttled_pct = if i > 10 { 60.0 } else { 5.0 };
            a.psi = Some(Pressure { cpu_some: 45.0, ..Default::default() });
            let batch = unit("batch.service", GB, 0, if i > 9 { 350.0 } else { 10.0 });
            m.units.push((t, vec![a, batch]));
        }
        m.events.push(ev(T0 + 60 * S, EventKind::Throttle, Severity::Warn, Some("api.service"), "api.service throttled 60%"));
        let inc = run(&m, None, 40 * MIN);
        assert!(inc.chain.iter().any(|c| c.contains("throttled 60%")), "{:?}", inc.chain);
        assert!(inc.chain.iter().any(|c| c.contains("noisy neighbour: batch.service")), "{:?}", inc.chain);
        assert!(inc.headline.contains("batch.service"), "{}", inc.headline);
    }

    #[test]
    fn exhaustion_and_fs_fill() {
        let mut m = Mem::default();
        for i in 0..=10 {
            let k = Kernel { conntrack_used: Some(1000 + i as u64 * 9000), conntrack_max: Some(100_000), ..Default::default() };
            m.kernel.push((T0 + i * 5 * S, k));
        }
        let mut e = ev(T0 + 50 * S, EventKind::Exhaustion, Severity::Crit, None, "conntrack entries: 91000 of 100000 in use (91%)");
        e.extra.insert("resource".into(), "conntrack entries".into());
        m.events.push(e);
        let inc = run(&m, None, 40 * MIN);
        assert!(inc.headline.contains("conntrack"), "{}", inc.headline);
        assert!(inc.suggestions.iter().any(|s| s.contains("conntrack -S")));
        assert!(inc.evidence.iter().any(|s| s.contains("1000 at")), "{:?}", inc.evidence);

        let mut f = Mem::default();
        f.vols.push(("/var".into(), (0..=10).map(|i| (T0 + i * MIN, 80 * GB + i as u64 * 2 * GB, 20 * GB - i as u64 * 2 * GB)).collect()));
        f.units.push((T0, vec![unit("app.service", GB, 0, 1.0)]));
        f.writes.push((321, "logger".into(), 20 * GB));
        let inc = run(&f, None, 30 * MIN);
        assert!(inc.events.iter().any(|e| e.kind == EventKind::FsFill && e.severity == Severity::Warn), "{:?}", inc.events);
        assert!(inc.headline.contains("/var filling"), "{}", inc.headline);
        assert_eq!(inc.culprits[0].name, "logger");
    }

    #[test]
    fn generic_event_shows_disk_writers_and_volume_growth() {
        let mut m = Mem::default();
        // A memory jump in a unit that is also writing 1 GiB to /data (well below any fill alarm).
        m.events.push(ev(T0 + 5 * MIN, EventKind::ProcSpike, Severity::Warn, Some("filler.service"), "filler.service memory grew 48 MiB"));
        m.vols.push(("/data".into(), (0..=10).map(|i| (T0 + 4 * MIN + i * 10 * S, 100 * GB + i as u64 * GB / 10, 900 * GB)).collect()));
        m.vols.push(("/quiet".into(), (0..=10).map(|i| (T0 + 4 * MIN + i * 10 * S, 5 * GB, 5 * GB)).collect()));
        m.writes.push((77, "dd".into(), GB));
        m.units.push((T0, vec![unit("filler.service", GB, 0, 1.0)]));
        m.units.push((T0 + 10 * MIN, vec![unit("filler.service", GB, 0, 1.0)]));
        let inc = run(&m, Some(T0 + 5 * MIN), 10 * MIN);
        assert!(inc.evidence.iter().any(|e| e.contains("bytes written") && e.contains("dd (pid 77) 1.0 GiB")), "{} {:?} {:?}", inc.headline, inc.evidence, inc.gaps);
        assert!(inc.evidence.iter().any(|e| e.contains("/data +1.0 GiB") && !e.contains("/quiet")), "{:?}", inc.evidence);
    }

    #[test]
    fn live_fallback_reports_gaps_and_failed_units() {
        let mut live = sys_snap(T0, vec![]);
        let mut u = unit("nginx.service", 0, 0, 0.0);
        u.state = "failed".into();
        u.result = "exit-code".into();
        u.exit_code = Some(1);
        u.since = Some(T0 - 2 * MIN);
        live.units.push(u);
        live.kernel = Some(Kernel { ro_remounts: vec![], ..Default::default() });
        let inc = what_happened_with(None, &live, None, 15 * MIN, &ServerCfg::default(), |_| bail!("needs root")).unwrap();
        assert!(inc.headline.contains("nginx.service failed"), "{}", inc.headline);
        assert!(inc.gaps.iter().any(|g| g.contains("no flight recorder")), "{:?}", inc.gaps);
        if cfg!(target_os = "linux") {
            assert!(inc.gaps.iter().any(|g| g.contains("needs root")), "{:?}", inc.gaps);
        }
        assert_eq!(inc.host, "web-01");
        // Nothing at all: honest "nothing notable", plus what rose most when the recorder knows.
        let mut q = Mem::default();
        for i in 0..=24 {
            q.units.push((T0 + i * 5 * S, vec![unit("etl.service", GB, if i > 18 { 50 * MB } else { 0 }, 5.0)]));
        }
        let inc = what_happened_with(Some(&q), &sys_snap(T0 + 2 * MIN, vec![]), Some(T0 + 2 * MIN), 2 * MIN, &ServerCfg::default(), |_| Ok(vec![])).unwrap();
        assert!(inc.headline.starts_with("Nothing notable"), "{}", inc.headline);
        assert!(inc.evidence.iter().any(|e| e.starts_with("biggest I/O rise: etl.service 0 B/s -> 50 MiB/s")), "{:?}", inc.evidence);
        let quiet = what_happened_with(None, &sys_snap(T0, vec![]), None, 15 * MIN, &ServerCfg::default(), |_| Ok(vec![])).unwrap();
        assert!(quiet.headline.starts_with("Nothing notable"), "{}", quiet.headline);
        assert_eq!(quiet.severity, Severity::Info);
    }

    #[test]
    fn explain_event_without_history() {
        let live = sys_snap(T0, vec![Proc { pid: 5, name: "java".into(), mem: 6 * GB, ..Default::default() }]);
        let e = ev(T0 - 1000, EventKind::OomKill, Severity::Crit, None, "java OOM-killed");
        let inc = explain_event(None, &live, &e);
        assert!(inc.headline.contains("OOM-killed"));
        assert!(inc.gaps.iter().any(|g| g.contains("no flight recorder")));
    }

    #[test]
    fn parse_at_forms() {
        use chrono::{Local, TimeZone};
        let now = Local.with_ymd_and_hms(2026, 11, 10, 14, 0, 0).unwrap().timestamp_millis();
        assert_eq!(parse_at("-2h", now).unwrap(), now - 2 * 3_600_000);
        assert_eq!(parse_at("2h ago", now).unwrap(), now - 2 * 3_600_000);
        assert_eq!(parse_at("90m ago", now).unwrap(), now - 90 * MIN);
        assert_eq!(parse_at("now", now).unwrap(), now);
        assert_eq!(parse_at("1700000000", now).unwrap(), 1_700_000_000_000);
        assert_eq!(parse_at("03:12", now).unwrap(), Local.with_ymd_and_hms(2026, 11, 10, 3, 12, 0).unwrap().timestamp_millis());
        assert_eq!(parse_at("03:12:30", now).unwrap(), Local.with_ymd_and_hms(2026, 11, 10, 3, 12, 30).unwrap().timestamp_millis());
        // Later than now today -> yesterday.
        assert_eq!(parse_at("23:30", now).unwrap(), Local.with_ymd_and_hms(2026, 11, 9, 23, 30, 0).unwrap().timestamp_millis());
        assert_eq!(parse_at("2026-11-09 03:12", now).unwrap(), Local.with_ymd_and_hms(2026, 11, 9, 3, 12, 0).unwrap().timestamp_millis());
        assert_eq!(parse_at("2026-11-10T03:12:00Z", now).unwrap(), 1_794_280_320_000);
        assert!(parse_at("yesterday-ish", now).is_err());
        assert_eq!(parse_duration("15m").unwrap(), 15 * MIN);
        assert_eq!(parse_duration("1h30m").unwrap(), 90 * MIN);
        assert_eq!(parse_duration("90s").unwrap(), 90 * S);
        assert_eq!(parse_duration("2").unwrap(), 2 * MIN);
        assert!(parse_duration("5 parsecs").is_err());
        assert!(parse_duration("10").is_ok() && parse_duration("x").is_err());
    }

    #[test]
    fn timeline_dedups_and_derives_fill() {
        let mut m = Mem::default();
        let e = ev(T0, EventKind::UnitStart, Severity::Info, Some("a.service"), "a started");
        m.events.push(e.clone());
        m.events.push(Event { ts: T0 + 200, ..e });
        m.vols.push(("/".into(), vec![(T0, 89 * GB, 11 * GB), (T0 + MIN, 98 * GB, 2 * GB)]));
        let t = timeline_of(&m, T0 - MIN, T0 + 2 * MIN, &[]).unwrap();
        assert_eq!(t.iter().filter(|e| e.kind == EventKind::UnitStart).count(), 1);
        let fill: Vec<_> = t.iter().filter(|e| e.kind == EventKind::FsFill).collect();
        assert_eq!(fill.len(), 1);
        assert_eq!(fill[0].severity, Severity::Crit);
        let only = timeline_of(&m, T0 - MIN, T0 + 2 * MIN, &[EventKind::UnitStart]).unwrap();
        assert!(only.iter().all(|e| e.kind == EventKind::UnitStart));
        assert!(timeline_of(&m, T0, T0 - 1, &[]).is_err());
    }

    #[test]
    fn unit_next_steps_per_kind() {
        assert!(unit_next_steps("nginx.service", UnitKind::Systemd, None, None)[1].starts_with("journalctl -u nginx.service"));
        let meta = ContainerMeta { runtime: "podman".into(), ..Default::default() };
        assert!(unit_next_steps("web", UnitKind::Container, Some(&meta), None)[0].starts_with("podman logs"));
        let k8s = ContainerMeta { runtime: "containerd".into(), pod: Some("api-1".into()), namespace: Some("prod".into()), ..Default::default() };
        assert!(unit_next_steps("api", UnitKind::Container, Some(&k8s), None)[0].contains("kubectl -n prod describe pod api-1"));
        assert!(unit_next_steps("ns/p", UnitKind::Pod, None, None)[1].contains("kubectl -n ns logs p"));
    }
}
