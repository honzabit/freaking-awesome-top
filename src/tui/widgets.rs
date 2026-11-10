//! Small formatters, bars and color scales shared by the views.
//! Everything here is pure and cheap so it can run per visible row each frame.

use crate::model::Ts;
use ratatui::style::{Color, Modifier, Style};

const SPARK: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Preallocated indentation for tree view (sliced, never allocated per row).
pub const SPACES: &str = "                                                                ";

pub fn indent(depth: u16) -> &'static str {
    let n = (depth as usize * 2).min(SPACES.len());
    &SPACES[..n]
}

/// 1536 -> "1.5K", binary units, compact.
pub fn fmt_bytes(b: u64) -> String {
    let f = b as f64;
    const K: f64 = 1024.0;
    if b < 1024 {
        format!("{b}B")
    } else if f < K * K {
        format!("{:.1}K", f / K)
    } else if f < K * K * K {
        format!("{:.1}M", f / (K * K))
    } else if f < K * K * K * K {
        format!("{:.1}G", f / (K * K * K))
    } else {
        format!("{:.1}T", f / (K * K * K * K))
    }
}

/// Per-second rate; "-" for zero so idle columns stay quiet.
pub fn fmt_rate(bps: u64) -> String {
    if bps == 0 { "-".to_string() } else { fmt_bytes(bps) }
}

/// Milliwatts -> "850mW" / "12.3W".
pub fn fmt_power(mw: f32) -> String {
    if !mw.is_finite() || mw <= 0.0 {
        "-".to_string()
    } else if mw < 1000.0 {
        format!("{mw:.0}mW")
    } else {
        format!("{:.1}W", mw / 1000.0)
    }
}

/// Seconds -> "3d4h", "5h12m", "7m3s", "42s".
pub fn fmt_dur(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60, secs % 60);
    if d > 0 {
        format!("{d}d{h}h")
    } else if h > 0 {
        format!("{h}h{m}m")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// Epoch ms -> local "HH:MM:SS".
pub fn fmt_clock(ts: Ts) -> String {
    chrono::DateTime::from_timestamp_millis(ts)
        .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "--:--:--".into())
}

/// Epoch ms -> local "MM-DD HH:MM:SS".
pub fn fmt_datetime(ts: Ts) -> String {
    chrono::DateTime::from_timestamp_millis(ts)
        .map(|d| d.with_timezone(&chrono::Local).format("%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

/// Horizontal bar of `width` cells for ratio 0..1 using eighth blocks.
pub fn bar(ratio: f64, width: usize) -> String {
    const EIGHTHS: [char; 8] = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'];
    let r = if ratio.is_finite() { ratio.clamp(0.0, 1.0) } else { 0.0 };
    let total = (r * width as f64 * 8.0).round() as usize;
    let full = total / 8;
    let rem = total % 8;
    let mut s = String::with_capacity(width * 3);
    for _ in 0..full.min(width) {
        s.push('█');
    }
    if full < width {
        s.push(if rem > 0 { EIGHTHS[rem] } else { '·' });
        for _ in full + 1..width {
            s.push('·');
        }
    }
    s
}

/// One block char for a 0..100 value.
pub fn spark_char(pct: f32) -> char {
    let p = if pct.is_finite() { pct.clamp(0.0, 100.0) } else { 0.0 };
    SPARK[((p / 100.0) * 7.0).round() as usize]
}

/// Sparkline of the last `width` values (0..100 scale), right-aligned.
pub fn sparkline<I: DoubleEndedIterator<Item = f32> + ExactSizeIterator>(values: I, width: usize) -> String {
    let n = values.len();
    let skip = n.saturating_sub(width);
    let mut s = String::with_capacity(width * 3);
    for _ in n.min(width)..width {
        s.push(' ');
    }
    for v in values.skip(skip) {
        s.push(spark_char(v));
    }
    s
}

pub fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// Color for a CPU percent (100 = one core).
pub fn cpu_style(cpu: f32) -> Style {
    if cpu >= 100.0 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if cpu >= 50.0 {
        Style::default().fg(Color::Red)
    } else if cpu >= 15.0 {
        Style::default().fg(Color::Yellow)
    } else if cpu >= 0.5 {
        Style::default()
    } else {
        dim()
    }
}

/// Color for whole-machine percent 0..100.
pub fn pct_color(p: f32) -> Color {
    if p >= 85.0 {
        Color::Red
    } else if p >= 60.0 {
        Color::Yellow
    } else {
        Color::Green
    }
}

pub fn mem_style(bytes: u64) -> Style {
    const G: u64 = 1 << 30;
    if bytes >= 4 * G {
        Style::default().fg(Color::Red)
    } else if bytes >= G {
        Style::default().fg(Color::Yellow)
    } else if bytes >= 100 << 20 {
        Style::default()
    } else {
        dim()
    }
}

pub fn power_style(mw: f32) -> Style {
    if mw >= 5000.0 {
        Style::default().fg(Color::Red)
    } else if mw >= 1000.0 {
        Style::default().fg(Color::Yellow)
    } else if mw >= 100.0 {
        Style::default()
    } else {
        dim()
    }
}

pub fn rate_style(bps: u64) -> Style {
    if bps >= 10 << 20 {
        Style::default().fg(Color::Red)
    } else if bps >= 1 << 20 {
        Style::default().fg(Color::Yellow)
    } else if bps > 0 {
        Style::default()
    } else {
        dim()
    }
}

pub fn pressure_color(level: &str) -> Color {
    match level {
        "normal" => Color::Green,
        "warn" => Color::Yellow,
        "critical" => Color::Red,
        _ => Color::Gray,
    }
}

pub fn thermal_color(level: &str) -> Color {
    match level {
        "nominal" => Color::Green,
        "fair" => Color::Yellow,
        "serious" => Color::LightRed,
        "critical" => Color::Red,
        _ => Color::Gray,
    }
}

pub fn severity_style(sev: &str) -> Style {
    match sev {
        "crit" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "warn" => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::Cyan),
    }
}

/// Borrow at most `max` bytes of `s`, cut at a char boundary.
pub fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// ASCII case-insensitive substring test without allocating.
/// `needle_lower` must already be lowercase.
pub fn contains_ci(hay: &str, needle_lower: &str) -> bool {
    let n = needle_lower.as_bytes();
    if n.is_empty() {
        return true;
    }
    let h = hay.as_bytes();
    if n.len() > h.len() {
        return false;
    }
    h.windows(n.len()).any(|w| w.iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

// ------------------------------------------------------------------ storage formatting

/// Signed byte change: "+1.2G", "-300.0M", "0".
pub fn fmt_delta(d: i64) -> String {
    match d.cmp(&0) {
        std::cmp::Ordering::Equal => "0".to_string(),
        std::cmp::Ordering::Greater => format!("+{}", fmt_bytes(d.unsigned_abs())),
        std::cmp::Ordering::Less => format!("-{}", fmt_bytes(d.unsigned_abs())),
    }
}

/// Compact duration with one unit: "45s", "12m", "3h", "2d".
pub fn fmt_dur_short(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// Age of an event `secs` ago: "now", "42s ago", "2m ago", "3h ago". Negative (clock skew) = "now".
pub fn fmt_ago(secs: i64) -> String {
    if secs < 5 { "now".to_string() } else { format!("{} ago", fmt_dur_short(secs as u64)) }
}

/// Age of an epoch-seconds mtime relative to `now_ms`; "-" when unknown (0).
pub fn fmt_mtime_age(mtime_s: i64, now_ms: Ts) -> String {
    if mtime_s <= 0 { "-".to_string() } else { fmt_ago(now_ms / 1000 - mtime_s) }
}

/// Window length: "10m", "1h", "24h".
pub fn fmt_window(ms: i64) -> String {
    let s = (ms / 1000).max(0) as u64;
    if s >= 3600 && s.is_multiple_of(3600) { format!("{}h", s / 3600) } else { format!("{}m", (s / 60).max(1)) }
}

/// Fill rate expressed over a window: "+1.2G/10m". None when not filling or unknown.
pub fn fmt_fill(bps: Option<f64>, window_ms: i64) -> Option<String> {
    let b = bps.filter(|b| b.is_finite() && b.abs() >= 1.0)?;
    let d = (b * window_ms as f64 / 1000.0) as i64;
    Some(format!("{}/{}", fmt_delta(d), fmt_window(window_ms)))
}

/// "full in 3h".
pub fn fmt_eta(secs: u64) -> String {
    format!("full in {}", fmt_dur_short(secs))
}

/// Red under 2h, yellow under a day.
pub fn eta_color(secs: u64) -> Color {
    if secs < 2 * 3600 {
        Color::Red
    } else if secs < 86_400 {
        Color::Yellow
    } else {
        Color::Reset
    }
}

/// Short tag for where a growth number came from.
pub fn evidence_tag(e: crate::fs::Evidence) -> &'static str {
    use crate::fs::Evidence::*;
    match e {
        Fsevents => "fsevents",
        Watch => "watch",
        OpenFiles => "open-files",
        ScanDiff => "scan-diff",
        Mtime => "mtime≤",
    }
}

pub fn evidence_tags(ev: &[crate::fs::Evidence]) -> String {
    ev.iter().map(|e| evidence_tag(*e)).collect::<Vec<_>>().join(",")
}

/// How a grower's path reads in a list: "other under /x/" for a remainder row.
pub fn grower_label(g: &crate::fs::Grower) -> String {
    let slash = if g.is_dir && !g.path.ends_with('/') { "/" } else { "" };
    if g.other { format!("other under {}{slash}", g.path) } else { format!("{}{slash}", g.path) }
}

/// Deleted-but-open files smaller than this are counted, not listed.
pub const DELETED_MIN_BYTES: u64 = 1 << 20;

/// Deleted-but-still-open files held by one process.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeletedGroup {
    pub pid: u32,
    pub name: String,
    pub files: usize,
    pub bytes: u64,
    /// The biggest of its files.
    pub biggest: String,
}

/// Deleted-but-open files (pid, name, path, bytes) grouped by the process holding them,
/// biggest first. Files under `min` bytes are left out and returned as (count, bytes).
pub fn group_deleted(v: &[(u32, String, String, u64)], min: u64) -> (Vec<DeletedGroup>, usize, u64) {
    // (group, size of its biggest file)
    let mut groups: Vec<(DeletedGroup, u64)> = Vec::new();
    let (mut small, mut small_bytes) = (0usize, 0u64);
    for (pid, name, path, b) in v {
        if *b < min {
            small += 1;
            small_bytes += b;
            continue;
        }
        match groups.iter_mut().find(|(g, _)| g.pid == *pid) {
            Some((g, top)) => {
                g.files += 1;
                g.bytes += b;
                if *b > *top {
                    *top = *b;
                    g.biggest = path.clone();
                }
            }
            None => groups
                .push((DeletedGroup { pid: *pid, name: name.clone(), files: 1, bytes: *b, biggest: path.clone() }, *b)),
        }
    }
    let mut groups: Vec<DeletedGroup> = groups.into_iter().map(|(g, _)| g).collect();
    groups.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.pid.cmp(&b.pid)));
    (groups, small, small_bytes)
}

/// Growth coloring: big positive deltas are hot, shrinking is green.
pub fn delta_style(d: i64) -> Style {
    if d >= 1 << 30 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if d >= 100 << 20 {
        Style::default().fg(Color::Red)
    } else if d >= 1 << 20 {
        Style::default().fg(Color::Yellow)
    } else if d < 0 {
        Style::default().fg(Color::Green)
    } else if d > 0 {
        Style::default()
    } else {
        dim()
    }
}

/// Volume fill (0..1) color: crit at 97%, warn at 90%.
pub fn fill_color(ratio: f64) -> Color {
    if ratio >= 0.97 {
        Color::Red
    } else if ratio >= 0.90 {
        Color::Yellow
    } else {
        Color::Green
    }
}

/// Share of a volume in use from the user's point of view: (total - avail) / total.
pub fn volume_ratio(v: &crate::fs::Volume) -> f64 {
    if v.total == 0 { 0.0 } else { v.total.saturating_sub(v.avail) as f64 / v.total as f64 }
}

/// Volumes not worth a line in the strip: macOS system helper volumes (Preboot, Update, xarts,
/// ...: they share the Data volume's container), the sealed read-only system snapshot when the
/// Data volume is listed, container bind-mounted files (/etc/hosts), and empty ones.
pub fn volume_hidden(v: &crate::fs::Volume, all: &[crate::fs::Volume]) -> bool {
    if v.total == 0 || v.hidden {
        return true;
    }
    if v.primary {
        return false;
    }
    let m = v.mount.as_str();
    if m.starts_with("/System/Volumes/") && m != "/System/Volumes/Data" && m != "/System/Volumes/VM" {
        return true;
    }
    if m == "/" && v.read_only && all.iter().any(|o| o.primary && o.mount != "/") {
        return true;
    }
    m.starts_with("/etc/")
        || m.starts_with("/dev/")
        || m.starts_with("/proc")
        || m.starts_with("/sys/")
        || v.fstype == "squashfs"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deleted_files_group_by_holder() {
        let v = vec![
            (9, "java".to_string(), "/tmp/a.log".to_string(), 3 << 30),
            (7, "Chrome".to_string(), "/tmp/c1".to_string(), 1 << 10),
            (9, "java".to_string(), "/tmp/b.log".to_string(), 5 << 30),
            (7, "Chrome".to_string(), "/tmp/c2".to_string(), 2 << 20),
            (7, "Chrome".to_string(), "/tmp/c3".to_string(), 512),
        ];
        let (g, small, small_bytes) = group_deleted(&v, DELETED_MIN_BYTES);
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].pid, g[0].files, g[0].bytes, g[0].biggest.as_str()), (9, 2, 8 << 30, "/tmp/b.log"));
        assert_eq!((g[1].pid, g[1].files, g[1].bytes), (7, 1, 2 << 20));
        assert_eq!((small, small_bytes), (2, 1024 + 512));
        let other = crate::fs::Grower { path: "/w".into(), is_dir: true, other: true, ..Default::default() };
        assert_eq!(grower_label(&other), "other under /w/");
    }

    #[test]
    fn storage_formatting() {
        assert_eq!(fmt_delta(0), "0");
        assert_eq!(fmt_delta(1536), "+1.5K");
        assert_eq!(fmt_delta(-(300 << 20)), "-300.0M");
        assert_eq!(fmt_delta(i64::MIN), "-8388608.0T");
        assert_eq!(fmt_ago(2), "now");
        assert_eq!(fmt_ago(42), "42s ago");
        assert_eq!(fmt_ago(150), "2m ago");
        assert_eq!(fmt_ago(3 * 3600 + 5), "3h ago");
        assert_eq!(fmt_ago(-30), "now");
        assert_eq!(fmt_mtime_age(0, 1_000_000), "-");
        assert_eq!(fmt_mtime_age(1000 - 120, 1_000_000), "2m ago");
        assert_eq!(fmt_window(600_000), "10m");
        assert_eq!(fmt_window(3_600_000), "1h");
        assert_eq!(fmt_window(86_400_000), "24h");
        assert_eq!(fmt_fill(Some(2.0 * 1024.0 * 1024.0), 600_000).as_deref(), Some("+1.2G/10m"));
        assert_eq!(fmt_fill(Some(-1024.0), 3_600_000).as_deref(), Some("-3.5M/1h"));
        assert_eq!(fmt_fill(None, 600_000), None);
        assert_eq!(fmt_fill(Some(0.2), 600_000), None);
        assert_eq!(fmt_eta(3 * 3600 + 100), "full in 3h");
        assert_eq!(eta_color(3600), Color::Red);
        assert_eq!(eta_color(5 * 3600), Color::Yellow);
        assert_eq!(eta_color(3 * 86_400), Color::Reset);
        use crate::fs::Evidence;
        assert_eq!(evidence_tags(&[Evidence::Fsevents, Evidence::OpenFiles]), "fsevents,open-files");
        assert_eq!(fill_color(0.98), Color::Red);
        assert_eq!(fill_color(0.91), Color::Yellow);
    }

    #[test]
    fn hidden_volumes() {
        use crate::fs::Volume;
        let v = |m: &str, ro: bool, primary: bool| Volume {
            mount: m.into(),
            total: 100,
            read_only: ro,
            primary,
            ..Default::default()
        };
        let mac = vec![
            v("/", true, false),
            v("/System/Volumes/Data", false, true),
            v("/System/Volumes/VM", false, false),
            v("/System/Volumes/Preboot", false, false),
            v("/Volumes/Install", true, false),
        ];
        let shown: Vec<&str> = mac.iter().filter(|x| !volume_hidden(x, &mac)).map(|x| x.mount.as_str()).collect();
        assert_eq!(shown, vec!["/System/Volumes/Data", "/System/Volumes/VM", "/Volumes/Install"]);
        let linux = vec![v("/", false, true), v("/etc/hosts", false, false), v("/home", false, false)];
        let shown: Vec<&str> = linux.iter().filter(|x| !volume_hidden(x, &linux)).map(|x| x.mount.as_str()).collect();
        assert_eq!(shown, vec!["/", "/home"]);
        assert!((volume_ratio(&Volume { total: 100, avail: 25, ..Default::default() }) - 0.75).abs() < 1e-9);
    }

    #[test]
    fn bytes_and_rates() {
        assert_eq!(fmt_bytes(512), "512B");
        assert_eq!(fmt_bytes(1536), "1.5K");
        assert_eq!(fmt_bytes(5 << 20), "5.0M");
        assert_eq!(fmt_bytes(3 << 30), "3.0G");
        assert_eq!(fmt_rate(0), "-");
        assert_eq!(fmt_power(0.0), "-");
        assert_eq!(fmt_power(850.0), "850mW");
        assert_eq!(fmt_power(12_340.0), "12.3W");
    }

    #[test]
    fn durations() {
        assert_eq!(fmt_dur(42), "42s");
        assert_eq!(fmt_dur(7 * 60 + 3), "7m3s");
        assert_eq!(fmt_dur(5 * 3600 + 12 * 60), "5h12m");
        assert_eq!(fmt_dur(3 * 86400 + 4 * 3600), "3d4h");
    }

    #[test]
    fn bars_have_exact_width() {
        for r in [0.0, 0.01, 0.33, 0.5, 0.99, 1.0, 2.0, f64::NAN] {
            assert_eq!(bar(r, 10).chars().count(), 10, "ratio {r}");
        }
        assert_eq!(bar(1.0, 4), "████");
        assert_eq!(sparkline([0.0f32, 100.0].into_iter(), 4).chars().count(), 4);
        assert!(sparkline([0.0f32, 100.0].into_iter(), 4).ends_with("▁█"));
        assert_eq!(sparkline((0..50).map(|i| i as f32), 5).chars().count(), 5);
    }

    #[test]
    fn clip_and_ci() {
        assert_eq!(clip("héllo", 2), "h");
        assert_eq!(clip("abc", 10), "abc");
        assert!(contains_ci("Google Chrome Helper", "chrome"));
        assert!(!contains_ci("node", "nodejs"));
        assert!(contains_ci("x", ""));
    }
}
