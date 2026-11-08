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

#[cfg(test)]
mod tests {
    use super::*;

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
