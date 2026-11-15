//! Colors by what they mean. Views ask for `warn()` or `crit()` rather than a fixed color,
//! so a theme (and the user's `[theme]` overrides) recolors everything at once.
//!
//! Themes:
//! - `dark`: the 16 basic terminal colors, so the terminal's own palette applies.
//! - `light`: fixed 256-color shades that stay readable on a light background.
//! - `mono`: no color. Each frame is drawn as `dark`, then [`strip`] turns every color into
//!   an attribute (bold, underline, dim, reverse), so nothing can slip through uncolored-but-
//!   meaningless. Chosen by itself when `NO_COLOR` is set and the config names no theme.
//!
//! The current theme is per thread: the TUI draws on one thread, and tests that set a theme
//! don't disturb each other.
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use std::cell::Cell;

/// Built-in theme names, for the Settings page ("auto": mono with NO_COLOR, else dark).
pub const NAMES: &[&str] = &["auto", "dark", "light", "mono"];

/// Keys `[theme]` accepts besides `name`, in the order the docs list them.
pub const ROLES: &[&str] =
    &["accent", "badge_text", "good", "warn", "crit", "hot", "info", "mark", "key", "dim", "muted", "selection"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub name: &'static str,
    /// Focus, tab bar, headings.
    pub accent: Color,
    /// Text on a colored badge (accent, mark, warn, crit backgrounds).
    pub badge_text: Color,
    /// Fine, running, live, shrinking.
    pub good: Color,
    /// Worth a look.
    pub warn: Color,
    /// Act now.
    pub crit: Color,
    /// Between warn and crit (thermal "serious", load).
    pub hot: Color,
    /// Neutral facts: mounts, names, sources.
    pub info: Color,
    /// Off the normal path: paused, rewound, agent actions.
    pub mark: Color,
    /// Key hints and the active filter.
    pub key: Color,
    /// Secondary text.
    pub dim: Color,
    /// Unknown or inactive.
    pub muted: Color,
    /// Background of the selected row.
    pub selection: Color,
    /// Colors are turned into attributes after drawing.
    pub mono: bool,
}

impl Theme {
    pub const fn dark() -> Self {
        Theme {
            name: "dark",
            accent: Color::Cyan,
            badge_text: Color::Black,
            good: Color::Green,
            warn: Color::Yellow,
            crit: Color::Red,
            hot: Color::LightRed,
            info: Color::LightBlue,
            mark: Color::Magenta,
            key: Color::Yellow,
            dim: Color::DarkGray,
            muted: Color::Gray,
            selection: Color::Indexed(236),
            mono: false,
        }
    }

    pub const fn light() -> Self {
        Theme {
            name: "light",
            accent: Color::Indexed(31),
            badge_text: Color::Indexed(231),
            good: Color::Indexed(28),
            warn: Color::Indexed(130),
            crit: Color::Indexed(160),
            hot: Color::Indexed(166),
            info: Color::Indexed(25),
            mark: Color::Indexed(127),
            key: Color::Indexed(94),
            dim: Color::Indexed(244),
            muted: Color::Indexed(240),
            selection: Color::Indexed(254),
            mono: false,
        }
    }

    pub const fn mono() -> Self {
        Theme { name: "mono", mono: true, ..Theme::dark() }
    }

    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "dark" => Some(Self::dark()),
            "light" => Some(Self::light()),
            "mono" => Some(Self::mono()),
            _ => None,
        }
    }

    fn slot(&mut self, role: &str) -> Option<&mut Color> {
        Some(match role {
            "accent" => &mut self.accent,
            "badge_text" => &mut self.badge_text,
            "good" => &mut self.good,
            "warn" => &mut self.warn,
            "crit" => &mut self.crit,
            "hot" => &mut self.hot,
            "info" => &mut self.info,
            "mark" => &mut self.mark,
            "key" => &mut self.key,
            "dim" => &mut self.dim,
            "muted" => &mut self.muted,
            "selection" => &mut self.selection,
            _ => return None,
        })
    }

    /// The theme `[theme]` asks for, given `NO_COLOR` and `FAT_THEME`, plus what was wrong
    /// with it (unknown names, colors that don't parse). Overrides don't apply to mono.
    pub fn from_cfg(cfg: &crate::config::ThemeCfg, env: &dyn Fn(&str) -> Option<String>) -> (Theme, Vec<String>) {
        let mut problems = Vec::new();
        let set = |v: Option<String>| v.filter(|v| !v.trim().is_empty());
        let wanted = set(env("FAT_THEME")).or_else(|| set(Some(cfg.name.clone()))).unwrap_or_default();
        let wanted = wanted.trim().to_ascii_lowercase();
        let auto = || if set(env("NO_COLOR")).is_some() { Theme::mono() } else { Theme::dark() };
        let mut t = match wanted.as_str() {
            "" | "auto" => auto(),
            n => Theme::by_name(n).unwrap_or_else(|| {
                problems.push(format!("theme \"{n}\" is not one of dark, light, mono"));
                auto()
            }),
        };
        if t.mono {
            return (t, problems);
        }
        for (role, value) in &cfg.colors {
            let Some(slot) = t.slot(role) else {
                problems.push(format!("[theme] {role}: not a color name fat uses ({})", ROLES.join(", ")));
                continue;
            };
            let value = match value {
                toml::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            match parse_color(&value) {
                Some(c) => *slot = c,
                None => problems
                    .push(format!("[theme] {role} = \"{value}\": use a name (red, light-blue…), 0-255, or #rrggbb")),
            }
        }
        (t, problems)
    }
}

/// "red", "light-blue", "dark_gray", "default", "208", "#d08700".
pub fn parse_color(s: &str) -> Option<Color> {
    let s = s.trim().to_ascii_lowercase().replace(['_', ' '], "-");
    if let Some(hex) = s.strip_prefix('#') {
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let v = u32::from_str_radix(hex, 16).ok()?;
        return Some(Color::Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8));
    }
    if let Ok(i) = s.parse::<u8>() {
        return Some(Color::Indexed(i));
    }
    Some(match s.as_str() {
        "default" | "reset" | "none" => Color::Reset,
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "gray" | "grey" => Color::Gray,
        "dark-gray" | "dark-grey" | "darkgray" | "darkgrey" => Color::DarkGray,
        "light-red" | "lightred" => Color::LightRed,
        "light-green" | "lightgreen" => Color::LightGreen,
        "light-yellow" | "lightyellow" => Color::LightYellow,
        "light-blue" | "lightblue" => Color::LightBlue,
        "light-magenta" | "lightmagenta" => Color::LightMagenta,
        "light-cyan" | "lightcyan" => Color::LightCyan,
        "white" => Color::White,
        _ => return None,
    })
}

thread_local! {
    static CURRENT: Cell<Theme> = const { Cell::new(Theme::dark()) };
}

pub fn set(t: Theme) {
    CURRENT.with(|c| c.set(t));
}

pub fn get() -> Theme {
    CURRENT.with(|c| c.get())
}

pub fn accent() -> Color {
    get().accent
}
pub fn badge_text() -> Color {
    get().badge_text
}
pub fn good() -> Color {
    get().good
}
pub fn warn() -> Color {
    get().warn
}
pub fn crit() -> Color {
    get().crit
}
pub fn hot() -> Color {
    get().hot
}
pub fn info() -> Color {
    get().info
}
pub fn mark() -> Color {
    get().mark
}
pub fn key() -> Color {
    get().key
}
pub fn dim_color() -> Color {
    get().dim
}
pub fn muted() -> Color {
    get().muted
}
pub fn selection() -> Color {
    get().selection
}

/// Text on a colored background.
pub fn badge(bg: Color) -> ratatui::style::Style {
    ratatui::style::Style::default().fg(badge_text()).bg(bg)
}

/// Mono: replace every color drawn (with the dark theme) by an attribute that keeps its
/// meaning, and every background by reverse video.
pub fn strip(buf: &mut Buffer) {
    let d = Theme::dark();
    for cell in buf.content.iter_mut() {
        let mut m = Modifier::empty();
        let fg = cell.fg;
        if fg == d.crit {
            m |= Modifier::BOLD | Modifier::UNDERLINED;
        } else if fg == d.hot || fg == d.warn || fg == d.accent {
            m |= Modifier::BOLD;
        } else if fg == d.mark {
            m |= Modifier::ITALIC;
        } else if fg == d.dim {
            m |= Modifier::DIM;
        }
        if cell.symbol() == " " {
            // Underline only the text, not the padding of a right-aligned number.
            m -= Modifier::UNDERLINED;
        }
        if cell.bg != Color::Reset {
            // A badge or the selected row: the text keeps its weight, the color becomes reverse.
            m = (m - Modifier::DIM) | Modifier::REVERSED;
        }
        cell.modifier |= m;
        cell.fg = Color::Reset;
        cell.bg = Color::Reset;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ThemeCfg;

    fn cfg(name: &str, colors: &[(&str, &str)]) -> ThemeCfg {
        let colors = colors.iter().map(|(k, v)| (k.to_string(), toml::Value::String(v.to_string()))).collect();
        ThemeCfg { name: name.into(), colors }
    }

    #[test]
    fn colors_parse_by_name_index_and_hex() {
        assert_eq!(parse_color("light_blue"), Some(Color::LightBlue));
        assert_eq!(parse_color("Dark Gray"), Some(Color::DarkGray));
        assert_eq!(parse_color("208"), Some(Color::Indexed(208)));
        assert_eq!(parse_color("#d08700"), Some(Color::Rgb(0xd0, 0x87, 0)));
        assert_eq!(parse_color("default"), Some(Color::Reset));
        for bad in ["#d087", "#gg0000", "256", "orange", ""] {
            assert_eq!(parse_color(bad), None, "{bad}");
        }
    }

    #[test]
    fn theme_from_config_env_and_no_color() {
        let none = |_: &str| None;
        assert_eq!(Theme::from_cfg(&cfg("", &[]), &none).0, Theme::dark());
        assert_eq!(Theme::from_cfg(&cfg("light", &[]), &none).0, Theme::light());
        let no_color = |k: &str| (k == "NO_COLOR").then(|| "1".to_string());
        assert!(Theme::from_cfg(&cfg("", &[]), &no_color).0.mono, "NO_COLOR picks mono");
        assert!(Theme::from_cfg(&cfg("auto", &[]), &no_color).0.mono);
        assert_eq!(Theme::from_cfg(&cfg("dark", &[]), &no_color).0, Theme::dark(), "a named theme wins over NO_COLOR");
        let empty_nc = |k: &str| (k == "NO_COLOR").then(String::new);
        assert!(!Theme::from_cfg(&cfg("", &[]), &empty_nc).0.mono, "an empty NO_COLOR doesn't count");
        let fat_theme = |k: &str| (k == "FAT_THEME").then(|| "mono".to_string());
        assert!(Theme::from_cfg(&cfg("light", &[]), &fat_theme).0.mono, "FAT_THEME wins over the file");
    }

    #[test]
    fn overrides_apply_and_bad_ones_are_reported() {
        let none = |_: &str| None;
        let (t, p) = Theme::from_cfg(&cfg("light", &[("warn", "#d08700"), ("crit", "203")]), &none);
        assert_eq!((t.warn, t.crit, t.good), (Color::Rgb(0xd0, 0x87, 0), Color::Indexed(203), Theme::light().good));
        assert!(p.is_empty());
        let (t, p) = Theme::from_cfg(&cfg("dark", &[("warn", "orange"), ("sparkle", "red")]), &none);
        assert_eq!(t.warn, Color::Yellow, "a bad color keeps the theme's own");
        assert_eq!(p.len(), 2);
        assert!(p[0].contains("sparkle") || p[1].contains("sparkle"));
        let (t, p) = Theme::from_cfg(&cfg("neon", &[]), &none);
        assert_eq!(t, Theme::dark());
        assert!(p[0].contains("neon"));
        let (t, _) = Theme::from_cfg(&cfg("mono", &[("warn", "red")]), &none);
        assert_eq!(t, Theme::mono(), "mono has no colors to override");
    }

    #[test]
    fn every_role_has_a_slot() {
        let mut t = Theme::dark();
        for r in ROLES {
            assert!(t.slot(r).is_some(), "{r}");
        }
    }

    #[test]
    fn strip_keeps_meaning_without_color() {
        use ratatui::layout::Rect;
        use ratatui::style::Style;
        let d = Theme::dark();
        let mut b = Buffer::empty(Rect::new(0, 0, 5, 1));
        b[(0, 0)].set_symbol("9").set_style(Style::default().fg(d.crit));
        b[(1, 0)].set_style(Style::default().fg(d.warn));
        b[(2, 0)].set_style(Style::default().fg(d.dim));
        b[(3, 0)].set_style(Style::default().fg(d.badge_text).bg(d.accent));
        b[(4, 0)].set_style(Style::default().fg(d.good));
        strip(&mut b);
        assert!(b.content.iter().all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
        assert!(b[(0, 0)].modifier.contains(Modifier::BOLD | Modifier::UNDERLINED));
        assert!(b[(1, 0)].modifier.contains(Modifier::BOLD));
        assert!(b[(2, 0)].modifier.contains(Modifier::DIM));
        assert!(b[(3, 0)].modifier.contains(Modifier::REVERSED));
        assert!(b[(4, 0)].modifier.is_empty());
        let mut pad = Buffer::empty(Rect::new(0, 0, 1, 1));
        pad[(0, 0)].set_style(Style::default().fg(d.crit));
        strip(&mut pad);
        assert!(!pad[(0, 0)].modifier.contains(Modifier::UNDERLINED), "padding isn't underlined");
    }
}
