//! Rendering. Only visible rows are materialized, so cost scales with the
//! terminal height, not the process count.

use crate::fs::Volume;
use crate::model::{Container, Proc};
use crate::tui::app::{App, FsMode, GrowthRow, Modal, SortKey, Tab, ZOOM_NAMES, ZOOMS};
use crate::tui::server_ui;
use crate::tui::widgets::*;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Axis, Block, Borders, Cell, Chart, Clear, Dataset, GraphType, LegendPosition, List, ListItem, ListState, Paragraph,
    Row, Table, Tabs, Wrap,
};

pub(super) const SEL_BG: Color = Color::Indexed(236);
pub(super) const ACCENT: Color = Color::Cyan;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn draw(f: &mut Frame, app: &mut App) {
    app.ensure_rows();
    app.ensure_server_rows();
    let area = f.area();
    let header_h = if area.height < 16 { 2 } else { 4 };
    let [header, tabs, main, footer] = Layout::vertical([
        Constraint::Length(header_h),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_header(f, app, header);
    draw_tabs(f, app, tabs);

    let side_panel = app.why.is_some() && main.width >= 120;
    let (main, side) = if side_panel {
        let [m, s] = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(main);
        (m, Some(s))
    } else {
        (main, None)
    };

    match app.tab {
        Tab::Procs => draw_procs(f, app, main),
        Tab::Ports => draw_ports(f, app, main),
        Tab::Fs => draw_fs(f, app, main),
        Tab::Fleet if app.fleet.active() => server_ui::draw_fleet(f, app, main),
        Tab::Fleet => draw_fleet(f, app, main),
        Tab::Timeline => draw_timeline(f, app, main),
        Tab::Doctor => draw_doctor(f, app, main),
        Tab::Ask => draw_ask_tab(f, app, main),
        Tab::Log => draw_log(f, app, main),
        Tab::Settings => draw_settings(f, app, main),
        Tab::Services => server_ui::draw_services(f, app, main),
        Tab::Events => server_ui::draw_events(f, app, main),
    }

    if let Some(p) = &app.panel {
        server_ui::draw_panel(f, p, main);
    }
    if app.why.is_some() {
        let r = side.unwrap_or_else(|| centered(main.width.saturating_sub(4), main.height, main));
        draw_why(f, app, r);
    }
    draw_footer(f, app, footer);
    draw_modal(f, app, area);
}

// ------------------------------------------------------------------- header

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let snap = app.view().or(app.live.as_ref());
    let w = area.width as usize;
    let mut lines: Vec<Line> = Vec::with_capacity(4);

    // line 1: identity + live/rewind badge
    let badge: Vec<Span> = match app.cursor {
        Some(ts) => vec![Span::styled(
            format!(" ⏪ REWIND {} ", fmt_clock(ts)),
            Style::default().fg(Color::White).bg(Color::Magenta).add_modifier(Modifier::BOLD),
        )],
        None => {
            let mut v = vec![Span::styled(" ● LIVE ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))];
            if app.history_ok {
                v.push(Span::styled("rec ", Style::default().fg(Color::Red)));
            }
            v
        }
    };
    let badge_w: usize = badge.iter().map(|s| s.width()).sum();
    let mut l1 = vec![Span::styled(" fat ", Style::default().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD))];
    if let Some(err) = &app.collector_error {
        l1.push(Span::styled(format!(" collector unavailable: {err}"), Style::default().fg(Color::Red)));
    } else if let Some(s) = snap {
        let sys = &s.system;
        l1.push(Span::styled(
            format!(" {} ", if sys.hostname.is_empty() { &s.host } else { &sys.hostname }),
            Style::default().bold(),
        ));
        l1.push(Span::styled(format!(" up {}", fmt_dur(sys.uptime)), dim()));
        l1.push(Span::raw(format!("  load {:.2} {:.2} {:.2}", sys.load[0], sys.load[1], sys.load[2])));
        if app.server() {
            // Load means little without the core count (and the D-state count on line 2).
            l1.push(Span::styled(format!("/{}c", sys.cores), dim()));
        }
        l1.push(Span::styled(format!("  {} procs", s.procs.len()), dim()));
        if app.server() && !s.units.is_empty() {
            l1.push(Span::styled(format!(" · {} units", s.units.len()), dim()));
        }
    } else {
        l1.push(Span::styled(" sampling…", dim()));
    }
    if let Some(note) = &app.update_note {
        let used: usize = l1.iter().map(|s| s.width()).sum();
        if used + badge_w + note.chars().count() + 3 < w {
            l1.push(Span::styled(format!("  {note}"), Style::default().fg(Color::Yellow)));
        }
    }
    let used: usize = l1.iter().map(|s| s.width()).sum();
    if used + badge_w < w {
        l1.push(Span::raw(" ".repeat(w - used - badge_w)));
        l1.extend(badge);
    } else {
        // Narrow terminal: the badge matters more than the load average.
        l1.splice(1..1, badge);
    }
    lines.push(Line::from(l1));

    let Some(s) = snap else {
        f.render_widget(Paragraph::new(lines), area);
        return;
    };
    let sys = &s.system;
    if app.server() {
        let n = area.height.saturating_sub(1) as usize;
        lines.extend(server_ui::header_lines(app, s, w, n));
        f.render_widget(Paragraph::new(lines), area);
        return;
    }

    // line 2: cpu sparkline + per-core
    let cores_w = if sys.per_core.len() + 12 < w / 2 { sys.per_core.len() } else { 0 };
    let spark_w = w.saturating_sub(10 + cores_w + 2);
    let mut l2 = vec![
        Span::styled("CPU ", Style::default().fg(ACCENT).bold()),
        Span::styled(format!("{:>4.0}% ", sys.cpu), Style::default().fg(pct_color(sys.cpu)).bold()),
        Span::styled(
            sparkline(app.ring_points.iter().map(|p| p.cpu), spark_w),
            Style::default().fg(pct_color(sys.cpu)),
        ),
    ];
    if cores_w > 0 {
        l2.push(Span::raw(" "));
        for &c in &sys.per_core {
            l2.push(Span::styled(spark_char(c).to_string(), Style::default().fg(pct_color(c))));
        }
    }
    lines.push(Line::from(l2));

    if area.height >= 4 {
        // line 3: memory
        let ratio = if sys.mem_total > 0 { sys.mem_used as f64 / sys.mem_total as f64 } else { 0.0 };
        // Linux PSI takes room on this line; the memory bar gives some back.
        let bw = if sys.psi.is_some() { (w / 6).clamp(8, 40) } else { (w / 4).clamp(8, 40) };
        let pc = pressure_color(&sys.mem_pressure);
        let mut l3 = vec![
            Span::styled("MEM ", Style::default().fg(ACCENT).bold()),
            Span::styled(bar(ratio, bw), Style::default().fg(pc)),
            Span::raw(format!(" {}/{} ", fmt_bytes(sys.mem_used), fmt_bytes(sys.mem_total))),
            Span::styled(
                if sys.mem_pressure.is_empty() { "unknown" } else { sys.mem_pressure.as_str() },
                Style::default().fg(pc),
            ),
        ];
        if let Some(psi) = &sys.psi {
            l3.extend(psi_spans(psi));
        }
        if sys.swap_total > 0 || sys.swap_used > 0 {
            l3.push(Span::styled("  SWP ", Style::default().fg(ACCENT)));
            l3.push(Span::raw(format!("{}/{}", fmt_bytes(sys.swap_used), fmt_bytes(sys.swap_total))));
        }
        if !sys.gpus.is_empty() {
            let util = sys.gpus.iter().map(|g| g.util).fold(0.0f32, f32::max);
            l3.push(Span::styled("  GPU ", Style::default().fg(ACCENT)));
            l3.push(Span::styled(format!("{util:.0}%"), Style::default().fg(pct_color(util))));
        }
        lines.push(Line::from(l3));

        // line 4: power, thermal, io, battery
        let mut l4 = vec![Span::styled("PWR ", Style::default().fg(ACCENT).bold())];
        l4.extend(power_spans(sys.power_mw, &sys.power_source));
        l4.push(Span::styled("  THERM ", Style::default().fg(ACCENT)));
        l4.extend(thermal_spans(&sys.thermal, sys.temp_c));
        l4.extend([
            Span::styled("  NET ", Style::default().fg(ACCENT)),
            Span::raw(format!("↓{}/s ↑{}/s", fmt_bytes(sys.net_rx_bps), fmt_bytes(sys.net_tx_bps))),
            Span::styled("  DISK ", Style::default().fg(ACCENT)),
            Span::raw(format!("r{}/s w{}/s", fmt_bytes(sys.disk_read_bps), fmt_bytes(sys.disk_write_bps))),
        ]);
        if let Some(b) = sys.battery_pct {
            let src = match sys.on_battery {
                Some(true) => " bat",
                Some(false) => " AC",
                None => "",
            };
            l4.push(Span::styled("  BAT ", Style::default().fg(ACCENT)));
            l4.push(Span::styled(
                format!("{b:.0}%{src}"),
                Style::default().fg(if b < 20.0 { Color::Red } else { Color::Reset }),
            ));
        }
        lines.push(Line::from(l4));
    }
    f.render_widget(Paragraph::new(lines), area);
}

/// "PSI cpu▃12 mem▁0 io▆31": avg10 stall percentages as one-cell gauges. Stalls are bad well
/// below 100%, so the gauge saturates at 25% (10% some-pressure is already noticeable).
pub(super) fn psi_spans(psi: &crate::model::Psi) -> Vec<Span<'static>> {
    let mut v = vec![Span::styled("  PSI", Style::default().fg(ACCENT))];
    for (label, val) in [("cpu", psi.cpu_some), ("mem", psi.mem_some.max(psi.mem_full)), ("io", psi.io_some)] {
        let st = Style::default().fg(psi_color(val));
        v.push(Span::raw(format!(" {label}")));
        v.push(Span::styled(spark_char(val * 4.0).to_string(), st));
        v.push(Span::styled(format!("{val:.0}"), st));
    }
    v
}

fn psi_color(pct: f32) -> Color {
    if pct >= 20.0 {
        Color::Red
    } else if pct >= 5.0 {
        Color::Yellow
    } else {
        Color::Green
    }
}

/// Power with its provenance: "48.2W rapl" (measured package energy), "~8.0W est" (CPU-time
/// model); macOS per-task energy ("rusage") stays unlabelled as before.
fn power_spans(mw: f32, source: &str) -> Vec<Span<'static>> {
    let st = power_style(mw / 4.0);
    match source {
        "estimate" if mw > 0.0 => vec![Span::styled(format!("~{}", fmt_power(mw)), st), Span::styled(" est", dim())],
        "rapl" => vec![Span::styled(fmt_power(mw), st), Span::styled(" rapl", dim())],
        _ => vec![Span::styled(fmt_power(mw), st)],
    }
}

/// Thermal state word (macOS) and/or the hottest sensor (Linux hwmon / thermal zones).
fn thermal_spans(thermal: &str, temp_c: Option<f32>) -> Vec<Span<'static>> {
    let known = !thermal.is_empty() && thermal != "unknown";
    let mut v = Vec::with_capacity(2);
    if known || temp_c.is_none() {
        v.push(Span::styled(
            if thermal.is_empty() { "unknown".to_string() } else { thermal.to_string() },
            Style::default().fg(thermal_color(thermal)),
        ));
    }
    if let Some(t) = temp_c.filter(|t| t.is_finite()) {
        let c = if t >= 90.0 {
            Color::Red
        } else if t >= 75.0 {
            Color::LightRed
        } else if t >= 60.0 {
            Color::Yellow
        } else {
            Color::Green
        };
        v.push(Span::styled(format!("{}{t:.0}°C", if known { " " } else { "" }), Style::default().fg(c)));
    }
    v
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    // Screens (Log, Settings) sit at the right end, dimmed, without number keys.
    let screen_spans: Vec<Span> = Tab::SCREENS
        .iter()
        .enumerate()
        .flat_map(|(i, t)| {
            let key = if *t == Tab::Log { "a " } else { ", " };
            let st = if app.tab == *t { Style::default().fg(Color::Black).bg(ACCENT).bold() } else { dim() };
            let mut v = vec![Span::styled(format!(" {key}{} ", t.title()), st)];
            if i + 1 < Tab::SCREENS.len() {
                v.push(Span::styled("│", dim()));
            }
            v
        })
        .collect();
    let screens_w = Line::from(screen_spans.clone()).width() as u16;
    // Views come first: the screens show only when every view fits beside them
    // (they stay reachable with `a` and `,`).
    let views_w: u16 = app
        .tabs()
        .iter()
        .filter(|t| !Tab::SCREENS.contains(t))
        .map(|t| {
            t.title().len() as u16
                + 4
                + if *t == Tab::Doctor || *t == Tab::Ports || *t == Tab::Services { 3 } else { 0 }
        })
        .sum();
    let (area, right) = if area.width >= screens_w + views_w || Tab::SCREENS.contains(&app.tab) {
        let [l, r] = Layout::horizontal([Constraint::Min(10), Constraint::Length(screens_w)]).areas(area);
        (l, Some(r))
    } else {
        (area, None)
    };
    if let Some(r) = right {
        f.render_widget(Paragraph::new(Line::from(screen_spans)), r);
    }
    let tabs: Vec<Tab> = app.tabs().into_iter().filter(|t| !Tab::SCREENS.contains(t)).collect();
    let titles: Vec<Line> = tabs
        .iter()
        .map(|t| {
            let mut spans = vec![
                Span::styled(format!("{}", app.tab_number(*t)), Style::default().fg(Color::Yellow)),
                Span::raw(t.title()),
            ];
            if let Some(b) = server_ui::tab_badge(app, *t) {
                spans.push(b);
            }
            if *t == Tab::Doctor {
                let crit = app.findings.iter().filter(|x| x.severity == "crit").count();
                let warn = app.findings.iter().filter(|x| x.severity == "warn").count();
                if crit > 0 {
                    spans.push(Span::styled(format!(" {crit}"), Style::default().fg(Color::Red).bold()));
                } else if warn > 0 {
                    spans.push(Span::styled(format!(" {warn}"), Style::default().fg(Color::Yellow)));
                }
            }
            if *t == Tab::Fs {
                let vols = &app.fs.volumes;
                let hot = vols.iter().filter(|v| !v.read_only && !v.remote && !volume_hidden(v, vols));
                let worst = hot.fold(None::<Color>, |acc, v| {
                    let c = if volume_ratio(v) >= 0.97 || v.eta_full_s.is_some_and(|e| e < 2 * 3600) {
                        Some(Color::Red)
                    } else if volume_ratio(v) >= 0.90 || v.eta_full_s.is_some_and(|e| e < 86_400) {
                        Some(Color::Yellow)
                    } else {
                        None
                    };
                    if acc == Some(Color::Red) { acc } else { c.or(acc) }
                });
                if let Some(c) = worst {
                    spans.push(Span::styled(" ⚠", Style::default().fg(c).bold()));
                }
            }
            if *t == Tab::Ports
                && let Some(n) = app.view().map(|s| s.ports.iter().filter(|p| p.orphan).count()).filter(|n| *n > 0)
            {
                spans.push(Span::styled(format!(" ⚠{n}"), Style::default().fg(Color::Yellow)));
            }
            Line::from(spans)
        })
        .collect();
    // Eight tabs with badges do not fit 80 columns with padding: drop it rather than a tab.
    let need: usize = titles.iter().map(|l| l.width() + 3).sum();
    let pad = if need <= area.width as usize { " " } else { "" };
    let tabs = Tabs::new(titles)
        .select(tabs.iter().position(|t| *t == app.tab))
        .style(dim())
        .highlight_style(Style::default().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD))
        .divider("│")
        .padding(pad, pad);
    f.render_widget(tabs, area);
}

// ------------------------------------------------------------------- procs table

#[derive(Clone, Copy, PartialEq)]
enum Col {
    Pid,
    User,
    Cpu,
    Mem,
    Power,
    Net,
    Disk,
    Thr,
    S,
    Ctr,
    Name,
}

/// `containers`: some process runs in a container, so CONTAINER earns a column.
fn columns(width: u16, containers: bool) -> &'static [Col] {
    use Col::*;
    if containers {
        return if width >= 100 {
            &[Pid, User, Cpu, Mem, Power, Net, Disk, Thr, S, Ctr, Name]
        } else if width >= 76 {
            // Same width as USER + THR, which matter less than "which container".
            &[Pid, Cpu, Mem, Power, Net, Disk, S, Ctr, Name]
        } else if width >= 60 {
            &[Pid, Cpu, Mem, S, Ctr, Name]
        } else {
            &[Pid, Cpu, Mem, S, Name]
        };
    }
    if width >= 76 {
        &[Pid, User, Cpu, Mem, Power, Net, Disk, Thr, S, Name]
    } else if width >= 60 {
        &[Pid, Cpu, Mem, Power, Net, Disk, S, Name]
    } else {
        &[Pid, Cpu, Mem, S, Name]
    }
}

fn col_width(c: Col) -> Constraint {
    match c {
        Col::Pid => Constraint::Length(7),
        Col::User => Constraint::Length(8),
        Col::Cpu => Constraint::Length(6),
        Col::Mem | Col::Power | Col::Net | Col::Disk => Constraint::Length(7),
        Col::Thr => Constraint::Length(4),
        Col::S => Constraint::Length(1),
        Col::Ctr => Constraint::Length(12),
        Col::Name => Constraint::Min(10),
    }
}

fn col_title(c: Col, sort: SortKey, desc: bool) -> Cell<'static> {
    let (t, key, right) = match c {
        Col::Pid => ("PID", Some(SortKey::Pid), true),
        Col::User => ("USER", None, false),
        Col::Cpu => ("CPU%", Some(SortKey::Cpu), true),
        Col::Mem => ("MEM", Some(SortKey::Mem), true),
        Col::Power => ("POWER", Some(SortKey::Power), true),
        Col::Net => ("NET", Some(SortKey::Net), true),
        Col::Disk => ("DISK", Some(SortKey::Disk), true),
        Col::Thr => ("THR", None, true),
        Col::S => ("S", None, false),
        Col::Ctr => ("CONTAINER", None, false),
        Col::Name => ("NAME / CMD", Some(SortKey::Name), false),
    };
    let sorted = key == Some(sort);
    let text = if sorted { format!("{t}{}", if desc { "▼" } else { "▲" }) } else { t.to_string() };
    let style = if sorted { Style::default().fg(ACCENT).bold() } else { Style::default().bold() };
    let line = Line::styled(text, style);
    Cell::from(if right { line.alignment(Alignment::Right) } else { line })
}

pub(super) fn num(s: String, style: Style) -> Cell<'static> {
    Cell::from(Line::styled(s, style).alignment(Alignment::Right))
}

fn proc_cell<'a>(c: Col, p: &'a Proc, depth: u16, tree: bool, containers: &[Container]) -> Cell<'a> {
    let paused = p.status == "T";
    match c {
        Col::Ctr => match &p.container {
            Some(id) => {
                let known = crate::fleet::find_container(containers, id);
                let label = crate::fleet::container_label(containers, id);
                let st = if known.is_some() { Style::default().fg(Color::LightBlue) } else { dim() };
                Cell::from(Span::styled(clip(&label, 12).to_string(), st))
            }
            None => Cell::from(""),
        },
        Col::Pid => num(p.pid.to_string(), Style::default()),
        Col::User => Cell::from(Span::styled(clip(&p.user, 8), dim())),
        // Another user's process without root: "?" rather than a misleading 0.
        Col::Cpu | Col::Mem | Col::Power if p.usage_unknown => num("?".into(), dim()),
        Col::Cpu => num(format!("{:.1}", p.cpu), cpu_style(p.cpu)),
        Col::Mem => num(fmt_bytes(p.mem), mem_style(p.mem)),
        Col::Power => num(fmt_power(p.power_mw), power_style(p.power_mw)),
        Col::Net => {
            let r = p.net_rx_bps + p.net_tx_bps;
            num(fmt_rate(r), rate_style(r))
        }
        Col::Disk => {
            let r = p.disk_read_bps + p.disk_write_bps;
            num(fmt_rate(r), rate_style(r))
        }
        Col::Thr => num(p.threads.to_string(), dim()),
        Col::S => {
            let st = if paused {
                Style::default().fg(Color::Black).bg(Color::Magenta).bold()
            } else if p.status == "R" {
                Style::default().fg(Color::Green)
            } else if p.status == "Z" {
                Style::default().fg(Color::Red)
            } else {
                dim()
            };
            Cell::from(Span::styled(clip(&p.status, 1), st))
        }
        Col::Name => {
            let mut spans = Vec::with_capacity(5);
            if tree && depth > 0 {
                spans.push(Span::styled(indent(depth - 1), dim()));
                spans.push(Span::styled("└ ", dim()));
            }
            let name_style = if paused { Style::default().fg(Color::Magenta).bold() } else { Style::default().bold() };
            spans.push(Span::styled(p.name.as_str(), name_style));
            if paused {
                spans.push(Span::styled(" [paused]", Style::default().fg(Color::Magenta)));
            }
            if !p.cmd.is_empty() {
                spans.push(Span::raw(" "));
                spans.push(Span::styled(clip(&p.cmd, 240), dim()));
            }
            Cell::from(Line::from(spans))
        }
    }
}

/// Keep `sel` inside the visible window of `height` rows.
pub(super) fn scroll_into_view(sel: usize, offset: &mut usize, height: usize, len: usize) {
    let height = height.max(1);
    if sel < *offset {
        *offset = sel;
    } else if sel >= *offset + height {
        *offset = sel + 1 - height;
    }
    *offset = (*offset).min(len.saturating_sub(height));
}

fn draw_procs(f: &mut Frame, app: &mut App, area: Rect) {
    let body_h = area.height.saturating_sub(2) as usize;
    let len = app.rows.len();
    scroll_into_view(app.sel, &mut app.offset, body_h, len);
    let app = &*app;

    let Some(snap) = app.view() else {
        let msg = if app.rewound() {
            if app.past_loading {
                "loading snapshot from the recorder…"
            } else {
                "no process snapshot recorded at this moment"
            }
        } else {
            "waiting for the first sample…"
        };
        f.render_widget(
            Paragraph::new(msg).style(dim()).block(Block::default().borders(Borders::TOP).title(" Procs ")),
            area,
        );
        return;
    };

    let mut title = vec![
        Span::styled(" Procs ", Style::default().bold()),
        Span::styled(format!("{}/{} ", len, snap.procs.len()), dim()),
        Span::raw(format!("· sort {}{} ", app.sort.label(), if app.sort_desc { "▼" } else { "▲" })),
    ];
    if app.tree {
        title.push(Span::styled("· tree ", Style::default().fg(Color::Green)));
    }
    if !app.filter.is_empty() {
        title.push(Span::styled(format!("· /{} ", app.filter), Style::default().fg(Color::Yellow)));
    }
    if let Some(ts) = app.cursor {
        title.push(Span::styled(format!("· ⏪ {} ", fmt_clock(ts)), Style::default().fg(Color::Magenta).bold()));
    }

    let cols = columns(area.width, app.has_containers);
    let containers: &[Container] = if snap.containers.is_empty() { &app.containers } else { &snap.containers };
    let header = Row::new(cols.iter().map(|&c| col_title(c, app.sort, app.sort_desc)));
    let rows = app.rows.iter().enumerate().skip(app.offset).take(body_h).map(|(i, r)| {
        let p = &snap.procs[r.idx];
        let mut row = Row::new(cols.iter().map(|&c| proc_cell(c, p, r.depth, app.tree, containers)));
        if i == app.sel {
            row = row.style(Style::default().bg(SEL_BG));
        }
        row
    });
    let table = Table::new(rows, cols.iter().map(|&c| col_width(c)))
        .header(header)
        .column_spacing(1)
        .block(Block::default().borders(Borders::TOP).border_style(dim()).title(Line::from(title)));
    f.render_widget(table, area);

    if len == 0 && !app.filter.is_empty() {
        let r = Rect { y: area.y + 2, height: 1, ..area };
        f.render_widget(
            Paragraph::new(format!("no process matches '{}' — Esc clears the filter", app.filter)).style(dim()),
            r,
        );
    }
}

// ------------------------------------------------------------------- ports

fn draw_ports(f: &mut Frame, app: &mut App, area: Rect) {
    use crate::tui::app::{PortRow, PortView};
    let [chips_area, table_area] = Layout::vertical([Constraint::Length(1), Constraint::Min(2)]).areas(area);
    let body_h = table_area.height.saturating_sub(2) as usize;
    let len = app.port_rows.len();
    scroll_into_view(app.port_sel, &mut app.port_offset, body_h, len);
    let app = &*app;
    let Some(snap) = app.view() else {
        f.render_widget(
            Paragraph::new("no snapshot").style(dim()).block(Block::default().borders(Borders::TOP).title(" Ports ")),
            table_area,
        );
        return;
    };
    // Chips with live counts.
    let c = &snap.conns;
    let other: u32 = c
        .states
        .iter()
        .filter(|(st, _)| !matches!(st.as_str(), "ESTABLISHED" | "TIME_WAIT" | "CLOSE_WAIT" | "LISTEN"))
        .map(|(_, n)| n)
        .sum();
    let orphans = snap.ports.iter().filter(|p| p.orphan).count() as u32;
    let count = |v: PortView| -> u32 {
        match v {
            PortView::All => {
                snap.ports.len() as u32 + c.states.iter().filter(|(s, _)| s != "LISTEN").map(|(_, n)| n).sum::<u32>()
            }
            PortView::Listen => snap.ports.len() as u32,
            PortView::Established => c.count("ESTABLISHED"),
            PortView::TimeWait => c.count("TIME_WAIT"),
            PortView::CloseWait => c.count("CLOSE_WAIT"),
            PortView::Other => other,
            PortView::Orphans => orphans,
        }
    };
    let mut spans = Vec::new();
    for v in PortView::ALL {
        let n = count(v);
        let warn = match v {
            PortView::CloseWait => app.close_wait_rising(),
            PortView::Orphans => n > 0,
            _ => false,
        };
        let st = if v == app.port_view {
            Style::default().fg(Color::Black).bg(ACCENT).bold()
        } else if warn {
            Style::default().fg(Color::Yellow).bold()
        } else if n == 0 {
            dim()
        } else {
            Style::default()
        };
        let mark = if warn { " ⚠" } else { "" };
        spans.push(Span::styled(format!(" {} {}{mark} ", v.title(), fmt_count(n as u64)), st));
        spans.push(Span::styled("·", dim()));
    }
    spans.pop();
    spans.push(Span::styled("  ←→ view · f filter", dim()));
    f.render_widget(Paragraph::new(Line::from(spans)), chips_area);

    let mut title = vec![
        Span::styled(" Ports ", Style::default().bold()),
        Span::styled(format!("{} · {} rows ", app.port_view.title().to_lowercase(), len), dim()),
    ];
    if !app.port_filter.is_empty() {
        title.push(Span::styled(
            format!("· filter: {} (Esc clears) ", app.port_filter.describe()),
            Style::default().fg(Color::Yellow),
        ));
    }
    if c.more_groups > 0 {
        title.push(Span::styled(format!("· +{} smaller groups not shown ", c.more_groups), dim()));
    }
    let header = Row::new(
        ["STATE", "LOCAL", "PEER", "COUNT", "PID", "PROCESS", "NOTE"]
            .map(|h| Cell::from(Span::styled(h, Style::default().bold()))),
    );
    let state_style = |st: &str| match st {
        "LISTEN" => Style::default().fg(Color::Green),
        "ESTABLISHED" => Style::default().fg(ACCENT),
        "CLOSE_WAIT" => Style::default().fg(Color::Yellow),
        "TIME_WAIT" => dim(),
        _ => Style::default().fg(Color::Magenta),
    };
    let rows = app.port_rows.iter().enumerate().skip(app.port_offset).take(body_h).map(|(i, r)| {
        let mut row = match *r {
            PortRow::Listen(pi) => {
                let p = &snap.ports[pi];
                let (state, st) = match p.proto {
                    crate::model::Proto::Tcp => ("LISTEN", state_style("LISTEN")),
                    crate::model::Proto::Udp => ("udp", Style::default()),
                };
                let note = if p.orphan {
                    Line::from(vec![
                        Span::styled("⚠ orphan ", Style::default().fg(Color::Black).bg(Color::Yellow).bold()),
                        Span::styled(format!(" {}", p.note), Style::default().fg(Color::Yellow)),
                    ])
                } else {
                    Line::styled(p.note.as_str(), dim())
                };
                Row::new(vec![
                    Cell::from(Span::styled(state, st)),
                    Cell::from(format!("{}:{}", p.addr, p.port)),
                    Cell::from(Span::styled("—", dim())),
                    Cell::from(""),
                    num(p.pid.to_string(), Style::default()),
                    Cell::from(Span::styled(p.process.as_str(), Style::default().bold())),
                    Cell::from(note),
                ])
            }
            PortRow::Group(gi) => {
                let g = &c.groups[gi];
                let local = if g.inbound { format!("{}:{}", g.local, g.local_port) } else { "—".to_string() };
                let peer = if g.inbound || g.remote_port == 0 {
                    format!("{}:*", g.remote)
                } else {
                    format!("{}:{}", g.remote, g.remote_port)
                };
                let (pid, process) = match (g.pid, g.state.as_str()) {
                    (0, "TIME_WAIT") => ("-".to_string(), Span::styled("(kernel)", dim())),
                    (0, _) => ("-".to_string(), Span::styled("(owner hidden)", dim())),
                    (p, _) => (p.to_string(), Span::styled(g.process.clone(), Style::default().bold())),
                };
                let dir = if g.inbound { format!("in → :{}", g.local_port) } else { "out".to_string() };
                let mut note = vec![Span::styled(dir, dim())];
                if !g.peer_name.is_empty() {
                    note.push(Span::raw(format!("  {}", g.peer_name)));
                    if !g.peer_name_verified {
                        // The address's owner picks its PTR name: unconfirmed names prove nothing.
                        note.push(Span::styled("?", Style::default().fg(Color::Yellow)));
                    }
                }
                if let Some(n) = &g.peer_net {
                    note.push(Span::styled(format!("  AS{} {}", n.asn, n.name), dim()));
                }
                Row::new(vec![
                    Cell::from(Span::styled(g.state.to_lowercase().replace('_', "-"), state_style(&g.state))),
                    Cell::from(local),
                    Cell::from(peer),
                    num(
                        format!("×{}", g.count),
                        if g.count >= 100 { Style::default().bold() } else { Style::default() },
                    ),
                    num(pid, Style::default()),
                    Cell::from(process),
                    Cell::from(Line::from(note)),
                ])
            }
        };
        if i == app.port_sel {
            row = row.style(Style::default().bg(SEL_BG));
        }
        row
    });
    let block = Block::default().borders(Borders::TOP).border_style(dim()).title(Line::from(title));
    let block = match c.notes.first() {
        Some(n) => block.title_bottom(Line::styled(format!(" {n} "), dim())),
        None => block,
    };
    let table = Table::new(
        rows,
        [
            Constraint::Length(11),
            Constraint::Length(22),
            Constraint::Length(24),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(16),
            Constraint::Min(8),
        ],
    )
    .header(header)
    .column_spacing(1)
    .block(block);
    f.render_widget(table, table_area);
    if len == 0 {
        let r = Rect { y: table_area.y + 2, height: 1, ..table_area };
        let msg = if app.port_filter.is_empty() && app.port_view == PortView::All {
            "nothing is listening or connected (or port data unavailable)"
        } else {
            "nothing matches this view or filter (Esc shows everything)"
        };
        f.render_widget(Paragraph::new(msg).style(dim()), r);
    }
}

/// The Ports filter dialog.
fn draw_port_filter(f: &mut Frame, app: &App, form: &crate::tui::app::PortFilterForm, area: Rect) {
    let flt = &app.port_filter;
    let r = centered(64.min(area.width.saturating_sub(2)), 11, area);
    f.render_widget(Clear, r);
    let values = [
        flt.proto.map(|p| format!("{p:?}").to_lowercase()).unwrap_or_else(|| "any".into()),
        flt.scope.title().to_string(),
        flt.process.clone(),
        flt.port.clone(),
        flt.remote.clone(),
    ];
    let hints = [
        "tcp · udp · any (⏎ / ←→)",
        "loopback · private · public (⏎ / ←→)",
        "part of the name",
        "8080 or 8000-8100",
        "address, name or AS",
    ];
    let mut lines = Vec::new();
    for (i, label) in crate::tui::app::PortFilterForm::LABELS.iter().enumerate() {
        let selected = i == form.sel;
        let mut v = values[i].clone();
        if selected && form.editing {
            v.push('▏');
        }
        let shown = if v.is_empty() { "—".to_string() } else { v };
        let mut line = Line::from(vec![
            Span::raw(format!(" {label:<15}")),
            Span::styled(format!("{shown:<22}"), Style::default().bold()),
            Span::styled(hints[i], dim()),
        ]);
        if selected {
            line = line.style(Style::default().bg(SEL_BG));
        }
        lines.push(line);
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(format!(" {} rows match", app.port_rows.len()), dim()));
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" Filter ports ")
                .title_bottom(Line::styled(
                    if form.editing {
                        " type · ⏎ done "
                    } else {
                        " ↑↓ field · ⏎ change · c clear all · Esc close "
                    },
                    dim(),
                )),
        ),
        r,
    );
}

// ------------------------------------------------------------------- storage

/// Volumes worth a line, primary first then biggest.
fn strip_volumes(vols: &[Volume]) -> Vec<&Volume> {
    let mut v: Vec<&Volume> = vols.iter().filter(|v| !volume_hidden(v, vols)).collect();
    v.sort_by(|a, b| b.primary.cmp(&a.primary).then(b.total.cmp(&a.total)).then(a.mount.cmp(&b.mount)));
    v
}

fn volume_line(app: &App, v: &Volume, mount_w: usize, width: u16) -> Line<'static> {
    let wide = width >= 100;
    let bw = if wide {
        20
    } else if width >= 70 {
        12
    } else {
        6
    };
    let recorded = app
        .fs
        .past
        .as_ref()
        .filter(|p| Some(p.ts) == app.cursor)
        .and_then(|p| p.vols.iter().find(|(m, _)| *m == v.mount))
        .map(|(_, u)| *u);
    let (used, past) = match recorded.or_else(|| app.cursor.and_then(|ts| app.fs.used_at(&v.mount, ts)).map(|(_, u)| u))
    {
        Some(u) if app.cursor.is_some() => (u, true),
        _ => (v.used, false),
    };
    // Same meaning live and rewound: the share of the container in use (APFS volumes share
    // one), assuming the other volumes in it did not change.
    let ratio = if v.total == 0 {
        0.0
    } else if past {
        let others = v.total.saturating_sub(v.avail).saturating_sub(v.used);
        ((others + used) as f64 / v.total as f64).min(1.0)
    } else {
        volume_ratio(v)
    };
    let mut spans = vec![
        Span::styled(format!(" {:<w$} ", clip(&v.mount, mount_w), w = mount_w), Style::default().bold()),
        Span::styled(bar(ratio, bw), Style::default().fg(fill_color(ratio))),
        Span::raw(format!(" {}/{}", fmt_bytes(used), fmt_bytes(v.total))),
        Span::styled(format!(" {:>3.0}%", ratio * 100.0), Style::default().fg(fill_color(ratio))),
    ];
    if past {
        spans.push(Span::styled(" ⏪", Style::default().fg(Color::Magenta).bold()));
        return Line::from(spans);
    }
    // Most important first: narrow terminals cut the end of the line.
    if let Some(eta) = v.eta_full_s {
        spans.push(Span::styled(format!("  {}", fmt_eta(eta)), Style::default().fg(eta_color(eta)).bold()));
    }
    if let Some(fill) = fmt_fill(v.fill_bps, app.fs.window_ms()) {
        let st = if v.fill_bps.is_some_and(|b| b > 0.0) {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Green)
        };
        spans.push(Span::styled(format!("  {fill}"), st));
    }
    spans.push(Span::styled(format!("  avail {}", fmt_bytes(v.avail)), dim()));
    if v.read_bps + v.write_bps > 0 {
        spans.push(Span::styled(format!("  r{}/s w{}/s", fmt_rate(v.read_bps), fmt_rate(v.write_bps)), dim()));
    }
    if let Some(p) = v.purgeable.filter(|p| *p > 0 && wide) {
        spans.push(Span::styled(format!("  purgeable {}", fmt_bytes(p)), dim()));
    }
    let mut tags = Vec::new();
    if v.remote {
        // Same words as `fat fs --volumes`: a remote APFS/HFS volume is an external disk/image.
        tags.push(if v.fstype == "apfs" || v.fstype == "hfs" { "external" } else { "network" });
    }
    if v.read_only {
        tags.push("ro");
    }
    if !tags.is_empty() {
        spans.push(Span::styled(format!("  [{}]", tags.join(",")), dim()));
    }
    Line::from(spans)
}

/// "scanning 43% · 1.2M files · as of 12m ago" and friends.
fn scan_status(app: &App) -> Vec<Span<'static>> {
    let fs = &app.fs;
    if let Some(e) = &fs.error {
        return vec![Span::styled(
            format!("storage engine unavailable: {}", clip(e, 80)),
            Style::default().fg(Color::Red),
        )];
    }
    let Some(l) = fs.current() else {
        return vec![Span::styled("measuring… (numbers appear as the background scan reaches this directory)", dim())];
    };
    let mut v = Vec::new();
    let p = &l.progress;
    if p.running || l.dir.partial {
        let pct = p.fraction.map(|f| format!(" {:.0}%", (f * 100.0).clamp(0.0, 100.0))).unwrap_or_default();
        v.push(Span::styled(format!("scanning{pct}"), Style::default().fg(Color::Yellow)));
        v.push(Span::styled(format!(" · {} files", fmt_count(p.files_seen.max(l.dir.files))), dim()));
        if l.dir.partial {
            v.push(Span::styled(" · partial (lower bound)", dim()));
        }
    } else {
        v.push(Span::styled(format!("{} files", fmt_count(l.dir.files)), dim()));
    }
    let at = if l.dir.scanned_at > 0 { l.dir.scanned_at } else { p.completed_at };
    if at > 0 {
        v.push(Span::styled(format!(" · as of {}", fmt_ago((app.now - at) / 1000)), dim()));
    }
    let locked = l.children.iter().filter(|c| c.denied > 0 && !c.mount_point).count();
    if l.dir.denied > 0 && l.dir.size == 0 && l.children.is_empty() {
        let why = if cfg!(target_os = "macos") { "macOS privacy or permissions" } else { "permission denied" };
        v.push(Span::styled(format!("  🔒 not read ({why})"), Style::default().fg(Color::Yellow)));
    } else if locked > 0 {
        let s = if locked == 1 { "" } else { "s" };
        v.push(Span::styled(
            if cfg!(target_os = "macos") {
                format!("  🔒 {locked} subdir{s} with unread parts: ⏎ on one reads it (or grant Full Disk Access)")
            } else {
                format!("  🔒 {locked} subdir{s} could not be read (permission denied): not counted")
            },
            Style::default().fg(Color::Yellow),
        ));
    }
    v
}

/// 1234567 -> "1.2M" (counts, not bytes).
fn fmt_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 10_000 {
        format!("{:.0}K", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

fn draw_fs(f: &mut Frame, app: &mut App, area: Rect) {
    app.fs.ensure_rows();
    let vols = strip_volumes(&app.fs.volumes);
    let vol_h = if area.height < 10 { 0 } else { (vols.len() as u16).min(4).min(area.height / 4) };
    let detail_h = if area.height >= 12 { 1 } else { 0 };
    let [vol_area, crumb_area, table_area, detail_area] = Layout::vertical([
        Constraint::Length(vol_h),
        Constraint::Length(1),
        Constraint::Min(2),
        Constraint::Length(detail_h),
    ])
    .areas(area);
    let body_h = table_area.height.saturating_sub(2) as usize;
    let len = app.fs.len();
    scroll_into_view(app.fs.sel, &mut app.fs.offset, body_h, len);
    let app = &*app;

    // volumes strip
    if vol_h > 0 {
        let mount_w = vols.iter().map(|v| v.mount.chars().count()).max().unwrap_or(1).clamp(1, 24);
        let lines: Vec<Line> =
            vols.iter().take(vol_h as usize).map(|v| volume_line(app, v, mount_w, area.width)).collect();
        f.render_widget(Paragraph::new(lines), vol_area);
    }

    // breadcrumb + status
    let fs = &app.fs;
    let mut crumb = vec![Span::styled(" ⛁ ", Style::default().fg(ACCENT))];
    match fs.mode {
        FsMode::Tree => crumb.push(Span::styled(fs.path.clone(), Style::default().fg(ACCENT).bold())),
        FsMode::Growth => {
            crumb.push(Span::styled("growth ", Style::default().fg(Color::Yellow).bold()));
            crumb
                .push(Span::styled(format!("last {} · anywhere", fmt_window(fs.window_ms())), Style::default().bold()));
        }
        FsMode::Largest => {
            crumb.push(Span::styled("largest below ", Style::default().fg(Color::Yellow).bold()));
            crumb.push(Span::styled(fs.largest_path.clone(), Style::default().fg(ACCENT).bold()));
        }
    }
    if fs.mode == FsMode::Tree {
        let size = match fs.past_view() {
            Some(p) => p.dir_size.or_else(|| Some(p.children.iter().map(|c| c.size).sum())),
            None => fs.current().map(|l| l.dir.size),
        };
        if let Some(size) = size {
            crumb.push(Span::styled(format!("  {}", fmt_bytes(size)), Style::default().bold()));
        }
    }
    // Time travel first: it changes what every number below means.
    if let Some(ts) = app.cursor {
        let text = match fs.past_view() {
            Some(p) => format!("  ⏪ as of {} (recorded {})", fmt_clock(ts), fmt_clock(p.at.unwrap_or(ts))),
            None if app.history_ok && fs.past.as_ref().is_none_or(|p| p.ts != ts) => {
                format!("  ⏪ as of {} · loading recorded sizes…", fmt_clock(ts))
            }
            None => format!("  ⏪ as of {} · no directory sizes recorded then, showing the latest scan", fmt_clock(ts)),
        };
        crumb.push(Span::styled(text, Style::default().fg(Color::Magenta).bold()));
    }
    crumb.push(Span::raw("  "));
    if fs.past_view().is_none() || fs.mode != FsMode::Tree {
        // The live scan's status does not describe recorded sizes.
        crumb.extend(scan_status(app));
    }
    if !fs.filter.is_empty() {
        crumb.push(Span::styled(format!("  /{}", fs.filter), Style::default().fg(Color::Yellow)));
    }
    f.render_widget(Paragraph::new(Line::from(crumb)), crumb_area);

    match fs.mode {
        FsMode::Tree => draw_fs_tree(f, app, table_area, body_h),
        FsMode::Growth => draw_fs_growth(f, app, table_area, body_h),
        FsMode::Largest => draw_fs_largest(f, app, table_area, body_h),
    }

    if detail_h > 0 {
        f.render_widget(Paragraph::new(fs_detail(app)), detail_area);
    }
}

/// The detail line under the table: known-directory advice, or growth notes.
fn fs_detail(app: &App) -> Line<'static> {
    let fs = &app.fs;
    if fs.mode == FsMode::Growth {
        let notes = fs.growth.as_ref().map(|g| g.notes.join(" · ")).unwrap_or_default();
        return Line::styled(
            format!(
                " {}",
                if notes.is_empty() { "⏎ on a writer: why it runs · on a path: open it".to_string() } else { notes }
            ),
            dim(),
        );
    }
    let Some(e) = fs.selected_entry() else { return Line::raw("") };
    let mut v = Vec::new();
    if let Some(cg) = fs.selected_child_growth()
        && let Some((pid, name, bps)) = &cg.top_writer
    {
        v.push(Span::styled(format!(" ✎ {name} ({pid}) {}/s", fmt_bytes(*bps)), Style::default().fg(Color::Yellow)));
    }
    match crate::blame::explain_path(&e.path) {
        Some(t) => v.push(Span::styled(format!(" 💡 {t}"), Style::default().fg(Color::Green))),
        None => {
            let mut info = format!(" {}", e.path);
            if e.apparent > 0 && e.apparent != e.size {
                info.push_str(&format!(" · {} apparent", fmt_bytes(e.apparent)));
            }
            if e.denied > 0 {
                info.push_str(&format!(" · {} unreadable subdirs", e.denied));
            }
            if e.mount_point {
                info.push_str(" · another filesystem is mounted here (⏎ to read it)");
            }
            v.push(Span::styled(info, dim()));
        }
    }
    Line::from(v)
}

fn fs_name_cell(e: &crate::fs::DirEntry) -> Cell<'static> {
    let mut spans = Vec::with_capacity(3);
    if e.mount_point {
        spans.push(Span::styled("⛁ ", Style::default().fg(Color::LightBlue)));
    } else if e.denied > 0 && e.size == 0 {
        spans.push(Span::styled("🔒", Style::default().fg(Color::Yellow)));
    }
    let name = if e.is_dir { format!("{}/", e.name) } else { e.name.clone() };
    spans.push(Span::styled(name, if e.is_dir { Style::default().bold() } else { Style::default() }));
    if e.denied > 0 && e.size > 0 {
        spans.push(Span::styled(" 🔒", Style::default().fg(Color::Yellow)));
    }
    if e.partial {
        spans.push(Span::styled(" …", dim()));
    }
    Cell::from(Line::from(spans))
}

fn draw_fs_tree(f: &mut Frame, app: &App, area: Rect, body_h: usize) {
    let fs = &app.fs;
    let wide = area.width >= 90;
    let mid = area.width >= 64;
    let win = fmt_window(fs.window_ms());
    let sort = fs.sort;
    let head = |t: String, key: Option<crate::tui::app::FsSort>, right: bool| {
        let sorted = key == Some(sort);
        let st = if sorted { Style::default().fg(ACCENT).bold() } else { Style::default().bold() };
        let l = Line::styled(if sorted { format!("{t}▼") } else { t }, st);
        Cell::from(if right { l.alignment(Alignment::Right) } else { l })
    };
    use crate::tui::app::FsSort as S;
    let mut header = vec![head("SIZE".into(), Some(S::Size), true)];
    let mut widths = vec![Constraint::Length(8)];
    if mid {
        header.push(head("".into(), None, false));
        widths.push(Constraint::Length(if wide { 16 } else { 10 }));
    }
    header.push(head(format!("Δ{win}"), Some(S::Growth), true));
    widths.push(Constraint::Length(8));
    if wide {
        header.push(head("WRITE/s".into(), Some(S::Io), true));
        widths.push(Constraint::Length(8));
        header.push(head("FILES".into(), Some(S::Files), true));
        widths.push(Constraint::Length(7));
    }
    if mid {
        header.push(head("NEWEST".into(), Some(S::Age), true));
        widths.push(Constraint::Length(8));
    }
    header.push(head("NAME".into(), Some(S::Name), false));
    widths.push(Constraint::Min(10));

    let title = Line::from(vec![
        Span::styled(" Storage ", Style::default().bold()),
        Span::styled(format!("{} entries · sort {} ", fs.len(), fs.sort.label()), dim()),
    ]);
    let block = Block::default().borders(Borders::TOP).border_style(dim()).title(title);
    let past = fs.past_view();
    let children = fs.tree_children();
    let (parent, dir_denied) = match (past, fs.current()) {
        (Some(p), _) => (p.dir_size.unwrap_or_else(|| children.iter().map(|c| c.size).sum()), false),
        (None, Some(l)) => (l.dir.size, l.dir.denied > 0),
        (None, None) => (0, false),
    };
    if past.is_none() && fs.current().is_none() {
        let msg = if fs.error.is_some() {
            "The storage engine could not start; other views keep working.".to_string()
        } else if !fs.opened {
            String::new()
        } else {
            format!(
                "Measuring {}… The first full scan of / takes a few minutes at background priority; \
                     results appear as it goes and are cached for next time. fat only reads — it never deletes anything.",
                fs.path
            )
        };
        f.render_widget(Paragraph::new(msg).style(dim()).wrap(Wrap { trim: true }).block(block), area);
        return;
    }
    let parent = parent.max(1);
    let rows = fs.rows.iter().enumerate().skip(fs.offset).take(body_h).map(|(i, &ci)| {
        let e = &children[ci];
        let g = fs.child_growth.get(ci).cloned().unwrap_or_default();
        let ratio = e.size as f64 / parent as f64;
        let size_cell = if e.mount_point && e.size == 0 {
            num("mount".into(), Style::default().fg(Color::LightBlue))
        } else if e.denied > 0 && e.size == 0 {
            num("?".into(), dim())
        } else {
            num(fmt_bytes(e.size), mem_style(e.size))
        };
        let mut cells = vec![size_cell];
        if mid {
            let bw = if wide { 10 } else { 5 };
            cells.push(Cell::from(Line::from(vec![
                Span::styled(bar(ratio, bw), Style::default().fg(ACCENT)),
                Span::styled(format!("{:>4.0}%", ratio * 100.0), dim()),
            ])));
        }
        cells.push(num(if g.delta == 0 { "-".into() } else { fmt_delta(g.delta) }, delta_style(g.delta)));
        if wide {
            cells.push(num(fmt_rate(g.write_bps), rate_style(g.write_bps)));
            // The recorder keeps sizes only: no file counts for the past.
            cells.push(num(if past.is_some() { "-".into() } else { fmt_count(e.files) }, dim()));
        }
        if mid {
            cells.push(num(fmt_mtime_age(e.newest_mtime, app.now), dim()));
        }
        cells.push(fs_name_cell(e));
        let mut row = Row::new(cells);
        if i == fs.sel {
            row = row.style(Style::default().bg(SEL_BG));
        }
        row
    });
    let table = Table::new(rows, widths).header(Row::new(header)).column_spacing(1).block(block);
    f.render_widget(table, area);
    if fs.rows.is_empty() {
        let r = Rect { y: area.y + 2, height: 1, ..area };
        let msg = if !fs.filter.is_empty() {
            format!("nothing here matches '{}' — Esc clears the filter", fs.filter)
        } else if past.is_none() && fs.current().is_some_and(|l| l.dir.files > 1) {
            "expanding… this directory was summarized by the background scan; its entries appear in a moment"
                .to_string()
        } else if dir_denied {
            if cfg!(target_os = "macos") {
                "🔒 this directory could not be read (protected). ⏎ from its parent reads it once, or grant Full Disk Access.".to_string()
            } else {
                "🔒 this directory could not be read (permission denied). Run fat as its owner, or as root.".to_string()
            }
        } else {
            "empty (or not scanned yet)".to_string()
        };
        f.render_widget(Paragraph::new(msg).style(dim()), r);
    }
}

fn draw_fs_growth(f: &mut Frame, app: &App, area: Rect, body_h: usize) {
    let fs = &app.fs;
    let win = fmt_window(fs.window_ms());
    let Some(g) = fs.growth.as_ref() else {
        let block = Block::default().borders(Borders::TOP).border_style(dim()).title(" Growth ");
        f.render_widget(Paragraph::new("collecting the growth report…").style(dim()).block(block), area);
        return;
    };
    let total: i64 = g.volumes.iter().map(|(_, d)| *d).sum();
    // No volume samples cover the window (no recorder history yet): unknown, not "0".
    let vol_text = if g.volumes.is_empty() { "volumes ?".to_string() } else { format!("volumes {}", fmt_delta(total)) };
    let shown_deleted = fs.grows.iter().filter(|r| matches!(r, GrowthRow::Deleted(_))).count();
    let (_, small, small_bytes) = group_deleted(&g.deleted_open, DELETED_MIN_BYTES);
    let mut deleted_text = format!("{shown_deleted} holding deleted files");
    if fs.deleted.len() > shown_deleted {
        deleted_text.push_str(&format!(" (+{} more)", fs.deleted.len() - shown_deleted));
    }
    if small > 0 {
        deleted_text.push_str(&format!(" · {small} small (<1M, {}) hidden", fmt_bytes(small_bytes)));
    }
    let title = Line::from(vec![
        Span::styled(" What is eating space ", Style::default().bold()),
        Span::styled(
            format!("last {win} · {vol_text} "),
            if g.volumes.is_empty() { dim() } else { delta_style(total) },
        ),
        Span::styled(
            format!(
                "· {} growers · {deleted_text} · {} writers ",
                fs.grows.iter().filter(|r| matches!(r, GrowthRow::Grower(_))).count(),
                g.writers.len()
            ),
            dim(),
        ),
    ]);
    let wide = area.width >= 90;
    let header = Row::new(
        ["KIND", "Δ / BYTES", "SIZE", "WRITE/s", "EVIDENCE", "PATH / PROCESS"]
            .into_iter()
            .enumerate()
            .filter(|(i, _)| wide || (*i != 2 && *i != 4))
            .map(|(_, h)| Cell::from(Span::styled(h, Style::default().bold()))),
    );
    let rows = fs.grows.iter().enumerate().skip(fs.offset).take(body_h).map(|(i, r)| {
        let (kind, kst, delta, dst, size, rate, ev, what): (&str, Style, String, Style, String, u64, String, Line) =
            match *r {
                GrowthRow::Grower(j) => {
                    let x = &g.growers[j];
                    let rate: u64 = x.writers.iter().map(|w| w.2).sum();
                    let mut spans = if x.other {
                        vec![
                            Span::styled("other under ", dim()),
                            Span::styled(format!("{}/", x.path.trim_end_matches('/')), Style::default().bold()),
                        ]
                    } else {
                        vec![Span::styled(grower_label(x), Style::default().bold())]
                    };
                    if let Some(w) = x.writers.iter().max_by_key(|w| w.2) {
                        spans.push(Span::styled(format!("  ← {} ({})", w.1, w.0), Style::default().fg(Color::Yellow)));
                        if x.writers.len() > 1 {
                            spans.push(Span::styled(format!(" +{}", x.writers.len() - 1), dim()));
                        }
                    }
                    if x.files_touched > 0 {
                        spans.push(Span::styled(format!("  {} files", fmt_count(x.files_touched)), dim()));
                    }
                    (
                        "grow",
                        Style::default(),
                        fmt_delta(x.delta),
                        delta_style(x.delta),
                        fmt_bytes(x.size),
                        rate,
                        evidence_tags(&x.evidence),
                        Line::from(spans),
                    )
                }
                GrowthRow::Deleted(j) => {
                    let d = &fs.deleted[j];
                    let files = if d.files == 1 {
                        format!("{} (deleted)", d.biggest)
                    } else {
                        format!("{} deleted files, biggest {}", d.files, d.biggest)
                    };
                    let line = Line::from(vec![
                        Span::styled(format!("{} ({}) holds ", d.name, d.pid), Style::default().fg(Color::Yellow)),
                        Span::raw(files),
                        Span::styled(" · restart it to free the space · ⏎ why", dim()),
                    ]);
                    (
                        "deleted",
                        Style::default().fg(Color::Magenta),
                        fmt_bytes(d.bytes),
                        Style::default().fg(Color::Magenta),
                        String::new(),
                        0,
                        "open-files".into(),
                        line,
                    )
                }
                GrowthRow::Writer(j) => {
                    let (pid, name, bytes) = &g.writers[j];
                    let rate = app.view().and_then(|s| s.proc(*pid)).map(|p| p.disk_write_bps).unwrap_or(0);
                    let line = Line::from(vec![
                        Span::styled(name.clone(), Style::default().bold()),
                        Span::styled(format!(" (pid {pid}) wrote {} in {win} · ⏎ why", fmt_bytes(*bytes)), dim()),
                    ]);
                    (
                        "writer",
                        Style::default().fg(ACCENT),
                        fmt_bytes(*bytes),
                        Style::default(),
                        String::new(),
                        rate,
                        String::new(),
                        line,
                    )
                }
            };
        let mut cells = vec![Cell::from(Span::styled(kind, kst)), num(delta, dst)];
        if wide {
            cells.push(num(size, dim()));
        }
        cells.push(num(fmt_rate(rate), rate_style(rate)));
        if wide {
            cells.push(Cell::from(Span::styled(ev, dim())));
        }
        cells.push(Cell::from(what));
        let mut row = Row::new(cells);
        if i == fs.sel {
            row = row.style(Style::default().bg(SEL_BG));
        }
        row
    });
    let widths: Vec<Constraint> = if wide {
        vec![
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(24),
            Constraint::Min(10),
        ]
    } else {
        vec![Constraint::Length(7), Constraint::Length(9), Constraint::Length(8), Constraint::Min(10)]
    };
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(Block::default().borders(Borders::TOP).border_style(dim()).title(title));
    f.render_widget(table, area);
    if fs.grows.is_empty() {
        let r = Rect { y: area.y + 2, height: 1, ..area };
        f.render_widget(
            Paragraph::new(format!("✓ nothing grew noticeably in the last {win}"))
                .style(Style::default().fg(Color::Green)),
            r,
        );
    }
}

fn draw_fs_largest(f: &mut Frame, app: &App, area: Rect, body_h: usize) {
    let fs = &app.fs;
    let block = Block::default().borders(Borders::TOP).border_style(dim()).title(Line::from(vec![
        Span::styled(" Largest ", Style::default().bold()),
        Span::styled("⏎ opens its directory ", dim()),
    ]));
    let Some(list) = fs.largest.as_ref() else {
        f.render_widget(Paragraph::new("finding the largest entries…").style(dim()).block(block), area);
        return;
    };
    let base = fs.current().filter(|l| l.dir.path == fs.largest_path).map(|l| l.dir.size).unwrap_or(0).max(1);
    let header = Row::new(
        ["SIZE", "%", "FILES", "NEWEST", "PATH"].map(|h| Cell::from(Span::styled(h, Style::default().bold()))),
    );
    let rows = fs.rows.iter().enumerate().skip(fs.offset).take(body_h).map(|(i, &j)| {
        let e = &list[j];
        let shown =
            e.path.strip_prefix(fs.largest_path.trim_end_matches('/')).filter(|s| !s.is_empty()).unwrap_or(&e.path);
        let mut row = Row::new(vec![
            num(fmt_bytes(e.size), mem_style(e.size)),
            num(format!("{:.0}%", e.size as f64 * 100.0 / base as f64), dim()),
            num(fmt_count(e.files), dim()),
            num(fmt_mtime_age(e.newest_mtime, app.now), dim()),
            Cell::from(Span::styled(
                if e.is_dir { format!("{shown}/") } else { shown.to_string() },
                Style::default().bold(),
            )),
        ]);
        if i == fs.sel {
            row = row.style(Style::default().bg(SEL_BG));
        }
        row
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .column_spacing(1)
    .block(block);
    f.render_widget(table, area);
    if list.is_empty() {
        let r = Rect { y: area.y + 2, height: 1, ..area };
        f.render_widget(Paragraph::new("nothing measured below here yet").style(dim()), r);
    }
}

// ------------------------------------------------------------------- fleet

fn draw_fleet(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(
        ["NAME", "KIND", "STATUS", "CPU%", "MEMORY", "DETAIL"]
            .map(|h| Cell::from(Span::styled(h, Style::default().bold()))),
    );
    let mut rows: Vec<Row> = Vec::with_capacity(app.fleet_len());
    if let Some(s) = app.live.as_ref() {
        let sys = &s.system;
        rows.push(Row::new(vec![
            Cell::from(Span::styled(
                format!("● {}", if sys.hostname.is_empty() { "local" } else { &sys.hostname }),
                Style::default().fg(Color::Green).bold(),
            )),
            Cell::from("local"),
            Cell::from(Span::styled("live", Style::default().fg(Color::Green))),
            num(format!("{:.0}", sys.cpu), Style::default().fg(pct_color(sys.cpu))),
            Cell::from(format!("{}/{}", fmt_bytes(sys.mem_used), fmt_bytes(sys.mem_total))),
            Cell::from(Span::styled(format!("{} procs · {} ports", s.procs.len(), s.ports.len()), dim())),
        ]));
    } else {
        rows.push(Row::new(vec![Cell::from("● local"), Cell::from("local"), Cell::from("sampling…")]));
    }
    let nc = app.containers.len();
    // Linux: how many host processes we attribute to each container (via cgroups).
    let mut per_ctr: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    if let Some(s) = app.live.as_ref() {
        for id in s.procs.iter().filter_map(|p| p.container.as_deref()) {
            *per_ctr.entry(id).or_default() += 1;
        }
    }
    for (i, c) in app.containers.iter().enumerate() {
        let glyph = if i + 1 == nc { "  └ " } else { "  ├ " };
        let nprocs: usize = per_ctr
            .iter()
            .filter(|(id, _)| !c.id.is_empty() && (id.starts_with(&c.id) || c.id.starts_with(**id)))
            .map(|(_, n)| n)
            .sum();
        let detail = if nprocs > 0 {
            format!("{nprocs} procs · {} {}", c.image, c.ports)
        } else {
            format!("{} {}", c.image, c.ports)
        };
        let running = c.status.to_lowercase().starts_with("up") || c.status.to_lowercase().contains("running");
        rows.push(Row::new(vec![
            Cell::from(Line::from(vec![Span::styled(glyph, dim()), Span::raw(c.name.as_str())])),
            Cell::from(Span::styled(c.runtime.as_str(), dim())),
            Cell::from(Span::styled(
                clip(&c.status, 14),
                Style::default().fg(if running { Color::Green } else { Color::Gray }),
            )),
            num(format!("{:.1}", c.cpu), cpu_style(c.cpu)),
            Cell::from(Span::styled(fmt_bytes(c.mem), mem_style(c.mem))),
            Cell::from(Span::styled(detail, dim())),
        ]));
    }
    let n_rows = rows.len();
    let rows = rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| if i == app.fleet_sel { r.style(Style::default().bg(SEL_BG)) } else { r });
    let title = Line::from(vec![
        Span::styled(" Fleet ", Style::default().bold()),
        Span::styled(format!("1 local · {nc} containers "), dim()),
    ]);
    let table = Table::new(
        rows,
        [
            Constraint::Min(18),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(5),
            Constraint::Length(14),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .column_spacing(1)
    .block(Block::default().borders(Borders::TOP).border_style(dim()).title(title));
    f.render_widget(table, area);

    let used = n_rows as u16 + 2;
    if nc == 0 && area.height > used + 2 {
        let r = Rect { y: area.y + used + 1, height: area.height - used - 1, ..area }
            .inner(Margin { horizontal: 2, vertical: 0 });
        let mut t = Text::default();
        if !app.fleet_loaded {
            t.lines.push(Line::styled("scanning for containers and remote hosts…", dim()));
        } else {
            if app.configured_hosts > 0 {
                t.lines.push(Line::styled(format!("contacting {} remote host(s)…", app.configured_hosts), dim()));
            }
            t.lines.push(Line::styled("No containers or remote hosts yet.", Style::default().bold()));
            t.lines.push(Line::raw(""));
            t.lines.push(Line::raw(
                "• Containers (docker / podman / orbstack / nerdctl) appear here automatically while they run.",
            ));
            t.lines.push(Line::raw(format!("• Remote hosts: add them to {}", app.config_path)));
            t.lines.push(Line::styled("      [[hosts]]", Style::default().fg(Color::Green)));
            t.lines.push(Line::styled("      name = \"devbox\"", Style::default().fg(Color::Green)));
            t.lines.push(Line::styled(
                "      ssh  = \"me@devbox\"   # needs `fat` installed there",
                Style::default().fg(Color::Green),
            ));
            t.lines.push(Line::raw("  or list many hosts in a file: [fleet] hosts_file = \"~/.config/fat/hosts\""));
        }
        f.render_widget(Paragraph::new(t).wrap(Wrap { trim: false }), r);
    }
}

// ------------------------------------------------------------------- timeline

fn draw_timeline(f: &mut Frame, app: &mut App, area: Rect) {
    let chart_h = if area.height < 14 { area.height.saturating_sub(4).min(6) } else { (area.height * 2 / 5).max(8) };
    let [chart_area, info_area, table_area] =
        Layout::vertical([Constraint::Length(chart_h), Constraint::Length(1), Constraint::Min(0)]).areas(area);
    draw_chart(f, app, chart_area);
    draw_cursor_info(f, app, info_area);
    if table_area.height >= 3 {
        draw_procs(f, app, table_area);
    }
}

fn draw_chart(f: &mut Frame, app: &App, area: Rect) {
    let to = app.now;
    // Fill the width when we have less data than the zoom window.
    let first = app.timeline.first().map(|p| p.ts).unwrap_or(to);
    let from = (to - ZOOMS[app.zoom]).max(first.min(to - 60_000));
    let window = (to - from).max(1);
    let source = if app.timeline_from_history { "recorder" } else { "memory" };
    let title = Line::from(vec![
        Span::styled(" Timeline ", Style::default().bold()),
        Span::styled(format!("last {} ", ZOOM_NAMES[app.zoom]), Style::default().fg(Color::Yellow)),
        Span::styled("· cpu ", Style::default().fg(ACCENT)),
        Span::styled("· power ", Style::default().fg(Color::Yellow)),
        Span::styled(format!("· {} spikes · source {source} ", app.spikes.len()), dim()),
    ]);
    let block = Block::default().borders(Borders::TOP).border_style(dim()).title(title);
    let pts = &app.timeline;
    if pts.is_empty() {
        let msg = "Collecting… the timeline fills as samples arrive.\nRun `fat record` in the background to keep days of history.";
        f.render_widget(Paragraph::new(msg).style(dim()).block(block), area);
        return;
    }
    let xs = |ts: i64| ((ts - from) as f64 / 1000.0).max(0.0);
    let max_pw = pts.iter().map(|p| p.power_mw).fold(1000.0f32, f32::max);
    let cpu: Vec<(f64, f64)> = pts.iter().map(|p| (xs(p.ts), p.cpu as f64)).collect();
    let pw: Vec<(f64, f64)> = pts.iter().map(|p| (xs(p.ts), (p.power_mw / max_pw * 100.0) as f64)).collect();
    let spikes: Vec<(f64, f64)> = app
        .spikes
        .iter()
        .filter(|&&t| t >= from)
        .filter_map(|&t| pts.iter().min_by_key(|p| (p.ts - t).abs()).map(|p| (xs(t), p.cpu as f64)))
        .collect();
    let cursor: Vec<(f64, f64)> = app.cursor.map(|c| vec![(xs(c), 0.0), (xs(c), 100.0)]).unwrap_or_default();

    let mut datasets = vec![
        Dataset::default()
            .name("cpu%")
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(ACCENT))
            .data(&cpu),
        Dataset::default()
            .name(format!("power (max {})", fmt_power(max_pw)))
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Yellow))
            .data(&pw),
    ];
    if !spikes.is_empty() {
        datasets.push(
            Dataset::default()
                .name("spike")
                .marker(Marker::Dot)
                .graph_type(GraphType::Scatter)
                .style(Style::default().fg(Color::Red))
                .data(&spikes),
        );
    }
    if !cursor.is_empty() {
        datasets.push(
            Dataset::default()
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(Color::Magenta))
                .data(&cursor),
        );
    }
    let span = window as f64 / 1000.0;
    let chart = Chart::new(datasets)
        .block(block)
        .legend_position(Some(LegendPosition::TopLeft))
        .hidden_legend_constraints((Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)))
        .x_axis(Axis::default().bounds([0.0, span]).style(dim()).labels(vec![
            Span::raw(fmt_clock(from)),
            Span::raw(fmt_clock(from + window / 2)),
            Span::raw("now"),
        ]))
        .y_axis(Axis::default().bounds([0.0, 100.0]).style(dim()).labels(vec![
            Span::raw("0"),
            Span::raw("50"),
            Span::raw("100"),
        ]));
    f.render_widget(chart, area);
}

fn draw_cursor_info(f: &mut Frame, app: &App, area: Rect) {
    let line = match app.cursor {
        None => Line::from(vec![
            Span::styled("● live ", Style::default().fg(Color::Green).bold()),
            Span::styled("← / [ rewind · s jump to spike · +/- zoom · procs below follow the cursor", dim()),
        ]),
        Some(ts) => {
            let mut v = vec![Span::styled(
                format!(" ⏪ {} ", fmt_clock(ts)),
                Style::default().fg(Color::White).bg(Color::Magenta).bold(),
            )];
            v.push(Span::styled(format!(" -{} ", fmt_dur(((app.now - ts).max(0) / 1000) as u64)), dim()));
            if let Some(p) = app.timeline.iter().min_by_key(|p| (p.ts - ts).abs()) {
                v.push(Span::styled(format!(" cpu {:.0}%", p.cpu), Style::default().fg(pct_color(p.cpu))));
                v.push(Span::raw(format!("  power {}  mem {}", fmt_power(p.power_mw), fmt_bytes(p.mem_used))));
                if !p.top_name.is_empty() {
                    v.push(Span::styled(format!("  top {} {:.0}%", p.top_name, p.top_cpu), Style::default().bold()));
                }
            }
            if app.past_loading {
                v.push(Span::styled("  loading…", dim()));
            }
            v.push(Span::styled("  L live", dim()));
            Line::from(v)
        }
    };
    f.render_widget(Paragraph::new(line), area);
}

// ------------------------------------------------------------------- doctor

fn draw_doctor(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::TOP).border_style(dim()).title(Line::from(vec![
        Span::styled(" Doctor ", Style::default().bold()),
        Span::styled(format!("{} findings · ⏎ run suggested action · w why ", app.findings.len()), dim()),
    ]));
    if app.findings.is_empty() {
        let p = if app.findings_loaded {
            Paragraph::new(Line::styled("✓ All good. Nothing unusual.", Style::default().fg(Color::Green).bold()))
        } else {
            Paragraph::new(Line::styled("diagnosing…", dim()))
        };
        f.render_widget(p.block(block), area);
        return;
    }
    let width = area.width.saturating_sub(8) as usize;
    let items: Vec<ListItem> = app
        .findings
        .iter()
        .map(|x| {
            let sev = match x.severity.as_str() {
                "crit" => "CRIT",
                "warn" => "WARN",
                _ => "INFO",
            };
            let mut lines = vec![Line::from(vec![
                Span::styled(format!(" {sev} "), severity_style(&x.severity).add_modifier(Modifier::REVERSED)),
                Span::raw(" "),
                Span::styled(x.title.as_str(), Style::default().bold()),
            ])];
            if !x.detail.is_empty() {
                lines.push(Line::from(vec![
                    Span::raw("       "),
                    Span::styled(clip(&x.detail, width.max(10) * 2), dim()),
                ]));
            }
            if let Some(a) = &x.action {
                lines.push(Line::from(vec![
                    Span::raw("       → "),
                    Span::styled(a.as_str(), Style::default().fg(Color::Green)),
                ]));
            }
            ListItem::new(lines)
        })
        .collect();
    let list = List::new(items).block(block).highlight_style(Style::default().bg(SEL_BG)).highlight_symbol("▌");
    let mut state = ListState::default().with_selected(Some(app.doctor_sel));
    f.render_stateful_widget(list, area, &mut state);
}

// ------------------------------------------------------------------- log

/// The action journal, as an overlay over the current view (`a`).
/// The action log screen: everything fat did, newest first, with who asked; details and
/// undo for the selected entry.
fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let rows = app.log_rows();
    let kind = app.log_kind.map(|k| format!("{k:?}").to_lowercase()).unwrap_or_else(|| "all".into());
    let filter = if app.log_filter.is_empty() { String::new() } else { format!(" · \"{}\"", app.log_filter) };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Line::from(vec![
            Span::styled(" Action log ", Style::default().bold()),
            Span::styled(format!("{} of {} · {kind}{filter} ", rows.len(), app.log.len()), dim()),
        ]))
        .title_bottom(Line::styled(
            " ⏎ undo selected · u undo last · f kind · / search · Esc back · TERM/KILL can't be undone ",
            dim(),
        ));
    if app.log.is_empty() {
        let t = Text::from(vec![
            Line::styled("No actions yet.", Style::default().bold()),
            Line::styled(
                "Pause (space), renice (r) or terminate (k) a process: every action lands here, with who asked.",
                dim(),
            ),
            Line::styled(
                "A pause can be undone with u (a renice too, as root); a terminate cannot (pause first to try it out).",
                dim(),
            ),
        ]);
        f.render_widget(Paragraph::new(t).block(block), area);
        return;
    }
    let inner = block.inner(area);
    f.render_widget(block, area);
    let detail_h = if inner.height >= 16 { 7 } else { 0 };
    let [list, detail] = Layout::vertical([Constraint::Min(3), Constraint::Length(detail_h)]).areas(inner);
    let header = Row::new(
        ["TIME", "#", "WHO", "ACTION", "PID", "NAME", "RESULT"]
            .map(|h| Cell::from(Span::styled(h, Style::default().bold()))),
    );
    let body_h = list.height.saturating_sub(1) as usize;
    let mut offset = 0;
    scroll_into_view(app.log_sel, &mut offset, body_h, rows.len());
    let table_rows = rows.iter().enumerate().skip(offset).take(body_h).map(|(i, &ri)| {
        let r = &app.log[ri];
        let (mark, ms) =
            if r.ok { ("✓", Style::default().fg(Color::Green)) } else { ("✗", Style::default().fg(Color::Red)) };
        let mut result = vec![Span::styled(mark, ms), Span::raw(" "), Span::raw(r.message.as_str())];
        if r.undone {
            result.push(Span::styled("  (undone)", dim()));
        } else if r.undoable && r.ok {
            result.push(Span::styled("  undoable", Style::default().fg(ACCENT)));
        }
        let who = if r.origin.is_empty() { "-" } else { r.origin.as_str() };
        let who_style = if r.origin.starts_with("mcp") { Style::default().fg(Color::Magenta) } else { dim() };
        let mut row = Row::new(vec![
            Cell::from(Span::styled(fmt_datetime(r.ts), dim())),
            num(r.id.to_string(), dim()),
            Cell::from(Span::styled(who.to_string(), who_style)),
            Cell::from(format!("{:?}", r.kind).to_lowercase()),
            num(r.pid.to_string(), Style::default()),
            Cell::from(Span::styled(r.name.as_str(), Style::default().bold())),
            Cell::from(Line::from(result)),
        ]);
        if r.undone {
            row = row.style(Style::default().add_modifier(Modifier::DIM));
        }
        if i == app.log_sel {
            row = row.style(Style::default().bg(SEL_BG));
        }
        row
    });
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(14),
            Constraint::Length(4),
            Constraint::Length(12),
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Length(16),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .column_spacing(1);
    f.render_widget(table, list);
    if detail_h == 0 {
        return;
    }
    let Some(r) = rows.get(app.log_sel).map(|&i| &app.log[i]) else {
        f.render_widget(Paragraph::new(Line::styled("nothing matches the filter (Esc clears it)", dim())), detail);
        return;
    };
    let who = match r.origin.as_str() {
        "" => "unknown (recorded before fat kept who asked)".to_string(),
        "tui" => "you, in the TUI".to_string(),
        "cli" => "the command line (fat pause/kill/…)".to_string(),
        o if o.starts_with("mcp") => format!("an agent over MCP: {o}"),
        o => o.to_string(),
    };
    let state = if !r.ok {
        "failed".to_string()
    } else if r.undone {
        "undone".to_string()
    } else if r.undoable {
        format!("can be undone: ⏎ here, or `fat undo {}`", r.id)
    } else {
        "cannot be undone".to_string()
    };
    let pids = if r.pids.len() > 1 {
        format!(
            "{} processes: {}",
            r.pids.len(),
            r.pids.iter().take(12).map(|p| p.to_string()).collect::<Vec<_>>().join(" ")
        )
    } else {
        format!("pid {}", r.pid)
    };
    let nice = match (r.prev_nice, r.new_nice) {
        (Some(a), Some(b)) => format!(" · nice {a} → {b}"),
        _ => String::new(),
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(format!("#{} {:?} ", r.id, r.kind).to_lowercase(), Style::default().bold()),
            Span::styled(format!("{} ({pids}){nice}", r.name), Style::default()),
        ]),
        Line::from(vec![Span::styled("when  ", dim()), Span::raw(fmt_datetime(r.ts))]),
        Line::from(vec![Span::styled("who   ", dim()), Span::raw(who)]),
        Line::from(vec![Span::styled("result ", dim()), Span::raw(r.message.clone())]),
        Line::from(vec![Span::styled("state ", dim()), Span::raw(state)]),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::TOP).border_style(dim())),
        detail,
    );
}

// ------------------------------------------------------------------- overlays

fn draw_why(f: &mut Frame, app: &App, area: Rect) {
    let Some(e) = &app.why else { return };
    let mut t = Text::default();
    t.lines.push(Line::styled(e.headline.as_str(), Style::default().fg(Color::Yellow).bold()));
    if let Some(p) = app.view().and_then(|s| s.proc(e.pid)) {
        let cs: &[Container] = match app.view() {
            Some(s) if !s.containers.is_empty() => &s.containers,
            _ => &app.containers,
        };
        if let Some(id) = &p.container {
            let mut v = vec![Span::styled("container ", dim())];
            match crate::fleet::find_container(cs, id) {
                Some(c) => {
                    v.push(Span::styled(c.name.clone(), Style::default().fg(Color::LightBlue).bold()));
                    v.push(Span::styled(format!(" ({id}) {} · {}", c.image, c.runtime), dim()));
                }
                None => v.push(Span::styled(id.clone(), Style::default().fg(Color::LightBlue))),
            }
            t.lines.push(Line::from(v));
        }
        if !p.cgroup.is_empty() {
            t.lines.push(Line::from(vec![Span::styled("cgroup ", dim()), Span::raw(short_cgroup(&p.cgroup))]));
        }
    }
    if !e.chain.is_empty() {
        t.lines.push(Line::raw(""));
        t.lines.push(Line::styled("Blame chain", Style::default().fg(ACCENT).bold()));
        for (i, step) in e.chain.iter().enumerate() {
            let lead = if i == 0 { "● ".to_string() } else { format!("{}↳ ", indent(i.min(10) as u16 - 1)) };
            t.lines.push(Line::from(vec![Span::styled(lead, dim()), Span::raw(step.as_str())]));
        }
    }
    if !e.evidence.is_empty() {
        t.lines.push(Line::raw(""));
        t.lines.push(Line::styled("Evidence", Style::default().fg(ACCENT).bold()));
        for ev in &e.evidence {
            t.lines.push(Line::from(vec![Span::styled("• ", dim()), Span::raw(ev.as_str())]));
        }
    }
    if !e.suggestions.is_empty() {
        t.lines.push(Line::raw(""));
        t.lines.push(Line::styled("What you can do", Style::default().fg(ACCENT).bold()));
        for s in &e.suggestions {
            t.lines
                .push(Line::from(vec![Span::styled("→ ", Style::default().fg(Color::Green)), Span::raw(s.as_str())]));
        }
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Line::styled(format!(" Why · pid {} ", e.pid), Style::default().bold()))
        .title_bottom(Line::styled(" Esc close · PgUp/PgDn scroll ", dim()));
    f.render_widget(Clear, area);
    f.render_widget(Paragraph::new(t).block(block).wrap(Wrap { trim: false }).scroll((app.why_scroll, 0)), area);
}

/// Container cgroups embed 64-hex ids; show the 12-char form so the path fits one line:
/// "/system.slice/docker-410892b21be2….scope".
fn short_cgroup(cg: &str) -> String {
    let mut out = String::with_capacity(cg.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= 32 {
            out.push_str(&run[..12]);
            out.push('…');
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for ch in cg.chars() {
        if ch.is_ascii_hexdigit() {
            run.push(ch);
        } else {
            flush(&mut run, &mut out);
            out.push(ch);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// The Ask tab: threads on the left; the open thread, rendered as Markdown, on the right;
/// the input line below it.
fn draw_ask_tab(f: &mut Frame, app: &App, area: Rect) {
    let a = &app.ask;
    let narrow = area.width < 90;
    let [list, convo] = if narrow {
        [Rect::default(), area]
    } else {
        Layout::horizontal([Constraint::Length((area.width / 3).clamp(28, 48)), Constraint::Min(30)]).areas(area)
    };
    if !narrow {
        let mut items: Vec<ListItem> = Vec::new();
        if let Some(e) = &a.error {
            items.push(ListItem::new(Line::styled(e.clone(), Style::default().fg(Color::Red))));
        }
        if a.threads.is_empty() && a.error.is_none() {
            items.push(ListItem::new(Line::styled("no threads yet: ? or Enter to ask", dim())));
        }
        let w = list.width.saturating_sub(4) as usize;
        for (i, t) in a.threads.iter().enumerate() {
            let selected = i == a.sel;
            let open = a.open == Some(t.id);
            let title_style = if open { Style::default().fg(ACCENT).bold() } else { Style::default() };
            let age = fmt_ago((app.now - t.updated) / 1000);
            let turns = if t.turns == 1 { "1 turn".to_string() } else { format!("{} turns", t.turns) };
            let mut lines = vec![Line::styled(clip(&t.title, w).to_string(), title_style)];
            lines.push(Line::styled(format!("{age} · {turns}"), dim()));
            let item = ListItem::new(lines);
            items.push(if selected { item.style(Style::default().bg(Color::DarkGray)) } else { item });
        }
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Threads ")
            .title_bottom(Line::styled(" ↑↓ open · n new · d delete ", dim()));
        f.render_widget(List::new(items).block(block), list);
    }

    let [body, input] = Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).areas(convo);
    let title = a
        .open
        .and_then(|id| a.threads.iter().find(|t| t.id == id))
        .map(|t| format!(" {} ", clip(&t.title, body.width.saturating_sub(6) as usize)))
        .unwrap_or_else(|| " New thread ".to_string());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if a.typing { Color::DarkGray } else { ACCENT }))
        .title(Line::styled(title, Style::default().bold()))
        .title(
            Line::styled(
                format!(" {} ", clip(&app.ask_dest, (body.width as usize).saturating_sub(30))),
                if app.ask_ready { dim() } else { Style::default().fg(Color::Yellow) },
            )
            .right_aligned(),
        );
    let inner_w = body.width.saturating_sub(2);
    let mut lines: Vec<Line> = Vec::new();
    let you = |ts: crate::model::Ts| {
        let when = chrono::DateTime::from_timestamp_millis(ts)
            .map(|d| d.with_timezone(&chrono::Local).format("%b %d %H:%M").to_string())
            .unwrap_or_default();
        Line::from(vec![Span::styled("▍You ", Style::default().fg(ACCENT).bold()), Span::styled(when, dim())])
    };
    for t in &a.turns {
        lines.push(you(t.ts));
        lines.extend(super::markdown::render(&t.question, inner_w));
        lines.push(Line::raw(""));
        lines.extend(super::markdown::render(&t.answer, inner_w));
        lines.push(Line::styled(format!("via {}", t.via), dim()));
        lines.push(Line::raw(""));
    }
    if let Some(p) = &a.pending {
        lines.push(you(p.since));
        lines.extend(super::markdown::render(&p.question, inner_w));
        lines.push(Line::raw(""));
        let spin = SPINNER[((app.now - p.since).max(0) / 100) as usize % SPINNER.len()];
        lines.push(Line::styled(format!("{spin} thinking…  (Esc to stop waiting)"), Style::default().fg(ACCENT)));
        if !app.ask_dest.is_empty() {
            lines.push(Line::styled(format!("→ {}", app.ask_dest), dim()));
        }
    }
    if lines.is_empty() && !app.ask_ready && !app.ask_dest.is_empty() {
        lines.extend(super::markdown::render(
            &format!("**No model is set up yet.**\n\n{}\n\nNow: {}", crate::ask::SETUP_HELP, app.ask_dest),
            inner_w,
        ));
    }
    if lines.is_empty() {
        lines.push(Line::styled("Ask about this machine in plain language, for example:", dim()));
        for ex in ["why is this machine slow?", "what writes all the time under /var?", "what is using port 3000?"] {
            lines.push(Line::styled(format!("  · {ex}"), dim()));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "Follow-ups stay in this thread; earlier threads on this host are remembered ([ask] memory).",
            dim(),
        ));
    }
    let visible = body.height.saturating_sub(2);
    let max_top = (lines.len() as u16).saturating_sub(visible);
    let top = max_top.saturating_sub(a.scroll_up.min(max_top));
    f.render_widget(Paragraph::new(lines).scroll((top, 0)).block(block), body);

    let prompt_style = Style::default().fg(ACCENT).bold();
    let line = if a.typing {
        let w = input.width.saturating_sub(6) as usize;
        let shown: String = {
            let n = a.input.chars().count();
            a.input.chars().skip(n.saturating_sub(w)).collect()
        };
        Line::from(vec![Span::styled("› ", prompt_style), Span::raw(shown), Span::styled("▏", prompt_style)])
    } else if a.pending.is_some() {
        Line::styled("waiting for the answer…", dim())
    } else {
        let what = if a.open.is_some() { "follow up in this thread" } else { "ask" };
        Line::styled(format!("Enter or i to {what} · ? new thread from anywhere"), dim())
    };
    let hint = if a.typing { " Enter send · Esc done " } else { "" };
    f.render_widget(
        Paragraph::new(line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if a.typing { ACCENT } else { Color::DarkGray }))
                .title_bottom(Line::styled(hint, dim())),
        ),
        input,
    );
}

/// The Settings screen: groups on the left, the selected group's settings on the right.
fn draw_settings(f: &mut Frame, app: &App, area: Rect) {
    use crate::settings::{GROUPS, Kind, Source};
    use crate::tui::app::SRow;
    let ui = &app.settings;
    let rows = ui.rows();
    let cur_group = ui.selected().map(|r| ui.group_of(r)).unwrap_or(GROUPS[0]);
    let [side, main] = Layout::horizontal([Constraint::Length(18), Constraint::Min(30)]).areas(area);
    // Sidebar.
    let items: Vec<ListItem> = GROUPS
        .iter()
        .map(|g| {
            let count = if *g == "Hosts" { ui.hosts.len() } else { ui.fields.iter().filter(|f| f.group == *g).count() };
            let st =
                if *g == cur_group { Style::default().fg(Color::Black).bg(ACCENT).bold() } else { Style::default() };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {g:<10}"), st),
                Span::styled(format!(" {count}"), dim()),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(items).block(
            Block::default().borders(Borders::ALL).title(" Settings ").title_bottom(Line::styled(" ←→ ", dim())),
        ),
        side,
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Line::styled(format!(" {cur_group} "), Style::default().bold()))
        .title(
            Line::styled(format!(" {} ", clip(&ui.path, (main.width as usize).saturating_sub(20))), dim())
                .right_aligned(),
        )
        .title_bottom(Line::styled(
            if ui.editing.is_some() {
                " ⏎ save · Esc cancel · Ctrl-U clear "
            } else if ui.picker.is_some() {
                " ↑↓ choose · ⏎ use this model · Esc back "
            } else if ui.multi.is_some() {
                " ↑↓ move · space toggle · ⏎ save · Esc back "
            } else if ui.host_form.as_ref().is_some_and(|h| h.editing) {
                " type · Tab next field · ⏎/Esc done "
            } else if ui.host_form.is_some() {
                " ↑↓ field · ⏎ edit · s save · t test ssh · Esc back "
            } else if cur_group == "Hosts" {
                " ⏎ edit / add · d remove · t test ssh · ←→ groups · Esc back "
            } else {
                " ↑↓ move · ⏎ change · r reset · t test model · m pick model · ←→ groups · Esc back "
            },
            dim(),
        ));
    let inner = block.inner(main);
    f.render_widget(block, main);
    let [list, foot] = Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).areas(inner);

    let mut lines: Vec<Line> = Vec::new();
    let mut sel_line = 0usize;
    if let Some(form) = &ui.host_form {
        let title = if form.index.is_some() { "Edit host" } else { "Add a host" };
        lines.push(Line::styled(title, Style::default().fg(ACCENT).bold()));
        lines.push(Line::raw(""));
        for (i, label) in crate::tui::app::HostForm::LABELS.iter().enumerate() {
            let selected = i == form.sel;
            let mut v = form.values[i].clone();
            if selected && form.editing {
                v.push('▏');
            }
            let mut line = Line::from(vec![
                Span::raw(format!("  {label:<18}")),
                Span::styled(if v.is_empty() { "—".to_string() } else { v }, Style::default().bold()),
            ]);
            if selected {
                line = line.style(Style::default().bg(SEL_BG));
                sel_line = lines.len();
            }
            lines.push(line);
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(format!("  {}", crate::tui::app::HostForm::HELP[form.sel]), dim()));
    } else {
        let label_w = 28usize;
        let src_w = 20usize;
        let val_w = (list.width as usize).saturating_sub(label_w + src_w + 3).max(8);
        if cur_group == "Ask" {
            // Always-visible status: ready or not, and why.
            let cfg = ask_cfg_of(ui);
            let ready = cfg.enabled && crate::llm::resolve(&cfg).is_ok_and(|e| e.usable());
            let (mark, st) = if ready {
                ("● Ready", Style::default().fg(Color::Green).bold())
            } else if !cfg.enabled {
                ("○ Off", dim())
            } else {
                ("○ Not ready", Style::default().fg(Color::Yellow).bold())
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {mark}  "), st),
                Span::raw(crate::llm::destination(&cfg)),
            ]));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                if ui.ask_detecting { "  Connect ask to:   (looking at this machine…)" } else { "  Connect ask to:" },
                Style::default().bold(),
            ));
        }
        if cur_group == "Hosts" && ui.hosts.is_empty() {
            lines.push(Line::styled(
                "  No hosts yet: add one to see it in Fleet (ssh with your own ssh config).",
                dim(),
            ));
            lines.push(Line::raw(""));
        }
        let mut last_sub = "";
        let current_opt = ui.current_ask_option();
        for (ri, r) in rows.iter().enumerate() {
            if ui.group_of(*r) != cur_group {
                continue;
            }
            // Ask: a heading before details and privacy.
            if let SRow::Field(i) = *r
                && ui.fields[i].section == "ask"
                && ui.fields[i].sub != last_sub
            {
                last_sub = ui.fields[i].sub;
                let head = match last_sub {
                    "details" => "Details",
                    "privacy" => "Privacy",
                    _ => "",
                };
                if !head.is_empty() {
                    lines.push(Line::raw(""));
                    lines.push(Line::styled(format!("  {head}"), Style::default().bold()));
                }
            }
            if *r == SRow::AskAdvanced {
                lines.push(Line::raw(""));
            }
            let selected = ri == ui.sel;
            if selected {
                sel_line = lines.len();
            }
            let mut line = match *r {
                SRow::Host(i) => {
                    let h = &ui.hosts[i];
                    let mut parts = vec![format!("ssh {}", h.ssh.as_deref().unwrap_or(&h.name))];
                    if let Some(p) = &h.fat_path {
                        parts.push(format!("fat {p}"));
                    }
                    if !h.groups.is_empty() {
                        parts.push(format!("groups {}", h.groups.join(",")));
                    }
                    if !h.tags.is_empty() {
                        parts.push(format!("tags {}", h.tags.join(",")));
                    }
                    Line::from(vec![
                        Span::styled(
                            format!("  {:<width$}", clip(&h.name, label_w - 2), width = label_w - 2),
                            Style::default().bold(),
                        ),
                        Span::styled(format!(" {}", parts.join(" · ")), dim()),
                    ])
                }
                SRow::AddHost => Line::styled("  + add a host", Style::default().fg(ACCENT)),
                SRow::AskOption(i) => {
                    let o = &ui.ask_options[i];
                    let on = current_opt == Some(i);
                    let st = if o.ready { Style::default().fg(Color::Green) } else { dim() };
                    Line::from(vec![
                        Span::styled(if on { "  ● " } else { "  ○ " }, Style::default().fg(ACCENT).bold()),
                        Span::styled(
                            format!("{:<width$}", clip(&o.label, label_w - 4), width = label_w - 4),
                            if on { Style::default().bold() } else { Style::default() },
                        ),
                        Span::styled(
                            format!(" {}", clip(&o.status, (list.width as usize).saturating_sub(label_w + 2))),
                            st,
                        ),
                    ])
                }
                SRow::AskAdvanced => Line::styled(
                    if ui.ask_advanced { "  ▾ Advanced" } else { "  ▸ Advanced (digest size, context, timeout)" },
                    Style::default().bold(),
                ),
                SRow::Field(i) => {
                    let fd = &ui.fields[i];
                    let value = match (&ui.editing, selected) {
                        (Some(input), true) => format!("{input}▏"),
                        _ => match (&fd.kind, fd.value.as_str()) {
                            (Kind::Bool, "true") => "on".to_string(),
                            (Kind::Bool, _) => "off".to_string(),
                            (Kind::Multi(_), "") => "nothing (read-only)".to_string(),
                            (Kind::Text | Kind::List | Kind::Map, "") => "—".to_string(),
                            (Kind::Number(..), "0")
                                if matches!(fd.key.as_str(), "context_bytes" | "num_ctx" | "timeout_s") =>
                            {
                                "auto".to_string()
                            }
                            (_, v) => v.to_string(),
                        },
                    };
                    let src = match &fd.source {
                        Source::Default => "default".to_string(),
                        Source::File => "config file".to_string(),
                        Source::Env(v) => format!("env {v}"),
                    };
                    let val_style = if !fd.editable() {
                        dim()
                    } else if ui.editing.is_some() && selected {
                        Style::default().fg(Color::Yellow)
                    } else if fd.sensitive() && !fd.value.is_empty() {
                        Style::default().fg(Color::Magenta).bold()
                    } else {
                        Style::default().bold()
                    };
                    Line::from(vec![
                        Span::raw(format!("  {:<width$}", clip(&fd.label, label_w - 2), width = label_w - 2)),
                        Span::styled(format!(" {:<width$}", clip_end(&value, val_w), width = val_w), val_style),
                        Span::styled(format!(" {:>width$}", clip(&src, src_w), width = src_w), dim()),
                    ])
                }
            };
            if selected {
                line = line.style(Style::default().bg(SEL_BG));
            }
            lines.push(line);
        }
    }
    let visible = list.height as usize;
    let top = sel_line.saturating_sub(visible.saturating_sub(3)).min(lines.len().saturating_sub(visible));
    f.render_widget(Paragraph::new(lines).scroll((top as u16, 0)), list);

    let mut foot_lines = Vec::new();
    match ui.selected() {
        Some(SRow::AskOption(i)) if ui.host_form.is_none() => {
            let o = &ui.ask_options[i];
            let how = match o.key.as_str() {
                "off" => "⏎ turn ask off (nothing is ever sent)".to_string(),
                "claude-code" | "codex" | "cursor" => {
                    format!(
                        "⏎ use {}: questions go through its own sign-in, to its vendor's cloud; t tests it",
                        o.label
                    )
                }
                "command" => "⏎ use a program you name (it gets the question on stdin); then type the command".into(),
                _ if o.url.is_some() => format!(
                    "⏎ use the server at {}; then pick a model (m) and test (t)",
                    o.url.as_deref().unwrap_or("")
                ),
                _ => "⏎ use this; then fill in the details below and test (t)".into(),
            };
            foot_lines.push(Line::styled(how, dim()));
        }
        Some(SRow::AskAdvanced) => foot_lines.push(Line::styled("⏎ show or hide the advanced settings", dim())),
        _ => {}
    }
    if let Some(fd) = ui.field().filter(|_| ui.host_form.is_none()) {
        let when = if fd.live { "" } else { " (applies the next time fat starts)" };
        let help = if fd.help.is_empty() {
            format!("[{}] {}{when}", if fd.section.is_empty() { "top level" } else { &fd.section }, fd.key)
        } else {
            format!("{}{when}", fd.help)
        };
        foot_lines.push(Line::styled(help, dim()));
    }
    if let Some(b) = &ui.busy {
        let spin = SPINNER[(app.now / 100) as usize % SPINNER.len()];
        foot_lines.push(Line::styled(format!("{spin} {b}"), Style::default().fg(ACCENT)));
    } else if let Some((text, err)) = &ui.note {
        let st = if *err { Style::default().fg(Color::Red) } else { Style::default().fg(Color::Green) };
        foot_lines.push(Line::styled(text.clone(), st));
    }
    f.render_widget(Paragraph::new(foot_lines).wrap(Wrap { trim: true }), foot);

    let popup = |f: &mut Frame, title: &str, items: Vec<ListItem>, sel: usize| {
        let ph = (items.len() as u16 + 2).min(main.height.saturating_sub(4)).max(3);
        let pr = centered(46.min(main.width.saturating_sub(4)), ph, main);
        f.render_widget(Clear, pr);
        let mut state = ratatui::widgets::ListState::default();
        state.select(Some(sel));
        f.render_stateful_widget(
            List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(ACCENT))
                        .title(format!(" {title} ")),
                )
                .highlight_style(Style::default().bg(SEL_BG).bold()),
            pr,
            &mut state,
        );
    };
    if let Some((models, i)) = &ui.picker {
        popup(f, "Models", models.iter().map(|m| ListItem::new(m.clone())).collect(), *i);
    }
    if let Some((items, i)) = &ui.multi {
        let rows =
            items.iter().map(|(name, on)| ListItem::new(format!("[{}] {name}", if *on { "x" } else { " " }))).collect();
        popup(f, "Agents may", rows, *i);
    }
}

/// The ask settings the overlay currently shows (for the "now:" line).
fn ask_cfg_of(ui: &crate::tui::app::SettingsUi) -> crate::config::AskCfg {
    let mut a = crate::config::AskCfg::default();
    for fd in &ui.fields {
        if fd.section != "ask" {
            continue;
        }
        let v = fd.value.clone();
        match fd.key.as_str() {
            "enabled" => a.enabled = v == "true",
            "provider" => a.provider = v,
            "url" => a.url = v,
            "model" => a.model = v,
            "key_env" => a.key_env = v,
            "command" => a.command = v,
            "local_only" => a.local_only = v == "true",
            "detail" => a.detail = v,
            _ => {}
        }
    }
    a
}

/// `s` shortened to `n` columns, keeping its end (where a URL or model name differs).
fn clip_end(s: &str, n: usize) -> String {
    let c = s.chars().count();
    if c <= n { s.to_string() } else { format!("…{}", s.chars().skip(c - n + 1).collect::<String>()) }
}

fn draw_modal(f: &mut Frame, app: &App, area: Rect) {
    match &app.modal {
        Modal::None | Modal::Filter => {}
        Modal::Help => draw_help(f, area),
        Modal::PortFilter(form) => draw_port_filter(f, app, form, area),

        Modal::Confirm { prompt, .. } => {
            let r = centered(64.min(area.width.saturating_sub(2)), 6, area);
            let t = Text::from(vec![
                Line::styled(prompt.as_str(), Style::default().bold()),
                Line::raw(""),
                Line::from(vec![
                    Span::styled(" y ", Style::default().fg(Color::Black).bg(Color::Red).bold()),
                    Span::raw(" yes    "),
                    Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::Gray).bold()),
                    Span::raw(" no / Esc"),
                ]),
            ]);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(t).wrap(Wrap { trim: true }).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Red))
                        .title(" Confirm "),
                ),
                r,
            );
        }
        Modal::Renice { pid, name, input, .. } => {
            let r = centered(60.min(area.width.saturating_sub(2)), 6, area);
            let t = Text::from(vec![
                Line::from(vec![
                    Span::raw("New nice value for "),
                    Span::styled(format!("{pid} ({name})"), Style::default().bold()),
                ]),
                Line::from(vec![
                    Span::raw("> "),
                    Span::styled(input.as_str(), Style::default().fg(Color::Yellow).bold()),
                    Span::styled("▏", Style::default().fg(ACCENT)),
                ]),
                Line::styled("-20 highest … 20 lowest priority · Enter apply · Esc cancel · undo with u", dim()),
            ]);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(t).wrap(Wrap { trim: true }).block(
                    Block::default().borders(Borders::ALL).border_style(Style::default().fg(ACCENT)).title(" Renice "),
                ),
                r,
            );
        }
    }
}

const HELP: &[(&str, &str)] = &[
    (
        "1-8 / Tab",
        "switch view: Procs Ports Fs Timeline Doctor (Fleet when containers/hosts exist); the server profile adds Services first and Events",
    ),
    ("↑↓ PgUp PgDn g G", "move selection"),
    ("c m p n d i N", "sort by cpu mem power net disk pid name (again = reverse)"),
    ("t", "toggle process tree"),
    ("/", "filter by name, command, container or cgroup (Esc clears)"),
    ("Enter / w", "why: blame chain for the selection"),
    ("space / z", "pause / resume (SIGSTOP/SIGCONT; undo resumes)"),
    ("r", "renice (default 10; undo restores it, lowering needs root)"),
    ("k / K", "terminate / whole tree (confirm; NOT undoable: pause first)"),
    ("u", "undo the last pause or renice"),
    ("a", "action log screen: everything fat did and who asked; ⏎ undo · f kind · / search · Esc back"),
    ("← → [ ] { }", "timeline: move through time (shift / braces = ×10)"),
    ("s  +/-", "timeline: jump to next spike · zoom window"),
    ("Fs: ⏎ → l  ← ⌫", "storage: open directory · go up (⏎ on a 🔒 dir reads it once)"),
    ("Fs: s g w", "sort size/growth/io/name/files/age · growth view · window 10m/1h/24h"),
    ("Fs: b r", "biggest entries below here · rescan this directory (fat never deletes)"),
    (
        "Services: ⏎ w W",
        "explain the unit (state, limits, processes, events, read-only next steps) · why its main pid · what happened recently",
    ),
    ("Services: sort", "s state (problems first) · c cpu · m mem · d io · r restarts · N name"),
    ("Services: t f i", "group by kind · problems only · show inactive units"),
    (
        "Events: ⏎ W f +/-",
        "what happened around the event (chain, culprits, evidence) · … recently · min severity · window 15m-7d",
    ),
    ("Fleet: ⏎ → r", "drill into a host (read-only snapshot: doctor, units, procs) · fleet findings panel · poll now"),
    (
        "Fleet: sort",
        "H health · c cpu · m mem · d disk · f findings · n name · l latency (nothing in Fleet acts on a host)",
    ),
    ("L / Esc", "return to live"),
    ("Ports: ←→ f", "view by state (All, Listen, Established, Time-wait, Close-wait, Other, Orphans) · filter dialog"),
    ("?", "ask in plain language: a new thread in the Ask tab"),
    (",", "settings screen: every setting by group (←→), with its source; Esc back"),
    ("!", "a shell while fat keeps running; exit returns. $FAT_PID, $FAT_PORT, $FAT_PEER, $FAT_PATH: the selection"),
    ("Ask: ⏎ n ↑↓ d", "follow up in this thread · new thread · open another · delete (Esc leaves the input)"),
    ("h", "this help"),
    ("q / Ctrl-C", "quit"),
];

/// Width of the help's key column (right-aligned key + two spaces).
const HELP_KEY_W: usize = 20;

/// The help text for an inner width of `inner` columns: descriptions wrap at word boundaries
/// onto continuation lines under the description column, so nothing is cut off.
fn help_lines(inner: usize) -> Vec<Line<'static>> {
    let desc_w = inner.saturating_sub(HELP_KEY_W).max(16);
    let mut out = Vec::new();
    for (k, d) in HELP {
        let mut rows: Vec<String> = vec![String::new()];
        for w in d.split(' ') {
            let cur = rows.last_mut().expect("non-empty");
            if !cur.is_empty() && cur.chars().count() + 1 + w.chars().count() > desc_w {
                rows.push(w.to_string());
            } else {
                if !cur.is_empty() {
                    cur.push(' ');
                }
                cur.push_str(w);
            }
        }
        for (i, row) in rows.into_iter().enumerate() {
            let key = if i == 0 { format!("{k:>18}  ") } else { " ".repeat(HELP_KEY_W) };
            out.push(Line::from(vec![Span::styled(key, Style::default().fg(Color::Yellow).bold()), Span::raw(row)]));
        }
    }
    out
}

fn draw_help(f: &mut Frame, area: Rect) {
    let width = 100.min(area.width.saturating_sub(2));
    let lines = help_lines(width.saturating_sub(2) as usize);
    let r = centered(width, (lines.len() as u16 + 2).min(area.height), area);
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(Line::styled(" fat — keys ", Style::default().bold()))
                .title_bottom(Line::styled(" any key closes ", dim())),
        ),
        r,
    );
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    if app.modal == Modal::Filter {
        let line = Line::from(vec![
            Span::styled(" / ", Style::default().fg(Color::Black).bg(Color::Yellow).bold()),
            Span::raw(" "),
            Span::raw(app.active_filter()),
            Span::styled("▏", Style::default().fg(ACCENT)),
            Span::styled("   Enter keep · Esc clear", dim()),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }
    if let Some(s) = &app.status {
        let style = if s.error { Style::default().fg(Color::Red).bold() } else { Style::default().fg(Color::Green) };
        f.render_widget(Paragraph::new(Line::styled(format!(" {}", s.text), style)), area);
        return;
    }
    let hints: &[(&str, &str)] = match app.tab {
        Tab::Procs => &[
            ("⏎", "why"),
            ("␣", "pause"),
            ("r", "renice"),
            ("k", "term"),
            ("K", "tree"),
            ("u", "undo"),
            ("a", "log"),
            ("/", "filter"),
            ("t", "tree"),
            ("cmpnd", "sort"),
            ("?", "ask"),
            ("h", "help"),
            ("q", "quit"),
        ],
        Tab::Ports => &[
            ("⏎", "why"),
            ("k", "kill tree"),
            ("␣", "pause"),
            ("u", "undo"),
            ("a", "log"),
            ("?", "ask"),
            ("h", "help"),
            ("q", "quit"),
        ],
        Tab::Fs if app.fs.mode == FsMode::Growth => &[
            ("⏎", "open / why"),
            ("w", "window"),
            ("g", "dirs"),
            ("/", "filter"),
            ("Esc", "back"),
            ("?", "ask"),
            ("h", "help"),
            ("q", "quit"),
        ],
        Tab::Fs => &[
            ("⏎", "open"),
            ("←", "up"),
            ("s", "sort"),
            ("g", "growth"),
            ("w", "window"),
            ("b", "biggest"),
            ("r", "rescan"),
            ("/", "filter"),
            ("?", "ask"),
            ("h", "help"),
            ("q", "quit"),
        ],
        Tab::Fleet if app.fleet.drill.is_some() => &[
            ("←→", "doctor/units/procs"),
            ("↑↓", "move"),
            ("r", "refresh"),
            ("Esc", "back"),
            ("h", "help"),
            ("q", "quit"),
        ],
        Tab::Fleet if app.fleet.focus_findings => {
            &[("↑↓", "move"), ("⏎", "show hosts"), ("←", "hosts"), ("r", "poll"), ("Esc", "back"), ("h", "help")]
        }
        Tab::Fleet if app.fleet.active() => &[
            ("⏎", "drill in"),
            ("→", "findings"),
            ("H c m d f n l", "sort"),
            ("/", "filter"),
            ("r", "poll"),
            ("?", "ask"),
            ("h", "help"),
            ("q", "quit"),
        ],
        Tab::Fleet => &[("↑↓", "move"), ("?", "ask"), ("h", "help"), ("q", "quit")],
        Tab::Services => &[
            ("⏎", "explain"),
            ("w", "why pid"),
            ("W", "what happened"),
            ("s c m d r N", "sort"),
            ("t", "by kind"),
            ("f", "problems"),
            ("i", "inactive"),
            ("/", "filter"),
            ("h", "help"),
            ("q", "quit"),
        ],
        Tab::Events => &[
            ("⏎", "what happened"),
            ("W", "now"),
            ("f", "severity"),
            ("+/-", "window"),
            ("/", "filter"),
            ("r", "refresh"),
            ("h", "help"),
            ("q", "quit"),
        ],
        Tab::Timeline => &[
            ("←→", "scrub"),
            ("s", "spike"),
            ("+/-", "zoom"),
            ("L", "live"),
            ("⏎", "why"),
            ("?", "ask"),
            ("h", "help"),
            ("q", "quit"),
        ],
        Tab::Doctor => &[("⏎", "run action"), ("w", "why"), ("a", "log"), ("?", "ask"), ("h", "help"), ("q", "quit")],
        Tab::Ask => &[
            ("⏎", "ask / follow up"),
            ("n", "new"),
            ("↑↓", "threads"),
            ("d", "delete"),
            ("PgUp", "scroll"),
            ("q", "quit"),
        ],
        Tab::Log => &[("⏎", "undo selected"), ("u", "undo last"), ("f", "kind"), ("/", "search"), ("Esc", "back")],
        Tab::Settings => &[("⏎", "change"), ("←→", "groups"), ("r", "reset"), ("t", "test"), ("Esc", "back")],
    };
    let hints: &[(&str, &str)] =
        if app.panel.is_some() { &[("↑↓", "scroll"), ("w", "why pid"), ("Esc", "close")] } else { hints };
    let mut spans = Vec::with_capacity(hints.len() * 3);
    if app.rewound() && app.tab != Tab::Timeline {
        spans.push(Span::styled(" ⏪ L live ", Style::default().fg(Color::White).bg(Color::Magenta).bold()));
    }
    for (k, d) in hints {
        spans.push(Span::styled(format!(" {k} "), Style::default().fg(Color::Black).bg(Color::Gray)));
        spans.push(Span::styled(format!(" {d} "), dim()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

pub(super) fn centered(w: u16, h: u16, area: Rect) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ActionKind, ActionRecord, Container, Explanation, Finding};
    use crate::tui::app::Modal;
    use crate::tui::app::tests::{linux_snap, proc, snap};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut s = String::new();
        for y in 0..h {
            for x in 0..w {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn header_shows_a_newer_release_when_it_fits() {
        let mut a = full_app();
        a.update_note = Some("⬆ fat 0.2.0 · fat update".into());
        let wide = render(&mut a, 160, 40);
        assert!(wide.lines().next().unwrap().contains("⬆ fat 0.2.0 · fat update"), "{wide}");
        assert!(wide.lines().next().unwrap().contains("LIVE"));
        let narrow = render(&mut a, 60, 40);
        assert!(!narrow.contains("fat 0.2.0"), "dropped before the live badge: {narrow}");
        assert!(narrow.lines().next().unwrap().contains("LIVE"));
    }

    fn full_app() -> App {
        let mut a = App::new(1000);
        for i in 0..30 {
            let mut s = snap(1_000_000 + i * 1000);
            s.system.cpu = (i * 3) as f32;
            a.now = s.ts;
            a.on_snapshot(s);
        }
        a.history_ok = true;
        a.config_path = "/Users/me/.config/fat/config.toml".into();
        a.set_findings(vec![
            Finding {
                severity: "crit".into(),
                title: "node is pegging a core".into(),
                detail: "88% for 10m".into(),
                pids: vec![200],
                action: Some("pause 200".into()),
            },
            Finding {
                severity: "warn".into(),
                title: "memory pressure".into(),
                detail: "swap in use".into(),
                pids: vec![],
                action: None,
            },
        ]);
        a.set_log(vec![ActionRecord {
            id: 3,
            ts: 1_000_000,
            kind: ActionKind::Pause,
            pid: 200,
            name: "node".into(),
            prev_nice: None,
            new_nice: None,
            pids: vec![200],
            undoable: true,
            undone: false,
            ok: true,
            message: "stopped".into(),
            origin: "tui".into(),
        }]);
        a
    }

    const SIZES: [(u16, u16); 3] = [(80, 24), (160, 48), (40, 10)];

    #[test]
    fn procs_tab_renders() {
        for (w, h) in SIZES {
            let mut a = full_app();
            let out = render(&mut a, w, h);
            assert!(out.contains("fat"), "{w}x{h}\n{out}");
            if h >= 24 {
                assert!(out.contains("testbox"));
                assert!(out.contains("PID"));
                assert!(out.contains("CPU%"));
                assert!(out.contains("node"));
                assert!(out.contains("MEM"));
                assert!(out.contains("LIVE"));
                assert!(out.contains("[paused]"), "paused proc highlighted\n{out}");
            }
        }
        let mut a = full_app();
        let out = render(&mut a, 160, 48);
        assert!(out.contains("POWER") && out.contains("NET") && out.contains("DISK") && out.contains("USER"));
        assert!(out.contains("GPU") && out.contains("PWR") && out.contains("THERM") && out.contains("BAT 85%"));
    }

    #[test]
    fn ports_tab_renders_orphans() {
        for (w, h) in SIZES {
            let mut a = full_app();
            a.switch_tab(Tab::Ports);
            a.mark_dirty();
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("3000"), "{out}");
                assert!(out.contains("orphan"));
                assert!(out.contains("5432"));
            }
        }
    }

    #[test]
    fn fleet_tab_empty_state_and_rows() {
        let mut a = full_app();
        a.set_fleet(Some(vec![]));
        // Nothing beyond this machine: no Fleet tab at all.
        assert!(!a.fleet_visible());
        a.switch_tab(Tab::Fleet);
        assert_eq!(a.tab, Tab::Procs);
        let out = render(&mut a, 80, 24);
        assert!(!out.contains("7Fleet") && out.contains("5Doctor"), "{out}");
        // A configured host makes it appear (with its empty-state hint until data arrives).
        a.configured_hosts = 1;
        a.switch_tab(Tab::Fleet);
        assert_eq!(a.tab, Tab::Fleet);
        let out = render(&mut a, 80, 24);
        assert!(out.contains("7Fleet"), "{out}");
        assert!(out.contains("contacting 1 remote host"), "{out}");
        a.configured_hosts = 0;
        a.set_fleet(Some(vec![Container {
            id: "abc".into(),
            name: "pg".into(),
            image: "postgres:16".into(),
            runtime: "docker".into(),
            status: "Up 3 hours".into(),
            cpu: 1.5,
            mem: 200 << 20,
            ports: "5432".into(),
        }]));
        for (w, h) in SIZES {
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("pg") && out.contains("postgres:16"), "{out}");
            }
        }
        // Remote hosts in the inventory: the fleet health table (both profiles).
        a.set_fleet_inventory(Ok(2));
        a.fleet_host(crate::server::FleetHost {
            name: "devbox".into(),
            ok: true,
            health: 90,
            cpu: 12.0,
            ..Default::default()
        });
        a.fleet_host(crate::server::FleetHost {
            name: "dead".into(),
            ok: false,
            error: Some("ssh: timeout".into()),
            ..Default::default()
        });
        for (w, h) in SIZES {
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("devbox") && out.contains("✗ down") && out.contains("2 hosts"), "{w}x{h}\n{out}");
            }
            if w >= 76 && h >= 24 {
                assert!(out.contains("timeout"), "{w}x{h}\n{out}");
            }
        }
    }

    #[test]
    fn timeline_tab_renders_live_and_rewound() {
        for (w, h) in SIZES {
            let mut a = full_app();
            a.switch_tab(Tab::Timeline);
            a.use_ring_timeline();
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("Timeline"), "{out}");
                assert!(out.contains("live"));
            }
            a.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
            a.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
            let out = render(&mut a, w, h);
            assert!(out.contains("REWIND"), "rewind badge shown everywhere {w}x{h}\n{out}");
            // still shown on another tab
            a.switch_tab(Tab::Procs);
            let out = render(&mut a, w, h);
            assert!(out.contains("REWIND"));
        }
        let mut a = full_app();
        a.switch_tab(Tab::Timeline);
        let out = render(&mut a, 80, 24);
        assert!(out.contains("Collecting"), "empty timeline message\n{out}");
    }

    #[test]
    fn doctor_and_log_tabs_render() {
        for (w, h) in SIZES {
            let mut a = full_app();
            a.switch_tab(Tab::Doctor);
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("CRIT") && out.contains("pegging") && out.contains("pause 200"), "{out}");
            }
            a.on_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
            assert_eq!(a.tab, Tab::Log);
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("Action log") && out.contains("pause"), "{out}");
                assert!(out.contains("undoable") || out.contains("can be undone"), "{out}");
                assert!(out.contains("WHO") && out.contains("tui"), "{out}");
            }
            a.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
            assert_eq!(a.tab, Tab::Doctor);
        }
        let mut a = App::new(1000);
        a.switch_tab(Tab::Doctor);
        assert!(render(&mut a, 80, 24).contains("diagnosing"));
        a.set_findings(vec![]);
        assert!(render(&mut a, 80, 24).contains("All good"));
        a.switch_tab(Tab::Log);
        let out = render(&mut a, 80, 24);
        assert!(out.contains("No actions yet") && out.contains("cannot"), "{out}");
    }

    #[test]
    fn overlays_render() {
        for (w, h) in SIZES {
            let mut a = full_app();
            a.set_why(Explanation {
                pid: 200,
                headline: "node is a vite dev server".into(),
                chain: vec!["node (200)".into(), "zsh (100)".into(), "launchd".into()],
                evidence: vec!["88% cpu".into()],
                suggestions: vec!["pause it".into()],
            });
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("Why") && out.contains("vite"), "{w}x{h}\n{out}");
            }
            a.why = None;
            a.modal = Modal::Help;
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("keys"), "{out}");
            }
            a.modal = Modal::Confirm { prompt: "Send TERM to 200 (node)?".into(), cmd: crate::tui::app::Command::Quit };
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("Confirm") && out.contains("TERM"));
            }
            a.modal = Modal::Renice { pid: 200, name: "node".into(), input: "10".into(), start: 0 };
            render(&mut a, w, h);
            a.modal = Modal::Filter;
            a.set_filter("nod".into());
            let out = render(&mut a, w, h);
            assert!(out.contains("nod"));
            a.modal = Modal::None;
            // The Ask tab: a pending question, then answers rendered as Markdown.
            a.tab = Tab::Ask;
            a.ask.pending =
                Some(crate::tui::app::Pending { id: 1, question: "why slow".into(), since: a.now, thread: None });
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("thinking") && out.contains("why slow"), "{out}");
            }
            a.ask.pending = None;
            a.ask.open = Some(1);
            a.ask.threads =
                vec![crate::threads::Thread { id: 1, title: "disk".into(), turns: 1, ..Default::default() }];
            a.ask.turns = vec![crate::threads::Turn {
                question: "what writes?".into(),
                answer: "**Disk** writes come from `prometheus`:\n- pid 1810 writes *steadily*\n".into(),
                via: "ollama · m · http://h".into(),
                ..Default::default()
            }];
            let out = render(&mut a, w, h);
            if h >= 24 && w >= 60 {
                assert!(out.contains("Disk writes come from prometheus:"), "{out}");
                assert!(out.contains("• pid 1810 writes steadily"), "{out}");
                assert!(!out.contains("**") && !out.contains('`'), "{out}");
                assert!(out.contains("via ollama"), "{out}");
            }
            // Long threads show their end; scrolling far up stops at the top.
            a.ask.turns[0].answer = "line\n".repeat(200) + "the end";
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("the end"), "{out}");
            }
            a.ask.scroll_up = u16::MAX;
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("what writes?"), "{out}");
            }
            a.ask.typing = true;
            a.ask.input = "since when".into();
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("› since when"), "{out}");
            }
            a.tab = Tab::Procs;
            a.ask = Default::default();
            // Settings overlay: values, sources, editing and the model picker.
            let fields = crate::settings::fields(&crate::config::Config::default(), "", &|k: &str| {
                (k == "FAT_ASK_URL").then(|| "http://10.0.0.5:11434".to_string())
            });
            let mut ui = crate::tui::app::SettingsUi {
                fields,
                path: "/home/u/.config/fat/config.toml".into(),
                ..Default::default()
            };
            ui.key_status = "ANTHROPIC_API_KEY: set ✓".into();
            a.tab = Tab::Settings;
            a.settings = ui.clone();
            let out = render(&mut a, w, h);
            if h >= 30 && w >= 100 {
                assert!(
                    out.contains("Settings") && out.contains("Recording") && out.contains("Connect ask to"),
                    "{out}"
                );
                assert!(out.contains("Privacy") && out.contains("Advanced") && out.contains("default"), "{out}");
                assert!(out.contains("Not ready") || out.contains("Ready"), "{out}");
                assert!(!out.contains("sk-"), "{out}");
            }
            ui.editing = Some("qwen3:32".into());
            ui.sel = ui
                .rows()
                .iter()
                .position(|r| matches!(r, crate::tui::app::SRow::Field(i) if ui.fields[*i].key == "model"))
                .unwrap();
            a.settings = ui.clone();
            let out = render(&mut a, w, h);
            if h >= 30 && w >= 100 {
                assert!(out.contains("qwen3:32▏"), "{out}");
            }
            ui.editing = None;
            ui.picker = Some((vec!["llama3.3:70b".into(), "qwen3:32b".into()], 1));
            a.settings = ui.clone();
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("Models") && out.contains("qwen3:32b"), "{out}");
            }
            // The Hosts group and the host form.
            ui.picker = None;
            ui.hosts = vec![crate::config::HostCfg {
                name: "web-01".into(),
                ssh: Some("ops@web-01".into()),
                ..Default::default()
            }];
            ui.sel = ui.rows().iter().position(|r| *r == crate::tui::app::SRow::Host(0)).unwrap();
            a.settings = ui.clone();
            let out = render(&mut a, w, h);
            if h >= 24 && w >= 80 {
                assert!(
                    out.contains("web-01") && out.contains("ssh ops@web-01") && out.contains("add a host"),
                    "{out}"
                );
            }
            ui.host_form = Some(crate::tui::app::HostForm::from(Some(0), &ui.hosts[0]));
            a.settings = ui;
            let out = render(&mut a, w, h);
            if h >= 24 && w >= 80 {
                assert!(out.contains("Edit host") && out.contains("ssh destination"), "{out}");
            }
            a.settings = Default::default();
            a.tab = Tab::Procs;
        }
    }

    #[test]
    fn empty_app_renders_everywhere() {
        for t in Tab::ALL {
            for (w, h) in SIZES.into_iter().chain([(10, 3), (1, 1)]) {
                let mut a = App::new(1000);
                a.switch_tab(t);
                render(&mut a, w, h);
            }
        }
    }

    #[test]
    fn tree_and_filter_render() {
        let mut a = full_app();
        a.tree = true;
        a.mark_dirty();
        let out = render(&mut a, 160, 48);
        assert!(out.contains("└ "), "{out}");
        a.set_filter("zzz".into());
        let out = render(&mut a, 80, 24);
        assert!(out.contains("no process matches"));
    }

    fn linux_app() -> App {
        let mut a = App::new(1000);
        for i in 0..10 {
            let s = linux_snap(1_000_000 + i * 1000);
            a.now = s.ts;
            a.on_snapshot(s);
        }
        a
    }

    #[test]
    fn linux_header_shows_psi_temp_and_power_source() {
        for (w, h) in SIZES {
            let mut a = linux_app();
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("PSI cpu") && out.contains("io"), "{w}x{h}\n{out}");
                assert!(out.contains("cpu▅12") && out.contains("io█31"), "psi values {w}x{h}\n{out}");
                assert!(out.contains("48.2W rapl"), "{w}x{h}\n{out}");
                assert!(out.contains("THERM 71°C"), "{w}x{h}\n{out}");
                assert!(!out.contains("BAT"), "no battery on this box");
            }
        }
        // estimate gets a tilde, macOS rusage stays unlabelled
        let mut a = linux_app();
        if let Some(l) = a.live.as_mut() {
            l.system.power_source = "estimate".into();
            l.system.thermal = "nominal".into();
        }
        let out = render(&mut a, 160, 48);
        assert!(out.contains("~48.2W est") && out.contains("nominal 71°C"), "{out}");
        let mut m = full_app();
        let out = render(&mut m, 160, 48);
        assert!(out.contains("PWR 23.4W  THERM nominal"), "macOS header unchanged\n{out}");
        assert!(!out.contains("PSI") && !out.contains("CONTAINER"));
    }

    #[test]
    fn linux_procs_show_container_column() {
        for (w, h) in [(80u16, 24u16), (120, 40), (160, 48), (64, 20)] {
            let mut a = linux_app();
            let out = render(&mut a, w, h);
            assert!(out.contains("CONTAINER"), "{w}x{h}\n{out}");
            assert!(out.contains("db-1"), "known container by name {w}x{h}\n{out}");
            assert!(out.contains("f592d553371f"), "unknown container by short id {w}x{h}\n{out}");
            assert!(out.contains("postgres"));
        }
        let out = render(&mut linux_app(), 160, 48);
        assert!(out.contains("USER") && out.contains("THR"), "wide keeps every column\n{out}");
        // narrow: column dropped, still renders
        let out = render(&mut linux_app(), 40, 10);
        assert!(!out.contains("CONTAINER"));
        // '/' filter by container name
        let mut a = linux_app();
        a.set_filter("db-1".into());
        let out = render(&mut a, 80, 24);
        assert!(out.contains("pg-worker") && !out.contains("clickhouse") && !out.contains("esbuild"), "{out}");
    }

    #[test]
    fn linux_why_shows_cgroup_and_container() {
        for (w, h) in SIZES {
            let mut a = linux_app();
            a.set_why(Explanation {
                pid: 500,
                headline: "postgres is busy".into(),
                chain: vec!["postgres (500)".into(), "containerd-shim".into()],
                ..Default::default()
            });
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("container db-1"), "{w}x{h}\n{out}");
                assert!(out.contains("cgroup /system.slice/docker-410892b21be2….scope"), "{w}x{h}\n{out}");
            }
        }
        let mut a = linux_app();
        a.set_why(Explanation { pid: 100, headline: "zsh".into(), ..Default::default() });
        let out = render(&mut a, 160, 48);
        assert!(out.contains("session-3.scope") && !out.contains("container "), "{out}");
    }

    #[test]
    fn cgroup_ids_are_shortened() {
        assert_eq!(
            short_cgroup("/system.slice/docker-410892b21be2ffda255ceb4e7e2077d968864674cefc8174a3843e6f01c860f7.scope"),
            "/system.slice/docker-410892b21be2….scope"
        );
        assert_eq!(
            short_cgroup("/user.slice/user-1000.slice/session-3.scope"),
            "/user.slice/user-1000.slice/session-3.scope"
        );
        assert_eq!(short_cgroup(""), "");
    }

    #[test]
    fn linux_fleet_counts_container_procs() {
        let mut a = linux_app();
        a.set_fleet(Some(a.live.as_ref().unwrap().containers.clone()));
        a.switch_tab(Tab::Fleet);
        let out = render(&mut a, 80, 24);
        assert!(out.contains("db-1") && out.contains("2 procs"), "{out}");
    }

    #[test]
    fn render_800_procs_is_fast() {
        let mut a = App::new(1000);
        let mut s = snap(1_000_000);
        for i in 0..800 {
            s.procs.push(proc(10_000 + i, 1, &format!("worker{i}"), (i % 97) as f32, (i as u64) << 20));
        }
        a.on_snapshot(s);
        let mut term = Terminal::new(TestBackend::new(160, 48)).unwrap();
        term.draw(|f| draw(f, &mut a)).unwrap(); // includes the one-time sort
        let t = std::time::Instant::now();
        let n = 50;
        for _ in 0..n {
            term.draw(|f| draw(f, &mut a)).unwrap();
        }
        let per = t.elapsed() / n;
        eprintln!("render 800 procs @160x48: {per:?}/frame");
        // generous bound for debug builds on CI; release is far below 5ms
        assert!(per < std::time::Duration::from_millis(40), "render took {per:?}");
    }

    // ------------------------------------------------------------ Fs tab

    fn fs_full_app() -> App {
        use crate::fs::{DirEntry, Evidence, Grower, Growth, Listing, ScanProgress, Volume};
        let mut a = full_app();
        a.set_volumes(
            a.now,
            vec![
                Volume {
                    mount: "/".into(),
                    read_only: true,
                    total: 994 << 30,
                    used: 11 << 30,
                    avail: 300 << 30,
                    ..Default::default()
                },
                Volume {
                    mount: "/System/Volumes/Data".into(),
                    fstype: "apfs".into(),
                    primary: true,
                    total: 994 << 30,
                    used: 630 << 30,
                    avail: 300 << 30,
                    fill_bps: Some(2.0 * 1024.0 * 1024.0),
                    eta_full_s: Some(3 * 3600 + 60),
                    write_bps: 5 << 20,
                    purgeable: Some(12 << 30),
                    ..Default::default()
                },
                Volume { mount: "/System/Volumes/Preboot".into(), total: 994 << 30, ..Default::default() },
            ],
        );
        a.switch_tab(Tab::Fs);
        let de = |p: &str, size: u64| DirEntry {
            path: p.into(),
            name: p.rsplit('/').next().unwrap().into(),
            is_dir: true,
            size,
            files: 1200,
            newest_mtime: a.now / 1000 - 120,
            ..Default::default()
        };
        a.set_fs_listing(
            "/",
            Some(Listing {
                dir: DirEntry { partial: true, ..de("/", 600 << 30) },
                children: vec![
                    de("/Users", 400 << 30),
                    de("/Applications", 80 << 30),
                    DirEntry { denied: 2, size: 0, ..de("/private", 0) },
                    DirEntry { mount_point: true, size: 0, ..de("/Volumes", 0) },
                ],
                progress: ScanProgress {
                    root: "/".into(),
                    running: true,
                    files_seen: 1_200_000,
                    fraction: Some(0.43),
                    ..Default::default()
                },
            }),
        );
        a.set_fs_growth(Growth {
            growers: vec![
                Grower {
                    path: "/Users/me/Library/Caches/pip".into(),
                    is_dir: true,
                    delta: 1 << 30,
                    size: 3 << 30,
                    writers: vec![(200, "node".into(), 4 << 20)],
                    evidence: vec![Evidence::Fsevents],
                    ..Default::default()
                },
                Grower {
                    path: "/Users/me/Library/Caches".into(),
                    is_dir: true,
                    delta: 300 << 20,
                    other: true,
                    evidence: vec![Evidence::Fsevents],
                    ..Default::default()
                },
            ],
            writers: vec![(200, "node".into(), 1 << 30)],
            deleted_open: vec![
                (400, "Chrome".into(), "/tmp/blob".into(), 2 << 30),
                (400, "Chrome".into(), "/tmp/blob2".into(), 1 << 30),
                (400, "Chrome".into(), "/tmp/tiny".into(), 4096),
            ],
            notes: vec!["open-file attribution covers your own processes".into()],
            ..Default::default()
        });
        a
    }

    #[test]
    fn fs_tab_renders_tree_growth_and_largest() {
        for (w, h) in SIZES {
            let mut a = fs_full_app();
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("Fs"), "{w}x{h}\n{out}");
                assert!(
                    out.contains("/System/Volumes/Data") && out.contains("full in 3h"),
                    "volume strip {w}x{h}\n{out}"
                );
                assert!(!out.contains("Preboot"), "helper volumes hidden\n{out}");
                assert!(out.contains("scanning 43%") && out.contains("1.2M files"), "{w}x{h}\n{out}");
                assert!(
                    out.contains("Users/") && out.contains("400.0G") && out.contains("+1.3G"),
                    "a remainder row adds to its children: {w}x{h}\n{out}"
                );
                assert!(out.contains("🔒") || out.contains("private/"), "{out}");
            }
            if w >= 100 {
                assert!(out.contains("+1.2G/10m") && out.contains("purgeable 12.0G"), "{out}");
                assert!(out.contains("2m ago") && out.contains("mount"), "{out}");
            }
            a.on_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(
                    out.contains("What is eating space")
                        && out.contains("Library/Caches/pip")
                        && out.contains("Chrome"),
                    "{w}x{h}\n{out}"
                );
                assert!(out.contains("other under /Users/me/Library/Caches/"), "remainder row is labelled\n{out}");
                assert_eq!(out.matches("Chrome (400) holds").count(), 1, "one row per holder\n{out}");
                if w >= 120 {
                    assert!(
                        out.contains("2 deleted files, biggest /tmp/blob") && out.contains("1 small (<1M"),
                        "{out}"
                    );
                }
            }
            a.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
            a.on_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("finding the largest"), "{out}");
            }
            a.set_fs_largest(
                "/",
                vec![crate::fs::DirEntry {
                    path: "/Users/me/vm.img".into(),
                    name: "vm.img".into(),
                    size: 40 << 30,
                    ..Default::default()
                }],
            );
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("Users/me/vm.img") && out.contains("40.0G"), "{out}");
            }
        }
    }

    #[test]
    fn fs_tab_detail_line_and_states() {
        let mut a = fs_full_app();
        let out = render(&mut a, 160, 48);
        // Users is selected: the known-dir hint is not for it, but its top writer is
        assert!(out.contains("✎ node (200)"), "{out}");
        // empty / error states
        let mut b = App::new(1000);
        b.switch_tab(Tab::Fs);
        assert!(render(&mut b, 80, 24).contains("Measuring /"));
        b.set_fs_error("scanner unavailable (boom)".into());
        let out = render(&mut b, 80, 24);
        assert!(out.contains("storage engine unavailable"), "{out}");
        // rewound without recorded sizes: clearly marked
        let mut c = fs_full_app();
        c.jump_to(c.now - 1000);
        c.history_ok = false;
        let out = render(&mut c, 160, 48);
        assert!(out.contains("as of") && out.contains("no directory sizes recorded"), "{out}");
        // rewound with recorded sizes
        let ts = c.now - 1000;
        c.history_ok = true;
        c.set_fs_past(crate::tui::app::fs_past_from(
            ts,
            "/",
            Some(ts - 60_000),
            &[("/".into(), 500 << 30), ("/Users".into(), 300 << 30), ("/Users/me".into(), 1)],
            vec![("/System/Volumes/Data".into(), 600 << 30)],
        ));
        let out = render(&mut c, 160, 48);
        assert!(out.contains("recorded") && out.contains("300.0G") && !out.contains("400.0G"), "{out}");
        assert!(out.contains("600.0G/994.0G") && out.contains("⏪"), "{out}");
    }

    #[test]
    fn help_lines_wrap_instead_of_cutting_off() {
        for inner in [76usize, 98, 40] {
            let lines = help_lines(inner);
            let text: String =
                lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>() + "\n").collect();
            for l in &lines {
                let w: usize = l.spans.iter().map(|s| s.content.chars().count()).sum();
                // Only a single word longer than the column may overflow (narrow terminals).
                let one_word = !l.spans[1].content.contains(' ');
                assert!(w <= inner || one_word, "{inner}: {w} > {inner}: {text}");
            }
            // Every word of every description survives, including the NOT-undoable warning.
            for (_, d) in HELP {
                for word in d.split(' ') {
                    assert!(text.contains(word), "{inner}: lost {word:?}");
                }
            }
        }
    }

    #[test]
    fn ports_view_shows_chips_groups_and_the_filter() {
        use crate::model::{ConnGroup, Conns};
        for (w, h) in SIZES {
            let mut a = full_app();
            let mut s = a.live.clone().unwrap();
            s.conns = Conns {
                states: vec![("ESTABLISHED".into(), 1240), ("TIME_WAIT".into(), 210), ("CLOSE_WAIT".into(), 18)],
                groups: vec![
                    ConnGroup {
                        state: "ESTABLISHED".into(),
                        pid: 200,
                        process: "node".into(),
                        remote: "10.0.3.7".into(),
                        remote_port: 5432,
                        count: 412,
                        peer_name: "db-1.internal".into(),
                        peer_name_verified: true,
                        ..Default::default()
                    },
                    ConnGroup {
                        state: "TIME_WAIT".into(),
                        inbound: true,
                        local: "*".into(),
                        local_port: 443,
                        remote: "203.0.113.5".into(),
                        count: 210,
                        peer_name: "claims.example".into(),
                        peer_net: Some(crate::model::PeerNet {
                            asn: 64500,
                            name: "EXAMPLE-NET".into(),
                            country: "NL".into(),
                        }),
                        ..Default::default()
                    },
                ],
                notes: vec!["TIME_WAIT is not shown on macOS".into()],
                ..Default::default()
            };
            a.on_snapshot(s);
            a.switch_tab(Tab::Ports);
            let out = render(&mut a, w, h);
            if h >= 24 && w >= 80 {
                assert!(
                    out.contains("Established 1240") && out.contains("Time-wait 210") && out.contains("Close-wait 18"),
                    "{out}"
                );
                assert!(out.contains("10.0.3.7:5432") && out.contains("×412") && out.contains("(kernel)"), "{out}");
            }
            if h >= 24 && w >= 140 {
                assert!(out.contains("out  db-1.internal "), "verified names carry no mark: {out}");
                assert!(out.contains("claims.example?  AS64500 EXAMPLE-NET"), "unconfirmed names are marked: {out}");
            }
            a.on_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE));
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("Filter ports") && out.contains("Address scope"), "{out}");
            }
            a.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        }
    }
}
