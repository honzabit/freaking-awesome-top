//! Rendering. Only visible rows are materialized, so cost scales with the
//! terminal height, not the process count.

use crate::model::Proc;
use crate::tui::app::{App, AskState, Modal, SortKey, Tab, ZOOMS, ZOOM_NAMES};
use crate::tui::widgets::*;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Axis, Block, Borders, Cell, Chart, Clear, Dataset, GraphType, LegendPosition, List, ListItem, ListState, Paragraph,
    Row, Table, Tabs, Wrap,
};

const SEL_BG: Color = Color::Indexed(236);
const ACCENT: Color = Color::Cyan;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn draw(f: &mut Frame, app: &mut App) {
    app.ensure_rows();
    let area = f.area();
    let header_h = if area.height < 16 { 2 } else { 4 };
    let [header, tabs, main, footer] =
        Layout::vertical([Constraint::Length(header_h), Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)])
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
        Tab::Fleet => draw_fleet(f, app, main),
        Tab::Timeline => draw_timeline(f, app, main),
        Tab::Doctor => draw_doctor(f, app, main),
        Tab::Log => draw_log(f, app, main),
    }

    if app.why.is_some() {
        let r = side.unwrap_or_else(|| centered(main.width.saturating_sub(4), main.height, main));
        draw_why(f, app, r);
    }
    draw_footer(f, app, footer);
    draw_ask(f, app, area);
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
        l1.push(Span::styled(format!(" {} ", if sys.hostname.is_empty() { &s.host } else { &sys.hostname }), Style::default().bold()));
        l1.push(Span::styled(format!(" up {}", fmt_dur(sys.uptime)), dim()));
        l1.push(Span::raw(format!("  load {:.2} {:.2} {:.2}", sys.load[0], sys.load[1], sys.load[2])));
        l1.push(Span::styled(format!("  {} procs", s.procs.len()), dim()));
    } else {
        l1.push(Span::styled(" sampling…", dim()));
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

    // line 2: cpu sparkline + per-core
    let cores_w = if sys.per_core.len() + 12 < w / 2 { sys.per_core.len() } else { 0 };
    let spark_w = w.saturating_sub(10 + cores_w + 2);
    let mut l2 = vec![
        Span::styled("CPU ", Style::default().fg(ACCENT).bold()),
        Span::styled(format!("{:>4.0}% ", sys.cpu), Style::default().fg(pct_color(sys.cpu)).bold()),
        Span::styled(sparkline(app.ring_points.iter().map(|p| p.cpu), spark_w), Style::default().fg(pct_color(sys.cpu))),
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
        let bw = (w / 4).clamp(8, 40);
        let pc = pressure_color(&sys.mem_pressure);
        let mut l3 = vec![
            Span::styled("MEM ", Style::default().fg(ACCENT).bold()),
            Span::styled(bar(ratio, bw), Style::default().fg(pc)),
            Span::raw(format!(" {}/{} ", fmt_bytes(sys.mem_used), fmt_bytes(sys.mem_total))),
            Span::styled(if sys.mem_pressure.is_empty() { "unknown" } else { sys.mem_pressure.as_str() }, Style::default().fg(pc)),
        ];
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
        let mut l4 = vec![
            Span::styled("PWR ", Style::default().fg(ACCENT).bold()),
            Span::styled(fmt_power(sys.power_mw), power_style(sys.power_mw / 4.0)),
            Span::styled("  THERM ", Style::default().fg(ACCENT)),
            Span::styled(
                if sys.thermal.is_empty() { "unknown" } else { sys.thermal.as_str() },
                Style::default().fg(thermal_color(&sys.thermal)),
            ),
            Span::styled("  NET ", Style::default().fg(ACCENT)),
            Span::raw(format!("↓{}/s ↑{}/s", fmt_bytes(sys.net_rx_bps), fmt_bytes(sys.net_tx_bps))),
            Span::styled("  DISK ", Style::default().fg(ACCENT)),
            Span::raw(format!("r{}/s w{}/s", fmt_bytes(sys.disk_read_bps), fmt_bytes(sys.disk_write_bps))),
        ];
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

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut spans = vec![Span::styled(format!("{}", i + 1), Style::default().fg(Color::Yellow)), Span::raw(t.title())];
            if *t == Tab::Doctor {
                let crit = app.findings.iter().filter(|x| x.severity == "crit").count();
                let warn = app.findings.iter().filter(|x| x.severity == "warn").count();
                if crit > 0 {
                    spans.push(Span::styled(format!(" {crit}"), Style::default().fg(Color::Red).bold()));
                } else if warn > 0 {
                    spans.push(Span::styled(format!(" {warn}"), Style::default().fg(Color::Yellow)));
                }
            }
            if *t == Tab::Ports
                && let Some(n) = app.view().map(|s| s.ports.iter().filter(|p| p.orphan).count()).filter(|n| *n > 0) {
                    spans.push(Span::styled(format!(" ⚠{n}"), Style::default().fg(Color::Yellow)));
                }
            Line::from(spans)
        })
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .style(dim())
        .highlight_style(Style::default().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD))
        .divider("│")
        .padding(" ", " ");
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
    Name,
}

fn columns(width: u16) -> &'static [Col] {
    use Col::*;
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
        Col::Name => ("NAME / CMD", Some(SortKey::Name), false),
    };
    let sorted = key == Some(sort);
    let text = if sorted { format!("{t}{}", if desc { "▼" } else { "▲" }) } else { t.to_string() };
    let style = if sorted { Style::default().fg(ACCENT).bold() } else { Style::default().bold() };
    let line = Line::styled(text, style);
    Cell::from(if right { line.alignment(Alignment::Right) } else { line })
}

fn num(s: String, style: Style) -> Cell<'static> {
    Cell::from(Line::styled(s, style).alignment(Alignment::Right))
}

fn proc_cell<'a>(c: Col, p: &'a Proc, depth: u16, tree: bool) -> Cell<'a> {
    let paused = p.status == "T";
    match c {
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
fn scroll_into_view(sel: usize, offset: &mut usize, height: usize, len: usize) {
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
            if app.past_loading { "loading snapshot from the recorder…" } else { "no process snapshot recorded at this moment" }
        } else {
            "waiting for the first sample…"
        };
        f.render_widget(Paragraph::new(msg).style(dim()).block(Block::default().borders(Borders::TOP).title(" Procs ")), area);
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

    let cols = columns(area.width);
    let header = Row::new(cols.iter().map(|&c| col_title(c, app.sort, app.sort_desc)));
    let rows = app.rows.iter().enumerate().skip(app.offset).take(body_h).map(|(i, r)| {
        let p = &snap.procs[r.idx];
        let mut row = Row::new(cols.iter().map(|&c| proc_cell(c, p, r.depth, app.tree)));
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
        f.render_widget(Paragraph::new(format!("no process matches '{}' — Esc clears the filter", app.filter)).style(dim()), r);
    }
}

// ------------------------------------------------------------------- ports

fn draw_ports(f: &mut Frame, app: &mut App, area: Rect) {
    let body_h = area.height.saturating_sub(2) as usize;
    let len = app.port_rows.len();
    scroll_into_view(app.port_sel, &mut app.port_offset, body_h, len);
    let app = &*app;
    let Some(snap) = app.view() else {
        f.render_widget(Paragraph::new("no snapshot").style(dim()).block(Block::default().borders(Borders::TOP).title(" Ports ")), area);
        return;
    };
    let orphans = snap.ports.iter().filter(|p| p.orphan).count();
    let mut title = vec![Span::styled(" Ports ", Style::default().bold()), Span::styled(format!("{} listening ", len), dim())];
    if orphans > 0 {
        title.push(Span::styled(format!("· ⚠ {orphans} orphaned "), Style::default().fg(Color::Yellow).bold()));
    }
    let header = Row::new(["PROTO", "ADDRESS", "PID", "PROCESS", "NOTE"].map(|h| Cell::from(Span::styled(h, Style::default().bold()))));
    let rows = app.port_rows.iter().enumerate().skip(app.port_offset).take(body_h).map(|(i, &pi)| {
        let p = &snap.ports[pi];
        let proto = match p.proto {
            crate::model::Proto::Tcp => "tcp",
            crate::model::Proto::Udp => "udp",
        };
        let note = if p.orphan {
            Line::from(vec![
                Span::styled("⚠ orphan ", Style::default().fg(Color::Black).bg(Color::Yellow).bold()),
                Span::styled(format!(" {}", p.note), Style::default().fg(Color::Yellow)),
            ])
        } else {
            Line::styled(p.note.as_str(), dim())
        };
        let mut row = Row::new(vec![
            Cell::from(proto),
            Cell::from(format!("{}:{}", p.addr, p.port)),
            num(p.pid.to_string(), Style::default()),
            Cell::from(Span::styled(p.process.as_str(), Style::default().bold())),
            Cell::from(note),
        ]);
        if i == app.port_sel {
            row = row.style(Style::default().bg(SEL_BG));
        }
        row
    });
    let table = Table::new(
        rows,
        [Constraint::Length(5), Constraint::Length(24), Constraint::Length(7), Constraint::Length(16), Constraint::Min(10)],
    )
    .header(header)
    .column_spacing(1)
    .block(Block::default().borders(Borders::TOP).border_style(dim()).title(Line::from(title)));
    f.render_widget(table, area);
    if len == 0 {
        let r = Rect { y: area.y + 2, height: 1, ..area };
        f.render_widget(Paragraph::new("nothing is listening (or port data unavailable)").style(dim()), r);
    }
}

// ------------------------------------------------------------------- fleet

fn draw_fleet(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(["NAME", "KIND", "STATUS", "CPU%", "MEMORY", "DETAIL"].map(|h| Cell::from(Span::styled(h, Style::default().bold()))));
    let mut rows: Vec<Row> = Vec::with_capacity(app.fleet_len());
    if let Some(s) = app.live.as_ref() {
        let sys = &s.system;
        rows.push(Row::new(vec![
            Cell::from(Span::styled(format!("● {}", if sys.hostname.is_empty() { "local" } else { &sys.hostname }), Style::default().fg(Color::Green).bold())),
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
    for (i, c) in app.containers.iter().enumerate() {
        let glyph = if i + 1 == nc { "  └ " } else { "  ├ " };
        let running = c.status.to_lowercase().starts_with("up") || c.status.to_lowercase().contains("running");
        rows.push(Row::new(vec![
            Cell::from(Line::from(vec![Span::styled(glyph, dim()), Span::raw(c.name.as_str())])),
            Cell::from(Span::styled(c.runtime.as_str(), dim())),
            Cell::from(Span::styled(clip(&c.status, 14), Style::default().fg(if running { Color::Green } else { Color::Gray }))),
            num(format!("{:.1}", c.cpu), cpu_style(c.cpu)),
            Cell::from(Span::styled(fmt_bytes(c.mem), mem_style(c.mem))),
            Cell::from(Span::styled(format!("{} {}", c.image, c.ports), dim())),
        ]));
    }
    for h in &app.hosts {
        let (status, st) = if h.ok {
            ("online".to_string(), Style::default().fg(Color::Green))
        } else {
            (format!("✗ {}", clip(&h.error, 40)), Style::default().fg(Color::Red))
        };
        rows.push(Row::new(vec![
            Cell::from(Span::styled(format!("● {}", h.name), Style::default().fg(if h.ok { ACCENT } else { Color::Red }).bold())),
            Cell::from("ssh"),
            Cell::from(Span::styled(status, st)),
            if h.ok { num(format!("{:.0}", h.cpu), Style::default().fg(pct_color(h.cpu))) } else { Cell::from("") },
            Cell::from(if h.ok { format!("{}/{}", fmt_bytes(h.mem_used), fmt_bytes(h.mem_total)) } else { String::new() }),
            Cell::from(Span::styled(if h.ok { format!("{} procs · {} ports", h.procs, h.ports) } else { String::new() }, dim())),
        ]));
    }
    let n_rows = rows.len();
    let rows = rows.into_iter().enumerate().map(|(i, r)| if i == app.fleet_sel { r.style(Style::default().bg(SEL_BG)) } else { r });
    let title = Line::from(vec![
        Span::styled(" Fleet ", Style::default().bold()),
        Span::styled(format!("1 local · {nc} containers · {} hosts ", app.hosts.len()), dim()),
    ]);
    let table = Table::new(
        rows,
        [Constraint::Min(18), Constraint::Length(8), Constraint::Length(16), Constraint::Length(5), Constraint::Length(14), Constraint::Min(10)],
    )
    .header(header)
    .column_spacing(1)
    .block(Block::default().borders(Borders::TOP).border_style(dim()).title(title));
    f.render_widget(table, area);

    let used = n_rows as u16 + 2;
    if nc == 0 && app.hosts.is_empty() && area.height > used + 2 {
        let r = Rect { y: area.y + used + 1, height: area.height - used - 1, ..area }.inner(Margin { horizontal: 2, vertical: 0 });
        let mut t = Text::default();
        if !app.fleet_loaded {
            t.lines.push(Line::styled("scanning for containers and remote hosts…", dim()));
        } else {
            if app.configured_hosts > 0 {
                t.lines.push(Line::styled(format!("contacting {} remote host(s)…", app.configured_hosts), dim()));
            }
            t.lines.push(Line::styled("No containers or remote hosts yet.", Style::default().bold()));
            t.lines.push(Line::raw(""));
            t.lines.push(Line::raw("• Containers (docker / podman / orbstack) appear here automatically while they run."));
            t.lines.push(Line::raw(format!("• Remote hosts: add them to {}", app.config_path)));
            t.lines.push(Line::styled("      [[hosts]]", Style::default().fg(Color::Green)));
            t.lines.push(Line::styled("      name = \"devbox\"", Style::default().fg(Color::Green)));
            t.lines.push(Line::styled("      ssh  = \"me@devbox\"   # needs `fat` installed there", Style::default().fg(Color::Green)));
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
        Dataset::default().name("cpu%").marker(Marker::Braille).graph_type(GraphType::Line).style(Style::default().fg(ACCENT)).data(&cpu),
        Dataset::default()
            .name(format!("power (max {})", fmt_power(max_pw)))
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Yellow))
            .data(&pw),
    ];
    if !spikes.is_empty() {
        datasets.push(Dataset::default().name("spike").marker(Marker::Dot).graph_type(GraphType::Scatter).style(Style::default().fg(Color::Red)).data(&spikes));
    }
    if !cursor.is_empty() {
        datasets.push(Dataset::default().marker(Marker::Braille).graph_type(GraphType::Line).style(Style::default().fg(Color::Magenta)).data(&cursor));
    }
    let span = window as f64 / 1000.0;
    let chart = Chart::new(datasets)
        .block(block)
        .legend_position(Some(LegendPosition::TopLeft))
        .hidden_legend_constraints((Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)))
        .x_axis(
            Axis::default()
                .bounds([0.0, span])
                .style(dim())
                .labels(vec![Span::raw(fmt_clock(from)), Span::raw(fmt_clock(from + window / 2)), Span::raw("now")]),
        )
        .y_axis(Axis::default().bounds([0.0, 100.0]).style(dim()).labels(vec![Span::raw("0"), Span::raw("50"), Span::raw("100")]));
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
                lines.push(Line::from(vec![Span::raw("       "), Span::styled(clip(&x.detail, width.max(10) * 2), dim())]));
            }
            if let Some(a) = &x.action {
                lines.push(Line::from(vec![Span::raw("       → "), Span::styled(a.as_str(), Style::default().fg(Color::Green))]));
            }
            ListItem::new(lines)
        })
        .collect();
    let list = List::new(items).block(block).highlight_style(Style::default().bg(SEL_BG)).highlight_symbol("▌");
    let mut state = ListState::default().with_selected(Some(app.doctor_sel));
    f.render_stateful_widget(list, area, &mut state);
}

// ------------------------------------------------------------------- log

fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::TOP).border_style(dim()).title(Line::from(vec![
        Span::styled(" Action log ", Style::default().bold()),
        Span::styled("most recent first · u undoes the last undoable action ", dim()),
    ]));
    if app.log.is_empty() {
        let t = Text::from(vec![
            Line::styled("No actions yet.", Style::default().bold()),
            Line::styled("Pause (space), renice (r) or terminate (k) a process — every action lands here,", dim()),
            Line::styled("and pause/renice can be undone with u.", dim()),
        ]);
        f.render_widget(Paragraph::new(t).block(block), area);
        return;
    }
    let header = Row::new(["TIME", "#", "ACTION", "PID", "NAME", "RESULT"].map(|h| Cell::from(Span::styled(h, Style::default().bold()))));
    let body_h = area.height.saturating_sub(2) as usize;
    let mut offset = 0;
    scroll_into_view(app.log_sel, &mut offset, body_h, app.log.len());
    let rows = app.log.iter().enumerate().skip(offset).take(body_h).map(|(i, r)| {
        let (mark, ms) = if r.ok { ("✓", Style::default().fg(Color::Green)) } else { ("✗", Style::default().fg(Color::Red)) };
        let mut result = vec![Span::styled(mark, ms), Span::raw(" "), Span::raw(r.message.as_str())];
        if r.undone {
            result.push(Span::styled("  (undone)", dim()));
        } else if r.undoable && r.ok {
            result.push(Span::styled("  undoable", Style::default().fg(ACCENT)));
        }
        let mut row = Row::new(vec![
            Cell::from(Span::styled(fmt_datetime(r.ts), dim())),
            num(r.id.to_string(), dim()),
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
        rows,
        [Constraint::Length(14), Constraint::Length(4), Constraint::Length(9), Constraint::Length(7), Constraint::Length(16), Constraint::Min(10)],
    )
    .header(header)
    .column_spacing(1)
    .block(block);
    f.render_widget(table, area);
}

// ------------------------------------------------------------------- overlays

fn draw_why(f: &mut Frame, app: &App, area: Rect) {
    let Some(e) = &app.why else { return };
    let mut t = Text::default();
    t.lines.push(Line::styled(e.headline.as_str(), Style::default().fg(Color::Yellow).bold()));
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
            t.lines.push(Line::from(vec![Span::styled("→ ", Style::default().fg(Color::Green)), Span::raw(s.as_str())]));
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

fn draw_ask(f: &mut Frame, app: &App, area: Rect) {
    match &app.ask {
        AskState::Idle => {}
        AskState::Thinking { question, since, .. } => {
            let r = centered(60.min(area.width.saturating_sub(4)), 5, area);
            let spin = SPINNER[((app.now - since).max(0) / 100) as usize % SPINNER.len()];
            let t = Text::from(vec![
                Line::from(vec![Span::styled(format!("{spin} thinking… "), Style::default().fg(ACCENT).bold())]),
                Line::styled(format!("“{question}”"), dim()),
            ]);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(t).wrap(Wrap { trim: true }).block(
                    Block::default().borders(Borders::ALL).border_style(Style::default().fg(ACCENT)).title(" Ask ").title_bottom(Line::styled(" Esc cancel ", dim())),
                ),
                r,
            );
        }
        AskState::Answer { question, text, scroll } => {
            let r = centered(area.width.saturating_sub(area.width / 8).max(20), area.height.saturating_sub(area.height / 6).max(6), area);
            f.render_widget(Clear, r);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(Line::styled(format!(" Ask · {} ", clip(question, 60)), Style::default().bold()))
                .title_bottom(Line::styled(" ↑↓ PgUp/PgDn scroll · ? ask again · Esc close ", dim()));
            f.render_widget(Paragraph::new(text.as_str()).wrap(Wrap { trim: false }).scroll((*scroll, 0)).block(block), r);
        }
    }
}

fn draw_modal(f: &mut Frame, app: &App, area: Rect) {
    match &app.modal {
        Modal::None | Modal::Filter => {}
        Modal::Help => draw_help(f, area),
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
                Paragraph::new(t).wrap(Wrap { trim: true }).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Red)).title(" Confirm ")),
                r,
            );
        }
        Modal::Renice { pid, name, input, .. } => {
            let r = centered(60.min(area.width.saturating_sub(2)), 6, area);
            let t = Text::from(vec![
                Line::from(vec![Span::raw("New nice value for "), Span::styled(format!("{pid} ({name})"), Style::default().bold())]),
                Line::from(vec![Span::raw("> "), Span::styled(input.as_str(), Style::default().fg(Color::Yellow).bold()), Span::styled("▏", Style::default().fg(ACCENT))]),
                Line::styled("-20 highest … 20 lowest priority · Enter apply · Esc cancel · undo with u", dim()),
            ]);
            f.render_widget(Clear, r);
            f.render_widget(Paragraph::new(t).wrap(Wrap { trim: true }).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(ACCENT)).title(" Renice ")), r);
        }
        Modal::AskInput(q) => {
            let r = centered(72.min(area.width.saturating_sub(2)), 6, area);
            let t = Text::from(vec![
                Line::styled("Ask about this machine in plain language", dim()),
                Line::from(vec![Span::styled("> ", Style::default().fg(ACCENT).bold()), Span::raw(q.as_str()), Span::styled("▏", Style::default().fg(ACCENT))]),
                Line::styled("e.g. why is my mac slow? · what is using port 3000? · Enter ask · Esc cancel", dim()),
            ]);
            f.render_widget(Clear, r);
            f.render_widget(Paragraph::new(t).wrap(Wrap { trim: true }).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(ACCENT)).title(" Ask ")), r);
        }
    }
}

const HELP: &[(&str, &str)] = &[
    ("1-6 / Tab", "switch view: Procs Ports Fleet Timeline Doctor Log"),
    ("↑↓ PgUp PgDn g G", "move selection"),
    ("c m p n d i N", "sort by cpu mem power net disk pid name (again = reverse)"),
    ("t", "toggle process tree"),
    ("/", "filter by name or command (Esc clears)"),
    ("Enter / w", "why: blame chain for the selection"),
    ("space / z", "pause / resume (SIGSTOP/SIGCONT, undoable)"),
    ("r", "renice (default 10, undoable)"),
    ("k / K", "terminate / terminate whole tree (confirm)"),
    ("u", "undo last undoable action"),
    ("← → [ ] { }", "timeline: move through time (shift / braces = ×10)"),
    ("s  +/-", "timeline: jump to next spike · zoom window"),
    ("L / Esc", "return to live"),
    ("?", "ask in plain language"),
    ("h", "this help"),
    ("q / Ctrl-C", "quit"),
];

fn draw_help(f: &mut Frame, area: Rect) {
    let r = centered(78.min(area.width.saturating_sub(2)), (HELP.len() as u16 + 4).min(area.height), area);
    let lines: Vec<Line> = HELP
        .iter()
        .map(|(k, d)| Line::from(vec![Span::styled(format!("{k:>18}  "), Style::default().fg(Color::Yellow).bold()), Span::raw(*d)]))
        .collect();
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
            Span::raw(app.filter.as_str()),
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
        Tab::Procs => &[("⏎", "why"), ("␣", "pause"), ("r", "renice"), ("k", "term"), ("K", "tree"), ("u", "undo"), ("/", "filter"), ("t", "tree"), ("cmpnd", "sort"), ("?", "ask"), ("h", "help"), ("q", "quit")],
        Tab::Ports => &[("⏎", "why"), ("k", "kill tree"), ("␣", "pause"), ("u", "undo"), ("?", "ask"), ("h", "help"), ("q", "quit")],
        Tab::Fleet => &[("↑↓", "move"), ("?", "ask"), ("h", "help"), ("q", "quit")],
        Tab::Timeline => &[("←→", "scrub"), ("s", "spike"), ("+/-", "zoom"), ("L", "live"), ("⏎", "why"), ("?", "ask"), ("h", "help"), ("q", "quit")],
        Tab::Doctor => &[("⏎", "run action"), ("w", "why"), ("?", "ask"), ("h", "help"), ("q", "quit")],
        Tab::Log => &[("u", "undo last"), ("↑↓", "move"), ("?", "ask"), ("h", "help"), ("q", "quit")],
    };
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

fn centered(w: u16, h: u16, area: Rect) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ActionKind, ActionRecord, Container, Explanation, Finding};
    use crate::tui::app::tests::{proc, snap};
    use crate::tui::app::{HostRow, Modal};
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
            Finding { severity: "crit".into(), title: "node is pegging a core".into(), detail: "88% for 10m".into(), pids: vec![200], action: Some("pause 200".into()) },
            Finding { severity: "warn".into(), title: "memory pressure".into(), detail: "swap in use".into(), pids: vec![], action: None },
        ]);
        a.set_log(vec![ActionRecord {
            id: 3, ts: 1_000_000, kind: ActionKind::Pause, pid: 200, name: "node".into(), prev_nice: None, new_nice: None,
            pids: vec![200], undoable: true, undone: false, ok: true, message: "stopped".into(),
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
        a.switch_tab(Tab::Fleet);
        a.set_fleet(Some(vec![]), Some(vec![]));
        let out = render(&mut a, 80, 24);
        assert!(out.contains("No containers or remote hosts"), "{out}");
        assert!(out.contains("[[hosts]]"));
        a.set_fleet(
            Some(vec![Container { id: "abc".into(), name: "pg".into(), image: "postgres:16".into(), runtime: "docker".into(), status: "Up 3 hours".into(), cpu: 1.5, mem: 200 << 20, ports: "5432".into() }]),
            Some(vec![HostRow { name: "devbox".into(), ok: true, cpu: 12.0, mem_used: 1 << 30, mem_total: 8 << 30, procs: 99, ports: 3, error: String::new() }, HostRow { name: "dead".into(), ok: false, error: "ssh: timeout".into(), ..Default::default() }]),
        );
        for (w, h) in SIZES {
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("pg") && out.contains("devbox") && out.contains("timeout"), "{out}");
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
            a.switch_tab(Tab::Log);
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("pause") && out.contains("undoable"), "{out}");
            }
        }
        let mut a = App::new(1000);
        a.switch_tab(Tab::Doctor);
        assert!(render(&mut a, 80, 24).contains("diagnosing"));
        a.set_findings(vec![]);
        assert!(render(&mut a, 80, 24).contains("All good"));
        a.switch_tab(Tab::Log);
        assert!(render(&mut a, 80, 24).contains("No actions yet"));
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
            a.modal = Modal::AskInput("why slow".into());
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("why slow"));
            }
            a.modal = Modal::Filter;
            a.set_filter("nod".into());
            let out = render(&mut a, w, h);
            assert!(out.contains("nod"));
            a.modal = Modal::None;
            a.ask = AskState::Thinking { question: "why slow".into(), since: a.now, id: 1 };
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("thinking"));
            }
            a.ask = AskState::Thinking { question: "q".into(), since: a.now, id: 1 };
            a.set_answer(1, "Your mac is slow because node is busy.\n".repeat(40));
            let out = render(&mut a, w, h);
            if h >= 24 {
                assert!(out.contains("because node"));
            }
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
}
