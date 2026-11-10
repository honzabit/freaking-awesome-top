//! Rendering of the server-profile views: header gauges, Services, Events, the fleet health
//! table with its drill-in, and explanation panels. Like `ui.rs`, only visible rows are
//! materialised, so the cost follows the terminal height, not the unit or host count.

use crate::model::{Psi, Snapshot};
use crate::server::{FleetHost, Kernel, Severity, Unit, UnitKind};
use crate::tui::app::{App, Tab};
use crate::tui::server::{
    DrillView, EVENT_WINDOW_NAMES, HostDrill, Panel, mem_limit_ratio, unit_is_problem, unit_kind_label, unit_rank,
};
use crate::tui::ui::{ACCENT, SEL_BG, centered, num, psi_spans, scroll_into_view};
use crate::tui::widgets::*;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};

fn sev_style(s: Severity) -> Style {
    severity_style(s.as_str())
}

fn sev_tag(s: Severity) -> &'static str {
    match s {
        Severity::Crit => "CRIT",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
    }
}

/// Colour of a fill ratio against the configured "near exhaustion" fraction.
fn limit_color(ratio: f64, warn: f32) -> Color {
    let warn = warn as f64;
    if ratio >= warn {
        Color::Red
    } else if ratio >= warn * 0.8 {
        Color::Yellow
    } else {
        Color::Green
    }
}

fn pct_of(used: Option<u64>, max: Option<u64>) -> Option<f64> {
    match (used, max) {
        (Some(u), Some(m)) if m > 0 => Some(u as f64 / m as f64),
        _ => None,
    }
}

/// Worst disk by await: (name, ms).
pub fn worst_await(k: &Kernel) -> Option<(&str, f32)> {
    k.disks
        .iter()
        .map(|d| (d.name.as_str(), d.r_await_ms.max(d.w_await_ms)))
        .filter(|(_, a)| a.is_finite())
        .max_by(|a, b| a.1.total_cmp(&b.1))
}

// ------------------------------------------------------------------------------- header

/// Lines 2-4 of the header in the server profile (`n` lines at most). Line 2: CPU with the
/// steal / iowait / irq split and run / blocked queues ("load high but CPU idle"). Line 3:
/// memory, PSI some/full, swap traffic. Line 4: OOM kills, failed units, fd / conntrack /
/// ephemeral-port use, worst disk await, network.
pub fn header_lines(app: &App, s: &Snapshot, w: usize, n: usize) -> Vec<Line<'static>> {
    let sys = &s.system;
    let k = s.kernel.as_ref();
    let cfg = &app.server_cfg;
    let mut out = Vec::with_capacity(3);

    // --- cpu
    let mut tail: Vec<Span> = Vec::new();
    if let Some(k) = k {
        let part = |label: &str, v: f32, warn: f32| {
            let st = if v >= warn {
                Style::default().fg(Color::Red).bold()
            } else if v >= warn / 2.0 {
                Style::default().fg(Color::Yellow)
            } else {
                dim()
            };
            vec![Span::styled(format!(" {label} "), dim()), Span::styled(format!("{v:.0}%"), st)]
        };
        // Steal and iowait matter well below 100%: a tenth of the CPU is already a story.
        tail.extend(part("st", k.steal_pct, 10.0));
        tail.extend(part("wa", k.iowait_pct, 10.0));
        if k.irq_pct + k.softirq_pct >= 1.0 {
            tail.extend(part("irq", k.irq_pct + k.softirq_pct, 10.0));
        }
        tail.push(Span::styled(format!("  R{}", k.procs_running), dim()));
        let d_style = if k.procs_blocked > 0 { Style::default().fg(Color::Yellow).bold() } else { dim() };
        tail.push(Span::styled(format!(" D{}", k.procs_blocked), d_style));
        if !k.d_state.is_empty() {
            tail.push(Span::styled(format!(" ({} stuck)", k.d_state.len()), Style::default().fg(Color::Red)));
        }
    }
    let tail_w: usize = tail.iter().map(|s| s.width()).sum();
    let cores_w = if sys.per_core.len() + 12 + tail_w < w / 2 { sys.per_core.len() } else { 0 };
    let spark_w = w.saturating_sub(10 + cores_w + 2 + tail_w);
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
    l2.extend(tail);
    out.push(Line::from(l2));
    if n < 2 {
        return out;
    }

    // --- memory
    let ratio = if sys.mem_total > 0 { sys.mem_used as f64 / sys.mem_total as f64 } else { 0.0 };
    let psi: Option<Psi> = k
        .and_then(|k| k.pressure)
        .map(|p| Psi {
            cpu_some: p.cpu_some,
            mem_some: p.mem_some,
            mem_full: p.mem_full,
            io_some: p.io_some,
            io_full: p.io_full,
        })
        .or(sys.psi);
    let bw = (w / 6).clamp(8, 30);
    let mut l3 = vec![
        Span::styled("MEM ", Style::default().fg(ACCENT).bold()),
        Span::styled(bar(ratio, bw), Style::default().fg(pct_color((ratio * 100.0) as f32))),
        Span::raw(format!(" {}/{}", fmt_bytes(sys.mem_used), fmt_bytes(sys.mem_total))),
    ];
    if let Some(k) = k.filter(|k| k.mem_available > 0) {
        l3.push(Span::styled(format!(" avail {}", fmt_bytes(k.mem_available)), dim()));
    }
    if let Some(p) = &psi {
        l3.extend(psi_spans(p));
    }
    if sys.swap_total > 0 || sys.swap_used > 0 {
        l3.push(Span::styled("  SWP ", Style::default().fg(ACCENT)));
        l3.push(Span::raw(format!("{}/{}", fmt_bytes(sys.swap_used), fmt_bytes(sys.swap_total))));
        if let Some(k) = k.filter(|k| k.swap_in_ps + k.swap_out_ps >= 1.0) {
            l3.push(Span::styled(
                format!(" in {:.0}/s out {:.0}/s", k.swap_in_ps, k.swap_out_ps),
                Style::default().fg(Color::Yellow),
            ));
        }
    }
    out.push(Line::from(l3));
    if n < 3 {
        return out;
    }

    // --- incidents in numbers
    let mut l4: Vec<Span> = Vec::new();
    let label = |t: &str| Span::styled(format!("{t} "), Style::default().fg(ACCENT).bold());
    let ring_ooms = app
        .event_ring
        .iter()
        .filter(|e| e.kind == crate::server::EventKind::OomKill && e.ts >= app.now - 86_400_000)
        .count() as u64;
    let (oom, oom_label) = match app.oom_24h {
        Some(n) => (n.max(ring_ooms), "OOM/24h"),
        None => (ring_ooms, "OOM"),
    };
    l4.push(label(oom_label));
    l4.push(Span::styled(
        oom.to_string(),
        if oom > 0 { Style::default().fg(Color::Red).bold() } else { Style::default().fg(Color::Green) },
    ));
    let failed = s.units.iter().filter(|u| u.is_failed()).count();
    let flapping = s.units.iter().filter(|u| u.flapping && !u.is_failed()).count();
    l4.push(Span::raw("  "));
    l4.push(label("FAILED"));
    l4.push(Span::styled(
        failed.to_string(),
        if failed > 0 { Style::default().fg(Color::Red).bold() } else { Style::default().fg(Color::Green) },
    ));
    if flapping > 0 {
        l4.push(Span::styled(format!(" ⟳{flapping}"), Style::default().fg(Color::Yellow).bold()));
    }
    if let Some(k) = k {
        for (name, r) in [
            ("FD", pct_of(k.fd_used, k.fd_max)),
            ("CT", pct_of(k.conntrack_used, k.conntrack_max)),
            ("EPH", pct_of(k.ephemeral_used, k.ephemeral_range.map(|(a, b)| (b as u64).saturating_sub(a as u64) + 1))),
        ] {
            if let Some(r) = r {
                l4.push(Span::raw("  "));
                l4.push(label(name));
                l4.push(Span::styled(
                    format!("{:.0}%", r * 100.0),
                    Style::default().fg(limit_color(r, cfg.exhaustion_warn)),
                ));
            }
        }
        if let Some((d, a)) = worst_await(k) {
            let st = if a >= cfg.disk_await_warn_ms {
                Style::default().fg(Color::Red).bold()
            } else if a >= cfg.disk_await_warn_ms / 2.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            l4.push(Span::raw("  "));
            l4.push(label("AWAIT"));
            l4.push(Span::styled(format!("{d} {a:.0}ms"), st));
        }
        if !k.mdraid.iter().all(|m| !m.degraded) {
            l4.push(Span::styled("  RAID degraded", Style::default().fg(Color::Red).bold()));
        }
        if !k.ro_remounts.is_empty() {
            l4.push(Span::styled(format!("  RO {}", k.ro_remounts.join(",")), Style::default().fg(Color::Red).bold()));
        }
        if k.ntp_synced == Some(false) {
            l4.push(Span::styled("  clock unsynced", Style::default().fg(Color::Yellow)));
        }
    }
    let used: usize = l4.iter().map(|s| s.width()).sum();
    let net = format!("  NET ↓{}/s ↑{}/s", fmt_bytes(sys.net_rx_bps), fmt_bytes(sys.net_tx_bps));
    if used + net.len() < w {
        l4.push(Span::styled(net, dim()));
    }
    out.push(Line::from(l4));
    out
}

// ------------------------------------------------------------------------------- tabs

/// Badge next to a server tab title.
pub fn tab_badge(app: &App, t: Tab) -> Option<Span<'static>> {
    match t {
        Tab::Services => {
            let failed = app.units().iter().filter(|u| u.is_failed()).count();
            let flap = app.units().iter().filter(|u| u.flapping && !u.is_failed()).count();
            if failed > 0 {
                Some(Span::styled(format!(" ✗{failed}"), Style::default().fg(Color::Red).bold()))
            } else if flap > 0 {
                Some(Span::styled(format!(" ⟳{flap}"), Style::default().fg(Color::Yellow).bold()))
            } else {
                None
            }
        }
        Tab::Events => {
            // Something notable in the last 15 minutes of this session.
            let recent = app.event_ring.iter().rev().take_while(|e| e.ts >= app.now - 15 * 60_000);
            let (mut c, mut wn) = (0, 0);
            for e in recent {
                match e.severity {
                    Severity::Crit => c += 1,
                    Severity::Warn => wn += 1,
                    Severity::Info => {}
                }
            }
            if c > 0 {
                Some(Span::styled(format!(" {c}"), Style::default().fg(Color::Red).bold()))
            } else if wn > 0 {
                Some(Span::styled(format!(" {wn}"), Style::default().fg(Color::Yellow)))
            } else {
                None
            }
        }
        Tab::Fleet if app.fleet.active() => {
            let (_, bad, crit, _) = app.fleet.tally();
            if bad + crit > 0 {
                Some(Span::styled(format!(" ⚠{}", bad + crit), Style::default().fg(Color::Red).bold()))
            } else {
                None
            }
        }
        _ => None,
    }
}

// ------------------------------------------------------------------------------- services

#[derive(Clone, Copy, PartialEq)]
enum UCol {
    Mark,
    Name,
    Kind,
    State,
    Since,
    Cpu,
    Mem,
    Limit,
    Io,
    Restarts,
    Throttle,
    Pids,
    Desc,
}

fn unit_columns(width: u16) -> &'static [UCol] {
    use UCol::*;
    if width >= 140 {
        &[Mark, Name, Kind, State, Since, Cpu, Mem, Limit, Io, Restarts, Throttle, Pids, Desc]
    } else if width >= 110 {
        &[Mark, Name, Kind, State, Since, Cpu, Mem, Limit, Io, Restarts, Throttle]
    } else if width >= 76 {
        &[Mark, Name, State, Cpu, Mem, Limit, Restarts, Kind]
    } else if width >= 50 {
        &[Mark, Name, State, Cpu, Mem]
    } else {
        &[Mark, Name, State]
    }
}

fn ucol_width(c: UCol) -> Constraint {
    match c {
        UCol::Mark => Constraint::Length(1),
        UCol::Name => Constraint::Min(18),
        UCol::Kind => Constraint::Length(9),
        UCol::State => Constraint::Length(19),
        UCol::Since => Constraint::Length(6),
        UCol::Cpu => Constraint::Length(6),
        UCol::Mem | UCol::Io => Constraint::Length(7),
        UCol::Limit => Constraint::Length(5),
        UCol::Restarts => Constraint::Length(6),
        UCol::Throttle => Constraint::Length(5),
        UCol::Pids => Constraint::Length(5),
        UCol::Desc => Constraint::Min(12),
    }
}

fn ucol_title(c: UCol, app: &App) -> Cell<'static> {
    use crate::tui::server::UnitSort as S;
    let (t, key, right) = match c {
        UCol::Mark => ("", None, false),
        UCol::Name => ("UNIT", Some(S::Name), false),
        UCol::Kind => ("KIND", None, false),
        UCol::State => ("STATE", Some(S::State), false),
        UCol::Since => ("SINCE", None, true),
        UCol::Cpu => ("CPU%", Some(S::Cpu), true),
        UCol::Mem => ("MEM", Some(S::Mem), true),
        UCol::Limit => ("LIM%", None, true),
        UCol::Io => ("IO", Some(S::Io), true),
        UCol::Restarts => ("↻", Some(S::Restarts), true),
        UCol::Throttle => ("THR%", None, true),
        UCol::Pids => ("PIDS", None, true),
        UCol::Desc => ("DESCRIPTION / IMAGE", None, false),
    };
    let sorted = key == Some(app.svc.sort);
    let text = if sorted { format!("{t}{}", if app.svc.natural { "▼" } else { "▲" }) } else { t.to_string() };
    let st = if sorted { Style::default().fg(ACCENT).bold() } else { Style::default().bold() };
    let line = Line::styled(text, st);
    Cell::from(if right { line.alignment(ratatui::layout::Alignment::Right) } else { line })
}

fn state_style(u: &Unit) -> Style {
    match unit_rank(u) {
        0 => Style::default().fg(Color::Red).bold(),
        1 | 2 => Style::default().fg(Color::Yellow).bold(),
        3 => dim(),
        4 => Style::default().fg(Color::Green),
        _ => dim(),
    }
}

fn unit_cell<'a>(c: UCol, u: &'a Unit, app: &App, first_of_kind: bool) -> Cell<'a> {
    let warn = app.server_cfg.exhaustion_warn;
    match c {
        UCol::Mark => {
            let (m, st) = if u.is_failed() {
                ("✗", Style::default().fg(Color::Red).bold())
            } else if u.flapping {
                ("⟳", Style::default().fg(Color::Yellow).bold())
            } else if unit_is_problem(u, warn) {
                ("!", Style::default().fg(Color::Yellow))
            } else {
                (" ", Style::default())
            };
            Cell::from(Span::styled(m, st))
        }
        UCol::Name => {
            let name = match (&u.kind, &u.container) {
                (UnitKind::Container, Some(c)) if !c.name.is_empty() => c.name.as_str(),
                _ => u.name.as_str(),
            };
            let st = if u.is_failed() { Style::default().fg(Color::Red).bold() } else { Style::default().bold() };
            Cell::from(Span::styled(name, st))
        }
        UCol::Kind => {
            let st = if app.svc.group && first_of_kind { Style::default().fg(ACCENT).bold() } else { dim() };
            let txt = if app.svc.group && !first_of_kind { "" } else { unit_kind_label(u) };
            Cell::from(Span::styled(txt, st))
        }
        UCol::State => {
            let mut s = u.state.clone();
            if u.is_failed() && !u.result.is_empty() {
                s = format!("failed {}", u.result);
            } else if !u.sub_state.is_empty() && u.sub_state != u.state {
                s = format!("{} {}", u.state, u.sub_state);
            }
            if u.flapping && !u.is_failed() {
                s = format!("flapping {s}");
            }
            Cell::from(Span::styled(s, state_style(u)))
        }
        UCol::Since => match u.since {
            Some(t) => num(fmt_dur_short(((app.now - t).max(0) / 1000) as u64), dim()),
            None => Cell::from(""),
        },
        // max(0): a counter reset between samples must not print "-0.0".
        UCol::Cpu => num(format!("{:.1}", u.cpu.max(0.0)), cpu_style(u.cpu)),
        UCol::Mem => num(fmt_bytes(u.mem), mem_style(u.mem)),
        UCol::Limit => match mem_limit_ratio(u) {
            Some(r) => num(format!("{:.0}", r * 100.0), Style::default().fg(limit_color(r, warn))),
            None => num("-".into(), dim()),
        },
        UCol::Io => {
            let r = u.io_read_bps + u.io_write_bps;
            num(fmt_rate(r), rate_style(r))
        }
        UCol::Restarts => {
            let st = if u.flapping {
                Style::default().fg(Color::Red).bold()
            } else if u.recent_restarts > 0 {
                Style::default().fg(Color::Yellow)
            } else {
                dim()
            };
            let txt = if u.recent_restarts > 0 {
                format!("{}/{}", u.recent_restarts, u.restarts)
            } else {
                u.restarts.to_string()
            };
            num(txt, st)
        }
        UCol::Throttle => {
            if u.cpu_throttled_pct > 0.0 {
                num(
                    format!("{:.0}", u.cpu_throttled_pct),
                    Style::default().fg(if u.cpu_throttled_pct >= 25.0 { Color::Red } else { Color::Yellow }),
                )
            } else {
                num("-".into(), dim())
            }
        }
        UCol::Pids => num(u.pids.to_string(), dim()),
        UCol::Desc => {
            let d = match &u.container {
                Some(c) if !c.image.is_empty() => {
                    let pod = c
                        .pod
                        .as_ref()
                        .map(|p| format!(" · pod {}/{p}", c.namespace.as_deref().unwrap_or("-")))
                        .unwrap_or_default();
                    let health = c.health.as_ref().map(|h| format!(" · {h}")).unwrap_or_default();
                    format!("{}{pod}{health}", c.image)
                }
                _ => u.description.clone(),
            };
            Cell::from(Span::styled(d, dim()))
        }
    }
}

pub fn draw_services(f: &mut Frame, app: &mut App, area: Rect) {
    let body_h = area.height.saturating_sub(2) as usize;
    let len = app.svc.rows.len();
    scroll_into_view(app.svc.sel, &mut app.svc.offset, body_h, len);
    let app = &*app;
    let block = Block::default().borders(Borders::TOP).border_style(dim());
    let Some(snap) = app.view() else {
        let msg = if app.rewound() { "no snapshot recorded at this moment" } else { "waiting for the first sample…" };
        f.render_widget(Paragraph::new(msg).style(dim()).block(block.title(" Services ")), area);
        return;
    };
    let units = &snap.units;
    let failed = units.iter().filter(|u| u.is_failed()).count();
    let flapping = units.iter().filter(|u| u.flapping && !u.is_failed()).count();
    let mut title = vec![
        Span::styled(" Services ", Style::default().bold()),
        Span::styled(format!("{}/{} ", len, units.len()), dim()),
    ];
    if failed > 0 {
        title.push(Span::styled(format!("✗ {failed} failed "), Style::default().fg(Color::Red).bold()));
    }
    if flapping > 0 {
        title.push(Span::styled(format!("⟳ {flapping} flapping "), Style::default().fg(Color::Yellow).bold()));
    }
    title.push(Span::raw(format!("· sort {}{} ", app.svc.sort.label(), if app.svc.natural { "▼" } else { "▲" })));
    if app.svc.group {
        let mut kinds: Vec<(UnitKind, usize)> = Vec::new();
        for u in units {
            match kinds.iter_mut().find(|(k, _)| *k == u.kind) {
                Some((_, n)) => *n += 1,
                None => kinds.push((u.kind, 1)),
            }
        }
        kinds.sort();
        let s: Vec<String> = kinds.iter().map(|(k, n)| format!("{} {n}", k.as_str())).collect();
        title.push(Span::styled(format!("· by kind: {} ", s.join(", ")), Style::default().fg(Color::Green)));
    }
    if app.svc.problems_only {
        title.push(Span::styled("· problems only ", Style::default().fg(Color::Yellow)));
    }
    if app.svc.hidden > 0 {
        title.push(Span::styled(format!("· {} inactive hidden (i) ", app.svc.hidden), dim()));
    }
    if !app.svc.filter.is_empty() {
        title.push(Span::styled(format!("· /{} ", app.svc.filter), Style::default().fg(Color::Yellow)));
    }
    if let Some(ts) = app.cursor {
        title.push(Span::styled(format!("· ⏪ {} ", fmt_clock(ts)), Style::default().fg(Color::Magenta).bold()));
    }
    let block = block.title(Line::from(title));

    if units.is_empty() {
        let mut t = Text::default();
        t.lines.push(Line::styled("No services found yet.", Style::default().bold()));
        t.lines.push(Line::styled(
            "fat reads systemd (when present), container runtimes and cgroup v2; none of them answered on this host.",
            dim(),
        ));
        if let Some(k) = &snap.kernel {
            for n in k.notes.iter().take(4) {
                t.lines.push(Line::styled(format!("• {n}"), dim()));
            }
        }
        f.render_widget(Paragraph::new(t).wrap(Wrap { trim: false }).block(block), area);
        return;
    }

    let cols = unit_columns(area.width);
    let header = Row::new(cols.iter().map(|&c| ucol_title(c, app)));
    let rows = app.svc.rows.iter().enumerate().skip(app.svc.offset).take(body_h).map(|(i, &idx)| {
        let u = &units[idx];
        let first = i == 0 || app.svc.rows.get(i - 1).is_none_or(|&p| units[p].kind != u.kind);
        let mut row = Row::new(cols.iter().map(|&c| unit_cell(c, u, app, first)));
        if i == app.svc.sel {
            row = row.style(Style::default().bg(SEL_BG));
        }
        row
    });
    let table = Table::new(rows, cols.iter().map(|&c| ucol_width(c))).header(header).column_spacing(1).block(block);
    f.render_widget(table, area);
    if len == 0 {
        let r = Rect { y: area.y + 2, height: 1, ..area };
        let msg = if app.svc.filter.is_empty() {
            "nothing to show — f shows all, i shows inactive units"
        } else {
            "no unit matches — Esc clears the filter"
        };
        f.render_widget(Paragraph::new(msg).style(dim()), r);
    }
}

// ------------------------------------------------------------------------------- events

pub fn draw_events(f: &mut Frame, app: &mut App, area: Rect) {
    let body_h = area.height.saturating_sub(2) as usize;
    let len = app.ev.rows.len();
    scroll_into_view(app.ev.sel, &mut app.ev.offset, body_h, len);
    let app = &*app;
    let (i, w, c) = app.ev.counts();
    let source = if app.ev.recorded.is_some() { "recorder + live" } else { "this session only" };
    let mut title = vec![
        Span::styled(" Events ", Style::default().bold()),
        Span::styled(format!("last {} ", EVENT_WINDOW_NAMES[app.ev.window]), Style::default().fg(Color::Yellow)),
    ];
    if c > 0 {
        title.push(Span::styled(format!("{c} crit "), Style::default().fg(Color::Red).bold()));
    }
    if w > 0 {
        title.push(Span::styled(format!("{w} warn "), Style::default().fg(Color::Yellow)));
    }
    title.push(Span::styled(format!("{i} info · {source} "), dim()));
    if app.ev.min_sev != Severity::Info {
        title.push(Span::styled(format!("· {}+ only ", app.ev.min_sev.as_str()), Style::default().fg(Color::Yellow)));
    }
    if !app.ev.filter.is_empty() {
        title.push(Span::styled(format!("· /{} ", app.ev.filter), Style::default().fg(Color::Yellow)));
    }
    let block = Block::default().borders(Borders::TOP).border_style(dim()).title(Line::from(title));
    if app.ev.merged.is_empty() {
        let mut t = Text::default();
        t.lines.push(Line::styled(
            format!("No events in the last {}.", EVENT_WINDOW_NAMES[app.ev.window]),
            Style::default().fg(Color::Green).bold(),
        ));
        t.lines.push(Line::styled(
            "Events (OOM kills, failed or flapping units, disk latency, exhaustion, kernel warnings…) appear as they are detected.",
            dim(),
        ));
        if app.ev.recorded.is_none() {
            t.lines.push(Line::styled(
                "For history across restarts, keep `fat record --server` running (see README).",
                dim(),
            ));
        }
        t.lines.push(Line::styled("+/- widen the window · W explains what happened recently", dim()));
        f.render_widget(Paragraph::new(t).wrap(Wrap { trim: false }).block(block), area);
        return;
    }
    let long = app.ev.window_ms() > 86_400_000;
    let wide = area.width >= 100;
    let mut widths = vec![Constraint::Length(if long { 14 } else { 8 }), Constraint::Length(4), Constraint::Length(18)];
    let mut heads = vec!["TIME", "SEV", "KIND"];
    if wide {
        widths.push(Constraint::Length(28));
        heads.push("SUBJECT");
    }
    widths.push(Constraint::Min(10));
    heads.push("WHAT");
    let header = Row::new(heads.into_iter().map(|h| Cell::from(Span::styled(h, Style::default().bold()))));
    let rows = app.ev.rows.iter().enumerate().skip(app.ev.offset).take(body_h).map(|(i, &idx)| {
        let e = &app.ev.merged[idx];
        let mut cells = vec![
            Cell::from(Span::styled(if long { fmt_datetime(e.ts) } else { fmt_clock(e.ts) }, dim())),
            Cell::from(Span::styled(sev_tag(e.severity), sev_style(e.severity))),
            Cell::from(Span::styled(e.kind.as_str(), Style::default().bold())),
        ];
        if wide {
            cells.push(Cell::from(Span::raw(e.subject.as_str())));
        }
        let what =
            if wide || e.subject.is_empty() { e.detail.clone() } else { format!("{} — {}", e.subject, e.detail) };
        cells.push(Cell::from(what));
        let mut row = Row::new(cells);
        if i == app.ev.sel {
            row = row.style(Style::default().bg(SEL_BG));
        }
        row
    });
    f.render_widget(Table::new(rows, widths).header(header).column_spacing(1).block(block), area);
    if len == 0 {
        let r = Rect { y: area.y + 2, height: 1, ..area };
        f.render_widget(
            Paragraph::new("no event matches — Esc clears the filter, f changes the severity").style(dim()),
            r,
        );
    }
}

// ------------------------------------------------------------------------------- fleet

#[derive(Clone, Copy, PartialEq)]
enum HCol {
    Name,
    Health,
    Cpu,
    Mem,
    Load,
    Disk,
    Find,
    Units,
    Oom,
    Lat,
    Age,
    Top,
}

fn host_columns(width: u16) -> &'static [HCol] {
    use HCol::*;
    if width >= 150 {
        &[Name, Health, Cpu, Mem, Load, Disk, Find, Units, Oom, Lat, Age, Top]
    } else if width >= 110 {
        &[Name, Health, Cpu, Mem, Load, Disk, Find, Units, Lat, Top]
    } else if width >= 76 {
        &[Name, Health, Cpu, Mem, Disk, Find, Top]
    } else {
        &[Name, Health, Find]
    }
}

fn hcol(c: HCol) -> (&'static str, Constraint, Option<crate::tui::server::FleetSort>, bool) {
    use crate::tui::server::FleetSort as S;
    match c {
        HCol::Name => ("HOST", Constraint::Min(14), Some(S::Name), false),
        HCol::Health => ("HEALTH", Constraint::Length(9), Some(S::Health), false),
        HCol::Cpu => ("CPU%", Constraint::Length(5), Some(S::Cpu), true),
        HCol::Mem => ("MEM%", Constraint::Length(5), Some(S::Mem), true),
        HCol::Load => ("LOAD", Constraint::Length(9), None, true),
        HCol::Disk => ("DISK", Constraint::Length(14), Some(S::Disk), false),
        HCol::Find => ("FIND", Constraint::Length(7), Some(S::Findings), false),
        HCol::Units => ("✗UNIT", Constraint::Length(5), None, true),
        HCol::Oom => ("OOM", Constraint::Length(4), None, true),
        HCol::Lat => ("RTT", Constraint::Length(6), Some(S::Latency), true),
        HCol::Age => ("AGE", Constraint::Length(5), None, true),
        HCol::Top => ("TOP FINDING", Constraint::Min(14), None, false),
    }
}

fn health_color(h: u8) -> Color {
    if h >= 80 {
        Color::Green
    } else if h >= 50 {
        Color::Yellow
    } else {
        Color::Red
    }
}

fn host_cell(c: HCol, h: &FleetHost) -> Cell<'_> {
    if !h.ok {
        return match c {
            HCol::Name => Cell::from(Span::styled(h.name.as_str(), Style::default().fg(Color::Red).bold())),
            HCol::Health => Cell::from(Span::styled("✗ down", Style::default().fg(Color::Red).bold())),
            HCol::Top => Cell::from(Span::styled(
                h.error.clone().unwrap_or_else(|| "unreachable".into()),
                Style::default().fg(Color::Red),
            )),
            HCol::Lat => num(format!("{}ms", h.latency_ms), dim()),
            _ => Cell::from(""),
        };
    }
    match c {
        HCol::Name => Cell::from(Span::styled(h.name.as_str(), Style::default().bold())),
        HCol::Health => {
            let col = health_color(h.health);
            Cell::from(Line::from(vec![
                Span::styled(bar(h.health as f64 / 100.0, 5), Style::default().fg(col)),
                Span::styled(format!("{:>3}", h.health), Style::default().fg(col).bold()),
            ]))
        }
        HCol::Cpu => num(format!("{:.0}", h.cpu), Style::default().fg(pct_color(h.cpu))),
        HCol::Mem => num(format!("{:.0}", h.mem_pct), Style::default().fg(pct_color(h.mem_pct))),
        HCol::Load => {
            let per = if h.cores > 0 { h.load1 / h.cores as f64 } else { 0.0 };
            let st = if per >= 2.0 {
                Style::default().fg(Color::Red)
            } else if per >= 1.0 {
                Style::default().fg(Color::Yellow)
            } else {
                dim()
            };
            num(format!("{:.1}/{}", h.load1, h.cores), st)
        }
        HCol::Disk => {
            if h.disk_worst_mount.is_empty() {
                Cell::from("")
            } else {
                Cell::from(Line::from(vec![
                    Span::styled(
                        format!("{:>3.0}% ", h.disk_worst_pct),
                        Style::default().fg(pct_color(h.disk_worst_pct)),
                    ),
                    Span::styled(h.disk_worst_mount.as_str(), dim()),
                ]))
            }
        }
        HCol::Find => {
            let f = h.findings;
            let mut v = Vec::new();
            if f.crit > 0 {
                v.push(Span::styled(format!("{}c ", f.crit), Style::default().fg(Color::Red).bold()));
            }
            if f.warn > 0 {
                v.push(Span::styled(format!("{}w", f.warn), Style::default().fg(Color::Yellow)));
            }
            if v.is_empty() {
                v.push(Span::styled("✓", Style::default().fg(Color::Green)));
            }
            Cell::from(Line::from(v))
        }
        HCol::Units => num(
            h.units_failed.to_string(),
            if h.units_failed > 0 { Style::default().fg(Color::Red).bold() } else { dim() },
        ),
        HCol::Oom => {
            num(h.oom_24h.to_string(), if h.oom_24h > 0 { Style::default().fg(Color::Red).bold() } else { dim() })
        }
        HCol::Lat => num(format!("{}ms", h.latency_ms), dim()),
        HCol::Age => num(if h.age_ms > 0 { fmt_dur_short((h.age_ms / 1000) as u64) } else { "live".into() }, dim()),
        HCol::Top => Cell::from(Span::styled(h.top_finding.clone().unwrap_or_default(), Style::default())),
    }
}

pub fn draw_fleet(f: &mut Frame, app: &mut App, area: Rect) {
    if app.fleet.drill.is_some() {
        draw_drill(f, app, area);
        return;
    }
    let show_findings = !app.fleet.findings.is_empty();
    if show_findings && app.fleet.focus_findings && area.width < 130 && area.height < 20 {
        // No room for both: the findings take the whole view while browsed.
        draw_fleet_findings(f, app, area);
        return;
    }
    let (table_area, find_area) = if show_findings && area.width >= 130 {
        let [a, b] = Layout::horizontal([Constraint::Percentage(64), Constraint::Percentage(36)]).areas(area);
        (a, Some(b))
    } else if show_findings && area.height >= 20 {
        let fh = ((app.fleet.findings.len() * 2 + 1) as u16).min(area.height / 3).max(4);
        let [a, b] = Layout::vertical([Constraint::Min(6), Constraint::Length(fh)]).areas(area);
        (a, Some(b))
    } else {
        (area, None)
    };

    let body_h = table_area.height.saturating_sub(2) as usize;
    let len = app.fleet.rows.len();
    scroll_into_view(app.fleet.sel, &mut app.fleet.offset, body_h, len);
    let app = &*app;
    let fl = &app.fleet;
    let (ok, bad, crit, warn) = fl.tally();
    let total = fl.targets.unwrap_or(0).max(fl.hosts.len());
    let mut title =
        vec![Span::styled(" Fleet ", Style::default().bold()), Span::styled(format!("{total} hosts "), dim())];
    if fl.polling {
        let secs = (app.now - fl.poll_started).max(0) / 1000;
        title.push(Span::styled(
            format!("polling {}/{} {secs}s ", fl.answered, total),
            Style::default().fg(ACCENT).bold(),
        ));
    }
    title.push(Span::styled(format!("✓{ok} "), Style::default().fg(Color::Green)));
    if bad > 0 {
        title.push(Span::styled(format!("✗{bad} down "), Style::default().fg(Color::Red).bold()));
    }
    if crit > 0 {
        title.push(Span::styled(format!("{crit} crit "), Style::default().fg(Color::Red)));
    }
    if warn > 0 {
        title.push(Span::styled(format!("{warn} warn "), Style::default().fg(Color::Yellow)));
    }
    // Narrow: the findings live behind →; say so before the less important parts.
    if find_area.is_none() && !fl.findings.is_empty() {
        title.push(Span::styled(format!("· {} findings → ", fl.findings.len()), Style::default().fg(ACCENT)));
    }
    if !fl.polling && fl.last_done > 0 {
        title.push(Span::styled(
            format!(
                "· polled {} ago in {:.1}s ",
                fmt_dur_short(((app.now - fl.last_done).max(0) / 1000) as u64),
                fl.last_elapsed_ms as f64 / 1000.0
            ),
            dim(),
        ));
    }
    title.push(Span::raw(format!("· sort {}{} ", fl.sort.label(), if fl.natural { "▼" } else { "▲" })));
    if let Some((t, set)) = &fl.only {
        title.push(Span::styled(
            format!("· {} hosts with \"{}\" ", set.len(), clip(t, 40)),
            Style::default().fg(Color::Yellow),
        ));
    }
    if !fl.filter.is_empty() {
        title.push(Span::styled(format!("· /{} ", fl.filter), Style::default().fg(Color::Yellow)));
    }
    let block = Block::default().borders(Borders::TOP).border_style(dim()).title(Line::from(title));

    if fl.hosts.is_empty() {
        let mut t = Text::default();
        if let Some(e) = &fl.inventory_error {
            t.lines.push(Line::styled(format!("inventory unreadable: {e}"), Style::default().fg(Color::Red)));
        } else if fl.polling {
            t.lines.push(Line::styled(format!("asking {total} host(s) for a read-only snapshot over ssh…"), dim()));
        } else {
            t.lines.push(Line::styled("no answers yet — r polls now", dim()));
        }
        f.render_widget(Paragraph::new(t).block(block), table_area);
    } else {
        let cols = host_columns(table_area.width);
        let header = Row::new(cols.iter().map(|&c| {
            let (t, _, key, right) = hcol(c);
            let sorted = key == Some(fl.sort);
            let text = if sorted { format!("{t}{}", if fl.natural { "▼" } else { "▲" }) } else { t.to_string() };
            let line =
                Line::styled(text, if sorted { Style::default().fg(ACCENT).bold() } else { Style::default().bold() });
            Cell::from(if right { line.alignment(ratatui::layout::Alignment::Right) } else { line })
        }));
        let rows = fl.rows.iter().enumerate().skip(fl.offset).take(body_h).map(|(i, &idx)| {
            let h = &fl.hosts[idx];
            let mut row = Row::new(cols.iter().map(|&c| host_cell(c, h)));
            if i == fl.sel && !fl.focus_findings {
                row = row.style(Style::default().bg(SEL_BG));
            }
            row
        });
        f.render_widget(
            Table::new(rows, cols.iter().map(|&c| hcol(c).1)).header(header).column_spacing(1).block(block),
            table_area,
        );
        if len == 0 {
            let r = Rect { y: table_area.y + 2, height: 1, ..table_area };
            f.render_widget(Paragraph::new("no host matches — Esc clears the filter").style(dim()), r);
        }
    }

    if let Some(fa) = find_area {
        draw_fleet_findings(f, app, fa);
    }
}

fn draw_fleet_findings(f: &mut Frame, app: &App, area: Rect) {
    let fl = &app.fleet;
    let focus = fl.focus_findings;
    let block = Block::default()
        .borders(Borders::TOP | Borders::LEFT)
        .border_style(if focus { Style::default().fg(ACCENT) } else { dim() })
        .title(Line::from(vec![
            Span::styled(" Fleet findings ", Style::default().bold()),
            Span::styled(if focus { "⏎ show those hosts · ← hosts " } else { "→ to browse " }, dim()),
        ]));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let per = 2usize;
    let visible = (inner.height as usize / per).max(1);
    let mut offset = 0;
    scroll_into_view(fl.finding_sel, &mut offset, visible, fl.findings.len());
    let w = inner.width as usize;
    let mut lines: Vec<Line> = Vec::with_capacity(visible * per);
    for (i, x) in fl.findings.iter().enumerate().skip(offset).take(visible) {
        let sel = focus && i == fl.finding_sel;
        let bg = if sel { Style::default().bg(SEL_BG) } else { Style::default() };
        lines.push(
            Line::from(vec![
                Span::styled(
                    format!("{} ", sev_tag(x.severity)),
                    sev_style(x.severity).add_modifier(Modifier::REVERSED),
                ),
                Span::styled(format!(" {:>4} ", x.count), Style::default().bold()),
                Span::styled(clip(&x.title, w.saturating_sub(12)).to_string(), Style::default().bold()),
            ])
            .style(bg),
        );
        let mut names = String::new();
        for (j, h) in x.hosts.iter().enumerate() {
            let add = if j == 0 { h.clone() } else { format!(", {h}") };
            if names.len() + add.len() + 8 > w.saturating_sub(7) {
                names.push_str(&format!(" +{}", x.count.saturating_sub(j)));
                break;
            }
            names.push_str(&add);
        }
        lines.push(Line::from(vec![Span::raw("       "), Span::styled(names, dim())]).style(bg));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_drill(f: &mut Frame, app: &App, area: Rect) {
    let Some(d) = app.fleet.drill.as_ref() else { return };
    let tab = |v: DrillView, label: &'static str| {
        if d.view == v {
            Span::styled(format!(" {label} "), Style::default().fg(Color::Black).bg(ACCENT).bold())
        } else {
            Span::styled(format!(" {label} "), dim())
        }
    };
    let title = Line::from(vec![
        Span::styled(format!(" {} ", d.name), Style::default().bold()),
        Span::styled("read-only snapshot ", dim()),
        tab(DrillView::Doctor, "d Doctor"),
        tab(DrillView::Units, "u Units"),
        tab(DrillView::Procs, "p Procs"),
        Span::styled(" r refresh · Esc back ", dim()),
    ]);
    let block = Block::default().borders(Borders::TOP).border_style(Style::default().fg(ACCENT)).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let Some(s) = d.snap.as_deref() else {
        let msg = if d.loading() {
            Line::styled(format!("fetching {}'s snapshot over ssh (read-only)…", d.name), dim())
        } else {
            Line::styled(
                format!("could not fetch {}: {}", d.name, d.error.as_deref().unwrap_or("unknown error")),
                Style::default().fg(Color::Red),
            )
        };
        f.render_widget(Paragraph::new(msg).wrap(Wrap { trim: false }), inner);
        return;
    };
    let [info, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
    let sys = &s.system;
    let mut iv = vec![
        Span::styled(format!("cpu {:.0}% ", sys.cpu), Style::default().fg(pct_color(sys.cpu))),
        Span::raw(format!("mem {}/{} ", fmt_bytes(sys.mem_used), fmt_bytes(sys.mem_total))),
        Span::raw(format!("load {:.2} /{}c ", sys.load[0], sys.cores)),
        Span::styled(format!("{} procs · {} units ", s.procs.len(), s.units.len()), dim()),
    ];
    if let Some(m) = &s.meta {
        iv.push(Span::styled(format!("· fat {} {} {}", m.version, m.profile.as_str(), m.source), dim()));
        if m.age_ms > 0 {
            iv.push(Span::styled(format!(" ({} old)", fmt_dur_short((m.age_ms / 1000) as u64)), dim()));
        }
    }
    f.render_widget(Paragraph::new(Line::from(iv)), info);
    draw_drill_body(f, app, d, s, body);
}

fn draw_drill_body(f: &mut Frame, app: &App, d: &HostDrill, s: &Snapshot, area: Rect) {
    let h = area.height.saturating_sub(1) as usize;
    let mut offset = 0;
    scroll_into_view(d.scroll, &mut offset, h, d.len());
    let sel = Style::default().bg(SEL_BG);
    match d.view {
        DrillView::Doctor => {
            if d.findings.is_empty() {
                f.render_widget(
                    Paragraph::new(Line::styled(
                        "✓ nothing unusual on this host",
                        Style::default().fg(Color::Green).bold(),
                    )),
                    area,
                );
                return;
            }
            let rows = d.findings.iter().enumerate().skip(offset).take(h).map(|(i, x)| {
                let r = Row::new(vec![
                    Cell::from(Span::styled(x.severity.to_uppercase(), severity_style(&x.severity))),
                    Cell::from(Span::styled(x.title.as_str(), Style::default().bold())),
                    Cell::from(Span::styled(x.detail.as_str(), dim())),
                ]);
                if i == d.scroll { r.style(sel) } else { r }
            });
            let header =
                Row::new(["SEV", "FINDING", "DETAIL"].map(|t| Cell::from(Span::styled(t, Style::default().bold()))));
            f.render_widget(
                Table::new(rows, [Constraint::Length(5), Constraint::Percentage(45), Constraint::Min(10)])
                    .header(header)
                    .column_spacing(1),
                area,
            );
        }
        DrillView::Units => {
            let mut idx: Vec<usize> = (0..s.units.len()).collect();
            idx.sort_by(|&a, &b| {
                unit_rank(&s.units[a]).cmp(&unit_rank(&s.units[b])).then(s.units[b].cpu.total_cmp(&s.units[a].cpu))
            });
            let cols = unit_columns(area.width);
            let header = Row::new(cols.iter().map(|&c| ucol_title(c, app)));
            let rows = idx.iter().enumerate().skip(offset).take(h).map(|(i, &j)| {
                let r = Row::new(cols.iter().map(|&c| unit_cell(c, &s.units[j], app, true)));
                if i == d.scroll { r.style(sel) } else { r }
            });
            f.render_widget(
                Table::new(rows, cols.iter().map(|&c| ucol_width(c))).header(header).column_spacing(1),
                area,
            );
        }
        DrillView::Procs => {
            let mut idx: Vec<usize> = (0..s.procs.len()).collect();
            idx.sort_by(|&a, &b| s.procs[b].cpu.total_cmp(&s.procs[a].cpu));
            let header = Row::new(
                ["PID", "CPU%", "MEM", "S", "NAME / CMD"].map(|t| Cell::from(Span::styled(t, Style::default().bold()))),
            );
            let rows = idx.iter().enumerate().skip(offset).take(h).map(|(i, &j)| {
                let p = &s.procs[j];
                let r = Row::new(vec![
                    num(p.pid.to_string(), Style::default()),
                    num(format!("{:.1}", p.cpu), cpu_style(p.cpu)),
                    num(fmt_bytes(p.mem), mem_style(p.mem)),
                    Cell::from(Span::styled(p.status.clone(), dim())),
                    Cell::from(Line::from(vec![
                        Span::styled(p.name.as_str(), Style::default().bold()),
                        Span::raw(" "),
                        Span::styled(clip(&p.cmd, 200), dim()),
                    ])),
                ]);
                if i == d.scroll { r.style(sel) } else { r }
            });
            f.render_widget(
                Table::new(
                    rows,
                    [
                        Constraint::Length(7),
                        Constraint::Length(6),
                        Constraint::Length(7),
                        Constraint::Length(1),
                        Constraint::Min(10),
                    ],
                )
                .header(header)
                .column_spacing(1),
                area,
            );
        }
    }
}

// ------------------------------------------------------------------------------- panel

pub fn draw_panel(f: &mut Frame, p: &Panel, area: Rect) {
    let r = centered(
        area.width.saturating_sub(area.width / 10).max(20),
        area.height.saturating_sub(area.height / 8).max(6),
        area,
    );
    let mut t = Text::default();
    let head_style = match p.severity {
        Severity::Crit => Style::default().fg(Color::Red).bold(),
        Severity::Warn => Style::default().fg(Color::Yellow).bold(),
        Severity::Info => Style::default().fg(ACCENT).bold(),
    };
    t.lines.push(Line::styled(p.headline.clone(), head_style));
    for (title, items) in &p.sections {
        t.lines.push(Line::raw(""));
        t.lines.push(Line::styled(title.clone(), Style::default().fg(ACCENT).bold()));
        for it in items {
            let lead =
                if title.starts_with("What you can do") || title.starts_with("Look closer") { "$ " } else { "• " };
            t.lines.push(Line::from(vec![Span::styled(lead, dim()), Span::raw(it.clone())]));
        }
    }
    if p.pending.is_some() {
        t.lines.push(Line::raw(""));
        t.lines.push(Line::styled("reading the recorder and the kernel log…", dim()));
    }
    let hint = match p.pid {
        Some(pid) => format!(" Esc close · ↑↓ PgUp/PgDn scroll · w why pid {pid} "),
        None => " Esc close · ↑↓ PgUp/PgDn scroll ".to_string(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Line::styled(format!(" {} ", p.title), Style::default().bold()))
        .title_bottom(Line::styled(hint, dim()));
    f.render_widget(Clear, r);
    f.render_widget(Paragraph::new(t).block(block).wrap(Wrap { trim: false }).scroll((p.scroll, 0)), r);
}

#[cfg(test)]
mod tests {
    use crate::server::{Incident, Severity};
    use crate::tui::app::{App, Tab};
    use crate::tui::server::tests::{fleet_app, server_app, server_snap};
    use crate::tui::ui::draw;
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

    const SIZES: [(u16, u16); 2] = [(80, 24), (200, 60)];

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    #[test]
    fn server_header_shows_the_3am_numbers() {
        for (w, h) in SIZES {
            let mut a = server_app();
            a.set_counts(Some(2));
            let out = render(&mut a, w, h);
            assert!(out.contains("web-01") && out.contains("/4c"), "{w}x{h}\n{out}");
            assert!(
                out.contains("st 14%") && out.contains("wa 22%") && out.contains("D9"),
                "steal/iowait/blocked {w}x{h}\n{out}"
            );
            assert!(out.contains("PSI cpu") && out.contains("io█31"), "{w}x{h}\n{out}");
            assert!(out.contains("OOM/24h 2") && out.contains("FAILED 1") && out.contains("⟳1"), "{w}x{h}\n{out}");
            assert!(out.contains("FD 10%") && out.contains("CT 88%"), "{w}x{h}\n{out}");
            assert!(out.contains("AWAIT nvme0n1 230ms"), "worst disk {w}x{h}\n{out}");
            assert!(out.contains("1Services") && out.contains("3Events"), "{w}x{h}\n{out}");
            assert!(!out.contains("PWR") && !out.contains("BAT"), "laptop gauges replaced\n{out}");
        }
        // recorder unknown: session count, labelled as such
        let mut a = server_app();
        let out = render(&mut a, 200, 60);
        assert!(out.contains("OOM 1"), "{out}");
    }

    #[test]
    fn services_tab_renders_300_units() {
        for (w, h) in SIZES {
            let mut a = server_app();
            let out = render(&mut a, w, h);
            assert!(
                out.contains("Services") && out.contains("✗ 1 failed") && out.contains("⟳ 1 flapping"),
                "{w}x{h}\n{out}"
            );
            assert!(out.contains("db.service") && out.contains("failed oom-kill"), "{w}x{h}\n{out}");
            assert!(out.contains("worker.service") && out.contains("flapping"), "{w}x{h}\n{out}");
            assert!(out.contains("inactive hidden"), "{w}x{h}\n{out}");
            assert!(out.contains("UNIT") && out.contains("STATE") && out.contains("CPU%"), "{w}x{h}\n{out}");
            if w >= 140 {
                assert!(
                    out.contains("THR%") && out.contains("LIM%") && out.contains("registry.example.com/app:1.0"),
                    "{out}"
                );
                assert!(out.contains("42") && out.contains("93"), "throttle and limit columns\n{out}");
            }
            // grouped by kind
            a.on_key(key('t'));
            let out = render(&mut a, w, h);
            assert!(out.contains("by kind: systemd"), "{w}x{h}\n{out}");
            // unit panel
            a.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            let out = render(&mut a, w, h);
            assert!(out.contains("Unit · db.service") && out.contains("result oom-kill"), "{w}x{h}\n{out}");
            if h >= 60 {
                assert!(out.contains("journalctl -u db.service") && out.contains("Recent events"), "{out}");
            }
        }
        // nothing found yet: says which sources were tried, no host assumptions
        let mut a = server_app();
        a.live.as_mut().unwrap().units.clear();
        a.svc.dirty = true;
        let out = render(&mut a, 80, 24);
        assert!(out.contains("No services found yet"), "{out}");
    }

    #[test]
    fn events_tab_and_incident_panel_render() {
        for (w, h) in SIZES {
            let mut a = server_app();
            a.switch_tab(Tab::Events);
            let out = render(&mut a, w, h);
            assert!(
                out.contains("Events") && out.contains("last 1h") && out.contains("1 crit") && out.contains("2 warn"),
                "{w}x{h}\n{out}"
            );
            assert!(
                out.contains("oom_kill") && out.contains("disk_latency_spike") && out.contains("CRIT"),
                "{w}x{h}\n{out}"
            );
            assert!(out.contains("this session only"), "{w}x{h}\n{out}");
            let cmds = a.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            let crate::tui::app::Command::ExplainEvent { id, .. } = cmds[0].clone() else { panic!() };
            let out = render(&mut a, w, h);
            assert!(out.contains("working it out"), "{w}x{h}\n{out}");
            a.set_incident(
                id,
                Ok(Incident {
                    host: "web-01".into(),
                    severity: Severity::Crit,
                    headline: "db.service OOM-killed: batch.service grew to 6 GiB".into(),
                    chain: vec![
                        "db.service failed (oom-kill)".into(),
                        "host memory exhausted".into(),
                        "batch.service grew 4 GiB in 5 min".into(),
                    ],
                    evidence: vec!["MemAvailable 80M at 03:11:58".into()],
                    suggestions: vec!["journalctl -u batch.service --since 03:00".into()],
                    gaps: vec!["kmsg unreadable: needs root".into()],
                    ..Default::default()
                }),
            );
            let out = render(&mut a, w, h);
            assert!(
                out.contains("What happened") && out.contains("batch.service grew") && out.contains("↳"),
                "{w}x{h}\n{out}"
            );
            if h >= 60 {
                assert!(out.contains("needs root") && out.contains("$ journalctl"), "{out}");
            }
        }
        let mut a = server_app();
        a.event_ring.clear();
        a.switch_tab(Tab::Events);
        let out = render(&mut a, 80, 24);
        assert!(out.contains("No events in the last 1h"), "{out}");
    }

    #[test]
    fn fleet_tab_renders_2000_hosts() {
        for (w, h) in SIZES {
            let mut a = fleet_app(2000);
            a.switch_tab(Tab::Fleet);
            a.fleet.polling = false;
            let out = render(&mut a, w, h);
            assert!(out.contains("Fleet") && out.contains("2000 hosts") && out.contains("✗40 down"), "{w}x{h}\n{out}");
            assert!(out.contains("HOST") && out.contains("HEALTH") && out.contains("✗ down"), "{w}x{h}\n{out}");
            if h >= 30 {
                assert!(out.contains("Fleet findings") && out.contains("disk /var almost full"), "{w}x{h}\n{out}");
            } else {
                assert!(out.contains("2 findings →") && out.contains("8Fleet"), "{w}x{h}\n{out}");
                a.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
                let out = render(&mut a, w, h);
                assert!(
                    out.contains("Fleet findings") && out.contains("disk /var almost full") && out.contains("web-0000"),
                    "{w}x{h}\n{out}"
                );
                a.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
            }
            if w >= 150 {
                assert!(
                    out.contains("RTT")
                        && out.contains("OOM")
                        && out.contains("TOP FINDING")
                        && out.contains("connect timed out"),
                    "{out}"
                );
            }
            // streaming state
            a.fleet.polling = true;
            a.fleet.answered = 830;
            let out = render(&mut a, w, h);
            assert!(out.contains("polling 830/2000"), "{w}x{h}\n{out}");
            a.fleet.polling = false;
            // drill-in
            a.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            let out = render(&mut a, w, h);
            assert!(out.contains("read-only snapshot") && out.contains("over ssh"), "{w}x{h}\n{out}");
            let name = a.fleet.drill.as_ref().unwrap().name.clone();
            let f = vec![crate::model::Finding {
                severity: "crit".into(),
                title: "db.service failed".into(),
                detail: "oom-kill".into(),
                ..Default::default()
            }];
            a.set_fleet_drill(&name, Ok((server_snap(a.now, 40), f)));
            let out = render(&mut a, w, h);
            assert!(out.contains("db.service failed") && out.contains("d Doctor"), "{w}x{h}\n{out}");
            a.on_key(key('u'));
            let out = render(&mut a, w, h);
            assert!(out.contains("worker.service") && out.contains("UNIT"), "{w}x{h}\n{out}");
            a.on_key(key('p'));
            let out = render(&mut a, w, h);
            assert!(out.contains("node") && out.contains("PID"), "{w}x{h}\n{out}");
        }
    }

    #[test]
    fn server_views_render_at_any_size() {
        for t in Tab::ALL {
            for (w, h) in [(80u16, 24u16), (200, 60), (40, 10), (10, 3), (1, 1)] {
                let mut a = fleet_app(50);
                a.switch_tab(t);
                render(&mut a, w, h);
                let mut e = App::new(1000);
                e.set_profile(crate::server::Profile::Server, Default::default(), 30);
                e.switch_tab(t);
                render(&mut e, w, h);
            }
        }
    }

    #[test]
    fn desktop_layout_is_unchanged() {
        let mut a = App::new(1000);
        a.on_snapshot(crate::tui::app::tests::snap(1_000_000));
        let out = render(&mut a, 80, 24);
        assert!(
            out.contains("1Procs") && out.contains("5Doctor") && !out.contains("Services") && !out.contains("Events"),
            "{out}"
        );
        assert!(out.contains("PWR") && !out.contains("OOM"), "{out}");
    }

    #[test]
    fn render_2000_hosts_and_300_units_is_fast() {
        let mut a = fleet_app(2000);
        a.switch_tab(Tab::Fleet);
        let mut term = Terminal::new(TestBackend::new(200, 60)).unwrap();
        term.draw(|f| draw(f, &mut a)).unwrap(); // includes the one-time sort
        let n = 30;
        let t = std::time::Instant::now();
        for _ in 0..n {
            term.draw(|f| draw(f, &mut a)).unwrap();
        }
        let fleet = t.elapsed() / n;
        a.switch_tab(Tab::Services);
        term.draw(|f| draw(f, &mut a)).unwrap();
        let t = std::time::Instant::now();
        for _ in 0..n {
            term.draw(|f| draw(f, &mut a)).unwrap();
        }
        let svc = t.elapsed() / n;
        // A re-sort of all rows (new sample / streamed host) per frame, worst case.
        let t = std::time::Instant::now();
        for _ in 0..n {
            a.fleet.set_sort(crate::tui::server::FleetSort::Cpu);
            a.ensure_server_rows();
        }
        let resort = t.elapsed() / n;
        eprintln!(
            "render @200x60: fleet 2000 hosts {fleet:?}/frame, services 300 units {svc:?}/frame, fleet re-sort {resort:?}"
        );
        // A guard against per-frame work growing with the host / unit count (debug builds on a
        // busy CI box are slow; release renders these in a few ms, see README).
        assert!(
            fleet < std::time::Duration::from_millis(200) && svc < std::time::Duration::from_millis(200),
            "{fleet:?} {svc:?}"
        );
        assert!(resort < std::time::Duration::from_millis(100), "{resort:?}");
    }
}
