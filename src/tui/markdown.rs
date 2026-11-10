//! Markdown for the terminal: turns an answer written in GitHub-flavored Markdown (what `ask`
//! gets back from the model) into styled, pre-wrapped lines.
//!
//! Covers what answers use: headings, paragraphs, `-`/`*`/`+` and numbered lists (nested by
//! indentation, wrapped with a hanging indent), `> ` quotes, fenced code blocks, horizontal
//! rules, tables (kept as typed, pipes dimmed), and inline `**bold**`, `*italic*`, `` `code` ``
//! and `[links](url)`. Anything else is shown as typed. A marker without a closing partner is
//! literal text, so a lone `*` never italicizes the rest of a line.
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

const CODE: Color = Color::Yellow;
const HEADING: Color = Color::Cyan;

fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn code_style() -> Style {
    Style::default().fg(CODE)
}

/// Render `text` as lines at most `width` cells wide.
pub fn render(text: &str, width: u16) -> Vec<Line<'static>> {
    let width = (width as usize).max(8);
    let mut out: Vec<Line<'static>> = Vec::new();
    let mut fence: Option<String> = None;
    let mut blank_run = 0;
    for raw in text.replace('\t', "    ").lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        // Fenced code: verbatim, hard-wrapped by width.
        if let Some(marker) = &fence {
            if trimmed.starts_with(marker.as_str()) {
                fence = None;
            } else {
                for chunk in hard_wrap(line, width.saturating_sub(2)) {
                    out.push(Line::from(vec![Span::styled("  ", dim()), Span::styled(chunk, code_style())]));
                }
            }
            continue;
        }
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fence = Some(trimmed[..3].to_string());
            continue;
        }
        if trimmed.is_empty() {
            blank_run += 1;
            if blank_run == 1 && !out.is_empty() {
                out.push(Line::raw(""));
            }
            continue;
        }
        blank_run = 0;
        if is_rule(trimmed) {
            out.push(Line::styled("─".repeat(width), dim()));
            continue;
        }
        if let Some((level, title)) = heading(trimmed) {
            let style = Style::default().fg(HEADING).add_modifier(Modifier::BOLD);
            let style = if level == 1 { style.add_modifier(Modifier::UNDERLINED) } else { style };
            let spans = inline(title).into_iter().map(|s| Span::styled(s.content, style.patch(s.style))).collect();
            out.extend(wrap(spans, width, Vec::new(), Vec::new()));
            continue;
        }
        if trimmed.starts_with('|') {
            out.extend(table_row(trimmed, width));
            continue;
        }
        let indent = line.len() - trimmed.len();
        if let Some(q) = trimmed.strip_prefix('>') {
            let bar = || vec![Span::styled("│ ", dim())];
            let spans =
                inline(q.trim_start()).into_iter().map(|s| Span::styled(s.content, s.style.patch(dim()))).collect();
            out.extend(wrap(spans, width, bar(), bar()));
            continue;
        }
        if let Some((marker, rest)) = list_item(trimmed) {
            let level = indent / 2;
            let pad = "  ".repeat(level);
            let bullet = match marker {
                Marker::Bullet => (if level == 0 { "• " } else { "◦ " }).to_string(),
                Marker::Number(n) => format!("{n} "),
            };
            let first = vec![Span::raw(pad.clone()), Span::styled(bullet.clone(), Style::default().fg(HEADING))];
            let hang = vec![Span::raw(format!("{pad}{}", " ".repeat(Span::raw(bullet.as_str()).width())))];
            out.extend(wrap(inline(rest), width, first, hang));
            continue;
        }
        // Paragraph text (an indented continuation of a list item keeps its indent).
        let pad = vec![Span::raw(" ".repeat(indent.min(width / 2)))];
        out.extend(wrap(inline(trimmed), width, pad.clone(), pad));
    }
    while out.last().is_some_and(|l| l.width() == 0) {
        out.pop();
    }
    out
}

fn is_rule(t: &str) -> bool {
    let c: Vec<char> = t.chars().filter(|c| !c.is_whitespace()).collect();
    c.len() >= 3 && (c.iter().all(|&x| x == '-') || c.iter().all(|&x| x == '*') || c.iter().all(|&x| x == '_'))
}

fn heading(t: &str) -> Option<(usize, &str)> {
    let level = t.chars().take_while(|&c| c == '#').count();
    if (1..=6).contains(&level) && t[level..].starts_with(' ') {
        Some((level, t[level..].trim().trim_end_matches('#').trim_end()))
    } else {
        None
    }
}

enum Marker {
    Bullet,
    Number(String),
}

fn list_item(t: &str) -> Option<(Marker, &str)> {
    for b in ["- ", "* ", "+ "] {
        if let Some(rest) = t.strip_prefix(b) {
            return Some((Marker::Bullet, rest.trim_start()));
        }
    }
    let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
    if (1..=3).contains(&digits) {
        let rest = &t[digits..];
        for sep in [". ", ") "] {
            if let Some(r) = rest.strip_prefix(sep) {
                return Some((Marker::Number(format!("{}.", &t[..digits])), r.trim_start()));
            }
        }
    }
    None
}

/// A table row as typed, with dim pipes; the `|---|` separator becomes a rule. Not wrapped:
/// cells would lose their columns.
fn table_row(t: &str, width: usize) -> Vec<Line<'static>> {
    if t.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')) {
        return vec![Line::styled("─".repeat(Span::raw(t).width().min(width)), dim())];
    }
    let mut spans = Vec::new();
    for (i, cell) in t.split('|').enumerate() {
        if i > 0 {
            spans.push(Span::styled("│", dim()));
        }
        spans.extend(inline(cell));
    }
    vec![Line::from(spans)]
}

/// Inline formatting of one line into styled runs.
pub fn inline(s: &str) -> Vec<Span<'static>> {
    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<Span<'static>> = Vec::new();
    let mut buf = String::new();
    let (mut bold, mut italic) = (false, false);
    let style = |bold: bool, italic: bool| {
        let mut st = Style::default();
        if bold {
            st = st.add_modifier(Modifier::BOLD);
        }
        if italic {
            st = st.add_modifier(Modifier::ITALIC);
        }
        st
    };
    let flush = |buf: &mut String, out: &mut Vec<Span<'static>>, st: Style| {
        if !buf.is_empty() {
            out.push(Span::styled(std::mem::take(buf), st));
        }
    };
    let find = |from: usize, pat: &[char]| -> Option<usize> {
        (from..chars.len().saturating_sub(pat.len() - 1)).find(|&j| chars[j..j + pat.len()] == *pat)
    };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // `code` (any number of backticks, matched by the same number).
        if c == '`' {
            let n = chars[i..].iter().take_while(|&&x| x == '`').count();
            let fence: Vec<char> = vec!['`'; n];
            if let Some(end) = find(i + n, &fence) {
                flush(&mut buf, &mut out, style(bold, italic));
                let code: String = chars[i + n..end].iter().collect();
                let code = if n > 1 { code.trim().to_string() } else { code };
                out.push(Span::styled(code, code_style().patch(style(bold, false))));
                i = end + n;
                continue;
            }
        }
        // [text](url)
        if c == '['
            && let Some(close) = find(i + 1, &[']'])
            && chars.get(close + 1) == Some(&'(')
            && let Some(paren) = find(close + 2, &[')'])
        {
            flush(&mut buf, &mut out, style(bold, italic));
            let label: String = chars[i + 1..close].iter().collect();
            let url: String = chars[close + 2..paren].iter().collect();
            out.push(Span::styled(label.clone(), style(bold, italic).add_modifier(Modifier::UNDERLINED)));
            if !url.is_empty() && url != label {
                out.push(Span::styled(format!(" ({url})"), dim()));
            }
            i = paren + 1;
            continue;
        }
        // **bold** / __bold__
        if (c == '*' || c == '_') && chars.get(i + 1) == Some(&c) {
            let pat = [c, c];
            let opens = !bold && chars.get(i + 2).is_some_and(|x| !x.is_whitespace()) && find(i + 2, &pat).is_some();
            if bold || opens {
                flush(&mut buf, &mut out, style(bold, italic));
                bold = !bold;
            } else {
                // No partner: both characters are text (not an italic marker plus a star).
                buf.push(c);
                buf.push(c);
            }
            i += 2;
            continue;
        }
        // *italic* / _italic_ (an underscore inside a word, as in snake_case, stays literal)
        if c == '*' || c == '_' {
            let word_inside = c == '_'
                && i > 0
                && chars[i - 1].is_alphanumeric()
                && chars.get(i + 1).is_some_and(|x| x.is_alphanumeric());
            let opens = !italic
                && !word_inside
                && chars.get(i + 1).is_some_and(|x| !x.is_whitespace())
                && (c == '*' || i == 0 || !chars[i - 1].is_alphanumeric())
                && find(i + 1, &[c]).is_some();
            let closes = italic && !word_inside && i > 0 && !chars[i - 1].is_whitespace();
            if opens || closes {
                flush(&mut buf, &mut out, style(bold, italic));
                italic = !italic;
                i += 1;
                continue;
            }
        }
        buf.push(c);
        i += 1;
    }
    flush(&mut buf, &mut out, style(bold, italic));
    out
}

/// Greedy word wrap of styled runs: the first line starts with `first`, the rest with `hang`.
fn wrap(
    spans: Vec<Span<'static>>,
    width: usize,
    first: Vec<Span<'static>>,
    hang: Vec<Span<'static>>,
) -> Vec<Line<'static>> {
    let prefix_w = |p: &[Span]| p.iter().map(Span::width).sum::<usize>();
    // Split runs into words (keeping each word's style) and the spaces between them.
    let mut words: Vec<(Vec<Span<'static>>, bool)> = Vec::new(); // (pieces, space before)
    let mut space_pending = false;
    let mut cur: Vec<Span<'static>> = Vec::new();
    for s in spans {
        let st = s.style;
        let mut piece = String::new();
        for ch in s.content.chars() {
            if ch == ' ' {
                if !piece.is_empty() {
                    cur.push(Span::styled(std::mem::take(&mut piece), st));
                }
                if !cur.is_empty() {
                    words.push((std::mem::take(&mut cur), space_pending));
                }
                space_pending = true;
            } else {
                piece.push(ch);
            }
        }
        if !piece.is_empty() {
            cur.push(Span::styled(piece, st));
        }
    }
    if !cur.is_empty() {
        words.push((cur, space_pending));
    }
    let mut lines = Vec::new();
    let mut line: Vec<Span<'static>> = first.clone();
    let mut used = prefix_w(&first);
    let mut at_start = true;
    for (pieces, space_before) in words {
        let w: usize = pieces.iter().map(Span::width).sum();
        let gap = usize::from(space_before && !at_start);
        if !at_start && used + gap + w > width {
            lines.push(Line::from(std::mem::take(&mut line)));
            line = hang.clone();
            used = prefix_w(&hang);
            at_start = true;
        }
        let avail = width.saturating_sub(used).max(1);
        if at_start && w > avail {
            // A word longer than the line (a long path or URL): break it by characters.
            let text: String = pieces.iter().map(|p| p.content.as_ref()).collect();
            let st = pieces[0].style;
            let mut chunks = hard_wrap(&text, avail).into_iter().peekable();
            while let Some(chunk) = chunks.next() {
                let cw = Span::raw(chunk.as_str()).width();
                line.push(Span::styled(chunk, st));
                used += cw;
                if chunks.peek().is_some() {
                    lines.push(Line::from(std::mem::take(&mut line)));
                    line = hang.clone();
                    used = prefix_w(&hang);
                }
            }
            at_start = false;
            continue;
        }
        if gap == 1 {
            let st = line.last().map(|s: &Span| s.style).unwrap_or_default();
            line.push(Span::styled(" ", st));
            used += 1;
        }
        used += w;
        line.extend(pieces);
        at_start = false;
    }
    lines.push(Line::from(line));
    lines
}

/// Break `s` into chunks of at most `width` cells.
fn hard_wrap(s: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut w = 0;
    for ch in s.chars() {
        let cw = Span::raw(ch.to_string()).width();
        if w + cw > width && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
            w = 0;
        }
        cur.push(ch);
        w += cw;
    }
    if !cur.is_empty() || out.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(lines: &[Line]) -> Vec<String> {
        lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect()).collect()
    }

    fn styled<'a>(lines: &'a [Line], needle: &str) -> &'a Span<'a> {
        lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .find(|s| s.content.contains(needle))
            .unwrap_or_else(|| panic!("no span with {needle:?}"))
    }

    #[test]
    fn bold_italic_code_and_links_lose_their_markers() {
        let l = render("**Disk** is *busy*: run `fat fs --growth` or see [docs](https://x.y).", 200);
        assert_eq!(text(&l), vec!["Disk is busy: run fat fs --growth or see docs (https://x.y)."]);
        assert!(styled(&l, "Disk").style.add_modifier.contains(Modifier::BOLD));
        assert!(styled(&l, "busy").style.add_modifier.contains(Modifier::ITALIC));
        assert_eq!(styled(&l, "--growth").style.fg, Some(CODE));
        assert!(styled(&l, "docs").style.add_modifier.contains(Modifier::UNDERLINED));
    }

    #[test]
    fn lone_markers_and_snake_case_stay_literal() {
        let l = render("2 * 3 = 6, io_some and mem_full, a **dangling marker", 200);
        assert_eq!(text(&l), vec!["2 * 3 = 6, io_some and mem_full, a **dangling marker"]);
        assert!(l[0].spans.iter().all(|s| !s.style.add_modifier.contains(Modifier::ITALIC)));
    }

    #[test]
    fn code_keeps_inner_markers() {
        let l = render("`a*b*c` and `__init__`", 200);
        assert_eq!(text(&l), vec!["a*b*c and __init__"]);
    }

    #[test]
    fn lists_nest_and_wrap_with_a_hanging_indent() {
        let md = "- **firecracker** microVMs under `agental-machines.service`, running as systemd children\n  - pid 1403467\n1. first\n2. second";
        let l = render(md, 40);
        let t = text(&l);
        assert!(t[0].starts_with("• firecracker microVMs"), "{t:?}");
        assert!(t[1].starts_with("  ") && !t[1].starts_with("  •"), "hanging indent: {t:?}");
        assert!(t.iter().any(|x| x == "  ◦ pid 1403467"), "{t:?}");
        assert!(t.iter().any(|x| x == "1. first") && t.iter().any(|x| x == "2. second"), "{t:?}");
        assert!(l.iter().all(|x| x.width() <= 40), "{t:?}");
    }

    #[test]
    fn headings_rules_quotes_and_fences() {
        let md = "## To confirm\n\n---\n> note this\n```sh\nsudo cat /proc/1/io\n```\nafter";
        let t = text(&render(md, 30));
        assert_eq!(t[0], "To confirm");
        assert_eq!(t[1], "");
        assert_eq!(t[2], "─".repeat(30));
        assert_eq!(t[3], "│ note this");
        assert_eq!(t[4], "  sudo cat /proc/1/io");
        assert_eq!(t[5], "after");
    }

    #[test]
    fn long_words_break_and_blank_runs_collapse() {
        let path = format!("/var/lib/{}", "x".repeat(50));
        let t = text(&render(&format!("see {path}\n\n\n\nend\n\n"), 20));
        assert!(t.iter().all(|x| Span::raw(x.as_str()).width() <= 20), "{t:?}");
        assert_eq!(t.iter().filter(|x| x.is_empty()).count(), 1, "{t:?}");
        assert_eq!(t.last().unwrap(), "end");
        assert_eq!(t.concat().replace(' ', ""), format!("see{path}end"));
    }

    #[test]
    fn tables_keep_columns() {
        let t = text(&render("| pid | name |\n|---|---|\n| 1 | **init** |", 80));
        assert_eq!(t[0], "│ pid │ name │");
        assert!(t[1].starts_with('─'));
        assert_eq!(t[2], "│ 1 │ init │");
    }

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(text(&render("Nothing unusual.", 80)), vec!["Nothing unusual."]);
        assert!(render("", 80).is_empty());
    }
}
