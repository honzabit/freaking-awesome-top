//! README screenshots: fat's own TUI rendered from made-up demo data (no real host, user or
//! path), written as SVG to docs/img/. Regenerate after UI changes:
//!
//! ```text
//! cargo test screenshots -- --ignored
//! ```
use super::app::{App, Tab};
use crate::model::{ConnGroup, Conns, Finding, Port, Proc, Proto, Snapshot};
use crate::server::{Profile, ServerCfg, UnitKind};
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::{Terminal, backend::TestBackend};

const W: u16 = 132;

#[allow(clippy::too_many_arguments)]
fn proc(pid: u32, ppid: u32, name: &str, user: &str, cpu: f32, mem_mb: u64, cmd: &str, cgroup: &str) -> Proc {
    Proc {
        pid,
        ppid,
        name: name.into(),
        cmd: cmd.into(),
        user: user.into(),
        cpu,
        mem: mem_mb << 20,
        status: "S".into(),
        threads: 4 + pid % 20,
        power_mw: cpu * 9.0,
        start_time: 1_700_000_000 + pid as u64,
        cgroup: cgroup.into(),
        disk_write_bps: if name == "backup" { 48 << 20 } else { 0 },
        ..Default::default()
    }
}

fn demo_procs() -> Vec<Proc> {
    let s = |u: &str| format!("/system.slice/{u}");
    vec![
        proc(1, 0, "systemd", "root", 0.1, 12, "/sbin/init", "/init.scope"),
        proc(612, 1, "sshd", "root", 0.0, 8, "sshd: /usr/sbin/sshd -D", &s("ssh.service")),
        proc(
            801,
            1,
            "postgres",
            "postgres",
            3.2,
            420,
            "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main",
            &s("postgresql.service"),
        ),
        proc(
            845,
            801,
            "postgres",
            "postgres",
            41.5,
            610,
            "postgres: app appdb 10.0.3.21(51234) SELECT",
            &s("postgresql.service"),
        ),
        proc(
            846,
            801,
            "postgres",
            "postgres",
            12.8,
            380,
            "postgres: app appdb 10.0.3.22(40112) idle",
            &s("postgresql.service"),
        ),
        proc(902, 1, "nginx", "root", 0.0, 6, "nginx: master process /usr/sbin/nginx", &s("nginx.service")),
        proc(903, 902, "nginx", "www-data", 6.4, 28, "nginx: worker process", &s("nginx.service")),
        proc(904, 902, "nginx", "www-data", 5.9, 27, "nginx: worker process", &s("nginx.service")),
        proc(1200, 1, "node", "app", 96.0, 1480, "node /srv/api/dist/server.js", &s("api.service")),
        proc(1310, 1, "python3", "app", 64.0, 2210, "python3 -m worker --queue images", &s("worker.service")),
        proc(1402, 1, "redis-server", "redis", 2.1, 310, "/usr/bin/redis-server 127.0.0.1:6379", &s("redis.service")),
        proc(
            1500,
            1,
            "prometheus",
            "prometheus",
            4.8,
            890,
            "/usr/bin/prometheus --storage.tsdb.path=/var/lib/prometheus",
            &s("prometheus.service"),
        ),
        proc(1630, 1, "containerd", "root", 1.2, 64, "/usr/bin/containerd", &s("containerd.service")),
        proc(2101, 1, "backup", "root", 22.0, 140, "/usr/local/bin/backup --to /mnt/backup", &s("backup.service")),
        proc(2105, 2101, "zstd", "root", 88.0, 35, "zstd -T2 -19", &s("backup.service")),
        proc(3300, 1, "fat", "root", 0.4, 11, "/usr/local/bin/fat record --server", &s("fat-record.service")),
        proc(4100, 612, "bash", "ops", 0.0, 5, "-bash", "/user.slice/user-1001.slice/session-4.scope"),
        proc(
            4188,
            4100,
            "vite",
            "ops",
            0.3,
            160,
            "node node_modules/.bin/vite --port 5173",
            "/user.slice/user-1001.slice/session-4.scope",
        ),
    ]
}

fn demo_snap(ts: i64, wobble: f32) -> Snapshot {
    let mut s = super::server::tests::server_snap(ts, 14);
    s.system.hostname = "demo-01".into();
    s.system.os = "Debian GNU/Linux 13".into();
    s.system.cpu_model = "16-core x86_64".into();
    s.system.cores = 16;
    s.system.per_core = (0..16).map(|i| ((i * 37) % 90) as f32 + wobble).collect();
    s.system.cpu = 46.0 + wobble;
    s.system.mem_total = 64 << 30;
    s.system.mem_used = 41 << 30;
    let names = [
        ("postgresql.service", UnitKind::Systemd),
        ("worker.service", UnitKind::Systemd),
        ("backup.service", UnitKind::Systemd),
        ("api.service", UnitKind::Systemd),
        ("nginx.service", UnitKind::Systemd),
        ("redis.service", UnitKind::Systemd),
        ("prometheus.service", UnitKind::Systemd),
        ("cron.service", UnitKind::Systemd),
        ("ssh.service", UnitKind::Systemd),
        ("containerd.service", UnitKind::Systemd),
        ("metrics-exporter", UnitKind::Container),
        ("log-shipper", UnitKind::Container),
        ("fat-record.service", UnitKind::Systemd),
        ("systemd-journald.service", UnitKind::Systemd),
    ];
    for (u, (n, k)) in s.units.iter_mut().zip(names) {
        u.name = n.into();
        u.kind = k;
        u.description = String::new();
        u.cgroup = format!("/system.slice/{n}");
    }
    s.units[0].result = "oom-kill".into();
    if let Some(e) = s.events.iter_mut().find(|e| e.unit.as_deref() == Some("db.service")) {
        e.unit = Some("postgresql.service".into());
        e.subject = "unit:postgresql.service".into();
        e.detail = "postgres (4242) killed by the OOM killer, anon-rss 5.9G".into();
    }
    for e in &mut s.events {
        e.detail = e.detail.replace("db.service", "postgresql.service");
    }
    s.procs = demo_procs();
    s.ports = vec![
        Port {
            proto: Proto::Tcp,
            addr: "*".into(),
            port: 443,
            pid: 902,
            process: "nginx".into(),
            state: "LISTEN".into(),
            note: "nginx · nginx.service · up 12d".into(),
            ..Default::default()
        },
        Port {
            proto: Proto::Tcp,
            addr: "127.0.0.1".into(),
            port: 5432,
            pid: 801,
            process: "postgres".into(),
            state: "LISTEN".into(),
            note: "postgres · postgresql.service · up 12d".into(),
            ..Default::default()
        },
        Port {
            proto: Proto::Tcp,
            addr: "127.0.0.1".into(),
            port: 6379,
            pid: 1402,
            process: "redis-server".into(),
            state: "LISTEN".into(),
            note: "redis-server · redis.service · up 12d".into(),
            ..Default::default()
        },
        Port {
            proto: Proto::Tcp,
            addr: "127.0.0.1".into(),
            port: 9877,
            pid: 3300,
            process: "fat".into(),
            state: "LISTEN".into(),
            note: "fat · fat-record.service · up 2d".into(),
            ..Default::default()
        },
        Port {
            proto: Proto::Tcp,
            addr: "*".into(),
            port: 5173,
            pid: 4188,
            process: "vite".into(),
            state: "LISTEN".into(),
            orphan: true,
            note: "node vite dev server in ~/web (started 6h ago)".into(),
        },
        Port {
            proto: Proto::Udp,
            addr: "127.0.0.53".into(),
            port: 53,
            pid: 0,
            process: "?".into(),
            note: "systemd-resolved".into(),
            ..Default::default()
        },
    ];
    let g = |state: &str, pid: u32, process: &str, inbound: bool, lport: u16, remote: &str, rport: u16, count: u32| {
        ConnGroup {
            state: state.into(),
            pid,
            process: process.into(),
            inbound,
            local: if inbound { "10.0.3.10".into() } else { String::new() },
            local_port: if inbound { lport } else { 0 },
            remote: remote.into(),
            remote_port: rport,
            count,
        }
    };
    s.conns = Conns {
        states: vec![
            ("ESTABLISHED".into(), 1268),
            ("TIME_WAIT".into(), 214),
            ("CLOSE_WAIT".into(), 18),
            ("LISTEN".into(), 5),
            ("SYN_SENT".into(), 2),
        ],
        groups: vec![
            g("ESTABLISHED", 903, "nginx", true, 443, "203.0.113.40", 0, 412),
            g("ESTABLISHED", 1200, "node", false, 0, "127.0.0.1", 5432, 80),
            g("TIME_WAIT", 0, "", true, 443, "198.51.100.7", 0, 214),
            g("ESTABLISHED", 1310, "python3", false, 0, "127.0.0.1", 6379, 32),
            g("CLOSE_WAIT", 1310, "python3", false, 0, "192.0.2.15", 443, 18),
            g("SYN_SENT", 2101, "backup", false, 0, "10.0.9.2", 873, 2),
        ],
        ..Default::default()
    };
    s
}

fn demo_app() -> App {
    let mut a = App::new(1000);
    a.set_profile(Profile::Server, ServerCfg::default(), 30);
    let t0 = 1_794_000_000_000;
    for i in 0..60 {
        let wobble = ((i * 7) % 23) as f32;
        let mut s = demo_snap(t0 + i * 2000, wobble);
        if i < 59 {
            s.events.clear();
        }
        a.now = s.ts;
        a.on_snapshot(s);
    }
    let finding = |sev: &str, title: &str, detail: &str, action: Option<&str>| Finding {
        severity: sev.into(),
        title: title.into(),
        detail: detail.into(),
        action: action.map(str::to_string),
        ..Default::default()
    };
    a.set_findings(vec![
        finding(
            "crit",
            "postgresql.service was OOM-killed 1m ago",
            "postgres (4242) used 5.9G; the unit has no memory limit and the host had 1.2G free.",
            None,
        ),
        finding("warn", "worker.service is flapping", "5 restarts in 10 minutes (40 in total).", None),
        finding("warn", "backup.service is throttled", "42% of CPU periods throttled at a 0.5-core quota.", None),
        finding(
            "warn",
            "Orphaned dev server on :5173",
            "vite (pid 4188) still listens but whatever launched it is gone.",
            Some("kill 4188 --tree"),
        ),
    ]);
    a.ensure_rows();
    a.ensure_server_rows();
    a
}

fn color(c: Color, fg: bool) -> Option<String> {
    let named = |hex: &str| Some(hex.to_string());
    match c {
        Color::Reset => None,
        Color::Black => named("#1b1f27"),
        Color::Red => named("#e06c75"),
        Color::Green => named("#98c379"),
        Color::Yellow => named("#e5c07b"),
        Color::Blue => named("#61afef"),
        Color::Magenta => named("#c678dd"),
        Color::Cyan => named("#56b6c2"),
        Color::Gray => named("#abb2bf"),
        Color::DarkGray => named(if fg { "#6b7280" } else { "#30353f" }),
        Color::LightRed => named("#ff7b86"),
        Color::LightGreen => named("#b5e890"),
        Color::LightYellow => named("#f2d58f"),
        Color::LightBlue => named("#82c4ff"),
        Color::LightMagenta => named("#dc98f0"),
        Color::LightCyan => named("#7fd3dc"),
        Color::White => named("#e6e6e6"),
        Color::Rgb(r, g, b) => Some(format!("#{r:02x}{g:02x}{b:02x}")),
        Color::Indexed(i) => {
            // xterm 256: the 6x6x6 cube and the grey ramp; the first 16 as above.
            let (r, g, b) = match i {
                16..=231 => {
                    let v = |x: u8| if x == 0 { 0 } else { 55 + x * 40 };
                    let i = i - 16;
                    (v(i / 36), v((i / 6) % 6), v(i % 6))
                }
                232..=255 => {
                    let v = 8 + (i - 232) * 10;
                    (v, v, v)
                }
                _ => (171, 178, 191),
            };
            Some(format!("#{r:02x}{g:02x}{b:02x}"))
        }
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A terminal window with the buffer in it.
fn svg(buf: &Buffer, title: &str) -> String {
    const CW: f32 = 8.6;
    const CH: f32 = 18.0;
    const PAD: f32 = 14.0;
    const BAR: f32 = 30.0;
    let (w, h) = (buf.area.width, buf.area.height);
    let width = w as f32 * CW + PAD * 2.0;
    let height = h as f32 * CH + PAD * 2.0 + BAR;
    let (fg0, bg0) = ("#d7dae0", "#14171c");
    let mut out = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{t}">
<style>text{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"DejaVu Sans Mono",monospace;font-size:14px;white-space:pre}}.b{{font-weight:700}}.i{{font-style:italic}}.u{{text-decoration:underline}}</style>
<rect width="{width}" height="{height}" rx="10" fill="{bg0}"/>
<rect width="{width}" height="{BAR}" rx="10" fill="#1f232b"/><rect y="20" width="{width}" height="10" fill="#1f232b"/>
<circle cx="20" cy="15" r="6" fill="#ff5f57"/><circle cx="40" cy="15" r="6" fill="#febc2e"/><circle cx="60" cy="15" r="6" fill="#28c840"/>
<text x="{cx}" y="20" fill="#8b919c" text-anchor="middle" style="font-size:13px">{t}</text>
"##,
        t = esc(title),
        cx = width / 2.0,
    );
    for y in 0..h {
        let ty = BAR + PAD + y as f32 * CH;
        // Backgrounds, in runs (reverse video swaps foreground and background).
        let bg_of = |x: u16| {
            let c = &buf[(x, y)];
            if c.modifier.contains(Modifier::REVERSED) {
                Some(color(c.fg, true).unwrap_or_else(|| fg0.to_string()))
            } else {
                color(c.bg, false)
            }
        };
        let mut x = 0;
        while x < w {
            let bg = bg_of(x);
            let start = x;
            while x < w && bg_of(x) == bg {
                x += 1;
            }
            if let Some(bg) = bg {
                out.push_str(&format!(
                    r#"<rect x="{:.1}" y="{:.1}" width="{:.1}" height="{CH}" fill="{bg}"/>"#,
                    PAD + start as f32 * CW,
                    ty,
                    (x - start) as f32 * CW
                ));
            }
        }
        // Text, in runs of one style; each run is stretched to its cells so columns line up.
        let mut x = 0;
        while x < w {
            let c = &buf[(x, y)];
            let key = (c.fg, c.modifier);
            let start = x;
            let mut text = String::new();
            let mut cells = 0u16;
            while x < w && (buf[(x, y)].fg, buf[(x, y)].modifier) == key {
                let sym = buf[(x, y)].symbol();
                text.push_str(if sym.is_empty() { " " } else { sym });
                cells += 1;
                x += 1;
            }
            if text.trim().is_empty() {
                continue;
            }
            let mut fill = color(key.0, true).unwrap_or_else(|| fg0.to_string());
            let m = key.1;
            if m.contains(Modifier::REVERSED) {
                fill = color(c.bg, false).unwrap_or_else(|| bg0.to_string());
            }
            let mut class = Vec::new();
            if m.contains(Modifier::BOLD) {
                class.push("b");
            }
            if m.contains(Modifier::ITALIC) {
                class.push("i");
            }
            if m.contains(Modifier::UNDERLINED) {
                class.push("u");
            }
            let opacity = if m.contains(Modifier::DIM) { r#" opacity="0.6""# } else { "" };
            out.push_str(&format!(
                r#"<text x="{:.1}" y="{:.1}" fill="{fill}"{opacity}{} textLength="{:.1}" lengthAdjust="spacingAndGlyphs" xml:space="preserve">{}</text>"#,
                PAD + start as f32 * CW,
                ty + CH * 0.78,
                if class.is_empty() { String::new() } else { format!(r#" class="{}""#, class.join(" ")) },
                cells as f32 * CW,
                esc(&text)
            ));
        }
        out.push('\n');
    }
    out.push_str("</svg>\n");
    out
}

fn shot(a: &mut App, name: &str, title: &str, h: u16) -> String {
    let mut term = Terminal::new(TestBackend::new(W, h)).unwrap();
    term.draw(|f| super::ui::draw(f, a)).unwrap();
    let buf = term.backend().buffer().clone();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/img").join(format!("{name}.svg"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, svg(&buf, title)).unwrap();
    (0..h).map(|y| (0..W).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>() + "\n").collect()
}

#[test]
#[ignore = "writes docs/img/*.svg; run with --ignored to refresh README screenshots"]
fn screenshots() {
    let mut a = demo_app();

    a.switch_tab(Tab::Services);
    a.ensure_server_rows();
    let out = shot(&mut a, "services", "fat · Services (server profile)", 22);
    assert!(out.contains("postgresql.service"), "{out}");

    a.switch_tab(Tab::Procs);
    a.ensure_rows();
    let out = shot(&mut a, "procs", "fat · Procs", 29);
    assert!(out.contains("node"), "{out}");

    a.switch_tab(Tab::Ports);
    a.ensure_rows();
    let out = shot(&mut a, "ports", "fat · Ports: listeners and connections by state", 22);
    assert!(out.contains("Established"), "{out}");

    a.switch_tab(Tab::Doctor);
    let out = shot(&mut a, "doctor", "fat · Doctor", 18);
    assert!(out.contains("OOM"), "{out}");

    // Ask: a thread with an answer.
    a.ask.threads = vec![crate::threads::Thread {
        id: 1,
        title: "why did postgres restart?".into(),
        turns: 1,
        updated: a.now - 60_000,
        ..Default::default()
    }];
    a.ask.open = Some(1);
    a.ask.turns = vec![crate::threads::Turn {
        id: 1,
        thread: 1,
        ts: a.now - 60_000,
        question: "why did postgres restart?".into(),
        answer: "**postgresql.service was killed by the kernel's OOM killer** 1 minute ago.\n\n\
- `postgres` (pid 4242) had grown to **5.9G** of anonymous memory.\n\
- The unit has **no memory limit**, so the whole host ran short: 1.2G was free.\n\
- `worker.service` (pid 1310, 2.2G) was also growing and is restarting in a loop.\n\n\
**What to do**\n\
- Look at the query that grew: `fat what-happened --at -2m`.\n\
- Cap the unit so it can't take the host down: `MemoryMax=8G` in a drop-in.\n\
- Check `worker.service` with `journalctl -u worker.service -n 50`."
            .into(),
        via: "ollama · qwen3:32b · http://10.0.0.20:11434 · local only".into(),
    }];
    a.ask_ready = true;
    a.switch_tab(Tab::Ask);
    a.ask.threads.push(crate::threads::Thread {
        id: 2,
        title: "what writes all the time under /var?".into(),
        turns: 2,
        updated: a.now - 3 * 3_600_000,
        ..Default::default()
    });
    let out = shot(&mut a, "ask", "fat · Ask", 24);
    assert!(out.contains("OOM killer"), "{out}");

    // Settings: the Ask group.
    let env = |k: &str| (k == "FAT_ASK_KEY").then(|| "x".to_string());
    let mut cfg = crate::config::Config::default();
    cfg.ask.provider = "ollama".into();
    cfg.ask.url = "http://10.0.0.20:11434".into();
    cfg.ask.model = "qwen3:32b".into();
    cfg.ask.local_only = true;
    let file =
        "[ask]\nprovider = \"ollama\"\nurl = \"http://10.0.0.20:11434\"\nmodel = \"qwen3:32b\"\nlocal_only = true\n";
    a.settings = super::app::SettingsUi {
        fields: crate::settings::fields(&cfg, file, &env),
        path: "~/.config/fat/config.toml".into(),
        key_status: "FAT_ASK_KEY: not set (fine if the server needs no key)".into(),
        note: Some(("✓ ollama · qwen3:32b · http://10.0.0.20:11434 answered in 1.4s: OK".into(), false)),
        ..Default::default()
    };
    a.settings.sel = 2;
    a.tab = Tab::Settings;
    let out = shot(&mut a, "settings", "fat · Settings", 24);
    assert!(out.contains("Provider"), "{out}");
}
