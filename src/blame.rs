//! Blame chains ("why") and whole-machine diagnosis ("doctor"). OWNER: blame agent.
//!
//! Everything here is pure logic over a [`Snapshot`] (plus optional flight-recorder
//! [`History`]); no syscalls, no signals. History errors are swallowed: a missing or
//! broken recorder only means fewer "how long has this been going on" details.
use crate::history::History;
use crate::model::{Explanation, Finding, Proc, Snapshot, Ts};
use std::collections::HashMap;

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;
const MIN_MS: i64 = 60_000;

pub fn explain(snap: &Snapshot, pid: u32, hist: Option<&History>) -> Explanation {
    let Some(p) = snap.proc(pid) else {
        return Explanation {
            pid,
            headline: format!("pid {pid} is not running (or not visible to this user)"),
            chain: vec![format!("no process with pid {pid} in the current snapshot")],
            evidence: vec![format!("{} processes visible on {}", snap.procs.len(), host_label(snap))],
            suggestions: vec![
                "it may have exited; check the recorder: fat history --since 30m".into(),
                "list what is running now: fat snapshot".into(),
            ],
        };
    };

    let now = now_of(snap);
    let descendants = snap.descendants(pid);
    let ancestors = snap.ancestors(pid);
    let tree = TreeCost::of(p, &descendants);
    let series = hist.and_then(|h| h.proc_series(pid, now - 30 * MIN_MS, now).ok()).unwrap_or_default();
    let streak = hot_streak(&series, HOT_CPU, now);

    // ---- headline ----
    let mut headline = if p.usage_unknown {
        format!("{} (pid {}): CPU and RAM unknown", p.name, p.pid)
    } else {
        format!("{} (pid {}) is using {:.0}% CPU, {} RAM", p.name, p.pid, p.cpu, human_bytes(p.mem))
    };
    if p.power_mw > 0.0 {
        headline.push_str(&format!(", {}", human_watts(p.power_mw)));
    }
    if is_stopped(p) {
        headline.push_str(" [paused]");
    }
    if p.usage_unknown || (p.mem == 0 && p.cpu == 0.0 && p.threads == 0) {
        headline.push_str(" (usage unreadable: owned by another user, needs root)");
    }

    // ---- chain: symptom → process → ancestry → cause ----
    let mut chain = vec![symptom(snap, p, &tree)];
    let mut proc_step = format!("{} (pid {})", p.name, p.pid);
    if !p.cmd.is_empty() && p.cmd != p.name {
        proc_step.push_str(&format!(": `{}`", truncate(&p.cmd, 90)));
    }
    chain.push(proc_step);
    if let Some(a) = ancestry_step(&ancestors) {
        chain.push(a);
    }
    let causes = cause_steps(snap, p, &tree, hist, now);
    chain.extend(causes.steps);
    if let Some((start, dur)) = streak {
        let mut s = format!("hot for the last {}, started {}", human_dur_ms(dur), clock(start));
        if let Some(sp) = hist.and_then(|h| coinciding_spike(h, start)) {
            s.push_str(&format!(
                " (coincides with a system spike at {}: {:.0}% CPU, top {} {:.0}%)",
                clock(sp.ts),
                sp.cpu,
                sp.top_name,
                sp.top_cpu
            ));
        }
        chain.push(s);
    }

    // ---- evidence ----
    let mut evidence = Vec::new();
    evidence.push(format!(
        "cpu {:.1}%  mem {}  threads {}  nice {}",
        p.cpu,
        human_bytes(p.mem),
        p.threads,
        p.nice
    ));
    if p.power_mw > 0.0 {
        let share = if snap.system.power_mw > 0.0 { p.power_mw / snap.system.power_mw * 100.0 } else { 0.0 };
        evidence.push(format!("power {} ({:.0}% of measured total)", human_watts(p.power_mw), share));
    }
    if let Some(g) = p.gpu {
        evidence.push(format!("gpu {g:.0}%"));
    }
    if p.disk_read_bps + p.disk_write_bps > 0 {
        evidence.push(format!("disk read {} write {}", human_rate(p.disk_read_bps), human_rate(p.disk_write_bps)));
    }
    if p.net_rx_bps + p.net_tx_bps > 0 {
        evidence.push(format!("net rx {} tx {}", human_rate(p.net_rx_bps), human_rate(p.net_tx_bps)));
    }
    if !descendants.is_empty() {
        evidence.push(format!(
            "{} descendants costing {:.0}% CPU, {} RAM (tree total {:.0}% CPU, {})",
            descendants.len(),
            tree.desc_cpu,
            human_bytes(tree.desc_mem),
            tree.cpu(),
            human_bytes(tree.mem())
        ));
    }
    let ports: Vec<String> = snap
        .ports
        .iter()
        .filter(|pt| pt.pid == pid)
        .map(|pt| {
            let mut s = format!("{}:{}/{}", pt.addr, pt.port, format!("{:?}", pt.proto).to_lowercase());
            if pt.orphan {
                s.push_str(" (orphaned)");
            }
            s
        })
        .collect();
    if !ports.is_empty() {
        evidence.push(format!("owns ports {}", ports.join(", ")));
    }
    if p.start_time > 0 {
        let up = (now / 1000 - p.start_time as i64).max(0) * 1000;
        evidence.push(format!("started {} (up {})", clock(p.start_time as i64 * 1000), human_dur_ms(up)));
    }
    if !p.user.is_empty() {
        evidence.push(format!("user {}", p.user));
    }
    if !p.cwd.is_empty() {
        evidence.push(format!("cwd {}", p.cwd));
    }
    evidence.push(format!("status {}", status_word(&p.status)));
    if series.len() >= 2 {
        let peak = series.iter().map(|s| s.1).fold(0.0f32, f32::max);
        let avg = series.iter().map(|s| s.1).sum::<f32>() / series.len() as f32;
        evidence.push(format!("last 30m: avg {avg:.0}% CPU, peak {peak:.0}% ({} samples)", series.len()));
    }
    evidence.extend(causes.evidence);

    // ---- suggestions ----
    let mut suggestions = Vec::new();
    suggestions.extend(causes.suggestions);
    if is_stopped(p) {
        suggestions.push(format!("it is paused; resume it: fat resume {pid}"));
        suggestions.push(format!("or stop it for good: fat kill {pid}{}", tree_flag(&descendants)));
    } else if is_system_critical(p) {
        suggestions.push(format!(
            "{} is part of macOS; don't kill it. Address the cause above instead.",
            p.name
        ));
        if p.pid != 0 && p.pid != 1 && p.name != "kernel_task" {
            suggestions.push(format!("if it's hurting right now, lower its priority: fat renice {pid} 10"));
        }
    } else {
        suggestions.push(format!("pause it (reversible): fat pause {pid}"));
        suggestions.push(format!("lower its priority (reversible): fat renice {pid} 10"));
        if descendants.is_empty() {
            suggestions.push(format!("stop it: fat kill {pid}"));
        } else {
            suggestions.push(format!("stop the tree ({} procs): fat kill {pid} --tree", descendants.len() + 1));
        }
    }

    Explanation { pid, headline, chain, evidence, suggestions }
}

/// Ranked findings, most severe first.
pub fn diagnose(snap: &Snapshot, hist: Option<&History>) -> Vec<Finding> {
    let now = now_of(snap);
    let mut out = Vec::new();

    rule_memory(snap, &mut out);
    rule_swap(snap, &mut out);
    rule_thermal(snap, &mut out);
    rule_cpu(snap, hist, now, &mut out);
    rule_power(snap, &mut out);
    rule_orphans(snap, &mut out);
    rule_stopped(snap, hist, now, &mut out);
    rule_zombies(snap, &mut out);
    rule_swarms(snap, &mut out);
    rule_disk(snap, &mut out);
    rule_net(snap, &mut out);
    rule_load(snap, &mut out);
    rule_unattributed(snap, &mut out);

    out.sort_by_key(|f| std::cmp::Reverse(severity_rank(&f.severity)));
    out
}

/// Human explanation for well-known system daemons (mds_stores, kernel_task, ...).
pub fn known(name: &str) -> Option<&'static str> {
    let n = name.trim();
    let lower = n.to_ascii_lowercase();
    KNOWN.iter().find(|k| k.matches(n, &lower)).map(|k| k.text)
}

// ======================================================================
// Known process table
// ======================================================================

enum M {
    /// Exact name (case-insensitive).
    Eq(&'static str),
    /// Name starts with (case-insensitive).
    Prefix(&'static str),
    /// Name contains (case-insensitive).
    Has(&'static str),
}

struct Known {
    m: M,
    text: &'static str,
}

impl Known {
    fn matches(&self, _orig: &str, lower: &str) -> bool {
        match self.m {
            M::Eq(s) => lower == s.to_ascii_lowercase(),
            M::Prefix(s) => lower.starts_with(&s.to_ascii_lowercase()),
            M::Has(s) => lower.contains(&s.to_ascii_lowercase()),
        }
    }
}

macro_rules! k {
    ($kind:ident $pat:literal => $text:literal) => {
        Known { m: M::$kind($pat), text: $text }
    };
}

/// Order matters: more specific patterns first.
static KNOWN: &[Known] = &[
    k!(Eq "mds_stores" => "Spotlight index writer. Busy after lots of new files appear (node_modules, target/, .git, downloads, unpacked archives) or after an OS update/reindex."),
    k!(Prefix "mdworker" => "Spotlight importer: reads new or changed files to extract searchable metadata. Swarms of these mean a big tree of files just changed."),
    k!(Eq "mds" => "Spotlight metadata server: coordinates indexing. High CPU usually means a reindex or a flood of new files (node_modules, target/, .git)."),
    k!(Eq "mdsync" => "Spotlight sync helper, keeps the index consistent across volumes."),
    k!(Eq "corespotlightd" => "Core Spotlight: indexes app content (Mail, Notes, Messages, third-party apps) for search."),
    k!(Eq "kernel_task" => "The macOS kernel. High CPU here is usually thermal management: the kernel 'reserves' CPU to keep the chip cool, so the real cause is heat (heavy load, blocked vents, hot room, charging)."),
    k!(Eq "WindowServer" => "Draws and composites every window. Rises with many/high-resolution or high-refresh displays, transparency effects, animations, and apps that redraw constantly."),
    k!(Eq "photoanalysisd" => "Photos library analysis (faces, objects, memories). Runs after imports, mostly when idle and on power; it finishes on its own."),
    k!(Eq "photolibraryd" => "Photos library daemon: manages the Photos database and iCloud Photos transfers."),
    k!(Eq "mediaanalysisd" => "Analyzes photos/videos for Live Text, Visual Look Up and search. Usually after imports or OS updates; finishes on its own."),
    k!(Eq "bird" => "iCloud Drive sync daemon. Busy while uploading/downloading files, especially many small files (e.g. a code repo inside ~/Documents or ~/Desktop)."),
    k!(Eq "cloudd" => "CloudKit sync daemon: syncs app data with iCloud. Spikes during large iCloud uploads/downloads."),
    k!(Eq "fileproviderd" => "File Provider: backs iCloud Drive, Dropbox, OneDrive, Google Drive folders. Busy during big syncs."),
    k!(Eq "backupd" => "Time Machine backup. Heavy disk and CPU during a backup, especially the first one or after many file changes."),
    k!(Prefix "backupd-helper" => "Time Machine helper that schedules and prepares backups."),
    k!(Eq "softwareupdated" => "macOS Software Update: checks for, downloads, and prepares updates."),
    k!(Eq "trustd" => "Certificate trust evaluation. Spikes with lots of TLS connections or code-signature checks (e.g. many new binaries)."),
    k!(Eq "syspolicyd" => "Gatekeeper: checks signatures/notarization of apps and binaries. Busy after downloading or building many new executables."),
    k!(Has "XprotectService" => "XProtect malware scanner: scans newly downloaded/launched code. Brief spikes after installs and builds are normal."),
    k!(Prefix "XProtect" => "XProtect malware scanning/remediation. Brief spikes after installs and builds are normal."),
    k!(Eq "nsurlsessiond" => "Background downloads for the system and apps (iCloud, App Store, updates, podcasts). High network use is expected while it works."),
    k!(Has "com.apple.Virtualization" => "Apple Virtualization framework VM: hosts a Linux/macOS VM (Docker Desktop, OrbStack, UTM, Lima, Tart). Its cost is whatever runs inside the VM."),
    k!(Prefix "qemu-system" => "QEMU virtual machine (Docker/Colima/Lima/UTM). Its cost is the workload running inside the VM."),
    k!(Has "Docker Desktop" => "Docker Desktop UI/backend. Container workloads run inside its VM (com.apple.Virtualization)."),
    k!(Prefix "com.docker" => "Docker Desktop backend/VM component. Container workloads show up here as one big process."),
    k!(Eq "dockerd" => "Docker daemon: manages containers. Its CPU is mostly container churn, builds and logs."),
    k!(Has "OrbStack" => "OrbStack: lightweight Docker/Linux VM. Container and VM workloads are billed to it."),
    k!(Has "SourceKitService" => "Xcode's Swift/ObjC language service (indexing, completion). Busy after opening a project, switching branches or editing headers."),
    k!(Eq "XCBBuildService" => "Xcode build system service: runs builds and dependency scanning."),
    k!(Eq "Xcode" => "Xcode IDE. Indexing and builds also spawn SourceKitService, swift-frontend, clang."),
    k!(Prefix "swift-frontend" => "Swift compiler process from a build (Xcode or swift build)."),
    k!(Eq "rust-analyzer" => "Rust language server for your editor: indexes the workspace and runs cargo check. Busy after opening a project, changing Cargo.toml or switching branches."),
    k!(Eq "rustc" => "Rust compiler, launched by cargo for builds/checks (possibly by rust-analyzer in the background)."),
    k!(Eq "cargo" => "Rust build tool. Spawns rustc/build scripts; heavy CPU while building, and creates large target/ trees that Spotlight then indexes."),
    k!(Has "tsserver" => "TypeScript language server (runs inside node for your editor). Large projects or huge node_modules make it hungry."),
    k!(Eq "node" => "Node.js runtime: dev servers (vite, next), build tools (webpack, esbuild, tsc), language servers, or agents. Check its cmd and cwd."),
    k!(Eq "bun" => "Bun JavaScript runtime: dev server, test runner or script."),
    k!(Eq "deno" => "Deno JavaScript/TypeScript runtime."),
    k!(Has "Chrome Helper (Renderer)" => "A Chrome tab or extension renderer. One heavy renderer is usually one heavy tab (video, ads, a runaway script). Find it in Chrome's Task Manager (Window > Task Manager)."),
    k!(Has "Chrome Helper (GPU)" => "Chrome's GPU process: compositing and video decode for all tabs."),
    k!(Has "Chrome Helper" => "A Chrome helper (tab, extension, GPU or network). Chrome's own Task Manager (Window > Task Manager) maps it to a tab."),
    k!(Has "Code Helper" => "VS Code/Cursor helper: extension host, language servers, or the renderer. Heavy ones are often extensions or file watchers on big folders."),
    k!(Has "WebContent" => "A Safari (WebKit) tab. A heavy one is usually a single busy page; Safari > Develop or closing tabs finds it."),
    k!(Has "Safari" => "Safari browser process; individual tabs run as com.apple.WebKit.WebContent."),
    k!(Eq "coreaudiod" => "Core Audio daemon: all sound in/out. Spikes with many audio apps, Bluetooth headsets or buggy audio plugins."),
    k!(Eq "logd" => "Unified logging. High CPU means something is logging furiously; look for a chatty process (or a log stream/Console capture)."),
    k!(Eq "runningboardd" => "Manages app lifecycle and resource assertions. Busy when apps launch/quit rapidly or crash-loop."),
    k!(Eq "launchd" => "The first process: starts and supervises every daemon and app. Processes re-parented to it lost their original launcher."),
    k!(Eq "spindump" => "Collects stack samples when an app hangs ('beachball'). Its activity means something just froze."),
    k!(Eq "ReportCrash" => "Writes crash reports. Repeated activity means something is crash-looping."),
    k!(Eq "sharingd" => "AirDrop, Handoff, Continuity, Universal Clipboard."),
    k!(Eq "bluetoothd" => "Bluetooth stack. Spikes with many devices or flaky connections."),
    k!(Eq "locationd" => "Location services daemon."),
    k!(Eq "secd" => "Keychain and iCloud Keychain sync."),
    k!(Eq "opendirectoryd" => "User/group directory lookups. High CPU usually means something is hammering user lookups."),
    k!(Eq "mds_stores_helper" => "Spotlight index maintenance helper."),
    k!(Eq "diskimagesd" => "Mounts and serves disk images (.dmg). Busy while a disk image is attached and read."),
    k!(Eq "Finder" => "Finder. Spikes while computing folder sizes, previews, or copying files."),
    k!(Eq "Dock" => "Dock, Mission Control and Launchpad."),
    k!(Eq "ControlCenter" => "Menu bar status items and Control Center."),
    k!(Eq "sshd" => "OpenSSH server: an incoming remote session (or its child) is running here."),
];

// ======================================================================
// Explain helpers
// ======================================================================

/// Threshold for "hot" when scanning history, percent CPU.
const HOT_CPU: f32 = 50.0;

#[derive(Default)]
struct TreeCost {
    own_cpu: f32,
    own_mem: u64,
    desc_cpu: f32,
    desc_mem: u64,
    top_desc: Option<(u32, String, f32)>,
}

impl TreeCost {
    fn of(p: &Proc, desc: &[&Proc]) -> TreeCost {
        let top = desc
            .iter()
            .max_by(|a, b| a.cpu.total_cmp(&b.cpu))
            .filter(|d| d.cpu > 0.0)
            .map(|d| (d.pid, d.name.clone(), d.cpu));
        TreeCost {
            own_cpu: p.cpu,
            own_mem: p.mem,
            desc_cpu: desc.iter().map(|d| d.cpu).sum(),
            desc_mem: desc.iter().map(|d| d.mem).sum(),
            top_desc: top,
        }
    }
    fn cpu(&self) -> f32 {
        self.own_cpu + self.desc_cpu
    }
    fn mem(&self) -> u64 {
        self.own_mem + self.desc_mem
    }
}

/// First chain step: what the user is actually noticing.
fn symptom(snap: &Snapshot, p: &Proc, tree: &TreeCost) -> String {
    let sys = &snap.system;
    let cores = sys.cores.max(1) as f32;
    let mut parts = Vec::new();
    if p.cpu >= 50.0 {
        parts.push(format!("{:.1} cores of CPU", p.cpu / 100.0));
    }
    if sys.mem_total > 0 && p.mem as f64 / sys.mem_total as f64 >= 0.10 {
        parts.push(format!("{:.0}% of RAM", p.mem as f64 / sys.mem_total as f64 * 100.0));
    }
    if p.power_mw >= 2000.0 {
        parts.push(format!("{} of power", human_watts(p.power_mw)));
    }
    if p.disk_write_bps + p.disk_read_bps >= 20 * MB {
        parts.push(format!("{} of disk I/O", human_rate(p.disk_write_bps + p.disk_read_bps)));
    }
    if p.net_rx_bps + p.net_tx_bps >= 5 * MB {
        parts.push(format!("{} of network", human_rate(p.net_rx_bps + p.net_tx_bps)));
    }
    if parts.is_empty() && tree.desc_cpu >= 50.0 {
        parts.push(format!("its children burn {:.1} cores", tree.desc_cpu / 100.0));
    }
    if is_stopped(p) {
        return "process is paused (SIGSTOP) and using no CPU".into();
    }
    if parts.is_empty() && p.usage_unknown {
        let owner = if p.user.is_empty() { "another user".to_string() } else { format!("user {}", p.user) };
        return format!(
            "usage unknown: owned by {owner}; macOS only lets root measure another user's CPU/memory (try `sudo fat why {}`)",
            p.pid
        );
    }
    if parts.is_empty() {
        let share = p.cpu / cores;
        return format!("light load: {:.0}% CPU ({share:.1}% of the machine), {}", p.cpu, human_bytes(p.mem));
    }
    format!("symptom: {}", parts.join(", "))
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum Launcher {
    Shell,
    Terminal,
    Ide,
    Agent,
    Remote,
    Init,
    Other,
}

fn classify_launcher(p: &Proc) -> Launcher {
    let n = p.name.to_ascii_lowercase();
    let n = n.trim_start_matches('-'); // login shells show as "-zsh"
    if p.pid == 1 || n == "launchd" {
        return Launcher::Init;
    }
    const SHELLS: &[&str] = &["zsh", "bash", "fish", "sh", "dash", "nu", "tcsh", "ksh", "pwsh", "xonsh", "elvish"];
    if SHELLS.contains(&n) {
        return Launcher::Shell;
    }
    const TERMS: &[&str] = &[
        "terminal", "iterm2", "alacritty", "kitty", "wezterm", "wezterm-gui", "ghostty", "warp", "stable", "hyper",
        "tmux", "screen", "zellij", "tabby", "rio", "login",
    ];
    if TERMS.contains(&n) || n.starts_with("tmux") || n.starts_with("iterm") {
        return Launcher::Terminal;
    }
    const IDES: &[&str] = &["code", "cursor", "zed", "xcode", "windsurf", "sublime_text", "nvim", "vim", "emacs", "helix", "hx"];
    if IDES.contains(&n)
        || n.starts_with("code helper")
        || n.starts_with("cursor helper")
        || n.contains("intellij")
        || n.starts_with("idea")
        || n.starts_with("pycharm")
        || n.starts_with("webstorm")
        || n.starts_with("goland")
        || n.starts_with("rustrover")
        || n.starts_with("clion")
    {
        return Launcher::Ide;
    }
    const AGENTS: &[&str] = &["claude", "codex", "aider", "gemini", "goose", "opencode", "amp"];
    if AGENTS.contains(&n) {
        return Launcher::Agent;
    }
    if n == "sshd" || n.starts_with("sshd-") || n == "mosh-server" {
        return Launcher::Remote;
    }
    Launcher::Other
}

/// "started from zsh (pid 10) ← Ghostty (pid 9) ← launchd". Collapses uninteresting
/// intermediate processes, but always keeps the direct parent.
fn ancestry_step(ancestors: &[&Proc]) -> Option<String> {
    if ancestors.is_empty() {
        return None;
    }
    let mut picked: Vec<String> = Vec::new();
    let mut skipped = 0usize;
    for (i, a) in ancestors.iter().enumerate() {
        let kind = classify_launcher(a);
        if i == 0 || kind != Launcher::Other {
            let mut s = format!("{} (pid {})", a.name, a.pid);
            match kind {
                Launcher::Shell => s.push_str(" shell"),
                Launcher::Terminal => s.push_str(" terminal"),
                Launcher::Ide => s.push_str(" editor/IDE"),
                Launcher::Agent => s.push_str(" agent"),
                Launcher::Remote => s.push_str(" ssh session"),
                Launcher::Init | Launcher::Other => {}
            }
            if skipped > 0 && i > 0 {
                picked.push(format!("…{skipped} more…"));
                skipped = 0;
            }
            picked.push(s);
        } else {
            skipped += 1;
        }
    }
    let direct_init = classify_launcher(ancestors[0]) == Launcher::Init;
    let mut out = format!("launched by {}", picked.join(" ← "));
    if direct_init {
        out.push_str(" (directly under launchd: a system/app service, or its original launcher exited)");
    }
    Some(out)
}

#[derive(Default)]
struct Causes {
    steps: Vec<String>,
    evidence: Vec<String>,
    suggestions: Vec<String>,
}

/// Names whose activity creates big file trees (and thus Spotlight / backup / sync work).
const FILE_CHURNERS: &[&str] = &[
    "npm", "pnpm", "yarn", "bun", "cargo", "rustc", "git", "pip", "pip3", "uv", "poetry", "brew", "xcodebuild",
    "swift-build", "go", "gradle", "java", "mvn", "tar", "unzip", "ditto", "rsync", "cp", "docker", "bazel", "make",
    "cmake", "ninja", "clang", "webpack", "esbuild", "vite", "tsc", "next",
];

fn is_file_churner(p: &Proc) -> bool {
    let n = p.name.to_ascii_lowercase();
    if FILE_CHURNERS.contains(&n.as_str()) {
        return true;
    }
    // node-based tools show up as `node .../npm-cli.js install`.
    if n == "node" {
        let c = p.cmd.to_ascii_lowercase();
        return ["npm", "pnpm", "yarn", "install", "webpack", "vite build", "next build", "tsc"]
            .iter()
            .any(|k| c.contains(k));
    }
    false
}

fn cause_steps(snap: &Snapshot, p: &Proc, tree: &TreeCost, hist: Option<&History>, now: Ts) -> Causes {
    let mut c = Causes::default();
    let name = p.name.as_str();
    let lname = name.to_ascii_lowercase();
    let known_text = known(name);

    if let Some(t) = known_text {
        c.steps.push(t.to_string());
    }

    let spotlight = lname == "mds" || lname == "mds_stores" || lname.starts_with("mdworker") || lname == "corespotlightd";
    let icloud = matches!(lname.as_str(), "bird" | "cloudd" | "fileproviderd");
    let backup = lname == "backupd";

    if spotlight || icloud || backup {
        let what = if spotlight { "Spotlight indexing" } else if icloud { "iCloud sync" } else { "Time Machine backup" };
        c.steps.push(format!("{what} is reacting to many new or changed files"));
        let churners = recent_churners(snap, hist, now);
        if churners.is_empty() {
            c.steps.push("likely cause: a large file tree was created recently (no build/install tool running right now)".into());
        } else {
            let list: Vec<String> = churners.iter().take(4).cloned().collect();
            c.steps.push(format!("likely cause: {}", list.join("; ")));
            c.evidence.push(format!("file-churning tools seen: {}", churners.join("; ")));
        }
        let mdworkers = snap.procs.iter().filter(|q| q.name.to_ascii_lowercase().starts_with("mdworker")).count();
        if spotlight && mdworkers > 0 {
            c.evidence.push(format!("{mdworkers} mdworker importers running"));
        }
        if spotlight {
            c.suggestions.push(
                "exclude build/dependency dirs from Spotlight: System Settings > Spotlight > Search Privacy (add node_modules, target/, build dirs), or create a `.metadata_never_index` file in them"
                    .into(),
            );
            c.suggestions.push("it finishes on its own; indexing pauses when the machine is busy".into());
        } else if icloud {
            c.suggestions.push("keep code repos and node_modules out of iCloud-synced folders (~/Desktop, ~/Documents), or name dirs with a `.nosync` suffix".into());
        } else {
            c.suggestions.push("exclude build/cache dirs from Time Machine: System Settings > General > Time Machine > Options".into());
            c.suggestions.push("or skip this backup: Time Machine menu > Skip This Backup".into());
        }
        return c;
    }

    if lname == "kernel_task" {
        let th = snap.system.thermal.as_str();
        c.steps.push(format!("thermal state is {th}"));
        let hot: Vec<String> = top_by(snap, |q| q.cpu, 3)
            .into_iter()
            .filter(|q| q.pid != p.pid && q.cpu >= 50.0)
            .map(|q| format!("{} (pid {}) {:.0}%", q.name, q.pid, q.cpu))
            .collect();
        if hot.is_empty() {
            c.steps.push("root cause: heat from outside current load (charging, ambient temperature, a recent burst, external displays)".into());
        } else {
            c.steps.push(format!("root cause: the heat comes from {}", hot.join(", ")));
        }
        c.suggestions.push("reduce the heavy work above (pause or renice it); kernel_task backs off as temperature drops".into());
        c.suggestions.push("improve cooling: hard flat surface, unblock vents, avoid charging while under heavy load".into());
        return c;
    }

    if lname == "windowserver" {
        c.steps.push("root cause: something is redrawing the screen a lot".into());
        c.suggestions.push("close or minimize apps with animations/video; reduce transparency (Accessibility > Display); fewer or lower-refresh external displays".into());
        return c;
    }

    if lname.contains("chrome helper") || lname.contains("webcontent") {
        c.steps.push("root cause: one browser tab/extension is doing heavy work".into());
        c.suggestions.push("find and close the tab: Chrome Window > Task Manager, or Safari Develop menu; reloading a runaway tab also works".into());
        return c;
    }

    if lname.contains("virtualization") || lname.starts_with("qemu") || lname.contains("docker") || lname.contains("orbstack") {
        let busy: Vec<String> = snap
            .containers
            .iter()
            .filter(|ct| ct.cpu > 1.0 || ct.mem > 256 * MB)
            .map(|ct| format!("{} ({}) {:.0}% CPU {}", ct.name, ct.image, ct.cpu, human_bytes(ct.mem)))
            .collect();
        if busy.is_empty() {
            c.steps.push("root cause: workload inside the VM (containers or VM guest processes)".into());
        } else {
            c.steps.push(format!("root cause: containers inside the VM: {}", busy.join(", ")));
        }
        c.suggestions.push("inspect containers: fat fleet (or docker stats); stop idle ones with docker stop".into());
        return c;
    }

    // Generic: where does the cost actually come from?
    if tree.desc_cpu > tree.own_cpu.max(10.0) {
        if let Some((dpid, dname, dcpu)) = &tree.top_desc {
            c.steps.push(format!(
                "root cause: most of the cost is in its children; heaviest is {dname} (pid {dpid}) at {dcpu:.0}%"
            ));
            c.suggestions.push(format!("drill down: fat why {dpid}"));
        }
    } else if is_file_churner(p) || matches!(lname.as_str(), "node" | "python" | "python3" | "ruby" | "java" | "go") {
        let place = if p.cwd.is_empty() { String::new() } else { format!(" in {}", p.cwd) };
        c.steps.push(format!("root cause: a dev/build workload{place}"));
    } else if known_text.is_none() && p.cpu >= 90.0 && p.disk_read_bps + p.disk_write_bps < MB && p.net_rx_bps + p.net_tx_bps < 64 * KB {
        c.steps.push("hypothesis: pure CPU spin with no I/O: busy loop, heavy computation, or a stuck process".into());
    }
    if snap.ports.iter().any(|pt| pt.pid == p.pid && pt.orphan) {
        c.steps.push("its server port is orphaned: the terminal/agent that started it is gone".into());
    }
    c
}

/// Build/install tools running now (or recently top in history) with their cwd.
fn recent_churners(snap: &Snapshot, hist: Option<&History>, now: Ts) -> Vec<String> {
    let mut out: Vec<String> = snap
        .procs
        .iter()
        .filter(|q| is_file_churner(q))
        .map(|q| {
            let place = if q.cwd.is_empty() { String::new() } else { format!(" in {}", q.cwd) };
            format!("{} (pid {}) running{place}", q.name, q.pid)
        })
        .collect();
    if let Some(h) = hist
        && let Ok(points) = h.timeline(now - 30 * MIN_MS, now, 120) {
            let mut seen: Vec<String> = Vec::new();
            for pt in points {
                let probe = Proc { name: pt.top_name.clone(), ..Default::default() };
                if !pt.top_name.is_empty() && is_file_churner(&probe) && !seen.contains(&pt.top_name) {
                    seen.push(pt.top_name.clone());
                    out.push(format!("{} was the top process at {}", pt.top_name, clock(pt.ts)));
                }
            }
        }
    out
}

/// Longest trailing run of samples above `threshold`, as (start_ts, duration_ms),
/// counting only if the run reaches the latest sample and lasts at least one minute.
/// The series is (ts, cpu, mem) sorted or unsorted.
fn hot_streak(series: &[(Ts, f32, u64)], threshold: f32, now: Ts) -> Option<(Ts, i64)> {
    let mut s: Vec<&(Ts, f32, u64)> = series.iter().collect();
    s.sort_by_key(|x| x.0);
    let last = s.last()?;
    if last.1 < threshold {
        return None;
    }
    let mut start = last.0;
    for x in s.iter().rev() {
        if x.1 >= threshold {
            start = x.0;
        } else {
            break;
        }
    }
    let end = now.max(last.0);
    let dur = end - start;
    (dur >= MIN_MS).then_some((start, dur))
}

fn coinciding_spike(h: &History, start: Ts) -> Option<crate::history::Point> {
    let spikes = h.spikes(start - 2 * MIN_MS, start + 2 * MIN_MS).ok()?;
    spikes.into_iter().min_by_key(|p| (p.ts - start).abs())
}

fn is_stopped(p: &Proc) -> bool {
    p.status.starts_with('T')
}

fn is_zombie(p: &Proc) -> bool {
    p.status.starts_with('Z')
}

fn is_system_critical(p: &Proc) -> bool {
    crate::actions::is_critical_name(&p.name) || p.pid <= 1
}

/// CPU the system reports as busy that no measurable process accounts for. Unprivileged, the
/// kernel hides other users' (root/system daemons') usage, so name the gap instead of
/// pretending those processes are idle.
fn rule_unattributed(snap: &Snapshot, out: &mut Vec<Finding>) {
    let unknown: Vec<&Proc> = snap.procs.iter().filter(|p| p.usage_unknown).collect();
    if unknown.is_empty() {
        return;
    }
    let total = snap.system.cpu * snap.system.cores.max(1) as f32;
    let attributed: f32 = snap.procs.iter().map(|p| p.cpu).sum();
    let gap = total - attributed;
    if gap < 50.0 {
        return;
    }
    let sev = if gap >= 200.0 { "warn" } else { "info" };
    let mut names: Vec<&str> = unknown.iter().map(|p| p.name.as_str()).filter(|n| !n.is_empty()).collect();
    names.sort_unstable();
    names.dedup();
    let sample = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
    out.push(finding(
        sev,
        format!("{:.1} cores of CPU unattributed (other users' processes need root)", gap / 100.0),
        format!(
            "The system is {:.0}% busy but measurable processes account for only {:.1} cores. {} processes owned by other users \
             (e.g. {sample}) can't be measured without root. Run `sudo fat` or `sudo fat doctor` to see which one it is.",
            snap.system.cpu,
            attributed / 100.0,
            unknown.len()
        ),
        Vec::new(),
        None,
    ));
}

fn status_word(s: &str) -> String {
    let w = match s.chars().next() {
        Some('R') => "running",
        Some('S') => "sleeping",
        Some('I') => "idle",
        Some('T') => "paused/stopped (T)",
        Some('Z') => "zombie (exited, parent hasn't reaped it)",
        Some('U') => "uninterruptible wait (U)",
        _ => "unknown",
    };
    w.to_string()
}

fn tree_flag(desc: &[&Proc]) -> &'static str {
    if desc.is_empty() { "" } else { " --tree" }
}

// ======================================================================
// Diagnose rules
// ======================================================================

fn finding(sev: &str, title: String, detail: String, pids: Vec<u32>, action: Option<String>) -> Finding {
    Finding { severity: sev.to_string(), title, detail, pids, action }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "crit" => 2,
        "warn" => 1,
        _ => 0,
    }
}

fn top_by(snap: &Snapshot, key: impl Fn(&Proc) -> f32, n: usize) -> Vec<&Proc> {
    let mut v: Vec<&Proc> = snap.procs.iter().collect();
    v.sort_by(|a, b| key(b).total_cmp(&key(a)));
    v.truncate(n);
    v
}

fn list_procs(ps: &[&Proc], f: impl Fn(&Proc) -> String) -> String {
    if ps.is_empty() {
        return "none measurable in this sample".into();
    }
    ps.iter().map(|p| format!("{} (pid {}) {}", p.name, p.pid, f(p))).collect::<Vec<_>>().join(", ")
}

/// Safe default action for a process: pause unless it's part of macOS.
fn safe_action(p: &Proc, snap: &Snapshot) -> Option<String> {
    if is_system_critical(p) {
        None
    } else if snap.descendants(p.pid).is_empty() {
        Some(format!("pause {}", p.pid))
    } else {
        Some(format!("pause {} (or kill {} --tree)", p.pid, p.pid))
    }
}

fn rule_memory(snap: &Snapshot, out: &mut Vec<Finding>) {
    let sys = &snap.system;
    let ratio = if sys.mem_total > 0 { sys.mem_used as f64 / sys.mem_total as f64 } else { 0.0 };
    let sev = match sys.mem_pressure.as_str() {
        "critical" => Some("crit"),
        "warn" => Some("warn"),
        "normal" => None,
        _ if ratio >= 0.95 => Some("warn"),
        _ => None,
    };
    let Some(sev) = sev else { return };
    let top: Vec<&Proc> = top_by(snap, |p| p.mem as f32, 5).into_iter().filter(|p| p.mem > 0).collect();
    let first = top.iter().find(|p| !is_system_critical(p)).copied();
    out.push(finding(
        sev,
        format!("Memory pressure is {}", if sev == "crit" { "critical" } else { "elevated" }),
        format!(
            "{} of {} RAM used ({:.0}%). Top consumers: {}",
            human_bytes(sys.mem_used),
            human_bytes(sys.mem_total),
            ratio * 100.0,
            list_procs(&top, |p| human_bytes(p.mem))
        ),
        top.iter().map(|p| p.pid).collect(),
        first.map(|p| format!("kill {}{}", p.pid, tree_flag(&snap.descendants(p.pid)))),
    ));
}

fn rule_swap(snap: &Snapshot, out: &mut Vec<Finding>) {
    let s = &snap.system;
    if s.swap_total == 0 || s.swap_used < 2 * GB {
        return;
    }
    let ratio = s.swap_used as f64 / s.swap_total as f64;
    if ratio < 0.5 && s.swap_used < 8 * GB {
        return;
    }
    let top = top_by(snap, |p| p.mem as f32, 3);
    out.push(finding(
        "warn",
        "Heavy swap use".into(),
        format!(
            "{} of {} swap in use; the machine is paging to disk, which feels sluggish. Biggest residents: {}",
            human_bytes(s.swap_used),
            human_bytes(s.swap_total),
            list_procs(&top, |p| human_bytes(p.mem))
        ),
        top.iter().map(|p| p.pid).collect(),
        None,
    ));
}

fn rule_thermal(snap: &Snapshot, out: &mut Vec<Finding>) {
    let sev = match snap.system.thermal.as_str() {
        "critical" => "crit",
        "serious" => "warn",
        "fair" => "info",
        _ => return,
    };
    let hot: Vec<&Proc> =
        top_by(snap, |p| p.cpu, 4).into_iter().filter(|p| p.cpu >= 50.0 && p.name != "kernel_task").collect();
    let kt = snap.procs.iter().find(|p| p.name == "kernel_task" && p.cpu >= 50.0);
    let mut detail = format!("Thermal state is {}; macOS is throttling the CPU to cool down.", snap.system.thermal);
    if let Some(k) = kt {
        detail.push_str(&format!(" kernel_task is reserving {:.0}% CPU to shed heat.", k.cpu));
    }
    if !hot.is_empty() {
        detail.push_str(&format!(" Heat sources: {}", list_procs(&hot, |p| format!("{:.0}%", p.cpu))));
    }
    out.push(finding(
        sev,
        "Thermal throttling".into(),
        detail,
        hot.iter().map(|p| p.pid).collect(),
        hot.iter().find(|p| !is_system_critical(p)).map(|p| format!("renice {} 10", p.pid)),
    ));
}

fn rule_cpu(snap: &Snapshot, hist: Option<&History>, now: Ts, out: &mut Vec<Finding>) {
    for p in &snap.procs {
        if is_stopped(p) {
            continue;
        }
        // Only query history for procs that are at least warm now: keeps it cheap.
        let streak = if p.cpu >= 50.0 {
            hist.and_then(|h| h.proc_series(p.pid, now - 30 * MIN_MS, now).ok())
                .and_then(|s| hot_streak(&s, 90.0, now))
                .filter(|(_, d)| *d >= 5 * MIN_MS)
        } else {
            None
        };
        if streak.is_none() && p.cpu <= 150.0 {
            continue;
        }
        let (title, detail) = match streak {
            Some((start, dur)) => (
                format!("{} has been pegging CPU for {}", p.name, human_dur_ms(dur)),
                format!(
                    "{} (pid {}) is at {:.0}% CPU now and above 90% since {}.",
                    p.name,
                    p.pid,
                    p.cpu,
                    clock(start)
                ),
            ),
            None => (
                format!("{} is using {:.1} cores", p.name, p.cpu / 100.0),
                format!("{} (pid {}) is at {:.0}% CPU right now.", p.name, p.pid, p.cpu),
            ),
        };
        let mut detail = detail;
        if let Some(k) = known(&p.name) {
            detail.push(' ');
            detail.push_str(k);
        }
        detail.push_str(&format!(" Details: fat why {}", p.pid));
        out.push(finding("warn", title, detail, vec![p.pid], safe_action(p, snap)));
    }
}

fn rule_power(snap: &Snapshot, out: &mut Vec<Finding>) {
    let sys = &snap.system;
    let heavy: Vec<&Proc> = snap.procs.iter().filter(|p| p.power_mw > 5000.0).collect();
    for p in &heavy {
        out.push(finding(
            "warn",
            format!("{} is drawing {}", p.name, human_watts(p.power_mw)),
            format!("{} (pid {}) is the kind of load that drains a battery in a couple of hours.", p.name, p.pid),
            vec![p.pid],
            safe_action(p, snap),
        ));
    }
    if sys.on_battery == Some(true)
        && let Some(b) = sys.battery_pct
            && b < 20.0 && (sys.power_mw > 10_000.0 || !heavy.is_empty()) {
                let top: Vec<&Proc> = top_by(snap, |p| p.power_mw, 3).into_iter().filter(|p| p.power_mw > 0.0).collect();
                out.push(finding(
                    "crit",
                    format!("Battery at {b:.0}% with heavy power draw"),
                    format!(
                        "Drawing about {} on battery. Biggest consumers: {}",
                        human_watts(sys.power_mw),
                        list_procs(&top, |p| human_watts(p.power_mw))
                    ),
                    top.iter().map(|p| p.pid).collect(),
                    top.iter().find(|p| !is_system_critical(p)).map(|p| format!("pause {}", p.pid)),
                ));
            }
}

fn rule_orphans(snap: &Snapshot, out: &mut Vec<Finding>) {
    let mut seen: Vec<u32> = Vec::new();
    for pt in snap.ports.iter().filter(|p| p.orphan) {
        if seen.contains(&pt.pid) {
            continue;
        }
        seen.push(pt.pid);
        let ports: Vec<String> =
            snap.ports.iter().filter(|q| q.pid == pt.pid && q.orphan).map(|q| q.port.to_string()).collect();
        let mut detail = format!(
            "{} (pid {}) still listens on port {} but whatever launched it is gone.",
            pt.process,
            pt.pid,
            ports.join(", ")
        );
        if !pt.note.is_empty() {
            detail.push_str(&format!(" {}", pt.note));
        }
        out.push(finding(
            "warn",
            format!("Orphaned dev server on :{}", pt.port),
            detail,
            vec![pt.pid],
            Some(format!("kill {} --tree", pt.pid)),
        ));
    }
}

fn rule_stopped(snap: &Snapshot, hist: Option<&History>, now: Ts, out: &mut Vec<Finding>) {
    for p in snap.procs.iter().filter(|p| is_stopped(p)) {
        let idle_ms = stopped_for(p, hist, now);
        if idle_ms < 10 * MIN_MS {
            continue;
        }
        out.push(finding(
            "info",
            format!("{} has been paused for {}+", p.name, human_dur_ms(idle_ms)),
            format!(
                "{} (pid {}) is stopped (T) holding {} RAM. Forgotten? Resume it or end it.",
                p.name,
                p.pid,
                human_bytes(p.mem)
            ),
            vec![p.pid],
            Some(format!("resume {} (or kill {}{})", p.pid, p.pid, tree_flag(&snap.descendants(p.pid)))),
        ));
    }
}

/// Best estimate of how long a stopped process has been idle. With history: the
/// trailing run of zero-CPU samples. Without: its age (an upper bound).
fn stopped_for(p: &Proc, hist: Option<&History>, now: Ts) -> i64 {
    let age = if p.start_time > 0 { (now - p.start_time as i64 * 1000).max(0) } else { 0 };
    let Some(series) = hist.and_then(|h| h.proc_series(p.pid, now - 24 * 60 * MIN_MS, now).ok()) else {
        return age;
    };
    if series.is_empty() {
        return age;
    }
    let mut s = series;
    s.sort_by_key(|x| x.0);
    let mut start = now;
    for x in s.iter().rev() {
        if x.1 <= 0.1 {
            start = x.0;
        } else {
            break;
        }
    }
    (now - start).max(0)
}

fn rule_zombies(snap: &Snapshot, out: &mut Vec<Finding>) {
    let z: Vec<&Proc> = snap.procs.iter().filter(|p| is_zombie(p)).collect();
    if z.is_empty() {
        return;
    }
    let mut by_parent: HashMap<u32, usize> = HashMap::new();
    for p in &z {
        *by_parent.entry(p.ppid).or_default() += 1;
    }
    let (parent, n) = by_parent.iter().max_by_key(|(_, n)| **n).map(|(a, b)| (*a, *b)).unwrap_or((0, 0));
    let pname = snap.proc(parent).map(|p| p.name.clone()).unwrap_or_else(|| "?".into());
    let sev = if z.len() >= 20 { "warn" } else { "info" };
    out.push(finding(
        sev,
        format!("{} zombie process{}", z.len(), if z.len() == 1 { "" } else { "es" }),
        format!(
            "Exited processes not reaped by their parent; most ({n}) belong to {pname} (pid {parent}). They hold no memory but leak pid slots; restarting the parent clears them."
        ),
        z.iter().map(|p| p.pid).collect(),
        (parent > 1).then(|| format!("kill {parent}")),
    ));
}

fn rule_swarms(snap: &Snapshot, out: &mut Vec<Finding>) {
    let mut groups: HashMap<&str, Vec<&Proc>> = HashMap::new();
    for p in &snap.procs {
        groups.entry(p.name.as_str()).or_default().push(p);
    }
    let mut names: Vec<(&str, Vec<&Proc>)> = groups.into_iter().filter(|(_, v)| v.len() > 30).collect();
    names.sort_by_key(|(n, v)| (std::cmp::Reverse(v.len()), *n));
    for (name, ps) in names {
        // Browsers and the OS legitimately run many helpers; still report, but as info.
        let benign = name.contains("Helper") || name.contains("WebContent") || name.starts_with("mdworker") || name.starts_with("com.apple");
        let cpu: f32 = ps.iter().map(|p| p.cpu).sum();
        let mem: u64 = ps.iter().map(|p| p.mem).sum();
        // Common parent (if most share one) is the thing to kill.
        let mut parents: HashMap<u32, usize> = HashMap::new();
        for p in &ps {
            *parents.entry(p.ppid).or_default() += 1;
        }
        let (pp, cnt) = parents.iter().max_by_key(|(_, c)| **c).map(|(a, b)| (*a, *b)).unwrap_or((0, 0));
        let action = if pp > 1 && cnt * 2 >= ps.len() && !benign {
            Some(format!("kill {pp} --tree"))
        } else {
            None
        };
        let mut detail = format!("{} processes named {name} using {:.0}% CPU and {} RAM together.", ps.len(), cpu, human_bytes(mem));
        if pp > 1 && cnt * 2 >= ps.len() {
            let pname = snap.proc(pp).map(|p| p.name.as_str()).unwrap_or("?");
            detail.push_str(&format!(" {cnt} share parent {pname} (pid {pp})."));
        } else if pp == 1 && !benign {
            detail.push_str(" Most were re-parented to launchd: likely leaked workers.");
        }
        out.push(finding(
            if benign { "info" } else { "warn" },
            format!("{} copies of {name}", ps.len()),
            detail,
            ps.iter().map(|p| p.pid).collect(),
            action,
        ));
    }
}

fn rule_disk(snap: &Snapshot, out: &mut Vec<Finding>) {
    const STORM: u64 = 100 * MB;
    let writers: Vec<&Proc> = snap.procs.iter().filter(|p| p.disk_write_bps >= STORM).collect();
    for p in &writers {
        out.push(finding(
            "warn",
            format!("{} is writing {}", p.name, human_rate(p.disk_write_bps)),
            format!(
                "Disk write storm from {} (pid {}){}. Sustained writes wear the SSD and stall other apps.",
                p.name,
                p.pid,
                if p.cwd.is_empty() { String::new() } else { format!(" in {}", p.cwd) }
            ),
            vec![p.pid],
            safe_action(p, snap),
        ));
    }
    if writers.is_empty() && snap.system.disk_write_bps >= STORM {
        let top = top_by(snap, |p| p.disk_write_bps as f32, 3);
        out.push(finding(
            "warn",
            format!("Disk writes at {}", human_rate(snap.system.disk_write_bps)),
            format!("System-wide write storm. Top writers: {}", list_procs(&top, |p| human_rate(p.disk_write_bps))),
            top.iter().map(|p| p.pid).collect(),
            None,
        ));
    }
}

fn rule_net(snap: &Snapshot, out: &mut Vec<Finding>) {
    const BIG: u64 = 10 * MB;
    for p in snap.procs.iter().filter(|p| p.net_rx_bps + p.net_tx_bps >= BIG) {
        let dir = if p.net_tx_bps > p.net_rx_bps { "uploading" } else { "downloading" };
        let mut detail = format!(
            "{} (pid {}) is {dir}: rx {} tx {}.",
            p.name,
            p.pid,
            human_rate(p.net_rx_bps),
            human_rate(p.net_tx_bps)
        );
        if let Some(k) = known(&p.name) {
            detail.push(' ');
            detail.push_str(k);
        }
        out.push(finding("info", format!("{} is a big network user", p.name), detail, vec![p.pid], None));
    }
}

fn rule_load(snap: &Snapshot, out: &mut Vec<Finding>) {
    let cores = snap.system.cores;
    if cores == 0 {
        return;
    }
    let l1 = snap.system.load[0];
    let ratio = l1 / cores as f64;
    let sev = if ratio >= 4.0 {
        "crit"
    } else if ratio >= 2.0 {
        "warn"
    } else if ratio >= 1.25 {
        "info"
    } else {
        return;
    };
    let top: Vec<&Proc> = top_by(snap, |p| p.cpu, 3).into_iter().filter(|p| p.cpu > 0.0).collect();
    out.push(finding(
        sev,
        format!("Load {:.1} on {cores} cores", l1),
        format!(
            "{:.1}x more runnable work than cores (load {:.1} / {:.1} / {:.1}). Top: {}",
            ratio,
            snap.system.load[0],
            snap.system.load[1],
            snap.system.load[2],
            list_procs(&top, |p| format!("{:.0}%", p.cpu))
        ),
        top.iter().map(|p| p.pid).collect(),
        top.iter().find(|p| !is_system_critical(p)).map(|p| format!("renice {} 10", p.pid)),
    ));
}

// ======================================================================
// Formatting
// ======================================================================

fn now_of(snap: &Snapshot) -> Ts {
    if snap.ts > 0 { snap.ts } else { crate::model::now_ms() }
}

fn host_label(snap: &Snapshot) -> &str {
    if snap.host.is_empty() { "local" } else { &snap.host }
}

fn human_bytes(b: u64) -> String {
    let f = b as f64;
    if b >= GB {
        format!("{:.1}G", f / GB as f64)
    } else if b >= MB {
        format!("{:.0}M", f / MB as f64)
    } else if b >= KB {
        format!("{:.0}K", f / KB as f64)
    } else {
        format!("{b}B")
    }
}

fn human_rate(bps: u64) -> String {
    format!("{}/s", human_bytes(bps))
}

fn human_watts(mw: f32) -> String {
    if mw >= 1000.0 { format!("{:.1} W", mw / 1000.0) } else { format!("{mw:.0} mW") }
}

fn human_dur_ms(ms: i64) -> String {
    let s = (ms / 1000).max(0);
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86_400 {
        let m = (s % 3600) / 60;
        if m == 0 { format!("{}h", s / 3600) } else { format!("{}h{}m", s / 3600, m) }
    } else {
        format!("{}d{}h", s / 86_400, (s % 86_400) / 3600)
    }
}

/// Local wall-clock "14:03" for an epoch-ms timestamp.
fn clock(ts: Ts) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_millis_opt(ts) {
        chrono::LocalResult::Single(t) => t.format("%H:%M").to_string(),
        _ => "?".into(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Port, Proto, System};

    const NOW: Ts = 1_800_000_000_000;

    fn pr(pid: u32, ppid: u32, name: &str, cpu: f32, mem: u64) -> Proc {
        Proc {
            pid,
            ppid,
            name: name.into(),
            cmd: name.into(),
            user: "me".into(),
            cpu,
            mem,
            status: "R".into(),
            start_time: (NOW / 1000 - 3600) as u64,
            ..Default::default()
        }
    }

    fn base_procs() -> Vec<Proc> {
        vec![
            pr(1, 0, "launchd", 0.1, 20 * MB),
            pr(100, 1, "Ghostty", 2.0, 200 * MB),
            pr(101, 100, "login", 0.0, 2 * MB),
            pr(102, 101, "-zsh", 0.0, 5 * MB),
        ]
    }

    fn snap(procs: Vec<Proc>) -> Snapshot {
        Snapshot {
            ts: NOW,
            host: "local".into(),
            system: System {
                cores: 16,
                mem_total: 64 * GB,
                mem_used: 20 * GB,
                mem_pressure: "normal".into(),
                thermal: "nominal".into(),
                load: [2.0, 2.0, 2.0],
                ..Default::default()
            },
            procs,
            ports: vec![],
            containers: vec![],
        }
    }

    #[test]
    fn known_table() {
        assert!(known("mds_stores").unwrap().contains("Spotlight"));
        assert!(known("mdworker_shared").unwrap().contains("Spotlight"));
        assert!(known("kernel_task").unwrap().contains("thermal"));
        assert!(known("Google Chrome Helper (Renderer)").unwrap().contains("tab"));
        assert!(known("com.apple.WebKit.WebContent").unwrap().contains("Safari"));
        assert!(known("com.apple.Virtualization.VirtualMachine").unwrap().contains("VM"));
        assert!(known("rust-analyzer").is_some());
        assert!(known("windowserver").is_some());
        assert!(known("my-random-binary").is_none());
        assert!(KNOWN.len() >= 40);
    }

    #[test]
    fn explain_missing_pid() {
        let e = explain(&snap(base_procs()), 4242, None);
        assert_eq!(e.pid, 4242);
        assert!(e.headline.contains("not running"));
        assert!(!e.suggestions.is_empty());
    }

    #[test]
    fn explain_dev_process_chain() {
        let mut ps = base_procs();
        let mut n = pr(200, 102, "node", 180.0, 2 * GB);
        n.cwd = "/Users/me/proj".into();
        n.cmd = "node node_modules/.bin/vite".into();
        n.power_mw = 6500.0;
        ps.push(n);
        ps.push(pr(201, 200, "esbuild", 20.0, 100 * MB));
        let mut s = snap(ps);
        s.ports.push(Port {
            proto: Proto::Tcp,
            addr: "127.0.0.1".into(),
            port: 5173,
            pid: 200,
            process: "node".into(),
            state: "LISTEN".into(),
            orphan: false,
            note: String::new(),
        });
        let e = explain(&s, 200, None);
        assert!(e.headline.starts_with("node (pid 200) is using 180% CPU, 2.0G RAM, 6.5 W"), "{}", e.headline);
        assert!(e.chain[0].contains("cores"));
        let anc = e.chain.iter().find(|c| c.starts_with("launched by")).unwrap();
        assert!(anc.contains("-zsh (pid 102) shell"), "{anc}");
        assert!(anc.contains("Ghostty (pid 100) terminal"), "{anc}");
        assert!(anc.contains("launchd"));
        assert!(e.chain.iter().any(|c| c.contains("/Users/me/proj")));
        assert!(e.evidence.iter().any(|x| x.contains("1 descendants")));
        assert!(e.evidence.iter().any(|x| x.contains("5173")));
        assert!(e.evidence.iter().any(|x| x.contains("cwd /Users/me/proj")));
        assert!(e.evidence.iter().any(|x| x.contains("up 1h")));
        let sg = e.suggestions.join("\n");
        let (pa, re, ki) = (sg.find("fat pause 200").unwrap(), sg.find("fat renice 200 10").unwrap(), sg.find("fat kill 200 --tree").unwrap());
        assert!(pa < re && re < ki, "severity order");
    }

    #[test]
    fn explain_spotlight_points_at_churner() {
        let mut ps = base_procs();
        ps.push(pr(50, 1, "mds_stores", 120.0, 300 * MB));
        ps.push(pr(51, 1, "mdworker_shared", 30.0, 50 * MB));
        let mut npm = pr(300, 102, "npm", 40.0, 400 * MB);
        npm.cwd = "/Users/me/web".into();
        ps.push(npm);
        let e = explain(&snap(ps), 50, None);
        let chain = e.chain.join("\n");
        assert!(chain.contains("Spotlight indexing"));
        assert!(chain.contains("npm (pid 300) running in /Users/me/web"), "{chain}");
        assert!(e.suggestions.iter().any(|s| s.contains("Search Privacy")));
        assert!(e.suggestions.iter().any(|s| s.contains("don't kill")));
        assert!(!e.suggestions.iter().any(|s| s.contains("fat kill 50")));
        assert!(e.evidence.iter().any(|s| s.contains("1 mdworker")));
    }

    #[test]
    fn explain_kernel_task_blames_heat_source() {
        let mut ps = base_procs();
        ps.push(pr(0, 0, "kernel_task", 300.0, GB));
        ps.push(pr(400, 102, "rustc", 700.0, 3 * GB));
        let mut s = snap(ps);
        s.system.thermal = "serious".into();
        let e = explain(&s, 0, None);
        let chain = e.chain.join("\n");
        assert!(chain.contains("thermal state is serious"));
        assert!(chain.contains("rustc (pid 400)"));
    }

    #[test]
    fn explain_parent_blames_children() {
        let mut ps = base_procs();
        ps.push(pr(500, 102, "make", 0.5, 10 * MB));
        ps.push(pr(501, 500, "clang", 95.0, 300 * MB));
        ps.push(pr(502, 500, "clang", 60.0, 300 * MB));
        let e = explain(&snap(ps), 500, None);
        assert!(e.chain.iter().any(|c| c.contains("clang (pid 501) at 95%")), "{:?}", e.chain);
        assert!(e.suggestions.iter().any(|s| s == "drill down: fat why 501"));
        assert!(e.suggestions.iter().any(|s| s.contains("--tree (3 procs)") || s.contains("(3 procs)")));
    }

    #[test]
    fn explain_paused_process() {
        let mut ps = base_procs();
        let mut p = pr(600, 102, "python3", 0.0, 500 * MB);
        p.status = "T".into();
        ps.push(p);
        let e = explain(&snap(ps), 600, None);
        assert!(e.headline.contains("[paused]"));
        assert!(e.chain[0].contains("paused"));
        assert!(e.suggestions[0].contains("fat resume 600"));
        assert!(e.evidence.iter().any(|x| x.contains("paused/stopped")));
    }

    #[test]
    fn ancestry_under_launchd_flags_orphan() {
        let mut ps = base_procs();
        ps.push(pr(700, 1, "node", 5.0, 100 * MB));
        let s = snap(ps);
        let step = ancestry_step(&s.ancestors(700)).unwrap();
        assert!(step.contains("directly under launchd"));
    }

    #[test]
    fn ancestry_collapses_boring_middle() {
        let mut ps = base_procs();
        ps.push(pr(800, 102, "python3", 0.0, MB));
        ps.push(pr(801, 800, "bash-wrapper", 0.0, MB));
        ps.push(pr(802, 801, "worker", 0.0, MB));
        ps.push(pr(803, 802, "leaf", 99.0, MB));
        let s = snap(ps);
        let step = ancestry_step(&s.ancestors(803)).unwrap();
        assert!(step.starts_with("launched by worker (pid 802)"), "{step}");
        assert!(step.contains("…2 more…"), "{step}");
        assert!(step.contains("-zsh (pid 102) shell"));
    }

    #[test]
    fn launcher_classes() {
        assert_eq!(classify_launcher(&pr(5, 1, "-zsh", 0.0, 0)), Launcher::Shell);
        assert_eq!(classify_launcher(&pr(5, 1, "iTerm2", 0.0, 0)), Launcher::Terminal);
        assert_eq!(classify_launcher(&pr(5, 1, "Code Helper (Plugin)", 0.0, 0)), Launcher::Ide);
        assert_eq!(classify_launcher(&pr(5, 1, "claude", 0.0, 0)), Launcher::Agent);
        assert_eq!(classify_launcher(&pr(1, 0, "launchd", 0.0, 0)), Launcher::Init);
        assert_eq!(classify_launcher(&pr(5, 1, "sshd", 0.0, 0)), Launcher::Remote);
        assert_eq!(classify_launcher(&pr(5, 1, "foo", 0.0, 0)), Launcher::Other);
    }

    #[test]
    fn hot_streak_logic() {
        let m = MIN_MS;
        let series = vec![
            (NOW - 10 * m, 10.0, 0),
            (NOW - 7 * m, 95.0, 0),
            (NOW - 4 * m, 99.0, 0),
            (NOW - m, 97.0, 0),
        ];
        let (start, dur) = hot_streak(&series, 90.0, NOW).unwrap();
        assert_eq!(start, NOW - 7 * m);
        assert_eq!(dur, 7 * m);
        // cooled down at the end -> no streak
        let mut cooled = series.clone();
        cooled.push((NOW, 5.0, 0));
        assert!(hot_streak(&cooled, 90.0, NOW).is_none());
        // too short
        assert!(hot_streak(&[(NOW - 10_000, 99.0, 0)], 90.0, NOW).is_none());
        assert!(hot_streak(&[], 90.0, NOW).is_none());
        // unsorted input
        let mut rev = series.clone();
        rev.reverse();
        assert_eq!(hot_streak(&rev, 90.0, NOW).unwrap().0, NOW - 7 * m);
    }

    #[test]
    fn diagnose_quiet_machine_is_empty() {
        let f = diagnose(&snap(base_procs()), None);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn diagnose_memory_pressure_critical_first() {
        let mut ps = base_procs();
        ps.push(pr(900, 102, "java", 160.0, 30 * GB));
        ps.push(pr(901, 1, "Docker Desktop", 1.0, 12 * GB));
        let mut s = snap(ps);
        s.system.mem_pressure = "critical".into();
        s.system.mem_used = 62 * GB;
        let f = diagnose(&s, None);
        assert_eq!(f[0].severity, "crit");
        assert!(f[0].title.contains("Memory"));
        assert!(f[0].detail.contains("java (pid 900)"));
        assert_eq!(f[0].pids[0], 900);
        assert_eq!(f[0].action.as_deref(), Some("kill 900"));
        assert!(f.iter().any(|x| x.title.contains("java is using 1.6 cores")));
        // Sorted: no warn before crit, no info before warn.
        let ranks: Vec<u8> = f.iter().map(|x| severity_rank(&x.severity)).collect();
        assert!(ranks.windows(2).all(|w| w[0] >= w[1]));
    }

    #[test]
    fn diagnose_unknown_pressure_falls_back_to_ratio() {
        let mut s = snap(base_procs());
        s.system.mem_pressure = "unknown".into();
        s.system.mem_used = 63 * GB;
        assert!(diagnose(&s, None).iter().any(|f| f.title.contains("Memory") && f.severity == "warn"));
    }

    #[test]
    fn diagnose_swap() {
        let mut s = snap(base_procs());
        s.system.swap_total = 6 * GB;
        s.system.swap_used = 5 * GB;
        assert!(diagnose(&s, None).iter().any(|f| f.title == "Heavy swap use"));
        s.system.swap_used = GB;
        assert!(!diagnose(&s, None).iter().any(|f| f.title == "Heavy swap use"));
    }

    #[test]
    fn diagnose_thermal() {
        let mut ps = base_procs();
        ps.push(pr(0, 0, "kernel_task", 250.0, GB));
        ps.push(pr(910, 102, "ffmpeg", 120.0, GB));
        let mut s = snap(ps);
        s.system.thermal = "critical".into();
        let f = diagnose(&s, None);
        let t = f.iter().find(|x| x.title == "Thermal throttling").unwrap();
        assert_eq!(t.severity, "crit");
        assert!(t.detail.contains("kernel_task is reserving 250%"));
        assert!(t.detail.contains("ffmpeg"));
        assert_eq!(t.action.as_deref(), Some("renice 910 10"));
        // kernel_task itself gets no kill/pause action
        let kt = f.iter().find(|x| x.pids == vec![0]).unwrap();
        assert!(kt.action.is_none());
    }

    #[test]
    fn diagnose_power_and_battery() {
        let mut ps = base_procs();
        let mut p = pr(920, 102, "blender", 80.0, GB);
        p.power_mw = 9000.0;
        ps.push(p);
        let mut s = snap(ps);
        s.system.power_mw = 12_000.0;
        s.system.on_battery = Some(true);
        s.system.battery_pct = Some(12.0);
        let f = diagnose(&s, None);
        assert!(f.iter().any(|x| x.title.contains("blender is drawing 9.0 W") && x.action.as_deref() == Some("pause 920")));
        assert_eq!(f[0].severity, "crit");
        assert!(f[0].title.contains("Battery at 12%"));
        s.system.on_battery = Some(false);
        assert!(!diagnose(&s, None).iter().any(|x| x.title.contains("Battery")));
    }

    #[test]
    fn diagnose_orphan_ports() {
        let mut ps = base_procs();
        ps.push(pr(930, 1, "node", 0.5, 200 * MB));
        let mut s = snap(ps);
        for port in [3000, 3001] {
            s.ports.push(Port {
                proto: Proto::Tcp,
                addr: "*".into(),
                port,
                pid: 930,
                process: "node".into(),
                state: "LISTEN".into(),
                orphan: true,
                note: "node next dev server in ~/app".into(),
            });
        }
        let f = diagnose(&s, None);
        let o: Vec<&Finding> = f.iter().filter(|x| x.title.starts_with("Orphaned")).collect();
        assert_eq!(o.len(), 1, "one finding per pid");
        assert!(o[0].detail.contains("3000, 3001"));
        assert_eq!(o[0].action.as_deref(), Some("kill 930 --tree"));
    }

    #[test]
    fn diagnose_stopped_and_zombies() {
        let mut ps = base_procs();
        let mut t = pr(940, 102, "vim", 0.0, 50 * MB);
        t.status = "T".into();
        ps.push(t);
        let mut fresh = pr(941, 102, "less", 0.0, MB);
        fresh.status = "T".into();
        fresh.start_time = (NOW / 1000 - 60) as u64;
        ps.push(fresh);
        for i in 0..3 {
            let mut z = pr(950 + i, 102, "defunct", 0.0, 0);
            z.status = "Z".into();
            ps.push(z);
        }
        let f = diagnose(&snap(ps), None);
        let st: Vec<&Finding> = f.iter().filter(|x| x.title.contains("paused")).collect();
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].pids, vec![940]);
        assert!(st[0].action.as_deref().unwrap().starts_with("resume 940"));
        let z = f.iter().find(|x| x.title.contains("zombie")).unwrap();
        assert_eq!(z.pids.len(), 3);
        assert!(z.detail.contains("-zsh (pid 102)"));
        assert_eq!(z.action.as_deref(), Some("kill 102"));
    }

    #[test]
    fn diagnose_reports_unattributed_cpu() {
        let mut s = Snapshot::default();
        s.system.cores = 10;
        s.system.cpu = 40.0; // 4 cores busy
        let mut ws = pr(392, 1, "WindowServer", 0.0, 0);
        ws.usage_unknown = true;
        s.procs = vec![pr(100, 1, "node", 100.0, 1 << 20), ws.clone()];
        let f = diagnose(&s, None);
        let u = f.iter().find(|f| f.title.contains("unattributed")).expect("unattributed finding");
        assert!(u.title.starts_with("3.0 cores"), "{}", u.title);
        assert_eq!(u.severity, "warn");
        assert!(u.detail.contains("WindowServer"));
        // why on such a process must not claim it is idle
        let e = explain(&s, 392, None);
        assert!(e.chain.iter().chain(std::iter::once(&e.headline)).any(|l| l.contains("usage unknown")), "{e:?}");
        assert!(!e.chain.iter().any(|l| l.contains("light load")));
        // fully measured machine: no finding
        s.procs = vec![pr(100, 1, "node", 400.0, 1 << 20)];
        assert!(!diagnose(&s, None).iter().any(|f| f.title.contains("unattributed")));
    }

    #[test]
    fn diagnose_swarm() {
        let mut ps = base_procs();
        ps.push(pr(1000, 102, "jest", 1.0, 100 * MB));
        for i in 0..35 {
            ps.push(pr(1001 + i, 1000, "node", 2.0, 80 * MB));
        }
        for i in 0..40 {
            ps.push(pr(2000 + i, 1, "Google Chrome Helper (Renderer)", 0.5, 50 * MB));
        }
        let f = diagnose(&snap(ps), None);
        let n = f.iter().find(|x| x.title == "35 copies of node").unwrap();
        assert_eq!(n.severity, "warn");
        assert_eq!(n.action.as_deref(), Some("kill 1000 --tree"));
        assert!(n.detail.contains("jest (pid 1000)"));
        let c = f.iter().find(|x| x.title.contains("Chrome")).unwrap();
        assert_eq!(c.severity, "info");
        assert!(c.action.is_none());
    }

    #[test]
    fn diagnose_disk_net_load() {
        let mut ps = base_procs();
        let mut w = pr(1100, 102, "dd", 30.0, MB);
        w.disk_write_bps = 400 * MB;
        ps.push(w);
        let mut n = pr(1101, 1, "nsurlsessiond", 3.0, 30 * MB);
        n.net_rx_bps = 40 * MB;
        ps.push(n);
        let mut s = snap(ps);
        s.system.load = [40.0, 30.0, 20.0];
        let f = diagnose(&s, None);
        assert!(f.iter().any(|x| x.title.contains("dd is writing 400M/s")));
        let nf = f.iter().find(|x| x.title.contains("nsurlsessiond")).unwrap();
        assert!(nf.detail.contains("downloading"));
        let l = f.iter().find(|x| x.title.starts_with("Load 40.0")).unwrap();
        assert_eq!(l.severity, "warn");
    }

    #[test]
    fn formatting() {
        assert_eq!(human_bytes(512), "512B");
        assert_eq!(human_bytes(3 * MB), "3M");
        assert_eq!(human_bytes(GB + GB / 2), "1.5G");
        assert_eq!(human_watts(450.0), "450 mW");
        assert_eq!(human_watts(5200.0), "5.2 W");
        assert_eq!(human_dur_ms(42_000), "42s");
        assert_eq!(human_dur_ms(7 * MIN_MS), "7m");
        assert_eq!(human_dur_ms(125 * MIN_MS), "2h5m");
        assert_eq!(human_dur_ms(26 * 60 * MIN_MS), "1d2h");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(status_word("Z"), "zombie (exited, parent hasn't reaped it)");
    }
}
