//! Blame chains ("why") and whole-machine diagnosis ("doctor"). OWNER: blame agent.
//!
//! Everything here is pure logic over a [`Snapshot`] (plus optional flight-recorder
//! [`History`]); no syscalls, no signals. History errors are swallowed: a missing or
//! broken recorder only means fewer "how long has this been going on" details.
use crate::fs::{Growth, Volume};
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
    let os = platform(snap);
    let descendants = snap.descendants(pid);
    let ancestors = snap.ancestors(pid);
    let tree = TreeCost::of(p, &descendants);
    let kthread = os == Os::Linux && is_kernel_thread(p);
    let cg = if os == Os::Linux { parse_cgroup(&p.cgroup) } else { CgInfo::default() };
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
    let mut chain = vec![symptom(snap, os, p, &tree)];
    let mut proc_step = format!("{} (pid {})", p.name, p.pid);
    if !p.cmd.is_empty() && p.cmd != p.name {
        proc_step.push_str(&format!(": `{}`", truncate(&p.cmd, 90)));
    }
    chain.push(proc_step);
    if kthread {
        chain.push(
            "kernel thread (child of kthreadd): it does kernel work for the whole system, not for one program; its cost is caused by something else"
                .into(),
        );
    } else if let Some(a) = ancestry_step(&ancestors, os) {
        chain.push(a);
    }
    if os == Os::Linux {
        chain.extend(placement_steps(snap, p, &cg));
    }
    if is_dstate(p) && os != Os::Mac {
        chain.push(
            "it is in uninterruptible sleep (D): blocked inside the kernel waiting for IO (disk, NFS/FUSE/network mount, or a stuck device); signals, even kill -9, wait until that IO returns"
                .into(),
        );
    }
    let causes = cause_steps(snap, os, p, &tree, hist, now);
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
    if !p.cgroup.is_empty() && p.cgroup != "/" {
        evidence.push(format!("cgroup {}", p.cgroup));
    }
    if let Some(ps) = snap.system.psi.filter(|_| os == Os::Linux) {
        evidence.push(format!(
            "system pressure (PSI avg10): cpu {:.0}%, memory {:.0}% some / {:.0}% full, io {:.0}% some / {:.0}% full",
            ps.cpu_some, ps.mem_some, ps.mem_full, ps.io_some, ps.io_full
        ));
    }
    if series.len() >= 2 {
        let peak = series.iter().map(|s| s.1).fold(0.0f32, f32::max);
        let avg = series.iter().map(|s| s.1).sum::<f32>() / series.len() as f32;
        evidence.push(format!("last 30m: avg {avg:.0}% CPU, peak {peak:.0}% ({} samples)", series.len()));
    }
    evidence.extend(causes.evidence);

    // ---- suggestions ----
    let mut suggestions = Vec::new();
    suggestions.extend(causes.suggestions);
    if is_dstate(p) && os == Os::Linux {
        suggestions.push(format!(
            "see what it waits on: cat /proc/{pid}/wchan (sudo cat /proc/{pid}/stack for the full kernel stack); check `dmesg` for IO errors or hung-task warnings"
        ));
    }
    if is_stopped(p) {
        suggestions.push(format!("it is paused; resume it: fat resume {pid}"));
        suggestions.push(format!("or stop it for good: fat kill {pid}{}", tree_flag(&descendants)));
    } else if kthread {
        suggestions.push(format!(
            "{} is a kernel thread: it can't be paused or killed, and renicing it doesn't help. Address the cause above instead.",
            p.name
        ));
    } else if is_system_critical_on(os, p) {
        let msg = match os {
            Os::Linux if is_package_manager(p) => format!(
                "{} is installing or updating packages; interrupting it can leave packages half-configured. Let it finish.",
                p.name
            ),
            Os::Linux if p.pid == 1 => format!(
                "{} is pid 1, the init of this machine or container; don't kill it. Address the cause above instead.",
                p.name
            ),
            Os::Linux => format!("{} is a core Linux system/session service; don't kill it. Address the cause above instead.", p.name),
            Os::Other => format!("{} is a core system process; don't kill it. Address the cause above instead.", p.name),
            Os::Mac => format!("{} is part of macOS; don't kill it. Address the cause above instead.", p.name),
        };
        suggestions.push(msg);
        if p.pid != 0 && p.pid != 1 && p.name != "kernel_task" {
            suggestions.push(format!("if it's hurting right now, lower its priority: fat renice {pid} 10"));
        }
    } else {
        if os == Os::Linux {
            suggestions.extend(placement_suggestions(snap, &cg, p));
        }
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
    let os = platform(snap);
    let mut out = Vec::new();

    rule_memory(snap, os, &mut out);
    rule_swap(snap, &mut out);
    rule_thermal(snap, os, &mut out);
    rule_cpu(snap, os, hist, now, &mut out);
    rule_power(snap, os, &mut out);
    rule_orphans(snap, &mut out);
    rule_stopped(snap, hist, now, &mut out);
    rule_zombies(snap, &mut out);
    rule_swarms(snap, os, &mut out);
    rule_disk(snap, os, &mut out);
    rule_net(snap, os, &mut out);
    rule_load(snap, os, &mut out);
    rule_unattributed(snap, os, &mut out);
    if os != Os::Mac {
        rule_psi(snap, os, &mut out);
        rule_temp(snap, os, &mut out);
        rule_dstate(snap, os, hist, now, &mut out);
    }
    rule_containers(snap, &mut out);

    out.sort_by_key(|f| std::cmp::Reverse(severity_rank(&f.severity)));
    out
}

// ======================================================================
// Storage
// ======================================================================

/// Storage facts for the disk rules. The caller gathers them (volumes, growth report,
/// deleted-but-open files); blame stays pure.
#[derive(Debug, Clone, Default)]
pub struct FsFacts {
    pub volumes: Vec<Volume>,
    pub growth: Option<Growth>,
    pub deleted_open: Vec<(u32, String, String, u64)>,
}

/// [`diagnose`] plus the storage rules, ranked together.
pub fn diagnose_with_fs(snap: &Snapshot, hist: Option<&History>, fs: &FsFacts) -> Vec<Finding> {
    let mut out = diagnose(snap, hist);
    out.extend(diagnose_fs(fs));
    out.sort_by_key(|f| std::cmp::Reverse(severity_rank(&f.severity)));
    out
}

/// Disk findings: volumes nearly full or filling fast, space held by deleted-but-open files,
/// large swap files. Advice only: fat never deletes anything.
pub fn diagnose_fs(fs: &FsFacts) -> Vec<Finding> {
    let mut out = Vec::new();
    let watched = watched_volumes(&fs.volumes);
    rule_volume_full(&watched, fs, &mut out);
    rule_volume_filling(&watched, fs, &mut out);
    rule_deleted_open(fs, &mut out);
    rule_swapfiles(fs, &mut out);
    out.sort_by_key(|f| std::cmp::Reverse(severity_rank(&f.severity)));
    out
}

const FS_SKIP_TYPES: &[&str] = &["squashfs", "iso9660", "udf", "cd9660", "devtmpfs", "ramfs", "devfs", "autofs", "nullfs"];

/// Local, writable, real volumes, one per underlying filesystem: APFS volumes of one container
/// (and Linux bind mounts of one device) report the same space, so only the first is kept,
/// preferring the primary (user data) volume.
fn watched_volumes(vols: &[Volume]) -> Vec<&Volume> {
    let mut v: Vec<&Volume> = vols
        .iter()
        .filter(|v| !v.read_only && !v.remote && v.total >= 2 * GB && !FS_SKIP_TYPES.contains(&v.fstype.as_str()))
        .filter(|v| !(v.mount.starts_with("/System/Volumes/") && v.mount != "/System/Volumes/Data"))
        .collect();
    v.sort_by(|a, b| b.primary.cmp(&a.primary).then(a.mount.len().cmp(&b.mount.len())));
    let mut out: Vec<&Volume> = Vec::new();
    for x in v {
        let same = |o: &&Volume| {
            (!x.device.is_empty() && o.device == x.device && x.device.starts_with('/'))
                || (o.total == x.total && o.avail / (256 * MB) == x.avail / (256 * MB))
        };
        if !out.iter().any(same) {
            out.push(x);
        }
    }
    out
}

fn fill_ratio(v: &Volume) -> f64 {
    if v.total == 0 { 0.0 } else { v.total.saturating_sub(v.avail) as f64 / v.total as f64 }
}

/// The volume holding `path`: longest mount prefix; macOS firmlinks (/Users, /Applications,
/// /private ... live on the Data volume) resolve to the primary volume instead of the sealed "/".
fn volume_of<'a>(vols: &'a [Volume], path: &str) -> Option<&'a Volume> {
    let v = vols
        .iter()
        .filter(|v| crate::tui::app::path_within(path, &v.mount))
        .max_by_key(|v| v.mount.len())?;
    if v.mount == "/" && v.read_only {
        return vols.iter().find(|p| p.primary).or(Some(v));
    }
    Some(v)
}

/// Biggest positive growers on volume `v`: "~/Library/Caches +3.0G (node 200)".
fn growers_on<'a>(fs: &'a FsFacts, v: &Volume, n: usize) -> Vec<&'a crate::fs::Grower> {
    let Some(g) = &fs.growth else { return Vec::new() };
    let mut out: Vec<&crate::fs::Grower> =
        g.growers.iter().filter(|x| x.delta > 0 && volume_of(&fs.volumes, &x.path).is_none_or(|o| o.mount == v.mount)).collect();
    out.sort_by_key(|x| std::cmp::Reverse(x.delta));
    out.truncate(n);
    out
}

fn grower_text(x: &crate::fs::Grower) -> String {
    let mut t = format!("{} +{}", tilde(&x.path), human_bytes(x.delta.max(0) as u64));
    if let Some((pid, name, _)) = x.writers.iter().max_by_key(|w| w.2) {
        t.push_str(&format!(" ({name} {pid})"));
    }
    t
}

fn rule_volume_full(watched: &[&Volume], fs: &FsFacts, out: &mut Vec<Finding>) {
    for v in watched {
        let r = fill_ratio(v);
        let sev = if r >= 0.97 {
            "crit"
        } else if r >= 0.90 {
            "warn"
        } else {
            continue;
        };
        let mut detail = format!(
            "{} of {} used on {} ({}), {} available.",
            human_bytes(v.total.saturating_sub(v.avail)),
            human_bytes(v.total),
            if v.device.is_empty() { "?" } else { &v.device },
            v.fstype,
            human_bytes(v.avail)
        );
        if let Some(p) = v.purgeable.filter(|p| *p >= GB) {
            detail.push_str(&format!(" macOS can reclaim about {} of purgeable space (caches, local snapshots) on demand.", human_bytes(p)));
        }
        let top = growers_on(fs, v, 3);
        if !top.is_empty() {
            detail.push_str(&format!(" Growing lately: {}.", top.iter().map(|x| grower_text(x)).collect::<Vec<_>>().join(", ")));
        }
        detail.push_str(&format!(" See what uses it: the Fs tab, or `fat fs {}`; `fat fs --growth` for recent growth.", v.mount));
        let pids = top.iter().flat_map(|x| x.writers.iter().map(|w| w.0)).collect();
        out.push(finding(sev, format!("Disk {} is {:.0}% full ({} left)", v.mount, r * 100.0, human_bytes(v.avail)), detail, pids, None));
    }
}

fn rule_volume_filling(watched: &[&Volume], fs: &FsFacts, out: &mut Vec<Finding>) {
    for v in watched {
        let (Some(eta), Some(bps)) = (v.eta_full_s, v.fill_bps) else { continue };
        if bps <= 0.0 {
            continue;
        }
        let sev = if eta < 2 * 3600 {
            "crit"
        } else if eta < 24 * 3600 {
            "warn"
        } else {
            continue;
        };
        let per10 = (bps * 600.0) as u64;
        let top = growers_on(fs, v, 3);
        let mut detail = format!("{} is filling at {}/10m ({} left).", v.mount, human_bytes(per10), human_bytes(v.avail));
        if top.is_empty() {
            detail.push_str(" Open the Fs tab and press g (or `fat fs --growth --since 10m`) to see what is growing.");
        } else {
            detail.push_str(&format!(" Growing: {}.", top.iter().map(|x| grower_text(x)).collect::<Vec<_>>().join(", ")));
        }
        let pids: Vec<u32> = top.iter().flat_map(|x| x.writers.iter().map(|w| w.0)).collect();
        out.push(finding(sev, format!("{} will be full in {}", v.mount, human_dur_ms(eta as i64 * 1000)), detail, pids, None));
    }
}

fn rule_deleted_open(fs: &FsFacts, out: &mut Vec<Finding>) {
    let mut by_pid: Vec<(u32, String, u64, Vec<&str>)> = Vec::new();
    for (pid, name, path, bytes) in &fs.deleted_open {
        match by_pid.iter_mut().find(|e| e.0 == *pid) {
            Some(e) => {
                e.2 += bytes;
                e.3.push(path);
            }
            None => by_pid.push((*pid, name.clone(), *bytes, vec![path])),
        }
    }
    by_pid.sort_by_key(|e| std::cmp::Reverse(e.2));
    for (pid, name, bytes, paths) in by_pid.into_iter().filter(|e| e.2 >= GB) {
        let shown: Vec<String> = paths.iter().take(3).map(|p| tilde(p)).collect();
        let more = if paths.len() > 3 { format!(" and {} more", paths.len() - 3) } else { String::new() };
        out.push(finding(
            "warn",
            format!("{name} (pid {pid}) holds {} of deleted files", human_bytes(bytes)),
            format!(
                "These files were deleted but {name} still has them open, so their space is not freed until it closes them: {}{more}. \
                 Restarting {name} (pid {pid}) releases the space; nothing needs to be deleted.",
                shown.join(", ")
            ),
            vec![pid],
            None,
        ));
    }
}

fn rule_swapfiles(fs: &FsFacts, out: &mut Vec<Finding>) {
    let Some(vm) = fs.volumes.iter().find(|v| v.mount == "/System/Volumes/VM") else { return };
    let sev = if vm.used >= 16 * GB {
        "warn"
    } else if vm.used >= 8 * GB {
        "info"
    } else {
        return;
    };
    out.push(finding(
        sev,
        format!("Swap files use {} of disk", human_bytes(vm.used)),
        "macOS writes swap files (and the sleep image) to /System/Volumes/VM when RAM runs short. They shrink again once \
         memory pressure eases or after a reboot. Quit or pause the memory-heavy apps (see Procs sorted by mem); never \
         delete swap files by hand."
            .into(),
        Vec::new(),
        None,
    ));
}

/// "/Users/me/x" -> "~/x" for the current user.
fn tilde(p: &str) -> String {
    if let Some(h) = dirs::home_dir().map(|h| h.display().to_string()).filter(|h| h.len() > 1)
        && let Some(rest) = p.strip_prefix(&h)
        && (rest.is_empty() || rest.starts_with('/'))
    {
        return format!("~{rest}");
    }
    p.to_string()
}

/// How a known space hog is recognized.
enum PathPat {
    /// Relative to a home directory ("Library/Caches" = ~/Library/Caches).
    Home(&'static str),
    /// Absolute path.
    Abs(&'static str),
    /// Any directory with this name (node_modules, target).
    Name(&'static str),
    /// A directory whose name ends with this (".photoslibrary").
    Suffix(&'static str),
}

/// Common space hogs with safe advice. Order matters: more specific first.
static KNOWN_DIRS: &[(PathPat, &str)] = &[
    // ---- macOS, per user ----
    (PathPat::Home("Library/Caches/Homebrew"), "Homebrew downloads. `brew cleanup --prune=all` removes old ones."),
    (PathPat::Home("Library/Caches"), "App caches: apps rebuild them, so they are safe to clear per app while it is closed. Big ones are usually browsers, Xcode, Homebrew (`brew cleanup`), pip and yarn."),
    (PathPat::Home("Library/Developer/Xcode/DerivedData"), "Xcode build products and indexes, rebuilt automatically. Clear them from Xcode (Settings › Locations) or remove the folder while Xcode is closed."),
    (PathPat::Home("Library/Developer/Xcode/Archives"), "Archived app builds (needed to symbolicate crashes of shipped versions). Prune old ones in Xcode's Organizer."),
    (PathPat::Home("Library/Developer/Xcode/iOS DeviceSupport"), "Debug symbols copied for each iOS version you connected; old versions are safe to remove."),
    (PathPat::Home("Library/Developer/CoreSimulator"), "iOS/watchOS simulators and their data. `xcrun simctl delete unavailable` removes simulators of runtimes you no longer have; `xcrun simctl runtime list` shows runtime sizes."),
    (PathPat::Home("Library/Containers/com.docker.docker"), "Docker Desktop's VM disk: images, containers, volumes, build cache. `docker system df` shows usage, `docker system prune` frees it (add `--volumes` only if you don't need the data)."),
    (PathPat::Home(".orbstack"), "OrbStack: Linux machines plus Docker images and volumes. `docker system df` / `docker system prune` for Docker data; `orb list` and `orb delete <machine>` for machines."),
    (PathPat::Suffix(".dev.orbstack"), "OrbStack data (Linux machines, Docker images and volumes). `docker system df` / `docker system prune` for Docker data; `orb list` / `orb delete <machine>` for machines."),
    (PathPat::Home("Library/Application Support/Google/Chrome"), "Chrome profiles: history, caches, service workers, extensions. Clear browsing data from Chrome itself instead of deleting files."),
    (PathPat::Home("Library/Application Support/MobileSync/Backup"), "iPhone/iPad backups. Manage them in Finder (select the device › Manage Backups)."),
    (PathPat::Home("Library/Mobile Documents"), "iCloud Drive. With 'Optimize Mac Storage' macOS evicts local copies itself; deleting here also deletes from iCloud."),
    (PathPat::Home("Library/Mail"), "Mail messages and attachments."),
    (PathPat::Home("Library/Messages"), "Messages history and attachments. Settings › General › Keep messages limits it."),
    (PathPat::Suffix(".photoslibrary"), "A Photos library. Use iCloud Photos with 'Optimize Mac Storage' rather than touching files inside it."),
    (PathPat::Home(".Trash"), "The Trash: deleted files keep using space until it is emptied."),
    // ---- developer caches, any OS ----
    (PathPat::Home(".cargo/registry"), "Downloaded crate sources and index for Cargo. Safe to clear (re-downloaded on the next build)."),
    (PathPat::Home(".cargo/git"), "Git checkouts of Cargo dependencies. Safe to clear (re-fetched on the next build)."),
    (PathPat::Home(".rustup/toolchains"), "Installed Rust toolchains. `rustup toolchain list` and `rustup toolchain uninstall <name>`."),
    (PathPat::Home(".npm"), "npm's download cache. `npm cache clean --force` clears it (re-downloaded when needed)."),
    (PathPat::Home(".cache/huggingface"), "Downloaded ML models (Hugging Face). `huggingface-cli scan-cache` shows them, `huggingface-cli delete-cache` prunes."),
    (PathPat::Home(".cache"), "Per-user caches (pip, uv, go-build, yarn, Hugging Face models, …). Safe to clear per tool; each rebuilds its own."),
    (PathPat::Home(".gradle/caches"), "Gradle dependency and build caches; safe to clear when no build runs (re-downloaded)."),
    (PathPat::Home(".m2/repository"), "Maven's local repository; artifacts are re-downloaded as needed."),
    (PathPat::Home("go/pkg/mod"), "Go module cache. `go clean -modcache` clears it."),
    (PathPat::Home(".local/share/containers"), "Podman images and containers. `podman system df`, then `podman system prune`."),
    (PathPat::Home(".local/share/Trash"), "The Trash: deleted files keep using space until it is emptied."),
    (PathPat::Name("node_modules"), "npm/yarn/pnpm dependencies of one project, reinstalled by `npm install`. Old projects' node_modules are safe to remove (`npx npkill` finds them)."),
    (PathPat::Name("target"), "Probably a Rust (Cargo) or Maven build directory: `cargo clean` (or `mvn clean`) in the project frees it; it is rebuilt on the next build."),
    // ---- macOS, system ----
    (PathPat::Abs("/private/var/vm"), "Swap files and the sleep image. They grow under memory pressure and shrink after it eases or on reboot; never delete them by hand."),
    (PathPat::Abs("/System/Volumes/VM"), "Swap files and the sleep image. They grow under memory pressure and shrink after it eases or on reboot; never delete them by hand."),
    (PathPat::Abs("/private/var/folders"), "Per-user temporary files and caches managed by macOS. Cleared automatically (mostly at reboot); don't delete by hand."),
    (PathPat::Abs("/private/var/db/diagnostics"), "The unified system log. macOS caps and rotates it."),
    (PathPat::Abs("/Library/Developer/CoreSimulator"), "Simulator runtimes. `xcrun simctl runtime list` shows them, `xcrun simctl runtime delete <id>` removes one."),
    (PathPat::Abs("/System/Volumes/Data"), "The data volume behind /Users, /Applications, /Library … (firmlinks). Space that directories don't explain is often APFS local snapshots (`tmutil listlocalsnapshots /`, removed automatically when space runs low) or purgeable files."),
    // ---- Linux ----
    (PathPat::Abs("/var/log/journal"), "The systemd journal. `journalctl --disk-usage` shows its size; `sudo journalctl --vacuum-size=500M` trims it and SystemMaxUse= in journald.conf caps it."),
    (PathPat::Abs("/var/log"), "System logs, rotated by logrotate. Look for one huge file from a noisy service."),
    (PathPat::Abs("/var/lib/docker"), "Docker images, containers, volumes and build cache. `docker system df`, then `docker system prune` or `docker builder prune` (add `--volumes` only if you don't need the data)."),
    (PathPat::Abs("/var/lib/containerd"), "containerd images and snapshots (Kubernetes, nerdctl). `crictl rmi --prune` or `nerdctl system prune`."),
    (PathPat::Abs("/var/lib/containers"), "Podman images and containers. `podman system df`, then `podman system prune`."),
    (PathPat::Abs("/var/cache/apt"), "Downloaded .deb packages. `sudo apt clean` removes them."),
    (PathPat::Abs("/var/lib/snapd"), "Snap packages; snapd keeps old revisions. `snap list --all` shows disabled ones; `sudo snap set system refresh.retain=2` keeps fewer."),
    (PathPat::Abs("/var/lib/flatpak"), "Flatpak runtimes and apps. `flatpak uninstall --unused` removes unused runtimes."),
    (PathPat::Abs("/var/tmp"), "Temporary files kept across reboots; systemd-tmpfiles ages them out."),
    (PathPat::Abs("/tmp"), "Temporary files; usually cleared at reboot."),
    (PathPat::Abs("/"), "Space that directories don't explain may be filesystem snapshots (APFS: `tmutil listlocalsnapshots /`; btrfs/zfs snapshots), reserved blocks, or deleted files still held open (see doctor)."),
];

/// Safe advice for a known space hog at or above `path` ("inside ~/Library/Caches: …").
/// Text only: fat never deletes anything.
pub fn explain_path(path: &str) -> Option<String> {
    explain_path_in(path, dirs::home_dir().map(|h| h.display().to_string()).as_deref())
}

fn explain_path_in(path: &str, home: Option<&str>) -> Option<String> {
    // macOS firmlinks: /System/Volumes/Data/Users/x is /Users/x.
    let norm = match path.strip_prefix("/System/Volumes/Data") {
        Some(rest) if rest.starts_with('/') && rest.len() > 1 => rest,
        _ => path,
    };
    let norm = if norm.len() > 1 { norm.trim_end_matches('/') } else { norm };
    // Homes: ours, and whichever /Users/<u> or /home/<u> (or /root) the path is in.
    let mut homes: Vec<String> = home.filter(|h| h.len() > 1).map(|h| vec![h.trim_end_matches('/').to_string()]).unwrap_or_default();
    for base in ["/Users/", "/home/"] {
        if let Some(rest) = norm.strip_prefix(base)
            && let Some(user) = rest.split('/').next().filter(|u| !u.is_empty())
        {
            homes.push(format!("{base}{user}"));
        }
    }
    if crate::tui::app::path_within(norm, "/root") {
        homes.push("/root".into());
    }
    let mut cur = Some(norm.to_string());
    while let Some(dir) = cur {
        let name = dir.rsplit('/').next().unwrap_or("");
        for (pat, text) in KNOWN_DIRS {
            let hit = match pat {
                PathPat::Abs(a) => dir == *a,
                PathPat::Home(rel) => homes.iter().any(|h| dir == format!("{h}/{rel}")),
                PathPat::Name(n) => name == *n,
                PathPat::Suffix(suf) => name.len() > suf.len() && name.ends_with(suf),
            };
            if hit {
                if dir == norm {
                    return Some((*text).to_string());
                }
                // "/" only explains itself, not everything below it.
                if dir == "/" {
                    return None;
                }
                let shown = homes.first().and_then(|h| dir.strip_prefix(h.as_str()).map(|r| format!("~{r}"))).unwrap_or_else(|| dir.clone());
                return Some(format!("inside {shown}: {text}"));
            }
        }
        cur = crate::tui::app::parent_dir(&dir);
    }
    None
}

/// Human explanation for well-known system daemons (mds_stores, kernel_task, kswapd0, ...)
/// on the platform fat was built for.
#[allow(dead_code)]
pub fn known(name: &str) -> Option<&'static str> {
    known_for(name, host_os())
}

/// [`known`] for a specific platform (a snapshot may come from a remote Linux host).
fn known_for(name: &str, os: Os) -> Option<&'static str> {
    let n = name.trim();
    let lower = n.to_ascii_lowercase();
    KNOWN.iter().find(|k| k.os.is_none_or(|o| o == os) && k.matches(n, &lower)).map(|k| k.text)
}

/// Like [`known_for`] but also looks at the command line, for processes whose name alone is
/// generic (`java` running the Gradle daemon, `chrome --type=renderer`).
fn known_proc(p: &Proc, os: Os) -> Option<&'static str> {
    let lname = p.name.to_ascii_lowercase();
    KNOWN_CMD
        .iter()
        .find(|(names, needle, _)| names.contains(&lname.as_str()) && p.cmd.contains(needle))
        .map(|(_, _, text)| *text)
        .or_else(|| known_for(&p.name, os))
}

// ======================================================================
// Platform
// ======================================================================

/// Which OS a snapshot describes. Blame is pure logic over snapshots, which may come from
/// another host (fleet, history), so this is decided from the data, not only from `cfg!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Os {
    Mac,
    Linux,
    Other,
}

fn host_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::Mac
    } else if cfg!(target_os = "linux") {
        Os::Linux
    } else {
        Os::Other
    }
}

fn platform(snap: &Snapshot) -> Os {
    let os = snap.system.os.to_ascii_lowercase();
    if os.contains("macos") || os.contains("mac os") || os.contains("darwin") || os.contains("os x") {
        return Os::Mac;
    }
    const DISTROS: &[&str] = &[
        "linux", "ubuntu", "debian", "fedora", "arch", "alpine", "centos", "red hat", "rhel", "nixos", "suse",
        "mint", "pop!_os", "rocky", "alma", "gentoo", "amazon",
    ];
    if DISTROS.iter().any(|d| os.contains(d)) {
        return Os::Linux;
    }
    if snap.system.psi.is_some() || snap.procs.iter().any(|p| !p.cgroup.is_empty()) {
        return Os::Linux;
    }
    for p in &snap.procs {
        if (p.pid == 1 && p.name == "launchd") || p.name == "kernel_task" {
            return Os::Mac;
        }
        if (p.pid == 1 && p.name == "systemd") || (p.pid == 2 && p.name == "kthreadd") {
            return Os::Linux;
        }
    }
    host_os()
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
    /// Only on this platform (None = everywhere).
    os: Option<Os>,
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
        Known { m: M::$kind($pat), os: None, text: $text }
    };
    (linux $kind:ident $pat:literal => $text:literal) => {
        Known { m: M::$kind($pat), os: Some(Os::Linux), text: $text }
    };
}

/// (lowercase process names, substring of cmd, explanation). Checked before [`KNOWN`].
static KNOWN_CMD: &[(&[&str], &str, &str)] = &[
    (&["java"], "GradleDaemon", "Gradle build daemon: a long-lived JVM that runs your Gradle builds and keeps GBs of heap warm between them. `gradle --stop` (or `./gradlew --stop`) frees it."),
    (&["java"], "KotlinCompileDaemon", "Kotlin compile daemon, started by Gradle/IntelliJ builds. Idle ones hold a lot of RAM; `gradle --stop` ends them."),
    (&["chrome", "chromium", "chromium-browser", "google-chrome"], "--type=renderer", "A Chrome/Chromium tab or extension renderer. One heavy renderer is usually one heavy tab (video, ads, a runaway script). Shift+Esc opens Chrome's Task Manager to find it."),
    (&["chrome", "chromium", "chromium-browser", "google-chrome"], "--type=gpu-process", "Chrome's GPU process: compositing and video decode for all tabs."),
];

/// Order matters: more specific patterns first. Linux kernel/daemon names come from
/// /proc/<pid>/comm, which the kernel truncates to 15 chars ("systemd-journal",
/// "unattended-upgr", "containerd-shim"), hence the prefixes.
static KNOWN: &[Known] = &[
    // ---- Linux-only overrides of names that also exist on macOS ----
    k!(linux Eq "cargo" => "Rust build tool. Spawns rustc/build scripts; heavy CPU while building, and creates large target/ trees that file watchers (inotify), desktop indexers (tracker, baloo) and backups then react to."),
    k!(linux Prefix "orbstack-agent" => "OrbStack's in-VM agent: connects this Linux machine to the macOS host (file sharing, networking, port forwarding)."),
    // ---- Linux kernel threads ----
    k!(Prefix "kswapd" => "Kernel memory reclaim thread. A busy kswapd means you're short on RAM: the kernel is evicting page cache and swapping to free memory. Find the memory hog, not kswapd."),
    k!(Prefix "kworker/" => "Kernel worker thread running queued kernel work: block IO completion, filesystem writeback, driver and interrupt bottom halves. The suffix names the queue (-kblockd = disk, -events = misc). Look at disk IO and interrupts, not the thread."),
    k!(Prefix "ksoftirqd/" => "Per-CPU soft-interrupt handler. Busy means heavy network or interrupt load: high packet rates, a traffic flood, or a NIC whose interrupts all land on one CPU."),
    k!(Prefix "kcompactd" => "Kernel memory compaction: defragments RAM so large/huge-page allocations succeed. Busy under memory pressure or fragmentation; often seen with khugepaged."),
    k!(Eq "khugepaged" => "Transparent Huge Pages collapser: merges 4 KB pages into 2 MB huge pages in the background. Heavy activity can stall latency-sensitive apps; THP=madvise avoids it."),
    k!(Prefix "jbd2/" => "ext4 journaling thread for one filesystem (jbd2/<device>). Busy means an fsync-heavy workload (databases, package managers, builds, editors saving often) is forcing journal commits."),
    k!(Eq "kthreadd" => "Kernel thread daemon (pid 2): the parent of every kernel thread. It does no real work itself."),
    k!(Prefix "irq/" => "Threaded interrupt handler for one device (irq/<n>-<device>). Busy means that device (NIC, NVMe, GPU) is raising a lot of interrupts."),
    k!(Prefix "rcu_" => "Kernel RCU grace-period thread. Rarely busy; sustained CPU here points at a kernel or driver problem."),
    k!(Prefix "migration/" => "Per-CPU scheduler thread that moves tasks between CPUs. Normally idle."),
    k!(Prefix "btrfs" => "Btrfs filesystem kernel worker (transaction commits, cleaner, scrub/balance). Busy during heavy writes, snapshot deletion, or a running scrub/balance."),
    // ---- Linux system daemons ----
    k!(Prefix "systemd-journal" => "systemd-journald: collects every service's logs. High CPU or disk writes mean something is logging furiously; find the noisy unit and fix or rate-limit it."),
    k!(Prefix "systemd-oomd" => "systemd's userspace OOM killer: watches memory pressure (PSI) and kills whole cgroups before the machine thrashes."),
    k!(Prefix "systemd-udevd" => "Device manager: handles hotplug and device events. CPU spikes mean a device event storm (flaky USB, docking, a udev rule loop)."),
    k!(Eq "systemd" => "systemd: as pid 1 it starts and supervises every service; as `systemd --user` it runs your session's services. Processes re-parented to it lost their original launcher. High CPU usually means a unit is crash-looping or a flood of D-Bus/udev events."),
    k!(Eq "rsyslogd" => "Traditional syslog daemon writing /var/log/syslog. Busy when a program floods syslog; same root cause as a busy journald."),
    k!(Eq "dbus-daemon" => "D-Bus message bus: IPC between system/desktop services. High CPU means some service is spamming messages (`busctl monitor` shows who)."),
    k!(Eq "dbus-broker" => "D-Bus message bus: IPC between system/desktop services. High CPU means some service is spamming messages (`busctl monitor` shows who)."),
    k!(Prefix "containerd-shim" => "Per-container shim: parent of one container's processes, keeps it running across containerd restarts. Its cost is the container below it."),
    k!(Eq "containerd" => "containerd: the container runtime under Docker and Kubernetes. Its own CPU is image pulls/unpacking and container lifecycle; workloads run as separate processes under containerd-shim."),
    k!(Eq "runc" => "OCI runtime that creates containers. Short-lived; seeing it often means containers are being (re)started, maybe a restart loop."),
    k!(Eq "conmon" => "Podman container monitor: parent of one container's processes. Its cost is the container below it."),
    k!(Eq "kubelet" => "Kubernetes node agent: starts pods, runs probes, reports status. High CPU usually means many pods, aggressive probes, or churn from crash-looping pods."),
    k!(Eq "snapd" => "Snap package daemon: refreshes snaps in the background (downloads, squashfs mounts). `snap changes` shows what it is doing."),
    k!(Eq "packagekitd" => "PackageKit: package metadata refreshes and updates for desktop software centers. Busy while refreshing caches or installing updates."),
    k!(Prefix "unattended-upgr" => "unattended-upgrades: automatic security updates via apt, run daily by a systemd timer. Heavy disk/CPU while installing; let it finish (interrupting can leave dpkg half-configured)."),
    k!(Eq "apt" => "apt package manager: downloading, unpacking or configuring packages. Let it finish."),
    k!(Eq "apt-get" => "apt package manager: downloading, unpacking or configuring packages. Let it finish."),
    k!(Prefix "dpkg" => "Debian package manager unpacking/configuring packages. Heavy disk IO while it runs; don't kill it mid-run (packages can be left half-configured)."),
    k!(Prefix "updatedb" => "updatedb (locate database): walks every directory to index file names, daily from a timer. Heavy IO on big trees; add build/dependency dirs to PRUNEPATHS in /etc/updatedb.conf."),
    k!(Prefix "plocate-update" => "plocate's updatedb: walks every directory to index file names, daily from a timer. Heavy IO on big trees; add build/dependency dirs to PRUNEPATHS in /etc/updatedb.conf."),
    k!(Prefix "tracker-miner" => "GNOME Tracker file indexer (search in Files/Activities). Busy after lots of new files appear (node_modules, target/, unpacked archives), like Spotlight on macOS."),
    k!(Prefix "tracker-extract" => "GNOME Tracker metadata extractor: reads new/changed files for search. Busy after big file trees change."),
    k!(Prefix "baloo_file" => "KDE Baloo file indexer. Busy after many new or changed files; `balooctl suspend` pauses it."),
    k!(Eq "gnome-shell" => "GNOME's compositor and desktop shell: draws every window. Rises with animations, many/high-refresh displays and misbehaving extensions; steadily growing RAM is usually an extension leak."),
    k!(Prefix "kwin_" => "KDE's window manager and compositor: draws every window. Rises with effects, many/high-refresh displays, and apps that redraw constantly."),
    k!(Eq "Xorg" => "X11 display server: draws windows for X clients. High CPU means some app redraws constantly, or the GPU driver is missing (software rendering)."),
    k!(Eq "Xwayland" => "X11 compatibility server for older apps on Wayland. Its cost is the X11 apps drawing through it (games, older Electron/Java apps)."),
    k!(Prefix "pipewire" => "PipeWire: audio/video routing (sound, screen sharing, cameras). Spikes with many streams, Bluetooth audio, or a buggy client."),
    k!(Eq "wireplumber" => "PipeWire session manager: decides which app goes to which audio/video device."),
    k!(Eq "pulseaudio" => "PulseAudio sound server: all sound in/out. Spikes with resampling, many streams, or Bluetooth headsets."),
    k!(Eq "NetworkManager" => "Network configuration daemon (Wi-Fi, VPN, DHCP). Busy during Wi-Fi scans/roaming, flapping links, or VPN reconnect loops."),
    k!(Eq "irqbalance" => "Spreads hardware interrupts across CPUs. Wakes periodically; rarely costly."),
    k!(Eq "thermald" => "Intel thermal daemon: throttles the CPU to keep temperatures in check. Activity here means the machine is running hot."),
    k!(Prefix "fwupd" => "Firmware update daemon (LVFS): checks and applies device firmware updates. Brief activity during metadata refresh."),
    k!(Eq "Web Content" => "A Firefox content process (one or more tabs). A heavy one is a single busy page; about:processes shows which tab."),
    k!(Prefix "Isolated Web" => "A Firefox site-isolated content process (one site's tabs). A heavy one is a single busy page; about:processes shows which tab."),
    k!(Prefix "firefox" => "Firefox browser main process; tabs run as 'Web Content' / 'Isolated Web Co' processes (about:processes maps them to tabs)."),
    k!(Eq "chrome" => "Chrome: every tab, extension and the GPU run as separate `chrome --type=...` processes. A heavy renderer is one heavy tab; Shift+Esc opens Chrome's Task Manager."),
    k!(Prefix "chromium" => "Chromium: every tab, extension and the GPU run as separate processes. A heavy renderer is one heavy tab; Shift+Esc opens its Task Manager."),
    k!(Prefix "rust-analyzer-" => "rust-analyzer's proc-macro server: expands your crates' procedural macros for the editor."),
    k!(Eq "cc1plus" => "GCC's C++ compiler proper, spawned by g++ from make/ninja/cmake. Many at once = a parallel C++ build; each can take 1-2 GB RAM on template-heavy code."),
    k!(Eq "cc1" => "GCC's C compiler proper, spawned by gcc from a build."),
    k!(Eq "ld" => "The linker: joins object files into the final binary. RAM-hungry and mostly single-threaded on big C++/Rust binaries; lld or mold are much faster."),
    k!(Prefix "ld." => "The linker (bfd/gold/lld): joins object files into the final binary. RAM-hungry on big C++/Rust binaries; lld or mold are much faster."),
    k!(Eq "mold" => "mold, a fast parallel linker: short bursts of all-core CPU at the end of a build are normal."),
    k!(Eq "gradle" => "Gradle build tool; the real work runs in a long-lived Gradle daemon (java ... GradleDaemon) that keeps GBs of heap between builds. `gradle --stop` frees it."),
    k!(Eq "java" => "Java VM: IDEs (IntelliJ), build daemons (Gradle, Kotlin, Maven), or servers (Elasticsearch, Kafka). The main class in its cmd says which. Heap is reserved up front, so RAM stays high even when idle."),
    k!(Prefix "python" => "Python interpreter: a script, dev server (Django/Flask/FastAPI), notebook kernel, ML job or agent tool. Check its cmd and cwd."),
    // ---- macOS and cross-platform ----
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
fn symptom(snap: &Snapshot, os: Os, p: &Proc, tree: &TreeCost) -> String {
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
        if os == Os::Linux {
            return format!(
                "usage unknown: owned by {owner}; this system hides other users' /proc details (hidepid or ptrace limits), so only root can measure it (try `sudo fat why {}`)",
                p.pid
            );
        }
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
    Container,
    Other,
}

fn classify_launcher(p: &Proc) -> Launcher {
    let n = p.name.to_ascii_lowercase();
    let n = n.trim_start_matches('-'); // login shells show as "-zsh"
    if p.pid == 1 || n == "launchd" || n == "systemd" || n == "init" {
        return Launcher::Init;
    }
    const SHELLS: &[&str] = &["zsh", "bash", "fish", "sh", "dash", "nu", "tcsh", "ksh", "pwsh", "xonsh", "elvish"];
    if SHELLS.contains(&n) {
        return Launcher::Shell;
    }
    const TERMS: &[&str] = &[
        "terminal", "iterm2", "alacritty", "kitty", "wezterm", "wezterm-gui", "ghostty", "warp", "stable", "hyper",
        "tmux", "screen", "zellij", "tabby", "rio", "login", "konsole", "xterm", "foot", "terminator", "tilix",
        "xfce4-terminal", "kgx", "urxvt", "ptyxis", "ptyxis-agent",
    ];
    if TERMS.contains(&n) || n.starts_with("tmux") || n.starts_with("iterm") || n.starts_with("gnome-terminal") {
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
    if n.starts_with("containerd-shim") || n == "conmon" || n == "runc" || n == "crun" {
        return Launcher::Container;
    }
    Launcher::Other
}

/// "started from zsh (pid 10) ← Ghostty (pid 9) ← launchd". Collapses uninteresting
/// intermediate processes, but always keeps the direct parent.
fn ancestry_step(ancestors: &[&Proc], os: Os) -> Option<String> {
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
                Launcher::Container => s.push_str(" container runtime"),
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
        let a = ancestors[0];
        match os {
            Os::Mac => out.push_str(" (directly under launchd: a system/app service, or its original launcher exited)"),
            _ if a.pid == 1 && a.name == "systemd" => {
                out.push_str(" (directly under systemd: a system service, or its original launcher exited)")
            }
            _ if a.pid == 1 => out.push_str(&format!(
                " (directly under pid 1 ({}): a service or container entrypoint, or its original launcher exited)",
                a.name
            )),
            _ => out.push_str(" (directly under the user's systemd manager: a user service, or its original launcher exited)"),
        }
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
    "cmake", "ninja", "clang", "webpack", "esbuild", "vite", "tsc", "next", "cc1plus", "cc1", "dpkg", "apt",
    "apt-get",
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

fn cause_steps(snap: &Snapshot, os: Os, p: &Proc, tree: &TreeCost, hist: Option<&History>, now: Ts) -> Causes {
    let mut c = Causes::default();
    let name = p.name.as_str();
    let lname = name.to_ascii_lowercase();
    let known_text = known_proc(p, os);

    if let Some(t) = known_text {
        c.steps.push(t.to_string());
    }

    if os == Os::Linux && linux_causes(snap, p, &lname, hist, now, &mut c) {
        return c;
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

/// macOS session/system daemons (mirrors actions.rs's macOS list, so a macOS snapshot is
/// judged the same wherever fat runs).
const MAC_CRITICAL: &[&str] = &[
    "kernel_task", "launchd", "WindowServer", "loginwindow", "logd", "runningboardd", "coreaudiod",
    "opendirectoryd", "mds", "mds_stores", "trustd", "syspolicyd", "secd", "securityd", "bluetoothd",
    "configd", "notifyd", "distnoted", "cfprefsd", "usernoted", "UserEventAgent", "coreservicesd",
    "lsd", "tccd", "powerd", "diskarbitrationd", "fseventsd", "mDNSResponder", "kernelmanagerd",
    "watchdogd", "hidd", "airportd", "sshd", "launchservicesd", "nsurlsessiond", "containermanagerd",
    "symptomsd", "thermalmonitord", "sandboxd", "authd", "keybagd", "apsd", "corebrightnessd",
];

/// Linux processes whose loss takes down the session or the machine's plumbing (blame only
/// uses this to avoid suggesting pause/kill; actions.rs does the enforcing). Full names; the
/// kernel's 15-char `comm` truncation is matched too.
const LINUX_CRITICAL: &[&str] = &[
    "systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "systemd-resolved", "systemd-networkd",
    "systemd-oomd", "systemd-timesyncd", "dbus-daemon", "dbus-broker", "dbus-broker-launch", "polkitd", "Xorg",
    "Xwayland", "gnome-shell", "gnome-session-binary", "kwin_wayland", "kwin_x11", "plasmashell", "gdm", "gdm3",
    "gdm-session-worker", "sddm", "lightdm", "NetworkManager", "wpa_supplicant", "containerd", "dockerd", "kubelet",
    "pipewire", "wireplumber", "udisksd", "accounts-daemon", "agetty",
];

fn name_in(list: &[&str], name: &str) -> bool {
    list.iter().any(|full| {
        full.eq_ignore_ascii_case(name)
            || (name.len() == 15 && full.len() > 15 && full.is_char_boundary(15) && full[..15].eq_ignore_ascii_case(name))
    })
}

fn is_package_manager(p: &Proc) -> bool {
    let n = p.name.to_ascii_lowercase();
    matches!(n.as_str(), "apt" | "apt-get" | "aptitude" | "dnf" | "yum" | "rpm" | "zypper" | "pacman")
        || n.starts_with("dpkg")
        || n.starts_with("unattended-upgr")
}

fn is_system_critical_on(os: Os, p: &Proc) -> bool {
    if is_system_critical(p) {
        return true;
    }
    match os {
        Os::Mac => MAC_CRITICAL.iter().any(|n| n.eq_ignore_ascii_case(&p.name)),
        Os::Linux => name_in(LINUX_CRITICAL, &p.name) || is_kernel_thread(p) || is_package_manager(p),
        Os::Other => false,
    }
}

/// Linux kernel thread: kthreadd (pid 2) or one of its children. Kernel threads have no
/// command line (collectors report it empty or as `[name]`).
fn is_kernel_thread(p: &Proc) -> bool {
    (p.pid == 2 && p.name == "kthreadd")
        || (p.ppid == 2 && (p.cmd.is_empty() || p.cmd.starts_with('[') || p.cmd == p.name) && p.exe.is_empty())
}

/// Uninterruptible sleep. Linux reports 'D'; sysinfo maps it to 'U'.
fn is_dstate(p: &Proc) -> bool {
    p.status.starts_with('D') || p.status.starts_with('U')
}

/// CPU the system reports as busy that no measurable process accounts for. Unprivileged, the
/// kernel hides other users' (root/system daemons') usage, so name the gap instead of
/// pretending those processes are idle.
fn rule_unattributed(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
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
    let why = if os == Os::Linux {
        "hide their usage from this user (/proc mounted with hidepid, or ptrace restrictions)"
    } else {
        "can't be measured without root"
    };
    let mut names: Vec<&str> = unknown.iter().map(|p| p.name.as_str()).filter(|n| !n.is_empty()).collect();
    names.sort_unstable();
    names.dedup();
    let sample = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
    out.push(finding(
        sev,
        format!("{:.1} cores of CPU unattributed (other users' processes need root)", gap / 100.0),
        format!(
            "The system is {:.0}% busy but measurable processes account for only {:.1} cores. {} processes owned by other users \
             (e.g. {sample}) {why}. Run `sudo fat` or `sudo fat doctor` to see which one it is.",
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
        Some('D') => "uninterruptible IO wait (D)",
        Some('t') => "stopped by a debugger (t)",
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
fn safe_action(os: Os, p: &Proc, snap: &Snapshot) -> Option<String> {
    if is_system_critical_on(os, p) {
        None
    } else if snap.descendants(p.pid).is_empty() {
        Some(format!("pause {}", p.pid))
    } else {
        Some(format!("pause {} (or kill {} --tree)", p.pid, p.pid))
    }
}

fn rule_memory(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
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
    let first = top.iter().find(|p| !is_system_critical_on(os, p)).copied();
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

fn rule_thermal(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
    let sev = match snap.system.thermal.as_str() {
        "critical" => "crit",
        "serious" => "warn",
        "fair" => "info",
        _ => return,
    };
    let hot: Vec<&Proc> =
        top_by(snap, |p| p.cpu, 4).into_iter().filter(|p| p.cpu >= 50.0 && p.name != "kernel_task").collect();
    let kt = snap.procs.iter().find(|p| p.name == "kernel_task" && p.cpu >= 50.0);
    let mut detail = if os == Os::Mac {
        format!("Thermal state is {}; macOS is throttling the CPU to cool down.", snap.system.thermal)
    } else {
        let t = snap.system.temp_c.map(|t| format!(" (hottest sensor {t:.0}°C)")).unwrap_or_default();
        format!("Thermal state is {}{t}; the CPU is being throttled to cool down.", snap.system.thermal)
    };
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
        hot.iter().find(|p| !is_system_critical_on(os, p)).map(|p| format!("renice {} 10", p.pid)),
    ));
}

fn rule_cpu(snap: &Snapshot, os: Os, hist: Option<&History>, now: Ts, out: &mut Vec<Finding>) {
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
        if let Some(k) = known_proc(p, os) {
            detail.push(' ');
            detail.push_str(k);
        }
        detail.push_str(&format!(" Details: fat why {}", p.pid));
        out.push(finding("warn", title, detail, vec![p.pid], safe_action(os, p, snap)));
    }
}

fn rule_power(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
    let sys = &snap.system;
    let heavy: Vec<&Proc> = snap.procs.iter().filter(|p| p.power_mw > 5000.0).collect();
    for p in &heavy {
        out.push(finding(
            "warn",
            format!("{} is drawing {}", p.name, human_watts(p.power_mw)),
            format!("{} (pid {}) is the kind of load that drains a battery in a couple of hours.", p.name, p.pid),
            vec![p.pid],
            safe_action(os, p, snap),
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
                    top.iter().find(|p| !is_system_critical_on(os, p)).map(|p| format!("pause {}", p.pid)),
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
    // Linux: a container's pid 1 (e.g. `sleep infinity` as the entrypoint) never reaps the
    // orphans re-parented to it. Killing it would stop the whole container, so say that instead.
    let container_init = (platform(snap) == Os::Linux)
        .then(|| snap.proc(parent))
        .flatten()
        .and_then(|pp| {
            let c = pp.container.as_deref()?;
            let grand_same = snap.proc(pp.ppid).is_some_and(|g| g.container.as_deref() == Some(c));
            (!grand_same).then(|| c.to_string())
        });
    // Inside a container (own pid namespace) the entrypoint is pid 1 and has no container id.
    let reaper_pid1 = platform(snap) == Os::Linux
        && parent == 1
        && container_init.is_none()
        && snap.proc(1).is_some_and(|p| !matches!(p.name.as_str(), "systemd" | "init" | "tini" | "dumb-init" | "docker-init" | "s6-svscan" | "runit" | "catatonit"));
    let detail = match &container_init {
        None if reaper_pid1 => format!(
            "Exited processes not reaped by their parent; most ({n}) belong to {pname} (pid 1), which is not an init and doesn't reap orphans (typical for a container whose entrypoint is a plain program). They hold no memory but leak pid slots; restarting the container clears them, and running it with an init (`docker run --init`, tini) prevents it."
        ),
        Some(c) => format!(
            "Exited processes not reaped by their parent; most ({n}) belong to {pname} (pid {parent}), the init process of container {}, which doesn't reap orphans. They hold no memory but leak pid slots; restarting the container clears them, and running it with an init (`docker run --init`, tini) prevents it.",
            container_label(snap, c)
        ),
        None => format!(
            "Exited processes not reaped by their parent; most ({n}) belong to {pname} (pid {parent}). They hold no memory but leak pid slots; restarting the parent clears them."
        ),
    };
    let protected = platform(snap) == Os::Linux && snap.proc(parent).is_some_and(|pp| is_system_critical_on(Os::Linux, pp));
    out.push(finding(
        sev,
        format!("{} zombie process{}", z.len(), if z.len() == 1 { "" } else { "es" }),
        detail,
        z.iter().map(|p| p.pid).collect(),
        (parent > 1 && container_init.is_none() && !protected).then(|| format!("kill {parent}")),
    ));
}

fn rule_swarms(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
    let mut groups: HashMap<&str, Vec<&Proc>> = HashMap::new();
    for p in &snap.procs {
        groups.entry(p.name.as_str()).or_default().push(p);
    }
    let mut names: Vec<(&str, Vec<&Proc>)> = groups.into_iter().filter(|(_, v)| v.len() > 30).collect();
    names.sort_by_key(|(n, v)| (std::cmp::Reverse(v.len()), *n));
    for (name, ps) in names {
        // Browsers and the OS legitimately run many helpers; still report, but as info.
        let benign = name.contains("Helper")
            || name.contains("WebContent")
            || name.starts_with("mdworker")
            || name.starts_with("com.apple")
            || (os == Os::Linux
                && (matches!(name, "chrome" | "chromium" | "Web Content" | "code" | "electron")
                    || name.starts_with("Isolated Web")
                    || ps.iter().all(|p| is_kernel_thread(p))));
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
            detail.push_str(if os == Os::Mac {
                " Most were re-parented to launchd: likely leaked workers."
            } else {
                " Most were re-parented to init/systemd: likely leaked workers."
            });
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

fn rule_disk(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
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
            safe_action(os, p, snap),
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

fn rule_net(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
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
        if let Some(k) = known_proc(p, os) {
            detail.push(' ');
            detail.push_str(k);
        }
        out.push(finding("info", format!("{} is a big network user", p.name), detail, vec![p.pid], None));
    }
}

fn rule_load(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
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
        top.iter().find(|p| !is_system_critical_on(os, p)).map(|p| format!("renice {} 10", p.pid)),
    ));
}

// ======================================================================
// Linux: cgroups, containers, systemd units
// ======================================================================
//
// Pure parsing over `Proc::cgroup` (the cgroup v2 path from /proc/<pid>/cgroup, "0::<path>").
// Real-world paths this understands:
//   /init.scope                                                    systemd (pid 1)
//   /system.slice/nginx.service                                    a system service
//   /system.slice/systemd-udevd.service/udev                       sub-cgroup of a service
//   /system.slice/docker-<64 hex>.scope                            docker, systemd cgroup driver
//   /docker/<64 hex>                                               docker, cgroupfs driver (OrbStack, older hosts)
//   /machine.slice/libpod-<64 hex>.scope                           podman
//   /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid_with_underscores>.slice/cri-containerd-<64 hex>.scope
//   /kubepods/besteffort/pod<uid>/<64 hex>                         kubernetes, cgroupfs driver
//   /lxc.payload.<name>                                            LXC/Incus
//   /user.slice/user-1000.slice/session-3.scope                    a login session (ssh, tty, desktop)
//   /user.slice/user-1000.slice/user@1000.service/init.scope       the `systemd --user` manager
//   /user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-firefox-4242.scope   desktop app
//   /user.slice/user-1000.slice/user@1000.service/app.slice/syncthing.service             user unit

#[derive(Debug, Default, Clone, PartialEq)]
struct CgInfo {
    /// Short (12 hex) container id.
    container_id: Option<String>,
    runtime: Option<&'static str>,
    lxc: Option<String>,
    /// (pod uid, QoS class).
    pod: Option<(String, &'static str)>,
    /// Deepest systemd unit (*.service / *.scope) that is not a container scope.
    unit: Option<String>,
    uid: Option<u32>,
    /// Under user@UID.service (the per-user systemd manager).
    user_manager: bool,
}

fn is_hex_id(s: &str) -> bool {
    s.len() >= 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn container_component(comp: &str, comps: &[&str]) -> Option<(String, Option<&'static str>)> {
    // cgroupfs + systemd driver mixes: "kubepods-besteffort-pod<uid>.slice:cri-containerd:<id>"
    let c = comp.rsplit(':').next().unwrap_or(comp);
    const PREFIXES: &[(&str, &str)] =
        &[("docker-", "docker"), ("cri-containerd-", "containerd"), ("crio-", "cri-o"), ("libpod-", "podman")];
    for (pre, rt) in PREFIXES {
        if let Some(rest) = c.strip_prefix(pre) {
            let id = rest.strip_suffix(".scope").unwrap_or(rest);
            if is_hex_id(id) {
                return Some((id[..12].to_string(), Some(*rt)));
            }
        }
    }
    if is_hex_id(c) {
        let rt = if comps.contains(&"docker") {
            Some("docker")
        } else if comps.iter().any(|x| x.starts_with("kubepods")) {
            Some("kubernetes")
        } else if comps.iter().any(|x| x.starts_with("libpod")) {
            Some("podman")
        } else {
            None
        };
        return Some((c[..12].to_string(), rt));
    }
    None
}

fn pod_uid(comp: &str) -> Option<String> {
    let rest = comp.strip_suffix(".slice").unwrap_or(comp);
    let uid = rest.rsplit_once("-pod").map(|x| x.1).or_else(|| rest.strip_prefix("pod"))?;
    let ok = uid.len() >= 32 && uid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_');
    ok.then(|| uid.replace('_', "-"))
}

fn parse_cgroup(path: &str) -> CgInfo {
    let mut cg = CgInfo::default();
    let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    for comp in &comps {
        let comp = *comp;
        if let Some((id, rt)) = container_component(comp, &comps) {
            cg.container_id = Some(id);
            cg.runtime = rt;
            continue;
        }
        if let Some(n) = comp.strip_prefix("lxc.payload.") {
            cg.lxc = Some(n.to_string());
            continue;
        }
        if let Some(uid) = pod_uid(comp) {
            let qos = if comps.iter().any(|c| c.contains("besteffort")) {
                "BestEffort"
            } else if comps.iter().any(|c| c.contains("burstable")) {
                "Burstable"
            } else {
                "Guaranteed"
            };
            cg.pod = Some((uid, qos));
            continue;
        }
        if let Some(uid) = comp.strip_prefix("user-").and_then(|r| r.strip_suffix(".slice")).and_then(|u| u.parse().ok()) {
            cg.uid = Some(uid);
            continue;
        }
        if let Some(uid) = comp.strip_prefix("user@").and_then(|r| r.strip_suffix(".service")) {
            cg.user_manager = true;
            if cg.uid.is_none() {
                cg.uid = uid.parse().ok();
            }
            continue;
        }
        if comp.starts_with("libpod-conmon-") || comp.starts_with("crio-conmon-") {
            continue;
        }
        if comp.ends_with(".service") || comp.ends_with(".scope") {
            cg.unit = Some(comp.to_string());
        }
    }
    cg
}

/// Container id of a process: the collector's, else derived from its cgroup path.
fn container_of(p: &Proc) -> Option<(String, Option<&'static str>)> {
    let cg = if p.cgroup.is_empty() { CgInfo::default() } else { parse_cgroup(&p.cgroup) };
    match (&p.container, cg.container_id) {
        (Some(id), _) if !id.is_empty() => Some((id.clone(), cg.runtime)),
        (_, Some(id)) => Some((id, cg.runtime)),
        _ => None,
    }
}

fn find_container<'a>(snap: &'a Snapshot, id: &str) -> Option<&'a crate::model::Container> {
    let id = id.trim_start_matches("sha256:");
    snap.containers.iter().find(|c| {
        let cid = c.id.trim_start_matches("sha256:");
        !cid.is_empty() && !id.is_empty() && (cid.starts_with(id) || id.starts_with(cid))
    })
}

fn short_id(id: &str) -> &str {
    let id = id.trim_start_matches("sha256:");
    &id[..id.len().min(12)]
}

/// "runs in container 1c5d10a36e64 (web, image nginx:1.27) [docker]"
fn container_phrase(snap: &Snapshot, id: &str, runtime: Option<&str>) -> String {
    let ct = find_container(snap, id);
    let mut s = format!("runs in container {}", short_id(id));
    match ct {
        Some(c) if !c.name.is_empty() && !c.image.is_empty() => s.push_str(&format!(" ({}, image {})", c.name, c.image)),
        Some(c) if !c.name.is_empty() => s.push_str(&format!(" ({})", c.name)),
        _ => {}
    }
    let rt = ct.map(|c| c.runtime.as_str()).filter(|r| !r.is_empty()).or(runtime);
    if let Some(rt) = rt {
        s.push_str(&format!(" [{rt}]"));
    }
    s
}

/// Container CLI to suggest for a runtime.
fn container_cli(rt: Option<&str>) -> &'static str {
    match rt {
        Some("podman") => "podman",
        Some("cri-o") | Some("containerd") | Some("kubernetes") => "crictl",
        _ => "docker",
    }
}

/// `pid1` is the name of pid 1 when known (systemd, or e.g. a VM/container supervisor).
fn unit_phrase(cg: &CgInfo, is_pid1: bool, pid1: Option<&str>) -> Option<String> {
    let unit = cg.unit.as_deref()?;
    let uid = cg.uid.map(|u| format!(" (uid {u})")).unwrap_or_default();
    Some(if unit == "init.scope" {
        if cg.user_manager {
            format!("part of the per-user systemd manager (user@{}.service)", cg.uid.map(|u| u.to_string()).unwrap_or_else(|| "?".into()))
        } else if is_pid1 {
            "in the init scope: the init system's own cgroup".into()
        } else {
            let who = pid1.map(|n| format!(" ({n})")).unwrap_or_default();
            format!("in the init scope: started by the init system (pid 1{who}) itself, not by a systemd unit")
        }
    } else if unit.starts_with("session-") && unit.ends_with(".scope") {
        format!("in your login session scope {unit}{uid}: started from an ssh, console or desktop login")
    } else if cg.user_manager && unit.ends_with(".service") {
        format!("started by your user systemd unit {unit}{uid}")
    } else if cg.user_manager && (unit.starts_with("app-") || unit.starts_with("snap.") || unit.starts_with("flatpak-")) {
        format!("in desktop app scope {unit}{uid}: launched from your desktop or app launcher")
    } else if unit.starts_with("run-") {
        format!("in transient scope {unit}: started with systemd-run")
    } else if cg.user_manager {
        format!("in user scope {unit}{uid}")
    } else if unit.ends_with(".service") {
        format!("started by systemd unit {unit}")
    } else {
        format!("in systemd scope {unit}")
    })
}

/// Chain steps saying where a Linux process lives: container / pod / systemd unit.
fn placement_steps(snap: &Snapshot, p: &Proc, cg: &CgInfo) -> Vec<String> {
    let mut v = Vec::new();
    let container = container_of(p);
    if let Some((id, rt)) = &container {
        v.push(container_phrase(snap, id, *rt));
    } else if let Some(n) = &cg.lxc {
        v.push(format!("runs in LXC container {n}"));
    }
    if let Some((uid, qos)) = &cg.pod {
        v.push(format!("part of Kubernetes pod {uid} (QoS {qos}): kubelet restarts its containers if they die"));
    }
    let pid1 = snap.proc(1).map(|q| q.name.as_str());
    if container.is_none() && cg.lxc.is_none() && cg.pod.is_none()
        && let Some(u) = unit_phrase(cg, p.pid == 1, pid1) {
            v.push(u);
        }
    v
}

/// Lifecycle-aware ways to stop/restart it (before the generic pause/kill suggestions).
fn placement_suggestions(snap: &Snapshot, cg: &CgInfo, p: &Proc) -> Vec<String> {
    let mut v = Vec::new();
    if let Some((id, rt)) = container_of(p) {
        let ct = find_container(snap, &id);
        let rt = ct.map(|c| c.runtime.as_str()).filter(|r| !r.is_empty()).or(rt);
        let label = ct.map(|c| c.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| short_id(&id).to_string());
        if cg.pod.is_some() || rt == Some("kubernetes") {
            v.push("it belongs to a Kubernetes pod: fix or scale the pod (kubectl); kubelet restarts killed containers".into());
        } else {
            let cli = container_cli(rt);
            v.push(format!(
                "it belongs to container {label}: watch it with `{cli} stats {label}`, stop the whole container with `{cli} stop {label}` (killing one process may just restart it)"
            ));
        }
        return v;
    }
    if let Some(unit) = cg.unit.as_deref().filter(|u| u.ends_with(".service")) {
        if cg.user_manager {
            v.push(format!("it's your user service: `systemctl --user restart {unit}` or `systemctl --user stop {unit}`"));
        } else {
            v.push(format!(
                "it's a systemd service: `sudo systemctl restart {unit}` or `sudo systemctl stop {unit}` (a plain kill may just trigger Restart=)"
            ));
        }
    }
    v
}

struct ContainerLoad<'a> {
    id: String,
    runtime: Option<&'static str>,
    cpu: f32,
    mem: u64,
    procs: Vec<&'a Proc>,
}

/// Processes grouped by container, busiest first.
fn container_loads(snap: &Snapshot) -> Vec<ContainerLoad<'_>> {
    let mut by: HashMap<String, ContainerLoad<'_>> = HashMap::new();
    for p in &snap.procs {
        if let Some((id, rt)) = container_of(p) {
            let e = by.entry(id.clone()).or_insert_with(|| ContainerLoad { id, runtime: rt, cpu: 0.0, mem: 0, procs: Vec::new() });
            e.cpu += p.cpu;
            e.mem += p.mem;
            e.runtime = e.runtime.or(rt);
            e.procs.push(p);
        }
    }
    let mut v: Vec<ContainerLoad<'_>> = by.into_values().collect();
    for c in &mut v {
        c.procs.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.mem.cmp(&a.mem)));
    }
    v.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.mem.cmp(&a.mem)).then(a.id.cmp(&b.id)));
    v
}

fn container_label(snap: &Snapshot, id: &str) -> String {
    find_container(snap, id).map(|c| c.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| short_id(id).to_string())
}

// ======================================================================
// Linux: cause analysis for kernel threads and daemons
// ======================================================================

fn busiest(snap: &Snapshot, key: impl Fn(&Proc) -> f32, n: usize, skip: u32) -> Vec<&Proc> {
    top_by(snap, &key, n + 1).into_iter().filter(|q| q.pid != skip && key(q) > 0.0).take(n).collect()
}

fn psi_mem_text(snap: &Snapshot) -> Option<String> {
    snap.system.psi.map(|ps| format!("memory stalls (PSI avg10): {:.0}% some / {:.0}% full", ps.mem_some, ps.mem_full))
}

/// Linux-specific blame for kernel threads and system daemons. Returns true when it fully
/// explained the process (the caller then skips the generic analysis).
fn linux_causes(snap: &Snapshot, p: &Proc, lname: &str, hist: Option<&History>, now: Ts, c: &mut Causes) -> bool {
    let sys = &snap.system;
    let io = |q: &Proc| (q.disk_read_bps + q.disk_write_bps) as f32;
    let net = |q: &Proc| (q.net_rx_bps + q.net_tx_bps) as f32;

    // Daemons that only matter when they are busy: idle ones get no invented root cause.
    let reactive = lname.starts_with("kswapd")
        || lname.starts_with("kcompactd")
        || lname == "khugepaged"
        || lname.starts_with("kworker/")
        || lname.starts_with("irq/")
        || lname.starts_with("ksoftirqd/")
        || lname.starts_with("jbd2/")
        || lname.starts_with("systemd-journal")
        || lname == "rsyslogd"
        || matches!(lname, "gnome-shell" | "xorg" | "xwayland")
        || lname.starts_with("kwin_");
    if reactive && p.cpu < 5.0 && io(p) < MB as f32 && !p.usage_unknown {
        c.steps.push("it is quiet right now: nothing to blame".into());
        return true;
    }

    // Memory reclaim / compaction: the cause is whoever holds the RAM.
    if lname.starts_with("kswapd") || lname.starts_with("kcompactd") || lname == "khugepaged" {
        let swap = if sys.swap_total > 0 {
            format!(", swap {} of {}", human_bytes(sys.swap_used), human_bytes(sys.swap_total))
        } else {
            String::new()
        };
        c.steps.push(format!(
            "root cause: memory is short: {} of {} RAM used{swap}",
            human_bytes(sys.mem_used),
            human_bytes(sys.mem_total)
        ));
        let top: Vec<&Proc> =
            busiest(snap, |q| q.mem as f32, 4, p.pid).into_iter().filter(|q| !is_kernel_thread(q)).take(3).collect();
        if !top.is_empty() {
            c.steps.push(format!("biggest memory users: {}", list_procs(&top, |q| human_bytes(q.mem))));
        }
        if let Some(t) = psi_mem_text(snap) {
            c.evidence.push(t);
        }
        if let Some(q) = top.iter().find(|q| !is_system_critical_on(Os::Linux, q)) {
            c.suggestions.push(format!("free memory: fat why {} ({}, {}), then pause or end it", q.pid, q.name, human_bytes(q.mem)));
        }
        c.suggestions.push("check swap and cache: `free -h`, `swapon --show`".into());
        return true;
    }

    // Kernel work queues and threaded IRQs: usually disk IO, sometimes a device.
    if lname.starts_with("kworker/") || lname.starts_with("irq/") {
        if let Some(dev) = lname.strip_prefix("irq/").and_then(|r| r.split_once('-')).map(|x| x.1) {
            c.steps.push(format!("root cause: device {dev} is raising a lot of interrupts"));
        } else {
            c.steps.push("root cause: whatever generates the kernel work; disk IO and writeback are the usual suspects".into());
        }
        let top = busiest(snap, io, 3, p.pid);
        if !top.is_empty() {
            c.steps.push(format!("busiest disk users: {}", list_procs(&top, |q| human_rate(io(q) as u64))));
        }
        if let Some(ps) = sys.psi {
            c.evidence.push(format!("io stalls (PSI avg10): {:.0}% some / {:.0}% full", ps.io_some, ps.io_full));
        }
        let d = snap.procs.iter().filter(|q| is_dstate(q)).count();
        if d > 0 {
            c.evidence.push(format!("{d} processes in uninterruptible IO wait (D)"));
        }
        c.suggestions.push(format!(
            "see which work it does: `sudo cat /proc/{}/stack` or `sudo perf top`; interrupts: `watch -d cat /proc/interrupts`",
            p.pid
        ));
        return true;
    }

    if lname.starts_with("ksoftirqd/") {
        c.steps.push("root cause: heavy network or interrupt load (packet rate, not just bytes)".into());
        let top = busiest(snap, net, 3, p.pid);
        if !top.is_empty() {
            c.steps.push(format!("busiest network users: {}", list_procs(&top, |q| human_rate(net(q) as u64))));
        }
        if sys.net_rx_bps + sys.net_tx_bps > 0 {
            c.evidence.push(format!("system network rx {} tx {}", human_rate(sys.net_rx_bps), human_rate(sys.net_tx_bps)));
        }
        c.suggestions.push("check `cat /proc/softirqs` (NET_RX/NET_TX) and `ip -s link`; spread NIC interrupts across CPUs (irqbalance, RSS)".into());
        return true;
    }

    if let Some(dev) = lname.strip_prefix("jbd2/") {
        let dev = dev.rsplit_once('-').map(|x| x.0).unwrap_or(dev);
        c.steps.push(format!("root cause: fsync-heavy writes to {dev} are forcing ext4 journal commits"));
        let top = busiest(snap, |q| q.disk_write_bps as f32, 3, p.pid);
        if !top.is_empty() {
            c.steps.push(format!("top writers: {}", list_procs(&top, |q| human_rate(q.disk_write_bps))));
        }
        c.suggestions.push("the writers above are the cause (databases, package managers, builds, editors); `sudo iotop -o` shows them live; put scratch data on tmpfs".into());
        return true;
    }

    if lname.starts_with("systemd-journal") || lname == "rsyslogd" {
        c.steps.push("root cause: some unit or program is logging at a very high rate (or crash-looping and logging each restart)".into());
        c.suggestions.push(
            "find the noisy unit: `journalctl --since '5 min ago' -o short | awk '{print $5}' | sort | uniq -c | sort -rn | head`"
                .into(),
        );
        c.suggestions.push("then fix or rate-limit it: LogRateLimitIntervalSec=/LogRateLimitBurst= on the unit, or RateLimitBurst= in /etc/systemd/journald.conf".into());
        return true;
    }

    let indexer = if lname.starts_with("tracker-miner") || lname.starts_with("tracker-extract") {
        Some(("GNOME Tracker indexing", "drop an empty `.trackerignore` (or `.nomedia`) file into build/dependency dirs, or remove them in Settings > Search > Search Locations"))
    } else if lname.starts_with("baloo_file") {
        Some(("KDE Baloo indexing", "exclude build/dependency dirs in System Settings > Search > File Search; `balooctl suspend` pauses it now"))
    } else if lname.starts_with("updatedb") || lname.starts_with("plocate-update") {
        Some(("the locate database rebuild", "add build/dependency dirs to /etc/updatedb.conf (PRUNENAMES=\"node_modules target .git\", or PRUNEPATHS)"))
    } else {
        None
    };
    if let Some((what, fix)) = indexer {
        c.steps.push(format!("{what} is reacting to many new or changed files"));
        let churners = recent_churners(snap, hist, now);
        if churners.is_empty() {
            c.steps.push("likely cause: a large file tree was created recently (no build/install tool running right now)".into());
        } else {
            let list: Vec<String> = churners.iter().take(4).cloned().collect();
            c.steps.push(format!("likely cause: {}", list.join("; ")));
            c.evidence.push(format!("file-churning tools seen: {}", churners.join("; ")));
        }
        c.suggestions.push(fix.into());
        c.suggestions.push("it finishes on its own".into());
        return true;
    }

    if is_package_manager(p) || lname == "packagekitd" || lname == "snapd" {
        c.steps.push("root cause: packages are being downloaded, unpacked or configured".into());
        let how = if lname == "snapd" {
            "see progress: `snap changes`; it finishes on its own"
        } else if lname == "packagekitd" {
            "see progress: `pkcon get-transactions` or your software center; it finishes on its own"
        } else if lname.starts_with("unattended-upgr") {
            "see progress: `systemctl status unattended-upgrades apt-daily-upgrade.service` and /var/log/unattended-upgrades/; it finishes on its own"
        } else {
            "let it finish; its terminal (or /var/log/dpkg.log) shows progress"
        };
        c.suggestions.push(how.into());
        return true;
    }

    let shim = lname.starts_with("containerd-shim") || lname == "conmon";
    if shim {
        let desc = snap.descendants(p.pid);
        let heavy = desc.iter().max_by(|a, b| a.cpu.total_cmp(&b.cpu)).copied();
        let id = desc.iter().find_map(|q| container_of(q));
        let what = match &id {
            Some((id, _)) => format!("container {}", container_label(snap, id)),
            None => "the container".into(),
        };
        c.steps.push(format!("root cause: the processes of {what} below it ({} procs)", desc.len()));
        if let Some(h) = heavy.filter(|h| h.cpu > 0.0) {
            c.steps.push(format!("heaviest: {} (pid {}) at {:.0}%", h.name, h.pid, h.cpu));
            c.suggestions.push(format!("drill down: fat why {}", h.pid));
        }
        return true;
    }

    if matches!(lname, "dockerd" | "containerd" | "kubelet" | "podman" | "runc" | "crun" | "crio") {
        let loads = container_loads(snap);
        let busy: Vec<String> = loads
            .iter()
            .filter(|l| l.cpu > 1.0 || l.mem > 256 * MB)
            .take(4)
            .map(|l| format!("{} {:.0}% CPU {}", container_label(snap, &l.id), l.cpu, human_bytes(l.mem)))
            .collect();
        if busy.is_empty() {
            c.steps.push("no container is busy right now: its own work is image pulls/builds, log handling, or API calls (e.g. a monitoring tool polling it)".into());
        } else {
            c.steps.push(format!("containers run as ordinary processes on this machine; busiest: {}", busy.join(", ")));
        }
        if let Some(l) = loads.first().filter(|l| l.cpu > 1.0)
            && let Some(q) = l.procs.first() {
                c.suggestions.push(format!("drill into the busiest container's top process: fat why {}", q.pid));
            }
        c.suggestions.push("inspect containers: fat fleet (or docker stats)".into());
        return true;
    }

    let chrome_renderer = (lname == "chrome" || lname.starts_with("chromium") || lname == "google-chrome") && p.cmd.contains("--type=renderer");
    let firefox_content = lname == "web content" || lname.starts_with("isolated web");
    if chrome_renderer || firefox_content {
        c.steps.push("root cause: one browser tab/extension is doing heavy work".into());
        c.suggestions.push(if chrome_renderer {
            "find the tab: Shift+Esc opens Chrome's Task Manager; close or reload it".into()
        } else {
            "find the tab: open about:processes in Firefox; close or reload it".into()
        });
        return true;
    }

    if matches!(lname, "gnome-shell" | "xorg" | "xwayland") || lname.starts_with("kwin_") {
        c.steps.push("root cause: something is redrawing the screen a lot (or rendering without GPU acceleration)".into());
        c.suggestions.push("close or minimize apps with animations/video; disable shell extensions (`gnome-extensions list --enabled`); check `glxinfo -B` does not report llvmpipe (software rendering)".into());
        return true;
    }

    if lname == "systemd" && p.cpu >= 20.0 {
        c.steps.push("root cause: probably a crash-looping unit or an event storm (udev, D-Bus, mounts)".into());
        c.suggestions.push("look for restarting units: `systemctl list-units --failed` and `journalctl -b -p warning --since '10 min ago'`".into());
        return true;
    }
    false
}

// ======================================================================
// Linux diagnose rules (PSI, temperature, D state, containers)
// ======================================================================

/// Pressure stall information: % of the last 10 s that tasks were stalled on a resource.
/// Example /proc/pressure/memory on a thrashing box:
///   some avg10=34.50 avg60=20.12 avg300=8.03 total=123456789
///   full avg10=12.07 avg60=6.40 avg300=2.10 total=45678901
fn rule_psi(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
    let Some(ps) = snap.system.psi else { return };
    let sys = &snap.system;

    if ps.cpu_some >= 20.0 {
        let top = busiest(snap, |q| q.cpu, 3, u32::MAX);
        out.push(finding(
            if ps.cpu_some >= 80.0 { "crit" } else { "warn" },
            format!("CPU contention: tasks waited for a CPU {:.0}% of the time", ps.cpu_some),
            format!(
                "PSI cpu some avg10 is {:.0}%: runnable tasks are queueing for a CPU (load {:.1} on {} cores), so everything gets slower. Top CPU users: {}",
                ps.cpu_some,
                sys.load[0],
                sys.cores,
                list_procs(&top, |q| format!("{:.0}%", q.cpu))
            ),
            top.iter().map(|q| q.pid).collect(),
            top.iter().find(|q| !is_system_critical_on(os, q)).map(|q| format!("renice {} 10", q.pid)),
        ));
    }

    if ps.mem_full >= 5.0 || ps.mem_some >= 20.0 {
        let top: Vec<&Proc> =
            busiest(snap, |q| q.mem as f32, 6, u32::MAX).into_iter().filter(|q| !is_kernel_thread(q)).take(5).collect();
        let first = top.iter().find(|q| !is_system_critical_on(os, q)).copied();
        let title = if ps.mem_full >= 5.0 {
            "Memory stalls: the system is thrashing"
        } else {
            "Memory stalls: tasks are waiting on memory reclaim"
        };
        let mut detail = format!(
            "PSI memory {:.0}% some / {:.0}% full (avg10): tasks spend that much time waiting for the kernel to free memory{}. {} of {} RAM used",
            ps.mem_some,
            ps.mem_full,
            if ps.mem_full >= 5.0 { " (\"full\" = every non-idle task stalled at once)" } else { "" },
            human_bytes(sys.mem_used),
            human_bytes(sys.mem_total)
        );
        if sys.swap_total > 0 {
            detail.push_str(&format!(", swap {} of {}", human_bytes(sys.swap_used), human_bytes(sys.swap_total)));
        }
        detail.push('.');
        let kswapd: f32 = snap.procs.iter().filter(|q| q.name.starts_with("kswapd")).map(|q| q.cpu).sum();
        if kswapd >= 5.0 {
            detail.push_str(&format!(" kswapd is burning {kswapd:.0}% CPU reclaiming."));
        }
        detail.push_str(&format!(" Biggest consumers: {}", list_procs(&top, |q| human_bytes(q.mem))));
        out.push(finding(
            if ps.mem_full >= 20.0 { "crit" } else { "warn" },
            title.into(),
            detail,
            top.iter().map(|q| q.pid).collect(),
            first.map(|q| format!("kill {}{}", q.pid, tree_flag(&snap.descendants(q.pid)))),
        ));
    }

    if ps.io_full >= 10.0 {
        let io = |q: &Proc| (q.disk_read_bps + q.disk_write_bps) as f32;
        let top = busiest(snap, io, 3, u32::MAX);
        let d: Vec<&Proc> = snap.procs.iter().filter(|q| is_dstate(q)).take(5).collect();
        let mut detail = format!(
            "PSI io {:.0}% some / {:.0}% full (avg10): tasks are stalled on disk/filesystem IO. Top disk users: {}.",
            ps.io_some,
            ps.io_full,
            list_procs(&top, |q| human_rate(io(q) as u64))
        );
        if !d.is_empty() {
            let names = d.iter().map(|q| format!("{} (pid {})", q.name, q.pid)).collect::<Vec<_>>().join(", ");
            detail.push_str(&format!(" Blocked in IO wait (D): {names}."));
        }
        detail.push_str(" Usual causes: an fsync-heavy job (database, package manager, build), a slow or failing disk, or a saturated network mount.");
        let mut pids: Vec<u32> = top.iter().map(|q| q.pid).collect();
        pids.extend(d.iter().map(|q| q.pid).filter(|x| !pids.contains(x)).collect::<Vec<_>>());
        out.push(finding(
            if ps.io_full >= 30.0 { "crit" } else { "warn" },
            format!("IO stalls: all tasks blocked on IO {:.0}% of the time", ps.io_full),
            detail,
            pids,
            top.first().filter(|q| io(q) >= MB as f32).and_then(|q| safe_action(os, q, snap)),
        ));
    }
}

/// Hottest sensor temperature (hwmon/thermal zones). Skipped when the thermal-state rule
/// already reports throttling, and on macOS where Apple silicon routinely runs ~100°C.
fn rule_temp(snap: &Snapshot, os: Os, out: &mut Vec<Finding>) {
    let Some(t) = snap.system.temp_c else { return };
    if matches!(snap.system.thermal.as_str(), "fair" | "serious" | "critical") {
        return;
    }
    let sev = if t >= 98.0 {
        "crit"
    } else if t >= 90.0 {
        "warn"
    } else if t >= 85.0 {
        "info"
    } else {
        return;
    };
    let hot: Vec<&Proc> = top_by(snap, |q| q.cpu, 4).into_iter().filter(|q| q.cpu >= 50.0).collect();
    let mut detail = format!(
        "Hottest sensor reads {t:.0}°C; most CPUs throttle around 95-100°C, which slows everything down."
    );
    if !hot.is_empty() {
        detail.push_str(&format!(" Heat sources: {}.", list_procs(&hot, |q| format!("{:.0}%", q.cpu))));
    }
    detail.push_str(" Check fans and vents; `sensors` lists every sensor.");
    out.push(finding(
        sev,
        format!("Running hot: {t:.0}°C"),
        detail,
        hot.iter().map(|q| q.pid).collect(),
        hot.iter().find(|q| !is_system_critical_on(os, q)).map(|q| format!("renice {} 10", q.pid)),
    ));
}

/// How long each D-state pid has been continuously in D, from the flight recorder: probe a
/// few past samples (one `History::at` each, shared by all pids) and stop at the first sample
/// where the process was not in D (or was a different process with the same pid).
fn dstate_durations(d: &[&Proc], hist: Option<&History>, now: Ts) -> HashMap<u32, i64> {
    let mut dur: HashMap<u32, i64> = HashMap::new();
    let Some(h) = hist else { return dur };
    let mut alive: Vec<&Proc> = d.to_vec();
    const PROBES_S: &[i64] = &[30, 60, 120, 300, 600, 1200, 1800];
    for off in PROBES_S {
        if alive.is_empty() {
            break;
        }
        let at = now - off * 1000;
        let Ok(Some(old)) = h.at(at) else { break };
        if now - old.ts < off * 500 {
            break; // nearest recorded sample is too recent to say anything about `at`
        }
        alive.retain(|p| match old.proc(p.pid) {
            Some(o) if is_dstate(o) && (o.start_time == 0 || p.start_time == 0 || o.start_time.abs_diff(p.start_time) <= 2) => {
                dur.insert(p.pid, now - old.ts);
                true
            }
            _ => false,
        });
    }
    dur
}

fn rule_dstate(snap: &Snapshot, os: Os, hist: Option<&History>, now: Ts, out: &mut Vec<Finding>) {
    let d: Vec<&Proc> = snap.procs.iter().filter(|p| is_dstate(p)).collect();
    if d.is_empty() {
        return;
    }
    let dur = dstate_durations(&d, hist, now);
    let mut stuck: Vec<(&Proc, i64)> =
        d.iter().filter_map(|p| dur.get(&p.pid).filter(|ms| **ms >= 2 * MIN_MS).map(|ms| (*p, *ms))).collect();
    stuck.sort_by_key(|(p, ms)| (std::cmp::Reverse(*ms), p.pid));
    let hint = if os == Os::Linux {
        " Check `dmesg` for IO errors or hung-task warnings, and `cat /proc/<pid>/wchan` for what each waits on."
    } else {
        ""
    };
    if let Some(&(_, longest)) = stuck.first() {
        let list = stuck
            .iter()
            .take(6)
            .map(|(p, ms)| format!("{} (pid {}) {}", p.name, p.pid, human_dur_ms(*ms)))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(finding(
            if longest >= 10 * MIN_MS { "crit" } else { "warn" },
            format!(
                "{} process{} stuck in uninterruptible IO wait for {}+",
                stuck.len(),
                if stuck.len() == 1 { "" } else { "es" },
                human_dur_ms(longest)
            ),
            format!(
                "In D state across recorded samples: {list}. They are blocked inside the kernel on IO: a slow or failing disk, a hung NFS/FUSE/network mount, or a stuck driver. They ignore signals (even kill -9) until the IO returns.{hint}"
            ),
            stuck.iter().map(|(p, _)| p.pid).collect(),
            None,
        ));
    } else if d.len() >= 8 {
        out.push(finding(
            "info",
            format!("{} processes waiting on IO (D state)", d.len()),
            format!(
                "Many processes are in uninterruptible IO wait at once ({}): the disk or a mount is slow to respond.{hint}",
                d.iter().take(6).map(|p| format!("{} (pid {})", p.name, p.pid)).collect::<Vec<_>>().join(", ")
            ),
            d.iter().map(|p| p.pid).collect(),
            None,
        ));
    }
}

/// Containers whose processes (grouped by `Proc::container` / cgroup) are hogging the host.
fn rule_containers(snap: &Snapshot, out: &mut Vec<Finding>) {
    let total = snap.system.mem_total;
    for l in container_loads(snap) {
        let mem_share = if total > 0 { l.mem as f64 / total as f64 } else { 0.0 };
        if l.cpu < 150.0 && !(mem_share >= 0.25 && l.mem >= GB) {
            continue;
        }
        let ct = find_container(snap, &l.id);
        let label = container_label(snap, &l.id);
        let rt = ct.map(|c| c.runtime.as_str()).filter(|r| !r.is_empty()).or(l.runtime);
        let mut what = format!("container {}", short_id(&l.id));
        if let Some(c) = ct {
            match (c.name.is_empty(), c.image.is_empty()) {
                (false, false) => what.push_str(&format!(" ({}, image {})", c.name, c.image)),
                (false, true) => what.push_str(&format!(" ({})", c.name)),
                _ => {}
            }
        }
        let heavy: Vec<&Proc> = l.procs.iter().take(3).copied().collect();
        let cli = container_cli(rt);
        let how = if rt == Some("kubernetes") {
            "Inspect it with `kubectl top pod -A`.".to_string()
        } else {
            format!("Watch it: `{cli} stats {label}`; stop it: `{cli} stop {label}`.")
        };
        out.push(finding(
            "warn",
            format!("Container {label} is using {:.1} cores, {}", l.cpu / 100.0, human_bytes(l.mem)),
            format!(
                "{} processes in {what} together use {:.0}% CPU and {} RAM ({:.0}% of the machine's). Heaviest: {}. {how}",
                l.procs.len(),
                l.cpu,
                human_bytes(l.mem),
                mem_share * 100.0,
                list_procs(&heavy, |q| format!("{:.0}% {}", q.cpu, human_bytes(q.mem)))
            ),
            l.procs.iter().map(|q| q.pid).collect(),
            None,
        ));
    }
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
    use crate::model::{Port, Proto, Psi, System};

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
        let step = ancestry_step(&s.ancestors(700), Os::Mac).unwrap();
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
        let step = ancestry_step(&s.ancestors(803), Os::Mac).unwrap();
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
    fn linux_zombies_under_container_init_suggest_no_kill() {
        let mut procs = vec![
            Proc { pid: 1, ppid: 0, name: "systemd".into(), status: "S".into(), ..Default::default() },
            Proc { pid: 50, ppid: 1, name: "containerd-shim-runc-v2".into(), status: "S".into(), ..Default::default() },
            Proc { pid: 60, ppid: 50, name: "sleep".into(), status: "S".into(), container: Some("410892b21be2".into()), ..Default::default() },
        ];
        for i in 0..25 {
            procs.push(Proc { pid: 100 + i, ppid: 60, name: "yes".into(), status: "Z".into(), container: Some("410892b21be2".into()), ..Default::default() });
        }
        let mut snap = Snapshot { procs, ..Default::default() };
        snap.system.os = "Debian GNU/Linux 12 (bookworm)".into();
        let f = diagnose(&snap, None);
        let z = f.iter().find(|x| x.title.contains("zombie")).expect("zombie finding");
        assert!(z.detail.contains("init process of container"), "{}", z.detail);
        assert_eq!(z.action, None);
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

    // ------------------------------------------------------------------
    // Linux
    // ------------------------------------------------------------------

    const CID: &str = "1c5d10a36e643dfc79ca9514c31b8fb651d4c4b2741fb0bef58d591761db6384";

    fn kt(pid: u32, name: &str, cpu: f32) -> Proc {
        Proc { pid, ppid: 2, name: name.into(), user: "root".into(), cpu, status: "S".into(), ..Default::default() }
    }

    fn linux_procs() -> Vec<Proc> {
        let mut sysd = pr(1, 0, "systemd", 0.1, 12 * MB);
        sysd.cgroup = "/init.scope".into();
        let mut kthreadd = pr(2, 0, "kthreadd", 0.0, 0);
        kthreadd.cmd = String::new();
        let mut sshd = pr(700, 1, "sshd", 0.0, 8 * MB);
        sshd.cgroup = "/system.slice/ssh.service".into();
        let mut sess = pr(710, 700, "sshd-session", 0.0, 6 * MB);
        sess.cgroup = "/user.slice/user-1000.slice/session-3.scope".into();
        let mut bash = pr(720, 710, "bash", 0.0, 4 * MB);
        bash.cgroup = "/user.slice/user-1000.slice/session-3.scope".into();
        vec![sysd, kthreadd, sshd, sess, bash]
    }

    fn linux_snap(procs: Vec<Proc>) -> Snapshot {
        let mut s = snap(procs);
        s.system.os = "Linux 12 Debian GNU/Linux".into();
        s.system.mem_pressure = "unknown".into();
        s.system.thermal = "unknown".into();
        s.system.psi = Some(Psi::default());
        s
    }

    #[test]
    fn linux_known_table() {
        let l = Os::Linux;
        assert!(known_for("kswapd0", l).unwrap().contains("short on RAM"));
        assert!(known_for("kworker/u8:2-events_unbound", l).unwrap().contains("disk IO"));
        assert!(known_for("ksoftirqd/3", l).unwrap().contains("network"));
        assert!(known_for("jbd2/nvme0n1p2-8", l).unwrap().contains("fsync"));
        assert!(known_for("kcompactd0", l).is_some());
        assert!(known_for("khugepaged", l).is_some());
        // comm is truncated to 15 chars by the kernel
        assert!(known_for("systemd-journal", l).unwrap().contains("noisy unit"));
        assert!(known_for("unattended-upgr", l).unwrap().contains("security updates"));
        assert!(known_for("containerd-shim", l).unwrap().contains("container"));
        assert!(known_for("tracker-miner-f", l).unwrap().contains("Tracker"));
        assert!(known_for("plocate-updated", l).unwrap().contains("updatedb"));
        assert!(known_for("Isolated Web Co", l).unwrap().contains("about:processes"));
        assert!(known_for("Web Content", l).unwrap().contains("Firefox"));
        for n in [
            "rsyslogd", "dockerd", "containerd", "runc", "kubelet", "snapd", "packagekitd", "apt", "dpkg", "updatedb",
            "baloo_file", "gnome-shell", "Xorg", "Xwayland", "pipewire", "pulseaudio", "NetworkManager", "sshd",
            "irqbalance", "thermald", "fwupd", "node", "python3", "python3.12", "java", "chrome", "firefox",
            "rust-analyzer", "cargo", "rustc", "cc1plus", "ld", "ld.lld", "gradle", "systemd",
        ] {
            assert!(known_for(n, l).is_some(), "{n}");
        }
        // Platform-specific text for the same name.
        assert!(!known_for("cargo", l).unwrap().contains("Spotlight"));
        assert!(known_for("cargo", Os::Mac).unwrap().contains("Spotlight"));
        // Command-line refinements.
        let mut g = pr(10, 1, "java", 0.0, 0);
        g.cmd = "/usr/lib/jvm/bin/java -Xmx2g org.gradle.launcher.daemon.bootstrap.GradleDaemon 8.10".into();
        assert!(known_proc(&g, l).unwrap().contains("Gradle"));
        let mut r = pr(11, 1, "chrome", 0.0, 0);
        r.cmd = "/opt/google/chrome/chrome --type=renderer --lang=en-US".into();
        assert!(known_proc(&r, l).unwrap().contains("Shift+Esc"));
        let linux_only = KNOWN.iter().filter(|k| k.os == Some(Os::Linux)).count();
        assert!(KNOWN.len() >= 100 && linux_only >= 1, "{}", KNOWN.len());
    }

    #[test]
    fn platform_detection() {
        let mut s = Snapshot::default();
        s.system.os = "macOS 15.6 Sequoia".into();
        assert_eq!(platform(&s), Os::Mac);
        s.system.os = "Linux 24.04 Ubuntu".into();
        assert_eq!(platform(&s), Os::Linux);
        s.system.os = String::new();
        s.procs = base_procs();
        assert_eq!(platform(&s), Os::Mac, "launchd as pid 1");
        s.procs = linux_procs();
        assert_eq!(platform(&s), Os::Linux, "cgroups present");
        s.procs = vec![pr(1, 0, "systemd", 0.0, 0)];
        assert_eq!(platform(&s), Os::Linux);
        s.procs.clear();
        s.system.psi = Some(Psi::default());
        assert_eq!(platform(&s), Os::Linux);
    }

    #[test]
    fn cgroup_parsing() {
        let c = parse_cgroup("/system.slice/nginx.service");
        assert_eq!(c.unit.as_deref(), Some("nginx.service"));
        assert!(c.container_id.is_none() && !c.user_manager);
        let c = parse_cgroup("/system.slice/systemd-udevd.service/udev");
        assert_eq!(c.unit.as_deref(), Some("systemd-udevd.service"));
        let c = parse_cgroup(&format!("/system.slice/docker-{CID}.scope"));
        assert_eq!(c.container_id.as_deref(), Some("1c5d10a36e64"));
        assert_eq!(c.runtime, Some("docker"));
        assert!(c.unit.is_none(), "container scope is not a unit");
        let c = parse_cgroup(&format!("/docker/{CID}"));
        assert_eq!((c.container_id.as_deref(), c.runtime), (Some("1c5d10a36e64"), Some("docker")));
        let c = parse_cgroup(&format!("/machine.slice/libpod-{CID}.scope"));
        assert_eq!(c.runtime, Some("podman"));
        let c = parse_cgroup(&format!("/machine.slice/libpod-conmon-{CID}.scope"));
        assert!(c.container_id.is_none() && c.unit.is_none());
        let c = parse_cgroup(&format!(
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod0f2a1b3c_4d5e_6f70_8192_a3b4c5d6e7f8.slice/cri-containerd-{CID}.scope"
        ));
        assert_eq!(c.container_id.as_deref(), Some("1c5d10a36e64"));
        assert_eq!(c.runtime, Some("containerd"));
        assert_eq!(c.pod, Some(("0f2a1b3c-4d5e-6f70-8192-a3b4c5d6e7f8".to_string(), "Burstable")));
        let c = parse_cgroup(&format!("/kubepods/besteffort/pod0f2a1b3c-4d5e-6f70-8192-a3b4c5d6e7f8/{CID}"));
        assert_eq!((c.runtime, c.pod.as_ref().map(|p| p.1)), (Some("kubernetes"), Some("BestEffort")));
        let c = parse_cgroup("/lxc.payload.devbox");
        assert_eq!(c.lxc.as_deref(), Some("devbox"));
        let c = parse_cgroup("/user.slice/user-1000.slice/session-3.scope");
        assert_eq!((c.unit.as_deref(), c.uid, c.user_manager), (Some("session-3.scope"), Some(1000), false));
        let c = parse_cgroup("/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-firefox-4242.scope");
        assert_eq!((c.unit.as_deref(), c.uid, c.user_manager), (Some("app-gnome-firefox-4242.scope"), Some(1000), true));
        assert!(unit_phrase(&c, false, None).unwrap().contains("desktop app scope"));
        let c = parse_cgroup("/user.slice/user-501.slice/user@501.service/init.scope");
        assert!(unit_phrase(&c, false, None).unwrap().contains("per-user systemd manager"));
        assert!(unit_phrase(&parse_cgroup("/init.scope"), true, Some("systemd")).unwrap().contains("own cgroup"));
        let u = unit_phrase(&parse_cgroup("/init.scope"), false, Some("simplevisor")).unwrap();
        assert!(u.contains("pid 1 (simplevisor)"), "{u}");
        assert_eq!(parse_cgroup("/"), CgInfo::default());
        assert_eq!(parse_cgroup(""), CgInfo::default());
        assert_eq!(parse_cgroup("/.lxc"), CgInfo::default());
    }

    #[test]
    fn linux_explain_systemd_service() {
        let mut ps = linux_procs();
        let mut n = pr(800, 1, "nginx", 160.0, 300 * MB);
        n.cgroup = "/system.slice/nginx.service".into();
        n.user = "www-data".into();
        ps.push(n);
        let e = explain(&linux_snap(ps), 800, None);
        let chain = e.chain.join("\n");
        assert!(chain.contains("started by systemd unit nginx.service"), "{chain}");
        assert!(chain.contains("directly under systemd: a system service"), "{chain}");
        assert!(!chain.contains("launchd"));
        assert!(e.evidence.iter().any(|x| x == "cgroup /system.slice/nginx.service"));
        assert!(e.evidence.iter().any(|x| x.contains("PSI")));
        let sg = e.suggestions.join("\n");
        assert!(sg.contains("sudo systemctl restart nginx.service"), "{sg}");
        assert!(sg.contains("fat pause 800"));
    }

    #[test]
    fn linux_explain_login_session_and_ssh_chain() {
        let mut ps = linux_procs();
        let mut c = pr(900, 720, "cargo", 30.0, 200 * MB);
        c.cgroup = "/user.slice/user-1000.slice/session-3.scope".into();
        ps.push(c);
        let e = explain(&linux_snap(ps), 900, None);
        let chain = e.chain.join("\n");
        assert!(chain.contains("in your login session scope session-3.scope (uid 1000)"), "{chain}");
        assert!(chain.contains("bash (pid 720) shell"));
        assert!(chain.contains("sshd-session (pid 710) ssh session"));
        assert!(!chain.contains("Spotlight"), "{chain}");
    }

    #[test]
    fn linux_explain_container_process() {
        let mut ps = linux_procs();
        let mut shim = pr(1000, 1, "containerd-shim", 0.5, 10 * MB);
        shim.cgroup = "/system.slice/containerd.service".into();
        let mut w = pr(1001, 1000, "nginx", 220.0, GB);
        w.cgroup = format!("/system.slice/docker-{CID}.scope");
        ps.push(shim);
        ps.push(w);
        let mut s = linux_snap(ps);
        s.containers.push(crate::model::Container {
            id: "1c5d10a36e64".into(),
            name: "web".into(),
            image: "nginx:1.27".into(),
            runtime: "docker".into(),
            status: "running".into(),
            ..Default::default()
        });
        let e = explain(&s, 1001, None);
        let chain = e.chain.join("\n");
        assert!(chain.contains("runs in container 1c5d10a36e64 (web, image nginx:1.27) [docker]"), "{chain}");
        assert!(chain.contains("containerd-shim (pid 1000) container runtime"), "{chain}");
        assert!(!chain.contains("systemd unit"), "container wins over unit: {chain}");
        assert!(e.suggestions.iter().any(|x| x.contains("docker stop web")), "{:?}", e.suggestions);
        // The shim blames its container.
        let e = explain(&s, 1000, None);
        let chain = e.chain.join("\n");
        assert!(chain.contains("container web"), "{chain}");
        assert!(e.suggestions.iter().any(|x| x == "drill down: fat why 1001"));
        // Collector-provided id without a cgroup path works too; unknown name shows the id.
        let mut p = pr(1002, 1, "redis-server", 5.0, MB);
        p.container = Some("abcdef012345".into());
        s.procs.push(p);
        let e = explain(&s, 1002, None);
        assert!(e.chain.iter().any(|c| c == "runs in container abcdef012345"), "{:?}", e.chain);
        assert!(e.suggestions.iter().any(|x| x.contains("docker stats abcdef012345")));
    }

    #[test]
    fn linux_explain_kswapd_kernel_thread() {
        let mut ps = linux_procs();
        ps.push(kt(90, "kswapd0", 85.0));
        let mut j = pr(950, 720, "java", 120.0, 40 * GB);
        j.cgroup = "/user.slice/user-1000.slice/session-3.scope".into();
        ps.push(j);
        let mut s = linux_snap(ps);
        s.system.mem_used = 63 * GB;
        s.system.psi = Some(Psi { mem_some: 40.0, mem_full: 12.0, ..Default::default() });
        let e = explain(&s, 90, None);
        let chain = e.chain.join("\n");
        assert!(chain.contains("kernel thread (child of kthreadd)"), "{chain}");
        assert!(chain.contains("memory is short: 63.0G of 64.0G"), "{chain}");
        assert!(chain.contains("java (pid 950) 40.0G"), "{chain}");
        assert!(e.evidence.iter().any(|x| x.contains("40% some / 12% full")));
        let sg = e.suggestions.join("\n");
        assert!(sg.contains("fat why 950"));
        assert!(sg.contains("can't be paused or killed"), "{sg}");
        assert!(!sg.contains("fat pause 90") && !sg.contains("fat kill 90") && !sg.contains("renice 90"), "{sg}");
    }

    #[test]
    fn linux_explain_kworker_and_journald() {
        let mut ps = linux_procs();
        ps.push(kt(91, "kworker/u8:3-events_unbound", 60.0));
        let mut dd = pr(960, 720, "dd", 20.0, MB);
        dd.disk_write_bps = 300 * MB;
        ps.push(dd);
        let mut jd = pr(130, 1, "systemd-journal", 70.0, 60 * MB);
        jd.cgroup = "/system.slice/systemd-journald.service".into();
        ps.push(jd);
        let s = linux_snap(ps);
        let e = explain(&s, 91, None);
        assert!(e.chain.iter().any(|c| c.contains("busiest disk users: dd (pid 960) 300M/s")), "{:?}", e.chain);
        let e = explain(&s, 130, None);
        assert!(e.chain.iter().any(|c| c.contains("logging at a very high rate")));
        assert!(e.suggestions.iter().any(|x| x.contains("journalctl")));
        assert!(e.suggestions.iter().any(|x| x.contains("core Linux")), "{:?}", e.suggestions);
        assert!(!e.suggestions.iter().any(|x| x.contains("fat pause 130")));
        // Idle daemons get no invented root cause.
        let mut s = s;
        s.procs.iter_mut().find(|q| q.pid == 130).unwrap().cpu = 0.5;
        let e = explain(&s, 130, None);
        assert!(e.chain.iter().any(|c| c.contains("quiet right now")), "{:?}", e.chain);
        assert!(!e.chain.iter().any(|c| c.contains("logging at a very high rate")));
    }

    #[test]
    fn linux_explain_dstate() {
        let mut ps = linux_procs();
        let mut p = pr(970, 720, "rsync", 1.0, 30 * MB);
        p.status = "D".into();
        ps.push(p);
        let e = explain(&linux_snap(ps), 970, None);
        assert!(e.chain.iter().any(|c| c.contains("uninterruptible sleep (D)")));
        assert!(e.suggestions.iter().any(|x| x.contains("/proc/970/wchan")));
        assert!(e.evidence.iter().any(|x| x == "status uninterruptible IO wait (D)"));
        // sysinfo maps D to U: same explanation.
        let mut ps = linux_procs();
        let mut p = pr(971, 720, "cp", 1.0, MB);
        p.status = "U".into();
        ps.push(p);
        assert!(explain(&linux_snap(ps), 971, None).chain.iter().any(|c| c.contains("(D)")));
    }

    #[test]
    fn linux_package_manager_not_killed() {
        let mut ps = linux_procs();
        ps.push(pr(980, 1, "dpkg", 60.0, 50 * MB));
        let s = linux_snap(ps);
        let e = explain(&s, 980, None);
        assert!(e.suggestions.iter().any(|x| x.contains("Let it finish")), "{:?}", e.suggestions);
        assert!(!e.suggestions.iter().any(|x| x.contains("fat kill 980") || x.contains("fat pause 980")));
    }

    #[test]
    fn linux_quiet_machine_is_empty() {
        let mut s = linux_snap(linux_procs());
        s.system.psi = Some(Psi { cpu_some: 2.0, mem_some: 0.5, mem_full: 0.1, io_some: 3.0, io_full: 1.0 });
        s.system.temp_c = Some(55.0);
        let f = diagnose(&s, None);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn linux_diagnose_psi() {
        let mut ps = linux_procs();
        let mut hog = pr(1100, 720, "stress-ng", 790.0, 100 * MB);
        hog.cgroup = "/user.slice/user-1000.slice/session-3.scope".into();
        ps.push(hog);
        let mut fat = pr(1101, 720, "python3", 50.0, 50 * GB);
        fat.cgroup = hog_cg();
        ps.push(fat);
        let mut w = pr(1102, 720, "postgres", 10.0, GB);
        w.disk_write_bps = 80 * MB;
        ps.push(w);
        let mut d = pr(1103, 720, "tar", 2.0, MB);
        d.status = "D".into();
        ps.push(d);
        ps.push(kt(90, "kswapd0", 40.0));
        let mut s = linux_snap(ps);
        s.system.psi = Some(Psi { cpu_some: 35.0, mem_some: 30.0, mem_full: 8.0, io_some: 60.0, io_full: 40.0 });
        let f = diagnose(&s, None);
        let cpu = f.iter().find(|x| x.title.starts_with("CPU contention")).expect("cpu psi");
        assert_eq!(cpu.severity, "warn");
        assert!(cpu.title.contains("35%"));
        assert_eq!(cpu.action.as_deref(), Some("renice 1100 10"));
        let mem = f.iter().find(|x| x.title.contains("thrashing")).expect("mem psi");
        assert_eq!(mem.severity, "warn");
        assert!(mem.detail.contains("kswapd is burning 40% CPU"), "{}", mem.detail);
        assert_eq!(mem.pids[0], 1101);
        assert_eq!(mem.action.as_deref(), Some("kill 1101"));
        let io = f.iter().find(|x| x.title.starts_with("IO stalls")).expect("io psi");
        assert_eq!(io.severity, "crit");
        assert!(io.detail.contains("postgres (pid 1102) 80M/s"), "{}", io.detail);
        assert!(io.detail.contains("Blocked in IO wait (D): tar (pid 1103)"), "{}", io.detail);
        assert!(io.pids.contains(&1103));
        assert_eq!(f[0].severity, "crit");
        // Below thresholds: nothing.
        s.system.psi = Some(Psi { cpu_some: 19.0, mem_some: 19.0, mem_full: 4.9, io_some: 50.0, io_full: 9.9 });
        assert!(!diagnose(&s, None).iter().any(|x| x.title.contains("contention") || x.title.contains("stalls")));
    }

    fn hog_cg() -> String {
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-jupyter.scope".into()
    }

    #[test]
    fn linux_diagnose_temperature() {
        let mut ps = linux_procs();
        ps.push(pr(1200, 720, "ffmpeg", 600.0, GB));
        let mut s = linux_snap(ps);
        s.system.temp_c = Some(92.0);
        let f = diagnose(&s, None);
        let t = f.iter().find(|x| x.title == "Running hot: 92°C").expect("temp");
        assert_eq!(t.severity, "warn");
        assert!(t.detail.contains("ffmpeg (pid 1200)"));
        assert_eq!(t.action.as_deref(), Some("renice 1200 10"));
        s.system.temp_c = Some(99.0);
        assert!(diagnose(&s, None).iter().any(|x| x.title.starts_with("Running hot") && x.severity == "crit"));
        // Thermal-state rule already covers it: no duplicate.
        s.system.thermal = "serious".into();
        let f = diagnose(&s, None);
        assert!(!f.iter().any(|x| x.title.starts_with("Running hot")));
        let th = f.iter().find(|x| x.title == "Thermal throttling").unwrap();
        assert!(th.detail.contains("hottest sensor 99°C") && !th.detail.contains("macOS"), "{}", th.detail);
        // macOS: Apple silicon runs ~100°C routinely; temp alone is not a finding.
        let mut m = snap(base_procs());
        m.system.temp_c = Some(101.0);
        assert!(diagnose(&m, None).is_empty());
    }

    #[test]
    fn linux_diagnose_containers() {
        let mut ps = linux_procs();
        for (i, cpu) in [120.0f32, 90.0, 40.0].iter().enumerate() {
            let mut p = pr(1300 + i as u32, 1, "node", *cpu, 2 * GB);
            p.cgroup = format!("/system.slice/docker-{CID}.scope");
            ps.push(p);
        }
        let mut quiet = pr(1310, 1, "redis-server", 3.0, 100 * MB);
        quiet.container = Some("aaaaaaaaaaaa".into());
        ps.push(quiet);
        let mut s = linux_snap(ps);
        s.containers.push(crate::model::Container {
            id: CID.into(),
            name: "api".into(),
            image: "node:22".into(),
            runtime: "docker".into(),
            ..Default::default()
        });
        let f = diagnose(&s, None);
        let c: Vec<&Finding> = f.iter().filter(|x| x.title.starts_with("Container")).collect();
        assert_eq!(c.len(), 1, "{f:?}");
        assert_eq!(c[0].title, "Container api is using 2.5 cores, 6.0G");
        assert!(c[0].detail.contains("3 processes in container 1c5d10a36e64 (api, image node:22)"), "{}", c[0].detail);
        assert!(c[0].detail.contains("docker stop api"));
        assert_eq!(c[0].pids, vec![1300, 1301, 1302]);
        // dockerd's why points at the busy container.
        s.procs.push(pr(600, 1, "dockerd", 15.0, 100 * MB));
        let e = explain(&s, 600, None);
        assert!(e.chain.iter().any(|x| x.contains("busiest: api 250% CPU")), "{:?}", e.chain);
        assert!(e.suggestions.iter().any(|x| x == "drill into the busiest container's top process: fat why 1300"));
    }

    fn tmp_hist() -> (std::path::PathBuf, History) {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("fat-blame-{}-{n}.db", std::process::id()));
        let h = History::open(Some(p.to_str().unwrap())).unwrap();
        (p, h)
    }

    #[test]
    fn linux_diagnose_dstate_with_history() {
        let (path, mut h) = tmp_hist();
        let mk = |ts: Ts, nfs_d: bool, cp_d: bool| {
            let mut ps = linux_procs();
            let mut a = pr(1400, 720, "ls", 0.0, 4 * MB);
            a.status = if nfs_d { "D".into() } else { "S".into() };
            let mut b = pr(1401, 720, "cp", 1.0, 8 * MB);
            b.status = if cp_d { "D".into() } else { "R".into() };
            ps.push(a);
            ps.push(b);
            let mut s = linux_snap(ps);
            s.ts = ts;
            s
        };
        // ls stuck in D for 11 minutes; cp only for the last minute.
        let mut t = NOW - 11 * MIN_MS;
        while t < NOW {
            h.record(&mk(t, true, t >= NOW - MIN_MS)).unwrap();
            t += 30_000;
        }
        let now = mk(NOW, true, true);
        h.record(&now).unwrap();
        let f = diagnose(&now, Some(&h));
        let d = f.iter().find(|x| x.title.contains("uninterruptible IO wait")).expect("dstate finding");
        assert_eq!(d.pids, vec![1400], "{d:?}");
        assert_eq!(d.severity, "crit");
        assert!(d.title.starts_with("1 process stuck"), "{}", d.title);
        assert!(d.detail.contains("ls (pid 1400) 1"), "{}", d.detail);
        assert!(d.detail.contains("dmesg"));
        // Without the recorder, two D processes are just a moment in time.
        assert!(!diagnose(&now, None).iter().any(|x| x.title.contains("IO wait")));
        drop(h);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
        }
    }

    #[test]
    fn linux_swarm_and_wording() {
        let mut ps = linux_procs();
        ps.push(pr(1500, 720, "chrome", 5.0, 300 * MB));
        for i in 0..35 {
            let mut r = pr(1501 + i, 1500, "chrome", 1.0, 100 * MB);
            r.cmd = "/opt/google/chrome/chrome --type=renderer".into();
            ps.push(r);
        }
        for i in 0..32 {
            ps.push(pr(1600 + i, 1, "worker", 1.0, 10 * MB));
        }
        let s = linux_snap(ps);
        let f = diagnose(&s, None);
        let c = f.iter().find(|x| x.title == "36 copies of chrome").unwrap();
        assert_eq!(c.severity, "info");
        assert!(c.action.is_none());
        let w = f.iter().find(|x| x.title == "32 copies of worker").unwrap();
        assert!(w.detail.contains("re-parented to init/systemd"), "{}", w.detail);
        // A renderer's why is about the tab.
        let e = explain(&s, 1501, None);
        assert!(e.suggestions.iter().any(|x| x.contains("Shift+Esc")));
    }

    #[test]
    fn linux_unattributed_wording() {
        let mut s = linux_snap(linux_procs());
        s.system.cores = 4;
        s.system.cpu = 90.0;
        let mut hidden = pr(1700, 1, "postgres", 0.0, 0);
        hidden.usage_unknown = true;
        hidden.user = "postgres".into();
        s.procs.push(hidden);
        let f = diagnose(&s, None);
        let u = f.iter().find(|x| x.title.contains("unattributed")).unwrap();
        assert!(u.detail.contains("hidepid") && u.detail.contains("sudo fat"), "{}", u.detail);
        let e = explain(&s, 1700, None);
        assert!(e.chain[0].contains("hidepid"), "{}", e.chain[0]);
    }

    // ------------------------------------------------------------ storage

    fn vol(mount: &str, total: u64, avail: u64) -> Volume {
        Volume {
            mount: mount.into(),
            device: format!("/dev/{}", mount.trim_start_matches('/').replace('/', "_")),
            fstype: "apfs".into(),
            total,
            used: total - avail,
            avail,
            ..Default::default()
        }
    }

    #[test]
    fn fs_full_volumes_warn_and_crit_once_per_container() {
        let mut data = vol("/System/Volumes/Data", 1000 * GB, 50 * GB);
        data.primary = true;
        data.purgeable = Some(20 * GB);
        // APFS siblings in the same container report the same space; only one finding.
        let sealed = Volume { read_only: true, ..vol("/", 1000 * GB, 50 * GB) };
        let vm = Volume { used: 2 * GB, ..vol("/System/Volumes/VM", 1000 * GB, 50 * GB) };
        let ext = vol("/Volumes/T7", 500 * GB, 10 * GB);
        let nfs = Volume { remote: true, ..vol("/Users/me/OrbStack", 100 * GB, GB) };
        let tiny = vol("/Volumes/EFI", GB, 0);
        let f = diagnose_fs(&FsFacts { volumes: vec![sealed, data, vm, ext, nfs, tiny], ..Default::default() });
        let titles: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert_eq!(titles, vec!["Disk /Volumes/T7 is 98% full (10.0G left)", "Disk /System/Volumes/Data is 95% full (50.0G left)"], "{f:#?}");
        assert_eq!(f[0].severity, "crit");
        assert_eq!(f[1].severity, "warn");
        assert!(f[1].detail.contains("purgeable") && f[1].detail.contains("fat fs /System/Volumes/Data"));
        // below 90%: nothing
        assert!(diagnose_fs(&FsFacts { volumes: vec![vol("/", 100 * GB, 20 * GB)], ..Default::default() }).is_empty());
    }

    #[test]
    fn fs_filling_volume_names_top_growers() {
        let mut root = vol("/", 1000 * GB, 400 * GB);
        root.primary = true;
        root.fill_bps = Some(50.0 * MB as f64);
        root.eta_full_s = Some(3600);
        let mut home = vol("/home", 100 * GB, 60 * GB);
        home.fill_bps = Some(1e6);
        home.eta_full_s = Some(10 * 3600);
        let mut slow = vol("/data", 100 * GB, 60 * GB);
        slow.fill_bps = Some(10.0);
        slow.eta_full_s = Some(30 * 86_400);
        let growth = Growth {
            growers: vec![
                crate::fs::Grower { path: "/var/log/app".into(), delta: 30 * GB as i64, writers: vec![(321, "app".into(), 50 * MB)], ..Default::default() },
                crate::fs::Grower { path: "/home/u/dl".into(), delta: GB as i64, ..Default::default() },
                crate::fs::Grower { path: "/tmp/shrunk".into(), delta: -(GB as i64), ..Default::default() },
            ],
            ..Default::default()
        };
        let f = diagnose_fs(&FsFacts { volumes: vec![root, home, slow], growth: Some(growth), ..Default::default() });
        let crit = f.iter().find(|x| x.title == "/ will be full in 1h").expect("crit eta");
        assert_eq!(crit.severity, "crit");
        assert!(crit.detail.contains("/var/log/app +30.0G (app 321)"), "{}", crit.detail);
        assert!(!crit.detail.contains("/home/u/dl"), "growers on other volumes are not blamed");
        assert_eq!(crit.pids, vec![321]);
        let warn = f.iter().find(|x| x.title.starts_with("/home will be full")).expect("warn eta");
        assert_eq!(warn.severity, "warn");
        assert!(warn.detail.contains("/home/u/dl"));
        assert!(!f.iter().any(|x| x.title.starts_with("/data")), "a month away is not a finding");
    }

    #[test]
    fn fs_deleted_open_and_swap() {
        let facts = FsFacts {
            volumes: vec![Volume { mount: "/System/Volumes/VM".into(), used: 20 * GB, total: 1000 * GB, avail: 500 * GB, ..Default::default() }],
            deleted_open: vec![
                (77, "java".into(), "/var/log/a.log".into(), 900 * MB),
                (77, "java".into(), "/var/log/b.log".into(), 300 * MB),
                (88, "vim".into(), "/tmp/.swp".into(), 10 * MB),
            ],
            ..Default::default()
        };
        let f = diagnose_fs(&facts);
        let d = f.iter().find(|x| x.title.starts_with("java (pid 77) holds")).expect("deleted-open");
        assert_eq!(d.title, "java (pid 77) holds 1.2G of deleted files");
        assert_eq!(d.pids, vec![77]);
        assert!(d.detail.contains("Restarting java (pid 77)") && d.detail.contains("/var/log/a.log"));
        assert!(d.action.is_none(), "no automatic action for storage");
        assert!(!f.iter().any(|x| x.title.contains("vim")), "small holders are not findings");
        let s = f.iter().find(|x| x.title.starts_with("Swap files")).expect("swap");
        assert_eq!(s.severity, "warn");
        assert!(s.detail.contains("never") && s.detail.contains("delete"));
        // merged into the full diagnosis, crit first
        let all = diagnose_with_fs(&snap(base_procs()), None, &facts);
        assert!(all.iter().any(|x| x.title.starts_with("java")));
        assert!(all.windows(2).all(|w| severity_rank(&w[0].severity) >= severity_rank(&w[1].severity)));
    }

    #[test]
    fn known_dirs_explained() {
        let h = Some("/Users/me");
        let e = |p: &str| explain_path_in(p, h);
        assert!(e("/Users/me/Library/Caches").unwrap().starts_with("App caches"));
        assert!(e("/Users/me/Library/Caches/Homebrew").unwrap().contains("brew cleanup"));
        assert_eq!(e("/Users/me/Library/Caches/com.foo/x").unwrap().split(':').next(), Some("inside ~/Library/Caches"));
        assert!(e("/System/Volumes/Data/Users/me/Library/Developer/Xcode/DerivedData").unwrap().contains("Xcode"), "firmlink alias");
        assert!(e("/Users/me/Library/Developer/CoreSimulator/Devices").unwrap().contains("simctl"));
        assert!(e("/Users/me/code/app/node_modules").unwrap().contains("npm"));
        assert!(e("/Users/me/code/app/node_modules/react/dist").unwrap().starts_with("inside ~/code/app/node_modules"));
        assert!(e("/Users/me/code/fat/target").unwrap().contains("cargo clean"));
        assert!(e("/Users/me/.cargo/registry").unwrap().contains("Cargo"));
        assert!(e("/Users/me/Library/Group Containers/HUAQ24HBR6.dev.orbstack").unwrap().contains("OrbStack"));
        assert!(e("/private/var/vm").unwrap().contains("Swap"));
        assert!(e("/private/var/folders").unwrap().contains("temporary"));
        assert!(e("/").unwrap().contains("tmutil"));
        // Another user's home is recognized too (e.g. running as root on Linux).
        assert!(explain_path_in("/home/dev/.cache", Some("/root")).unwrap().contains("caches"));
        assert!(explain_path_in("/root/.npm", Some("/root")).unwrap().contains("npm cache"));
        assert!(e("/var/log/journal").unwrap().contains("journalctl --vacuum-size"));
        assert!(e("/var/lib/docker/overlay2").unwrap().contains("docker system df"));
        assert!(e("/var/cache/apt/archives").unwrap().contains("apt clean"));
        assert!(e("/var/lib/snapd/snaps").unwrap().contains("refresh.retain"));
        // unknown paths and "/" descendants without a match say nothing
        assert_eq!(e("/Users/me/Projects"), None);
        assert_eq!(e("/opt/thing"), None);
        // advice only: nothing tells the user to rm
        for (_, t) in KNOWN_DIRS {
            assert!(!t.contains("rm -"), "{t}");
        }
    }
}
