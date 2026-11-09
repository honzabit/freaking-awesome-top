//! Hub processes and the safe-advice gate. OWNER: blame agent.
//!
//! A *hub* is a process whose resource use is really other workloads': a VM or container host
//! (OrbStack Helper, Docker Desktop's VM, qemu, UTM ...), a container runtime, shim or a
//! container's pid 1, init (launchd / systemd), a browser's or Electron app's main process, an
//! interactive shell / terminal / tmux / ssh / agent session, the display server, the kernel.
//! Killing or pausing one takes down everything it hosts ("fat kill <OrbStack Helper>" would
//! kill every container and VM), so advice for a hub names the workload instead.
//!
//! Every runnable suggestion blame produces goes through [`Ctx::advise`]. It returns a fat
//! command only for a process the user owns that is not a hub, not part of the OS, not a GUI
//! app (those get "quit <App>" as text) and not a system/root service. Everything else gets
//! `action: None` plus a sentence of advice for the finding's detail.
use super::{
    Launcher, Os, classify_launcher, container_cli, container_label, container_loads, container_of, find_container,
    human_bytes, is_kernel_thread, is_system_critical_on, is_zombie,
};
use crate::model::{Container, Proc, Snapshot};
use std::collections::HashMap;

/// Why a process hosts other work.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Hub {
    /// VM or container host; `product` names it ("OrbStack", "Docker Desktop", "QEMU" ...).
    Vm { product: &'static str },
    /// Container daemon, runtime or shim (dockerd, containerd, containerd-shim, podman, conmon, runc).
    Runtime,
    /// pid 1 (entrypoint) of a container, seen from the host.
    ContainerInit { id: String },
    /// launchd / systemd / init, for the machine or a user.
    Init,
    /// A browser's main process.
    Browser { app: String },
    /// Main process of a multi-process GUI app (Electron: Slack, Claude, VS Code, Discord ...).
    AppMain { app: String },
    /// Interactive shell, terminal, multiplexer, ssh session, editor or coding agent.
    Session { what: &'static str },
    /// Display server / compositor.
    Display,
    /// The kernel itself or a kernel thread.
    Kernel,
}

/// The GUI app a process belongs to.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct App {
    /// Short display name ("Brave", "Slack", "Docker Desktop").
    pub name: String,
    pub browser: bool,
    /// The app's main process (not a helper/renderer).
    pub main: bool,
}

/// Why fat won't offer pause/kill for a process.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Block {
    Hub(Hub),
    Critical,
    Gui(App),
    /// Container process the user doesn't own: stop the container instead.
    Container { id: String },
    /// Owned by root / a system account and not started from a user's session.
    Service,
}

/// What a rule would like to do about a process.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Want {
    /// `pause N`
    Pause,
    /// `pause N` (or `kill N --tree` when it has children)
    Calm,
    /// `renice N 10`
    Renice,
    /// `kill N` (`--tree` when it has children)
    End,
    /// `kill N --tree`
    EndTree,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct Advice {
    /// A fat command the TUI may run (parsed by `tui::app::parse_action`), or None.
    pub action: Option<String>,
    /// Plain-language advice when there is no safe command (or extra context).
    pub note: Option<String>,
}

/// One memory workload: a process, a whole app, a VM, or a container.
pub(super) struct Consumer<'a> {
    pub name: String,
    pub kind: CKind,
    pub mem: u64,
    pub lead: &'a Proc,
    pub members: Vec<&'a Proc>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum CKind {
    Proc,
    App { browser: bool },
    Vm { product: &'static str },
    Container { id: String },
}

/// Per-snapshot context for advice.
pub(super) struct Ctx<'a> {
    pub snap: &'a Snapshot,
    pub os: Os,
    /// Login users (not root/system accounts) that own a shell, terminal or GUI app.
    users: Vec<&'a str>,
    /// Linux: container id -> pid of its init (entrypoint).
    inits: HashMap<String, u32>,
}

const SHELL_HOSTS: &[Launcher] = &[Launcher::Shell, Launcher::Terminal, Launcher::Remote, Launcher::Agent, Launcher::Ide];

/// Root and the system accounts of macOS (`_*`) and common Linux distros.
pub(super) fn system_account(u: &str) -> bool {
    const SYS: &[&str] = &[
        "root", "daemon", "bin", "sys", "nobody", "messagebus", "syslog", "www-data", "avahi", "polkitd", "rtkit",
        "colord", "sshd", "dbus", "uuidd", "tss", "cups", "lp", "mail", "man", "proxy", "backup", "dnsmasq", "chrony",
        "ntp", "geoclue", "gdm", "lightdm", "sddm", "pulse", "saned", "kernoops", "whoopsie", "usbmux", "postgres",
        "mysql", "redis", "nginx", "statd", "unbound", "fwupd-refresh", "landscape", "pollinate", "lxd", "Debian-gdm",
        "speech-dispatcher", "hplip", "nm-openvpn", "dhcpcd", "_apt", "rpc", "rpcuser", "apache", "httpd", "named",
        "prometheus", "grafana", "elasticsearch", "docker", "containerd",
    ];
    u.starts_with('_') || u.starts_with("systemd-") || SYS.contains(&u)
}

/// `/Applications/Brave Browser.app/Contents/...` -> ("Brave Browser", is the bundle's main exe).
/// Only bundles under an Applications folder (or CoreServices) count as GUI apps; CLI tools
/// shipped inside a bundle (`Contents/MacOS/bin/`, `Contents/Resources/`) do not.
pub(super) fn bundle_of(path: &str) -> Option<(&str, bool)> {
    let i = path.find(".app/")?;
    let head = &path[..i];
    let (dir, name) = head.rsplit_once('/')?;
    let dir_ok = format!("{dir}/").contains("/Applications/") || dir == "/System/Library/CoreServices";
    if !dir_ok || name.is_empty() {
        return None;
    }
    let rest = &path[i + 5..];
    if rest.starts_with("Contents/MacOS/bin/") || rest.starts_with("Contents/Resources/") {
        return None;
    }
    let main = rest.strip_prefix("Contents/MacOS/").is_some_and(|r| !r.contains('/'));
    Some((name, main))
}

const BROWSERS: &[&str] = &[
    "Google Chrome", "Chromium", "Brave Browser", "Microsoft Edge", "Arc", "Vivaldi", "Opera", "Firefox", "Zen",
    "Safari", "Orion", "Dia", "Comet", "Thorium", "LibreWolf", "Waterfox", "Floorp", "Tor Browser", "Chrome", "Brave",
    "Edge",
];

fn is_browser(app: &str) -> bool {
    BROWSERS.iter().any(|b| app == *b || app.strip_prefix(b).is_some_and(|r| r.starts_with(' ')))
}

/// Friendlier names for summaries.
fn display_name(bundle: &str) -> String {
    match bundle {
        "Brave Browser" => "Brave".into(),
        "Visual Studio Code" => "VS Code".into(),
        "Docker" => "Docker Desktop".into(),
        b => b.into(),
    }
}

/// VM product of an app bundle.
fn bundle_vm(bundle: &str) -> Option<&'static str> {
    Some(match bundle {
        "OrbStack" => "OrbStack",
        "Docker" | "Docker Desktop" => "Docker Desktop",
        "UTM" => "UTM",
        "Parallels Desktop" => "Parallels",
        "VMware Fusion" => "VMware Fusion",
        "VirtualBox" => "VirtualBox",
        "Rancher Desktop" => "Rancher Desktop",
        "Podman Desktop" => "Podman",
        _ => return None,
    })
}

/// Linux (and exe-less) browser / Electron process families by name: (display, browser).
fn linux_family(lname: &str) -> Option<(&'static str, bool)> {
    Some(match lname {
        "chrome" | "google-chrome" | "chrome_crashpad" | "chrome_crashpad_handler" => ("Chrome", true),
        "chromium" | "chromium-browser" => ("Chromium", true),
        "brave" | "brave-browser" => ("Brave", true),
        "msedge" | "microsoft-edge" => ("Edge", true),
        "vivaldi-bin" | "vivaldi" => ("Vivaldi", true),
        "opera" => ("Opera", true),
        "firefox" | "firefox-esr" | "firefox-bin" | "web content" | "isolated web co" | "webextensions"
        | "isolated servic" => ("Firefox", true),
        "slack" => ("Slack", false),
        "discord" => ("Discord", false),
        "code" | "code-insiders" => ("VS Code", false),
        "cursor" => ("Cursor", false),
        "obsidian" => ("Obsidian", false),
        "signal-desktop" => ("Signal", false),
        "spotify" => ("Spotify", false),
        "teams-for-linux" => ("Teams", false),
        "1password" => ("1Password", false),
        "electron" => ("Electron app", false),
        _ => return None,
    })
}

/// Firefox's generic helper names: only Firefox's when a parent is Firefox.
const FIREFOX_HELPERS: &[&str] = &["rdd process", "socket process", "utility process", "privileged cont", "gpu process", "forkserver"];

fn is_vm_name_mac_only(l: &str) -> bool {
    l.starts_with("orbstack")
}

impl<'a> Ctx<'a> {
    pub fn new(snap: &'a Snapshot, os: Os) -> Ctx<'a> {
        let mut users: Vec<&'a str> = Vec::new();
        for p in &snap.procs {
            let u = p.user.as_str();
            if u.is_empty() || system_account(u) || users.contains(&u) {
                continue;
            }
            let k = classify_launcher(p);
            let session = matches!(k, Launcher::Shell | Launcher::Terminal | Launcher::Agent | Launcher::Ide)
                || p.cgroup.contains("/session-")
                || p.cgroup.contains("/user@");
            if session || bundle_of(&p.exe).is_some() {
                users.push(u);
            }
        }
        // A container's init is its earliest-started process whose parent is outside it;
        // `docker exec` sessions also hang off the shim but start later.
        let mut inits: HashMap<String, (u64, u32)> = HashMap::new();
        if os == Os::Linux {
            for p in &snap.procs {
                let Some((id, _)) = container_of(p) else { continue };
                if snap.proc(p.ppid).and_then(container_of).is_some_and(|(pid_, _)| pid_ == id) {
                    continue;
                }
                let key = (p.start_time, p.pid);
                let e = inits.entry(id).or_insert(key);
                if key < *e {
                    *e = key;
                }
            }
        }
        let inits = inits.into_iter().map(|(k, v)| (k, v.1)).collect();
        Ctx { snap, os, users, inits }
    }

    // ------------------------------------------------------------ identity

    /// The GUI app `p` belongs to (bundle on macOS, process family on Linux).
    pub fn app(&self, p: &Proc) -> Option<App> {
        let path = if p.exe.is_empty() { p.cmd.as_str() } else { p.exe.as_str() };
        if let Some((bundle, main)) = bundle_of(path) {
            return Some(App { name: display_name(bundle), browser: is_browser(bundle), main: main && !p.cmd.contains("--type=") });
        }
        let lname = p.name.to_ascii_lowercase();
        if lname.starts_with("com.apple.webkit.") {
            let safari = self.snap.procs.iter().any(|q| q.name == "Safari");
            return Some(App { name: if safari { "Safari".into() } else { "WebKit".into() }, browser: safari, main: false });
        }
        if let Some((name, browser)) = linux_family(&lname) {
            let parent_same = self.snap.proc(p.ppid).is_some_and(|q| linux_family(&q.name.to_ascii_lowercase()).is_some_and(|f| f.0 == name));
            return Some(App { name: name.into(), browser, main: !parent_same && !p.cmd.contains("--type=") });
        }
        if FIREFOX_HELPERS.contains(&lname.as_str())
            && self.snap.ancestors(p.pid).iter().take(3).any(|q| linux_family(&q.name.to_ascii_lowercase()).is_some_and(|f| f.0 == "Firefox"))
        {
            return Some(App { name: "Firefox".into(), browser: true, main: false });
        }
        // macOS without a readable exe: "Brave Browser Helper (Renderer)" -> Brave Browser.
        if self.os == Os::Mac
            && p.exe.is_empty()
            && let Some((app, _)) = p.name.split_once(" Helper")
            && !app.is_empty()
        {
            return Some(App { name: display_name(app), browser: is_browser(app), main: false });
        }
        if self.os == Os::Mac && is_browser(&p.name) && p.exe.is_empty() {
            return Some(App { name: display_name(&p.name), browser: true, main: true });
        }
        None
    }

    /// VM product hosted by `p`, if it is a VM / container host.
    pub fn vm_product(&self, p: &Proc) -> Option<&'static str> {
        let path = if p.exe.is_empty() { p.cmd.as_str() } else { p.exe.as_str() };
        if let Some((b, _)) = bundle_of(path)
            && let Some(v) = bundle_vm(b)
        {
            return Some(v);
        }
        let l = p.name.to_ascii_lowercase();
        let cmd = p.cmd.to_ascii_lowercase();
        if self.os == Os::Mac && is_vm_name_mac_only(&l) {
            return Some("OrbStack");
        }
        if l.starts_with("com.docker.") || l.starts_with("docker desktop") {
            return Some("Docker Desktop");
        }
        if l.starts_with("qemu-system") || l == "qemu" || l == "qemulauncher" {
            return Some(if l == "qemulauncher" || cmd.contains("/utm") {
                "UTM"
            } else if cmd.contains("colima") {
                "Colima"
            } else if cmd.contains("lima") {
                "Lima"
            } else if cmd.contains("podman") {
                "Podman"
            } else {
                "QEMU"
            });
        }
        Some(match l.as_str() {
            "limactl" if cmd.contains("colima") => "Colima",
            "limactl" => "Lima",
            "colima" => "Colima",
            "vfkit" | "krunkit" if cmd.contains("podman") => "Podman",
            "vfkit" | "krunkit" if cmd.contains("docker") => "Docker Desktop",
            "vfkit" | "krunkit" if cmd.contains("minikube") => "minikube",
            "vfkit" | "krunkit" => "a vfkit/krunkit VM",
            "com.apple.virtualization.virtualmachine" => self.apple_vm_owner(),
            "prl_vm_app" | "prl_client_app" => "Parallels",
            "vmware-vmx" => "VMware Fusion",
            "vboxheadless" | "virtualboxvm" | "vboxsvc" => "VirtualBox",
            "firecracker" => "Firecracker",
            "crosvm" => "crosvm",
            "tart" => "Tart",
            _ => return None,
        })
    }

    /// Which product runs an Apple Virtualization.framework VM (an XPC service under launchd).
    fn apple_vm_owner(&self) -> &'static str {
        let has = |f: &dyn Fn(&str) -> bool| self.snap.procs.iter().any(|q| f(&q.name.to_ascii_lowercase()));
        if has(&|n| n.starts_with("com.docker.")) {
            "Docker Desktop"
        } else if has(&|n| n == "colima") {
            "Colima"
        } else if has(&|n| n == "limactl") {
            "Lima"
        } else if has(&|n| n == "utm") {
            "UTM"
        } else if has(&|n| n == "tart") {
            "Tart"
        } else if has(&|n| n == "vfkit" || n == "krunkit" || n == "podman") {
            "Podman"
        } else if has(&|n| n.starts_with("rancher desktop")) {
            "Rancher Desktop"
        } else {
            "an Apple Virtualization VM"
        }
    }

    /// An interactive shell: a login shell, or one with no script / `-c` argument. A shell
    /// running a script is a job; one re-parented to init is a leftover, not a session.
    fn interactive_shell(&self, p: &Proc) -> bool {
        if p.name.starts_with('-') || p.cmd.starts_with('-') {
            return true;
        }
        if p.ppid == 1 {
            return false;
        }
        let toks: Vec<&str> = p.cmd.split_whitespace().collect();
        toks.len() <= 1 || !toks[1..].iter().any(|a| *a == "-c" || !a.starts_with('-'))
    }

    /// Classify `p` as a hub, if it is one.
    pub fn hub(&self, p: &Proc) -> Option<Hub> {
        let l = p.name.to_ascii_lowercase();
        if p.name == "kernel_task" || (p.pid == 0 && self.os == Os::Mac) || (self.os == Os::Linux && is_kernel_thread(p)) {
            return Some(Hub::Kernel);
        }
        if p.pid == 1 || matches!(l.as_str(), "launchd" | "systemd" | "init") {
            return Some(Hub::Init);
        }
        if self.os == Os::Linux
            && let Some((id, _)) = container_of(p)
            && self.inits.get(&id) == Some(&p.pid)
        {
            return Some(Hub::ContainerInit { id });
        }
        if let Some(product) = self.vm_product(p) {
            return Some(Hub::Vm { product });
        }
        if l.starts_with("containerd-shim")
            || matches!(
                l.as_str(),
                "dockerd" | "containerd" | "podman" | "conmon" | "crun" | "runc" | "crio" | "cri-dockerd" | "kubelet" | "k3s" | "k3s-server" | "k3s-agent"
            )
        {
            return Some(Hub::Runtime);
        }
        if matches!(l.as_str(), "windowserver" | "xorg" | "xwayland" | "gnome-shell" | "plasmashell" | "mutter" | "sway" | "hyprland" | "weston")
            || l.starts_with("kwin_")
        {
            return Some(Hub::Display);
        }
        if let Some(app) = self.app(p).filter(|a| a.main) {
            let multi = self.snap.procs.iter().any(|q| q.ppid == p.pid && self.app(q).is_some_and(|a| a.name == app.name));
            if app.browser {
                return Some(Hub::Browser { app: app.name });
            }
            if multi {
                return Some(Hub::AppMain { app: app.name });
            }
        }
        let what = match classify_launcher(p) {
            Launcher::Shell if self.interactive_shell(p) => "shell",
            Launcher::Terminal => "terminal",
            Launcher::Remote => "ssh session",
            Launcher::Agent => "agent session",
            Launcher::Ide => "editor",
            _ => return None,
        };
        Some(Hub::Session { what })
    }

    /// The container a shim (containerd-shim, conmon) runs.
    fn shim_container(&self, p: &Proc) -> Option<String> {
        let l = p.name.to_ascii_lowercase();
        if !(l.starts_with("containerd-shim") || l == "conmon") {
            return None;
        }
        self.snap.descendants(p.pid).into_iter().find_map(container_of).map(|x| x.0)
    }

    /// Started (directly or not) from a shell, terminal, ssh session, editor or agent.
    fn session_launched(&self, p: &Proc) -> bool {
        self.snap.ancestors(p.pid).iter().any(|a| SHELL_HOSTS.contains(&classify_launcher(a)))
    }

    /// A process the user may pause/kill: their own, or root/system but started from their session.
    pub fn owned(&self, p: &Proc) -> bool {
        let u = p.user.as_str();
        if u.is_empty() || system_account(u) {
            return self.session_launched(p);
        }
        self.users.is_empty() || self.users.contains(&u)
    }

    /// Why pause/kill is off the table for `p` (None = it's a plain user process).
    pub fn block(&self, p: &Proc) -> Option<Block> {
        if let Some(h) = self.hub(p) {
            return Some(Block::Hub(h));
        }
        if is_system_critical_on(self.os, p) || p.exe.starts_with("/System/Library/CoreServices/") {
            return Some(Block::Critical);
        }
        if let Some(a) = self.app(p) {
            return Some(Block::Gui(a));
        }
        if !self.owned(p) {
            if self.os == Os::Linux
                && let Some((id, _)) = container_of(p)
            {
                return Some(Block::Container { id });
            }
            return Some(Block::Service);
        }
        None
    }

    // ------------------------------------------------------------ advice

    /// The one gate every runnable suggestion goes through.
    pub fn advise(&self, p: &Proc, want: Want) -> Advice {
        let block = self.block(p);
        let renice_ok = match &block {
            None => true,
            Some(Block::Gui(a)) => !a.main && self.owned(p),
            _ => false,
        };
        if want == Want::Renice {
            return if renice_ok {
                Advice { action: Some(format!("renice {} 10", p.pid)), note: None }
            } else {
                Advice { action: None, note: block.map(|b| self.block_note(p, &b)) }
            };
        }
        if let Some(b) = block {
            return Advice { action: None, note: Some(self.block_note(p, &b)) };
        }
        // Zombies are already dead: they don't make a process a tree.
        let desc: Vec<&Proc> = self.snap.descendants(p.pid).into_iter().filter(|d| !is_zombie(d)).collect();
        // Never end a tree that hosts other work (a shell, terminal, app or VM below it).
        let hosted: Vec<&Proc> = desc.iter().copied().filter(|d| self.hub(d).is_some()).collect();
        let tree_ok = hosted.is_empty();
        let pid = p.pid;
        let action = match want {
            Want::Pause => Some(format!("pause {pid}")),
            Want::Calm if desc.is_empty() || !tree_ok => Some(format!("pause {pid}")),
            Want::Calm => Some(format!("pause {pid} (or kill {pid} --tree)")),
            Want::End if desc.is_empty() => Some(format!("kill {pid}")),
            Want::End | Want::EndTree if tree_ok => Some(format!("kill {pid} --tree")),
            Want::End | Want::EndTree => None,
            Want::Renice => unreachable!(),
        };
        let note = (!tree_ok && matches!(want, Want::End | Want::EndTree | Want::Calm)).then(|| {
            format!(
                "{} (pid {pid}) hosts {} (pid {}); end the specific job instead of the whole tree",
                p.name, hosted[0].name, hosted[0].pid
            )
        });
        Advice { action, note }
    }

    fn quit_hint(&self, app: &str) -> String {
        if self.os == Os::Mac { format!("quit {app} normally ({app} menu > Quit, or Cmd-Q)") } else { format!("close {app} normally") }
    }

    fn tab_hint(app: &str) -> String {
        match app {
            "Firefox" | "Zen" | "LibreWolf" | "Waterfox" | "Floorp" | "Tor Browser" => "open about:processes to see which tab".into(),
            "Safari" | "WebKit" | "Orion" => "Activity Monitor names each tab's WebContent process".into(),
            _ => format!("Shift+Esc in {app} opens its task manager"),
        }
    }

    /// One sentence on what to do instead of pausing/killing `p`.
    pub fn block_note(&self, p: &Proc, b: &Block) -> String {
        match b {
            Block::Hub(h) => self.hub_note(p, h),
            Block::Critical => format!("{} is part of the OS; don't pause or kill it", p.name),
            Block::Gui(a) if a.browser => {
                format!("it is a {} tab/helper: close heavy tabs ({}), or {}", a.name, Self::tab_hint(&a.name), self.quit_hint(&a.name))
            }
            Block::Gui(a) => format!("it is part of {}: {} rather than killing its processes", a.name, self.quit_hint(&a.name)),
            Block::Container { id } => {
                let ct = find_container(self.snap, id);
                let label = container_label(self.snap, id);
                let cli = container_cli(ct.map(|c| c.runtime.as_str()).or_else(|| container_of(p).and_then(|x| x.1)));
                format!("it runs in container {label}: end it from where it was started (e.g. its `{cli} exec` shell), or `{cli} stop {label}` stops the whole container")
            }
            Block::Service => {
                let who = if p.user.is_empty() { "another user".to_string() } else { p.user.clone() };
                let mgr = if self.os == Os::Linux { "systemctl" } else { "launchctl" };
                format!("{} runs as {who}, a system service: restart it through its service manager ({mgr}) rather than killing it", p.name)
            }
        }
    }

    fn hub_note(&self, p: &Proc, h: &Hub) -> String {
        match h {
            Hub::Vm { product } => {
                let cts = self.vm_containers(product);
                let mut s = match cts.first() {
                    Some(c) => format!(
                        "{} is the {product} VM; its memory is containers ({}): `{} stop {}` frees the biggest",
                        p.name,
                        Self::container_list(&cts, 3),
                        vm_cli(product),
                        c.name
                    ),
                    None => format!("{} is the {product} VM; its cost is whatever runs inside it (`fat fleet` lists the containers)", p.name),
                };
                s.push_str(&format!("; to cap it, {}", vm_limit_hint(product)));
                s
            }
            Hub::Runtime if self.shim_container(p).is_some() => {
                let id = self.shim_container(p).unwrap_or_default();
                let label = container_label(self.snap, &id);
                format!("{} is the shim of container {label}: its cost is that container; `docker stop {label}` stops it cleanly", p.name)
            }
            Hub::Runtime => {
                format!("{} is a container runtime; its load is its containers': stop the busy container (`docker stop <name>`), not the runtime", p.name)
            }
            Hub::ContainerInit { id } => {
                let label = container_label(self.snap, id);
                format!("{} is pid 1 of container {label}: killing it stops the container; use `docker restart {label}` or `docker stop {label}`", p.name)
            }
            Hub::Init => format!("{} is init; it hosts every service and app", p.name),
            Hub::Browser { app } => {
                let heavy = self.app_heaviest(app, 2);
                let list = if heavy.is_empty() { String::new() } else { format!(" (heaviest: {})", Self::proc_list(&heavy)) };
                format!("{} is {app}'s main process{list}: close heavy tabs ({}), or {}", p.name, Self::tab_hint(app), self.quit_hint(app))
            }
            Hub::AppMain { app } => format!("{} is {app}'s main process: {} rather than killing it", p.name, self.quit_hint(app)),
            Hub::Session { what } => {
                let jobs = self.heaviest_jobs(p, 2);
                if jobs.is_empty() {
                    format!("{} is your {what}; ending it ends everything running in it", p.name)
                } else {
                    format!("{} is your {what}; its cost is its jobs ({}): see `fat why {}`", p.name, Self::proc_list(&jobs), jobs[0].pid)
                }
            }
            Hub::Display => format!("{} draws every window; the cause is an app redrawing a lot", p.name),
            Hub::Kernel => format!("{} is the kernel; the cause is elsewhere", p.name),
        }
    }

    // ------------------------------------------------------------ workloads

    /// Containers a VM product hosts, biggest first. On macOS, containers no running VM claims
    /// are attributed to the only VM present.
    pub fn vm_containers(&self, product: &str) -> Vec<&'a Container> {
        let rts: &[&str] = match product {
            "OrbStack" => &["orbstack"],
            "Docker Desktop" => &["docker", "docker-rootless"],
            "Colima" => &["colima"],
            "Lima" => &["lima", "colima"],
            "Rancher Desktop" => &["rancher"],
            "Podman" => &["podman"],
            _ => &[],
        };
        let mut v: Vec<&Container> = self.snap.containers.iter().filter(|c| rts.contains(&c.runtime.as_str())).collect();
        if v.is_empty() && self.os == Os::Mac {
            let mut products: Vec<&'static str> = self.snap.procs.iter().filter_map(|q| self.vm_product(q)).collect();
            products.sort_unstable();
            products.dedup();
            if products.len() == 1 && products[0] == product {
                v = self.snap.containers.iter().collect();
            }
        }
        v.sort_by(|a, b| b.mem.cmp(&a.mem).then(a.name.cmp(&b.name)));
        v
    }

    fn container_list(cts: &[&Container], n: usize) -> String {
        let mut s = cts.iter().take(n).map(|c| format!("{} {}", c.name, human_bytes(c.mem))).collect::<Vec<_>>().join(", ");
        if cts.len() > n {
            s.push_str(&format!(", +{} more", cts.len() - n));
        }
        s
    }

    fn proc_list(ps: &[&Proc]) -> String {
        ps.iter().map(|q| format!("{} (pid {}) {}", q.name, q.pid, human_bytes(q.mem))).collect::<Vec<_>>().join(", ")
    }

    /// Heaviest (by memory) non-main processes of an app.
    fn app_heaviest(&self, app: &str, n: usize) -> Vec<&'a Proc> {
        let mut v: Vec<&Proc> =
            self.snap.procs.iter().filter(|q| self.app(q).is_some_and(|a| a.name == app && !a.main)).collect();
        v.sort_by(|a, b| b.mem.cmp(&a.mem).then(b.cpu.total_cmp(&a.cpu)));
        v.truncate(n);
        v
    }

    /// Heaviest descendants of a session hub that are not hubs themselves (by CPU, then memory).
    fn heaviest_jobs(&self, p: &Proc, n: usize) -> Vec<&'a Proc> {
        let mut v: Vec<&Proc> = self.snap.descendants(p.pid).into_iter().filter(|d| self.hub(d).is_none() && !is_zombie(d)).collect();
        v.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.mem.cmp(&a.mem)));
        v.retain(|d| d.cpu >= 1.0 || d.mem >= 64 * super::MB);
        v.truncate(n);
        v
    }

    /// Memory workloads, biggest first: multi-process apps and VMs count once with all their
    /// processes, Linux containers by their processes, everything else per process.
    pub fn consumers(&self) -> Vec<Consumer<'a>> {
        let mut groups: HashMap<String, Consumer<'a>> = HashMap::new();
        for p in &self.snap.procs {
            if is_zombie(p) || p.mem == 0 || (self.os == Os::Linux && is_kernel_thread(p)) {
                continue;
            }
            let (key, name, kind) = if let Some((id, _)) = container_of(p).filter(|_| self.os == Os::Linux) {
                (format!("ct:{id}"), container_label(self.snap, &id), CKind::Container { id })
            } else if let Some(product) = self.vm_product(p) {
                (format!("app:{product}"), product.to_string(), CKind::Vm { product })
            } else if let Some(a) = self.app(p) {
                (format!("app:{}", a.name), a.name.clone(), CKind::App { browser: a.browser })
            } else {
                (format!("pid:{}", p.pid), p.name.clone(), CKind::Proc)
            };
            let e = groups.entry(key).or_insert_with(|| Consumer { name, kind, mem: 0, lead: p, members: Vec::new() });
            e.mem += p.mem;
            e.members.push(p);
        }
        let mut v: Vec<Consumer<'a>> = groups.into_values().collect();
        for c in &mut v {
            c.members.sort_by(|a, b| b.mem.cmp(&a.mem).then(a.pid.cmp(&b.pid)));
            c.lead = match &c.kind {
                CKind::App { .. } => c
                    .members
                    .iter()
                    .find(|q| self.app(q).is_some_and(|a| a.main))
                    .copied()
                    .unwrap_or(c.members[0]),
                CKind::Container { .. } => c
                    .members
                    .iter()
                    .find(|q| matches!(self.hub(q), Some(Hub::ContainerInit { .. })))
                    .copied()
                    .unwrap_or(c.members[0]),
                _ => c.members[0],
            };
        }
        v.sort_by(|a, b| b.mem.cmp(&a.mem).then(a.name.cmp(&b.name)));
        v
    }

    /// "Brave 7.3G across 84 processes (heaviest: ...)", "OrbStack 2.9G (VM: containers ...)".
    pub fn consumer_text(&self, c: &Consumer<'_>) -> String {
        let n = c.members.len();
        match &c.kind {
            CKind::Proc => format!("{} (pid {}) {}", c.lead.name, c.lead.pid, human_bytes(c.mem)),
            CKind::App { .. } if n == 1 => format!("{} (pid {}) {}", c.name, c.lead.pid, human_bytes(c.mem)),
            CKind::App { browser } => {
                let heavy: Vec<&Proc> = c.members.iter().filter(|q| q.pid != c.lead.pid).take(2).copied().collect();
                let what = if *browser { "heaviest tabs/helpers" } else { "heaviest" };
                format!(
                    "{} {} across {n} processes ({what}: {})",
                    c.name,
                    human_bytes(c.mem),
                    heavy.iter().map(|q| format!("pid {} {}", q.pid, human_bytes(q.mem))).collect::<Vec<_>>().join(", ")
                )
            }
            CKind::Vm { product } => {
                let cts = self.vm_containers(product);
                let inside = if cts.is_empty() {
                    "VM: the cost is the VM and what runs in it; `fat fleet` lists its containers".to_string()
                } else {
                    format!("VM: containers {}; the rest is the VM itself", Self::container_list(&cts, 3))
                };
                format!("{} {} ({inside})", c.name, human_bytes(c.mem))
            }
            CKind::Container { .. } => format!("container {} {} ({n} processes)", c.name, human_bytes(c.mem)),
        }
    }

    /// What to do about a workload: a runnable fat command when one is safe, else advice text.
    pub fn consumer_advice(&self, c: &Consumer<'_>) -> Advice {
        match &c.kind {
            CKind::Proc => self.advise(c.lead, Want::End),
            CKind::App { browser: true } => Advice {
                action: None,
                note: Some(format!("close heavy tabs in {} ({}), or {}", c.name, Self::tab_hint(&c.name), self.quit_hint(&c.name))),
            },
            CKind::App { .. } => Advice { action: None, note: Some(format!("{} and reopen it", self.quit_hint(&c.name))) },
            CKind::Vm { product } => {
                let cts = self.vm_containers(product);
                let first = cts.first().map(|x| format!("`{} stop {}` (its biggest container), or ", vm_cli(product), x.name)).unwrap_or_default();
                Advice { action: None, note: Some(format!("{product}: {first}{}", vm_limit_hint(product))) }
            }
            CKind::Container { id } => {
                let rt = find_container(self.snap, id).map(|x| x.runtime.as_str()).or_else(|| container_of(c.lead).and_then(|x| x.1));
                Advice { action: None, note: Some(format!("`{} stop {}` stops that container", container_cli(rt), c.name)) }
            }
        }
    }

    // ------------------------------------------------------------ why

    /// Chain steps and suggestions for a hub's `fat why`. Never suggests pausing/killing it.
    pub fn hub_explain(&self, p: &Proc, h: &Hub) -> (Vec<String>, Vec<String>) {
        let mut steps = Vec::new();
        let mut sugg = Vec::new();
        match h {
            Hub::Vm { product } => {
                steps.push(format!(
                    "it is the {product} VM host: its {} is the Linux VM and everything running inside it, not {} itself",
                    human_bytes(p.mem),
                    p.name
                ));
                let cts = self.vm_containers(product);
                if cts.is_empty() {
                    steps.push("no containers listed for it; the load is the VM guest itself (Linux machines, builds, page cache)".into());
                } else {
                    steps.push(format!(
                        "root cause: containers inside it: {}",
                        cts.iter()
                            .take(5)
                            .map(|c| {
                                let img = if c.image.is_empty() { String::new() } else { format!(" ({})", c.image) };
                                format!("{}{img} {:.0}% CPU {}", c.name, c.cpu, human_bytes(c.mem))
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    sugg.push(format!("stop the biggest container: {} stop {}", vm_cli(product), cts[0].name));
                }
                sugg.push(vm_limit_hint(product));
                sugg.push("inspect what runs inside: fat fleet (or docker stats)".into());
                sugg.push(format!("don't pause or kill {}: that freezes or kills every container and VM inside it", p.name));
            }
            Hub::Runtime if self.shim_container(p).is_some() => {
                let id = self.shim_container(p).unwrap_or_default();
                let label = container_label(self.snap, &id);
                let cli = container_cli(find_container(self.snap, &id).map(|c| c.runtime.as_str()).or_else(|| container_of(p).and_then(|x| x.1)));
                sugg.push(format!("stop or restart its container instead: {cli} stop {label} / {cli} restart {label}"));
                sugg.push(format!("don't kill {}: it is container {label}'s shim, the container dies with it", p.name));
            }
            Hub::Runtime => {
                let loads = if self.os == Os::Linux { container_loads(self.snap) } else { Vec::new() };
                if let Some(l) = loads.first() {
                    let label = container_label(self.snap, &l.id);
                    sugg.push(format!("stop a busy container instead: {} stop {label}", container_cli(l.runtime)));
                } else if let Some(c) = self.snap.containers.iter().max_by_key(|c| c.mem) {
                    sugg.push(format!("stop a container instead: docker stop {}", c.name));
                }
                sugg.push(format!("don't kill {}: every container it manages would stop or be orphaned", p.name));
            }
            Hub::ContainerInit { id } => {
                let label = container_label(self.snap, id);
                steps.push(format!("it is pid 1 (the entrypoint) of container {label}: the container lives exactly as long as it does"));
                sugg.push(format!("restart or stop the container instead: docker restart {label} / docker stop {label}"));
            }
            Hub::Init => {}
            Hub::Browser { app } | Hub::AppMain { app } => {
                let members: Vec<&Proc> = self.snap.procs.iter().filter(|q| self.app(q).is_some_and(|a| &a.name == app)).collect();
                let total: u64 = members.iter().map(|q| q.mem).sum();
                let cpu: f32 = members.iter().map(|q| q.cpu).sum();
                steps.push(format!(
                    "it is {app}'s main process: {app} runs {} processes using {} RAM and {cpu:.0}% CPU in total",
                    members.len(),
                    human_bytes(total)
                ));
                let heavy = self.app_heaviest(app, 3);
                if !heavy.is_empty() {
                    let what = if matches!(h, Hub::Browser { .. }) { "heaviest tabs/helpers" } else { "heaviest helpers" };
                    steps.push(format!("{what}: {}", Self::proc_list(&heavy)));
                }
                if p.cpu >= 50.0 {
                    steps.push(format!(
                        "the main process itself is busy ({:.0}% CPU): usually an extension, sync, or a stuck page/window",
                        p.cpu
                    ));
                }
                if matches!(h, Hub::Browser { .. }) {
                    sugg.push(format!("find the heavy tab: {}; close or reload it", Self::tab_hint(app)));
                    sugg.push(format!("or {} to free all of it (most browsers reopen tabs on relaunch)", self.quit_hint(app)));
                } else {
                    sugg.push(format!("{} and reopen it; a heavy renderer is usually one window or workspace", self.quit_hint(app)));
                }
                if let Some(h) = heavy.first() {
                    sugg.push(format!("drill down: fat why {}", h.pid));
                }
            }
            Hub::Session { what } => {
                let jobs = self.heaviest_jobs(p, 3);
                steps.push(format!("it is an interactive {what}: its cost is the jobs started from it, not the {what} itself"));
                if let Some(j) = jobs.first() {
                    steps.push(format!("heaviest jobs: {}", Self::proc_list(&jobs)));
                    sugg.push(format!("drill down: fat why {}", j.pid));
                    if let Some(a) = self.advise(j, Want::End).action {
                        sugg.push(format!("end that job: fat {a}"));
                    }
                }
                sugg.push(format!("stop a job from its terminal (Ctrl-C) instead of killing the {what}"));
            }
            Hub::Display | Hub::Kernel => {}
        }
        (steps, sugg)
    }
}

/// CLI for a VM product's containers.
fn vm_cli(product: &str) -> &'static str {
    if product == "Podman" { "podman" } else { "docker" }
}

/// How to give a VM less memory, per product.
pub(super) fn vm_limit_hint(product: &str) -> String {
    match product {
        "OrbStack" => "lower the VM memory limit in OrbStack Settings > System (or `orb config set memory_mib <MiB>`); Linux machines: `orb list`, `orb stop <name>`".into(),
        "Docker Desktop" => "lower the VM memory limit in Docker Desktop Settings > Resources".into(),
        "Colima" => "`colima stop`, or restart it smaller: `colima start --memory <GiB>`".into(),
        "Lima" => "`limactl stop <instance>`; its memory is set in the instance's lima.yaml".into(),
        "Rancher Desktop" => "lower its memory in Rancher Desktop Preferences > Virtual Machine".into(),
        "Podman" => "`podman machine stop`, or `podman machine set --memory <MiB>`".into(),
        _ => "shut the guest down from inside it, or give it less memory in the VM's settings".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{GB, MB, diagnose, explain};
    use super::*;
    use crate::model::{ActionKind, Explanation, Finding, Port, Proto, System};
    use crate::tui::app::parse_action;

    const NOW: i64 = 1_800_000_000_000;
    const BRAVE: &str = "/Applications/Brave Browser.app";

    fn mp(pid: u32, ppid: u32, name: &str, exe: &str, cpu: f32, mem: u64) -> Proc {
        Proc {
            pid,
            ppid,
            name: name.into(),
            cmd: if exe.is_empty() { name.into() } else { exe.into() },
            exe: exe.into(),
            user: "me".into(),
            cpu,
            mem,
            status: "S".into(),
            start_time: (NOW / 1000 - 3600) as u64,
            ..Default::default()
        }
    }

    fn mac_base() -> Vec<Proc> {
        let mut l = mp(1, 0, "launchd", "/sbin/launchd", 0.1, 20 * MB);
        l.user = "root".into();
        vec![
            l,
            mp(100, 1, "ghostty", "/Applications/Ghostty.app/Contents/MacOS/ghostty", 2.0, 200 * MB),
            mp(101, 100, "login", "/usr/bin/login", 0.0, 2 * MB),
            mp(102, 101, "-zsh", "/bin/zsh", 0.0, 5 * MB),
        ]
    }

    fn mac(procs: Vec<Proc>) -> Snapshot {
        Snapshot {
            ts: NOW,
            host: "local".into(),
            system: System {
                os: "macOS 15.6".into(),
                cores: 14,
                mem_total: 36 * GB,
                mem_used: 30 * GB,
                swap_total: 8 * GB,
                swap_used: 6 * GB + 700 * MB,
                mem_pressure: "warn".into(),
                thermal: "nominal".into(),
                load: [2.0, 2.0, 2.0],
                ..Default::default()
            },
            procs,
            ports: vec![],
            containers: vec![],
        }
    }

    fn ct(name: &str, runtime: &str, mem: u64) -> Container {
        Container { id: format!("{:0<12}", name.len()), name: name.into(), image: "img:1".into(), runtime: runtime.into(), mem, ..Default::default() }
    }

    /// Pause/Term/Kill/KillTree targets of every finding's runnable action.
    fn harmful_targets(f: &[Finding]) -> Vec<(u32, String)> {
        f.iter()
            .filter_map(|x| x.action.as_deref())
            .filter_map(|a| parse_action(a).map(|(k, pid, _)| (k, pid, a.to_string())))
            .filter(|(k, _, _)| matches!(k, ActionKind::Pause | ActionKind::Term | ActionKind::Kill | ActionKind::KillTree))
            .map(|(_, pid, a)| (pid, a))
            .collect()
    }

    fn says_stop(e: &Explanation, pid: u32) -> bool {
        e.suggestions.iter().any(|s| {
            s.contains(&format!("fat kill {pid}")) || s.contains(&format!("fat pause {pid}")) || s.contains(&format!("kill {pid} --tree"))
        })
    }

    #[test]
    fn orbstack_helper_is_its_containers_never_killed() {
        let mut ps = mac_base();
        ps.push(mp(11043, 1, "OrbStack", "/Applications/OrbStack.app/Contents/MacOS/OrbStack", 0.0, 31 * MB));
        let helper = "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper";
        ps.push(mp(13792, 1, "OrbStack Helper", helper, 300.0, 2800 * MB));
        let mut s = mac(ps);
        s.containers = vec![ct("toposcope-clickhouse-1", "orbstack", 328 * MB), ct("toposcope-app-1", "orbstack", 55 * MB)];
        let f = diagnose(&s, None);
        let m = f.iter().find(|x| x.title.starts_with("Memory pressure")).expect("memory finding");
        assert!(m.detail.contains("OrbStack 2.8G (VM: containers toposcope-clickhouse-1 328M, toposcope-app-1 55M"), "{}", m.detail);
        assert!(m.detail.contains("`docker stop toposcope-clickhouse-1`"), "{}", m.detail);
        assert!(m.detail.contains("memory limit"), "{}", m.detail);
        assert!(m.detail.contains("swap 6.7G of 8.0G in use"), "{}", m.detail);
        assert_eq!(m.pids[0], 13792, "the lead is the VM process, for `fat why`");
        assert_eq!(m.action, None, "nothing safe to run: the only workload is the VM");
        let hot = f.iter().find(|x| x.title.starts_with("OrbStack Helper is using")).expect("cpu finding");
        assert_eq!(hot.action, None);
        assert!(hot.detail.contains("toposcope-clickhouse-1"), "{}", hot.detail);
        assert!(harmful_targets(&f).is_empty(), "{:?}", harmful_targets(&f));
        let e = explain(&s, 13792, None);
        assert!(!says_stop(&e, 13792), "{:?}", e.suggestions);
        assert!(!e.suggestions.iter().any(|x| x.contains("renice 13792")), "{:?}", e.suggestions);
        assert!(e.suggestions.iter().any(|x| x == "stop the biggest container: docker stop toposcope-clickhouse-1"), "{:?}", e.suggestions);
        assert!(e.chain.iter().any(|c| c.contains("OrbStack VM host")), "{:?}", e.chain);
        assert!(!e.chain.iter().any(|c| c.contains("pure CPU spin")));
    }

    #[test]
    fn docker_desktop_vm_is_attributed_to_docker() {
        let mut ps = mac_base();
        ps.push(mp(2236, 1, "com.docker.backend", "/Applications/Docker.app/Contents/MacOS/com.docker.backend", 1.0, 100 * MB));
        ps.push(mp(
            5745,
            2236,
            "Docker Desktop",
            "/Applications/Docker.app/Contents/MacOS/Docker Desktop.app/Contents/MacOS/Docker Desktop",
            0.0,
            20 * MB,
        ));
        let vm = "/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine";
        ps.push(mp(3000, 1, "com.apple.Virtualization.VirtualMachine", vm, 250.0, 6 * GB));
        let mut s = mac(ps);
        s.system.mem_pressure = "critical".into();
        s.containers = vec![ct("api", "docker", 1536 * MB), ct("db", "docker", 700 * MB)];
        let f = diagnose(&s, None);
        assert_eq!(f[0].severity, "crit");
        let m = &f[0];
        assert!(m.detail.contains("Docker Desktop 6.1G (VM: containers api 1.5G, db 700M"), "{}", m.detail);
        assert!(m.detail.contains("Settings > Resources"), "{}", m.detail);
        assert_eq!(m.pids[0], 3000);
        assert!(harmful_targets(&f).is_empty(), "{:?}", harmful_targets(&f));
        let e = explain(&s, 3000, None);
        assert!(e.chain.iter().any(|c| c.contains("Docker Desktop VM host")), "{:?}", e.chain);
        assert!(e.suggestions.iter().any(|x| x.contains("docker stop api")));
        assert!(!says_stop(&e, 3000), "{:?}", e.suggestions);
    }

    fn brave(ps: &mut Vec<Proc>) {
        ps.push(mp(1686, 1, "Brave Browser", &format!("{BRAVE}/Contents/MacOS/Brave Browser"), 200.0, 600 * MB));
        let helper = format!(
            "{BRAVE}/Contents/Frameworks/Brave Browser Framework.framework/Versions/1/Helpers/Brave Browser Helper (Renderer).app/Contents/MacOS/Brave Browser Helper (Renderer)"
        );
        for i in 0..21 {
            ps.push(mp(2000 + i, 1686, "Brave Browser Helper (Renderer)", &helper, 0.5, 150 * MB));
        }
        ps.push(mp(52510, 1686, "Brave Browser Helper (Renderer)", &helper, 160.0, 650 * MB));
    }

    #[test]
    fn browser_is_one_workload_close_tabs_not_kill() {
        let mut ps = mac_base();
        brave(&mut ps);
        ps.push(mp(900, 102, "java", "/usr/bin/java", 5.0, GB));
        let s = mac(ps);
        let f = diagnose(&s, None);
        let m = f.iter().find(|x| x.title.starts_with("Memory pressure")).unwrap();
        assert!(m.detail.contains("Biggest workloads: Brave 4.3G across 23 processes (heaviest tabs/helpers: pid 52510 650M"), "{}", m.detail);
        assert!(m.detail.contains("close heavy tabs in Brave"), "{}", m.detail);
        assert_eq!(m.pids[0], 1686);
        // The first safe action among the top workloads is the user's own CLI process.
        assert_eq!(m.action.as_deref(), Some("kill 900"));
        let hot = f.iter().find(|x| x.title.starts_with("Brave Browser is using")).expect("main busy");
        assert_eq!(hot.action, None);
        assert!(hot.detail.contains("Shift+Esc in Brave"), "{}", hot.detail);
        let r = f.iter().find(|x| x.pids == vec![52510]).expect("renderer busy");
        assert_eq!(r.action, None);
        assert!(r.detail.contains("close heavy tabs"), "{}", r.detail);
        for (pid, a) in harmful_targets(&f) {
            assert_eq!(pid, 900, "{a}");
        }
        let e = explain(&s, 1686, None);
        assert!(!says_stop(&e, 1686), "{:?}", e.suggestions);
        assert!(e.chain.iter().any(|c| c.contains("Brave runs 23 processes using 4.3G")), "{:?}", e.chain);
        assert!(e.chain.iter().any(|c| c.contains("main process itself is busy")), "{:?}", e.chain);
        assert!(e.suggestions.iter().any(|x| x == "drill down: fat why 52510"), "{:?}", e.suggestions);
        let e = explain(&s, 52510, None);
        assert!(!says_stop(&e, 52510), "{:?}", e.suggestions);
        assert!(e.chain.iter().any(|c| c.contains("one Brave tab")), "{:?}", e.chain);
    }

    #[test]
    fn electron_app_gets_quit_advice() {
        let mut ps = mac_base();
        ps.push(mp(44401, 1, "Slack", "/Applications/Slack.app/Contents/MacOS/Slack", 1.0, 109 * MB));
        let h = "/Applications/Slack.app/Contents/Frameworks/Slack Helper (Renderer).app/Contents/MacOS/Slack Helper (Renderer)";
        ps.push(mp(46079, 44401, "Slack Helper (Renderer)", h, 180.0, 1536 * MB));
        ps.push(mp(46080, 44401, "Slack Helper", "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper", 0.0, 30 * MB));
        let s = mac(ps);
        let f = diagnose(&s, None);
        let m = f.iter().find(|x| x.title.starts_with("Memory pressure")).unwrap();
        assert!(m.detail.contains("Slack 1.6G across 3 processes"), "{}", m.detail);
        assert!(m.detail.contains("quit Slack normally"), "{}", m.detail);
        let hot = f.iter().find(|x| x.pids == vec![46079]).unwrap();
        assert_eq!(hot.action, None);
        assert!(harmful_targets(&f).is_empty(), "{:?}", harmful_targets(&f));
        let e = explain(&s, 46079, None);
        assert!(e.suggestions.iter().any(|x| x.contains("quit Slack normally")), "{:?}", e.suggestions);
        assert!(!says_stop(&e, 46079), "{:?}", e.suggestions);
        let e = explain(&s, 44401, None);
        assert!(e.chain.iter().any(|c| c.contains("Slack's main process")), "{:?}", e.chain);
        assert!(!says_stop(&e, 44401), "{:?}", e.suggestions);
    }

    #[test]
    fn runaway_cli_still_gets_pause_and_kill() {
        let mut ps = mac_base();
        ps.push(mp(3000, 102, "yes", "/usr/bin/yes", 200.0, MB));
        ps.push(mp(3001, 102, "leaky", "/Users/me/bin/leaky", 10.0, 20 * GB));
        let mut sudo = mp(3002, 102, "stress", "/opt/homebrew/bin/stress", 400.0, 10 * MB);
        sudo.user = "root".into(); // `sudo stress` from the user's shell
        ps.push(sudo);
        let s = mac(ps);
        let f = diagnose(&s, None);
        assert_eq!(f.iter().find(|x| x.pids == vec![3000]).unwrap().action.as_deref(), Some("pause 3000"));
        assert_eq!(f.iter().find(|x| x.pids == vec![3002]).unwrap().action.as_deref(), Some("pause 3002"));
        let m = f.iter().find(|x| x.title.starts_with("Memory pressure")).unwrap();
        assert_eq!(m.action.as_deref(), Some("kill 3001"));
        assert!(m.detail.contains("leaky (pid 3001) 20.0G"), "{}", m.detail);
        let e = explain(&s, 3000, None);
        assert!(e.suggestions.iter().any(|x| x == "pause it (reversible): fat pause 3000"));
        assert!(e.suggestions.iter().any(|x| x == "stop it: fat kill 3000"));
    }

    #[test]
    fn root_daemon_gets_no_kill() {
        let mut ps = mac_base();
        let mut d = mp(400, 1, "somed", "/usr/libexec/somed", 300.0, 2 * GB);
        d.user = "root".into();
        d.disk_write_bps = 300 * MB;
        ps.push(d);
        let mut w = mp(401, 1, "helperd", "/usr/libexec/helperd", 0.0, 0);
        w.user = "_spotlight".into();
        w.power_mw = 9000.0;
        ps.push(w);
        let s = mac(ps);
        let f = diagnose(&s, None);
        let hot = f.iter().find(|x| x.title.starts_with("somed is using")).unwrap();
        assert_eq!(hot.action, None);
        assert!(hot.detail.contains("runs as root, a system service"), "{}", hot.detail);
        assert!(harmful_targets(&f).is_empty(), "{:?}", harmful_targets(&f));
        let e = explain(&s, 400, None);
        assert!(!says_stop(&e, 400), "{:?}", e.suggestions);
        assert!(e.suggestions.iter().any(|x| x.contains("launchctl")), "{:?}", e.suggestions);
    }

    #[test]
    fn sessions_are_hubs_but_scripts_are_jobs() {
        let s = mac(mac_base());
        let cx = Ctx::new(&s, Os::Mac);
        let p = |name: &str, cmd: &str, ppid: u32| Proc { cmd: cmd.into(), ..mp(9, ppid, name, "", 0.0, 0) };
        assert_eq!(cx.hub(&p("-zsh", "-zsh", 101)), Some(Hub::Session { what: "shell" }));
        assert_eq!(cx.hub(&p("zsh", "/bin/zsh -il", 101)), Some(Hub::Session { what: "shell" }));
        assert_eq!(cx.hub(&p("bash", "bash ./build.sh", 102)), None);
        assert_eq!(cx.hub(&p("bash", "bash -c while true; do :; done", 102)), None);
        assert_eq!(cx.hub(&p("bash", "/bin/bash", 1)), None, "re-parented to launchd: a leftover");
        assert_eq!(cx.hub(&p("tmux", "tmux new -s x", 1)), Some(Hub::Session { what: "terminal" }));
        assert_eq!(cx.hub(&p("claude", "claude", 102)), Some(Hub::Session { what: "agent session" }));
        assert_eq!(cx.hub(&p("dockerd", "dockerd", 1)), Some(Hub::Runtime));
        assert_eq!(cx.hub(&p("qemu-system-aarch64", "qemu-system-aarch64 -m 4096 lima", 1)), Some(Hub::Vm { product: "Lima" }));
        assert_eq!(bundle_of("/Applications/OrbStack.app/Contents/MacOS/bin/orb"), None, "CLI inside a bundle");
        assert_eq!(bundle_of("/Users/me/Library/Application Support/Claude/claude-code/1/claude.app/Contents/MacOS/claude"), None);
        assert_eq!(bundle_of("/Applications/Slack.app/Contents/MacOS/Slack"), Some(("Slack", true)));
        // A kill --tree never reaches a hosted session/app.
        let mut ps = mac_base();
        ps.push(mp(500, 102, "runner", "/Users/me/bin/runner", 0.0, MB));
        ps.push(Proc { cmd: "tmux new".into(), ..mp(501, 500, "tmux", "/opt/homebrew/bin/tmux", 0.0, MB) });
        let s = mac(ps);
        let cx = Ctx::new(&s, Os::Mac);
        let a = cx.advise(s.proc(500).unwrap(), Want::EndTree);
        assert_eq!(a.action, None);
        assert!(a.note.unwrap().contains("hosts tmux (pid 501)"));
        assert_eq!(cx.advise(s.proc(500).unwrap(), Want::Calm).action.as_deref(), Some("pause 500"));
    }

    #[test]
    fn linux_container_pid1_and_runtime_are_hubs() {
        let cid = "410892b21be2";
        let mut procs = vec![
            Proc { pid: 1, ppid: 0, name: "systemd".into(), user: "root".into(), status: "S".into(), cgroup: "/init.scope".into(), ..Default::default() },
            Proc { pid: 40, ppid: 1, name: "containerd".into(), user: "root".into(), status: "S".into(), mem: 60 * MB, cpu: 30.0, ..Default::default() },
            Proc { pid: 50, ppid: 1, name: "containerd-shim-runc-v2".into(), user: "root".into(), status: "S".into(), mem: 10 * MB, ..Default::default() },
            Proc { pid: 60, ppid: 50, name: "sleep".into(), user: "root".into(), status: "S".into(), mem: MB, container: Some(cid.into()), start_time: 1000, ..Default::default() },
            // `docker exec` session: same shim parent, started later. A job, not the init.
            Proc { pid: 62, ppid: 50, name: "bash".into(), cmd: "bash -c ./write-test.sh".into(), user: "root".into(), status: "R".into(), mem: MB, disk_write_bps: 700 * MB, container: Some(cid.into()), start_time: 5000, ..Default::default() },
            Proc { pid: 61, ppid: 60, name: "python3".into(), user: "root".into(), status: "R".into(), cpu: 390.0, mem: 6 * GB, container: Some(cid.into()), ..Default::default() },
        ];
        for i in 0..25 {
            procs.push(Proc { pid: 100 + i, ppid: 60, name: "yes".into(), status: "Z".into(), container: Some(cid.into()), ..Default::default() });
        }
        let mut s = Snapshot { ts: NOW, procs, ..Default::default() };
        s.system = System { os: "Debian GNU/Linux 12".into(), cores: 4, mem_total: 8 * GB, mem_used: 7900 * MB, mem_pressure: "unknown".into(), load: [9.0, 9.0, 9.0], ..Default::default() };
        s.containers = vec![Container { id: cid.into(), name: "worker".into(), runtime: "docker".into(), mem: 6 * GB, ..Default::default() }];
        let f = diagnose(&s, None);
        assert!(harmful_targets(&f).is_empty(), "{:?}", harmful_targets(&f));
        let m = f.iter().find(|x| x.title.starts_with("Memory pressure")).unwrap();
        assert!(m.detail.contains("container worker 6.0G (27 processes)") || m.detail.contains("container worker 6.0G"), "{}", m.detail);
        assert!(m.detail.contains("`docker stop worker`"), "{}", m.detail);
        assert_eq!(m.pids[0], 60, "lead is the container's init");
        let cpu = f.iter().find(|x| x.pids == vec![61]).unwrap();
        assert!(cpu.detail.contains("docker stop worker"), "{}", cpu.detail);
        let w = f.iter().find(|x| x.pids == vec![62]).expect("exec'd writer");
        assert_eq!(w.action, None, "root on the host, not from a user session");
        assert!(w.detail.contains("`docker exec` shell") && !w.detail.contains("pid 1 of"), "{}", w.detail);
        let cx = Ctx::new(&s, Os::Linux);
        assert_eq!(cx.hub(s.proc(62).unwrap()), None);
        assert_eq!(cx.hub(s.proc(60).unwrap()), Some(Hub::ContainerInit { id: cid.into() }));
        let e = explain(&s, 60, None);
        assert!(e.chain.iter().any(|c| c.contains("pid 1 (the entrypoint) of container worker")), "{:?}", e.chain);
        assert!(e.suggestions.iter().any(|x| x.contains("docker restart worker")), "{:?}", e.suggestions);
        assert!(!says_stop(&e, 60), "{:?}", e.suggestions);
        let e = explain(&s, 40, None);
        assert!(!says_stop(&e, 40), "{:?}", e.suggestions);
        assert!(e.suggestions.iter().any(|x| x.contains("docker stop worker")), "{:?}", e.suggestions);
    }

    /// Every hub kind, hot in every dimension at once: no finding may offer to pause or kill
    /// any of them, and `why` must not either.
    #[test]
    fn no_hub_is_ever_paused_or_killed() {
        let mut ps = mac_base();
        brave(&mut ps);
        let heat = |p: &mut Proc| {
            p.cpu = 400.0;
            p.mem = 3 * GB;
            p.power_mw = 9000.0;
            p.disk_write_bps = 300 * MB;
        };
        let mut hubs = vec![
            mp(13792, 1, "OrbStack Helper", "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper", 0.0, 0),
            mp(44401, 1, "Slack", "/Applications/Slack.app/Contents/MacOS/Slack", 0.0, 0),
            mp(0, 0, "kernel_task", "", 0.0, 0),
            mp(392, 1, "WindowServer", "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer", 0.0, 0),
            mp(700, 1, "tmux", "/opt/homebrew/bin/tmux", 0.0, 0),
            mp(701, 700, "-zsh", "/bin/zsh", 0.0, 0),
            mp(800, 102, "claude", "/Users/me/.local/bin/claude", 0.0, 0),
            mp(801, 1, "qemu-system-x86_64", "/opt/homebrew/bin/qemu-system-x86_64", 0.0, 0),
            mp(802, 1, "sshd", "/usr/sbin/sshd", 0.0, 0),
        ];
        hubs.push(mp(45000, 44401, "Slack Helper (Renderer)", "/Applications/Slack.app/Contents/Frameworks/Slack Helper (Renderer).app/Contents/MacOS/Slack Helper (Renderer)", 0.0, 0));
        for h in &mut hubs {
            heat(h);
        }
        ps.extend(hubs);
        for p in ps.iter_mut().filter(|p| [1686, 52510, 1, 100, 102].contains(&p.pid)) {
            heat(p);
        }
        // Zombies and a swarm under hubs, a stopped hub, an orphaned port owned by a hub.
        for i in 0..40 {
            ps.push(Proc { status: "Z".into(), ..mp(6000 + i, 701, "defunct", "", 0.0, 0) });
            ps.push(mp(7000 + i, 800, "node", "/usr/local/bin/node", 1.0, 10 * MB));
        }
        ps.iter_mut().find(|p| p.pid == 44401).unwrap().status = "T".into();
        let mut s = mac(ps);
        s.system.mem_pressure = "critical".into();
        s.system.thermal = "critical".into();
        s.system.load = [80.0, 80.0, 80.0];
        s.system.on_battery = Some(true);
        s.system.battery_pct = Some(5.0);
        s.system.power_mw = 90_000.0;
        s.system.disk_write_bps = 900 * MB;
        s.ports.push(Port { proto: Proto::Tcp, addr: "*".into(), port: 3000, pid: 13792, process: "OrbStack Helper".into(), state: "LISTEN".into(), orphan: true, note: String::new() });
        s.containers = vec![ct("web", "orbstack", GB)];
        let hub_pids: Vec<u32> = s.procs.iter().filter(|p| Ctx::new(&s, Os::Mac).block(p).is_some()).map(|p| p.pid).collect();
        for want in [13792, 44401, 0, 392, 700, 701, 800, 801, 802, 1686, 52510, 45000, 1, 100, 102] {
            assert!(hub_pids.contains(&want), "{want} should be blocked");
        }
        let f = diagnose(&s, None);
        assert!(f.len() >= 8, "{f:?}");
        for (pid, a) in harmful_targets(&f) {
            assert!(!hub_pids.contains(&pid), "finding action `{a}` targets protected pid {pid}");
            // Renice and resume are the only actions allowed on blocked processes.
        }
        for f in &f {
            if let Some((k, pid, _)) = f.action.as_deref().and_then(parse_action)
                && hub_pids.contains(&pid)
            {
                assert!(matches!(k, ActionKind::Resume | ActionKind::Renice), "{f:?}");
                assert!(k != ActionKind::Renice || s.proc(pid).is_some_and(|p| !p.name.contains("OrbStack")), "{f:?}");
            }
        }
        for pid in hub_pids {
            let e = explain(&s, pid, None);
            assert!(!says_stop(&e, pid), "why {pid}: {:?}", e.suggestions);
        }
    }
}
