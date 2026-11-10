//! Server mode: services as the primary unit, kernel health, an event log, incident
//! explanation, Prometheus export, and fleets of any size. OWNER: architect (this file is the
//! CONTRACT; implementers change it only by ADDING `#[serde(default)]` fields or new items,
//! never by renaming or removing anything here).
//!
//! # Generality rule (applies to every file under this module and to fleet code)
//!
//! Nothing here may assume one environment: no hardcoded fleet sizes, host names, distros,
//! init systems, container runtimes, cloud vendors, network topologies (jump hosts, proxies) or
//! org conventions. Every limit is a field of [`ServerCfg`] / [`FleetCfg`] with a default that is
//! justified generically in its doc comment. Every data source is optional: a missing file,
//! command, permission or kernel feature yields `None`/empty plus, where it matters, a
//! "needs root" / "not available on this kernel" note, never an error or a panic.
//!
//! # Ownership
//!
//! | file                         | agent            |
//! |------------------------------|------------------|
//! | `src/server/mod.rs`          | architect (contract; additive edits only) |
//! | `src/server/services.rs`     | services         |
//! | `src/server/kernel.rs`       | kernel           |
//! | `src/server/incident.rs`     | doctor-incident  |
//! | `src/server/rules.rs`        | doctor-incident  |
//! | `src/server/export.rs`       | recorder-export  |
//! | `src/history.rs` (additions) | recorder-export  |
//! | `src/fleet.rs`, `src/fleet/*`, `src/config.rs`, `scripts/build-static.sh` | fleet |
//! | `src/tui/*`                  | tui              |
//!
//! Shared files (`README.md`, `src/main.rs`, `src/model.rs`, `src/mcp.rs`, `Cargo.toml`): small
//! targeted edits inside a section marked with the owning agent's name only.
//!
//! # Data flow
//!
//! ```text
//! collect::Collector::sample() -> Snapshot (procs, system, ports)       [unchanged]
//!          |
//! ServerSampler::fill(&mut snap)  -> snap.units, snap.kernel, snap.events (delta since last fill)
//!          |                              (services::Services + kernel::KernelSampler)
//!          +--> History::record(&snap) + History::record_server(&snap)   (recorder, bounded)
//!          +--> export::LatestSnapshot (Prometheus /metrics)
//!          +--> rules::diagnose_server(&snap, hist) -> Vec<Finding>       (doctor)
//!          +--> incident::what_happened(hist, &snap, at, window) -> Incident
//! fleet: inventory -> fanout (ssh `fat snapshot --json --fast`) -> FleetHost rows -> FleetSummary
//! ```
//!
//! # Recorder contract (implemented in `src/history.rs` by recorder-export)
//!
//! New tables (created by the existing schema migration path; old databases upgrade in place):
//! `events` (ts, kind, severity, subject, unit, pid, value, detail, extra-json; indexed by ts and
//! kind), `units` (one row per unit per sample: ts, unit-id, state, sub_state, restarts, cpu,
//! mem, mem_limit, pids, io r/w, throttled %, psi cpu/mem/io some+full, oom_kills; unit names are
//! interned in a `unit_ids` table), `kernel` (one row per sample: scalar fields of [`Kernel`];
//! per-disk rows in `disks`). Cardinality: every unit (capped by `ServerCfg::max_units`), top
//! `ServerCfg::record_top_procs` processes (not every pid), every disk. Disk usage is bounded by
//! `Config::history_days` pruning; the README documents measured MB/day.
//!
//! ```ignore
//! impl History {
//!     /// Persist units, kernel and events of a snapshot filled by ServerSampler. Cheap no-op when
//!     /// snap.units/kernel/events are all empty (desktop profile). Events are de-duplicated on
//!     /// (ts, kind, subject).
//!     pub fn record_server(&mut self, snap: &Snapshot) -> anyhow::Result<()>;
//!     /// Append events directly (kmsg backlog import on daemon start). Returns rows inserted.
//!     pub fn record_events(&mut self, events: &[Event]) -> anyhow::Result<usize>;
//!     /// Events with from <= ts <= to, oldest first; `kinds` empty = all kinds; at most `limit`.
//!     pub fn events(&self, from: Ts, to: Ts, kinds: &[EventKind], limit: usize) -> anyhow::Result<Vec<Event>>;
//!     /// One unit over time, oldest first.
//!     pub fn unit_series(&self, name: &str, from: Ts, to: Ts) -> anyhow::Result<Vec<UnitPoint>>;
//!     /// All units as recorded at the sample nearest to `ts` (within one interval), else empty.
//!     pub fn units_at(&self, ts: Ts) -> anyhow::Result<Vec<Unit>>;
//!     /// Kernel state over time, oldest first, downsampled to at most `max_points`.
//!     pub fn kernel_series(&self, from: Ts, to: Ts, max_points: usize) -> anyhow::Result<Vec<(Ts, Kernel)>>;
//!     /// The newest recorded sample as a full Snapshot (system, top procs, units, kernel, events
//!     /// of the last interval) if it is younger than `max_age_ms`; used by `fat snapshot --fast`
//!     /// so a fleet poll costs one SQLite read instead of a live sample. meta.source = "recorder".
//!     pub fn latest(&self, max_age_ms: i64) -> anyhow::Result<Option<Snapshot>>;
//!     /// Count of events of `kind` since `from` (header gauges: OOM kills in 24h).
//!     pub fn event_count(&self, kind: EventKind, from: Ts) -> anyhow::Result<u64>;
//! }
//! /// `fat record` loop with server options (profile, Prometheus export). `record_forever(cfg)`
//! /// stays and calls this with RecordOpts::default().
//! pub fn record_with(cfg: &Config, opts: &crate::server::export::RecordOpts) -> anyhow::Result<()>;
//! ```
//!
//! # CLI (each owner adds its own variants in a marked section of `src/main.rs` and its name to
//! a `("Server", ...)` entry of `HELP_GROUPS`)
//!
//! | command | owner |
//! |---|---|
//! | `fat services [--failed] [--kind systemd\|container\|k8s-pod\|cgroup] [--json]` | services |
//! | `fat kernel [--json]` | kernel |
//! | `fat events [--since 2h] [--kind K]... [--json]` | doctor-incident |
//! | `fat what-happened [--at TIME] [--window 15m] [--json]` | doctor-incident |
//! | `fat record [--server] [--export prometheus [--listen ADDR]]` | recorder-export |
//! | `fat snapshot --fast` (flag on the existing command) | fleet |
//! | `fat fleet [--group G]... [--tag T]... [--host GLOB]... [--json] [summary\|doctor\|events\|what-happened\|exec-readonly ...]` | fleet |
//!
//! # MCP tools (all read-only; `destructive: false`; each owner adds its own in `src/mcp.rs`)
//!
//! `services` (services), `kernel` (kernel), `events`, `what_happened` (doctor-incident),
//! `fleet_summary`, `fleet_doctor`, `host_snapshot{host}`, `host_what_happened{host, at?, window?}`
//! (fleet). No fleet tool can signal anything.

pub mod export;
pub mod incident;
pub mod kernel;
pub mod rules;
pub mod services;

use crate::model::{Finding, Proc, Snapshot, Ts};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------------------------

/// Which defaults and views fat uses. Desktop keeps today's behaviour exactly; Server adds
/// units/kernel/events sampling, the Services tab first, and recorder server tables.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    #[default]
    Desktop,
    Server,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Desktop => "desktop",
            Profile::Server => "server",
        }
    }

    /// Resolve the profile: `FAT_PROFILE` env (desktop|server) beats `cfg.profile`
    /// ("auto"|"desktop"|"server"); "auto" picks Server on Linux when there is no graphical
    /// session and no battery, Desktop otherwise (always Desktop on macOS). A heuristic only:
    /// operators who disagree set `profile` in the config.
    pub fn detect(cfg: &ServerCfg) -> Profile {
        let env = std::env::var("FAT_PROFILE").ok();
        Self::resolve(env.as_deref().unwrap_or(&cfg.profile), Self::auto_is_server())
    }

    fn resolve(choice: &str, auto_server: bool) -> Profile {
        match choice.trim().to_ascii_lowercase().as_str() {
            "server" => Profile::Server,
            "desktop" => Profile::Desktop,
            _ if auto_server => Profile::Server,
            _ => Profile::Desktop,
        }
    }

    fn auto_is_server() -> bool {
        if !cfg!(target_os = "linux") {
            return false;
        }
        let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        if set("DISPLAY") || set("WAYLAND_DISPLAY") {
            return false;
        }
        let has_battery = std::fs::read_dir("/sys/class/power_supply").is_ok_and(|d| {
            d.flatten().any(|e| std::fs::read_to_string(e.path().join("type")).is_ok_and(|t| t.trim() == "Battery"))
        });
        !has_battery
    }
}

// ---------------------------------------------------------------------------------------------
// Config (embedded in crate::config::Config as `server` and `fleet`)
// ---------------------------------------------------------------------------------------------

/// `[server]` table. Defaults target the daemon budget (< 1% of a core, < 60 MB RSS) on any host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ServerCfg {
    /// "auto" | "desktop" | "server". See [`Profile::detect`].
    pub profile: String,
    /// Processes recorded per sample in server mode (by cpu, mem and io, union). Bounds recorder
    /// cardinality independent of how many pids a host runs. 50 covers every process that
    /// matters for blame while keeping rows/sample constant.
    pub record_top_procs: usize,
    /// Upper bound on units sampled/recorded/exported per host. Hosts that churn thousands of
    /// transient units (e.g. per-connection scopes) must not blow up memory, disk or label
    /// cardinality; past this bound, inactive units are dropped first and a note is emitted.
    pub max_units: usize,
    /// Minimum seconds between full unit-property refreshes (state, restarts, result); cheap
    /// cgroup counters are still read every sample. Unit state changes are rare compared to the
    /// sample interval, so 10 s keeps systemctl/runtime CLI calls off the hot path.
    pub unit_refresh_s: u64,
    /// Restarts within `flap_window_s` at or above which a unit is "flapping".
    pub flap_restarts: u32,
    pub flap_window_s: u64,
    /// Read the kernel log (/dev/kmsg) for OOM kills, hung tasks, I/O and fs errors. Needs root
    /// or kernel.dmesg_restrict=0; silently degrades otherwise.
    pub kmsg: bool,
    /// Uninterruptible (D-state) processes are reported once blocked at least this long.
    pub dstate_min_s: u64,
    /// Disk await (ms) above which a `disk_latency_spike` event fires. Rotational and
    /// network-backed devices may need a higher value; it is per-host config, not a constant.
    pub disk_await_warn_ms: f32,
    /// Fraction (0..1) of a limit (fds, conntrack, ephemeral ports, memory.max) that is "near
    /// exhaustion".
    pub exhaustion_warn: f32,
    /// A burst of at least this many new processes in one unit within one interval is recorded
    /// as a `deploy_burst` event.
    pub burst_procs: u32,
    /// PSI `full` avg10 (% of the last 10 s in which every non-idle task was stalled on cpu,
    /// memory or io) at or above which a `pressure_spike` event fires. Relative to wall time,
    /// so it means the same on any core count; 10% = a tenth of all work time lost. (kernel)
    pub pressure_full_warn: f32,
    /// Prometheus exposition: listen address when `fat record --export prometheus` is given
    /// without --listen. Loopback by default: exposing metrics beyond the host is an explicit
    /// operator decision.
    pub export_listen: String,
    /// Serve /metrics from `fat record` without the CLI flag.
    pub export_enabled: bool,
    // --- recorder-export additions (additive) ---
    /// Sample interval (ms) of `fat record` in the server profile (the desktop profile keeps
    /// `interval_ms`). Unit and kernel state changes are rare next to it, rates are averages
    /// over it, and it keeps the daemon well inside its CPU budget on hosts with many
    /// processes; lower it for finer incident timing at proportional CPU and disk cost.
    pub record_interval_ms: u64,
    /// Events persisted per sample at most; the rest are summarised in one `other` event.
    /// Bounds recorder disk when a source floods (kernel log storms, crash loops).
    pub max_events_per_sample: usize,
    /// "Level" events (throttle, pressure, exhaustion, latency/cpu/mem spikes, fs fill, clock)
    /// for the same subject are recorded at most once per this many seconds while the
    /// condition persists; transitions (unit failed/restart, OOM kills) are never suppressed.
    pub spike_cooldown_s: u64,
    /// A unit's CPU rising this many percent of host capacity (all cores) above its trailing
    /// median, and by at least half a core, is a `proc_spike`. Relative to the host so it means
    /// the same on any core count.
    pub spike_cpu_pct: f32,
    /// A unit's memory growing by this many percent of host RAM within one minute is a
    /// `proc_spike` (memory). Relative to the host for the same reason.
    pub spike_mem_pct: f32,
    /// `fs_fill` fires when a volume's projected time to full drops below this many seconds
    /// (crit below a sixth of it) or its use crosses 95%. Six hours leaves time to react on
    /// any volume size.
    pub fs_fill_eta_s: u64,
    /// Run the background directory scanner in the server recorder (volumes are always
    /// sampled). Off by default: a full-filesystem walk costs I/O and CPU the daemon budget
    /// does not have on large disks; `fat fs` still scans on demand.
    pub fs_scan: bool,
    // --- services additions (additive) ---
    /// A unit throttled by its cpu.max in at least this percent of enforcement periods over
    /// one sample raises a `throttle` event. A quarter of periods means its CPU limit, not its
    /// own demand, is visibly shaping its latency on any core count.
    pub throttle_warn_pct: f32,
    /// Seconds between full systemd property reads of every loaded, non-inactive unit. Between
    /// them only units whose state, sub-state or main pid changed are re-read (a restart of a
    /// running service always changes one of those), so the cost follows change, not unit
    /// count. The full pass is a safety net for the rare change none of those reveal (a unit
    /// without a main process restarting between two list calls); reading a unit's properties
    /// costs systemd and systemctl about 1 ms, so every 5 minutes keeps it negligible on hosts
    /// with thousands of units.
    pub unit_full_refresh_s: u64,
    /// One OOM kill is seen by up to three sources: the kernel log, the unit's cgroup
    /// memory.events and systemd's Result=oom-kill. A cgroup or systemd OOM event matching a
    /// kernel-log kill in the same cgroup within this many seconds is the same kill and is not
    /// recorded again. Long enough for systemd to notice the death and for slow property
    /// refreshes (`unit_refresh_s`), short next to how often a unit can really be re-killed.
    pub oom_dedup_s: u64,
    /// Thread stat files read per sample, at most, to find blocked worker threads (only while
    /// /proc/stat counts more blocked tasks than the main-thread scan found). Bounds the cost
    /// on hosts with very many threads; 20000 small procfs reads take tens of milliseconds.
    pub dstate_max_thread_reads: usize,
}

impl Default for ServerCfg {
    fn default() -> Self {
        Self {
            profile: "auto".into(),
            record_top_procs: 50,
            max_units: 2000,
            unit_refresh_s: 10,
            flap_restarts: 3,
            flap_window_s: 600,
            kmsg: true,
            dstate_min_s: 5,
            disk_await_warn_ms: 100.0,
            exhaustion_warn: 0.85,
            burst_procs: 20,
            pressure_full_warn: 10.0,
            export_listen: "127.0.0.1:9877".into(),
            export_enabled: false,
            record_interval_ms: 5000,
            max_events_per_sample: 100,
            spike_cooldown_s: 300,
            spike_cpu_pct: 25.0,
            spike_mem_pct: 10.0,
            fs_fill_eta_s: 6 * 3600,
            fs_scan: false,
            throttle_warn_pct: 25.0,
            unit_full_refresh_s: 300,
            oom_dedup_s: 120,
            dstate_max_thread_reads: 20_000,
        }
    }
}

/// `[fleet]` table. Fleet size is never assumed: concurrency and timeouts bound the in-flight
/// cost of one poll whatever the host count (`control_master`, off by default, is the one
/// option whose resident cost grows with the hosts polled).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FleetCfg {
    /// Parallel ssh sessions. 64 keeps a laptop's fd/process table and an sshd's MaxStartups
    /// comfortable while polling large inventories in O(hosts / 64 * latency).
    pub concurrency: usize,
    /// ssh `ConnectTimeout` seconds.
    pub connect_timeout_s: u64,
    /// Hard wall-clock limit per remote command (connect + run + transfer), seconds.
    pub command_timeout_s: u64,
    /// Add `ControlMaster=auto`, `ControlPath` (in fat's runtime dir) and `ControlPersist` so
    /// repeated polls reuse connections. Off by default: plain ssh, so connection sharing is
    /// whatever the operator's own ssh_config sets (fat never adds ProxyJump or similar). When
    /// on, these options override any ControlMaster/ControlPath/ControlPersist in ssh_config, and
    /// every host polled keeps one ssh master process here (and a session on the host) for
    /// `control_persist` after its last use: the resident cost grows with the number of hosts
    /// polled, not with `concurrency`. Enable it for inventories well inside your per-user
    /// process limit.
    pub control_master: bool,
    /// ssh `ControlPersist` value.
    pub control_persist: String,
    /// Extra `-o` options passed verbatim (operator-chosen), placed before fat's own so they win
    /// (ssh keeps the first value it sees for an option).
    pub ssh_options: Vec<String>,
    /// Optional inventory file: one host per line, `name [ssh=DEST] [fat=PATH] [groups=a,b]
    /// [tags=x,y]`, `#` comments.
    pub hosts_file: Option<String>,
    /// Also offer non-wildcard `Host` entries from ~/.ssh/config (filtered by `ssh_config_filter`
    /// globs when non-empty). Off by default: not every ssh alias is a fat host.
    pub ssh_config_hosts: bool,
    pub ssh_config_filter: Vec<String>,
    /// Named groups -> host globs (in addition to per-host `groups`).
    pub groups: BTreeMap<String, Vec<String>>,
    /// Bytes of remote stdout accepted per host before the reply is rejected.
    pub max_output_bytes: usize,
    /// `fat snapshot --fast` accepts a recorder sample up to this old before sampling live.
    pub fast_max_age_ms: i64,
    /// Remote fat invocation when a host sets no `fat_path`.
    pub default_fat_path: Option<String>,
    // --- tui additions (additive) ---
    /// Seconds between Fleet-tab polls, counted from the end of the previous poll and only
    /// while the tab is on screen (`r` polls at once). A poll never overlaps the previous one,
    /// so the cost stays bounded by `concurrency` whatever the inventory size; 30 s keeps a
    /// screen fresh without turning an open terminal into a constant load on every host.
    pub tui_refresh_s: u64,
    // --- fleet additions (additive) ---
    /// ssh `-C`: snapshot JSON compresses ~5-10x, which matters more than the CPU it costs on
    /// any link slower than a LAN. Turn off on fast local networks if CPU matters more.
    pub compress: bool,
    /// Seconds a fleet poll result is reused by `fleet_*` MCP tools before polling again, so an
    /// agent calling them in a loop does not re-poll every host on every call.
    pub cache_ttl_s: u64,
    /// Host names listed per aggregated finding (the count stays exact). Keeps summaries
    /// readable and MCP replies small whatever the fleet size.
    pub max_hosts_per_finding: usize,
    /// A group needs at least this many reachable hosts before outliers are computed: medians
    /// of tiny groups are noise.
    pub outlier_min_group: usize,
    /// Robust z-score (median absolute deviation, Iglewicz-Hoaglin) above which a host is an
    /// outlier in its group. 3.5 is the textbook threshold.
    pub outlier_z: f32,
    /// ...and it must also differ from the group median by at least this many percentage
    /// points, so a near-uniform group (MAD ~ 0) does not flag 1-point differences.
    pub outlier_min_delta: f32,
    /// A host whose poll timed out is not polled again by fleet summaries (CLI, Fleet tab, MCP)
    /// for this many seconds; it is listed as `timeout` meanwhile. The remote fat is told to
    /// end itself after `command_timeout_s`, but one blocked in the kernel (hung storage) cannot,
    /// so re-polling on every refresh would pile copies onto the host that is already in trouble.
    /// Five minutes spans many refreshes yet lets a recovered host back soon; 0 disables.
    pub timeout_backoff_s: u64,
}

impl Default for FleetCfg {
    fn default() -> Self {
        Self {
            concurrency: 64,
            connect_timeout_s: 5,
            command_timeout_s: 20,
            control_master: false,
            control_persist: "60s".into(),
            ssh_options: vec![],
            hosts_file: None,
            ssh_config_hosts: false,
            ssh_config_filter: vec![],
            groups: BTreeMap::new(),
            max_output_bytes: 8 * 1024 * 1024,
            fast_max_age_ms: 10_000,
            default_fat_path: None,
            tui_refresh_s: 30,
            compress: true,
            cache_ttl_s: 15,
            max_hosts_per_finding: 10,
            outlier_min_group: 5,
            outlier_z: 3.5,
            outlier_min_delta: 20.0,
            timeout_backoff_s: 300,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Units (services)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnitKind {
    /// systemd service/scope/socket/timer/mount... (name keeps its suffix: "nginx.service").
    #[default]
    #[serde(rename = "systemd")]
    Systemd,
    /// A container from any runtime (docker, podman, containerd, cri-o...); runtime in
    /// `Unit.container.runtime`.
    #[serde(rename = "container")]
    Container,
    /// A Kubernetes pod (sum of its containers).
    #[serde(rename = "k8s-pod")]
    Pod,
    /// Any other cgroup with processes (non-systemd inits, manual cgroups, user slices).
    #[serde(rename = "cgroup")]
    Cgroup,
}

impl UnitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            UnitKind::Systemd => "systemd",
            UnitKind::Container => "container",
            UnitKind::Pod => "k8s-pod",
            UnitKind::Cgroup => "cgroup",
        }
    }
}

/// Pressure stall information, avg10 percentages, for the system or one cgroup.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Pressure {
    pub cpu_some: f32,
    pub cpu_full: f32,
    pub mem_some: f32,
    pub mem_full: f32,
    pub io_some: f32,
    pub io_full: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ContainerMeta {
    /// 12-hex short id (joins `Proc.container`).
    pub id: String,
    pub name: String,
    pub image: String,
    /// "docker" | "podman" | "containerd" | "cri-o" | ... as detected.
    pub runtime: String,
    /// Pod name / namespace / uid when orchestrated by Kubernetes.
    pub pod: Option<String>,
    pub namespace: Option<String>,
    pub pod_uid: Option<String>,
    /// Container health status if the runtime reports one ("healthy" | "unhealthy" | "starting").
    pub health: Option<String>,
}

/// A service: the operator's unit of thought. Resource numbers are cgroup totals (all processes).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Unit {
    /// Stable identity within its kind: "nginx.service", container name, "namespace/pod",
    /// or the cgroup path for `Cgroup`.
    pub name: String,
    pub kind: UnitKind,
    /// Normalised: "active" | "activating" | "deactivating" | "reloading" | "inactive" |
    /// "failed" | "unknown". Containers: running->active, restarting->activating,
    /// exited non-zero/dead->failed, exited 0/created->inactive, paused->active(sub "paused").
    pub state: String,
    /// Runtime-specific detail (systemd SubState, container status text).
    pub sub_state: String,
    pub description: String,
    /// systemd Result ("success", "exit-code", "signal", "core-dump", "oom-kill", "timeout",
    /// "start-limit-hit"...) or container exit reason; empty if unknown.
    pub result: String,
    pub exit_code: Option<i32>,
    /// Lifetime restart count (systemd NRestarts, container RestartCount).
    pub restarts: u32,
    /// Restarts observed within `ServerCfg::flap_window_s`.
    pub recent_restarts: u32,
    pub flapping: bool,
    /// When the unit entered its current state (epoch ms).
    pub since: Option<Ts>,
    /// cgroup v2 path relative to the cgroup root (joins `Proc.cgroup`).
    pub cgroup: String,
    pub main_pid: Option<u32>,
    pub pids: u32,
    /// CPU percent, 100 = one core.
    pub cpu: f32,
    /// memory.current bytes.
    pub mem: u64,
    /// memory.max (None = unlimited / unknown).
    pub mem_limit: Option<u64>,
    /// memory.peak if the kernel exposes it.
    pub mem_peak: Option<u64>,
    pub io_read_bps: u64,
    pub io_write_bps: u64,
    /// Share of the last interval this cgroup was throttled by cpu.max (0..100).
    pub cpu_throttled_pct: f32,
    /// cpu.max quota in cores, if set.
    pub cpu_quota: Option<f32>,
    pub psi: Option<Pressure>,
    /// memory.events oom_kill counter (cumulative).
    pub oom_kills: u64,
    pub container: Option<ContainerMeta>,
    /// Why some fields are empty ("needs root", "cgroup v1: no psi", ...).
    pub notes: Vec<String>,
}

impl Unit {
    pub fn is_failed(&self) -> bool {
        self.state == "failed"
    }
}

/// One recorded sample of a unit (recorder `unit_series`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UnitPoint {
    pub ts: Ts,
    pub state: String,
    pub restarts: u32,
    pub cpu: f32,
    pub mem: u64,
    pub mem_limit: Option<u64>,
    pub pids: u32,
    pub io_read_bps: u64,
    pub io_write_bps: u64,
    pub cpu_throttled_pct: f32,
    pub psi: Option<Pressure>,
    pub oom_kills: u64,
}

/// What a cgroup path belongs to, derived from the path alone (no I/O).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRef {
    pub kind: UnitKind,
    /// systemd unit name, 12-hex container id, or pod uid; for `Cgroup` the path itself.
    pub key: String,
}

/// Map a cgroup v2 path ("/system.slice/nginx.service", ".../docker-<64hex>.scope",
/// ".../kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope") to its owning unit.
/// Innermost container wins over pod; pod wins over systemd slice. Returns None for "/" and
/// bare slices with no service below them.
pub fn unit_of_cgroup(path: &str) -> Option<UnitRef> {
    let path = path.trim();
    if path.is_empty() || path == "/" {
        return None;
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for seg in segs.iter().rev() {
        if let Some(id) = container_id_of(seg) {
            return Some(UnitRef { kind: UnitKind::Container, key: id });
        }
    }
    for seg in segs.iter().rev() {
        if let Some(uid) = pod_uid_of(seg) {
            return Some(UnitRef { kind: UnitKind::Pod, key: uid });
        }
    }
    const SUFFIXES: [&str; 6] = [".service", ".scope", ".socket", ".mount", ".swap", ".timer"];
    for seg in segs.iter().rev() {
        if SUFFIXES.iter().any(|s| seg.ends_with(s)) {
            return Some(UnitRef { kind: UnitKind::Systemd, key: seg.to_string() });
        }
    }
    if segs.last().is_some_and(|s| s.ends_with(".slice")) {
        return None;
    }
    Some(UnitRef { kind: UnitKind::Cgroup, key: format!("/{}", segs.join("/")) })
}

/// 12-hex id from "docker-<hex>.scope", "libpod-<hex>.scope", "cri-containerd-<hex>.scope",
/// "crio-<hex>.scope", or a bare 64-hex segment (cgroupfs driver).
fn container_id_of(seg: &str) -> Option<String> {
    let s = seg.strip_suffix(".scope").unwrap_or(seg);
    let hex = match s.rfind('-') {
        Some(i) => &s[i + 1..],
        None => s,
    };
    let is_hex = hex.len() >= 32 && hex.bytes().all(|b| b.is_ascii_hexdigit());
    // "-conmon-" scopes belong to the runtime's monitor, not the container.
    (is_hex && !s.contains("conmon")).then(|| hex[..12].to_ascii_lowercase())
}

/// Pod uid from "kubepods-burstable-pod<uid>.slice" or "pod<uid>" (cgroupfs driver).
fn pod_uid_of(seg: &str) -> Option<String> {
    let s = seg.strip_suffix(".slice").unwrap_or(seg);
    let i = s.rfind("pod")?;
    if i > 0 && !s[..i].ends_with('-') {
        return None;
    }
    let uid = &s[i + 3..];
    (uid.len() >= 32 && uid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'_' || b == b'-')).then(|| uid.replace('_', "-"))
}

// ---------------------------------------------------------------------------------------------
// Kernel
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DiskStat {
    /// Kernel device name ("sda", "nvme0n1", "dm-0", "md0").
    pub name: String,
    /// Busy time share of the interval (0..100). Meaningless for some virtual/striped devices;
    /// rules weigh await and queue depth more.
    pub util_pct: f32,
    pub r_await_ms: f32,
    pub w_await_ms: f32,
    /// Average in-flight requests (aqu-sz).
    pub queue_depth: f32,
    pub r_iops: f32,
    pub w_iops: f32,
    pub r_bps: u64,
    pub w_bps: u64,
    /// Cumulative I/O errors if the driver exposes them.
    pub io_errors: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NumaNode {
    pub node: u32,
    pub mem_total: u64,
    pub mem_free: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DStateProc {
    pub pid: u32,
    pub name: String,
    /// Kernel function it sleeps in (/proc/pid/wchan), e.g. "io_schedule", "nfs_wait_bit_killable".
    pub wchan: String,
    /// Seconds continuously observed in D state (lower bound).
    pub seconds: u64,
    /// Owning unit name, if known.
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FsErrorStat {
    pub device: String,
    pub mount: Option<String>,
    /// Cumulative error count (e.g. ext4 errors_count); 0 if only "remounted ro" is known.
    pub errors: u64,
    pub read_only: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MdArray {
    pub name: String,
    pub level: String,
    /// "clean" | "active" | "degraded" | "recovering" | "resyncing" | ...
    pub state: String,
    pub degraded: bool,
    /// Rebuild/resync progress 0..100.
    pub sync_pct: Option<f32>,
}

/// Host-level kernel health. Every Option is None when the source is missing or unreadable.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Kernel {
    /// CPU time shares over the last interval, 0..100 of all cores.
    pub steal_pct: f32,
    pub iowait_pct: f32,
    pub irq_pct: f32,
    pub softirq_pct: f32,
    /// /proc/stat procs_running / procs_blocked.
    pub procs_running: u32,
    pub procs_blocked: u32,
    /// System pressure incl. `full` lines (System.psi keeps the desktop subset).
    pub pressure: Option<Pressure>,
    /// MemAvailable bytes.
    pub mem_available: u64,
    /// Swap pages in/out per second.
    pub swap_in_ps: f32,
    pub swap_out_ps: f32,
    /// Cumulative /proc/vmstat oom_kill.
    pub oom_kills_total: u64,
    pub numa: Vec<NumaNode>,
    pub disks: Vec<DiskStat>,
    pub fd_used: Option<u64>,
    pub fd_max: Option<u64>,
    pub conntrack_used: Option<u64>,
    pub conntrack_max: Option<u64>,
    /// Local ports in use from the ephemeral range (all sockets, all states).
    pub ephemeral_used: Option<u64>,
    pub ephemeral_range: Option<(u16, u16)>,
    pub tcp_retrans_ps: f32,
    pub listen_overflows_ps: f32,
    pub listen_drops_ps: f32,
    /// Processes in D state at least `ServerCfg::dstate_min_s`.
    pub d_state: Vec<DStateProc>,
    /// Mounts that were read-write earlier in this process's life and are now read-only, or
    /// that the kernel log says were remounted read-only.
    pub ro_remounts: Vec<String>,
    pub fs_errors: Vec<FsErrorStat>,
    /// /proc/sys/kernel/tainted bitmask and its decoded letters.
    pub taint: u64,
    pub taint_flags: String,
    /// Clock synchronised per adjtimex (STA_UNSYNC clear); None when unknown.
    pub ntp_synced: Option<bool>,
    pub mdraid: Vec<MdArray>,
    /// Missing sources and why ("needs root: /dev/kmsg", "no conntrack module").
    pub notes: Vec<String>,
}

/// Parsed kernel OOM-kill report (from kmsg "Out of memory: Killed process ..." and the
/// "oom-kill:constraint=...,task_memcg=..." line).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct OomInfo {
    pub victim_pid: u32,
    pub victim_name: String,
    /// "CONSTRAINT_NONE" (host-wide) | "CONSTRAINT_MEMCG" (a cgroup's memory.max) | ...
    pub constraint: String,
    /// cgroup whose limit was hit (task_memcg / oom_memcg).
    pub memcg: String,
    /// cgroup of the killed task ("task_memcg=", or "Task in <cg> killed ..." before 4.19).
    pub task_memcg: String,
    pub anon_rss_kb: u64,
    pub file_rss_kb: u64,
    pub shmem_rss_kb: u64,
    pub oom_score_adj: i32,
    /// Process that triggered the OOM ("invoked oom-killer"), if logged.
    pub invoker: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    OomKill,
    UnitFailed,
    UnitRestart,
    UnitStart,
    UnitStop,
    /// Unit restarting at least `flap_restarts` within `flap_window_s`.
    UnitFlapping,
    /// Many processes started in one unit in one interval (deploy, cron storm, fork loop).
    DeployBurst,
    /// A process consumed abnormal cpu/mem/io compared with its recent history.
    ProcSpike,
    /// A notable process exited (top consumer, a unit's main pid) with its last resources.
    ProcessExitNotable,
    DiskLatencySpike,
    DiskError,
    FsFill,
    RoRemount,
    /// Kernel WARN/BUG/hung task/soft lockup/segfault lines.
    KernelWarn,
    HungTask,
    /// A cgroup throttled by cpu.max or stalled by PSI (noisy neighbour / undersized limit).
    Throttle,
    PressureSpike,
    /// fds, conntrack, ephemeral ports or memory.max near/at their limits.
    Exhaustion,
    ClockUnsynced,
    #[default]
    Other,
}

impl EventKind {
    pub const ALL: [EventKind; 20] = [
        EventKind::OomKill,
        EventKind::UnitFailed,
        EventKind::UnitRestart,
        EventKind::UnitStart,
        EventKind::UnitStop,
        EventKind::UnitFlapping,
        EventKind::DeployBurst,
        EventKind::ProcSpike,
        EventKind::ProcessExitNotable,
        EventKind::DiskLatencySpike,
        EventKind::DiskError,
        EventKind::FsFill,
        EventKind::RoRemount,
        EventKind::KernelWarn,
        EventKind::HungTask,
        EventKind::Throttle,
        EventKind::PressureSpike,
        EventKind::Exhaustion,
        EventKind::ClockUnsynced,
        EventKind::Other,
    ];

    /// snake_case name, identical to the serde form ("oom_kill").
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::OomKill => "oom_kill",
            EventKind::UnitFailed => "unit_failed",
            EventKind::UnitRestart => "unit_restart",
            EventKind::UnitStart => "unit_start",
            EventKind::UnitStop => "unit_stop",
            EventKind::UnitFlapping => "unit_flapping",
            EventKind::DeployBurst => "deploy_burst",
            EventKind::ProcSpike => "proc_spike",
            EventKind::ProcessExitNotable => "process_exit_notable",
            EventKind::DiskLatencySpike => "disk_latency_spike",
            EventKind::DiskError => "disk_error",
            EventKind::FsFill => "fs_fill",
            EventKind::RoRemount => "ro_remount",
            EventKind::KernelWarn => "kernel_warn",
            EventKind::HungTask => "hung_task",
            EventKind::Throttle => "throttle",
            EventKind::PressureSpike => "pressure_spike",
            EventKind::Exhaustion => "exhaustion",
            EventKind::ClockUnsynced => "clock_unsynced",
            EventKind::Other => "other",
        }
    }

    /// Accepts the snake_case name, with '-' allowed for '_' (CLI `--kind oom-kill`).
    pub fn parse(s: &str) -> Option<EventKind> {
        let s = s.trim().to_ascii_lowercase().replace('-', "_");
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Warn,
    Crit,
}

impl Severity {
    /// Same vocabulary as `Finding.severity`.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Crit => "crit",
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "crit" | "critical" => Severity::Crit,
            "warn" | "warning" => Severity::Warn,
            _ => Severity::Info,
        }
    }
}

/// Something that happened at an instant. Snapshot.events holds the events detected since the
/// previous sample; the recorder keeps all of them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Event {
    pub ts: Ts,
    pub kind: EventKind,
    pub severity: Severity,
    /// "unit:nginx.service" | "container:web" | "pod:ns/name" | "pid:1234" | "disk:sda" |
    /// "mount:/var" | "kernel" | "host".
    pub subject: String,
    pub unit: Option<String>,
    pub pid: Option<u32>,
    /// One human sentence: "nginx.service restarted (exit-code 1), 4th time in 10 min".
    pub detail: String,
    /// Main number when one applies (await ms, % full, rss bytes...).
    pub value: Option<f64>,
    /// "kmsg" | "systemd" | "runtime" | "cgroup" | "procfs" | "sampler" | "recorder".
    pub source: String,
    /// Small, bounded structured extras (OOM: victim, memcg, rss_kb, invoker). At most ~8 keys.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------------------------

/// Who is to blame, ranked.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Culprit {
    /// "unit" | "process" | "kernel" | "external" (e.g. steal from the hypervisor).
    pub kind: String,
    pub name: String,
    pub pid: Option<u32>,
    pub unit: Option<String>,
    /// Why this one: "used 6.1 GiB (78% of RAM) at 03:11:58, grew 4 GiB in 5 min".
    pub why: String,
    pub cpu: Option<f32>,
    pub mem: Option<u64>,
}

/// "What happened at 03:12 and who did it?"
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Incident {
    pub host: String,
    /// Window examined, epoch ms.
    pub from: Ts,
    pub to: Ts,
    /// Moment of interest (the `--at`, or the most severe event).
    pub at: Ts,
    pub severity: Severity,
    /// "db-01: postgres.service OOM-killed at 03:12 — backup.service grew to 6 GiB".
    pub headline: String,
    /// Ordered causal steps, symptom first, root cause last.
    pub chain: Vec<String>,
    /// Numbers backing the chain.
    pub evidence: Vec<String>,
    pub culprits: Vec<Culprit>,
    /// Read-only next steps ("journalctl -u backup.service --since 03:00", "set MemoryMax=...").
    pub suggestions: Vec<String>,
    pub events: Vec<Event>,
    /// Data gaps ("recorder not running before 03:05", "kmsg unreadable: needs root").
    pub gaps: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// Fleet
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SevCounts {
    pub info: u32,
    pub warn: u32,
    pub crit: u32,
}

impl SevCounts {
    pub fn of(findings: &[Finding]) -> SevCounts {
        let mut c = SevCounts::default();
        for f in findings {
            match Severity::parse(&f.severity) {
                Severity::Info => c.info += 1,
                Severity::Warn => c.warn += 1,
                Severity::Crit => c.crit += 1,
            }
        }
        c
    }
}

/// One row of the fleet table.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FleetHost {
    pub name: String,
    pub groups: Vec<String>,
    pub tags: Vec<String>,
    pub ok: bool,
    pub error: Option<String>,
    /// Round trip of the poll (connect + remote run).
    pub latency_ms: u64,
    /// Age of the data on the remote ("recorder" source) in ms; 0 for a live sample.
    pub age_ms: i64,
    pub profile: Profile,
    /// 0 (on fire) ..= 100 (healthy); see fleet::fanout::health_score.
    pub health: u8,
    pub cpu: f32,
    pub mem_pct: f32,
    pub load1: f64,
    pub cores: usize,
    pub disk_worst_pct: f32,
    pub disk_worst_mount: String,
    pub findings: SevCounts,
    pub top_finding: Option<String>,
    pub units_failed: u32,
    pub oom_24h: u32,
    pub version: String,
    pub ts: Ts,
}

/// One finding title aggregated across hosts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FleetFinding {
    pub title: String,
    pub severity: Severity,
    pub count: usize,
    /// Affected hosts, worst first, capped by the caller's `max_hosts` (count stays exact).
    pub hosts: Vec<String>,
    /// When hosts' titles differ in their numbers: the worst host's own title, values intact
    /// ("web-03: Disk /var is 99% full"). Empty when every host has the identical title.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub worst: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FleetSummary {
    pub ts: Ts,
    pub elapsed_ms: u64,
    pub total: usize,
    pub ok: usize,
    pub unreachable: usize,
    pub hosts: Vec<FleetHost>,
    /// Sorted by severity, then count.
    pub findings: Vec<FleetFinding>,
}

/// A host whose metric is far from its group's median (robust z-score, see FleetCfg::outlier_z).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FleetOutlier {
    pub host: String,
    /// Group compared against ("*" = all selected hosts, for hosts without a group).
    pub group: String,
    /// "cpu" | "mem_pct" | "disk_worst_pct" | "load_per_core_pct".
    pub metric: String,
    pub value: f32,
    pub median: f32,
    pub z: f32,
}

// ---------------------------------------------------------------------------------------------
// Snapshot metadata and the combined sampler
// ---------------------------------------------------------------------------------------------

/// Where a snapshot came from; lets fleet show versions and stale data.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SnapMeta {
    pub version: String,
    pub profile: Profile,
    /// "live" | "recorder".
    pub source: String,
    /// now - snapshot ts at the time it was served.
    pub age_ms: i64,
    /// Whether fat ran as root (affects which fields are filled).
    pub root: bool,
}

impl SnapMeta {
    pub fn live(profile: Profile) -> SnapMeta {
        SnapMeta {
            version: env!("CARGO_PKG_VERSION").into(),
            profile,
            source: "live".into(),
            age_ms: 0,
            // SAFETY: geteuid has no preconditions.
            root: unsafe { libc::geteuid() } == 0,
        }
    }
}

/// Shared slot holding the latest snapshot for the exporter (written by the recorder loop).
pub type LatestSnapshot = std::sync::Arc<std::sync::RwLock<Option<std::sync::Arc<Snapshot>>>>;

/// Services + kernel sampling on top of a collect::Collector snapshot. Callers (recorder, TUI,
/// CLI) own one per process and call `fill` after every `Collector::sample`.
pub struct ServerSampler {
    pub services: services::Services,
    pub kernel: kernel::KernelSampler,
    oom: OomDedup,
}

impl ServerSampler {
    pub fn new(cfg: &ServerCfg) -> ServerSampler {
        ServerSampler {
            services: services::Services::new(cfg),
            kernel: kernel::KernelSampler::new(cfg),
            oom: OomDedup::new(cfg.oom_dedup_s),
        }
    }

    /// Fill `snap.units`, `snap.kernel`, `snap.events` (events since the previous fill, sorted
    /// by ts) and `snap.meta`. Never panics or blocks for more than ~a sample interval; on
    /// macOS units come from containers only and kernel is None.
    pub fn fill(&mut self, snap: &mut Snapshot) {
        snap.units = self.services.sample(&snap.procs);
        snap.kernel = self.kernel.sample(&snap.procs, &snap.units);
        let mut ev = self.services.drain_events();
        let kev = self.kernel.drain_events();
        self.oom.dedup(&kev, &mut ev);
        ev.extend(kev);
        ev.sort_by_key(|e| e.ts);
        snap.events = ev;
        snap.meta = Some(SnapMeta::live(Profile::Server));
    }
}

/// Drops cgroup/systemd OOM events that repeat a kernel-log OOM kill (see
/// [`ServerCfg::oom_dedup_s`]), so one kill counts once in doctor, fleet and exported totals.
struct OomDedup {
    window_ms: Ts,
    /// Recent kernel-log kills not yet matched: (ts, victim's cgroup, unit name).
    kills: std::collections::VecDeque<(Ts, String, Option<String>)>,
}

impl OomDedup {
    fn new(window_s: u64) -> OomDedup {
        OomDedup { window_ms: (window_s * 1000) as Ts, kills: Default::default() }
    }

    /// Remember the kernel-log kills in `kernel`; remove (or reduce) the unit-level OOM events
    /// in `units` that they already account for.
    fn dedup(&mut self, kernel: &[Event], units: &mut Vec<Event>) {
        for e in kernel.iter().filter(|e| e.kind == EventKind::OomKill && e.source == "kmsg") {
            let cg = e.extra.get("task_memcg").or_else(|| e.extra.get("memcg")).cloned().unwrap_or_default();
            self.kills.push_back((e.ts, cg, e.unit.clone()));
        }
        let newest = self.kills.iter().map(|k| k.0).chain(units.iter().map(|e| e.ts)).max().unwrap_or(0);
        while self.kills.front().is_some_and(|k| k.0 < newest - self.window_ms) {
            self.kills.pop_front();
        }
        units.retain_mut(|e| {
            if e.kind != EventKind::OomKill || e.source == "kmsg" {
                return true;
            }
            let n = e.value.map_or(1, |v| v.max(1.0) as u64);
            let cg = e.extra.get("cgroup").map(String::as_str).unwrap_or("");
            let mut matched = 0u64;
            while matched < n {
                let hit = self.kills.iter().position(|(ts, kcg, kunit)| {
                    (ts - e.ts).abs() <= self.window_ms
                        && (cg_within(kcg, cg) || (kunit.is_some() && kunit.as_deref() == e.unit.as_deref()))
                });
                let Some(i) = hit else { break };
                self.kills.remove(i);
                matched += 1;
            }
            if matched == 0 {
                return true;
            }
            if matched >= n {
                return false;
            }
            let rest = n - matched;
            e.value = Some(rest as f64);
            if let Some(tail) = e.detail.strip_prefix(&format!("{n} process(es)")) {
                e.detail = format!("{rest} process(es){tail}");
            }
            true
        });
    }
}

/// True when cgroup path `task` is `unit` or below it. Paths may differ in prefix when the
/// kernel prints them from outside a cgroup namespace, so `unit` is matched as a path suffix.
fn cg_within(task: &str, unit: &str) -> bool {
    let (t, u) = (task.trim_matches('/'), unit.trim_matches('/'));
    !u.is_empty()
        && !t.is_empty()
        && (t == u || t.starts_with(&format!("{u}/")) || t.ends_with(&format!("/{u}")) || t.contains(&format!("/{u}/")))
}

/// Keep only the processes worth recording in server mode: the union of the top `n` by cpu,
/// by memory and by disk io (non-zero values only), plus each unit's main pid. Bounded at
/// 3n + units.
pub fn top_procs<'a>(procs: &'a [Proc], units: &[Unit], n: usize) -> Vec<&'a Proc> {
    let mut keep = std::collections::HashSet::new();
    let mut idx: Vec<usize> = (0..procs.len()).collect();
    let mut take = |key: &dyn Fn(&Proc) -> f64, keep: &mut std::collections::HashSet<usize>| {
        idx.sort_by(|&a, &b| key(&procs[b]).partial_cmp(&key(&procs[a])).unwrap_or(std::cmp::Ordering::Equal));
        // Zero values carry no ranking information; taking them would pick arbitrary idle
        // processes and make the recorded set churn between samples.
        keep.extend(idx.iter().take(n).copied().filter(|&i| key(&procs[i]) > 0.0));
    };
    take(&|p| p.cpu as f64, &mut keep);
    take(&|p| p.mem as f64, &mut keep);
    take(&|p| (p.disk_read_bps + p.disk_write_bps) as f64, &mut keep);
    let mains: std::collections::HashSet<u32> = units.iter().filter_map(|u| u.main_pid).collect();
    let mut out: Vec<&Proc> = procs.iter().enumerate().filter(|(i, p)| keep.contains(i) || mains.contains(&p.pid)).map(|(_, p)| p).collect();
    out.sort_by_key(|p| p.pid);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oom_ev(ts: Ts, subject: &str, source: &str, extra: &[(&str, &str)], value: Option<f64>, detail: &str) -> Event {
        Event {
            ts,
            kind: EventKind::OomKill,
            severity: Severity::Crit,
            subject: subject.into(),
            unit: subject.strip_prefix("unit:").map(str::to_string),
            pid: None,
            detail: detail.into(),
            value,
            source: source.into(),
            extra: extra.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    /// One kill reported by the kernel log, the cgroup and systemd is counted once; a cgroup
    /// report of more kills than the kernel log saw keeps the remainder.
    #[test]
    fn oom_sources_dedup() {
        let mut d = OomDedup::new(120);
        let k = oom_ev(1000, "pid:42", "kmsg", &[("task_memcg", "/outer/ns/system.slice/x.service")], Some(1e6), "OOM killer killed python3");
        let mut units = vec![oom_ev(5000, "unit:x.service", "cgroup", &[("cgroup", "/system.slice/x.service")], Some(1.0), "1 process(es) OOM-killed in x.service")];
        d.dedup(std::slice::from_ref(&k), &mut units);
        assert!(units.is_empty(), "cgroup report of the logged kill dropped");
        // systemd's later Result=oom-kill for the same unit: the kill was already consumed, so it
        // is kept only if no kernel kill remains; here the services layer suppresses it itself.
        let mut units = vec![oom_ev(7000, "unit:y.service", "systemd", &[("cgroup", "/system.slice/y.service")], None, "y was OOM-killed")];
        d.dedup(&[], &mut units);
        assert_eq!(units.len(), 1, "no kernel kill for y: kept");
        // Three kills in the cgroup, one logged: two remain.
        let k = oom_ev(10_000, "pid:7", "kmsg", &[("memcg", "/system.slice/z.service")], None, "");
        let mut units = vec![oom_ev(11_000, "unit:z.service", "cgroup", &[("cgroup", "/system.slice/z.service")], Some(3.0), "3 process(es) OOM-killed in z.service")];
        d.dedup(&[k], &mut units);
        assert_eq!(units[0].value, Some(2.0));
        assert!(units[0].detail.starts_with("2 process(es)"), "{}", units[0].detail);
        // Outside the window: a different kill.
        let k = oom_ev(20_000, "pid:8", "kmsg", &[("memcg", "/system.slice/w.service")], None, "");
        d.dedup(&[k], &mut vec![]);
        let mut units = vec![oom_ev(20_000 + 121_000, "unit:w.service", "cgroup", &[("cgroup", "/system.slice/w.service")], Some(1.0), "")];
        d.dedup(&[], &mut units);
        assert_eq!(units.len(), 1);
        assert!(cg_within("/a/system.slice/x.service", "/system.slice/x.service"));
        assert!(cg_within("/system.slice/x.service/child", "/system.slice/x.service"));
        assert!(!cg_within("/system.slice/x.service2", "/system.slice/x.service"));
        assert!(!cg_within("/system.slice/x.service", ""));
    }

    #[test]
    fn profile_resolution() {
        assert_eq!(Profile::resolve("server", false), Profile::Server);
        assert_eq!(Profile::resolve("Desktop", true), Profile::Desktop);
        assert_eq!(Profile::resolve("auto", true), Profile::Server);
        assert_eq!(Profile::resolve("auto", false), Profile::Desktop);
        assert_eq!(Profile::resolve("bogus", false), Profile::Desktop);
    }

    #[test]
    fn cgroup_to_unit() {
        let r = |p: &str| unit_of_cgroup(p);
        assert_eq!(r("/system.slice/nginx.service"), Some(UnitRef { kind: UnitKind::Systemd, key: "nginx.service".into() }));
        let hex = "410892b21be2ffda255ceb4e7e2077d968864674cefc8174a3843e6f01c860f7";
        assert_eq!(r(&format!("/system.slice/docker-{hex}.scope")).unwrap(), UnitRef { kind: UnitKind::Container, key: "410892b21be2".into() });
        assert_eq!(r(&format!("/machine.slice/libpod-{hex}.scope/container")).unwrap().kind, UnitKind::Container);
        assert_eq!(r(&format!("/machine.slice/libpod-conmon-{hex}.scope")).unwrap().kind, UnitKind::Systemd);
        let pod = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234abcd_5678_90ef_1234_567890abcdef.slice";
        assert_eq!(r(pod).unwrap(), UnitRef { kind: UnitKind::Pod, key: "1234abcd-5678-90ef-1234-567890abcdef".into() });
        assert_eq!(r(&format!("{pod}/cri-containerd-{hex}.scope")).unwrap().kind, UnitKind::Container);
        assert_eq!(r(&format!("/kubepods/besteffort/pod1234abcd-5678-90ef-1234-567890abcdef/{hex}")).unwrap().kind, UnitKind::Container);
        assert_eq!(r("/user.slice/user-1000.slice/session-3.scope").unwrap().key, "session-3.scope");
        assert_eq!(r("/"), None);
        assert_eq!(r("/system.slice"), None);
        assert_eq!(r("/mygroup/worker").unwrap(), UnitRef { kind: UnitKind::Cgroup, key: "/mygroup/worker".into() });
    }

    #[test]
    fn event_kind_names_match_serde() {
        for k in EventKind::ALL {
            assert_eq!(serde_json::to_value(k).unwrap(), serde_json::json!(k.as_str()));
            assert_eq!(EventKind::parse(&k.as_str().replace('_', "-")), Some(k));
        }
        assert_eq!(serde_json::to_value(UnitKind::Pod).unwrap(), serde_json::json!("k8s-pod"));
    }

    #[test]
    fn old_snapshots_still_parse() {
        let s: Snapshot = serde_json::from_str(r#"{"ts":1,"host":"h","system":{"hostname":"","os":"","cpu_model":"","cores":0,"per_core":[],"cpu":0,"load":[0,0,0],"mem_total":0,"mem_used":0,"swap_total":0,"swap_used":0,"mem_pressure":"","thermal":"","gpus":[],"power_mw":0,"net_rx_bps":0,"net_tx_bps":0,"disk_read_bps":0,"disk_write_bps":0,"uptime":0,"battery_pct":null,"on_battery":null},"procs":[],"ports":[]}"#).unwrap();
        assert!(s.units.is_empty() && s.kernel.is_none() && s.events.is_empty() && s.meta.is_none());
        let v = serde_json::to_value(&s).unwrap();
        assert!(v.get("units").is_none() && v.get("kernel").is_none(), "desktop JSON shape unchanged");
    }

    #[test]
    fn top_procs_is_bounded() {
        let procs: Vec<Proc> = (1..=500).map(|i| Proc { pid: i, cpu: i as f32, mem: (501 - i) as u64, ..Default::default() }).collect();
        let units = vec![Unit { main_pid: Some(250), ..Default::default() }];
        let kept = top_procs(&procs, &units, 10);
        assert!(kept.len() <= 31);
        assert!(kept.iter().any(|p| p.pid == 500) && kept.iter().any(|p| p.pid == 1) && kept.iter().any(|p| p.pid == 250));
    }
}
