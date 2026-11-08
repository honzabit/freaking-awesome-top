//! Shared data model. Every collector, view, and API speaks these types.
//! CONTRACT: other modules may ADD optional fields only with `#[serde(default)]`;
//! never rename or remove fields here without updating all users.

use serde::{Deserialize, Serialize};

/// Unix epoch milliseconds.
pub type Ts = i64;

pub fn now_ms() -> Ts {
    chrono::Utc::now().timestamp_millis()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    /// Full command line joined by spaces (may be empty if not permitted).
    pub cmd: String,
    pub exe: String,
    pub cwd: String,
    pub user: String,
    /// CPU percent, 100 = one full core.
    pub cpu: f32,
    /// Resident memory bytes.
    pub mem: u64,
    pub virt: u64,
    /// Disk bytes read/written since last sample, per second.
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
    /// Network bytes/sec (from nettop; 0 if unavailable).
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
    /// Estimated power in milliwatts (from proc_pid_rusage billed energy delta).
    pub power_mw: f32,
    /// GPU time percent if known.
    pub gpu: Option<f32>,
    pub threads: u32,
    /// Process start, epoch seconds.
    pub start_time: u64,
    /// Single char status: R, S, T (stopped), Z, I, U.
    pub status: String,
    pub nice: i32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Port {
    pub proto: Proto,
    pub addr: String,
    pub port: u16,
    pub pid: u32,
    pub process: String,
    /// "LISTEN" for tcp listeners; "" for udp.
    pub state: String,
    /// Heuristic: listener whose parent chain lost its terminal/agent (re-parented to launchd)
    /// and looks like a dev server.
    pub orphan: bool,
    /// Human description: "node vite dev server in ~/proj (started 3h ago)".
    pub note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Gpu {
    pub name: String,
    /// Device utilization percent 0..100.
    pub util: f32,
    pub mem_used: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct System {
    pub hostname: String,
    pub os: String,
    pub cpu_model: String,
    pub cores: usize,
    /// Per-core usage percent.
    pub per_core: Vec<f32>,
    /// Overall CPU percent 0..100.
    pub cpu: f32,
    pub load: [f64; 3],
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    /// macOS memory pressure level: "normal" | "warn" | "critical" | "unknown".
    pub mem_pressure: String,
    /// Thermal state: "nominal" | "fair" | "serious" | "critical" | "unknown".
    pub thermal: String,
    pub gpus: Vec<Gpu>,
    /// Total estimated power mW (sum of process power).
    pub power_mw: f32,
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
    pub uptime: u64,
    pub battery_pct: Option<f32>,
    pub on_battery: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub runtime: String, // "docker" | "podman" | "orbstack"...
    pub status: String,
    pub cpu: f32,
    pub mem: u64,
    pub ports: String,
}

/// One machine's state at an instant.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Snapshot {
    pub ts: Ts,
    /// "local" or the configured remote host name.
    pub host: String,
    pub system: System,
    pub procs: Vec<Proc>,
    pub ports: Vec<Port>,
    #[serde(default)]
    pub containers: Vec<Container>,
}

impl Snapshot {
    pub fn proc(&self, pid: u32) -> Option<&Proc> {
        self.procs.iter().find(|p| p.pid == pid)
    }
    /// Ancestors from parent up to (and including) pid 1 / root.
    pub fn ancestors(&self, pid: u32) -> Vec<&Proc> {
        let mut out = Vec::new();
        let mut cur = self.proc(pid).map(|p| p.ppid);
        let mut guard = 0;
        while let Some(pp) = cur {
            if pp == 0 || guard > 64 {
                break;
            }
            guard += 1;
            match self.proc(pp) {
                Some(p) => {
                    out.push(p);
                    if p.pid == 1 {
                        break;
                    }
                    cur = Some(p.ppid);
                }
                None => break,
            }
        }
        out
    }
    /// All descendants (not including pid itself), breadth first.
    pub fn descendants(&self, pid: u32) -> Vec<&Proc> {
        let mut out: Vec<&Proc> = Vec::new();
        let mut frontier = vec![pid];
        while let Some(cur) = frontier.pop() {
            for p in self.procs.iter().filter(|p| p.ppid == cur && p.pid != cur) {
                if !out.iter().any(|o| o.pid == p.pid) {
                    out.push(p);
                    frontier.push(p.pid);
                }
            }
        }
        out
    }
}

/// A causal explanation ("blame chain") for something consuming resources.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Explanation {
    pub pid: u32,
    pub headline: String,
    /// Ordered chain from symptom to root cause, each a human-readable step.
    pub chain: Vec<String>,
    /// Evidence lines (numbers, files, ports).
    pub evidence: Vec<String>,
    pub suggestions: Vec<String>,
}

/// A rule-based or LLM diagnosis of the whole machine.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// "info" | "warn" | "crit"
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub pids: Vec<u32>,
    /// Suggested safe action, e.g. "pause 1234".
    pub action: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    Pause,
    Resume,
    Renice,
    Term,
    Kill,
    /// TERM the process and all descendants.
    KillTree,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionRecord {
    pub id: u64,
    pub ts: Ts,
    pub kind: ActionKind,
    pub pid: u32,
    pub name: String,
    /// For renice: previous nice value (for undo).
    pub prev_nice: Option<i32>,
    pub new_nice: Option<i32>,
    /// Pids affected (KillTree / Pause tree).
    pub pids: Vec<u32>,
    pub undoable: bool,
    pub undone: bool,
    pub ok: bool,
    pub message: String,
}

/// Resource budget for `fat run`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Budget {
    /// Max CPU percent across the tree (100 = 1 core).
    pub cpu: Option<f32>,
    /// Max resident bytes across the tree.
    pub mem: Option<u64>,
    /// Max wall time seconds.
    pub time: Option<u64>,
    /// Max processes in tree.
    pub procs: Option<usize>,
    /// What to do on violation: "pause" | "kill" | "warn".
    pub on_violation: String,
}
