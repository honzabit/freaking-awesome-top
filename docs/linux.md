# Linux

[← README](../README.md)

Everything works on Linux, and several things work better than on macOS, because Linux exposes more of the
kernel's own accounting.

- fat reads procfs and sysfs directly. A sample of about 1,000 processes takes roughly 10–30 ms.
- The sample path spawns no subprocesses.
- Per-process network rates come from a netlink `sock_diag` dump every 2 s. That costs about 0.2–1 ms of CPU per
  cycle, up to about 2.5 ms as root (which also walks every container's network namespace). The `ss` it replaced
  took 2–19 ms.
- The only child processes are the container CLIs (cached), and `ss` only if netlink is unavailable.

macOS keeps the desktop profile and behaves as before.

## Target environments

Server mode assumes as little as possible about the host. Every source below is optional: when it is missing, the
matching fields stay empty and a note says why (often "needs root"). Nothing fails.

| | What fat assumes |
| --- | --- |
| Distribution and kernel | Any Linux distribution and any kernel version still in common use. Features that newer kernels add (PSI, cgroup v2, `memory.peak`) are used when present. |
| Init | systemd is used when it is PID 1. Other inits and minimal containers work too: the cgroups that hold processes become the units. |
| Containers | docker, containerd, CRI-O, podman and Kubernetes pods are recognised from the cgroup tree when present. None is required. |
| CPU architecture | Any target Rust supports. Prebuilt static binaries (x86_64, aarch64) are on the [releases page](https://github.com/honzabit/freaking-awesome-top/releases); see [Install](../README.md#install) to verify them. `scripts/build-static.sh` builds a static binary to copy to hosts. |
| Privileges | Root is optional. Without it, other users' process details, the kernel log and some per-cgroup files may be unreadable, and the output says so. See [Root vs non-root](#root-vs-non-root). |
| Fleets | fat runs your `ssh` with your ssh config. It adds no network topology of its own. See [Fleets](fleet.md). |
| Overhead budget for the always-on recorder | Under 1% of one core on average, under 60 MB RSS, and disk bounded by `history_days`. Measured numbers are in [Servers](server.md). Every limit is a config value. |

## What you get on Linux

These are the Linux-only or Linux-better readings, and where fat gets each one.

| What | How fat measures it |
| --- | --- |
| **PSI (pressure stall information)** | The header shows `PSI cpu▂3 mem▁0 io▅12`: the share of the last 10 seconds that tasks spent waiting for a CPU, for memory and for io. Load average can't tell you this. A busy machine with PSI near 0 is fine. Sustained PSI above about 10% means real contention, and `doctor` / `ask` say so. |
| **Measured power** | With RAPL (Intel, and AMD Zen), system power is the CPU package's real energy counter, the `package-N` zones, shown as `48.2W rapl`. A laptop's `psys` platform zone is used only when there is no package zone, since it already contains the package. Each process gets its share of the machine's CPU capacity (one of 8 cores busy = 1/8 of package power), so the idle and uncore baseline stays unattributed. Without RAPL access it falls back to a CPU-time model, shown as `~8.0W est`. |
| **Temperatures** | The hottest hwmon sensor or thermal zone (`THERM 71°C`). The thermal *state* (throttling) only comes from CPU sources at their real trip points (thermal-zone passive/hot/critical trips, coretemp / k10temp limits). A hot NVMe, or a CPU at 80°C under a build, is hot, not throttled. |
| **Container limits** | When fat itself runs in a cgroup with `memory.max` / `cpu.max` / a cpuset (a container started with `--memory`, `--cpus`, `--cpuset-cpus`), memory total and used, memory pressure, PSI, the core count and CPU% are the container's, not the host's `/proc/meminfo` and cores. CPU% is of its quota. |
| **System disk and network totals** | From `/proc/diskstats` (whole disks) and `/proc/net/dev` (all but `lo`). Both are world-readable, so the totals are right without root even though other users' per-process io isn't. |
| **Containers as first-class processes** | Each process's cgroup v2 path (`/system.slice/docker-<id>.scope`, `…/libpod-<id>.scope`, kubepods, …) gives its container id. The procs table gets a **CONTAINER** column (the container's name when the runtime reports it, otherwise the short id), and `/db-1` filters to that container's processes. The Why panel shows the cgroup and container. The Fleet view counts each container's processes. |
| **cgroup-based budgets** | `fat run` budgets are backed by the kernel when fat can create a cgroup. See [cgroup-based budgets](#cgroup-based-budgets-fat-run). |
| **Ports and orphans without lsof** | Ports come from `/proc/net/{tcp,tcp6,udp,udp6}` of fat's own network namespace and of every other one it can see (`/proc/<pid>/net/*`; all containers' as root, tagged "in container &lt;id&gt;"). Owners come from `/proc/<pid>/fd`. As root, per-process traffic is also read from each container's namespace (a netlink socket opened inside it with `setns`). A dev server re-parented to pid 1 or to a `systemd --user` subreaper is flagged as an orphan. |

### cgroup-based budgets (`fat run`)

`fat run` measures the whole tree from procfs, including children that already exited. When it can create a
cgroup v2 child (as root, or inside a delegated subtree such as a systemd user scope), the kernel backs the budget,
so a sudden allocation or a fork bomb can't outrun the poll. The policy keeps its meaning:

| Flag | Kernel control | What happens |
| --- | --- | --- |
| `--cpu` | `cpu.max` holds the job at its quota | A job throttled in most periods wants more than its budget. That is a cpu violation, so `pause` and `kill` fire as on macOS. `warn` sets no limit and only reports. |
| `--mem` with `pause` (the default) | `memory.high` just above the budget; `memory.max` well above it, only as a backstop | `memory.high` slows the job down (no kill). The poll pauses the job at the breach, and it can be resumed. |
| `--mem` with `kill` | `memory.max` at the budget, with `memory.oom.group` | An OOM kills the whole job. |
| `--procs` | `pids.max` as a backstop: 16 × procs + 256 tasks (it counts threads) | The exact process count is polled. |

Where the cgroup comes from:

- **As root**, fat creates `/sys/fs/cgroup/fat.slice/run-<pid>-<random>`. It never does this inside a container's
  cgroup-namespace root that holds processes.
- **As a normal user**, fat starts a transient `systemd-run --user --scope` itself. This needs a user manager. On a
  headless box, run this once:

  ```bash
  loginctl enable-linger $USER
  ```

  If `systemd-run` fails, the command is started directly and polled.
- **Inside a limited cgroup** (another `fat run`, a container with `--memory`/`--cpus`), fat makes no new cgroup,
  because that would escape those limits. The job stays under them and this budget is polled.
- Processes that leave the job's cgroup (`systemd-run --scope`) are noticed and polled too.
- **Otherwise** fat polls every 500 ms, as on macOS.

The first line of output says which mechanism is enforcing. `FAT_BUDGET_MODE=auto|cgroup|poll` forces a choice.

## Data sources

Where each reading comes from on each platform.

| Data | macOS | Linux |
| --- | --- | --- |
| Process list, cpu, memory, threads, nice | `proc_pid_rusage`, `proc_pidinfo`, `sysinfo` | `/proc/<pid>/stat`, `status` |
| Per-process disk I/O | `proc_pid_rusage` | `/proc/<pid>/io` (own processes, or all as root); system totals `/proc/diskstats` |
| Per-process network | `nettop` | `NETLINK_SOCK_DIAG` tcp_info byte counters + `/proc/<pid>/fd` owners (own sockets, or all as root, every netns; `ss -tinpeH` fallback); system totals `/proc/net/dev` |
| Power | per-task energy (`ri_energy_nj`) → `rusage` | RAPL `/sys/class/powercap/intel-rapl:*/energy_uj` → `rapl`, else CPU-time model → `estimate` |
| Memory pressure | `kern.memorystatus_vm_pressure_level` | `/proc/pressure/memory`, `/proc/meminfo` |
| CPU / io pressure | none | `/proc/pressure/{cpu,io}` (PSI, kernel 4.20+, `psi=1`) |
| Thermal | notify `com.apple.system.thermalpressurelevel` (state word) | `/sys/class/hwmon/*/temp*_input`, `/sys/class/thermal/thermal_zone*` (°C) |
| Battery | IOKit `IOPSCopyPowerSourcesInfo` | `/sys/class/power_supply/BAT*` |
| GPU | IOKit `IOAccelerator` | `/sys/class/drm` and DRM fdinfo; `nvidia-smi` if installed |
| Listening ports | libproc socket fds | `/proc/net/*` + `/proc/<pid>/fd` |
| cgroup / container | none | `/proc/<pid>/cgroup` (v2) → container id; names from docker / podman / nerdctl |
| Containers | docker / podman (OrbStack, colima contexts) | docker / podman (incl. the podman-docker shim), nerdctl fallback |

On a kernel without PSI, RAPL, hwmon or a battery (many VMs and containers), those fields are simply absent. The
header leaves them out and nothing errors.

## Services (`fat services`)

`fat services` lists every unit on the host and its health, because on a server services are the unit of thought, not pids.

```bash
fat services                       # every unit: systemd services and scopes, containers, pods, plain cgroups
fat services --failed              # failed or flapping only
fat services --kind container --json
```

Failed and flapping units sort first. The MCP tool `services` returns the same data, plus the transitions seen
since the previous call (see [MCP](agents.md)).

### What each unit shows

| Field | Details |
| --- | --- |
| State | Normalised to systemd's words: active, activating, deactivating, reloading, inactive, failed |
| Sub-state | The runtime's own sub-state |
| Result and exit code | systemd's result (exit-code, signal, oom-kill, start-limit-hit...) and the exit code |
| Restarts | Lifetime restarts, restarts within `flap_window_s`, and a `flapping` flag |
| cgroup totals (all its processes) | CPU, memory with its limit and peak, OOM kills, the share of CPU periods it was throttled by its own `cpu.max`, its CPU quota, io bytes/s, and its own PSI |

### Sources

Each source is optional.

- **cgroup v2 files**, read every sample. cgroup v1 hosts give memory, CPU and pids best effort, with no per-unit
  io or PSI.
- **systemd**, when it is PID 1:
  - one `systemctl list-units` runs every `unit_refresh_s`;
  - after it, one batched `systemctl show` reads only the units whose state, sub-state or main pid changed;
  - every `unit_full_refresh_s` it reads every unit that is not inactive.
- **Containers** of any runtime (docker, podman, containerd, CRI-O), found from their cgroups. Names, images,
  restart counts and Kubernetes pod and namespace come from the runtime's own state files, which need root.
  Without them the short id is the name, and a note says so.
- **Without systemd** (other inits, minimal containers), the cgroups that hold processes are the units.

### Events

Events are created on transitions:

| Event | When |
| --- | --- |
| `unit_start`, `unit_stop`, `unit_failed` | A unit starts, stops or fails. `unit_failed` is crit for oom-kill, start-limit-hit, core-dump and watchdog. |
| `unit_restart` | From the restart counter, or for a container that comes back after it went away. While a unit keeps flapping, its restarts are summed into one event per `spike_cooldown_s` (the event's value is the count), so a restart loop does not flood the recorder. |
| `unit_flapping` | Once, when `flap_restarts` restarts land within `flap_window_s`. |
| `oom_kill` | From the cgroup's `memory.events`, or from systemd's `Result=oom-kill` when the cgroup died between samples. |
| `throttle` | A unit is throttled in `throttle_warn_pct` of its CPU periods. |
| `exhaustion` | At `exhaustion_warn` of `memory.max` (not counting reclaimable page cache), or of `pids.max`. |
| `deploy_burst` | `burst_procs` new processes appear in one unit within one sample. |

- Level events re-arm only after the value drops well below the threshold.
- Session scopes do not produce start or stop events.
- At most `max_units` units are kept, and inactive units are dropped first.

### Service settings

| `[server]` key | default | meaning |
|---|---|---|
| `unit_refresh_s` | 10 | list units, walk the cgroup tree and re-read limits this often |
| `unit_full_refresh_s` | 300 | re-read every non-inactive unit's systemd properties this often |
| `oom_dedup_s` | 120 | a cgroup or systemd OOM report within this long of a kernel-log kill in the same cgroup is the same kill, counted once |
| `dstate_max_thread_reads` | 20000 | thread stat files read per sample to find blocked worker threads, only while `/proc/stat` counts more blocked tasks than the main-thread scan found |
| `flap_restarts`, `flap_window_s` | 3, 600 | a unit with at least this many restarts within this window is flapping |
| `throttle_warn_pct` | 25 | share of CPU periods throttled that raises a `throttle` event |
| `exhaustion_warn` | 0.85 | share of `memory.max` or `pids.max` that raises an `exhaustion` event |
| `burst_procs` | 20 | number of new processes in one unit within one sample that raises a `deploy_burst` event |
| `max_units` | 2000 | upper bound on units per sample |

See [Configuration](configuration.md) for where the config file lives.

### Measured cost

Release build, 5 s samples, on an aarch64 VM with about 200 units (133 active):

- 2–7 ms per sample, plus 5–14 ms of `systemctl` every `unit_refresh_s`.
- That averages 0.28% of one core. systemd itself adds about 0.07%.
- A full pass costs systemd and systemctl together about 1.7 ms per unit.
- On a host without systemd running 7 containers, a sample costs 0.5–2 ms (0.02% of a core).

## Kernel health and kernel events (`fat kernel`)

`fat kernel` answers the classic "load is high but the CPU is idle" questions.

```bash
fat kernel                  # 1 s sample + kernel log events of the last 24h
fat kernel --since 2h --json
fat kernel --watch [--json] # stream kernel events as they happen (Ctrl-C to stop)
```

The MCP tool `kernel` returns the same report.

### What the report shows

| What | How fat measures it |
| --- | --- |
| Steal, iowait, irq, softirq, `procs_blocked` | `/proc/stat` |
| Processes in D state | The kernel function they wait in, and their unit |
| PSI | Reported as some and full |
| Disks | Per whole disk: util %, read/write await, queue depth and iops |
| Swap rates | `/proc/vmstat` |
| File handles, conntrack entries, ephemeral ports | Shown against their limits. For ports, the count is the larger of distinct local ports and the connections to the busiest remote endpoint from one local address. |
| Network | TCP retransmits, listen overflows and drops |
| Filesystems and storage | Mounts that went read-only, ext4 error counters, degraded md arrays |
| Kernel and clock | Kernel taint; clock sync from adjtimex, with the same rule as systemd: a maximum error under 16 s |

### Kernel log events

Kernel log lines become events:

| Event | What it carries |
| --- | --- |
| `oom_kill` | The victim pid and name, its rss, the constraint, the cgroup whose limit was hit, its unit and the invoking task |
| `hung_task` | |
| `disk_error` | I/O, ext4, xfs, btrfs, nvme, ata errors |
| `ro_remount` | |
| `exhaustion` | Conntrack table full, file-max, SYN backlog, neighbour table, pids controller |
| `kernel_warn` | Lockups, oopses, WARN, segfaults and traps, machine checks |
| NIC link up/down | |

Where fat reads the kernel log, in order:

1. `/dev/kmsg`. That needs root or `kernel.dmesg_restrict=0`.
2. Without it, `journalctl -k`. That needs read access to the system journal, and runs at most every `unit_refresh_s`.
3. Without either, a note says so. OOM kills are still counted from `/proc/vmstat`, but without a victim.

How events behave:

- Events are edge-triggered: one event when a condition starts, re-armed once it falls below half the threshold.
- Identical kernel-log lines within one sample are collapsed into one event with a `repeats` count.

### Measured cost

- 0.25–1 ms per sample on an aarch64 VM with a 7.2 kernel.
- The TCP socket table is rescanned at most every `unit_refresh_s`. A 100k-socket table scans in 9–34 ms.

### Kernel settings

| `[server]` key | default | meaning |
|---|---|---|
| `kmsg` | true | read the kernel log |
| `dstate_min_s` | 5 | report D-state processes blocked at least this long (`hung_task` event once per episode) |
| `disk_await_warn_ms` | 100 | `disk_latency_spike` when a busy disk's read or write await exceeds this |
| `exhaustion_warn` | 0.85 | `exhaustion` when fds, conntrack or ephemeral ports reach this fraction of their limit |
| `pressure_full_warn` | 10 | `pressure_spike` when PSI `full` avg10 for cpu, memory or io reaches this % |

## Root vs non-root

fat never needs root on Linux. Root, or `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH`, only adds visibility.

| | As a normal user | As root (or with `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH`) |
| --- | --- | --- |
| Processes | All processes, with cpu, memory, threads, state, cgroup and container, because `stat`, `status` and `cgroup` are world-readable. With `hidepid=2` on `/proc` you only see your own. | All processes |
| Disk rates, cwd, exe | Your own processes only. For other users these read 0 / empty. The system disk and network totals are still complete. | Every process's io, cwd and exe |
| Network rates | Your own sockets only, because other users' `/proc/<pid>/fd` (socket owners) are unreadable | Every socket's owner and traffic |
| Listening ports | Listeners for every port, but owners only for your own. Others show as pid 0, "owner hidden (needs root)". | Every socket's owner |
| Power | No RAPL: `energy_uj` has been root-only since CVE-2020-8694, so power is `~est` | Measured RAPL power |
| Budgets (`fat run`) | Kernel-enforced inside a delegated subtree such as a systemd user scope, otherwise polled; see [cgroup-based budgets](#cgroup-based-budgets-fat-run) | Kernel-enforced budgets |

To allow RAPL for a group without root, use this with a udev rule:

```bash
sudo chmod g+r /sys/class/powercap/intel-rapl:*/energy_uj
```

Actions still refuse to signal other users' processes unless you are root. They never touch pid 1, kernel threads
or fat's own ancestors.

## Install

Prebuilt static binaries for Linux (x86_64, aarch64) are on the
[releases page](https://github.com/honzabit/freaking-awesome-top/releases). See [Install](../README.md#install) for
how to verify a download.

To build from source you need Rust 1.89+ and a C compiler (SQLite is bundled). No other system libraries are needed.
On Debian/Ubuntu: `apt install build-essential`.

```bash
cargo install --path .
```

Or build once and copy the binary to other machines of the same arch and libc:

```bash
cargo build --release && install -m755 target/release/fat ~/.local/bin/
```

For a static binary to copy to any host, use `scripts/build-static.sh` (see [Deploy to a fleet](fleet.md#deploy-to-a-fleet)).

`ss` (iproute2) is used for per-process network rates only if netlink `sock_diag` is blocked. Everything else is
read from `/proc` and `/sys`.

## Running in a container

Inside a container, fat sees the container's own pid namespace: its processes, with cgroup `/`. To see the whole
host, share the host's pid namespace (and cgroup namespace, for container attribution):

```bash
docker run --rm -it --pid=host --cgroupns=host --network=host \
  -v /sys:/sys:ro -v "$HOME/.local/share/fat:/root/.local/share/fat" \
  my-image-with-fat fat
```

| Flag | What it gives |
| --- | --- |
| `--pid=host` | The whole host's process tree |
| `--cgroupns=host` | Real cgroup paths, so the CONTAINER column works |
| `--network=host` | `/proc/net/*` and netlink show the host's sockets |
| `--privileged`, or `--cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH` | Root-level visibility (RAPL, other users' io and sockets) |

In Kubernetes the equivalent is a DaemonSet with `hostPID: true` and `hostNetwork: true`.

## Keep the flight recorder running

- On a server, use the system unit in [Servers](server.md).
- On a desktop, use the systemd user unit in [The flight recorder](recorder.md#linux-systemd-user-unit).

## What happened at 03:12, and who did it?

`fat what-happened` explains an incident as a chain from symptom to cause.

```bash
fat what-happened --at 03:12
```

- It picks the most important event near that time (the MCP tool `what_happened` does the same).
- It shows the numbers behind each step, the culprits, a confidence level, and read-only next steps. fat never
  runs them.
- Without `--at` it explains the last `--window` (default 15m).
- It reads the flight recorder (`fat record --server`). Without one, it uses the current state plus the kernel log,
  and lists what it could not know under "Gaps".
- `fat events` prints the raw timeline.

| incident | what the chain shows |
| --- | --- |
| OOM kill | the victim and its unit; a cgroup limit (`memory.max`) or the whole host out of memory; which unit held the most memory just before and how fast it grew; what started shortly before |
| restart loop, failed unit | restarts in the window, result and exit status, OOM kills inside it, a package update, deploy burst, scheduled job or backup just before the first failure |
| disk latency, load high but CPU idle | the device's await before and at the peak, queue and util, processes in D state and the kernel function they wait in, iowait and steal, the unit whose I/O rose and the job that started it |
| disk filling | growth rate and time to full, the writers whose command line points at that mount, grouped |
| fd, conntrack or ephemeral-port exhaustion | usage against the limit over time, what started as it grew, the commands that show who holds them |
| noisy neighbour | a unit throttled by its own `cpu.max` (quota too small or bursty) versus another unit whose CPU or memory rose at the same time; per-unit PSI |
| read-only remount, I/O or fs errors, degraded RAID | the kernel's messages around it (crit) |

### Advice and protected processes

- Advice is unit-oriented: `journalctl -u <unit>`, `systemctl status`, `docker|podman logs`, `kubectl describe pod`.
- Databases (postgres, mysqld, mongod, redis-server, clickhouse, ...) and server plumbing (the sshd listener,
  systemd-*, the logger, the message bus, time sync, VM guest agents, container runtimes) are never offered for
  pause or kill, not even to an MCP agent.
- For a database the advice is to investigate its workload.

### `fat doctor` in the server profile

`fat doctor` in the server profile adds findings for:

- failed units, restart loops, units near `memory.max` or throttled by `cpu.max`;
- load high with idle CPU, slow disks, swap thrashing;
- fd/conntrack/port exhaustion, accept-queue drops;
- read-only remounts, filesystem and I/O errors, degraded RAID;
- an unsynchronised clock, a tainted kernel;
- OOM kills, restarts and hung tasks in the last 24 hours.

Thresholds an operator may want to change (`disk_await_warn_ms`, `exhaustion_warn`, `flap_restarts`,
`flap_window_s`) live in `[server]`.
