# fat — Fucking Awesome Top

`htop` tells you **what** is running. `fat` tells you **why**, **since when**, **what it costs**
(CPU, RAM, watts, GPU, disk, network, ports), and lets you do something about it **safely**
(pause before kill, undo everything).

There is one engine with two interfaces:

- **A terminal UI for humans.** It is built with ratatui and has live, tree and time-travel views.
- **An MCP / JSON interface for agents.** Every view is also a tool or a `--json` flag.

What makes it different:

- **Flight recorder with time travel.** `fat record` keeps about 3 days of compact history in SQLite (around 27 MB/day at 2s).
  In the TUI you can scrub back to the moment the fan spun up and see which process caused it.
- **Blame chains.** `fat why <pid>` gives the cause, not just a number. For example:
  "mds_stores is hot → Spotlight is indexing → because `npm install` in ~/code/app is writing 40k files → add `.metadata_never_index`".
  It shows the ancestry (shell / terminal / editor / agent / launchd), how long the process has been hot, its children and what they cost, and the ports it owns.
- **Every modern resource.** Covers per-process energy (watts, from the kernel's per-task energy counters on macOS,
  RAPL package energy on Linux), GPU, thermal state and temperatures, memory pressure (and Linux PSI stall times for
  cpu, memory and io), battery, and per-process net and disk rates.
- **Ports are first-class.** Shows every listening socket and its owner, with a framework hint ("node · vite dev · ~/code/app · up 3h").
  It also flags **orphans**: dev servers whose launcher died and that were re-parented to launchd (macOS) or to init /
  a systemd user manager (Linux).
- **Safe, reversible actions.** Pause (SIGSTOP) before kill, renice, and kill a whole tree.
  Everything is journaled and `fat undo` reverses it. fat refuses to touch launchd, WindowServer, kernel_task
  (macOS), init/systemd, kernel threads and the session's display/dbus daemons (Linux),
  its own ancestors, processes owned by other users, and recycled pids.
- **Resource budgets for commands (and agents).** For example, `fat run --cpu 200 --mem 4G --time 10m -- cargo build`.
- **One tree for local, containers and ssh hosts.** Supports docker, podman, OrbStack, colima and nerdctl, plus any host that has `fat` installed.
  On Linux every process is tagged with its cgroup and container, so you can filter the process list by container name.
- **Storage: what eats your disk, and what is filling it right now.** The Fs tab and `fat fs` show disk usage of every
  directory from `/` down (a cached, low-priority background scan), which paths grew in the last 10 minutes and which
  processes are writing there, space held by deleted-but-open files, and when each volume will be full. fat only reads:
  it never deletes, moves or truncates your files.
- **Plain-language `ask`.** Ask "why is this machine hot?" and get an answer, offline from rules or richer through Claude if you set an API key.

First-class on **macOS** (developed on Apple Silicon, macOS 15) and **Linux** (x86_64 and aarch64, kernel 4.20+ for PSI,
cgroup v2 recommended). On Linux it reads procfs and sysfs directly. It never needs `sudo`; root only adds visibility
(see [Linux](#linux)).

## Install

```sh
cargo install --path .
# or: cargo build --release && cp target/release/fat ~/.local/bin/
```

## Quick tour

```sh
fat                         # the TUI
fat snapshot [--json] [--top 25]
fat ports [--json]          # listeners, owners, ⚠ orphans
fat why <pid> [--json]      # blame chain + evidence + suggested fixes
fat doctor [--json]         # whole-machine diagnosis, ranked crit > warn > info
fat ask "why is this machine hot"

fat record                  # flight recorder (foreground; run it under launchd / systemd / tmux)
fat history --since 1h      # timeline (avg cpu/mem/power, top process per bucket)
fat history --since 1h --spikes
fat history --at 10m        # the machine as it was 10 minutes ago

fat pause <pid>             # SIGSTOP — undoable
fat resume <pid>            # SIGCONT
fat renice <pid> 10         # lower priority
fat kill <pid> [--tree] [--force]
fat undo [id]               # undo last (or a specific) action
fat log [--json]            # action journal

fat run --cpu 150 --mem 2G --time 10m --procs 64 --on-violation pause|kill|warn -- <cmd...>
fat fleet [--json]          # containers + ssh hosts

fat fs [PATH] [--depth N] [--top 25] [--wait 2m] [--json]   # disk usage of PATH's children (default /)
fat fs --growth [--since 10m] [--under PATH] [--json]     # what is eating space right now
fat fs --volumes [--json]                                 # capacity, fill rate, ETA to full, I/O
fat fs --largest 20 PATH                                  # biggest files / dirs below PATH
fat mcp                     # MCP server on stdio
```

How `fat run` enforces a budget:

- It runs the command in its own process group and checks the whole tree every 500 ms.
- **CPU** is in per-core percent, so 100 means one full core. A CPU breach must persist for two consecutive checks to count.
- **pause** (the default) stops the group and prints how to resume it. **kill** sends TERM, then KILL after 3 seconds.
- A `--time` overrun always stops the job, unless the policy is `warn`.
- The exit code is the child's own, or 128 + the signal number if it was killed.

### TUI keys

| Key | Action |
| --- | --- |
| `1`–`7`, `Tab` | views: Procs · Ports · Fs · Fleet · Timeline · Doctor · Log |
| `↑↓ PgUp PgDn g G` | move |
| `c m p n d i N` | sort by cpu · mem · power · net · disk · pid · name (press again to reverse) |
| `t` | process tree |
| `/` | filter by name, command line, container name / id / image, or cgroup path (`Esc` clears it) |
| `Enter` / `w` | why: the blame chain (a side panel at 120+ columns, otherwise an overlay) |
| `space` / `z` | pause / resume |
| `r` | renice (default +10) |
| `k` / `K` | terminate / terminate the whole tree (asks for confirmation; in Ports, `k` kills the tree) |
| `u` | undo the last action |
| `← → [ ] { }` | time travel through history (`{ }` = ×10) |
| `s` · `+`/`-` | jump to the next spike · zoom the window (5m … 24h) |
| `L` / `Esc` | back to live |
| `?` | ask in plain language |
| `h` | help |
| `q` / `Ctrl-C` | quit |

In the **Fs** tab: `⏎` / `→` / `l` opens a directory, `←` / `Backspace` goes up, `s` cycles the sort (size · growth ·
io · name · files · age), `g` toggles the growth view, `w` (or `+`/`-`) cycles the window (10m · 1h · 24h), `b` lists the
biggest entries below here, `r` rescans this directory, `/` filters, and `⏎` on a writer row explains that process.
`h` stays help and `L` stays "back to live", as in every other view.

While you are rewinding, every view shows a big `⏪ REWIND hh:mm:ss` badge, and actions are refused because they would hit processes from the past.
In the Doctor view, `Enter` runs a finding's suggested action after you confirm it.

## For agents: MCP

```sh
claude mcp add fat -- /path/to/fat mcp
```

For any other MCP client, use this JSON config:

```json
{
  "mcpServers": {
    "fat": { "command": "/Users/you/.cargo/bin/fat", "args": ["mcp"] }
  }
}
```

The server provides these tools:

- **Read-only:** `snapshot`, `process`, `ports`, `why`, `doctor`, `history`, `find_port_owner`, `containers`, `ask`.
  `snapshot` takes `sort`, `limit`, `filter` and `container` (a container name or id prefix: only that container's
  processes). Its result includes `psi`, `temp_c` and `power_source` (null where the platform has none), and each
  containerised process carries `container` (12-char id), `container_name` and `cgroup`.
- **Storage (read-only):** `fs_volumes` (capacity, `fill_bps`, `eta_full_s`, I/O), `fs_list {path, depth?, limit?,
  wait_seconds?}` (du-style children with `known` advice for common space hogs), `fs_largest {path, n?}` and
  `fs_growth {since?, under?}` (growing paths with their writers and evidence, top writers, deleted-but-open files).
- **Destructive, annotated as such:** `pause`, `resume`, `renice`, `kill`, `undo`.

Every result carries the same object twice: as pretty JSON text and as `structuredContent`.
Every action returns an id that `undo` accepts. The same safety rules as the CLI apply.
For one-off scripting, every CLI view also has `--json`.

## Configuration

`~/.config/fat/config.toml`, or `$XDG_CONFIG_HOME/fat/config.toml`. Every key is optional.

```toml
interval_ms  = 1500        # TUI / recorder sample interval (the recorder uses at least 1000)
containers   = true        # docker / podman / orbstack / colima
history_days = 3           # flight-recorder retention
# history_path = "~/.local/share/fat/history.db"

[ask]
enabled = true             # use the Claude API when ANTHROPIC_API_KEY is set
model   = "claude-opus-5-5"

[[hosts]]
name     = "devbox"
ssh      = "me@devbox.local"   # defaults to name; uses BatchMode, 3s connect timeout
fat_path = "~/.cargo/bin/fat"  # defaults to "fat"
```

## Storage

Three questions, one tab (`3`, right after Ports) and one command (`fat fs`):

- **What eats my storage?** The table lists the children of the current directory with their allocated size (hard
  links counted once), a bar and share of the parent, files below, and the age of the newest change. Drill in with `⏎`,
  go up with `←`. A dir with `⛁` is another filesystem (not counted), `🔒` could not be read, `…` is still being scanned
  (numbers are a lower bound). The line under the table explains well-known space hogs with safe advice: `~/Library/Caches`,
  Xcode DerivedData and CoreSimulator, Docker Desktop and OrbStack data, `~/.cargo/registry`, Rust `target/`,
  `node_modules`, `~/.npm`, `~/.cache`, Chrome profiles, `/private/var/vm` (swap), `/private/var/folders`, APFS local
  snapshots; on Linux `/var/log/journal` (`journalctl --vacuum-size`), `/var/lib/docker` (`docker system df` / `prune`),
  `/var/cache/apt`, snap revisions.
- **What is eating my space so fast?** The Δ column shows how much each child grew in the window (10m, 1h or 24h; `w`
  cycles), and WRITE/s which processes write there. `g` switches to a flat list of the fastest growers anywhere, the
  space held by deleted-but-still-open files (restarting the holder frees it), and the top writing processes
  (`⏎` = why). `fat fs --growth --since 10m` prints the same.
- **Which volume, and when is it full?** The strip at the top shows every volume with used/total, the fill rate
  (`+1.2G/10m`), `full in 3h` (yellow under a day, red under 2 hours), device I/O and macOS purgeable space.

Every growth number says where it came from:

| Evidence | Meaning |
| --- | --- |
| `fsevents` | macOS FSEvents journal replay: exact paths, works retroactively (even for the time before fat started). |
| `watch` | Linux fanotify (root) or inotify watches: exact paths, only since fat started watching. |
| `open-files` | Files a writing process holds open, sized now vs earlier: attributes growth to a process. |
| `scan-diff` | Two scans of the tree compared: exact, but coarse in time. |
| `mtime≤` | Modified within the window, at its current size: an upper bound on growth. |

**How the scan behaves.** No directory is read until you open the Fs tab (or run `fat fs`); before that the TUI only
asks each mounted volume for its capacity (`statfs`, every sample, on its own thread) and, once a minute, lists the
deleted files processes still hold open, for the volume strip and `fat doctor`. Then `/` is scanned in
the background at the lowest priority (macOS `QOS_CLASS_BACKGROUND`, which also throttles its I/O; Linux nice 19 and
the idle I/O class), the directory you are looking at first, with partial results as it goes. It is held to a quarter of
a core, one core while the Fs tab is on screen, and 1.5 cores for the directory you opened; `fat fs PATH` and the MCP
`fs_*` tools run at utility priority (macOS `QOS_CLASS_UTILITY`; Linux nice 10) within the same 1.5 cores (so a first
full scan of a 20M-file Mac takes roughly 15 minutes with the tab open, longer in the background). Every 10 minutes the
tree is re-checked: directories whose entries changed, whose big files changed, that hold files written in the last hour,
or (macOS) that FSEvents reported changed are re-read; everything else waits for the 6-hourly full pass. Results are cached on disk, so the
next start shows numbers immediately, resumes an interrupted first scan instead of starting over, and refreshes them.
Sizes count APFS clones in full, like `du`, so on a Mac with many cloned files (uv, pnpm, `cp -c`) the tree can add up
to more than the volume's used space. Network, FUSE, autofs and removable mounts are never
descended automatically (open one with `⏎` to read it), and on macOS the Data volume is counted once even though
`/Users`, `/Applications`, `/private` … reach it through firmlinks. `fat record` also records volume use and directory
sizes, so rewinding (`←` in Timeline, then `3`) shows the sizes as they were, marked `⏪ as of hh:mm:ss`.

**Privacy (macOS).** Reading `~/Desktop`, `~/Documents`, `~/Downloads`, Mail, Messages, Photos libraries and removable
or network volumes from a terminal triggers "Terminal would like to access …" prompts unless the terminal has Full Disk
Access. The background scan never reads those places: they show as `🔒 protected` and are not counted. Pressing `⏎`
on one (or `fat fs ~/Documents`, or the `fs_list` tool) reads it because you asked. If the terminal already has Full
Disk Access, fat detects it and scans everything.

**fat never deletes.** No key, command or tool removes, moves or truncates files; fat only writes its own cache and
database. The advice it prints is for you to act on.

Doctor adds storage findings: a volume ≥ 90% full (crit at 97%), a volume that will be full within a day (crit within
2 hours, naming the paths and processes growing), more than 1 GiB held by deleted-but-open files (naming the process to
restart), and large swap files in `/System/Volumes/VM`.

## Linux

Everything works on Linux, and several things work better than on macOS, because Linux exposes more of the
kernel's own accounting. fat reads procfs and sysfs directly. A sample of about 1,000 processes takes roughly
10–30 ms, and the sample path spawns no subprocesses. The only child processes are `ss` (every 2s, for
per-process network rates) and the container CLIs (cached).

### What you get on Linux

- **PSI (pressure stall information).** The header shows `PSI cpu▂3 mem▁0 io▅12`: the share of the last 10
  seconds that tasks spent waiting for a CPU, for memory and for io. Load average can't tell you this. A busy
  machine with PSI near 0 is fine. Sustained PSI above about 10% means real contention, and `doctor` / `ask` say so.
- **Measured power.** With RAPL (Intel, and AMD Zen), system power is the CPU package's real energy counter
  (the `package-N` zones; a laptop's `psys` platform zone is used only when there is no package zone, since it
  already contains the package), shown as `48.2W rapl`. Each process gets its share of the machine's CPU capacity
  (one of 8 cores busy = 1/8 of package power), so the idle and uncore baseline stays unattributed. Without RAPL
  access it falls back to a CPU-time model, shown as `~8.0W est`.
- **Temperatures.** The hottest hwmon sensor or thermal zone (`THERM 71°C`). The thermal *state* (throttling)
  only comes from CPU sources at their real trip points (thermal-zone passive/hot/critical trips, coretemp /
  k10temp limits): a hot NVMe or a CPU at 80°C under a build is hot, not throttled.
- **Container limits.** When fat itself runs in a cgroup with `memory.max` / `cpu.max` / a cpuset (a container
  started with `--memory`, `--cpus`, `--cpuset-cpus`), memory total and used, memory pressure, PSI, the core
  count and CPU% are the container's (CPU% is of its quota), not the host's `/proc/meminfo` and cores.
- **System disk and network totals** come from `/proc/diskstats` (whole disks) and `/proc/net/dev` (all but
  `lo`), which are world-readable, so they are right without root even though other users' per-process io isn't.
- **Containers as first-class processes.** Each process's cgroup v2 path (`/system.slice/docker-<id>.scope`,
  `…/libpod-<id>.scope`, kubepods, …) gives its container id. The procs table gets a **CONTAINER** column
  (the container's name when the runtime reports it, otherwise the short id), and `/db-1` filters to that
  container's processes. The Why panel shows the cgroup and container. The Fleet view counts each container's
  processes.
- **cgroup-based budgets.** `fat run` measures the whole tree from procfs, including children that already exited.
  When it can create a cgroup v2 child (as root, or inside a delegated subtree such as a systemd user scope), the
  kernel backs the budget so a sudden allocation or a fork bomb can't outrun the poll, while the policy keeps
  its meaning:
  - `--cpu`: `cpu.max` holds the job at its quota. A job throttled in most periods wants more than its budget,
    which is a cpu violation, so `pause` and `kill` fire as on macOS (`warn` sets no limit and only reports).
  - `--mem` with `pause` (the default): `memory.high` just above the budget slows the job down (no kill) and
    `memory.max` well above it is only a backstop; the poll pauses the job at the breach, and it can be resumed.
    With `kill`, `memory.max` sits at the budget and an OOM kills the whole job (`memory.oom.group`).
  - `--procs`: `pids.max` as a backstop (16 × procs + 256 tasks; it counts threads), with the exact process
    count polled.

  As root it creates `/sys/fs/cgroup/fat.slice/run-<pid>-<random>` (never inside a container's cgroup-namespace
  root that holds processes); as a normal user it starts a transient `systemd-run --user --scope` itself (this
  needs a user manager: on a headless box run `loginctl enable-linger $USER` once; if systemd-run fails, the
  command is started directly and polled). When fat itself runs inside a limited cgroup (another `fat run`, a
  container with `--memory`/`--cpus`), it makes no new cgroup, which would escape those limits: the job stays
  under them and this budget is polled. Processes that leave the job's cgroup (`systemd-run --scope`) are
  noticed and polled too. Otherwise it polls every 500 ms, as on macOS. The first line of output says which
  mechanism is enforcing. `FAT_BUDGET_MODE=auto|cgroup|poll` forces a choice.

- **Ports and orphans without lsof.** Ports come from `/proc/net/{tcp,tcp6,udp,udp6}` of fat's own network
  namespace and of every other one it can see (`/proc/<pid>/net/*`; all containers' as root, tagged "in
  container <id>"), and owners from `/proc/<pid>/fd`. As root, per-process traffic is also read from each
  container's namespace (`nsenter -n ss`). A dev server re-parented to pid 1 or to a `systemd --user` subreaper is flagged as an orphan.

### Data sources

| Data | macOS | Linux |
| --- | --- | --- |
| Process list, cpu, memory, threads, nice | `proc_pid_rusage`, `proc_pidinfo`, `sysinfo` | `/proc/<pid>/stat`, `status` |
| Per-process disk I/O | `proc_pid_rusage` | `/proc/<pid>/io` (own processes, or all as root); system totals `/proc/diskstats` |
| Per-process network | `nettop` | `ss -tinpeH` tcp_info byte counters (own sockets, or all as root, every netns); system totals `/proc/net/dev` |
| Power | per-task energy (`ri_energy_nj`) → `rusage` | RAPL `/sys/class/powercap/intel-rapl:*/energy_uj` → `rapl`, else CPU-time model → `estimate` |
| Memory pressure | `kern.memorystatus_vm_pressure_level` | `/proc/pressure/memory`, `/proc/meminfo` |
| CPU / io pressure | none | `/proc/pressure/{cpu,io}` (PSI, kernel 4.20+, `psi=1`) |
| Thermal | `pmset -g therm` (state word) | `/sys/class/hwmon/*/temp*_input`, `/sys/class/thermal/thermal_zone*` (°C) |
| Battery | `pmset -g batt` | `/sys/class/power_supply/BAT*` |
| GPU | `ioreg -c IOAccelerator` | `/sys/class/drm` and DRM fdinfo; `nvidia-smi` if installed |
| Listening ports | `lsof` | `/proc/net/*` + `/proc/<pid>/fd` |
| cgroup / container | none | `/proc/<pid>/cgroup` (v2) → container id; names from docker / podman / nerdctl |
| Containers | docker / podman (OrbStack, colima contexts) | docker / podman (incl. the podman-docker shim), nerdctl fallback |

On a kernel without PSI, RAPL, hwmon or a battery (many VMs and containers), those fields are simply absent.
The header leaves them out and nothing errors.

### Root vs non-root

fat never needs root on Linux. As a normal user:

- **All processes**, with cpu, memory, threads, state, cgroup and container, because `stat`, `status` and `cgroup` are world-readable.
  (With `hidepid=2` on `/proc` you only see your own.)
- **Disk rates, cwd and exe for your own processes only.** For other users these read 0 / empty (the system
  disk and network totals are still complete).
- **Network rates for your own sockets only**, because `ss` hides other users' pids.
- **Listeners for every port, but owners only for your own.** Others show as pid 0, "owner hidden (needs root)".
- **No RAPL.** `energy_uj` has been root-only since CVE-2020-8694, so power is `~est`. To allow it for a group, use
  `sudo chmod g+r /sys/class/powercap/intel-rapl:*/energy_uj` with a udev rule.

As root, or with `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH`, you also get every process's io, cwd and exe, every
socket's owner and traffic, measured RAPL power, and kernel-enforced budgets. Actions still refuse to signal
other users' processes unless you are root, and they never touch pid 1, kernel threads or fat's own ancestors.

### Install

```sh
# needs Rust 1.85+ and a C compiler (SQLite is bundled); no other system libraries
cargo install --path .
# or build once and copy the binary to other machines of the same arch and libc
cargo build --release && install -m755 target/release/fat ~/.local/bin/   # Debian/Ubuntu: apt install build-essential
```

`ss` (iproute2) is used for per-process network rates if present. Everything else is read from `/proc` and `/sys`.

### Running in a container

Inside a container, fat sees the container's own pid namespace: its processes, with cgroup `/`. To see the whole host,
share the host's pid namespace (and cgroup namespace, for container attribution):

```sh
docker run --rm -it --pid=host --cgroupns=host --network=host \
  -v /sys:/sys:ro -v "$HOME/.local/share/fat:/root/.local/share/fat" \
  my-image-with-fat fat
```

- `--pid=host` gives the whole host's process tree.
- `--cgroupns=host` gives real cgroup paths, so the CONTAINER column works.
- `--network=host` makes `/proc/net/*` and `ss` show the host's sockets.
- Add `--privileged`, or `--cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH`, for root-level visibility (RAPL, other users' io and sockets).

In Kubernetes the equivalent is a DaemonSet with `hostPID: true` and `hostNetwork: true`.

### Keep the flight recorder running

**Linux (systemd user unit).** Save this as `~/.config/systemd/user/fat-record.service`:

```ini
[Unit]
Description=fat flight recorder
After=default.target

[Service]
ExecStart=%h/.cargo/bin/fat record
Restart=on-failure
RestartSec=5
Nice=10
IOSchedulingClass=idle
# fat record needs no privileges
NoNewPrivileges=yes

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now fat-record
sudo loginctl enable-linger "$USER"   # keep recording while you are logged out
journalctl --user -u fat-record -f    # logs
```

For a whole-machine recorder that sees everyone's io and power, install the same unit as a system service in
`/etc/systemd/system/` with `ExecStart=/usr/local/bin/fat record` and run it as root.

**macOS (launchd agent).** Save this as `~/Library/LaunchAgents/dev.fat.record.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>dev.fat.record</string>
  <key>ProgramArguments</key>  <array><string>/Users/you/.cargo/bin/fat</string><string>record</string></array>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>ProcessType</key>       <string>Background</string>
  <key>LowPriorityIO</key>     <true/>
  <key>StandardErrorPath</key> <string>/tmp/fat-record.log</string>
</dict>
</plist>
```

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.fat.record.plist
launchctl kickstart -k gui/$(id -u)/dev.fat.record    # restart after upgrading fat
```

## Design notes

**Architecture.** `collect` (one `Collector`) → `model::Snapshot` → consumed by `tui`, `mcp`, `history`,
`blame`, `ask` and `actions`. The TUI and MCP are thin. Every module is wrapped so that a failure in one
(for example, docker not installed) degrades to "unknown" or an empty list instead of crashing the program.

**Data sources (macOS, all unprivileged).** For the Linux sources, see [Linux](#linux).

| Data | Source | Notes |
| --- | --- | --- |
| CPU, energy, disk I/O per process | `proc_pid_rusage(RUSAGE_INFO_V6)` | Energy is `ri_energy_nj`, the kernel's per-task energy, shown as mW. |
| Threads, nice | `proc_pidinfo`, `getpriority` | |
| Memory, command, cwd, user | `sysinfo` | Built without its rayon thread pool, because spinning workers cost about 4% of a core. |
| Memory pressure | `sysctl kern.memorystatus_vm_pressure_level` | |
| Thermal | `pmset -g therm` | Every 10s. |
| Battery | `pmset -g batt` | Every 30s. |
| GPU utilization and memory | `ioreg -c IOAccelerator` | Every 4s. |
| Listening ports | `lsof -iTCP -sTCP:LISTEN -iUDP` | Cached 5s, with a 350 ms timeout. |
| Per-process network | `nettop -L 1` | Every 2s, in a background thread. |
| Containers | `docker` / `podman` `ps` and `stats` | Run in the background and cached 5s. |
| Remote hosts | `ssh host fat snapshot --json` | |

**No `powermetrics` and no root.** Processes owned by other users (for example WindowServer)
show as "unreadable", so system power is a lower bound.

**Flight recorder.** SQLite in WAL mode. Each sample stores one small system row. Rarely-changing data
(ports, containers, thermal) is stored only when it changes. The interesting processes (the top consumers,
port owners, paused processes and their ancestors) use keyframe + delta encoding packed into varint blobs.
`at(t)` replays from the previous keyframe. Old data is pruned hourly.

**Actions journal.** `~/Library/Application Support/fat/actions.jsonl` (Linux: `$XDG_STATE_HOME/fat`, usually `~/.local/state/fat`).
The history DB is `~/Library/Application Support/fat/history.db` (Linux: `~/.local/share/fat/history.db`).
Each entry records the pid's start time, so undo never signals a recycled pid.

**Privacy.** Everything stays on your machine: the history DB, the journal and all collection.
The one exception is `ask`. When `ANTHROPIC_API_KEY` is set (and `[ask] enabled`), it sends a compact summary to the
Anthropic API: about 20 KB at most, with the top processes, ports, containers and doctor findings. Command lines are
redacted for anything that looks like a token, key or password. Without a key, `ask` answers offline from rules.

## Performance (macOS: M3 Max, ~1,050 processes)

| What | Measured |
| --- | --- |
| `Collector::sample()` | First sample about 80 ms, then 20–30 ms. |
| `fat record` at a 2s interval | About 1.5% of one core for its own process. About 4% including the `lsof`, `nettop` and `ioreg` children it spawns. |
| TUI at 1.5s | About 2% of a core. |
| Fs background scan | Capped at 0.25 core (1 core while the Fs tab is visible). After a full scan of `/` (19.9M files): CLI peak RSS about 120 MB, TUI about 200 MB in total. |
| History writes | About 0.5 ms per sample, about 27 MB/day. |

## Known limitations

- On macOS, without root, per-process CPU and power are invisible for other users' processes, and so are their sockets and network traffic.
  On Linux, CPU and memory are visible for everyone. Only io, sockets and traffic of other users need root.
- The first sample after start has no rates. The CLI takes two samples 600 ms apart, so one-shot commands take about 1s.
- Remote hosts are shown as summary rows. You can't browse a remote process tree yet.
- A non-root user can raise nice but can't lower it again, so a renice can't be undone without root. On Linux,
  `RLIMIT_NICE` or `CAP_SYS_NICE` lifts this.
