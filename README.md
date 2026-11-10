# fat — Fucking Awesome Top

**fat is best at answering "why is my machine slow, hot or full, and what can I safely do about it?"**
- `fat` opens instantly on your processes sorted by CPU, with CPU, memory, power and thermal gauges on top.
- `fat why <pid>` says who started a process, since when and what it costs; `fat doctor` ranks what is wrong.
- `fat fs --growth` names the path and the process filling your disk right now.
- First aid you can take back: pause is journaled and undone with `fat undo`; so is renice, though only root can lower
  nice again. Kill can't be undone: the TUI and MCP ask first, the CLI `fat kill` acts at once.

First-class on **macOS** (developed on Apple Silicon, macOS 15) and **Linux** (x86_64 and aarch64, kernel 4.20+ for PSI,
cgroup v2 recommended). On Linux it reads procfs and sysfs directly. It never needs `sudo`; root only adds visibility
(see [Linux](#linux)).

## Install

Prebuilt binaries are on the GitHub releases page for Linux (x86_64, aarch64; fully static, any distribution) and
macOS (Apple silicon, Intel). Each release has a `SHA256SUMS` file and a signed build-provenance attestation, so
you can check a download came from this repository's release workflow:

```sh
sha256sum -c SHA256SUMS --ignore-missing          # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
gh attestation verify fat-<version>-<target>.tar.gz --repo <owner>/<repo>
tar -xzf fat-<version>-<target>.tar.gz && install -m 755 fat-<version>-<target>/fat ~/.local/bin/
```

From source (Rust 1.89+ and a C compiler; SQLite is bundled):

```sh
cargo install --locked --path .
# or: cargo build --release --locked && cp target/release/fat ~/.local/bin/
```

## Quick tour

`fat --help` groups the commands the same way.

```sh
# Everyday
fat                         # the TUI: processes by CPU (h for keys)
fat snapshot [--json] [--top 25]
fat ports [--json]          # listeners, owners, ⚠ orphans
fat fs [PATH] [--depth N] [--top 25] [--wait 2m] [--json]   # disk usage of PATH's children (default /)
fat fs --growth [--since 10m] [--under PATH] [--json]     # what is eating space right now
fat fs --volumes [--json]                                 # capacity, fill rate, ETA to full, I/O
fat fs --largest 20 PATH                                  # biggest files / dirs below PATH
fat why <pid> [--json]      # blame chain + evidence + suggested fixes
fat doctor [--json]         # whole-machine diagnosis, ranked crit > warn > info
fat ask "why is this machine hot"
fat ask --dry-run "why is this machine hot"   # print the exact (redacted) API request; send nothing

# Actions (journaled)
fat pause <pid>             # SIGSTOP; undoable
fat resume <pid>            # SIGCONT
fat renice <pid> 10         # lower priority; journaled, but undoing it needs root
fat kill <pid> [--tree | --force]  # TERM (KILL with --force); NOT undoable; no prompt
fat undo [id]               # undo the last pause/renice (or a specific one)
fat log [--json]            # action journal

# Flight recorder
fat record                  # foreground; see "Run the flight recorder always-on" below
fat history --since 1h      # timeline (avg cpu/mem/power, top process per bucket)
fat history --since 1h --spikes
fat history --at 10m        # the machine as it was 10 minutes ago
fat services [--failed] [--kind systemd|container|k8s-pod|cgroup] [--json]   # services: state, restarts, flapping, OOM kills, throttling
fat events [--since 2h] [--kind oom-kill,unit-failed]... [--json]   # what happened, in order
fat what-happened [--at 03:12] [--window 15m] [--json]         # the incident: causal chain, who did it, next steps

# Advanced
fat run --cpu 150 --mem 2G --time 10m --procs 64 --on-violation pause|kill|warn -- <cmd...>
fat fleet [--group G] [--tag T] [--host GLOB] [--sort health|cpu|mem|disk] [--json]   # every host's health, findings across hosts
fat fleet doctor | events --since 2h | hosts | containers
fat fleet --host db-01 what-happened --at 03:12           # one host's incident, read-only
fat fleet exec-readonly kernel --json                     # one allowlisted read-only fat command everywhere
fat mcp                     # MCP server on stdio
```

### TUI keys

| Key | Action |
| --- | --- |
| `1`–`5`, `Tab` | views: Procs · Ports · Fs · Timeline · Doctor (`6` Fleet appears only when containers run or hosts are configured). The server profile numbers them Services · Procs · Events · Ports · Fs · Timeline · Doctor · Fleet (`1`–`8`) |
| `↑↓ PgUp PgDn g G` | move |
| `c m p n d i N` | sort by cpu · mem · power · net · disk · pid · name (press again to reverse) |
| `t` | process tree |
| `/` | filter by name, command line, container name / id / image, or cgroup path (`Esc` clears it) |
| `Enter` / `w` | why: the blame chain (a side panel at 120+ columns, otherwise an overlay) |
| `space` / `z` | pause / resume (undoable) |
| `r` | renice (default +10; undoing it needs root) |
| `k` / `K` | terminate / terminate the whole tree (asks for confirmation; **not undoable**; in Ports, `k` kills the tree) |
| `u` | undo the last pause or renice |
| `a` | action log (an overlay on any view): everything fat did; `⏎` undoes the selected entry if it can be undone |
| `← → [ ] { }` | in Timeline (`4`): time travel through history (`{ }` = ×10) |
| `s` · `+`/`-` | in Timeline (`4`): jump to the next spike · zoom the window (5m … 24h) |
| `L` / `Esc` | back to live |
| `?` | ask in plain language |
| `h` | help |
| `q` / `Ctrl-C` | quit |

In the **Fs** tab: `⏎` / `→` / `l` opens a directory, `←` / `Backspace` goes up, `s` cycles the sort (size · growth ·
io · name · files · age), `g` toggles the growth view, `w` (or `+`/`-`) cycles the window (10m · 1h · 24h), `b` lists the
biggest entries below here, `r` rescans this directory, `/` filters, and `⏎` on a writer row explains that process.
`h` stays help and `L` stays "back to live", as in every other view.

#### Server profile in the TUI

On a server (see "Servers" below for how the profile is chosen) the TUI opens on **Services** and the header shows
what matters at 3am instead of laptop gauges: CPU with steal (`st`), iowait (`wa`) and irq shares plus the run and
blocked queues (`R` / `D`: a high load with an idle CPU is usually `D`), memory with MemAvailable, PSI some/full and
swap traffic, then OOM kills (last 24h from the recorder, or this session), failed / flapping units, fd, conntrack and
ephemeral-port use, the worst disk await, and read-only remounts, degraded RAID or an unsynced clock when present.
Colours follow `[server] exhaustion_warn` and `disk_await_warn_ms`, not built-in numbers.

**Services** lists systemd units, containers (any runtime), pods and plain cgroups as rows: state, CPU, memory and its
limit, I/O, restarts (recent / total), CPU throttling, processes. Failed units come first (`✗`, red), then flapping
ones (`⟳`), then units in transition; inactive units are hidden until `i` (the title says how many). `⏎` explains the
unit: what it is (cgroup, main pid, container image / pod), its resources against its limits, its processes, its
recent events, and read-only commands to look closer (`journalctl -u …`, `<runtime> logs …`, `kubectl describe pod …`,
chosen from what was detected). `w` explains the unit's main process, `W` asks what happened in the last 15 minutes.

| Key (Services) | Action |
| --- | --- |
| `s c m d r N` | sort by state (problems first) · cpu · mem · io · restarts · name (again reverses) |
| `t` · `f` · `i` | group by kind · problems only · show inactive units |
| `/` | filter by name, description, state, kind, runtime, image, pod or cgroup |

**Events** is the incident timeline: OOM kills, failed / restarting / flapping units, deploy bursts, disk latency
spikes and errors, filling or read-only filesystems, hung tasks and kernel warnings, throttling, pressure spikes,
exhaustion of fds / conntrack / ports / memory limits, clock problems. It merges the recorder's events (when
`fat record --server` runs) with the ones this session saw. `⏎` on an event asks the incident engine what happened
around it and shows the chain from symptom to cause, who is to blame, the evidence, read-only next steps and which
data was missing. `f` cycles the minimum severity, `+`/`-` the window (15m · 1h · 6h · 24h · 7d), `W` explains
the last 15 minutes (or the rewind moment), `/` filters.

**Fleet** (any profile, as soon as the inventory has hosts: `[[hosts]]`, `[fleet] hosts_file`, or ssh config
entries when enabled) is a health table of every host. Polls run only while the tab is on screen, every
`[fleet] tui_refresh_s` seconds after the previous one ends (`r` polls now), never two at once, with at most
`[fleet] concurrency` ssh sessions; rows stream in as hosts answer. Sort with `H` health (worst first, unreachable
hosts lowest) · `c` cpu · `m` mem · `d` disk · `f` findings · `n` name · `l` latency, filter with `/` (name,
group, tag, finding, error). `→` moves to the fleet findings panel (findings grouped across hosts, worst first);
`⏎` there narrows the table to the affected hosts. `⏎` on a host drills into its snapshot, fetched read-only with
the same allowlisted `fat snapshot` call (`d` doctor · `u` units · `p` procs, `r` refresh, `Esc` back). Nothing in
the Fleet tab can act on a remote host.

While you are rewinding, every view shows a big `⏪ REWIND hh:mm:ss` badge, and actions are refused because they would hit processes from the past.
In the Doctor view, `Enter` runs a finding's suggested action after you confirm it.
`doctor` and `why` never suggest pausing or killing a *hub*, a process whose cost is really other work: a VM host
(OrbStack Helper, Docker Desktop's VM, qemu, UTM), a container runtime, shim or a container's pid 1, init, a browser's
or Electron app's main process, your shell, terminal, tmux, ssh or agent session, WindowServer, the kernel. They
name the workload instead ("OrbStack 2.8G (VM: containers db 328M ...)": `docker stop db`, or lower the VM memory
limit; "Brave 4.1G across 23 processes": close heavy tabs). GUI apps get "quit <App>", and root/system services get
service-manager advice. Memory findings rank whole apps and VMs, not single processes. Only your own CLI/dev
processes get a runnable `pause` / `kill`.
The same gate guards the actions themselves: MCP `pause` and `kill` refuse a hub (and a tree with one inside) and
name the workload instead, and in the TUI, pausing or terminating one (`space`, `k`, `K`, also in Ports, where a
forwarded container port belongs to the VM host) asks first and says what it hosts.

## Run the flight recorder always-on (optional)

Time travel (`←` in the TUI's Timeline view, `fat history`) only has data for the times something was recording: the TUI records while
it is open, and `fat record` records in the foreground. To record all the time, run `fat record` as a background
service. fat does not install one for you; copy and paste one of these. Disk use is about 27 MB per day at the default
interval, kept for `history_days` (default 3, so about 80 MB; see [Configuration](#configuration)). The recorder runs
at low CPU and I/O priority and uses about 1–2% of one core.

**macOS (launchd LaunchAgent).** This writes `~/Library/LaunchAgents/dev.fat.record.plist` with the absolute path of
your `fat` (launchd does not expand `~`), checks it, and starts it:

```sh
FAT="$(command -v fat || echo "$HOME/.cargo/bin/fat")"
mkdir -p ~/Library/LaunchAgents ~/Library/Logs
cat > ~/Library/LaunchAgents/dev.fat.record.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>dev.fat.record</string>
  <key>ProgramArguments</key>  <array><string>$FAT</string><string>record</string></array>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>ThrottleInterval</key>  <integer>30</integer>
  <key>ProcessType</key>       <string>Background</string>
  <key>LowPriorityIO</key>     <true/>
  <key>Nice</key>              <integer>10</integer>
  <key>StandardOutPath</key>   <string>$HOME/Library/Logs/fat-record.log</string>
  <key>StandardErrorPath</key> <string>$HOME/Library/Logs/fat-record.log</string>
</dict>
</plist>
PLIST
plutil -lint ~/Library/LaunchAgents/dev.fat.record.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.fat.record.plist
```

- Check: `launchctl print gui/$(id -u)/dev.fat.record | grep -E 'state|pid'`, `tail ~/Library/Logs/fat-record.log`
  (its first line says where it writes), and after a minute `fat history --since 5m`.
- After upgrading fat: `launchctl kickstart -k gui/$(id -u)/dev.fat.record`.
- Uninstall: `launchctl bootout gui/$(id -u)/dev.fat.record && rm ~/Library/LaunchAgents/dev.fat.record.plist`.
  The history stays in `~/Library/Application Support/fat/history.db`; delete it yourself if you want it gone.

**Linux (systemd user unit).** Save this as `~/.config/systemd/user/fat-record.service` (change the `ExecStart` path
if fat is not in `~/.cargo/bin`):

```ini
[Unit]
Description=fat flight recorder (fat record)

[Service]
ExecStart=%h/.cargo/bin/fat record
Nice=19
IOSchedulingClass=idle
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now fat-record
loginctl enable-linger "$USER"   # keep recording while you are logged out, and from boot (may need sudo)
```

- Check: `systemctl --user status fat-record`, `journalctl --user -u fat-record -n 20`, and after a minute
  `fat history --since 5m`.
- After upgrading fat: `systemctl --user restart fat-record`.
- Uninstall: `systemctl --user disable --now fat-record`, then `rm ~/.config/systemd/user/fat-record.service` and
  `systemctl --user daemon-reload` (and `loginctl disable-linger "$USER"` if you enabled it only for this). The
  history stays in `~/.local/share/fat/history.db`.

<!-- recorder-export -->
### Servers: system-wide recorder with Prometheus export (Linux)

On a server, run the recorder once for the whole machine, as a system service. In the **server profile** it
records more than processes:

- every unit: systemd services, containers from any runtime, Kubernetes pods, and plain cgroups.
  Each unit's state, restarts, CPU, memory and its limit, I/O, CPU throttling, PSI and OOM kills are recorded.
- kernel health: steal, iowait, PSI, disk latency, D-state processes, and fd, conntrack and ephemeral-port use.
- an **event log**: OOM kills with victim and cgroup, unit failures, restarts and flapping, kernel warnings, hung
  tasks, disk errors, read-only remounts, throttling, pressure, exhaustion, and per-unit CPU or memory spikes. A
  volume about to fill is logged too. On start the recorder imports the kernel log backlog, so OOM kills from
  before the daemon started are on the timeline.

fat picks the server profile by itself on a Linux host with no graphical session and no battery. To choose it
yourself, pass `--server`, set `[server] profile = "server"`, or set `FAT_PROFILE=server`.

When the recorder runs as root in the server profile it writes to `/var/lib/fat/history.db`. If that file exists,
every user's `fat` reads it: `fat history`, `fat events`, `fat what-happened`, the TUI, and `fat snapshot --fast`.
`fat snapshot --fast` opens it read-only and returns the newest sample, so a fleet poll costs one SQLite read
instead of a live sample. Readers need read access to the database and its `-wal`/`-shm` files. They are
world-readable by default (umask 022). Process command lines in them are already visible in `/proc` to every user
unless `/proc` is mounted with `hidepid`; on such hosts set `UMask=0077` in the unit and read as root. A fat
of another version never changes that database: readers (`doctor`, `why`, `history`, `ask`, `fs`, the fleet's
remote commands) open it read-only and refuse a schema they do not know, and only `fat record` replaces it, after
moving the old file aside to `history.db.schema-v<N>`.

Save this as `/etc/systemd/system/fat-record.service` (adjust the `ExecStart` path):

```ini
[Unit]
Description=fat flight recorder (server profile)
After=network.target

[Service]
ExecStart=/usr/local/bin/fat record --server --export prometheus
# Optional config (e.g. [server] record_interval_ms); without it the defaults apply.
Environment=XDG_CONFIG_HOME=/etc
# Creates /var/lib/fat (the only writable path below).
StateDirectory=fat
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
Restart=on-failure
RestartSec=10
# Hardening: read-only system, no privilege gain, only the capabilities fat reads with.
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_SYSLOG
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
# Safety net, well above the measured footprint below.
MemoryMax=256M

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now fat-record
curl -s 127.0.0.1:9877/metrics | head     # if you kept --export
```

Why each capability is kept (fat never signals anything from the recorder, so it needs only read access):

| Capability | What it reads | Without it |
|---|---|---|
| `CAP_SYS_PTRACE` | passes the kernel's ptrace access check on `/proc/<pid>/{io,fd,exe,cwd}` of other users' processes: per-process disk I/O, executable and cwd, and which process owns a port | those fields only for root's own processes |
| `CAP_DAC_READ_SEARCH` | files owned by other users without read permission for others, such as `/proc/<pid>/io` (mode 0400, owned by the process's user) and container runtime state | the same fields stay empty (it is needed together with `CAP_SYS_PTRACE` for `/proc/<pid>/io`) |
| `CAP_SYSLOG` | `/dev/kmsg` when `kernel.dmesg_restrict=1`: OOM kills (victim, cgroup, RSS), hung tasks, I/O and filesystem errors | no kernel-log events; OOM kills are still counted from `/proc/vmstat`, without a victim |

Some hardening options are left out on purpose. `ProtectKernelLogs` and `PrivateDevices` hide `/dev/kmsg`.
`ProtectClock` blocks the read-only `adjtimex` call that tells whether the clock is synchronised.
`IOSchedulingClass=idle` and `Nice=19` would starve the recorder during exactly the I/O or CPU storm you want
recorded.

**Prometheus export.** `--export prometheus` serves `GET /metrics` (text format 0.0.4) from the recorder's newest
in-memory sample. It binds `127.0.0.1:9877`. Use `--listen ADDR` or `[server] export_listen` to change that, or
`[server] export_enabled = true` to serve without the flag. A non-loopback address prints a warning: the metrics
name units, disks and mounts, so exposing them is your decision, behind your own firewall. The server is one
thread on `std::net`, one request at a time, with 5 s timeouts. It is not TLS; put a proxy in front if you need TLS.

Metrics, all prefixed `fat_`:

- host: `up`, `info{version,profile}`, `cpu_percent`, `cpu_steal_percent`, `cpu_iowait_percent`, `load{period}`,
  `memory_{total,used,available}_bytes`, `swap_used_bytes`, `pressure_percent{resource,kind}`
- kernel: `oom_kills_total`, `procs_blocked`, `dstate_procs`, `fd_{used,max}`, `conntrack_{used,max}`,
  `ephemeral_ports_used`, `ephemeral_ports_range_size`, `tcp_retrans_per_second`, `listen_drops_per_second`
- disks and volumes: `disk_util_percent{disk}`, `disk_await_ms{disk,op}`, `disk_queue_depth{disk}`,
  `volume_used_ratio{mount}`
- per unit, labels `{unit,kind}`: `unit_up`, `unit_cpu_percent`, `unit_memory_bytes`, `unit_memory_limit_bytes`,
  `unit_io_bytes_per_second{op}`, `unit_restarts_total`, `unit_cpu_throttled_percent`,
  `unit_pressure_percent{resource}`, `unit_oom_kills_total`
- also `units{kind,state}`, `findings{severity}` (current `fat doctor` findings), and `events_total{kind}`
  (events since the recorder started)

Label cardinality is bounded. Units are capped by `[server] max_units`. There is no pid or command-line label.
Disk and mount labels are the host's own.

```yaml
# prometheus.yml (a Prometheus on the same host; for a remote one, --listen on an internal address)
scrape_configs:
  - job_name: fat
    static_configs:
      - targets: ["127.0.0.1:9877"]
```

**Footprint and bounds.** The server profile samples every `[server] record_interval_ms` (default 5000).
Directory scanning is off unless `[server] fs_scan = true`; volumes are still recorded. Cardinality per sample is
bounded:

- processes: the existing interesting-process selection plus the top `record_top_procs` (default 50) by CPU,
  memory and I/O and every unit's main pid; at most 200, or 3 x `record_top_procs` when that is larger. Not
  every pid.
- units: at most `max_units`, inactive ones dropped first. Units are change-point encoded: a row when state or
  numbers move, and every unit every 15 minutes.
- events: at most `max_events_per_sample`. Repeats of a persisting condition for the same subject are recorded at
  most once per `spike_cooldown_s`.
- disks: a row only while busy.

Measured with the unit above on a systemd test host with about 200 units (including one CPU-throttled unit and
two units that crash and restart every 20 s) and 125 processes:

| | measured | budget |
|---|---|---|
| CPU, 5-minute average | 0.66% of one core | < 1% |
| memory | 11 MiB RSS, 13 MiB peak | < 60 MB |
| disk, whole database | 15.5 MB/day, about 45 MB for the default 3 days | bounded by `history_days` |
| `fat snapshot --json --fast`, as a non-root user | 12 ms (28 ms cold), against about 760 ms for a live sample | |
| one `/metrics` scrape | about 5 ms | |

The disk is split roughly like this: units 26%, events 23% (almost all from the two restarting units), kernel and
disks 10%, processes, system and volumes 41%. A quiet host writes less. A host with many restarting units writes
more, within `max_events_per_sample`. Most of the CPU left is the periodic systemd refresh; on hosts with thousands
of units, raise `[server] unit_refresh_s`.

| `[server]` key | default | meaning |
|---|---|---|
| `record_interval_ms` | 5000 | server-profile sample interval |
| `max_units` | 2000 | units sampled, recorded and exported per sample |
| `max_events_per_sample` | 100 | events kept per sample; the rest are summarised in one `other` event |
| `spike_cooldown_s` | 300 | minimum gap between repeats of a level event (throttle, pressure, spikes...) per subject |
| `spike_cpu_pct` | 25 | unit CPU spike: rise above its 1-minute median, in % of host capacity (at least half a core) |
| `spike_mem_pct` | 10 | unit memory spike: growth within a minute, in % of host RAM |
| `fs_fill_eta_s` | 21600 | `fs_fill` when a volume is projected full sooner than this (crit below a sixth of it, or above 95% used) |
| `fs_scan` | false | run the directory scanner in the server recorder |
| `export_listen` / `export_enabled` | `127.0.0.1:9877` / false | Prometheus export |

Set `FAT_RECORD_PROFILE=1` to make the recorder print the average time per phase every 60 samples, for sizing it on
a new kind of host.
<!-- /recorder-export -->

Only one fat records at a time: a TUI opened while the service runs reads the service's history instead of writing
its own, and a second `fat record` waits until the first stops.

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
- **Side effects, off by default:** `pause`, `resume`, `renice`, `kill`, `undo` (annotated as destructive). An
  agent can't signal anything until you allow it in the config:

  ```toml
  [mcp]
  allow_actions = ["pause", "resume", "renice", "undo"]   # or "all"; default: none
  ```

  Disabled tools stay in `tools/list`, marked `DISABLED` in their description, and calling one returns an error that
  says how to enable it. That is deliberate: an agent that can't see the tool tends to conclude fat can't do it and
  reach for a shell `kill`, while one that reads "disabled, ask the user to add X" asks you. The refusal happens in
  the server, so a listed tool is never a way around the setting.
- **`kill` takes two calls.** The first signals nothing: it returns a preview (the process, its command and user,
  the signal, its ancestors, for `tree: true` every descendant and whether it would be skipped as protected, or why
  fat would refuse) and a `confirm_token`. The token works once, for 60 seconds, for that pid, that signal and that
  process's start time, so a pid reused in between is refused. The second call, with the token, signals.

Every result carries the same object twice: as pretty JSON text and as `structuredContent`.
Pause, resume and renice return an id that `undo` accepts; a kill is journaled but can't be undone. The same safety
rules as the CLI apply.
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

[mcp]
allow_actions = []         # side-effect tools agents may use: "pause", "resume", "renice", "kill", "undo", or "all"

[[hosts]]
name     = "web-01"
ssh      = "admin@web-01.example.com"   # defaults to name; passed to ssh verbatim
fat_path = "/usr/local/bin/fat"         # default: fat on PATH, then the usual install dirs
groups   = ["web"]
tags     = ["prod"]

[fleet]                    # see "Fleets" below; every key is optional
# hosts_file = "~/fleet.txt"
```

## Everything else it does

There is one engine with two interfaces: a ratatui terminal UI for humans (live, tree and time-travel views), and
an MCP / JSON interface for agents (every view is also a tool or a `--json` flag).

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
- **Safe actions.** Pause (SIGSTOP) before kill, renice, and kill a whole tree. Everything is journaled. Pause and
  resume are undoable (`fat undo`), renice too as root (a user can't lower nice again); TERM and KILL are not, so pause a suspect first: that gives you a
  window to see whether it was the culprit before anything is lost. fat refuses to touch launchd, WindowServer, kernel_task
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

How `fat run` enforces a budget:

- It runs the command in its own process group and checks the whole tree every 500 ms.
- **CPU** is in per-core percent, so 100 means one full core. A CPU breach must persist for two consecutive checks to count.
- **pause** (the default) stops the group and prints how to resume it. **kill** sends TERM, then KILL after 3 seconds.
- A `--time` overrun always stops the job, unless the policy is `warn`.
- The exit code is the child's own, or 128 + the signal number if it was killed.

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
  (`⏎` = why). `fat fs --growth --since 10m` prints the same. The list is as specific as the evidence allows and
  never counts bytes twice: a directory is broken down into the children that carry its growth (a home directory or
  `/` always is), and shows up itself only as "other under DIR" with what those children leave unexplained, when
  that is at least 20% of it and 10 MB. Deleted-but-open files are grouped by the process holding them; files under
  1 MB are only counted.
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
10–30 ms, and the sample path spawns no subprocesses. Per-process network rates come from a netlink
`sock_diag` dump every 2s (about 0.2–1 ms of CPU per cycle; up to about 2.5 ms as root, which also walks every
container's network namespace; versus 2–19 ms for the `ss` it replaced). The only child processes
are the container CLIs (cached), and `ss` only if netlink is unavailable.

### Target environments

Server mode assumes as little as possible about the host. Every source below is optional: when it is missing,
the matching fields stay empty and a note says why (often "needs root"); nothing fails.

- **Distribution and kernel:** any Linux distribution and any kernel version still in common use. Features that
  newer kernels add (PSI, cgroup v2, `memory.peak`) are used when present.
- **Init:** systemd is used when it is PID 1. Other inits and minimal containers work too: the cgroups that hold
  processes become the units.
- **Containers:** docker, containerd, CRI-O, podman and Kubernetes pods are recognised from the cgroup tree when
  present. None is required.
- **CPU architecture:** any target Rust supports. `scripts/build-static.sh` builds a static binary to copy to hosts.
- **Privileges:** root is optional. Without it, other users' process details, the kernel log and some
  per-cgroup files may be unreadable, and the output says so.
- **Fleets:** fat runs your `ssh` with your ssh config. It adds no network topology of its own.
- **Overhead budget for the always-on recorder:** under 1% of one core on average, under 60 MB RSS, and disk
  bounded by `history_days` (measured numbers are in the recorder section). Every limit is a config value.

macOS keeps the desktop profile and behaves as before.

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
  container's namespace (a netlink socket opened inside it with `setns`). A dev server re-parented to pid 1 or to a `systemd --user` subreaper is flagged as an orphan.

### Data sources

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

On a kernel without PSI, RAPL, hwmon or a battery (many VMs and containers), those fields are simply absent.
The header leaves them out and nothing errors.

<!-- services -->
### Services (`fat services`)

```sh
fat services                       # every unit: systemd services and scopes, containers, pods, plain cgroups
fat services --failed              # failed or flapping only
fat services --kind container --json
```

Services are the unit of thought on a server, not pids. Every unit gets a state normalised to systemd's words
(active, activating, deactivating, reloading, inactive, failed), the runtime's own sub-state, systemd's result
(exit-code, signal, oom-kill, start-limit-hit...) and exit code, lifetime restarts, restarts within
`flap_window_s` and a `flapping` flag. Each unit also gets cgroup totals for all its processes: CPU, memory and its
limit and peak, OOM kills, the share of CPU periods it was throttled by its own `cpu.max`, its CPU quota, io bytes/s and
its own PSI. Failed and flapping units sort first. The MCP tool `services` returns the same data, plus the
transitions seen since the previous call.

Sources, each optional:

- cgroup v2 files, read every sample. cgroup v1 hosts give memory, CPU and pids best effort, with no per-unit io or PSI.
- systemd, when it is PID 1. One `systemctl list-units` runs every `unit_refresh_s`. After it, one batched
  `systemctl show` reads only the units whose state, sub-state or main pid changed. Every `unit_full_refresh_s` it
  reads every unit that is not inactive.
- Containers of any runtime (docker, podman, containerd, CRI-O), found from their cgroups. Names, images, restart
  counts and Kubernetes pod and namespace come from the runtime's own state files, which need root. Without them the
  short id is the name, and a note says so.
- Without systemd (other inits, minimal containers), the cgroups that hold processes are the units.

Events are created on transitions:

- `unit_start`, `unit_stop` and `unit_failed` (crit for oom-kill, start-limit-hit, core-dump and watchdog).
- `unit_restart`, from the restart counter, or for a container that comes back after it went away. While a unit
  keeps flapping, its restarts are summed into one event per `spike_cooldown_s` (the event's value is the count),
  so a restart loop does not flood the recorder.
- `unit_flapping`, once, when `flap_restarts` restarts land within `flap_window_s`.
- `oom_kill`, from the cgroup's `memory.events`, or from systemd's `Result=oom-kill` when the cgroup died between
  samples.
- `throttle`, when a unit is throttled in `throttle_warn_pct` of its CPU periods.
- `exhaustion`, at `exhaustion_warn` of `memory.max`, not counting reclaimable page cache, or of `pids.max`.
- `deploy_burst`, when `burst_procs` new processes appear in one unit within one sample.

Level events re-arm only after the value drops well below the threshold. Session scopes do not produce start or stop
events. At most `max_units` units are kept, and inactive units are dropped first.

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

Measured cost, release build, 5 s samples, on an aarch64 VM with about 200 units (133 active): 2–7 ms per sample,
plus 5–14 ms of `systemctl` every `unit_refresh_s`. That averages 0.28% of one core, and systemd itself adds about
0.07%. A full pass costs systemd and systemctl together about 1.7 ms per unit. On a host without systemd running 7
containers, a sample costs 0.5–2 ms (0.02% of a core).

<!-- kernel -->
### Kernel health and kernel events (`fat kernel`)

```sh
fat kernel                  # 1 s sample + kernel log events of the last 24h
fat kernel --since 2h --json
fat kernel --watch [--json] # stream kernel events as they happen (Ctrl-C to stop)
```

It answers the classic "load is high but the CPU is idle" questions. Steal, iowait, irq and softirq come from
`/proc/stat`, and `procs_blocked` too. For processes in D state you get the kernel function they wait in and their
unit. PSI is reported as some and full, and each whole disk gets util %, read/write await, queue depth and iops.
Swap rates come from `/proc/vmstat`. File handles, conntrack entries and ephemeral ports are shown against their
limits. For ports, the count is the larger of distinct local ports and the connections to the busiest remote endpoint
from one local address. You also get TCP retransmits, listen overflows and drops, mounts that went read-only, ext4
error counters, degraded md arrays, kernel taint and clock sync. Clock sync uses adjtimex, with the same rule as
systemd: a maximum error under 16 s. The MCP tool `kernel` returns the same report.

Kernel log lines become events:

- `oom_kill`, with the victim pid and name, its rss, the constraint, the cgroup whose limit was hit, its unit and the
  invoking task.
- `hung_task`.
- `disk_error` (I/O, ext4, xfs, btrfs, nvme, ata errors).
- `ro_remount`.
- `exhaustion` (conntrack table full, file-max, SYN backlog, neighbour table, pids controller).
- `kernel_warn` (lockups, oopses, WARN, segfaults and traps, machine checks).
- NIC link up/down.

fat reads the kernel log from `/dev/kmsg`. That needs root or `kernel.dmesg_restrict=0`. Without it, fat tries
`journalctl -k`, which needs read access to the system journal and runs at most every `unit_refresh_s`. Without either,
a note says so, and OOM kills are still counted from `/proc/vmstat`, but without a victim.

Events are edge-triggered: one event when a condition starts, and re-armed once it falls below half the threshold.
Identical kernel-log lines within one sample are collapsed into one event with a `repeats` count. Measured cost: 0.25–1 ms
per sample on an aarch64 VM with a 7.2 kernel. The TCP socket table is rescanned at most every
`unit_refresh_s`, and a 100k-socket table scans in 9–34 ms.

| `[server]` key | default | meaning |
|---|---|---|
| `kmsg` | true | read the kernel log |
| `dstate_min_s` | 5 | report D-state processes blocked at least this long (`hung_task` event once per episode) |
| `disk_await_warn_ms` | 100 | `disk_latency_spike` when a busy disk's read or write await exceeds this |
| `exhaustion_warn` | 0.85 | `exhaustion` when fds, conntrack or ephemeral ports reach this fraction of their limit |
| `pressure_full_warn` | 10 | `pressure_spike` when PSI `full` avg10 for cpu, memory or io reaches this % |
<!-- /kernel -->

### Root vs non-root

fat never needs root on Linux. As a normal user:

- **All processes**, with cpu, memory, threads, state, cgroup and container, because `stat`, `status` and `cgroup` are world-readable.
  (With `hidepid=2` on `/proc` you only see your own.)
- **Disk rates, cwd and exe for your own processes only.** For other users these read 0 / empty (the system
  disk and network totals are still complete).
- **Network rates for your own sockets only**, because other users' `/proc/<pid>/fd` (socket owners) are unreadable.
- **Listeners for every port, but owners only for your own.** Others show as pid 0, "owner hidden (needs root)".
- **No RAPL.** `energy_uj` has been root-only since CVE-2020-8694, so power is `~est`. To allow it for a group, use
  `sudo chmod g+r /sys/class/powercap/intel-rapl:*/energy_uj` with a udev rule.

As root, or with `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH`, you also get every process's io, cwd and exe, every
socket's owner and traffic, measured RAPL power, and kernel-enforced budgets. Actions still refuse to signal
other users' processes unless you are root, and they never touch pid 1, kernel threads or fat's own ancestors.

### Install

```sh
# needs Rust 1.89+ and a C compiler (SQLite is bundled); no other system libraries
cargo install --path .
# or build once and copy the binary to other machines of the same arch and libc
cargo build --release && install -m755 target/release/fat ~/.local/bin/   # Debian/Ubuntu: apt install build-essential
```

`ss` (iproute2) is used for per-process network rates only if netlink `sock_diag` is blocked. Everything else is read from `/proc` and `/sys`.

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
- `--network=host` makes `/proc/net/*` and netlink show the host's sockets.
- Add `--privileged`, or `--cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH`, for root-level visibility (RAPL, other users' io and sockets).

In Kubernetes the equivalent is a DaemonSet with `hostPID: true` and `hostNetwork: true`.

### Keep the flight recorder running

On a server, use the system unit in [Servers](#servers-system-wide-recorder-with-prometheus-export-linux). On a
desktop, see [Run the flight recorder always-on](#run-the-flight-recorder-always-on-optional) (systemd user unit).

### What happened at 03:12, and who did it?

`fat what-happened --at 03:12` (or the MCP tool `what_happened`) picks the most important event near that time and
explains it as a chain from symptom to cause, with the numbers behind each step, the culprits, a confidence level and
read-only next steps (fat never runs them). Without `--at` it explains the last `--window` (default 15m). It reads
the flight recorder (`fat record --server`); without one it uses the current state plus the kernel log and lists
what it could not know under "Gaps". `fat events` prints the raw timeline.

| incident | what the chain shows |
| --- | --- |
| OOM kill | the victim and its unit; a cgroup limit (`memory.max`) or the whole host out of memory; which unit held the most memory just before and how fast it grew; what started shortly before |
| restart loop, failed unit | restarts in the window, result and exit status, OOM kills inside it, a package update, deploy burst, scheduled job or backup just before the first failure |
| disk latency, load high but CPU idle | the device's await before and at the peak, queue and util, processes in D state and the kernel function they wait in, iowait and steal, the unit whose I/O rose and the job that started it |
| disk filling | growth rate and time to full, the writers whose command line points at that mount, grouped |
| fd, conntrack or ephemeral-port exhaustion | usage against the limit over time, what started as it grew, the commands that show who holds them |
| noisy neighbour | a unit throttled by its own `cpu.max` (quota too small or bursty) versus another unit whose CPU or memory rose at the same time; per-unit PSI |
| read-only remount, I/O or fs errors, degraded RAID | the kernel's messages around it (crit) |

Advice is unit-oriented: `journalctl -u <unit>`, `systemctl status`, `docker|podman logs`, `kubectl describe pod`.
Databases (postgres, mysqld, mongod, redis-server, clickhouse, ...) and server plumbing (the sshd listener,
systemd-*, the logger, the message bus, time sync, VM guest agents, container runtimes) are never offered for
pause or kill, not even to an MCP agent; for a database the advice is to investigate its workload.

`fat doctor` in the server profile adds findings for failed units, restart loops, units near `memory.max` or
throttled by `cpu.max`, load high with idle CPU, slow disks, fd/conntrack/port exhaustion, accept-queue drops,
swap thrashing, read-only remounts, filesystem and I/O errors, degraded RAID, an unsynchronised clock, a tainted
kernel, and OOM kills, restarts and hung tasks in the last 24 hours. Thresholds an operator may want to change
(`disk_await_warn_ms`, `exhaustion_warn`, `flap_restarts`, `flap_window_s`) live in `[server]`.

## Fleets: one host to thousands, over ssh

`fat fleet` asks every host for one snapshot over ssh, in parallel, read-only, and summarises the fleet: a
health score per host (worst first), findings aggregated by title across hosts, hosts that could not be polled
grouped by reason, and outliers that are far from their group's median.

```sh
fat fleet                                   # summary: findings across hosts, outliers, host table
fat fleet --group web --sort cpu --top 20   # a group, busiest first, 20 rows
fat fleet doctor --json                     # findings per host
fat fleet events --since 2h --kind oom_kill --kind unit_failed   # merged timeline, needs `fat record --server`
fat fleet --host db-01 what-happened --at 03:12 --window 30m     # "what happened and who did it", on one host
fat fleet hosts                             # the inventory, no network
```

```
fleet: 120 hosts · 118 ok · 2 not polled · 2.1s (concurrency 64)

findings across hosts:
  CRIT  Disk /var is #% full: 3 hosts [web-07, web-12, db-02] (worst: web-07: Disk /var is 99% full)
  warn  not polled: auth: 1 host [cache-03]
  warn  postgres is writing #M/s: 2 hosts [db-01, db-02] (worst: db-01: postgres is writing 180M/s)

outliers (far from their group's median):
  web-07               mem_pct                94  (group web median 41, z 6.2)
```

**Inventory.** Hosts come from `[[hosts]]` in the config, an optional hosts file, and (opt-in) the `Host` aliases
of `~/.ssh/config`. They are merged by name; groups and tags select them (`--group` any of, `--tag` all of,
`--host`/`--exclude` globs). A hosts file has one host per line:

```
# name   [ssh=DEST]                 [fat=PATH]            [groups=a,b]   [tags=x,y]
web-01   ssh=admin@web-01.example.com                      groups=web     tags=prod
db-01                               fat=/opt/fat/bin/fat  groups=db
```

**ssh.** fat runs your `ssh` and leaves everything about reaching a host (users, ports, keys, jump hosts, proxies,
certificates) to your ssh config: the destination is passed verbatim and fat adds no proxy or routing options of
its own. It adds `BatchMode=yes` (never prompts), `ConnectTimeout` and `-C`; all of these are configurable, and
`ssh_options` you set take precedence. Connection sharing is left to your ssh config unless you set
`control_master = true`: fat then adds `ControlMaster=auto` (socket in `$XDG_RUNTIME_DIR/fat/ssh` or
`~/.cache/fat/ssh`) and `ControlPersist`, which override your own multiplexing settings and keep one ssh process
per polled host resident for `control_persist`, so its cost grows with inventory size. Each remote fat gets
`FAT_DEADLINE_S=<command_timeout_s>` and ends itself then, since killing the local ssh does not stop it (a
`fat_path` through sudo drops that variable). A host whose poll timed out is skipped for `timeout_backoff_s`, so a
host whose `/proc` reads hang does not collect a stuck fat per refresh. The remote command is `fat snapshot --json --fast`:
one SQLite read when the host runs the recorder, a ~0.6 s live sample otherwise. Older remote fats without
`--fast` get a plain `fat snapshot --json`. Findings are computed locally, so every host gets this fat's rules.

Numbers that are values are merged as `#` (names keep theirs: `/data1` and `/data2` stay apart), and the worst
host's own line is shown with its value; `--json` has it in `worst`.

**Errors are structured**: `unreachable`, `auth`, `host-key`, `fat-missing`, `version`, `timeout`, `too-large`,
`bad-output`, `remote-error`, each with a hint. `auth`, `host-key` and `unreachable` are reported only when ssh
itself failed (exit status 255); a "Permission denied" from the remote shell or fat is a `remote-error`. fat never
accepts host keys for you.

**Read-only.** The fleet runs only `snapshot`, `doctor`, `why`, `ports`, `services`, `kernel`, `events`,
`what-happened`, `history` and `fs` on remote hosts. There are no fleet-wide actions. One reversible action on
one host is possible, and needs three separate opt-ins:

```sh
fat fleet --host web-01 act --allow-actions pause 4242 --name backup-job
```

It talks to that host's `fat mcp`, so the host's own `[mcp] allow_actions` must allow it, and the host's pid-reuse
check refuses the pid if it no longer runs `backup-job`. Only `pause`, `resume`, `renice` and `undo`; kill is
done on the host itself.

**Cost.** One poll takes about `hosts / concurrency x per-host round trip` of wall time. Local memory is bounded by
`concurrency` replies of at most `max_output_bytes` each, because snapshots are reduced to a row plus findings as
they arrive. Every limit is a config value:

```toml
[fleet]
concurrency           = 64      # parallel ssh sessions; bounded by your fd/process limits and sshd MaxStartups
connect_timeout_s     = 5
command_timeout_s     = 20      # per host: connect + run + transfer
control_master        = false   # true: fat's own ControlMaster/ControlPersist (one resident ssh per polled host)
control_persist       = "60s"
compress              = true    # ssh -C
ssh_options           = []      # e.g. ["ServerAliveInterval=5"]; yours win over fat's
hosts_file            = "~/fleet.txt"
ssh_config_hosts      = false   # also use ~/.ssh/config Host aliases...
ssh_config_filter     = []      # ...matching these globs
max_output_bytes      = 8388608
fast_max_age_ms       = 10000   # `snapshot --fast` serves a recorder sample this fresh
default_fat_path      = "/usr/local/bin/fat"
cache_ttl_s           = 15      # MCP fleet tools reuse a poll this long
tui_refresh_s         = 30      # the TUI Fleet tab re-polls this often while visible
max_hosts_per_finding = 10
outlier_min_group     = 5
outlier_z             = 3.5     # robust z-score (median absolute deviation)
outlier_min_delta     = 20      # and at least this many points from the median
timeout_backoff_s     = 300     # skip a host this long after its poll timed out (0 = never)

[fleet.groups]                  # groups by glob, in addition to per-host groups
web = ["web-*"]
db  = ["db-*", "replica-*"]
```

MCP: `fleet_summary`, `fleet_doctor`, `host_snapshot {host}` and `host_what_happened {host, at?, window?}`, all
read-only.

### Deploy to a fleet

fat is a single binary. A static musl build has no libc dependency and runs on any Linux distribution and kernel
in common use:

```sh
scripts/build-static.sh x86_64-unknown-linux-musl aarch64-unknown-linux-musl
# -> dist/fat-<version>-<target> (+ .sha256). Uses cargo-zigbuild, a musl C compiler, or docker/podman,
#    whichever is available; installs nothing.
```

Build one binary per architecture you run. `uname -m` names differ from Rust target names on some architectures
(`armv7l` is `armv7-unknown-linux-musleabihf`, `riscv64` is `riscv64gc-unknown-linux-musl`), so map them. Plain
ssh, any number of hosts (`hosts.txt` holds one ssh destination per line; parallelism is up to you):

```sh
v=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)
triple() {  # uname -m -> the musl target build-static.sh names its output after
  case "$1" in
    x86_64|aarch64|i686|s390x) echo "$1-unknown-linux-musl" ;;
    armv7l)  echo armv7-unknown-linux-musleabihf ;;
    armv6l)  echo arm-unknown-linux-musleabihf ;;
    riscv64) echo riscv64gc-unknown-linux-musl ;;
    ppc64le) echo powerpc64le-unknown-linux-musl ;;
    *) echo "no musl target known for $1" >&2; return 1 ;;
  esac
}
while read -r h; do
  t=$(triple "$(ssh -n "$h" uname -m)") &&
  scp -q "dist/fat-$v-$t" "$h:/tmp/fat" &&
  ssh -n "$h" 'sudo install -m755 /tmp/fat /usr/local/bin/fat && rm /tmp/fat'
done < hosts.txt
```

The recorder as a system service (optional; needed for `events`, `what-happened` and fast polls) is the hardened
unit from [Servers](#servers-system-wide-recorder-with-prometheus-export-linux): save it as `fat-record.service` next
to your playbook or loop and install it on every host. Run as root it writes `/var/lib/fat/history.db`, which every
local user's fat reads, so the account fleet logs in with sees it. Drop `--export prometheus` from its `ExecStart`
if nothing scrapes the hosts.

The same with Ansible:

```yaml
- hosts: all
  become: true
  vars:
    fat_target:   # ansible_architecture -> musl target (build-static.sh output names)
      x86_64: x86_64-unknown-linux-musl
      aarch64: aarch64-unknown-linux-musl
      armv7l: armv7-unknown-linux-musleabihf
      riscv64: riscv64gc-unknown-linux-musl
      ppc64le: powerpc64le-unknown-linux-musl
      s390x: s390x-unknown-linux-musl
  tasks:
    - copy: { src: "dist/fat-{{ fat_version }}-{{ fat_target[ansible_architecture] }}", dest: /usr/local/bin/fat, mode: "0755" }
    - copy: { src: fat-record.service, dest: /etc/systemd/system/fat-record.service }
    - systemd: { name: fat-record, enabled: true, state: restarted, daemon_reload: true }
```

Without systemd, run `fat record --server` under whatever supervises services on that host. fat needs no
agent, port or account of its own: polling is ssh, the recorder writes one SQLite file.

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
| Thermal | notify state `com.apple.system.thermalpressurelevel` | Every 10s. The level behind `NSProcessInfo.thermalState`: nominal, fair, serious, critical. |
| Battery | IOKit `IOPSCopyPowerSourcesInfo` | Every 30s. |
| GPU utilization and memory | IOKit `IOAccelerator` `PerformanceStatistics` | Every 4s. |
| Listening ports | libproc: `PROC_PIDLISTFDS` + `PROC_PIDFDSOCKETINFO` | Cached 5s. About 3 ms, against about 50 ms for `lsof`. Without root, only your own processes, as with `lsof`. |
| Disk I/O per volume | IOKit `IOBlockStorageDriver` `Statistics` | Every 5s, mapped to BSD disks through the registry tree. |
| Deleted-but-open files | libproc vnode fds and mapped regions with link count 0 | On demand, cached 15s. |
| Open files of disk writers | libproc `PROC_PIDFDVNODEPATHINFO` | Write-mode regular files of the top writers. |

All of these are native calls with no child process. `lsof`, `ioreg` and `pmset` run only if a native
call fails, with `LC_ALL=C` and a timeout. `FAT_DEBUG_SOURCES=1` prints the source each subsystem used
to stderr. `FAT_FORCE_FALLBACK=1` forces the command-line tools.
| Per-process network | `nettop -L 1` | Every 2s, in a background thread, with `LC_ALL=C` and a 3s timeout. Columns are found from the header row. |
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
Anthropic API: about 20 KB at most, with the top processes, ports, containers and doctor findings. Every string in
that request is redacted first: API keys and tokens (`sk-…`, `ghp_…`, `github_pat_…`, `xox…`, `AKIA…`, JWTs, `Bearer …`),
`password=` / `token=` / `secret=` style values, the value after `--token` / `--password` and in `-pX`, credentials in
URLs (`user:pass@`), and long hex or base64 blobs; your home directory becomes `~` and your user name `me`.
`fat ask --dry-run QUESTION` prints exactly the body that would be sent, and sends nothing. Without a key, `ask`
answers offline from rules.

## Performance (macOS: M3 Max, ~1,050 processes)

| What | Measured |
| --- | --- |
| `Collector::sample()` | First sample about 80 ms, then 20–30 ms. |
| `fat record` at a 2s interval | About 1.3% of one core for its own process. About 2.3% including `nettop`, the only child it still spawns (it was about 4% when ports, GPU, battery and thermal also came from `lsof`, `ioreg` and `pmset`). |
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
