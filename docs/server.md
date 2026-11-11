# Servers

[← README](../README.md)

On a server, run the flight recorder once for the whole machine, as a system service, with an optional Prometheus
export.

## What the server profile records

In the **server profile** the recorder records more than processes:

| What | Details |
| --- | --- |
| Every unit | systemd services, containers from any runtime, Kubernetes pods, and plain cgroups. Each unit's state, restarts, CPU, memory and its limit, I/O, CPU throttling, PSI and OOM kills are recorded. See [Services](linux.md#services-fat-services). |
| Kernel health | Steal, iowait, PSI, disk latency, D-state processes, and fd, conntrack and ephemeral-port use. See [Kernel health](linux.md#kernel-health-and-kernel-events-fat-kernel). |
| An **event log** | OOM kills with victim and cgroup, unit failures, restarts and flapping, kernel warnings, hung tasks, disk errors, read-only remounts, throttling, pressure, exhaustion, and per-unit CPU or memory spikes. A volume about to fill is logged too. On start the recorder imports the kernel log backlog, so OOM kills from before the daemon started are on the timeline. |

### Choosing the profile

fat picks the server profile by itself on a Linux host with no graphical session and no battery. To choose it
yourself, do one of these:

- pass `--server`;
- set `[server] profile = "server"` (see [Configuration](configuration.md));
- set `FAT_PROFILE=server`.

## The shared history database

When the recorder runs as root in the server profile, it writes to `/var/lib/fat/history.db`. See
[Storage](storage.md) for the database itself.

- **Every user's `fat` reads it** if that file exists: `fat history`, `fat events`, `fat what-happened`, the TUI,
  and `fat snapshot --fast`.
- **`fat snapshot --fast`** opens it read-only and returns the newest sample. A fleet poll then costs one SQLite
  read instead of a live sample (see [Fleets](fleet.md)).
- **Permissions.** Readers need read access to the database and its `-wal`/`-shm` files. They are world-readable
  by default (umask 022). Process command lines in them are already visible in `/proc` to every user, unless
  `/proc` is mounted with `hidepid`. On such hosts, set `UMask=0077` in the unit and read as root.
- **Other versions.** A fat of another version never changes that database. Readers (`doctor`, `why`, `history`,
  `ask`, `fs`, the fleet's remote commands) open it read-only and refuse a schema they do not know. Only
  `fat record` replaces it, after moving the old file aside to `history.db.schema-v<N>`.

## Install the system service

1. Get a fat binary on the host. Prebuilt static Linux binaries are on the
   [releases page](https://github.com/honzabit/freaking-awesome-top/releases); see [Install](../README.md#install)
   to verify them. To build one yourself, use `scripts/build-static.sh` (see
   [Deploy to a fleet](fleet.md#deploy-to-a-fleet)) or the steps in [Linux](linux.md#install).

2. Save this as `/etc/systemd/system/fat-record.service` (adjust the `ExecStart` path):

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

3. Reload systemd:

   ```bash
   sudo systemctl daemon-reload
   ```

4. Enable and start the recorder:

   ```bash
   sudo systemctl enable --now fat-record
   ```

5. If you kept `--export`, check the metrics:

   ```bash
   curl -s 127.0.0.1:9877/metrics | head
   ```

### Why each capability is kept

fat never signals anything from the recorder, so it needs only read access.

| Capability | What it reads | Without it |
|---|---|---|
| `CAP_SYS_PTRACE` | passes the kernel's ptrace access check on `/proc/<pid>/{io,fd,exe,cwd}` of other users' processes: per-process disk I/O, executable and cwd, and which process owns a port | those fields only for root's own processes |
| `CAP_DAC_READ_SEARCH` | files owned by other users without read permission for others, such as `/proc/<pid>/io` (mode 0400, owned by the process's user) and container runtime state | the same fields stay empty (it is needed together with `CAP_SYS_PTRACE` for `/proc/<pid>/io`) |
| `CAP_SYSLOG` | `/dev/kmsg` when `kernel.dmesg_restrict=1`: OOM kills (victim, cgroup, RSS), hung tasks, I/O and filesystem errors | no kernel-log events; OOM kills are still counted from `/proc/vmstat`, without a victim |

### Hardening options left out on purpose

| Option | Why it is left out |
| --- | --- |
| `ProtectKernelLogs`, `PrivateDevices` | They hide `/dev/kmsg`. |
| `ProtectClock` | It blocks the read-only `adjtimex` call that tells whether the clock is synchronised. |
| `IOSchedulingClass=idle`, `Nice=19` | They would starve the recorder during exactly the I/O or CPU storm you want recorded. |

## Prometheus export

`--export prometheus` serves `GET /metrics` (text format 0.0.4) from the recorder's newest in-memory sample.

- **Address.** It binds `127.0.0.1:9877`. Use `--listen ADDR` or `[server] export_listen` to change that.
- **Without the flag.** Set `[server] export_enabled = true` to serve without `--export`.
- **Exposure.** A non-loopback address prints a warning: the metrics name units, disks and mounts, so exposing
  them is your decision, behind your own firewall.
- **Server.** One thread on `std::net`, one request at a time, with 5 s timeouts. It is not TLS; put a proxy in
  front if you need TLS.

### Metrics

All metrics are prefixed `fat_`.

| Group | Metrics |
| --- | --- |
| Host | `up`, `info{version,profile}`, `cpu_percent`, `cpu_steal_percent`, `cpu_iowait_percent`, `load{period}`, `memory_{total,used,available}_bytes`, `swap_used_bytes`, `pressure_percent{resource,kind}` |
| Kernel | `oom_kills_total`, `procs_blocked`, `dstate_procs`, `fd_{used,max}`, `conntrack_{used,max}`, `ephemeral_ports_used`, `ephemeral_ports_range_size`, `tcp_retrans_per_second`, `listen_drops_per_second` |
| Disks and volumes | `disk_util_percent{disk}`, `disk_await_ms{disk,op}`, `disk_queue_depth{disk}`, `volume_used_ratio{mount}` |
| Per unit, labels `{unit,kind}` | `unit_up`, `unit_cpu_percent`, `unit_memory_bytes`, `unit_memory_limit_bytes`, `unit_io_bytes_per_second{op}`, `unit_restarts_total`, `unit_cpu_throttled_percent`, `unit_pressure_percent{resource}`, `unit_oom_kills_total` |
| Also | `units{kind,state}`, `findings{severity}` (current `fat doctor` findings), `events_total{kind}` (events since the recorder started) |

Label cardinality is bounded:

- Units are capped by `[server] max_units`.
- There is no pid or command-line label.
- Disk and mount labels are the host's own.

### Scrape config

```yaml
# prometheus.yml (a Prometheus on the same host; for a remote one, --listen on an internal address)
scrape_configs:
  - job_name: fat
    static_configs:
      - targets: ["127.0.0.1:9877"]
```

## Footprint and bounds

The server profile samples every `[server] record_interval_ms` (default 5000). Directory scanning is off unless
`[server] fs_scan = true`; volumes are still recorded.

Cardinality per sample is bounded:

| What | Bound |
| --- | --- |
| Processes | The existing interesting-process selection, plus the top `record_top_procs` (default 50) by CPU, memory and I/O, plus every unit's main pid. At most 200, or 3 x `record_top_procs` when that is larger. Not every pid. |
| Units | At most `max_units`, inactive ones dropped first. Units are change-point encoded: a row when state or numbers move, and every unit every 15 minutes. |
| Events | At most `max_events_per_sample`. Repeats of a persisting condition for the same subject are recorded at most once per `spike_cooldown_s`. |
| Disks | A row only while busy. |

### Measured footprint

Measured with the unit above on a systemd test host with about 200 units (including one CPU-throttled unit and two
units that crash and restart every 20 s) and 125 processes:

| | measured | budget |
|---|---|---|
| CPU, 5-minute average | 0.66% of one core | < 1% |
| memory | 11 MiB RSS, 13 MiB peak | < 60 MB |
| disk, whole database | 15.5 MB/day, about 45 MB for the default 3 days | bounded by `history_days` |
| `fat snapshot --json --fast`, as a non-root user | 12 ms (28 ms cold), against about 760 ms for a live sample | |
| one `/metrics` scrape | about 5 ms | |

- **Disk split**, roughly: units 26%, events 23% (almost all from the two restarting units), kernel and disks 10%,
  processes, system and volumes 41%.
- A quiet host writes less. A host with many restarting units writes more, within `max_events_per_sample`.
- Most of the CPU left is the periodic systemd refresh. On hosts with thousands of units, raise
  `[server] unit_refresh_s`.
- Set `FAT_RECORD_PROFILE=1` to make the recorder print the average time per phase every 60 samples, for sizing it
  on a new kind of host.

### Settings

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

More `[server]` keys are in [Service settings](linux.md#service-settings) and [Kernel settings](linux.md#kernel-settings).

## One recorder at a time

Only one fat records at a time:

- A TUI opened while the service runs reads the service's history instead of writing its own.
- A second `fat record` waits until the first stops.
