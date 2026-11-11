# Fleets

[← README](../README.md)

`fat fleet` polls many hosts over ssh at once and tells you which ones need attention.

It asks every host for one snapshot, in parallel and read-only, and summarises the fleet:

- a health score per host, worst first;
- findings aggregated by title across hosts;
- hosts that could not be polled, grouped by reason;
- outliers that are far from their group's median.

## Commands

Summary: findings across hosts, outliers and a host table.

```bash
fat fleet
```

One group, busiest first, 20 rows.

```bash
fat fleet --group web --sort cpu --top 20
```

Findings per host, as JSON.

```bash
fat fleet doctor --json
```

A merged timeline of events across hosts (needs `fat record --server` on the hosts).

```bash
fat fleet events --since 2h --kind oom_kill --kind unit_failed
```

"What happened and who did it", on one host.

```bash
fat fleet --host db-01 what-happened --at 03:12 --window 30m
```

The inventory, without touching the network.

```bash
fat fleet hosts
```

Example summary:

```
fleet: 120 hosts · 118 ok · 2 not polled · 2.1s (concurrency 64)

findings across hosts:
  CRIT  Disk /var is #% full: 3 hosts [web-07, web-12, db-02] (worst: web-07: Disk /var is 99% full)
  warn  not polled: auth: 1 host [cache-03]
  warn  postgres is writing #M/s: 2 hosts [db-01, db-02] (worst: db-01: postgres is writing 180M/s)

outliers (far from their group's median):
  web-07               mem_pct                94  (group web median 41, z 6.2)
```

How findings are merged:

- Numbers that are values are merged as `#`. Names keep theirs: `/data1` and `/data2` stay apart.
- The worst host's own line is shown with its value. In `--json` it is in `worst`.

## Inventory

The inventory is the list of hosts fat polls.

Hosts come from three sources, merged by name:

- `[[hosts]]` in the config;
- an optional hosts file;
- (opt-in) the `Host` aliases of `~/.ssh/config`.

Select hosts with:

| Flag | Selects |
| --- | --- |
| `--group` | hosts in any of the given groups |
| `--tag` | hosts with all of the given tags |
| `--host` / `--exclude` | hosts matching (or not matching) globs |

A hosts file has one host per line:

```
# name   [ssh=DEST]                 [fat=PATH]            [groups=a,b]   [tags=x,y]
web-01   ssh=admin@web-01.example.com                      groups=web     tags=prod
db-01                               fat=/opt/fat/bin/fat  groups=db
```

## ssh

fat runs your own `ssh` and leaves reaching a host entirely to your ssh config.

- **Your config decides.** Users, ports, keys, jump hosts, proxies and certificates all come from your ssh config.
  The destination is passed verbatim. fat adds no proxy or routing options of its own.
- **Options fat adds:** `BatchMode=yes` (never prompts), `ConnectTimeout` and `-C`. All are configurable, and
  `ssh_options` you set take precedence.
- **Connection sharing** is left to your ssh config, unless you set `control_master = true`. fat then adds
  `ControlMaster=auto` (socket in `$XDG_RUNTIME_DIR/fat/ssh` or `~/.cache/fat/ssh`) and `ControlPersist`.
  These override your own multiplexing settings and keep one ssh process per polled host resident for
  `control_persist`, so their cost grows with inventory size.
- **Remote deadline.** Each remote fat gets `FAT_DEADLINE_S=<command_timeout_s>` and ends itself then, because
  killing the local ssh does not stop it. A `fat_path` through sudo drops that variable.
- **Timeout backoff.** A host whose poll timed out is skipped for `timeout_backoff_s`. A host whose `/proc` reads
  hang therefore does not collect a stuck fat per refresh.
- **The remote command** is `fat snapshot --json --fast`: one SQLite read when the host runs the recorder, a
  ~0.6 s live sample otherwise. Older remote fats without `--fast` get a plain `fat snapshot --json`.
- **Findings are computed locally**, so every host gets this fat's rules.

### Errors

Every host that could not be polled gets a structured error with a hint:

`unreachable`, `auth`, `host-key`, `fat-missing`, `version`, `timeout`, `too-large`, `bad-output`, `remote-error`.

- `auth`, `host-key` and `unreachable` are reported only when ssh itself failed (exit status 255).
- A "Permission denied" from the remote shell or from fat is a `remote-error`.
- fat never accepts host keys for you.

## Read-only, with one exception

The fleet only reads; there are no fleet-wide actions.

On remote hosts it runs only `snapshot`, `doctor`, `why`, `ports`, `services`, `kernel`, `events`,
`what-happened`, `history` and `fs`.

One reversible action on one host is possible. It needs three separate opt-ins:

```bash
fat fleet --host web-01 act --allow-actions pause 4242 --name backup-job
```

1. `--allow-actions` on the command line.
2. The host's own `[mcp] allow_actions` must allow it, because this talks to that host's `fat mcp`.
3. `--name`: the host's pid-reuse check refuses the pid if it no longer runs `backup-job`.

Only `pause`, `resume`, `renice` and `undo` are possible. Kill is done on the host itself.

## Cost and limits

Every limit of a fleet poll is a config value.

- **Time:** one poll takes about `hosts / concurrency x per-host round trip` of wall time.
- **Memory:** local memory is bounded by `concurrency` replies of at most `max_output_bytes` each, because
  snapshots are reduced to a row plus findings as they arrive.

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

## MCP tools

Agents get the fleet as read-only [MCP](agents.md) tools:

- `fleet_summary`
- `fleet_doctor`
- `host_snapshot {host}`
- `host_what_happened {host, at?, window?}`

## Deploy to a fleet

fat is a single binary; copy it to each host and, optionally, run the recorder there.

fat needs no agent, port or account of its own: polling is ssh, and the recorder writes one SQLite file.

### 1. Build static binaries

A static musl build has no libc dependency and runs on any Linux distribution and kernel in common use.

```bash
scripts/build-static.sh x86_64-unknown-linux-musl aarch64-unknown-linux-musl
```

- Output: `dist/fat-<version>-<target>` (plus `.sha256`).
- It uses cargo-zigbuild, a musl C compiler, or docker/podman, whichever is available. It installs nothing.
- Build one binary per architecture you run.
- `uname -m` names differ from Rust target names on some architectures, so map them: `armv7l` is
  `armv7-unknown-linux-musleabihf`, `riscv64` is `riscv64gc-unknown-linux-musl`.

### 2. Copy them with plain ssh

This works for any number of hosts. `hosts.txt` holds one ssh destination per line; parallelism is up to you.

```bash
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

### 3. Optional: run the recorder as a system service

The recorder is needed for `events`, `what-happened` and fast polls.

- Use the hardened unit from [Servers](server.md). Save it as `fat-record.service` next to your playbook or loop
  and install it on every host.
- Run as root, it writes `/var/lib/fat/history.db`. Every local user's fat reads that file, so the account the
  fleet logs in with sees it.
- Drop `--export prometheus` from its `ExecStart` if nothing scrapes the hosts.
- Without systemd, run `fat record --server` under whatever supervises services on that host.

### The same with Ansible

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
