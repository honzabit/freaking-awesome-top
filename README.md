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
- **Every modern resource.** Covers per-process energy (watts, from the kernel's per-task energy counters), GPU, thermal state,
  memory pressure, battery, and per-process net and disk rates.
- **Ports are first-class.** Shows every listening socket and its owner, with a framework hint ("node · vite dev · ~/code/app · up 3h").
  It also flags **orphans**: dev servers whose launcher died and that were re-parented to launchd.
- **Safe, reversible actions.** Pause (SIGSTOP) before kill, renice, and kill a whole tree.
  Everything is journaled and `fat undo` reverses it. fat refuses to touch launchd, WindowServer, kernel_task,
  its own ancestors, processes owned by other users, and recycled pids.
- **Resource budgets for commands (and agents).** For example, `fat run --cpu 200 --mem 4G --time 10m -- cargo build`.
- **One tree for local, containers and ssh hosts.** Supports docker, podman, OrbStack and colima, plus any host that has `fat` installed.
- **Plain-language `ask`.** Ask "why is my mac hot?" and get an answer, offline from rules or richer through Claude if you set an API key.

macOS first (developed on Apple Silicon, macOS 15). It builds on Linux with reduced data. It never needs `sudo`.

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
fat ask "why is my mac hot"

fat record                  # flight recorder (foreground; run it under launchd/tmux)
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
| `1`–`6`, `Tab` | views: Procs · Ports · Fleet · Timeline · Doctor · Log |
| `↑↓ PgUp PgDn g G` | move |
| `c m p n d i N` | sort by cpu · mem · power · net · disk · pid · name (press again to reverse) |
| `t` | process tree |
| `/` | filter by name or command line (`Esc` clears it) |
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

## Design notes

**Architecture.** `collect` (one `Collector`) → `model::Snapshot` → consumed by `tui`, `mcp`, `history`,
`blame`, `ask` and `actions`. The TUI and MCP are thin. Every module is wrapped so that a failure in one
(for example, docker not installed) degrades to "unknown" or an empty list instead of crashing the program.

**Data sources (macOS, all unprivileged):**

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

**Actions journal.** `~/Library/Application Support/fat/actions.jsonl` (Linux: `$XDG_STATE_HOME/fat`).
Each entry records the pid's start time, so undo never signals a recycled pid.

**Privacy.** Everything stays on your machine: the history DB, the journal and all collection.
The one exception is `ask`. When `ANTHROPIC_API_KEY` is set (and `[ask] enabled`), it sends a compact summary to the
Anthropic API: about 20 KB at most, with the top processes, ports, containers and doctor findings. Command lines are
redacted for anything that looks like a token, key or password. Without a key, `ask` answers offline from rules.

## Performance (M3 Max, ~1,050 processes)

| What | Measured |
| --- | --- |
| `Collector::sample()` | First sample about 80 ms, then 20–30 ms. |
| `fat record` at a 2s interval | About 1.5% of one core for its own process. About 4% including the `lsof`, `nettop` and `ioreg` children it spawns. |
| TUI at 1.5s | About 2% of a core. |
| History writes | About 0.5 ms per sample, about 27 MB/day. |

## Known limitations

- Without root, per-process CPU and power are invisible for other users' processes, and so are their sockets and network traffic.
- The first sample after start has no rates. The CLI takes two samples 600 ms apart, so one-shot commands take about 1s.
- Remote hosts are shown as summary rows. You can't browse a remote process tree yet.
- On macOS, a non-root user can raise nice but can't lower it again, so a renice can't be undone without root.
- `fat run` doesn't hand the terminal to the child, so an interactive child that reads stdin gets SIGTTIN.
