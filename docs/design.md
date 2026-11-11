# Design notes

[← README](../README.md)

How fat is built, where its data comes from, what it costs, and what it can't do yet.

## Architecture

One collector feeds every interface.

- `collect` (one `Collector`) → `model::Snapshot` → consumed by `tui`, `mcp`, `history`, `blame`, `ask` and
  `actions`.
- The TUI and MCP are thin.
- Every module is wrapped so that a failure in one (for example, docker not installed) degrades to "unknown" or an
  empty list instead of crashing the program.

## Data sources (macOS, all unprivileged)

This is where each number comes from on macOS. For the Linux sources, see [Linux: Data sources](linux.md#data-sources).

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
| Per-process network | `nettop -L 1` | Every 2s, in a background thread, with `LC_ALL=C` and a 3s timeout. Columns are found from the header row. |
| Containers | `docker` / `podman` `ps` and `stats` | Run in the background and cached 5s. |
| Remote hosts | `ssh host fat snapshot --json` | |

Native calls first:

- Everything above `Per-process network` is a native call with no child process.
- `lsof`, `ioreg` and `pmset` run only if a native call fails, with `LC_ALL=C` and a timeout.
- `FAT_DEBUG_SOURCES=1` prints the source each subsystem used to stderr.
- `FAT_FORCE_FALLBACK=1` forces the command-line tools.

**No `powermetrics` and no root.** Processes owned by other users (for example WindowServer) show as
"unreadable", so system power is a lower bound.

## Flight recorder

The [flight recorder](recorder.md) stores compact history in SQLite (WAL mode).

- Each sample stores one small system row.
- Rarely-changing data (ports, containers, thermal) is stored only when it changes.
- The interesting processes (the top consumers, port owners, paused processes and their ancestors) use
  keyframe + delta encoding packed into varint blobs.
- `at(t)` replays from the previous keyframe.
- Old data is pruned hourly.

## Files on disk

| File | macOS | Linux |
| --- | --- | --- |
| Actions journal | `~/Library/Application Support/fat/actions.jsonl` | in `$XDG_STATE_HOME/fat`, usually `~/.local/state/fat` |
| History DB | `~/Library/Application Support/fat/history.db` | `~/.local/share/fat/history.db` |

Each journal entry records the pid's start time, so undo never signals a recycled pid.

## Privacy

Everything stays on your machine: the history DB, the journal and all collection.

The one exception is `ask`, which sends a redacted summary to the model you configure. See
[Ask: What ask sends](ask.md#what-ask-sends) for exactly what is sent and how it is redacted.

## Performance (macOS: M3 Max, ~1,050 processes)

Measured costs of collection, recording and the UI.

| What | Measured |
| --- | --- |
| `Collector::sample()` | First sample about 80 ms, then 20–30 ms. |
| `fat record` at a 2s interval | About 1.3% of one core for its own process. About 2.3% including `nettop`, the only child it still spawns (it was about 4% when ports, GPU, battery and thermal also came from `lsof`, `ioreg` and `pmset`). |
| TUI at 1.5s | About 2% of a core. |
| Fs background scan | Capped at 0.25 core (1 core while the Fs tab is visible). After a full scan of `/` (19.9M files): CLI peak RSS about 120 MB, TUI about 200 MB in total. |
| History writes | About 0.5 ms per sample, about 27 MB/day. |

## Known limitations

What fat can't see or do yet.

- **Other users' processes on macOS.** Without root, their per-process CPU and power are invisible, and so are their
  sockets and network traffic.
- **Other users' processes on Linux.** CPU and memory are visible for everyone. Only io, sockets and traffic of
  other users need root.
- **First sample.** The first sample after start has no rates. The CLI takes two samples 600 ms apart, so one-shot
  commands take about 1s.
- **Remote hosts** are shown as summary rows. You can't browse a remote process tree yet.
- **Renice undo.** A non-root user can raise nice but can't lower it again, so a renice can't be undone without
  root. On Linux, `RLIMIT_NICE` or `CAP_SYS_NICE` lifts this.
