# Everything fat does

[← README](../README.md)

A tour of fat's features, with links to the pages that go deeper.

fat is one engine with two interfaces:

- a ratatui terminal UI for humans, with live, tree and time-travel views ([TUI](tui.md));
- an MCP / JSON interface for agents: every view is also a tool or a `--json` flag ([For agents: MCP](agents.md)).

## Flight recorder with time travel

`fat record` keeps about 3 days of compact history in SQLite (around 27 MB/day at 2s). In the TUI you can scrub back
to the moment the fan spun up and see which process caused it. See [The flight recorder](recorder.md).

## Blame chains

`fat why <pid>` gives the cause, not just a number. For example:

> mds_stores is hot → Spotlight is indexing → because `npm install` in ~/code/app is writing 40k files → add `.metadata_never_index`

It shows:

- the ancestry (shell / terminal / editor / agent / launchd);
- how long the process has been hot;
- its children and what they cost;
- the ports it owns.

## Every modern resource

fat covers:

- per-process energy, in watts: from the kernel's per-task energy counters on macOS, RAPL package energy on Linux;
- GPU;
- thermal state and temperatures;
- memory pressure, and Linux PSI stall times for cpu, memory and io;
- battery;
- per-process net and disk rates.

## Ports and connections

Ports are first-class: every listening socket is shown with its owner and a framework hint
("node · vite dev · ~/code/app · up 3h").

**Connections by state.** Besides listeners, the Ports view counts every TCP socket by state and groups connections,
so thousands of connections become a few rows:

- inbound ones by local port and peer address (`nginx ← 203.0.113.5 ×412`);
- outbound ones by peer and port (`app → 10.0.3.7:5432 ×80`);
- TIME_WAIT sockets belong to the kernel and are grouped the same way;
- a Close-wait count that keeps rising (an application not closing connections) is flagged.

Platform differences:

- Linux reads `/proc/net/tcp*` of every network namespace it can see.
- macOS reads the sockets of processes it may inspect, so TIME_WAIT (no owning process) is not shown there.
- Counts are live only: they are not recorded in history.

**Orphans.** fat also flags dev servers whose launcher died and that were re-parented to launchd (macOS) or to
init / a systemd user manager (Linux).

## Safe actions

Pause (SIGSTOP) before kill, renice, and kill a whole tree. Everything is journaled.

- **Undoable:** pause and resume (`fat undo`); renice too, as root (a user can't lower nice again).
- **Not undoable:** TERM and KILL. So pause a suspect first: that gives you a window to see whether it was the
  culprit before anything is lost.
- **fat refuses to touch:**
  - launchd, WindowServer, kernel_task (macOS);
  - init/systemd, kernel threads and the session's display/dbus daemons (Linux);
  - its own ancestors;
  - processes owned by other users;
  - recycled pids.

## Resource budgets for commands (and agents)

`fat run` runs a command under a CPU, memory and time budget. For example:

```bash
fat run --cpu 200 --mem 4G --time 10m -- cargo build
```

How it enforces the budget:

- It runs the command in its own process group and checks the whole tree every 500 ms.
- **CPU** is in per-core percent, so 100 means one full core. A CPU breach must persist for two consecutive checks
  to count.
- **pause** (the default) stops the group and prints how to resume it. **kill** sends TERM, then KILL after 3
  seconds.
- A `--time` overrun always stops the job, unless the policy is `warn`.
- The exit code is the child's own, or 128 + the signal number if it was killed.

## One tree for local, containers and ssh hosts

- Containers: docker, podman, OrbStack, colima and nerdctl.
- Hosts: any host that has `fat` installed. See [Fleets](fleet.md).
- On Linux every process is tagged with its cgroup and container, so you can filter the process list by container
  name.

## Storage: what eats your disk, and what is filling it right now

The Fs tab and `fat fs` show:

- disk usage of every directory from `/` down (a cached, low-priority background scan);
- which paths grew in the last 10 minutes, and which processes are writing there;
- space held by deleted-but-open files;
- when each volume will be full.

fat only reads: it never deletes, moves or truncates your files. See [Storage](storage.md).

## Plain-language `ask`

Ask "why is this machine hot?" and get an answer from a language model: Claude with an API key, or your own model
server (Ollama, LM Studio, vLLM…). Without one, `ask` sends nothing and says how to set one up. See [Ask](ask.md).
