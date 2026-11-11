# Commands

[← README](../README.md)

Every fat command on one page, grouped the same way as `fat --help`.

## Everyday

Look at the machine, find what is using it, and ask about it. More in [The TUI](tui.md), [Storage](storage.md) and
[Ask](ask.md).

```bash
fat                         # the TUI: processes by CPU (h for keys)
fat snapshot [--json] [--top 25]
fat ports [--json]          # listeners, owners, ⚠ orphans
fat fs [PATH] [--depth N] [--top 25] [--wait 2m] [--json]   # disk usage of PATH's children (default /)
fat fs --growth [--since 10m] [--under PATH] [--json]     # what is eating space right now
fat fs --volumes [--json]                                 # capacity, fill rate, ETA to full, I/O
fat fs --largest 20 PATH                                  # biggest files / dirs below PATH
fat why <pid> [--json]      # blame chain + evidence + suggested fixes
fat doctor [--json]         # whole-machine diagnosis, ranked crit > warn > info
fat ask "why is this machine hot"              # starts a thread, kept locally
fat ask -c "since when?"                       # follow up in the latest thread (--thread N for another)
fat ask --list | --show N | --delete N         # your threads
fat ask --dry-run "why is this machine hot"   # print the exact (redacted) request and where it goes; send nothing
```

## Actions

Every action is journaled in `fat log`.

```bash
fat pause <pid>             # SIGSTOP; undoable
fat resume <pid>            # SIGCONT
fat renice <pid> 10         # lower priority; journaled, but undoing it needs root
fat kill <pid> [--tree | --force]  # TERM (KILL with --force); NOT undoable; no prompt
fat undo [id]               # undo the last pause/renice (or a specific one)
fat log [--json]            # action journal
```

## Flight recorder

Record history, then look back at it. To keep the recorder running, see
[Run the flight recorder always-on](recorder.md); for services and incidents on servers, see [Servers](server.md).

```bash
fat record                  # foreground
fat history --since 1h      # timeline (avg cpu/mem/power, top process per bucket)
fat history --since 1h --spikes
fat history --at 10m        # the machine as it was 10 minutes ago
fat services [--failed] [--kind systemd|container|k8s-pod|cgroup] [--json]   # services: state, restarts, flapping, OOM kills, throttling
fat events [--since 2h] [--kind oom-kill,unit-failed]... [--json]   # what happened, in order
fat what-happened [--at 03:12] [--window 15m] [--json]         # the incident: causal chain, who did it, next steps
```

## Advanced

Resource-limited runs, fleets over ssh, and the MCP server. More in [Fleets](fleet.md) and
[For agents: MCP](agents.md).

```bash
fat run --cpu 150 --mem 2G --time 10m --procs 64 --on-violation pause|kill|warn -- <cmd...>
fat fleet [--group G] [--tag T] [--host GLOB] [--sort health|cpu|mem|disk] [--json]   # every host's health, findings across hosts
fat fleet doctor | events --since 2h | hosts | containers
fat fleet --host db-01 what-happened --at 03:12           # one host's incident, read-only
fat fleet exec-readonly kernel --json                     # one allowlisted read-only fat command everywhere
fat mcp                     # MCP server on stdio
fat update [--check | --rollback]                         # install the latest release (signature-checked)
```

More on updates in [Updates](updates.md).
