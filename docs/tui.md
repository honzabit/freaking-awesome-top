# The TUI

[← README](../README.md)

Run `fat` with no arguments to open the TUI: a live view of the machine, with keys to explain, pause, renice or stop
what is using it. Press `h` for the key list at any time.

## Views and screens

The tab bar holds views, which have number keys, and two screens at its right end, which do not.

- **Views (desktop):** `1` Procs · `2` Ports · `3` Fs · `4` Timeline · `5` Doctor · `6` Ask · `7` Fleet.
  Fleet appears only when containers run or hosts are configured.
- **Views (server profile):** `1` Services · `2` Procs · `3` Events · `4` Ports · `5` Fs · `6` Timeline · `7` Doctor ·
  `8` Ask · `9` Fleet. See [Server profile](#server-profile) below.
- **Screens:** Log (`a`) and Settings (`,`). They have no number key; `Esc` returns to the view you came from.
- `Tab` (or `Shift-Tab` backwards) cycles through everything on the tab bar.

The key numbers in the sections below (Ports `2`, Timeline `4`) are the desktop ones.

## Keys

### Everywhere

| Key | Action |
| --- | --- |
| `1`–`9`, `Tab` | switch view (see above) |
| `↑↓ PgUp PgDn g G` | move |
| `c m p n d i N` | sort by cpu · mem · power · net · disk · pid · name (press again to reverse) |
| `t` | process tree |
| `/` | filter by name, command line, container name / id / image, or cgroup path (`Esc` clears it) |
| `Enter` / `w` | why: the blame chain (a side panel at 120+ columns, otherwise an overlay) |
| `space` / `z` | pause / resume (undoable) |
| `r` | renice (default +10; undoing it needs root) |
| `k` / `K` | terminate / terminate the whole tree (asks for confirmation; **not undoable**) |
| `u` | undo the last pause or renice |
| `L` / `Esc` | back to live |
| `?` | ask in plain language: opens the Ask tab on a new thread |
| `a` | the Log screen (see below) |
| `,` | the Settings screen (see [Settings](#settings-)) |
| `h` | help |
| `q` / `Ctrl-C` | quit |

### Log screen (`a`)

The action log: everything fat did and who asked (you in the TUI, the CLI, or an agent over MCP).

| Key | Action |
| --- | --- |
| `⏎` | undo the selected entry, if it can be undone |
| `f` | filter by kind |
| `/` | search |
| `Esc` | go back |

### Ports (`2`)

Connections grouped by state, each view with a live count.

| Key | Action |
| --- | --- |
| `←` `→` | switch view: All · Listen · Established · Time-wait · Close-wait · Other · Orphans |
| `f` | open the filter: protocol, address scope, process, port or range, peer address (`Esc` clears it) |
| `k` | kills the tree |

### Timeline (`4`)

Time travel through the recorded history.

| Key | Action |
| --- | --- |
| `← → [ ]` | move through history |
| `{ }` | move ×10 |
| `s` | jump to the next spike |
| `+` / `-` | zoom the window (5m … 24h) |
| `L` / `Esc` | back to live |

### Ask

The Ask view holds your questions as threads. See [Ask](ask.md).

| Key | Action |
| --- | --- |
| `Enter` / `i` | type a follow-up in the open thread |
| `n` | new thread |
| `↑↓` | open another thread |
| `d` | delete one |
| `Esc` | leave the input line, or stop waiting for an answer (the answer is still saved) |

### Fs

Disk usage, browsable by directory. See [Storage](storage.md).

| Key | Action |
| --- | --- |
| `⏎` / `→` / `l` | open a directory (`⏎` on a 🔒 directory reads it once) |
| `←` / `Backspace` | go up |
| `s` | cycle the sort: size · growth · io · name · files · age |
| `g` | toggle the growth view |
| `w` (or `+` / `-`) | cycle the window: 10m · 1h · 24h |
| `b` | list the biggest entries below here |
| `r` | rescan this directory |
| `/` | filter |
| `⏎` on a writer row | explain that process |

`h` stays help and `L` stays "back to live", as in every other view. fat never deletes anything.

## Rewind, Doctor and protected processes

- **Rewind:** while you are rewinding, every view shows a big `⏪ REWIND hh:mm:ss` badge. Actions are refused, because
  they would hit processes from the past.
- **Doctor:** `Enter` runs a finding's suggested action after you confirm it.
- **Hubs:** `doctor` and `why` never suggest pausing or killing a *hub*, a process whose cost is really other work:
  - a VM host (OrbStack Helper, Docker Desktop's VM, qemu, UTM);
  - a container runtime, shim or a container's pid 1;
  - init;
  - a browser's or Electron app's main process;
  - your shell, terminal, tmux, ssh or agent session;
  - WindowServer, the kernel.

  They name the workload instead, for example:
  - "OrbStack 2.8G (VM: containers db 328M ...)": `docker stop db`, or lower the VM memory limit;
  - "Brave 4.1G across 23 processes": close heavy tabs.
- **Advice by kind:** GUI apps get "quit <App>"; root/system services get service-manager advice. Memory findings
  rank whole apps and VMs, not single processes. Only your own CLI/dev processes get a runnable `pause` / `kill`.
- **The same gate guards the actions:**
  - MCP `pause` and `kill` refuse a hub (and a tree with one inside) and name the workload instead.
  - In the TUI, pausing or terminating a hub (`space`, `k`, `K`, also in Ports, where a forwarded container port
    belongs to the VM host) asks first and says what it hosts.

## Server profile

On a server the TUI opens on **Services**, and the header shows what matters at 3am instead of laptop gauges. See
[Servers](server.md) for how the profile is chosen.

### Header

- CPU with steal (`st`), iowait (`wa`) and irq shares.
- The run and blocked queues (`R` / `D`). A high load with an idle CPU is usually `D`.
- Memory with MemAvailable, PSI some/full and swap traffic.
- OOM kills: the last 24h from the recorder, or this session.
- Failed / flapping units.
- fd, conntrack and ephemeral-port use.
- The worst disk await.
- When present: read-only remounts, degraded RAID, an unsynced clock.

Colours follow `[server] exhaustion_warn` and `disk_await_warn_ms`, not built-in numbers.

### Services

One row per systemd unit, container (any runtime), pod or plain cgroup.

- **Columns:** state, CPU, memory and its limit, I/O, restarts (recent / total), CPU throttling, processes.
- **Order:** failed units first (`✗`, red), then flapping ones (`⟳`), then units in transition.
- **Inactive units** are hidden until `i`; the title says how many.
- **`⏎` explains the unit:**
  - what it is (cgroup, main pid, container image / pod);
  - its resources against its limits;
  - its processes and recent events;
  - read-only commands to look closer (`journalctl -u …`, `<runtime> logs …`, `kubectl describe pod …`), chosen
    from what was detected.
- **`w`** explains the unit's main process; **`W`** asks what happened in the last 15 minutes.

| Key (Services) | Action |
| --- | --- |
| `s c m d r N` | sort by state (problems first) · cpu · mem · io · restarts · name (again reverses) |
| `t` · `f` · `i` | group by kind · problems only · show inactive units |
| `/` | filter by name, description, state, kind, runtime, image, pod or cgroup |

### Events

The incident timeline. It merges the recorder's events (when `fat record --server` runs) with the ones this session
saw.

- **Event kinds:** OOM kills; failed / restarting / flapping units; deploy bursts; disk latency spikes and errors;
  filling or read-only filesystems; hung tasks and kernel warnings; throttling; pressure spikes; exhaustion of fds /
  conntrack / ports / memory limits; clock problems.
- **`⏎` on an event** asks the incident engine what happened around it. It shows the chain from symptom to cause,
  who is to blame, the evidence, read-only next steps, and which data was missing.

| Key (Events) | Action |
| --- | --- |
| `⏎` | what happened around this event |
| `f` | cycle the minimum severity |
| `+` / `-` | change the window (15m · 1h · 6h · 24h · 7d) |
| `W` | explain the last 15 minutes (or the rewind moment) |
| `/` | filter |

## Fleet

A health table of every host, in any profile. See [Fleets](fleet.md).

- **When it appears:** as soon as the inventory has hosts: `[[hosts]]`, `[fleet] hosts_file`, or ssh config entries
  when enabled.
- **Polling:**
  - polls run only while the tab is on screen;
  - every `[fleet] tui_refresh_s` seconds after the previous one ends (`r` polls now);
  - never two at once, with at most `[fleet] concurrency` ssh sessions;
  - rows stream in as hosts answer.
- **Findings panel:** `→` moves to it. Findings are grouped across hosts, worst first; `⏎` there narrows the table to
  the affected hosts.
- **Drill-down:** `⏎` on a host shows its snapshot, fetched read-only with the same allowlisted `fat snapshot` call.
- **Read-only:** nothing in the Fleet tab can act on a remote host.

| Key (Fleet) | Action |
| --- | --- |
| `H` · `c` · `m` · `d` · `f` · `n` · `l` | sort by health (worst first, unreachable hosts lowest) · cpu · mem · disk · findings · name · latency |
| `/` | filter by name, group, tag, finding, error |
| `→` | the fleet findings panel |
| `r` | poll now |
| `⏎` | drill into a host |
| `d` · `u` · `p` · `r` · `Esc` | in a host: doctor · units · procs · refresh · back |

## Settings (`,`)

`,` opens the Settings screen, where every setting can be read and edited. It sits with the Log screen at the right
end of the tab bar; neither has a number key, and `Esc` returns to the view you came from.

- **Groups** (on the left, `←` `→`): Ask, Recording, Server, Fleet, Hosts, Agents, Updates.
- **Source:** every setting shows its value and where that value comes from: the default, the config file, or an
  environment variable. An environment variable wins and can't be changed there.

### Groups

- **Ask:** a guided page.
  - A status line on top: ready or not, where questions go, and why not.
  - **Connect ask to:** the options found on this machine, each with its status: Claude Code, Codex and Cursor
    (installed, signed in), Ollama and LM Studio on localhost (and how many models), the Claude API (whether the
    key is set), another model server, a custom command, and Off. `⏎` picks one; one that still needs a URL or a
    command opens it for typing.
  - **Details:** only the fields that choice needs (a server's URL and model, the API's key variable, a tool's
    optional model, the custom command).
  - **Privacy:** local only, detail, memory, thread retention.
  - **Advanced** (folded): digest size, Ollama context, timeout.
  - The key itself is never shown or stored.
  - `t` sends a tiny "reply OK" question (nothing about the machine) and shows the time or the error.
  - `m` lists the server's models to pick from, chat models first.
  - Ask changes apply at once.
- **Recording, Server, Fleet:** every setting of the top level, `[server]` and `[fleet]`, including lists
  (`ssh_options`) and host groups (`db=db-*,pg-*; web=web-*`). These apply the next time fat (or `fat record`)
  starts, and the screen says so.
- **Hosts:** the `[[hosts]]` list.
  - `⏎` edits a host or adds one (name, ssh destination, fat path, groups, tags).
  - `t` runs `fat --version` on it over ssh with your own ssh config (batch mode, never prompts).
  - `d` removes it.
- **Agents:** which side-effect tools agents may use over MCP (`[mcp] allow_actions`), as a checklist. Allowing
  anything new asks for confirmation first. Kill still needs a preview and a one-time token per process. See
  [For agents: MCP](agents.md).
- **Updates:** the daily version check, automatic updates, and whether `fat record` restarts itself into a new
  binary. See [Updates](updates.md).

### Editing

| Key | Action |
| --- | --- |
| `⏎` | toggle, cycle or edit |
| `r` | remove a value from the file, so the default applies |

Changes are written to your `config.toml` at once, keeping its comments and layout, and only if the result is still
a valid config. See [Configuration](configuration.md).
