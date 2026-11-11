# For agents: MCP

[← README](../README.md)

`fat mcp` runs an MCP server on stdio, so an AI agent can read the machine through fat and, if you allow it, act on
processes.

## Connect an agent

With Claude Code:

```bash
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

## Tools

### Read-only

`snapshot`, `process`, `ports`, `why`, `doctor`, `history`, `find_port_owner`, `containers`, `ask`.

- `snapshot` takes `sort`, `limit`, `filter` and `container` (a container name or id prefix: only that container's
  processes).
- Its result includes `psi`, `temp_c` and `power_source` (null where the platform has none).
- Each containerised process carries `container` (12-char id), `container_name` and `cgroup`.

### Storage (read-only)

| Tool | Returns |
| --- | --- |
| `fs_volumes` | capacity, `fill_bps`, `eta_full_s`, I/O |
| `fs_list {path, depth?, limit?, wait_seconds?}` | du-style children, with `known` advice for common space hogs |
| `fs_largest {path, n?}` | the `n` largest files or directories below `path` |
| `fs_growth {since?, under?}` | growing paths with their writers and evidence, top writers, deleted-but-open files |

See [Storage](storage.md).

### Side effects (off by default)

`pause`, `resume`, `renice`, `kill`, `undo`, all annotated as destructive. An agent can't signal anything until you
allow it in the [config](configuration.md) (or on the Agents page of the TUI's [Settings](tui.md#settings-)):

```toml
[mcp]
allow_actions = ["pause", "resume", "renice", "undo"]   # or "all"; default: none
```

Disabled tools stay visible, on purpose:

- They stay in `tools/list`, marked `DISABLED` in their description.
- Calling one returns an error that says how to enable it.
- Why: an agent that can't see the tool tends to conclude fat can't do it and reach for a shell `kill`. One that reads
  "disabled, ask the user to add X" asks you instead.
- The refusal happens in the server, so a listed tool is never a way around the setting.

### `kill` takes two calls

1. **Preview.** The first call signals nothing. It returns a preview and a `confirm_token`. The preview shows:
   - the process, its command and user;
   - the signal;
   - its ancestors;
   - for `tree: true`, every descendant and whether it would be skipped as protected;
   - or why fat would refuse.
2. **Signal.** The second call, with the token, signals.

The token works once, for 60 seconds, for that pid, that signal and that process's start time. A pid reused in
between is refused.

## Results and safety

- Every result carries the same object twice: as pretty JSON text and as `structuredContent`.
- Pause, resume and renice return an id that `undo` accepts. A kill is journaled but can't be undone.
- The same safety rules as the CLI apply. For example, `pause` and `kill` refuse a hub process and name the workload
  instead (see [Rewind, Doctor and protected processes](tui.md#rewind-doctor-and-protected-processes)).
- For one-off scripting, every CLI view also has `--json` (see [Commands](commands.md)).
