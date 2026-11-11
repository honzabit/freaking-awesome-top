# Configuration

[← README](../README.md)

fat reads one optional TOML file for its settings. You can also edit every setting from the TUI's
[Settings screen](tui.md#settings-) (`,`).

## Where the file lives

- `~/.config/fat/config.toml`, or
- `$XDG_CONFIG_HOME/fat/config.toml`.

Every key is optional.

## Example

```toml
interval_ms  = 1500        # TUI / recorder sample interval (the recorder uses at least 1000)
containers   = true        # docker / podman / orbstack / colima
history_days = 3           # flight-recorder retention
# history_path = "~/.local/share/fat/history.db"

[ask]
enabled  = true            # false: ask is off, nothing is sent
provider = "anthropic"     # "anthropic" | "openai" (OpenAI-compatible server) | "ollama"
                           # | "claude-code" | "codex" | "cursor" (signed-in tools) | "command"
# command  = ""            # provider = "command": a program reading the question on stdin
# url      = ""            # required for openai/ollama, e.g. "http://HOST:11434"
# model    = ""            # default claude-opus-5-5 for anthropic; required otherwise
# key_env  = ""            # env var holding the key: ANTHROPIC_API_KEY / FAT_ASK_KEY by default
# local_only = false       # refuse any address outside loopback/private/link-local networks
# detail   = "full"        # "minimal": no command lines, short paths, hostnames replaced
# context_bytes = 20000    # digest size bound; lower it for small or CPU-only models
# num_ctx  = 0             # ollama: context window (0 = sized to the digest)
# timeout_s = 0            # 0 = 90 s for anthropic, 180 s for tools, 300 s for self-hosted
# memory   = true          # send excerpts of recent threads on this host with a question
# keep_days = 90           # delete threads untouched this long (0 = keep)

[mcp]
allow_actions = []         # side-effect tools agents may use: "pause", "resume", "renice", "kill", "undo", or "all"

[[hosts]]
name     = "web-01"
ssh      = "admin@web-01.example.com"   # defaults to name; passed to ssh verbatim
fat_path = "/usr/local/bin/fat"         # default: fat on PATH, then the usual install dirs
groups   = ["web"]
tags     = ["prod"]

[fleet]                    # every key is optional
# hosts_file = "~/fleet.txt"
```

## Sections

| Section | What it sets | More |
| --- | --- | --- |
| top level | sample interval, containers, flight-recorder retention and path | [The flight recorder](recorder.md) |
| `[ask]` | the model `fat ask` uses, and what it may send | [Ask](ask.md) |
| `[mcp]` | which side-effect tools agents may use | [For agents: MCP](agents.md) |
| `[[hosts]]` | hosts for the fleet commands and the Fleet tab | [Fleets](fleet.md) |
| `[fleet]` | fleet inventory and polling | [Fleets](fleet.md) |
| `[server]` | the server profile and system-wide recorder | [Servers](server.md) |
