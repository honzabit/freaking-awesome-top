# Ask

[← README](../README.md)

`ask` answers plain-language questions about the machine ("why is this machine slow?") with a language model.

## How it works

- **The model** is either Claude (set `ANTHROPIC_API_KEY`) or a self-hosted server: Ollama, or an
  OpenAI-compatible one such as LM Studio, vLLM or llama.cpp. See [Keep ask inside your network](#keep-ask-inside-your-network).
- **Without a model**, `ask` sends nothing and says how to set one up. `fat ask` then exits with status 1.
- **In the TUI**, press `?` to open the Ask tab. See [TUI keys](tui.md) and [Settings](tui.md#settings-) to
  configure the model from the TUI.
- **Every answer says where the question went:** `→ ollama · qwen3:32b · http://…` on stderr, in the TUI's ask box,
  and as `via` in the MCP result.

## Commands

Ask a question (starts a new thread):

```bash
fat ask "why is this machine slow?"
```

Follow up in the most recent thread:

```bash
fat ask -c "since when?"
```

Follow up in thread N:

```bash
fat ask --thread N "since when?"
```

List threads, newest first:

```bash
fat ask --list
```

Print thread N:

```bash
fat ask --show N
```

Delete thread N:

```bash
fat ask --delete N
```

Other flags:

| Flag | Effect |
| --- | --- |
| `-c`, `--continue` | Follow up in the most recent thread. |
| `--thread N` | Follow up in thread N. |
| `--list` | List threads, newest first. |
| `--show N` | Print thread N. |
| `--delete N` | Delete thread N. |
| `--no-save` | Don't keep this question and answer. |
| `--dry-run` | Print exactly the request body that would be sent, and where, and send nothing. |
| `--json` | JSON output (the answer, or the `--list` / `--show` output). |

## What ask sends

Everything else fat collects stays on your machine; `ask` is the one exception.

When a model is configured (by default: `ANTHROPIC_API_KEY` is set and `[ask] enabled`), it sends a compact summary
to that model:

- about 20 KB at most;
- the top processes, ports, containers and doctor findings;
- volumes and recent growth, for questions about disk.

Every string in that request is redacted first:

- API keys and tokens: `sk-…`, `ghp_…`, `github_pat_…`, `xox…`, `AKIA…`, JWTs, `Bearer …`;
- `password=` / `token=` / `secret=` style values;
- the value after `--token` / `--password` and in `-pX`;
- credentials in URLs (`user:pass@`);
- long hex or base64 blobs;
- your home directory becomes `~` and your user name `me`.

To see exactly the body that would be sent, and where, without sending anything:

```bash
fat ask --dry-run QUESTION
```

## Threads

Each question starts a **thread**, so follow-ups keep their context.

- **Follow-ups** (`Enter` in the Ask tab, `fat ask -c`) are sent with the thread's earlier turns (the last six), so
  "since when?" makes sense.
- **Storage:** threads are kept per user in `<data dir>/fat/threads.db`, readable only by you.
  - Linux: `~/.local/share/fat`
  - macOS: `~/Library/Application Support/fat`
  - `FAT_THREADS_DB` overrides the path.
- **Retention:** threads are deleted after `[ask] keep_days` (90) without activity.
- **Not kept:** `fat ask --no-save` keeps nothing. Questions agents ask through MCP are not kept.

### Memory of past threads

With `[ask] memory = true` (the default), a question also carries short excerpts of recent threads.

- Up to three recent threads on the same host, from the last 30 days.
- Each excerpt is the first question and the start of the last answer, so the model can notice "this looks like
  Tuesday's /var/log growth".
- They are sent as past conclusions with their dates. The current numbers always come from the fresh snapshot.
- They go through the same redaction (and `detail = "minimal"` shortening) as everything else.
- Set `memory = false` to send none.

## Keep `ask` inside your network

To keep this data on your own infrastructure, point `ask` at a model server you run:

```toml
[ask]
provider   = "ollama"                 # or "openai" for LM Studio, vLLM, llama.cpp, LocalAI, LiteLLM…
url        = "http://HOST:11434"
model      = "MODEL"
local_only = true                     # never send to a public address, even by mistake
```

The same settings can come from the environment, handy for a fleet:

| Variable | Setting |
| --- | --- |
| `FAT_ASK_PROVIDER` | `provider` |
| `FAT_ASK_URL` | `url` |
| `FAT_ASK_MODEL` | `model` |
| `FAT_ASK_LOCAL_ONLY=1` | `local_only = true` |
| `FAT_ASK_DETAIL=minimal` | `detail = "minimal"` |

A key, if the server wants one, is read from the variable `key_env` names (default `FAT_ASK_KEY`), never from the
config file.

Things to know:

- **`local_only`** is checked on the addresses the server name resolves to, when connecting. Loopback, RFC 1918,
  CGNAT (100.64/10), IPv6 ULA and link-local pass. Anything else is refused before a byte is sent. Redirects are
  not followed.
- **`detail = "minimal"`** sends less: no command lines or images, every path cut to two components
  (`/var/lib/…`), the hostname and container names replaced. Answers get vaguer about paths.
- **Use `provider = "ollama"` for Ollama**, not its OpenAI-compatible `/v1`. Through `/v1` Ollama keeps its small
  default context window and silently drops most of the digest, and reasoning models spend the answer budget
  thinking. With `ollama`, fat sizes `num_ctx` to the digest and turns thinking off.
- **Size matters on CPU.** The default digest is about 10,000 tokens. A GPU server reads that in a second or two; a
  CPU-only one at 50–150 tokens/s needs minutes. Set `context_bytes = 6000` (about 3,000 tokens) there.
- **Model quality.** fat ranks findings and labels evidence before asking, which helps small models a lot. Models
  below roughly 30B parameters still give noticeably weaker diagnoses than Claude.

All `[ask]` keys are listed in [Configuration](configuration.md).
