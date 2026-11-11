# Updates

[← README](../README.md)

fat checks once a day whether a newer release exists, and `fat update` installs it. Installing on its own is
off unless you turn it on.

## Check for a new release

```bash
fat update --check
```

In the background, the TUI and `fat record` check at most once a day:

- **One request:** fat asks `github.com/honzabit/freaking-awesome-top/releases/latest` where it redirects and
  reads the version from that. Nothing else is sent. GitHub sees your address and a `fat/<version>` user agent.
- **Never in the way:** the check runs in a background thread with a short timeout, and the answer is cached
  (`~/.local/share/fat/update.json` on Linux, `~/Library/Application Support/fat/update.json` on macOS).
  Being offline is silent.
- **Where it shows:** a yellow `⬆ fat 0.2.0 · fat update` in the TUI header, an `info` finding in
  `fat doctor`, and a line in the `fat record` log. Never in `--json` output or MCP replies.

Turn it off with any of:

- `[update] check = false`;
- `FAT_NO_UPDATE_CHECK=1` in the environment;
- `[ask] local_only = true` (fat then never goes to the internet on its own).

## Update

```bash
fat update
```

1. **Verify:** download the release's `SHA256SUMS` and `SHA256SUMS.sig`, and check the signature against the
   release key built into fat. Then download this platform's archive and check its SHA-256 against
   `SHA256SUMS`. A mismatch anywhere stops the update.
2. **Try it:** unpack next to the current binary and run the new binary's `--version`.
3. **Swap:** keep the current binary as `fat.prev` next to it, then replace the binary in one atomic rename.

Go back to the previous binary:

```bash
fat update --rollback
```

fat never escalates. If it can't write to the binary's directory (say `/usr/local/bin` as a normal user), it
says so; run `sudo fat update` there.

fat doesn't replace a binary a package manager owns (Homebrew, Nix, snap, `/usr/bin`), or a development build
in a cargo `target/` directory.

A mirror laid out like GitHub's releases can stand in for GitHub with `FAT_UPDATE_URL`. Downloads are still
checked against the built-in release key.

## Automatic updates

```toml
[update]
auto = true
```

With `auto`, the daily check also installs a newer release, in the same way as `fat update`:

- in the TUI, at start, in the background. The running TUI keeps its version; the header then says
  `fat 0.2.0 installed · restart fat`.
- in `fat record`. On a server this is what keeps fat current.

## The recorder after an update

A running `fat record` keeps running the binary it started with. When its binary is replaced (by
`fat update`, an automatic update, a package manager or by hand), it notices within a minute and prints a
notice. With

```toml
[update]
restart_recorder = true
```

it instead restarts itself into the new binary between two samples: same process id, arguments and
environment, so systemd and launchd see no change. It only restarts into a binary that runs.

## Release signing

Each release's `SHA256SUMS` is signed with an Ed25519 key kept as a GitHub Actions secret. Its public half is
`keys/release-signing.hex`, built into every fat. Someone who could replace the files on the releases page
still couldn't make fat install them without that key. See [RELEASING.md](../RELEASING.md).

fat 0.1.0 has no updater: update it by hand once.
