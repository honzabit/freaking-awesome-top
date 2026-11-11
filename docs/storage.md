# Storage

[← README](../README.md)

The Fs tab (`3`, right after Ports) and `fat fs` answer three questions about disk space.

## What eats my storage?

The table lists the children of the current directory, so you can drill down to what takes the space.

Each row shows:

- allocated size (hard links counted once);
- a bar and the share of the parent;
- the number of files below;
- the age of the newest change.

Navigation and markers:

| Key / marker | Meaning |
| --- | --- |
| `⏎` | drill into the directory |
| `←` | go up |
| `⛁` | another filesystem (not counted) |
| `🔒` | could not be read |
| `…` | still being scanned (numbers are a lower bound) |

The line under the table explains well-known space hogs, with safe advice:

- macOS and general: `~/Library/Caches`, Xcode DerivedData and CoreSimulator, Docker Desktop and OrbStack data,
  `~/.cargo/registry`, Rust `target/`, `node_modules`, `~/.npm`, `~/.cache`, Chrome profiles, `/private/var/vm`
  (swap), `/private/var/folders`, APFS local snapshots.
- Linux: `/var/log/journal` (`journalctl --vacuum-size`), `/var/lib/docker` (`docker system df` / `prune`),
  `/var/cache/apt`, snap revisions.

## What is eating my space so fast?

The growth view shows what grew recently and which processes wrote it.

- **Δ column:** how much each child grew in the window (10m, 1h or 24h; `w` cycles).
- **WRITE/s column:** which processes write there.
- **`g`** switches to a flat list of:
  - the fastest growers anywhere;
  - the space held by deleted-but-still-open files (restarting the holder frees it);
  - the top writing processes (`⏎` = why).

The same from the command line:

```bash
fat fs --growth --since 10m
```

How the list is built:

- It is as specific as the evidence allows and never counts bytes twice.
- A directory is broken down into the children that carry its growth. A home directory or `/` always is.
- A directory shows up itself only as "other under DIR", with what those children leave unexplained, and only
  when that is at least 20% of it and 10 MB.
- Deleted-but-open files are grouped by the process holding them. Files under 1 MB are only counted.

### Where growth numbers come from

Every growth number says where it came from:

| Evidence | Meaning |
| --- | --- |
| `fsevents` | macOS FSEvents journal replay: exact paths, works retroactively (even for the time before fat started). |
| `watch` | Linux fanotify (root) or inotify watches: exact paths, only since fat started watching. |
| `open-files` | Files a writing process holds open, sized now vs earlier: attributes growth to a process. |
| `scan-diff` | Two scans of the tree compared: exact, but coarse in time. |
| `mtime≤` | Modified within the window, at its current size: an upper bound on growth. |

## Which volume, and when is it full?

The strip at the top shows every volume and how soon it fills up.

For each volume:

- used/total;
- the fill rate (`+1.2G/10m`);
- `full in 3h` (yellow under a day, red under 2 hours);
- device I/O;
- macOS purgeable space.

## How the scan behaves

The scan is lazy, low-priority and cached, so it stays out of your way.

### Before you open the tab

No directory is read until you open the Fs tab (or run `fat fs`). Before that the TUI only:

- asks each mounted volume for its capacity (`statfs`, every sample, on its own thread);
- once a minute, lists the deleted files processes still hold open, for the volume strip and `fat doctor`.

### The background scan

- `/` is then scanned in the background at the lowest priority: macOS `QOS_CLASS_BACKGROUND` (which also throttles
  its I/O); Linux nice 19 and the idle I/O class.
- The directory you are looking at is scanned first, with partial results as it goes.
- CPU limits:

  | Situation | Limit |
  | --- | --- |
  | background | a quarter of a core |
  | Fs tab on screen | one core |
  | the directory you opened | 1.5 cores |
  | `fat fs PATH` and the MCP `fs_*` tools | 1.5 cores, at utility priority (macOS `QOS_CLASS_UTILITY`; Linux nice 10) |

- A first full scan of a 20M-file Mac takes roughly 15 minutes with the tab open, longer in the background.

### Refreshing

- Every 10 minutes the tree is re-checked. A directory is re-read if its entries changed, its big files changed,
  it holds files written in the last hour, or (macOS) FSEvents reported it changed.
- Everything else waits for the 6-hourly full pass.
- Results are cached on disk. The next start shows numbers immediately, resumes an interrupted first scan
  instead of starting over, and refreshes them.

### What is counted

- Sizes count APFS clones in full, like `du`. On a Mac with many cloned files (uv, pnpm, `cp -c`) the tree can
  add up to more than the volume's used space.
- Network, FUSE, autofs and removable mounts are never descended automatically. Open one with `⏎` to read it.
- On macOS the Data volume is counted once, even though `/Users`, `/Applications`, `/private` … reach it through
  firmlinks.

### Sizes in the past

`fat record` also records volume use and directory sizes. Rewinding (`←` in Timeline, then `3`) shows the sizes
as they were, marked `⏪ as of hh:mm:ss`.

## Privacy (macOS)

The background scan never triggers macOS privacy prompts.

- Reading these places from a terminal triggers "Terminal would like to access …" prompts, unless the terminal has
  Full Disk Access: `~/Desktop`, `~/Documents`, `~/Downloads`, Mail, Messages, Photos libraries, and removable or
  network volumes.
- The background scan never reads them. They show as `🔒 protected` and are not counted.
- fat reads one when you ask: pressing `⏎` on it, `fat fs ~/Documents`, or the `fs_list` tool.
- If the terminal already has Full Disk Access, fat detects it and scans everything.

## fat never deletes

No key, command or tool removes, moves or truncates files. fat only writes its own cache and database. The advice
it prints is for you to act on.

## Doctor findings

`fat doctor` adds storage findings:

- a volume ≥ 90% full (crit at 97%);
- a volume that will be full within a day (crit within 2 hours), naming the paths and processes growing;
- more than 1 GiB held by deleted-but-open files, naming the process to restart;
- large swap files in `/System/Volumes/VM`.
