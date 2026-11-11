# The flight recorder

[← README](../README.md)

Run `fat record` as a background service so time travel always has data to show.

## When fat records

Time travel (`←` in the TUI's Timeline view, `fat history`) only has data for the times something was recording:

- the TUI records while it is open;
- `fat record` records in the foreground.

To record all the time, run `fat record` as a background service. fat does not install one for you; copy and paste
one of the setups below. For one recorder for a whole Linux server, use the system unit in [Servers](server.md)
instead.

| | |
| --- | --- |
| Disk use | About 27 MB per day at the default interval |
| Retention | `history_days` (default 3, so about 80 MB); see [Configuration](configuration.md) and [Storage](storage.md) |
| CPU | About 1–2% of one core; the recorder runs at low CPU and I/O priority |

## macOS (launchd LaunchAgent)

This writes `~/Library/LaunchAgents/dev.fat.record.plist` with the absolute path of your `fat` (launchd does not
expand `~`), checks it, and starts it. Run it as one block:

```bash
FAT="$(command -v fat || echo "$HOME/.cargo/bin/fat")"
mkdir -p ~/Library/LaunchAgents ~/Library/Logs
cat > ~/Library/LaunchAgents/dev.fat.record.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>dev.fat.record</string>
  <key>ProgramArguments</key>  <array><string>$FAT</string><string>record</string></array>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>ThrottleInterval</key>  <integer>30</integer>
  <key>ProcessType</key>       <string>Background</string>
  <key>LowPriorityIO</key>     <true/>
  <key>Nice</key>              <integer>10</integer>
  <key>StandardOutPath</key>   <string>$HOME/Library/Logs/fat-record.log</string>
  <key>StandardErrorPath</key> <string>$HOME/Library/Logs/fat-record.log</string>
</dict>
</plist>
PLIST
plutil -lint ~/Library/LaunchAgents/dev.fat.record.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.fat.record.plist
```

### Check it

See whether it is running:

```bash
launchctl print gui/$(id -u)/dev.fat.record | grep -E 'state|pid'
```

Read its log. The first line says where it writes:

```bash
tail ~/Library/Logs/fat-record.log
```

After a minute, look at what it recorded:

```bash
fat history --since 5m
```

### After upgrading fat

```bash
launchctl kickstart -k gui/$(id -u)/dev.fat.record
```

### Uninstall

```bash
launchctl bootout gui/$(id -u)/dev.fat.record && rm ~/Library/LaunchAgents/dev.fat.record.plist
```

The history stays in `~/Library/Application Support/fat/history.db`; delete it yourself if you want it gone.

## Linux (systemd user unit)

1. Save this as `~/.config/systemd/user/fat-record.service` (change the `ExecStart` path if fat is not in
   `~/.cargo/bin`):

   ```ini
   [Unit]
   Description=fat flight recorder (fat record)

   [Service]
   ExecStart=%h/.cargo/bin/fat record
   Nice=19
   IOSchedulingClass=idle
   Restart=on-failure
   RestartSec=10
   NoNewPrivileges=yes

   [Install]
   WantedBy=default.target
   ```

2. Reload the user manager:

   ```bash
   systemctl --user daemon-reload
   ```

3. Enable and start the recorder:

   ```bash
   systemctl --user enable --now fat-record
   ```

4. Keep recording while you are logged out, and from boot (may need sudo):

   ```bash
   loginctl enable-linger "$USER"
   ```

### Check it

```bash
systemctl --user status fat-record
```

```bash
journalctl --user -u fat-record -n 20
```

After a minute, look at what it recorded:

```bash
fat history --since 5m
```

### After upgrading fat

```bash
systemctl --user restart fat-record
```

### Uninstall

1. Stop and disable the recorder:

   ```bash
   systemctl --user disable --now fat-record
   ```

2. Remove the unit file:

   ```bash
   rm ~/.config/systemd/user/fat-record.service
   ```

3. Reload the user manager:

   ```bash
   systemctl --user daemon-reload
   ```

4. If you enabled linger only for this, turn it off:

   ```bash
   loginctl disable-linger "$USER"
   ```

The history stays in `~/.local/share/fat/history.db`.
