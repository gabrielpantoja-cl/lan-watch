# lan-watch

**A tiny, dependency-free watcher that tells you when an unknown device joins your home network.**

It ARP-scans your LAN once a minute (`arp-scan` on Linux, the built-in `SendARP` API on Windows), compares what answers against a list of devices you trust, and sends a push notification through [ntfy](https://ntfy.sh) when something new shows up. Pure Python standard library, one file, SQLite for state. It runs on Linux and Windows 10/11, and is built to run on very old hardware (it was written for a 2010 netbook with 1 GB of RAM).

## Why not NetAlertX / WatchYourLAN / Fing?

They are good projects, and you should use them if they fit. `lan-watch` exists for the case where they do not:
NetAlertX wants Docker and more RAM than a netbook has, WatchYourLAN has had no commits for over a year, and Fing is closed source. If you only need "tell me about unknown devices", a single audited file beats a web stack.

## What it does

- Detects **new/unknown devices** and **IP address conflicts** (one IP answered by two MACs, a sign of ARP spoofing).
- **Hysteresis**: a device is only "offline" after N consecutive missed scans, because phones and cameras sleep and miss ARP requests.
- **Arm/disarm**: scans only record until you run `lan-watch arm`, so the first run does not flood you with alerts.
- **Privacy by default**: alerts about known devices are off (who is home is sensitive), and notifications carry only the vendor, IP and the last three MAC octets, never a person's name.
- Linux: runs as an unprivileged `lanwatch` user holding only `CAP_NET_RAW`, under a hardened systemd unit.
- Windows: runs as your own user from Task Scheduler; no admin rights, no drivers (no Npcap), nothing to install but Python.

## What it cannot do

- It sees only the LAN it is attached to (a guest network isolated by your router is invisible).
- It cannot see failed connection attempts; only your router can.
- Phones with a "private Wi-Fi address" appear as new devices if the setting changes.
- An attacker who clones the MAC of a trusted device is invisible to MAC allow-listing.
- On Windows it watches only while you are logged in, and `SendARP` may answer from the OS ARP cache, so a device that leaves is noticed a little later (the offline hysteresis absorbs it).

## Install (Debian/Ubuntu, Python >= 3.11)

```bash
sudo apt install arp-scan
sudo ./install.sh
sudoedit /etc/lan-watch/config.toml          # set your interface
sudo systemctl enable --now lan-watch.timer
sudo -u lanwatch lan-watch list              # see what answered; label the devices
sudoedit /etc/lan-watch/devices.toml         # add your devices (see examples/)
sudo cat /etc/lan-watch/ntfy-topic           # subscribe your phone to this topic in the ntfy app
sudo -u lanwatch lan-watch test-alert
sudo -u lanwatch lan-watch arm
```

## Install (Windows 10/11, Python >= 3.11)

From PowerShell in the repo directory (no admin needed):

```powershell
.\install.ps1 -Dashboard                       # add -Voice to speak alerts out loud
notepad $env:LOCALAPPDATA\lan-watch\devices.toml   # add your devices (see examples/)
lan-watch list                                 # in a new terminal; see what answered
Get-Content $env:LOCALAPPDATA\lan-watch\ntfy-topic  # subscribe your phone to this topic
lan-watch test-alert
lan-watch arm
```

It copies the program to `%LOCALAPPDATA%\Programs\lan-watch` (added to your `PATH`), keeps config and state in `%LOCALAPPDATA%\lan-watch`, downloads the vendor database `ieee-oui.txt`, and registers the task `lan-watch scan` (every minute, also on battery). The scan probes the subnet of the interface that holds the default route; set `[scan].network` to change it. `-Dashboard` opens the live view in a Windows Terminal window at logon; add `-Position "x,y"` to open it maximized on the monitor holding that point, or `-Fullscreen`. `.\install.ps1 -Uninstall` removes it all but your config and state.

The ntfy topic is generated randomly; treat it like a password. For stronger privacy, self-host ntfy and change `[ntfy].server`.

## Commands

| Command | Does |
|---|---|
| `lan-watch scan [--dry-run]` | one scan (the timer runs this) |
| `lan-watch list` | every device seen, flagging unlabeled ones |
| `lan-watch status` | one-line summary |
| `lan-watch arm [--off]` | enable / disable alerts |
| `lan-watch test-alert` | send a test notification |
| `lan-watch voice [--test unknown]` | speak every alert out loud (desktop session) |
| `lan-watch dashboard [--fps N]` | animated full-screen live view of devices and recent events |

## Managing known devices

`/etc/lan-watch/devices.toml` (Windows: `%LOCALAPPDATA%\lan-watch\devices.toml`) is the allow-list: any MAC not listed there is "unknown" and triggers an alert. It is re-read on every scan, so no restart is needed (the dashboard picks changes up within seconds). Keep your real file out of public repositories; a good pattern is a private repo as the source of truth plus a small deploy script that copies it to the host.

**Add a device**

1. Connect it to the network (the "unknown device" alert is expected) and find its MAC with `sudo -u lanwatch lan-watch list` (shown as `** UNLABELED **`) or in your router's app.
2. Append a block to `devices.toml`:
   ```toml
   [[device]]
   mac = "aa:bb:cc:dd:ee:ff"
   alias = "guest-laptop"     # lowercase, no spaces
   kind = "laptop"            # free text: phone, laptop, camera, tv, printer...
   ```
3. Check: `sudo -u lanwatch lan-watch status` should show `unlabeled: 0`.

**Edit a device**: change `alias` or `kind`. The MAC is the key: a different MAC is a different device.

**Remove a device**: delete its block. It does not alert right away; it alerts the next time it reconnects after being offline (`offline_after_misses` scans without an answer).

**Phones and "private Wi-Fi address"**: use the MAC the phone shows *on this network*, not the hardware MAC in its settings. If the owner turns the feature off or "forgets" the network, the MAC changes and the phone shows up as unknown again.

## Voice alerts

`lan-watch voice` runs inside the desktop session (as a systemd user service, see `systemd/lan-watch-voice.service`), watches the event log and plays a voice clip for every alert: "a new, unknown device has just connected to your network" or "two devices are claiming the same address". The clips in `sounds/` were made offline with Piper and a public-domain voice; replace them with any WAV you like. Set `[sound].quiet_hours = "23:00-07:00"` to keep the house quiet at night (push notifications still arrive). Try it with `lan-watch voice --test unknown`. On Windows it plays through Python's built-in `winsound` (`install.ps1 -Voice` starts it at logon).

## Live dashboard

`lan-watch dashboard` is an animated green-on-black view (4 fps by default, `--fps` to change): a live clock, a countdown bar to the next scan, a radar sweep over the device list with time since each device was last seen, and the event log filling the rest of the screen (fresh events blink, unknown devices in red). It reads the database read-only and costs about 3 % CPU on an Atom N450 (the terminal itself takes ~10 %). To have it open full screen whenever the desktop starts, copy `examples/lan-watch-dashboard.desktop` to `~/.config/autostart/` (Xfce); on Windows use `install.ps1 -Dashboard`. Keep in mind that anyone who can see that screen sees who is home.

On Linux every event is also written to the journal: `journalctl -u lan-watch.service -f`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
