# lan-watch

**A tiny, dependency-free watcher that tells you when an unknown device joins your home network.**

It runs `arp-scan` once a minute, compares what answers against a list of devices you trust, and sends a push notification through [ntfy](https://ntfy.sh) when something new shows up. Pure Python standard library, one file, SQLite for state. It is built to run on very old hardware (it was written for a 2010 netbook with 1 GB of RAM).

## Why not NetAlertX / WatchYourLAN / Fing?

They are good projects, and you should use them if they fit. `lan-watch` exists for the case where they do not:
NetAlertX wants Docker and more RAM than a netbook has, WatchYourLAN has had no commits for over a year, and Fing is closed source. If you only need "tell me about unknown devices", a single audited file beats a web stack.

## What it does

- Detects **new/unknown devices** and **IP address conflicts** (one IP answered by two MACs, a sign of ARP spoofing).
- **Hysteresis**: a device is only "offline" after N consecutive missed scans, because phones and cameras sleep and miss ARP requests.
- **Arm/disarm**: scans only record until you run `lan-watch arm`, so the first run does not flood you with alerts.
- **Privacy by default**: alerts about known devices are off (who is home is sensitive), and notifications carry only the vendor, IP and the last three MAC octets, never a person's name.
- Runs as an unprivileged `lanwatch` user holding only `CAP_NET_RAW`, under a hardened systemd unit.

## What it cannot do

- It sees only the LAN it is attached to (a guest network isolated by your router is invisible).
- It cannot see failed connection attempts; only your router can.
- Phones with a "private Wi-Fi address" appear as new devices if the setting changes.
- An attacker who clones the MAC of a trusted device is invisible to MAC allow-listing.

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

The ntfy topic is generated randomly; treat it like a password. For stronger privacy, self-host ntfy and change `[ntfy].server`.

## Commands

| Command | Does |
|---|---|
| `lan-watch scan [--dry-run]` | one scan (the timer runs this) |
| `lan-watch list` | every device seen, flagging unlabeled ones |
| `lan-watch status` | one-line summary |
| `lan-watch arm [--off]` | enable / disable alerts |
| `lan-watch test-alert` | send a test notification |
| `lan-watch dashboard [--refresh N]` | full-screen live view of devices and recent events |

## Live dashboard

`lan-watch dashboard` redraws a green-on-black view every few seconds: every device with its state, alias, IP and MAC, plus the latest events (new, online, offline, conflict). Unknown devices show in red. To have it open full screen whenever the desktop starts, copy `examples/lan-watch-dashboard.desktop` to `~/.config/autostart/` (Xfce). Keep in mind that anyone who can see that screen sees who is home.

Every event is also written to the journal: `journalctl -u lan-watch.service -f`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
