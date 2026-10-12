# Roadmap

Ideas for `lan-watch`, roughly in priority order. Nothing here is a promise; each item should keep the
project's constraints: one file, Python standard library only, runs on a 1 GB netbook, unprivileged
except for `CAP_NET_RAW`.

## Done (v0.1, 2026-10)

- Unknown-device and IP-conflict detection with `arp-scan`, hysteresis for sleeping devices.
- Push alerts through ntfy (random topic), arm/disarm, per-MAC cooldown.
- Hardened systemd service + timer, unprivileged `lanwatch` user.
- Animated full-screen dashboard; events also written to the journal.
- Voice alerts (`lan-watch voice`, systemd user service) with public-domain clips and quiet hours.

## Next

- **Heartbeat / dead man's switch.** If the host freezes or loses power, monitoring stops silently.
  Ping an external check (healthchecks.io or a self-hosted equivalent) after every successful scan;
  the external service alerts when pings stop. Optional `[heartbeat].url` in `config.toml`.
- **Gateway MAC change alert.** If the router's IP is suddenly answered by a different MAC, that is the
  classic sign of ARP spoofing against the whole LAN. Treat it as an urgent alert of its own.
- **Per-device offline threshold.** Printers and phones sleep and flap online/offline every few minutes,
  flooding the event log. Allow `offline_after_misses` per device in `devices.toml`.
- **Python 3.10 support.** Fall back to `tomli` when `tomllib` is missing (Ubuntu 22.04 ships 3.10).
- **CI.** GitHub Actions running the unit tests on Python 3.10–3.13.

## Later

- **Passive, real-time feed from `arpwatch`.** Detect a new station the moment it ARPs instead of on
  the next scan, and catch MAC flip-flops between scans. Read its journal output.
- **Identify unknown devices better.** Resolve hostnames via mDNS/NetBIOS/reverse DNS for unknown
  devices only, so an alert can say "iPhone-de-..." instead of just a vendor.
- **Fresher vendor database.** `ieee-oui.txt` from distro packages gets stale; document or automate
  `get-oui` updates.
- **Rogue DHCP server detection.** Periodically check that only the router answers DHCP.
- **Weekly digest.** One low-priority notification with new devices seen, conflicts and uptime.
- **Away mode / schedules.** Arm stricter alerts (e.g. known devices coming online) only at given hours.
- **Dashboard extras.** 24 h presence timeline per device, alert-only filter, scrolling through history.
- **Voice in more languages.** Ship a Spanish clip set; allow one clip per device kind.
- **Self-hosted ntfy guide.** Keep notification metadata off third-party servers.
- **Export.** Events as JSON/CSV; optional Prometheus text metrics.
- **Packaging.** `.deb` package and an `uninstall.sh`.

## Out of scope (decided)

- **Host health monitoring (temperatures, SMART, emergency shutdown).** It needs root and is hardware
  specific; putting it here would give a network-facing tool the power to read disks and power off
  the machine. It lives in a separate, privileged script. The heartbeat above covers the part that does
  belong here: knowing that the watcher itself stopped.
- **Active probing of devices (port scans).** Possible later as an explicit opt-in, never by default.
