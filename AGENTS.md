# AGENTS.md

Instructions for AI coding agents working in this repository.

## Project

`lan-watch` is a tiny watcher that alerts when an unknown device joins a home LAN. It ARP-scans once a minute, compares results against a trusted device list, keeps state in SQLite, and sends push notifications through ntfy. It runs on Linux (`arp-scan`, systemd timer) and Windows 10/11 (`SendARP` from `iphlpapi` through `ctypes`, Task Scheduler).

## Layout

- `lan_watch.py` — the entire application (single file, executable, installed as `lan-watch`).
- `tests/test_lan_watch.py` — unit tests (`unittest`).
- `examples/` — example `config.toml` and `devices.toml`.
- `systemd/` — hardened `lan-watch.service` and `lan-watch.timer`.
- `install.sh` — Debian/Ubuntu installer (run as root).
- `install.ps1` — Windows installer (current user, no admin).

## Commands

- Run tests: `python3 -m unittest discover -s tests -v`
- Dry-run a scan (no alerts, no state changes): `python3 lan_watch.py scan --dry-run`
- Syntax check shell: `bash -n install.sh`
- Validate the unit: `systemd-analyze verify systemd/lan-watch.service`

Requires Python >= 3.11 (`tomllib`). On Linux the runtime needs `arp-scan` and raw-socket privileges; on Windows nothing beyond Python. Tests need neither and must pass on both.

## Hard constraints

- **Standard library only.** No third-party dependencies, no `requirements.txt`, no `pip install`. This is a core design goal.
- **Single file.** Keep the application in `lan_watch.py`; do not split into a package without being asked.
- **Low-resource target.** It must run on very old hardware (1 GB RAM netbook). Avoid heavy imports, background threads, and large in-memory structures. Platform-specific modules (`ctypes`, `winsound`, `concurrent.futures`) are imported inside the Windows code paths only, so the Linux path stays as light as before.
- **Cross-platform.** Branch on `IS_WINDOWS` at the edges (paths, scanner, sound player, dashboard system info); `process_scan` and the state must stay identical on both systems.
- **Privacy by default.** Notifications may contain only vendor, IP and the last three MAC octets. Never put person names or full MACs in alerts. Alerts about known devices stay off by default.
- **Security posture.** The service runs as unprivileged `lanwatch` with only `CAP_NET_RAW`. Do not widen systemd capabilities, address families, or filesystem access without a concrete reason, and explain it in the commit message.
- **Never commit secrets or real network data**: ntfy topics, real MAC addresses, `devices.toml`, `config.toml`, or SQLite databases. Examples must use fake values.

## Code conventions

- `from __future__ import annotations`; type hints on public functions, modern syntax (`str | None`, `dict[str, dict]`).
- Keep pure logic (parsing, `process_scan`) separate from I/O so it stays testable; inject `now`, notifier and connection as the existing functions do.
- Match the surrounding style: short functions, minimal comments that explain *why*, no speculative abstraction.
- Parse external input defensively (`arp-scan` output, TOML); never use `shell=True`; pass subprocess arguments as lists.
- Normalize MACs with `normalize_mac` before comparing or storing.

## Testing

- Add or update tests in `tests/test_lan_watch.py` for every behavior change, especially `process_scan` (new device, IP conflict, hysteresis, arm/disarm).
- Tests must be deterministic and offline: use an in-memory SQLite DB, a fake notifier, and fixed timestamps. No real network, `arp-scan`, or ntfy calls.
- Run the full suite before declaring work done.

## Git

- Conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).
- Keep commits focused; do not commit `__pycache__/` or other generated files.
- Do not push, tag, or rewrite history unless asked.

## Docs

- User-facing documentation lives in `README.md` (English). Update it when commands, config keys, or behavior change.
- Keep the "What it cannot do" section honest; do not overclaim detection capabilities.

## Local overrides

If present, also read `AGENTS.local.md` (git-ignored, machine/user specific). It takes precedence on conflicts.
