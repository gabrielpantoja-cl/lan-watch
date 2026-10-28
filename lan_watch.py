#!/usr/bin/env python3
"""lan-watch: detect unknown devices on your LAN with ARP and alert through ntfy.

Standard library only (Python >= 3.11). On Linux it runs every minute from a systemd
timer as an unprivileged user holding CAP_NET_RAW and scans with arp-scan. On Windows
it runs every minute from Task Scheduler as the desktop user and asks the OS to ARP
each address (iphlpapi SendARP, no admin rights needed). State lives in SQLite.
"""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request

IS_WINDOWS = os.name == "nt"
# Windows has no service user here: config and state live in the desktop user's profile.
_WIN_HOME = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "lan-watch")
CONFIG_DIR = os.environ.get("LAN_WATCH_CONFIG_DIR", _WIN_HOME if IS_WINDOWS else "/etc/lan-watch")
STATE_DIR = os.environ.get("LAN_WATCH_STATE_DIR", _WIN_HOME if IS_WINDOWS else "/var/lib/lan-watch")
_SOUNDS = (os.path.join(os.path.dirname(os.path.abspath(__file__)), "sounds") if IS_WINDOWS
           else "/usr/local/share/lan-watch/sounds")

DEFAULTS = {
    "scan": {
        "interface": "eth0",
        "retries": 3,
        "ouifile": f"{CONFIG_DIR}/ieee-oui.txt" if IS_WINDOWS else "/usr/share/arp-scan/ieee-oui.txt",
        "arp_scan": "/usr/sbin/arp-scan",
        # Windows only: CIDR to scan ("" = the subnet of the interface holding the default
        # route) and parallel probes. An unanswered SendARP blocks ~3 s, so a /22 needs many.
        "network": "",
        "workers": 256,
    },
    "detect": {
        # Scans without an answer before a device is considered offline. Phones and
        # cameras sleep and miss ARP requests, so one miss must never mean "gone".
        "offline_after_misses": 10,
        # Minimum seconds between two alerts about the same MAC.
        "alert_cooldown_seconds": 6 * 3600,
    },
    "ntfy": {
        "server": "https://ntfy.sh",
        "topic_file": f"{CONFIG_DIR}/ntfy-topic",
    },
    "alerts": {
        "unknown_device": True,
        "address_conflict": True,
        # Presence of known people is sensitive information: off by default.
        "known_online_offline": False,
    },
    "retention": {"events_days": 90},
    "sound": {
        # Played by `lan-watch voice`, which runs inside the desktop session (it needs the
        # session's audio server). Empty path = no sound for that alert.
        "player": "winsound" if IS_WINDOWS else "paplay",  # winsound: Python's built-in player
        "unknown": os.path.join(_SOUNDS, "unknown.wav"),
        "conflict": os.path.join(_SOUNDS, "conflict.wav"),
        "quiet_hours": "",  # e.g. "23:00-07:00": stay silent (ntfy still notifies)
    },
}

ARP_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\t([0-9a-fA-F:]{17})\t(.*)$")


def merge(base: dict, extra: dict) -> dict:
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for key, val in extra.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], val)
        else:
            out[key] = val
    return out


def load_config(path: str | None = None) -> dict:
    path = path or f"{CONFIG_DIR}/config.toml"
    if not os.path.exists(path):
        return merge(DEFAULTS, {})
    with open(path, "rb") as fh:
        return merge(DEFAULTS, tomllib.load(fh))


def normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def load_devices(path: str | None = None) -> dict[str, dict]:
    """Known devices: {mac: {"alias": ..., "kind": ...}} from devices.toml."""
    path = path or f"{CONFIG_DIR}/devices.toml"
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    return {normalize_mac(d["mac"]): d for d in data.get("device", []) if "mac" in d}


def is_random_mac(mac: str) -> bool:
    """Locally administered bit set: typical of 'private Wi-Fi address' phones."""
    return bool(int(mac.split(":")[0], 16) & 0b10)


def parse_arp_scan(text: str) -> list[tuple[str, str, str]]:
    """Return unique (ip, mac, vendor) tuples from arp-scan output."""
    seen: dict[tuple[str, str], str] = {}
    for line in text.splitlines():
        m = ARP_LINE.match(line)
        if not m:
            continue
        ip, mac, vendor = m.group(1), normalize_mac(m.group(2)), m.group(3).strip()
        vendor = re.sub(r"\s*\(DUP: \d+\)$", "", vendor)
        if vendor.startswith("(Unknown"):
            vendor = ""
        seen.setdefault((ip, mac), vendor)
    return [(ip, mac, vendor) for (ip, mac), vendor in seen.items()]


def run_arp_scan(cfg: dict) -> list[tuple[str, str, str]]:
    s = cfg["scan"]
    cmd = [s["arp_scan"], f"--interface={s['interface']}", "--localnet",
           f"--retry={s['retries']}", f"--ouifile={s['ouifile']}"]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"arp-scan failed ({res.returncode}): {res.stderr.strip()[:300]}")
    return parse_arp_scan(res.stdout)


def parse_ipconfig_mask(text: str, ip: str) -> str | None:
    """Subnet mask that `ipconfig` prints after the line holding `ip` (labels are localized)."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(rf"[:\s]{re.escape(ip)}(\(\S+\))?\s*$", line):
            for nxt in lines[i + 1:i + 4]:
                m = re.search(r":\s*(255\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$", nxt)
                if m:
                    return m.group(1)
    return None


def local_network(cfg: dict):
    """(own IP, network to scan) on Windows."""
    import ipaddress
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.0.2.1", 9))  # UDP connect sends nothing; it only picks the route
        me = sock.getsockname()[0]
    if cfg["scan"]["network"]:
        return me, ipaddress.ip_network(cfg["scan"]["network"], strict=False)
    out = subprocess.run(["ipconfig"], capture_output=True, text=True, errors="replace",
                         timeout=30, check=False).stdout
    net = ipaddress.ip_network(f"{me}/{parse_ipconfig_mask(out, me) or '255.255.255.0'}", strict=False)
    if net.num_addresses > 4096:
        raise RuntimeError(f"{net} is too large to probe; set [scan].network to a smaller range")
    return me, net


def oui_vendors(lines, macs) -> dict[str, str]:
    """{mac: vendor} by longest prefix match against arp-scan's ieee-oui.txt format."""
    want = {mac: mac.replace(":", "").upper() for mac in macs if not is_random_mac(mac)}
    best: dict[str, tuple[int, str]] = {}
    for line in lines:
        prefix, _, vendor = line.rstrip("\n").partition("\t")
        if not vendor or line.startswith("#"):
            continue
        prefix = prefix.upper()
        for mac, hexmac in want.items():
            if hexmac.startswith(prefix) and len(prefix) > best.get(mac, (0, ""))[0]:
                best[mac] = (len(prefix), vendor.strip())
    return {mac: vendor for mac, (_, vendor) in best.items()}


def run_sendarp(cfg: dict) -> list[tuple[str, str, str]]:
    """Windows scan: one SendARP per address, in parallel. Answers may come from the ARP
    cache, which Windows expires within ~15-45 s, well inside the offline hysteresis."""
    import ctypes
    import socket
    import struct
    from concurrent.futures import ThreadPoolExecutor
    me, net = local_network(cfg)
    send_arp = ctypes.windll.iphlpapi.SendARP
    send_arp.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]

    def probe(ip):
        buf, size = ctypes.create_string_buffer(8), ctypes.c_ulong(8)
        dest = struct.unpack("<I", socket.inet_aton(ip))[0]
        if send_arp(dest, 0, buf, ctypes.byref(size)) == 0 and size.value == 6:
            return ip, normalize_mac(buf.raw[:6].hex(":"))
        return None

    # Our own address answers from the local adapter; arp-scan never lists itself either.
    targets = [str(h) for h in net.hosts() if str(h) != me]
    with ThreadPoolExecutor(max_workers=max(1, int(cfg["scan"]["workers"]))) as pool:
        found = [r for r in pool.map(probe, targets) if r]
    vendors = {}
    if found and os.path.exists(cfg["scan"]["ouifile"]):
        with open(cfg["scan"]["ouifile"], encoding="utf-8", errors="replace") as fh:
            vendors = oui_vendors(fh, {mac for _, mac in found})
    return [(ip, mac, vendors.get(mac, "")) for ip, mac in found]


def run_scan(cfg: dict) -> list[tuple[str, str, str]]:
    return run_sendarp(cfg) if IS_WINDOWS else run_arp_scan(cfg)


# --- state ---------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, first_seen INTEGER, last_seen INTEGER,
  misses INTEGER DEFAULT 0, online INTEGER DEFAULT 1, last_alert INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts INTEGER, kind TEXT, mac TEXT, ip TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def open_db(path: str | None = None) -> sqlite3.Connection:
    path = path or f"{STATE_DIR}/state.db"
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def meta_get(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def meta_set(conn, key, value):
    conn.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, str(value)))
    conn.commit()


ECHO = False  # set by `scan` so every event also lands in the journal


def log_event(conn, ts, kind, mac="", ip="", detail=""):
    conn.execute("INSERT INTO events(ts,kind,mac,ip,detail) VALUES(?,?,?,?,?)", (ts, kind, mac, ip, detail))
    if ECHO:
        print(f"{kind} {mac} {ip} {detail}".strip())


# --- notifications -------------------------------------------------------------

class Notifier:
    def __init__(self, cfg: dict, dry_run: bool = False):
        self.server = cfg["ntfy"]["server"].rstrip("/")
        self.topic_file = cfg["ntfy"]["topic_file"]
        self.dry_run = dry_run

    def send(self, title: str, body: str, priority: int = 3, tags: str = "") -> bool:
        if self.dry_run:
            print(f"[dry-run] ({priority}) {title} | {body}")
            return True
        try:
            topic = open(self.topic_file).read().strip()
            req = urllib.request.Request(
                f"{self.server}/{topic}", data=body.encode("utf-8"), method="POST",
                headers={"Title": title, "Priority": str(priority), "Tags": tags})
            with urllib.request.urlopen(req, timeout=15):
                return True
        except (OSError, urllib.error.URLError) as exc:
            print(f"lan-watch: could not send notification: {exc}", file=sys.stderr)
            return False


def short_mac(mac: str) -> str:
    return "..:" + ":".join(mac.split(":")[-3:])


# --- core logic ----------------------------------------------------------------

def process_scan(conn, seen, known, cfg, notifier, now=None) -> list[str]:
    """Apply one scan result to the state. Returns the list of event kinds produced."""
    now = int(now if now is not None else time.time())
    armed = meta_get(conn, "armed", "0") == "1"
    det, alerts = cfg["detect"], cfg["alerts"]
    produced: list[str] = []

    def alert(kind, mac, ip, title, body, priority, tags):
        row = conn.execute("SELECT last_alert FROM devices WHERE mac=?", (mac,)).fetchone() if mac else None
        if not armed or (row and row["last_alert"] and now - row["last_alert"] < det["alert_cooldown_seconds"]):
            return
        log_event(conn, now, "alert", mac, ip, kind)  # `lan-watch voice` speaks these
        produced.append("alert")
        notifier.send(title, body, priority, tags)
        if mac:
            conn.execute("UPDATE devices SET last_alert=? WHERE mac=?", (now, mac))

    # Address conflicts: one IP answered by two different MACs (ARP spoofing hint).
    by_ip: dict[str, set[str]] = {}
    for ip, mac, _ in seen:
        by_ip.setdefault(ip, set()).add(mac)
    for ip, macs in by_ip.items():
        if len(macs) > 1:
            detail = ",".join(sorted(macs))
            log_event(conn, now, "conflict", "", ip, detail)
            produced.append("conflict")
            last = int(meta_get(conn, f"conflict:{ip}", "0"))
            if alerts["address_conflict"] and armed and (last == 0 or now - last >= det["alert_cooldown_seconds"]):
                log_event(conn, now, "alert", "", ip, "conflict")
                produced.append("alert")
                if notifier.send("lan-watch: IP conflict",
                                 f"IP {ip} is being answered by {len(macs)} different devices "
                                 f"({', '.join(short_mac(m) for m in sorted(macs))}). Possible ARP spoofing.",
                                 5, "rotating_light"):
                    meta_set(conn, f"conflict:{ip}", now)

    seen_macs = set()
    for ip, mac, vendor in seen:
        seen_macs.add(mac)
        row = conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        is_new = row is None
        came_online = (row is not None and not row["online"])
        if is_new:
            conn.execute("INSERT INTO devices(mac,ip,vendor,first_seen,last_seen,misses,online) VALUES(?,?,?,?,?,0,1)",
                         (mac, ip, vendor, now, now))
            log_event(conn, now, "new", mac, ip, vendor)
            produced.append("new")
        else:
            conn.execute("UPDATE devices SET ip=?, vendor=COALESCE(NULLIF(?,''),vendor), last_seen=?, misses=0, online=1 WHERE mac=?",
                         (ip, vendor, now, mac))
            if came_online:
                log_event(conn, now, "online", mac, ip, "")
                produced.append("online")
        if mac in known:
            if came_online and alerts["known_online_offline"]:
                alert("online", mac, ip, "lan-watch: device online", f"{known[mac].get('alias', 'known device')} is online.", 2, "")
        elif (is_new or came_online) and alerts["unknown_device"]:
            hint = " Random MAC (probably a phone)." if is_random_mac(mac) else ""
            alert("unknown", mac, ip, "lan-watch: unknown device on the network",
                  f"Vendor: {vendor or 'unknown'}. IP: {ip}. MAC: {short_mac(mac)}.{hint}", 4, "warning")

    # Misses only count if the scan answered at all (otherwise the interface is down).
    if seen:
        for row in conn.execute("SELECT * FROM devices WHERE online=1").fetchall():
            if row["mac"] in seen_macs:
                continue
            misses = row["misses"] + 1
            if misses >= det["offline_after_misses"]:
                conn.execute("UPDATE devices SET misses=?, online=0 WHERE mac=?", (misses, row["mac"]))
                log_event(conn, now, "offline", row["mac"], row["ip"], "")
                produced.append("offline")
                if row["mac"] in known and alerts["known_online_offline"]:
                    alert("offline", row["mac"], row["ip"], "lan-watch: device offline",
                          f"{known[row['mac']].get('alias', 'known device')} went offline.", 2, "")
            else:
                conn.execute("UPDATE devices SET misses=? WHERE mac=?", (misses, row["mac"]))
    conn.execute("INSERT INTO meta(key,value) VALUES('last_scan',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (str(now),))
    conn.commit()
    return produced


def prune(conn, cfg, now=None):
    now = int(now if now is not None else time.time())
    cutoff = now - cfg["retention"]["events_days"] * 86400
    conn.execute("DELETE FROM events WHERE ts<?", (cutoff,))
    conn.execute("DELETE FROM devices WHERE last_seen<?", (cutoff,))
    conn.commit()


# --- CLI -----------------------------------------------------------------------

def cmd_scan(args):
    global ECHO
    ECHO = True
    cfg, known = load_config(args.config), load_devices(args.devices)
    conn = open_db(args.db)
    try:
        seen = run_scan(cfg)
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"lan-watch: {exc}", file=sys.stderr)
        return 1
    process_scan(conn, seen, known, cfg, Notifier(cfg, dry_run=args.dry_run))
    prune(conn, cfg)
    return 0


def fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


def cmd_list(args):
    known, conn = load_devices(args.devices), open_db(args.db)
    rows = conn.execute("SELECT * FROM devices ORDER BY online DESC, ip").fetchall()
    print(f"{'MAC':17}  {'IP':15}  {'STATE':7}  {'ALIAS':18}  {'LAST SEEN':16}  VENDOR")
    for r in rows:
        alias = known.get(r["mac"], {}).get("alias", "** UNLABELED **")
        print(f"{r['mac']:17}  {r['ip'] or '-':15}  {'online' if r['online'] else 'offline':7}  "
              f"{alias:18}  {fmt_ts(r['last_seen']):16}  {r['vendor'] or '-'}"
              f"{'  [random MAC]' if is_random_mac(r['mac']) else ''}")
    return 0


def cmd_status(args):
    conn, known = open_db(args.db), load_devices(args.devices)
    total = conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"]
    online = conn.execute("SELECT COUNT(*) c FROM devices WHERE online=1").fetchone()["c"]
    unl = sum(1 for r in conn.execute("SELECT mac FROM devices") if r["mac"] not in known)
    print(f"armed: {meta_get(conn, 'armed', '0') == '1'} | devices: {total} | online: {online} | unlabeled: {unl}")
    return 0


def _read_state(path):
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        devs = conn.execute("SELECT * FROM devices ORDER BY online DESC, ip").fetchall()
        evs = conn.execute("SELECT * FROM events ORDER BY ts DESC, id DESC LIMIT 200").fetchall()
        return devs, evs, meta_get(conn, "armed", "0") == "1", int(meta_get(conn, "last_scan", "0"))
    finally:
        conn.close()


def _sysinfo_windows():
    import ctypes

    class MemStatus(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + \
                   [(n, ctypes.c_ulonglong) for n in ("total", "avail", "tpage", "apage", "tvirt", "avirt", "aext")]

    k32 = ctypes.windll.kernel32
    st = MemStatus()
    st.dwLength = ctypes.sizeof(st)
    k32.GlobalMemoryStatusEx(ctypes.byref(st))
    k32.GetTickCount64.restype = ctypes.c_ulonglong
    return None, {"MemTotal": st.total >> 20, "MemAvailable": st.avail >> 20}, k32.GetTickCount64() // 1000


def _enable_ansi():
    """Old Windows consoles interpret escape codes only after opting in (Windows Terminal always does)."""
    if IS_WINDOWS:
        import ctypes
        k32 = ctypes.windll.kernel32
        handle, mode = k32.GetStdHandle(-11), ctypes.c_ulong()
        if k32.GetConsoleMode(handle, ctypes.byref(mode)):
            k32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING


def _sysinfo():
    if IS_WINDOWS:
        return _sysinfo_windows()
    mem = {}
    with open("/proc/meminfo") as fh:
        for line in fh:
            key, val = line.split(":", 1)
            if key in ("MemTotal", "MemAvailable"):
                mem[key] = int(val.split()[0]) // 1024
    with open("/proc/uptime") as fh:
        up = int(float(fh.read().split()[0]))
    return os.getloadavg()[0], mem, up


def _ago(seconds):
    seconds = max(0, int(seconds))
    if seconds < 120:
        return f"{seconds}s"
    return f"{seconds // 60}m" if seconds < 7200 else f"{seconds // 3600}h"


def cmd_dashboard(args):
    """Full-screen animated live view: devices, scan countdown, and as many recent events as fit."""
    import platform
    import shutil
    G, BG, R, Y, DIM, B, X, EL = ("\033[32m", "\033[92m", "\033[31m", "\033[33m", "\033[2m", "\033[1m",
                                  "\033[0m", "\033[K")
    spin = "|/-\\"
    path = args.db or f"{STATE_DIR}/state.db"
    host = platform.node()
    scan_span = 50  # timer fires every 60 s, measured from the start of the previous ~10 s scan
    state, known, loaded, frame = None, {}, 0.0, 0
    _enable_ansi()
    sys.stdout.write("\033[?25l\033[2J")
    try:
        while True:
            now = time.time()
            if state is None or now - loaded >= args.refresh:
                try:
                    state, known = _read_state(path), load_devices(args.devices)
                except sqlite3.Error:
                    pass
                load, mem, up = _sysinfo()
                loaded = now
            if state is None:
                time.sleep(1)
                continue
            devs, evs, armed, last = state
            cols, rows = shutil.get_terminal_size((100, 30))
            w = max(60, min(cols - 2, 118))
            blink = frame % 2 == 0
            lines = []

            pulse = (BG + B + "*" if blink else DIM + "*") if armed else Y + "o"
            lines.append(f" {BG}{B}LAN-WATCH{X}{G} :: {host} :: {time.strftime('%Y-%m-%d %H:%M:%S')} :: "
                         f"{pulse} {'ARMED' if armed else 'NOT ARMED'}{X}")
            barw = w - 30
            since = now - last if last else scan_span + 1
            if since <= scan_span:
                filled = int(barw * since / scan_span)
                bar, status = "#" * filled + "." * (barw - filled), f"next scan in {int(scan_span - since):2d}s"
            else:
                k = frame % barw
                bar = "".join("#" if (i - k) % barw < 8 else "." for i in range(barw))
                status = f"scanning {spin[frame % 4]}     "
            lines.append(f" {G}[{bar}] {status}{X}")
            lines.append(f" {DIM}load {'  - ' if load is None else f'{load:4.2f}'}   mem {mem.get('MemTotal', 0) - mem.get('MemAvailable', 0)}/"
                         f"{mem.get('MemTotal', 0)} MiB   uptime {up // 3600}h{up % 3600 // 60:02d}m   "
                         f"iface arp   frame {frame}{X}")
            lines.append(G + " " + "=" * w + X)
            lines.append(f" {B}  {'STATE':8}{'ALIAS':22}{'IP':16}{'MAC':19}{'SEEN':8}VENDOR{X}")
            sweep = (frame // 2) % max(1, len(devs))
            for i, d in enumerate(devs):
                alias = known.get(d["mac"], {}).get("alias")
                if not alias:
                    color = R + B if blink else R
                elif d["online"]:
                    color = BG + B if i == sweep else G
                else:
                    color = DIM
                mark = ">" if i == sweep else " "
                lines.append(f" {color}{mark} {'online' if d['online'] else 'offline':8}{(alias or '!! UNKNOWN !!')[:21]:22}"
                             f"{d['ip'] or '-':16}{d['mac']:19}{_ago(now - (d['last_seen'] or now)):8}"
                             f"{(d['vendor'] or '-')[:max(0, w - 76)]}{X}")
            lines.append(G + " " + "=" * w + X)
            unknown = sum(1 for d in devs if d["mac"] not in known)
            lines.append(f" {B}EVENTS{X}   {(R + B) if unknown else G}{unknown} unknown{X}   "
                         f"{G}{sum(1 for d in devs if d['online'])}/{len(devs)} online{X}")
            room = rows - len(lines) - 1  # the event log fills the rest of the screen
            n_events = max(3, min(args.events, room) if args.events else room)
            for e in evs[:n_events]:
                is_known = e["mac"] in known
                who = known.get(e["mac"], {}).get("alias") or e["mac"] or e["detail"]
                color = {"new": G if is_known else R + B, "conflict": R + B, "alert": R + B, "online": G, "offline": DIM}.get(e["kind"], "")
                if now - e["ts"] < 120 and blink:
                    color += B + "\033[7m"
                lines.append(f" {DIM}{fmt_ts(e['ts'])}{X}  {color}{e['kind']:9}{X}{who[:40]:42}{e['ip'] or ''}")

            sys.stdout.write("\033[H" + "".join(line + EL + "\n" for line in lines[:rows - 1]) + "\033[J")
            sys.stdout.flush()
            frame += 1
            time.sleep(1.0 / max(1, args.fps))
    except KeyboardInterrupt:
        return 0
    finally:
        sys.stdout.write(X + "\033[?25h\n")
        sys.stdout.flush()


def in_quiet_hours(spec: str, now: time.struct_time) -> bool:
    """True if `now` falls inside an "HH:MM-HH:MM" window (which may cross midnight)."""
    if not spec:
        return False
    start, end = ((int(h) * 60 + int(m)) for h, m in (part.split(":") for part in spec.split("-")))
    minute = now.tm_hour * 60 + now.tm_min
    return start <= minute < end if start <= end else (minute >= start or minute < end)


def cmd_voice(args):
    """Watch the event log and play a sound for each alert. Run it inside the desktop session."""
    try:
        cfg = load_config(args.config)
    except OSError:  # the config is readable only by root/lanwatch: fall back to defaults
        cfg = merge(DEFAULTS, {})
    snd = cfg["sound"]

    def play(kind):
        path = snd.get(kind) or ""
        if not os.path.exists(path):
            print(f"lan-watch voice: no sound for '{kind}' ({path or 'not set'})", file=sys.stderr)
            return
        if snd["player"] == "winsound":
            import winsound
            winsound.PlaySound(path, winsound.SND_FILENAME)
        else:
            subprocess.run([snd["player"], path], timeout=60, check=False)

    if args.test:
        play(args.test)
        return 0
    db = args.db or f"{STATE_DIR}/state.db"
    last_id = None
    while True:
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            if last_id is None:  # start from "now": never replay old alerts
                last_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            rows = conn.execute("SELECT id, detail FROM events WHERE kind='alert' AND id>? ORDER BY id",
                                (last_id,)).fetchall()
            conn.close()
        except sqlite3.Error as exc:
            print(f"lan-watch voice: {exc}", file=sys.stderr)
            rows = []
        for row in rows:
            last_id = row["id"]
            if in_quiet_hours(snd.get("quiet_hours", ""), time.localtime()):
                continue
            play(row["detail"])
        time.sleep(args.interval)


def cmd_arm(args):
    meta_set(open_db(args.db), "armed", "0" if args.off else "1")
    print("alerts disarmed" if args.off else "alerts armed")
    return 0


def cmd_test_alert(args):
    cfg = load_config(args.config)
    ok = Notifier(cfg).send("lan-watch: test", "If you can read this, alerts work.", 3, "white_check_mark")
    print("sent" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="lan-watch", description=__doc__.splitlines()[0])
    for opt in ("--config", "--devices", "--db"):
        p.add_argument(opt)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="run one scan and process it")
    s.add_argument("--dry-run", action="store_true", help="print alerts instead of sending them")
    s.set_defaults(fn=cmd_scan)
    sub.add_parser("list", help="show every device seen, flagging unlabeled ones").set_defaults(fn=cmd_list)
    sub.add_parser("status", help="short summary").set_defaults(fn=cmd_status)
    a = sub.add_parser("arm", help="enable alerts (before that, scans only record)")
    a.add_argument("--off", action="store_true")
    a.set_defaults(fn=cmd_arm)
    sub.add_parser("test-alert", help="send a test notification").set_defaults(fn=cmd_test_alert)
    v = sub.add_parser("voice", help="play a sound for every alert (run inside the desktop session)")
    v.add_argument("--interval", type=float, default=3, help="seconds between checks")
    v.add_argument("--test", choices=["unknown", "conflict"], help="play one sound and exit")
    v.set_defaults(fn=cmd_voice)
    d = sub.add_parser("dashboard", help="full-screen live view of devices and events")
    d.add_argument("--fps", type=int, default=4, help="frames per second of the animation")
    d.add_argument("--refresh", type=float, default=2, help="seconds between database reads")
    d.add_argument("--events", type=int, default=0, help="max recent events to show (0 = fill the screen)")
    d.set_defaults(fn=cmd_dashboard)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
