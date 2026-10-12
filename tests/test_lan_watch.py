import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import lan_watch as lw

SAMPLE = (
    "Interface: eth0, type: EN10MB, MAC: aa:aa:aa:aa:aa:aa, IPv4: 192.0.2.10\n"
    "Starting arp-scan 1.10.0 with 1024 hosts\n"
    "192.0.2.1\t00:00:5e:00:53:01\tExample Router Inc.\n"
    "192.0.2.51\t02:00:5e:10:00:51\t(Unknown: locally administered)\n"
    "192.0.2.24\t00:00:5e:00:53:24\tExample Laptops Ltd\n"
    "192.0.2.24\t00:00:5e:00:53:24\tExample Laptops Ltd (DUP: 2)\n"
    "\n3 packets received by filter\n"
)


class FakeNotifier:
    def __init__(self):
        self.sent = []

    def send(self, title, body, priority=3, tags=""):
        self.sent.append((title, body, priority))
        return True


def fresh():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(lw.SCHEMA)
    return conn, FakeNotifier(), lw.merge(lw.DEFAULTS, {})


class ParseTests(unittest.TestCase):
    def test_parse_dedupes_and_cleans_vendor(self):
        rows = lw.parse_arp_scan(SAMPLE)
        self.assertEqual(len(rows), 3)
        self.assertIn(("192.0.2.51", "02:00:5e:10:00:51", ""), rows)
        self.assertIn(("192.0.2.24", "00:00:5e:00:53:24", "Example Laptops Ltd"), rows)

    def test_random_mac(self):
        self.assertTrue(lw.is_random_mac("02:00:5e:10:00:51"))
        self.assertFalse(lw.is_random_mac("00:00:5e:00:53:01"))


class LogicTests(unittest.TestCase):
    def test_no_alerts_until_armed(self):
        conn, n, cfg = fresh()
        lw.process_scan(conn, [("10.0.0.5", "ee:00:00:00:00:01", "")], {}, cfg, n, now=1000)
        self.assertEqual(n.sent, [])

    def test_unknown_device_alerts_once_then_cooldown(self):
        conn, n, cfg = fresh()
        lw.meta_set(conn, "armed", 1)
        seen = [("10.0.0.5", "aa:00:00:00:00:01", "Acme")]
        lw.process_scan(conn, seen, {}, cfg, n, now=1000)
        lw.process_scan(conn, seen, {}, cfg, n, now=1060)
        self.assertEqual(len(n.sent), 1)
        self.assertEqual(n.sent[0][2], 4)

    def test_known_device_silent_by_default(self):
        conn, n, cfg = fresh()
        lw.meta_set(conn, "armed", 1)
        known = {"aa:00:00:00:00:01": {"alias": "tv"}}
        lw.process_scan(conn, [("10.0.0.5", "aa:00:00:00:00:01", "")], known, cfg, n, now=1000)
        self.assertEqual(n.sent, [])

    def test_offline_needs_consecutive_misses(self):
        conn, n, cfg = fresh()
        mac = "aa:00:00:00:00:01"
        lw.process_scan(conn, [("10.0.0.5", mac, "")], {}, cfg, n, now=0)
        other = [("10.0.0.1", "aa:00:00:00:00:99", "")]
        for i in range(cfg["detect"]["offline_after_misses"] - 1):
            lw.process_scan(conn, other, {}, cfg, n, now=60 * (i + 1))
        self.assertEqual(conn.execute("SELECT online FROM devices WHERE mac=?", (mac,)).fetchone()[0], 1)
        lw.process_scan(conn, other, {}, cfg, n, now=9999)
        self.assertEqual(conn.execute("SELECT online FROM devices WHERE mac=?", (mac,)).fetchone()[0], 0)

    def test_empty_scan_does_not_count_misses(self):
        conn, n, cfg = fresh()
        mac = "aa:00:00:00:00:01"
        lw.process_scan(conn, [("10.0.0.5", mac, "")], {}, cfg, n, now=0)
        for i in range(30):
            lw.process_scan(conn, [], {}, cfg, n, now=60 * i)
        self.assertEqual(conn.execute("SELECT online FROM devices WHERE mac=?", (mac,)).fetchone()[0], 1)

    def test_ip_conflict_alerts_urgent(self):
        conn, n, cfg = fresh()
        lw.meta_set(conn, "armed", 1)
        seen = [("10.0.0.1", "aa:00:00:00:00:01", ""), ("10.0.0.1", "bb:00:00:00:00:02", "")]
        lw.process_scan(conn, seen, {"aa:00:00:00:00:01": {}, "bb:00:00:00:00:02": {}}, cfg, n, now=1000)
        self.assertTrue(any(s[2] == 5 for s in n.sent))


if __name__ == "__main__":
    unittest.main()
