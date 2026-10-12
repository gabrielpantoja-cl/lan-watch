#!/usr/bin/env bash
# Install lan-watch on a Debian/Ubuntu host. Run as root from the repo directory.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (sudo ./install.sh)"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"

command -v arp-scan >/dev/null || { echo "arp-scan is not installed (apt install arp-scan)"; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "Python >= 3.11 required"; exit 1; }

id lanwatch >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin lanwatch
install -d -m 0750 -o root -g lanwatch /etc/lan-watch
install -D -m 0755 "$SRC/lan_watch.py" /usr/local/lib/lan-watch/lan_watch.py
ln -sf /usr/local/lib/lan-watch/lan_watch.py /usr/local/bin/lan-watch

[ -f /etc/lan-watch/config.toml ]  || install -m 0640 -o root -g lanwatch "$SRC/examples/config.example.toml" /etc/lan-watch/config.toml
[ -f /etc/lan-watch/devices.toml ] || install -m 0640 -o root -g lanwatch "$SRC/examples/devices.example.toml" /etc/lan-watch/devices.toml
if [ ! -f /etc/lan-watch/ntfy-topic ]; then
  # The topic acts as the password of your ntfy channel: long and random.
  python3 -c 'import secrets; print("lanwatch-" + secrets.token_urlsafe(18))' > /etc/lan-watch/ntfy-topic
  chown root:lanwatch /etc/lan-watch/ntfy-topic; chmod 0640 /etc/lan-watch/ntfy-topic
fi

install -m 0644 "$SRC/systemd/lan-watch.service" /etc/systemd/system/lan-watch.service
install -m 0644 "$SRC/systemd/lan-watch.timer"   /etc/systemd/system/lan-watch.timer
systemctl daemon-reload
echo "Installed. Next: edit /etc/lan-watch/config.toml (interface) and devices.toml,"
echo "subscribe your phone to the topic in /etc/lan-watch/ntfy-topic, then:"
echo "  systemctl enable --now lan-watch.timer ; sudo -u lanwatch lan-watch list ; sudo -u lanwatch lan-watch arm"
