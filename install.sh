#!/bin/bash
# Install Bouncer on a Raspberry Pi that already runs Raspberry Pi OS Lite
# (alternative to the ready-made SD card image, e.g. for a first test).
#
#   sudo ./install.sh owner/repository
#
# The repository name is where the Pi looks for signed updates.
set -euo pipefail
cd "$(dirname "$0")"

if [ "$(id -u)" != "0" ]; then echo "Please run with sudo."; exit 1; fi
REPO="${1:-}"
if [ -z "$REPO" ]; then echo "Usage: sudo ./install.sh <github-owner>/<repository>"; exit 1; fi
if grep -q "REPLACE" keys/release.pub; then
  echo "keys/release.pub still has the placeholder. Run 'python tools/keygen.py' first."; exit 1
fi
VERSION="$(cat VERSION)"

echo "==> Installing packages"
apt-get update
apt-get install -y python3 python3-aiohttp python3-dnslib python3-cryptography dnsmasq ndisc6 \
  rfkill avahi-daemon unattended-upgrades
systemctl disable --now dnsmasq || true

echo "==> Installing Bouncer $VERSION"
install -d "/opt/bouncer/releases/$VERSION"
rm -rf "/opt/bouncer/releases/$VERSION/bouncer"
cp -r bouncer VERSION "/opt/bouncer/releases/$VERSION/"
find "/opt/bouncer/releases/$VERSION" -name "__pycache__" -prune -exec rm -rf {} +
ln -sfn "/opt/bouncer/releases/$VERSION" /opt/bouncer/current
install -d /etc/bouncer /var/lib/bouncer/lists /etc/dnsmasq.d /etc/NetworkManager/dnsmasq-shared.d
install -m 644 keys/release.pub /etc/bouncer/release.pub
echo "{\"repo\": \"$REPO\"}" > /etc/bouncer/update.json

for unit in bouncer.service bouncer-netsetup.service bouncer-update.service bouncer-update.timer; do
  install -m 644 "system/systemd/$unit" "/etc/systemd/system/$unit"
done
install -d /etc/systemd/journald.conf.d
install -m 644 system/etc/networkmanager-bouncer.conf /etc/NetworkManager/conf.d/90-bouncer.conf
install -m 644 system/etc/journald-bouncer.conf /etc/systemd/journald.conf.d/90-bouncer.conf
install -m 644 system/etc/20auto-upgrades /etc/apt/apt.conf.d/20auto-upgrades
install -m 644 system/etc/52bouncer-unattended-upgrades /etc/apt/apt.conf.d/52bouncer-unattended-upgrades
install -m 644 system/etc/dnsmasq-default /etc/default/dnsmasq
[ -f /boot/firmware/bouncer-pin.txt ] || install -m 644 system/bouncer-pin.txt /boot/firmware/bouncer-pin.txt

echo "==> Hostname 'bouncer' (dashboard: http://bouncer.local)"
hostnamectl set-hostname bouncer
sed -i 's/127\.0\.1\.1.*/127.0.1.1\tbouncer/' /etc/hosts

echo "==> Downloading block lists"
BOUNCER_STATE_DIR=/var/lib/bouncer PYTHONPATH=/opt/bouncer/current python3 -m bouncer update-lists || true

echo "==> Switching DNS of the Pi itself to Bouncer"
rm -f /etc/resolv.conf
install -m 644 system/etc/resolv.conf /etc/resolv.conf
systemctl reload NetworkManager || true

systemctl daemon-reload
systemctl restart systemd-journald
systemctl enable bouncer-netsetup.service bouncer-update.timer
systemctl enable --now bouncer.service avahi-daemon.service
sleep 3
systemctl --no-pager status bouncer.service | head -5
echo
echo "Done. Open http://bouncer.local (or http://$(hostname -I | awk '{print $1}'))."
echo "No PIN yet? Put 'PIN=1234' (your PIN) into /boot/firmware/bouncer-pin.txt and run:"
echo "  sudo systemctl restart bouncer"
