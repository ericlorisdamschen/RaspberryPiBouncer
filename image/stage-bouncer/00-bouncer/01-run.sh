#!/bin/bash -e
# Installs Bouncer into the image. "files/" is prepared by the GitHub workflow
# (see .github/workflows/build-image.yml): the code, the owner's public key,
# the update settings and a first copy of the block lists.

VERSION="$(cat files/app/VERSION)"
APP="${ROOTFS_DIR}/opt/bouncer"

install -d "${APP}/releases/${VERSION}"
cp -r files/app/bouncer files/app/VERSION "${APP}/releases/${VERSION}/"
ln -sfn "/opt/bouncer/releases/${VERSION}" "${APP}/current"

install -d -m 755 "${ROOTFS_DIR}/etc/bouncer"
install -m 644 files/release.pub "${ROOTFS_DIR}/etc/bouncer/release.pub"
install -m 644 files/update.json "${ROOTFS_DIR}/etc/bouncer/update.json"

install -d -m 750 "${ROOTFS_DIR}/var/lib/bouncer/lists"
cp files/lists/* "${ROOTFS_DIR}/var/lib/bouncer/lists/" 2>/dev/null || true

for unit in bouncer.service bouncer-netsetup.service bouncer-update.service bouncer-update.timer; do
	install -m 644 "files/system/systemd/${unit}" "${ROOTFS_DIR}/etc/systemd/system/${unit}"
done
install -m 644 files/system/etc/networkmanager-bouncer.conf "${ROOTFS_DIR}/etc/NetworkManager/conf.d/90-bouncer.conf"
install -d "${ROOTFS_DIR}/etc/NetworkManager/dnsmasq-shared.d"
install -d "${ROOTFS_DIR}/etc/systemd/journald.conf.d"
install -m 644 files/system/etc/journald-bouncer.conf "${ROOTFS_DIR}/etc/systemd/journald.conf.d/90-bouncer.conf"
install -m 644 files/system/etc/20auto-upgrades "${ROOTFS_DIR}/etc/apt/apt.conf.d/20auto-upgrades"
install -m 644 files/system/etc/52bouncer-unattended-upgrades "${ROOTFS_DIR}/etc/apt/apt.conf.d/52bouncer-unattended-upgrades"
install -m 644 files/system/etc/dnsmasq-default "${ROOTFS_DIR}/etc/default/dnsmasq"
install -d "${ROOTFS_DIR}/etc/dnsmasq.d"
rm -f "${ROOTFS_DIR}/etc/resolv.conf"
install -m 644 files/system/etc/resolv.conf "${ROOTFS_DIR}/etc/resolv.conf"

# The first PIN goes on the boot partition so it can be edited from any computer.
install -m 644 files/system/bouncer-pin.txt "${ROOTFS_DIR}/boot/firmware/bouncer-pin.txt"

on_chroot << CHROOT
systemctl enable bouncer.service bouncer-netsetup.service bouncer-update.timer avahi-daemon.service
systemctl disable dnsmasq.service || true
systemctl disable ssh.service || true
python3 -m compileall -q /opt/bouncer/releases/${VERSION}/bouncer || true
CHROOT
