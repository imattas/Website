#!/bin/bash
# Forensics Challenge: Disk Image
# Creates an ext4 disk image, writes flag.txt, then deletes it.
# The flag can be recovered using tools like extundelete, photorec, or strings.
#
# Usage: sudo bash generate.sh
# Output: challenge.img (ext4 disk image with deleted flag)
# Requires: root privileges for mount/umount, mkfs.ext4

set -e

FLAG="zemi{d3l3t3d_but_n0t_g0n3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMG_FILE="${SCRIPT_DIR}/challenge.img"
MOUNT_POINT="${SCRIPT_DIR}/mnt_tmp"
IMG_SIZE_MB=2

echo "[+] Creating ${IMG_SIZE_MB}MB disk image..."
dd if=/dev/zero of="${IMG_FILE}" bs=1M count=${IMG_SIZE_MB} status=progress 2>/dev/null

echo "[+] Formatting as ext4..."
mkfs.ext4 -F -q "${IMG_FILE}"

echo "[+] Mounting image..."
mkdir -p "${MOUNT_POINT}"
mount -o loop "${IMG_FILE}" "${MOUNT_POINT}"

echo "[+] Writing flag.txt..."
echo "${FLAG}" > "${MOUNT_POINT}/flag.txt"

# Write some decoy files to make it more realistic
echo "Nothing to see here." > "${MOUNT_POINT}/readme.txt"
echo "user=admin" > "${MOUNT_POINT}/config.txt"
echo "TODO: fix the login page" > "${MOUNT_POINT}/notes.txt"

# Sync to ensure data is written to the image
sync

echo "[+] Deleting flag.txt..."
rm "${MOUNT_POINT}/flag.txt"
sync

echo "[+] Unmounting..."
umount "${MOUNT_POINT}"
rmdir "${MOUNT_POINT}"

echo "[+] Done! Created ${IMG_FILE}"
echo ""
echo "To solve:"
echo "  strings challenge.img | grep 'zemi{'"
echo "  # or: extundelete challenge.img --restore-all"
echo "  # or: photorec challenge.img"
echo "  # or: debugfs challenge.img -R 'ls -d'"
