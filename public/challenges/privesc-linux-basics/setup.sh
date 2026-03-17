#!/bin/bash
# Privilege Escalation Challenge: Linux Basics
# Sets up a Docker container with intentional privilege escalation vectors:
#   1. SUID binary (find)
#   2. Writable cron job running as root
#   3. sudo misconfiguration (vim as root without password)
#
# Usage: bash setup.sh
# Connect: docker exec -it privesc-basics su - user
#   OR:    ssh user@localhost -p 2222 (password: user)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER_NAME="privesc-basics"
IMAGE_NAME="privesc-basics-challenge"

echo "============================================"
echo "  Privilege Escalation: Linux Basics Setup"
echo "============================================"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "[!] Docker is not installed or not in PATH."
    echo "    Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Stop and remove existing container
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "[*] Removing existing container..."
    docker rm -f "${CONTAINER_NAME}" > /dev/null 2>&1
fi

# Build the image
echo "[*] Building Docker image..."
docker build -t "${IMAGE_NAME}" "${SCRIPT_DIR}"

# Run the container
echo "[*] Starting container..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    -p 2222:22 \
    "${IMAGE_NAME}"

echo ""
echo "[+] Container '${CONTAINER_NAME}' is running!"
echo ""
echo "Connect with:"
echo "  docker exec -it ${CONTAINER_NAME} su - user"
echo "  # OR"
echo "  ssh user@localhost -p 2222  (password: user)"
echo ""
echo "Vulnerabilities to exploit:"
echo "  1. SUID find:    find . -exec /bin/sh -p \\;"
echo "  2. Writable cron: echo 'cp /root/flag.txt /tmp/flag && chmod 777 /tmp/flag' > /opt/scripts/backup.sh"
echo "  3. Sudo vim:     sudo vim -c '!bash'"
echo ""
echo "Flag location: /root/flag.txt"
echo ""
echo "To stop: docker rm -f ${CONTAINER_NAME}"
