#!/bin/bash
# Forensics Challenge: Docker Forensics
# Builds the Docker image and saves it as a tar file for analysis.
#
# Usage: bash build.sh
# Output: challenge.tar (Docker image archive)
#
# Players should:
#   1. Extract challenge.tar
#   2. Inspect manifest.json to find layer order
#   3. Extract each layer's layer.tar
#   4. Find flag.txt in an earlier layer (even though it was deleted later)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="docker-forensics-challenge"

echo "[+] Building Docker image..."
docker build -t "${IMAGE_NAME}" "${SCRIPT_DIR}"

echo "[+] Saving image to challenge.tar..."
docker save "${IMAGE_NAME}" -o "${SCRIPT_DIR}/challenge.tar"

echo "[+] Done! Created ${SCRIPT_DIR}/challenge.tar"
echo ""
echo "To solve:"
echo "  mkdir extracted && cd extracted"
echo "  tar xf ../challenge.tar"
echo "  # Each directory is a layer; extract layer.tar from each"
echo "  for dir in */; do"
echo "    echo \"=== Layer: \$dir ===\""
echo "    tar tf \"\${dir}layer.tar\" 2>/dev/null | grep flag"
echo "  done"
echo "  # Or use: docker history ${IMAGE_NAME}"
echo "  # Or use: dive ${IMAGE_NAME}"
