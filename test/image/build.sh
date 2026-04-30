#!/bin/bash
# Build minimal test disk image for bdp-netstack e2e testing.
# Uses bootc install to-disk (avoids bootc-image-builder entirely).
#
# Requires: Linux, sudo, podman.
#
# Usage:
#   ./build.sh                        # build with default output
#   OUTPUT_DIR=/tmp/out ./build.sh    # custom output directory
#
# Output:
#   output/disk.raw                   # raw disk image for vfkit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

: "${IMAGE_TAG:=localhost/developer/bdp-netstack-test:latest}"
: "${OUTPUT_DIR:=$(pwd)/output}"
: "${DISK_SIZE:=10G}"
: "${PLATFORM:=linux/arm64}"

# Override platform on x86_64 Linux
[[ "$(uname -m)" == "x86_64" ]] && PLATFORM="linux/amd64"

OUTPUT_DIR="$(mkdir -p "${OUTPUT_DIR}" && cd "${OUTPUT_DIR}" && pwd)"

# Step 1: Build OCI image
# Use sudo on Linux, but not on macOS (podman machine handles rootful mode)
if [[ "$(uname -s)" == "Linux" ]]; then
    PODMAN="sudo podman"
else
    PODMAN="podman"
fi

echo "==> Step 1: Building OCI image: ${IMAGE_TAG} (platform: ${PLATFORM})"
${PODMAN} build --platform "${PLATFORM}" -t "${IMAGE_TAG}" -f Containerfile "${SCRIPT_DIR}"
echo "   Image built: ${IMAGE_TAG}"

# Step 2: Create blank disk image
echo "==> Step 2: Creating ${DISK_SIZE} disk image"
DISK_PATH="${OUTPUT_DIR}/disk.raw"
truncate -s "${DISK_SIZE}" "${DISK_PATH}"

# Step 3: Install bootc container to disk via loopback
echo "==> Step 3: Installing bootc container to disk"
${PODMAN} run --rm \
    --platform "${PLATFORM}" \
    --privileged \
    --pid=host \
    -v "${OUTPUT_DIR}:/output" \
    "${IMAGE_TAG}" \
    bootc install to-disk \
        --via-loopback \
        --generic-image \
        --wipe \
        --bootloader systemd \
        --composefs-backend \
        --disable-selinux \
        --filesystem ext4 \
        /output/disk.raw

echo ""
echo "==> Done: ${DISK_PATH}"
ls -lh "${DISK_PATH}"
echo ""
echo "    To use with vfkit:"
echo "    vfkit --bootloader efi,create --device virtio-blk,path=${DISK_PATH} ..."
