#!/usr/bin/env bash
# build.sh -- build the reeflex-holds MCPB bundle for the CURRENT
# macOS/Linux platform+arch.
#
# reeflex-holds' only declared dependency is `mcp>=1.2.0`, but that pulls in
# compiled wheels (pydantic_core -- Rust, cryptography/cffi -- C, rpds-py --
# Rust). Those wheels are platform+ABI specific, so an .mcpb built here is
# ONLY valid for the platform+arch this script runs on (e.g. a macOS-arm64
# machine produces a macosx_arm64 bundle; it will NOT run on Linux or an
# Intel Mac, and vice versa).
#
# This script does NOT run the reeflex-holds server. It only:
#   1. pip installs reeflex-holds==<version> (below) from PyPI into
#      mcpb/server/lib/ (--target, so deps land alongside the shim, not in
#      the ambient environment).
#   2. Packs manifest.json + server/ into a versioned .mcpb via the mcpb
#      CLI (falls back to a plain zip if the CLI is unavailable).
#
# See README.md in this directory for the full platform-matrix reality:
# this script only ever produces ONE platform+arch combination per run --
# the one it is invoked on. Other combinations must be built by running
# this recipe (or build.ps1) ON those platforms, or via a CI matrix
# (documented, NOT built, in README.md).
#
# Usage: ./build.sh [version]   (default: 0.1.1)

set -euo pipefail

VERSION="${1:-0.1.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/server/lib"

# ---- 1. Platform/arch tag (informational + used in the output filename) ----
UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

case "$UNAME_S" in
    Darwin) PLATFORM_TAG="darwin" ;;
    Linux)  PLATFORM_TAG="linux" ;;
    *)      PLATFORM_TAG="$(echo "$UNAME_S" | tr '[:upper:]' '[:lower:]')" ;;
esac

case "$UNAME_M" in
    arm64|aarch64) ARCH_TAG="arm64" ;;
    x86_64|amd64)  ARCH_TAG="x64" ;;
    *)             ARCH_TAG="$UNAME_M" ;;
esac

echo "Building reeflex-holds $VERSION for $PLATFORM_TAG-$ARCH_TAG ..."

# ---- 2. Fresh server/lib/ (idempotent: wipe any previous install) ----
rm -rf "$LIB_DIR"
mkdir -p "$LIB_DIR"

# ---- 3. pip install reeflex-holds + its deps into server/lib/ ----
# This is a BUILD step, not running the server -- reeflex-holds' console
# script / __main__ entry point is never invoked here.
python3 -m pip install --target "$LIB_DIR" "reeflex-holds==$VERSION" --no-compile

# Drop __pycache__ pip may have left behind (belt-and-suspenders alongside
# .mcpbignore, in case the packer used below doesn't honor it, e.g. the
# plain-zip fallback).
find "$LIB_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# ---- 4. Pack manifest.json (zip root) + server/ into the .mcpb ----
OUTPUT_NAME="reeflex-holds-${VERSION}-${PLATFORM_TAG}-${ARCH_TAG}.mcpb"
OUTPUT_PATH="$SCRIPT_DIR/$OUTPUT_NAME"

rm -f "$OUTPUT_PATH"

if command -v npx >/dev/null 2>&1; then
    echo "Packing via 'mcpb pack' (npx @anthropic-ai/mcpb) ..."
    npx -y "@anthropic-ai/mcpb" pack "$SCRIPT_DIR" "$OUTPUT_PATH"
else
    echo "mcpb CLI not found; falling back to plain zip."
    echo "NOTE: the plain-zip fallback does NOT honor .mcpbignore -- prefer the mcpb CLI."
    TMP_ZIP_DIR="$(mktemp -d)"
    cp "$SCRIPT_DIR/manifest.json" "$TMP_ZIP_DIR/"
    cp -R "$SCRIPT_DIR/server" "$TMP_ZIP_DIR/"
    ( cd "$TMP_ZIP_DIR" && zip -r "$OUTPUT_PATH" manifest.json server >/dev/null )
    rm -rf "$TMP_ZIP_DIR"
fi

echo "Built: $OUTPUT_PATH"
echo ""
echo "This bundle targets ${PLATFORM_TAG}-${ARCH_TAG} ONLY (compiled deps are ABI-specific)."
echo "See README.md for the full platform matrix and the CI-matrix upgrade path."
