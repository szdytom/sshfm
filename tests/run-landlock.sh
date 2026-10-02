#!/usr/bin/env bash
set -euo pipefail

PKG="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${SSHFM_WORK:-${TMPDIR:-/tmp}/sshfm-build}"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sshfm-landlock-run-XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT

# Build dependencies with build.sh first. Unused server/UI sections are
# discarded so the policy test needs only headers, not the SSH libraries.
g++ -O1 -std=c++17 -static -ffunction-sections -fdata-sections \
    -Wl,--gc-sections -I"$WORK/prefix/include" \
    "$PKG/tests/landlock.cpp" -lpthread -o "$TEST_DIR/landlock-test"
timeout 30 "$TEST_DIR/landlock-test"
