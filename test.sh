#!/usr/bin/env bash
# Copyright (c) 2026 VillageSQL Contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.
#
# Local test runner: builds the VEB (via build.sh), stages it into a temporary
# veb-dir, and runs the repo's MTR suite against the dev server. Running MTR by
# hand in the dev environment needs the VEB staged and the preview-extensions
# flag set, so this wraps it.
#
# The suite is hermetic (pre-signed RS256 tokens, no external IdP), so no
# network service is needed.
#
# Usage:
#   export VillageSQL_BUILD_DIR=$HOME/build/villagesql
#   ./test.sh                          # build + run the whole MTR suite
#   ./test.sh oauth_ecdsa              # build + run a single test by name
#   ./test.sh oauth_basic oauth_ecdsa  # build + run several named tests
#   RECORD=1 ./test.sh oauth_auto_create  # build + record one test's .result
#
# Any positional arguments are passed through to mysql-test-run.pl as test
# names; with none, the whole suite runs.

set -euo pipefail

VEB="vsql_oauth2.veb"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VILLAGESQL_BUILD_DIR="${VillageSQL_BUILD_DIR:-${VILLAGESQL_BUILD_DIR:-}}"
VEB_DIR="/tmp/${VEB%.veb}-test-veb-$$"

log() { echo "[test] $(date '+%H:%M:%S') - $1"; }
cleanup() { rm -rf "$VEB_DIR" 2>/dev/null || true; }
trap cleanup EXIT

if [[ -z "$VILLAGESQL_BUILD_DIR" ]]; then
    log "ERROR: VillageSQL_BUILD_DIR is not set."
    log "  export VillageSQL_BUILD_DIR=/path/to/villagesql/build"
    exit 1
fi

# Step 1: Build (delegates to build.sh so build logic lives in one place).
log "Building..."
"$SCRIPT_DIR/build.sh"

if [[ ! -f "$SCRIPT_DIR/build/$VEB" ]]; then
    log "ERROR: $VEB not found after build"
    exit 1
fi

# Step 2: Stage the VEB.
mkdir -p "$VEB_DIR"
cp "$SCRIPT_DIR/build/$VEB" "$VEB_DIR/"
log "VEB staged in $VEB_DIR"

# Step 3: Run MTR from the dev server's mysql-test dir (MTR manages its own
# server; do NOT start one manually). suite.opt supplies
# --vsql_allow_preview_extensions=ON.
MTR_RECORD_ARG=()
if [[ "${RECORD:-0}" == "1" ]]; then
    log "RECORD=1 set -- recording expected results"
    MTR_RECORD_ARG=(--record)
fi

log "Running MTR..."
cd "$VILLAGESQL_BUILD_DIR"
perl ./mysql-test/mysql-test-run.pl \
    --suite="$SCRIPT_DIR/mysql-test" \
    --parallel=1 \
    --nounit-tests \
    --mysqld=--veb-dir="$VEB_DIR" \
    ${MTR_RECORD_ARG[@]+"${MTR_RECORD_ARG[@]}"} \
    "$@"

log "Done."
