#!/usr/bin/env bash
# Copyright (c) 2026 VillageSQL Contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${VillageSQL_BUILD_DIR:-}" ]]; then
  echo "ERROR: VillageSQL_BUILD_DIR is not set." >&2
  echo "  export VillageSQL_BUILD_DIR=/path/to/villagesql/build" >&2
  exit 1
fi

BUILD_DIR="${SCRIPT_DIR}/build"
mkdir -p "${BUILD_DIR}"

# Select the newest SDK by modification time (not alphabetical) to avoid
# version mismatch when multiple SDK versions exist in the build directory.
SDK_DIR="$(ls -dt "${VillageSQL_BUILD_DIR}"/villagesql-extension-sdk-*/ 2>/dev/null | head -1)"
if [[ -z "${SDK_DIR}" ]]; then
  echo "ERROR: No villagesql-extension-sdk-* found in ${VillageSQL_BUILD_DIR}" >&2
  exit 1
fi
# Strip any trailing slash so cache comparisons are stable.
SDK_DIR="${SDK_DIR%/}"
echo "[build] selected SDK: ${SDK_DIR}"

# The SDK selection must win on EVERY build, not just the first configure.
# cmake caches VillageSQL_SDK_DIR, and FindVillageSQL.cmake also has a glob-based
# fallback (Method 1) keyed off VillageSQL_BUILD_DIR that can resolve a different
# (possibly stale) SDK. To make the freshly-selected SDK authoritative without
# any manual cache-clearing:
#   - if the cached SDK differs from what we just selected, wipe the cache so the
#     new selection can't be silently overridden by a frozen value;
#   - do NOT pass VillageSQL_BUILD_DIR, so FindVillageSQL's glob fallback stays
#     off and only our explicit SDK_DIR (Method 2) is used.
CACHE_FILE="${BUILD_DIR}/CMakeCache.txt"
if [[ -f "${CACHE_FILE}" ]]; then
  CACHED_SDK="$(sed -n 's/^VillageSQL_SDK_DIR:[^=]*=//p' "${CACHE_FILE}" | head -1)"
  CACHED_SDK="${CACHED_SDK%/}"
  if [[ "${CACHED_SDK}" != "${SDK_DIR}" ]]; then
    echo "[build] SDK changed (cached: '${CACHED_SDK:-none}') -- reconfiguring clean"
    rm -f "${CACHE_FILE}"
  fi
fi

# FORCE the cache value so a re-configure always adopts the current selection.
cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
  -DVillageSQL_SDK_DIR:PATH="${SDK_DIR}" \
  -DVillageSQL_VEB_INSTALL_DIR="${VillageSQL_BUILD_DIR}/veb_output_directory"

cmake --build "${BUILD_DIR}" -- -j"$(sysctl -n hw.logicalcpu 2>/dev/null || nproc)"

echo ""
echo "Build complete. VEB file:"
ls -lh "${BUILD_DIR}/"*.veb 2>/dev/null || \
  find "${BUILD_DIR}" -name "*.veb" -print
