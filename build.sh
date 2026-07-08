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

# Pass SDK_DIR and VEB install dir directly (not VillageSQL_BUILD_DIR) so that
# FindVillageSQL.cmake Method 2 runs, which uses our pre-selected SDK_DIR
# instead of a glob that picks alphabetically-first (possibly older) SDK.
cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
  -DVillageSQL_SDK_DIR="${SDK_DIR}" \
  -DVillageSQL_VEB_INSTALL_DIR="${VillageSQL_BUILD_DIR}/veb_output_directory"

cmake --build "${BUILD_DIR}" -- -j"$(sysctl -n hw.logicalcpu 2>/dev/null || nproc)"

echo ""
echo "Build complete. VEB file:"
ls -lh "${BUILD_DIR}/"*.veb 2>/dev/null || \
  find "${BUILD_DIR}" -name "*.veb" -print
