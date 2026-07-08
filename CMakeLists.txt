# Copyright (c) 2026 VillageSQL Contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License, version 2.0, for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.16)
project(vsql_oauth2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Extension name
set(EXTENSION_NAME "vsql_oauth2")

# Find VillageSQL SDK.
# This extension uses a preview capability (vsql::preview::auth), whose headers
# ship in the SDK's include-dev/ tree. Request the dev headers before
# find_package, exactly as the preview-using example extensions do.
set(VillageSQL_USE_DEV_HEADERS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(VillageSQL REQUIRED)

# OpenSSL provides the actual RS256/ES256 signature verification that jwt-cpp
# wraps. It is present anywhere the server builds, so this is not an extra
# prerequisite in practice.
find_package(OpenSSL REQUIRED)

# libcurl performs the JWKS HTTP(S) fetch (the jwks_url key source).
find_package(CURL)
if(NOT CURL_FOUND)
  message(FATAL_ERROR
    "libcurl development headers not found (needed for JWKS fetch).\n"
    "Install the development package and retry:\n"
    "  Ubuntu/Debian: sudo apt install libcurl4-openssl-dev\n"
    "  RHEL/Fedora:   sudo dnf install libcurl-devel\n"
    "  macOS:         included with Xcode Command Line Tools\n")
endif()

# jwt-cpp is header-only. Fetch it at configure time, pinned to a known-good
# ref (the same commit the vsql_oauth2 plugin was validated against). No headers
# are vendored in this repo; the pin keeps the build reproducible. Disable
# jwt-cpp's own OpenSSL discovery/targets -- we link OpenSSL ourselves above and
# only need the headers.
include(FetchContent)
set(JWT_DISABLE_PICOJSON OFF CACHE INTERNAL "")
set(JWT_BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(JWT_EXTERNAL_PICOJSON OFF CACHE INTERNAL "")
FetchContent_Declare(
  jwt-cpp
  GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
  GIT_TAG        0a503e75084cfdb48cc2186e6b961444eb819007  # pinned known-good
  GIT_SHALLOW    FALSE
)
FetchContent_MakeAvailable(jwt-cpp)

message(STATUS "VillageSQL SDK found at: ${VillageSQL_PREFIX}")
message(STATUS "VillageSQL include dir: ${VillageSQL_INCLUDE_DIR}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")

# Auth extension shared library
add_library(vsql_oauth2 SHARED
    src/extension.cc
    src/oauth_core.cc
    src/jwks_cache.cc
)

target_compile_options(vsql_oauth2 PRIVATE -fPIC)

# SDK headers, plus jwt-cpp as a SYSTEM include so its header warnings do not
# fail a maintainer-mode build. Use VillageSQL_INCLUDE_DIR (honors
# VillageSQL_USE_DEV_HEADERS) rather than the Framework config's include dir,
# which always points at the stable tree and would miss the preview headers.
target_include_directories(vsql_oauth2 PRIVATE
    ${VillageSQL_INCLUDE_DIR}
)
target_include_directories(vsql_oauth2 SYSTEM PRIVATE
    ${jwt-cpp_SOURCE_DIR}/include
)

target_link_libraries(vsql_oauth2 PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
)

# Create the VEB package
VEF_CREATE_VEB(
    NAME ${EXTENSION_NAME}
    LIBRARY_TARGET vsql_oauth2
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
)
