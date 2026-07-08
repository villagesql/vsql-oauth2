# AGENTS.md

This file provides guidance to AI coding assistants (Claude Code, Gemini Code Assist, etc.) when working with code in this repository.

**Note**: Also check `AGENTS.local.md` for additional local development instructions when present.

## Project Overview

This is an OAuth2/OIDC authentication extension for VillageSQL (a MySQL-compatible database). It turns VillageSQL into an OAuth 2.0 resource server: a client presents a Bearer JWT during the connection handshake, the extension validates it (signature, `iss`, `aud`, `exp`) against an external IdP, and maps the token identity to a database account. Users connect with their enterprise identity without a separate database password.

Unlike function extensions (VDFs), this is an **authentication capability** extension: it provides an auth method via the `vsql::preview::auth` capability, invoked on the pre-authentication handshake seam rather than mid-query.

## Build System

**IMPORTANT**: Always build in the `build/` directory, never in the source root.

### Build

```bash
export VillageSQL_BUILD_DIR=/path/to/villagesql/build
./build.sh
```

`build.sh` selects the newest staged SDK under `VillageSQL_BUILD_DIR` and passes
it as `VillageSQL_SDK_DIR`, then builds `build/vsql_oauth2.veb`.

### Test

```bash
export VillageSQL_BUILD_DIR=/path/to/villagesql/build
./test.sh            # build + run the MTR suite
RECORD=1 ./test.sh   # build + record the .result files
```

`test.sh` builds (via `build.sh`), stages the VEB into a temp veb-dir, and runs
the MTR suite against the dev server. The suite is hermetic (pre-signed tokens,
no external IdP). See `TESTING.md` for the manual MTR command as well.

### Dependencies

- VillageSQL Extension Framework SDK — **preview** headers (`include-dev/`), for
  the `vsql::preview::auth` and `vsql::preview::sys_var` capabilities. The
  bundled `cmake/FindVillageSQL.cmake` selects `include-dev/` when
  `VillageSQL_USE_DEV_HEADERS` is ON (set in `CMakeLists.txt`).
- OpenSSL (`libssl-dev`) — RS256/ES256 signature verification behind jwt-cpp.
- libcurl (`libcurl4-openssl-dev`) — JWKS fetch from the IdP.
- jwt-cpp — header-only, fetched at configure time via CMake `FetchContent`
  (pinned); not vendored.

## Architecture

**Core components (in `src/`):**
- `extension.cc` — the SDK capability objects: the `AuthCapability` (auth method
  name + handler + pinned client plugin), the sysvars, and the
  `VEF_GENERATE_ENTRY_POINTS` composition. The `authenticate` handler reads the
  bearer token from the handshake, calls `oauth_core::evaluate()`, and maps the
  `Decision` to the auth context (`set_authenticated_as` / `set_external_user`).
- `oauth_core.{h,cc}` — wrapper-agnostic JWT validation + claim→account/role
  mapping. Verifies signature (RS/ES SHA-2 families: RS256/384/512,
  ES256/384/512 only; every other alg, including
  `none` and the HS* family, is rejected before any signature check), `iss`,
  `aud`, `exp`. Maps `username_claim` → account and `roles_claim` → roles via
  `roles_filter`/`roles_transform`. Does no network I/O — the key source is
  behind `config.resolve_key`, so it is unit-testable with a fake resolver. Also
  hosts `token_from_packet(pkt, len, client_plugin)` — a pure helper that
  extracts the JWT from the raw handshake packet, dispatching on the negotiated
  client-plugin name (native `authentication_openid_connect_client` framing =
  `[capability][lenenc][JWT]`; anything else = clear-password-style token + NUL).
- `jwks_cache.{h,cc}` — JWKS HTTP fetch (libcurl) + JWK→PEM conversion (RSA and
  EC), with a `kid`-keyed cache refreshed on a TTL / unknown-kid.

**Auth flow:** the client sends the JWT → `authenticate` extracts it via
`token_from_packet` → `oauth_core::evaluate` validates + maps → on success the
session runs as the mapped account, with the original identity exposed via
`@@external_user`. Token-mapped roles are activated with `set_active_roles`
(grant-checked; ungranted names skipped — no escalation). With
`auto_create = ON`, a valid-token login for an account that does not exist is
provisioned on the fly (`account_unknown` → `request_provision`) and then runs as
the new account.

**Client-side token delivery (three ways, all provider-agnostic to the server):**
(a) built-in `mysql_clear_password` — JWT in the password slot (needs
`--enable-cleartext-plugin`); universal. (b) `vsql_oauth_client` — VillageSQL's
own client plugin (lives in the SERVER repo `libmysql/vsql_oauth_client/`, since
only the client build ships a client `.so`; the extension ships only a `.veb`);
fetches the token from `$VSQL_OAUTH_TOKEN_FILE` or `$VSQL_OAUTH_TOKEN_HELPER`, so it is
off the command line. (c) a stock MySQL 9.1+ client's own
`authentication_openid_connect_client` (token file) — the server accepts its
framing too. See README "Logging in".

**Config (sysvars, `vsql_oauth2.*`):** `issuer`, `audience`, `public_key`,
`jwks_url`, `jwks_refresh_interval`, `jwks_http_timeout`, `username_claim`,
`roles_claim`, `roles_filter`, `roles_transform_pattern`,
`roles_transform_replacement`, and `auto_create` (bool). Integer sysvars use
`int64_t` backing globals to match the SDK's fixed-width ABI; `auto_create` uses
a `bool` backing global via `sv::make_bool`.

**Fail closed:** any validation failure, missing key source, or malformed token
denies the connection. Only an explicit accept authenticates.

## Testing

MTR (MySQL Test Runner) via `./test.sh`, or manually (see `TESTING.md`). Test
files live in `mysql-test/t/` (`.test`) and `mysql-test/r/` (`.result`).

- `oauth_basic` — installs the method, binds an account, and drives login with
  pre-signed RS256 tokens: valid token accepted (maps to the account), and
  expired / malformed / empty / no-key-source all fail closed. Fully hermetic.
- `oauth_client_plugin` — drives login through the `vsql_oauth_client` plugin in
  token-file mode (`$VSQL_OAUTH_TOKEN_FILE`) instead of the password slot. Skips
  cleanly if the plugin was not built (needs the server configured with
  `-DWITH_AUTHENTICATION_CLIENT_PLUGINS=ON`; gated via the `VSQL_OAUTH_CLIENT`
  entry in the server's `mysql-test/include/plugin.defs`).

Regenerate expected results with `RECORD=1 ./test.sh` after an intended change.

## Licensing and Copyright

All source files (`.cc`, `.h`) and `CMakeLists.txt` must carry this header:

```
// Copyright (c) 2026 VillageSQL Contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License, version 2.0,
// as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License, version 2.0, for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
```

## Common Tasks for AI Agents

- **Adding a config knob**: add a backing global + a matching `sv::make_*` entry
  in `extension.cc`, thread it into `oauth_core::Config` in `build_config`, and
  consume it in `oauth_core.cc`. Type must match the factory: `int64_t*` for
  `make_int`, `char**` for `make_str`, `bool*` for `make_bool` (e.g.
  `auto_create`). A knob queried live by the server per-login (like the
  `auto_create_unknown_accounts` opt-in callback) reads the global directly.
- **Changing validation**: edit `oauth_core::evaluate`; keep fail-closed —
  reject unknown algs before any signature check.
- **Role mapping**: `roles_filter`/`roles_transform` in `oauth_core.cc`. Note
  the IdP-specific claim: Entra App Roles arrive in `roles`, Google/Okta groups
  in `groups`; the operator points `roles_claim` at the right one.
- **Testing**: add/update `mysql-test/t/*.test`, regenerate with
  `RECORD=1 ./test.sh`. Prefer pre-signed tokens so the suite stays hermetic.

Always maintain existing code style and include the copyright header.
