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
// along with this program; if not, see <https://www.gnu.org/licenses/>.

#ifndef VSQL_OAUTH2_OAUTH_CORE_H
#define VSQL_OAUTH2_OAUTH_CORE_H

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace vsql_oauth2 {

// Resolves a token's key id (kid) to a PEM public key. Returns true and sets
// out_pem on success; on failure returns false and sets error_detail (the token
// is then rejected). This is the seam between oauth_core's pure verification
// logic and where the key actually comes from:
//   - static key: ignore kid, return the configured PEM
//   - JWKS (future): look kid up in a cache, fetching as needed
// Keeping oauth_core dependent only on this callback (not on curl/caching)
// keeps it pure and unit-testable.
using KeyResolver = std::function<bool(
    const std::string &kid, std::string &out_pem, std::string &error_detail)>;

// Wrapper-agnostic configuration for one authentication decision. Sourced from
// extension system variables in extension.cc; oauth_core never reads server
// state directly. The static-key build validates against a configured public
// key; a future JWKS build replaces resolve_key with JWKS-by-kid.
struct Config {
  // Expected issuer (iss claim). Empty disables the iss check.
  std::string issuer;
  // Expected audience (aud claim). Empty disables the aud check.
  std::string audience;

  // Resolves the token's kid to a PEM public key (RSA for RS256, EC for ES256).
  // Static-key and JWKS modes both plug in here. Unset (nullptr) means no key
  // source is configured -> every token is rejected (fail closed).
  KeyResolver resolve_key;

  // Claim whose value is the user identity (default "sub"; "email" is common).
  std::string username_claim = "sub";
  // Claim holding the role/group identifiers to map to DB roles. The claim
  // name is IdP-specific: Entra App Roles arrive in "roles"; Google/Okta group
  // membership in "groups". Empty disables role mapping.
  std::string roles_claim;

  // Regex a claim value must fully match to become a role. Empty accepts every
  // value. E.g. "mysql-grp-.*" selects only DB-group entries.
  std::string roles_filter;

  // Optional transform applied to each selected value before it becomes a role:
  // std::regex_replace(value, regex(roles_transform_pattern),
  // roles_transform_replacement). regex_replace substitutes ALL matches, so an
  // "s/-/_/g"-style rewrite is pattern "-", replacement "_". Empty pattern = no
  // transform (value used verbatim).
  std::string roles_transform_pattern;
  std::string roles_transform_replacement;

  // The AS '...' clause from CREATE USER ... IDENTIFIED WITH vsql_oauth2 AS
  // '...', if any. Lets an account pin a specific identity (the static
  // MySQL-Enterprise mapping model). Empty when not specified.
  std::string auth_string;
};

// Result of evaluating a token. The adapter translates this to accept/reject
// and writes account/external_identity into the auth context. accept defaults
// false so a partially-populated Decision can never be mistaken for an accept.
struct Decision {
  bool accept = false;

  // Effective account to authenticate as (-> authenticated_as).
  std::string account;

  // Roles to activate for the session (from roles_claim). Empty unless a
  // roles claim is configured and present.
  std::vector<std::string> roles;

  // Original external identity for the audit trail (-> external_user).
  std::string external_identity;

  // Reason for a reject, for the error log only -- never sent to the client.
  std::string reject_reason;
};

// Validate a JWT and map it to an account.
//
// Verifies the signature (RS256 or ES256 only -- alg:none and all other
// algorithms are rejected) using the key returned by config.resolve_key for the
// token's kid, checks iss/aud/exp, then maps the username_claim to the account
// and the roles_claim to roles. The key source (static PEM or JWKS fetch) is
// entirely behind config.resolve_key, so this function does no network I/O and
// is unit-testable with a fake resolver.
//
// `token` is the raw JWT string read off the handshake.
Decision evaluate(const std::string &token, const Config &config);

// Extract the JWT from a raw client handshake packet. The framing depends on the
// client-side auth plugin that delivered it, identified by `client_plugin` (the
// name the connection actually negotiated, from ops->client_auth_plugin):
//   - "authentication_openid_connect_client" (MySQL's native OIDC client): a
//     1-byte capability field + a MySQL length-encoded integer length + the raw
//     JWT (no trailing NUL).
//   - anything else, incl. "mysql_clear_password" (the default): the raw JWT as
//     a string, with a trailing NUL dropped if present.
// Selecting by the negotiated plugin name is deterministic and robust to the
// OIDC framing's leading byte being an evolving capability bitmask (do NOT sniff
// it). Returns a view into `pkt` (valid while the caller holds the packet).
// Returns empty on an empty or malformed packet (caller fails closed). Pure
// function -- no MySQL/ABI types -- so it is unit-testable with crafted inputs.
std::string_view token_from_packet(const unsigned char *pkt, int64_t pkt_len,
                                   std::string_view client_plugin);

} // namespace vsql_oauth2

#endif // VSQL_OAUTH2_OAUTH_CORE_H
