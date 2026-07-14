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

// vsql_oauth2: OAuth2/OIDC JWT authentication as a VillageSQL extension.
//
// Provides the auth method "vsql_oauth2" via the vsql::preview::auth
// capability. An account created with IDENTIFIED WITH vsql_oauth2 authenticates
// by presenting a JWT (bearer token), which this extension validates with
// oauth_core::evaluate() and maps to an account. The verification key comes
// from either a static PEM public key (public_key) or a JWKS endpoint
// (jwks_url, which takes precedence); the resolver is selected in
// build_key_resolver().
//
// The JWT library (jwt-cpp, over OpenSSL) and the JWKS HTTP fetch (libcurl) are
// compiled directly into this extension -- an auth-extension author does not
// need any server-side JWT primitive.
//
// Pairs with the built-in mysql_clear_password client plugin so the token
// arrives verbatim in the password slot (client must use
// --enable-cleartext-plugin).
//
// Usage:
//   INSTALL EXTENSION vsql_oauth2;
//   SET GLOBAL vsql_oauth2.jwks_url = 'https://idp.example/.well-known/jwks';
//   SET GLOBAL vsql_oauth2.issuer = 'https://idp.example';
//   CREATE USER u IDENTIFIED WITH vsql_oauth2;
//
// Optional auto-create: with SET GLOBAL vsql_oauth2.auto_create = ON, a login
// for an account that does not yet exist but presents a valid token is
// provisioned on the fly (CREATE USER ... IDENTIFIED WITH vsql_oauth2) with the
// token's mapped roles granted, then runs as the new account. Roles must
// already exist as DB roles (the DBA owns roles); an unknown role is skipped.

#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <villagesql/preview/auth.h>
#include <villagesql/preview/sys_var.h>
#include <villagesql/vsql.h>

#include "jwks_cache.h"
#include "oauth_core.h"

using namespace vsql;
namespace sv = vsql::preview_sys_var;

namespace {

// System variables feeding oauth_core. Backing globals are read directly during
// authentication (string reads are stable for the duration of a handler call).
// Names are bare here; the server exposes them prefixed as vsql_oauth2_<name>.
char *g_issuer = nullptr;
char *g_audience = nullptr;
char *g_public_key = nullptr;
char *g_username_claim = nullptr;
char *g_roles_claim = nullptr;
char *g_roles_filter = nullptr;
char *g_roles_transform_pattern = nullptr;
char *g_roles_transform_replacement = nullptr;
char *g_jwks_url = nullptr;
int64_t g_jwks_refresh_interval = 3600;
int64_t g_jwks_http_timeout = 5;
bool g_auto_create = false;

auto SYS_VARS = sv::make_capability({
    sv::make_str("issuer",
                 "OIDC issuer URL the token's iss claim must match "
                 "(empty disables the iss check)",
                 &g_issuer, ""),
    sv::make_str("audience",
                 "Expected aud claim, i.e. the client/application id "
                 "(empty disables the aud check)",
                 &g_audience, ""),
    sv::make_str("public_key",
                 "PEM-encoded public key used to verify the JWT signature "
                 "(RSA for RS256, EC for ES256). Used only when jwks_url is "
                 "empty. Empty (with no jwks_url) rejects all tokens.",
                 &g_public_key, ""),
    sv::make_str("jwks_url",
                 "JWKS endpoint URL to fetch signing keys from (the IdP's "
                 ".well-known JWKS URI). When set, takes precedence over "
                 "public_key.",
                 &g_jwks_url, ""),
    sv::make_int("jwks_refresh_interval",
                 "How often (seconds) to refresh cached JWKS keys",
                 &g_jwks_refresh_interval, 3600, 60, 86400),
    sv::make_int("jwks_http_timeout",
                 "Timeout (seconds) for a JWKS HTTP fetch; a slow endpoint "
                 "fails the login closed rather than hanging",
                 &g_jwks_http_timeout, 5, 1, 60),
    sv::make_str("username_claim",
                 "JWT claim holding the user identity (default sub)",
                 &g_username_claim, "sub"),
    sv::make_str(
        "roles_claim",
        "JWT claim holding role/group identifiers, mapped to DB roles. "
        "IdP-specific: Entra App Roles arrive in 'roles', Google/Okta "
        "groups in 'groups' (empty disables role mapping)",
        &g_roles_claim, ""),
    sv::make_str("roles_filter",
                 "Regex a roles_claim value must fully match to become a role "
                 "(empty accepts all). E.g. 'mysql-grp-.*'",
                 &g_roles_filter, ""),
    sv::make_str("roles_transform_pattern",
                 "Regex applied (with roles_transform_replacement) to each "
                 "matched role value; regex_replace substitutes all matches. "
                 "E.g. '-' to turn mysql-grp-x into a valid role name (empty "
                 "disables the transform)",
                 &g_roles_transform_pattern, ""),
    sv::make_str("roles_transform_replacement",
                 "Replacement string for roles_transform_pattern. E.g. '_'",
                 &g_roles_transform_replacement, ""),
    sv::make_bool(
        "auto_create",
        "When ON, a login for an account that does not exist but presents a "
        "valid token is provisioned on the fly (CREATE USER ... IDENTIFIED "
        "WITH vsql_oauth2) and the mapped roles granted, then the session runs "
        "as the new account. When OFF (default), unknown accounts are rejected "
        "as usual. Enabling this relaxes anti-enumeration (a valid-token holder "
        "can tell an existing account from a non-existent one).",
        &g_auto_create, false),
});

// Process-wide JWKS key cache, shared by all connections.
vsql_oauth2::JwksCache g_jwks_cache;

// Build the key resolver from current config: JWKS-backed when jwks_url is set,
// otherwise the static public_key. Captured values are copied so the resolver
// is self-contained for this auth attempt. No key source -> nullptr, which
// makes oauth_core fail closed.
vsql_oauth2::KeyResolver build_key_resolver() {
  const std::string jwks_url = g_jwks_url != nullptr ? g_jwks_url : "";
  if (!jwks_url.empty()) {
    const unsigned int refresh =
        static_cast<unsigned int>(g_jwks_refresh_interval);
    const unsigned int timeout = static_cast<unsigned int>(g_jwks_http_timeout);
    return [jwks_url, refresh, timeout](const std::string &kid,
                                        std::string &out_pem,
                                        std::string &error_detail) -> bool {
      const std::time_t now = std::time(nullptr);
      const auto status = g_jwks_cache.lookup_pem(
          jwks_url, kid, now, refresh, timeout, out_pem, error_detail);
      return status == vsql_oauth2::JwksCache::Status::OK;
    };
  }

  const std::string pem = g_public_key != nullptr ? g_public_key : "";
  if (pem.empty())
    return nullptr;
  return [pem](const std::string & /*kid*/, std::string &out_pem,
               std::string & /*error_detail*/) -> bool {
    out_pem = pem;
    return true;
  };
}

// Assemble the per-attempt config from current sysvar values plus the account's
// AS '...' clause.
vsql_oauth2::Config build_config(const vef_auth_ops_t *ops,
                                 vef_auth_ctx_t *ctx) {
  vsql_oauth2::Config config;
  if (g_issuer != nullptr)
    config.issuer = g_issuer;
  if (g_audience != nullptr)
    config.audience = g_audience;
  config.resolve_key = build_key_resolver();
  if (g_username_claim != nullptr && g_username_claim[0] != '\0')
    config.username_claim = g_username_claim;
  if (g_roles_claim != nullptr)
    config.roles_claim = g_roles_claim;
  if (g_roles_filter != nullptr)
    config.roles_filter = g_roles_filter;
  if (g_roles_transform_pattern != nullptr)
    config.roles_transform_pattern = g_roles_transform_pattern;
  if (g_roles_transform_replacement != nullptr)
    config.roles_transform_replacement = g_roles_transform_replacement;
  const char *as = ops->auth_string(ctx);
  if (as != nullptr)
    config.auth_string = as;
  return config;
}

// Opt-in for handling UNKNOWN accounts, queried LIVE by the server per
// unknown-account login (so SET GLOBAL vsql_oauth2.auto_create takes effect
// without reinstalling). Non-zero routes unknown-account logins to this method
// for token validation + on-the-fly provisioning; zero preserves the standard
// "unknown account -> access denied".
int auto_create_enabled() { return g_auto_create ? 1 : 0; }

// The authenticator. Reads the JWT the client sent, hands it to
// oauth_core::evaluate() for validation + claim->account mapping, and maps the
// Decision to the auth context. Fail closed: only an explicit accept returns
// VEF_AUTH_OK.
vef_auth_result_t authenticate(vef_auth_ctx_t *ctx, const vef_auth_ops_t *ops) {
  // Read the token. A non-positive length means the client disconnected or sent
  // a malformed packet -- fail closed.
  const unsigned char *pkt = nullptr;
  const int64_t pkt_len = ops->read_packet(ctx, &pkt);
  if (pkt_len <= 0 || pkt == nullptr)
    return VEF_AUTH_ERROR;

  // Extract the JWT from the raw handshake packet. The framing depends on which
  // client plugin the connection negotiated, so pass that name (not a byte sniff)
  // to token_from_packet.
  const std::string token(vsql_oauth2::token_from_packet(
      pkt, pkt_len, ops->client_auth_plugin(ctx)));

  const vsql_oauth2::Decision decision =
      vsql_oauth2::evaluate(token, build_config(ops, ctx));

  // Fail closed: only an explicit accept authenticates. reject_reason is for
  // the server error log only and is never surfaced to the client.
  if (!decision.accept)
    return VEF_AUTH_REJECT;

  // A Decision marked accept must name an account; guard against a malformed
  // accept rather than authenticating as an empty user.
  if (decision.account.empty())
    return VEF_AUTH_ERROR;

  // Auto-create: when this login was routed here for an account that does not
  // exist (the unknown-account opt-in above), ask the server to provision the
  // mapped account -- CREATE USER ... IDENTIFIED WITH vsql_oauth2, granting the
  // token's mapped roles -- so the session then runs AS the new account (no
  // proxy). The server owns the DDL; the token has already been validated
  // above. Provision the DECISION's account (the token's mapped identity), not
  // the raw handshake username, so it matches what we authenticate as. On
  // failure fail closed. A pre-existing account skips this and authenticates
  // normally.
  if (ops->account_unknown(ctx)) {
    std::vector<const char *> role_ptrs;
    role_ptrs.reserve(decision.roles.size());
    for (const std::string &r : decision.roles)
      role_ptrs.push_back(r.c_str());
    if (ops->request_provision(ctx, decision.account.c_str(), role_ptrs.data(),
                               static_cast<uint64_t>(role_ptrs.size())) != 0)
      return VEF_AUTH_ERROR;
  }

  // authenticated_as is the account used for authorization (CURRENT_USER);
  // external_user is the original identity for the audit trail
  // (@@external_user).
  ops->set_authenticated_as(ctx, decision.account.c_str());
  ops->set_external_user(ctx, decision.external_identity.c_str());

  // Activate the roles mapped from the token's roles_claim (filter +
  // transform). The server activates only those already granted to the account
  // -- an ungranted name is skipped, so the token cannot escalate. When the
  // token carried no roles this stages an empty set (no roles active), matching
  // the account's non-default-role state. Skip the call entirely when role
  // mapping is not configured (roles empty) so default-role behavior is
  // unchanged.
  if (!decision.roles.empty()) {
    std::vector<const char *> role_ptrs;
    role_ptrs.reserve(decision.roles.size());
    for (const std::string &r : decision.roles)
      role_ptrs.push_back(r.c_str());
    ops->set_active_roles(ctx, role_ptrs.data(),
                          static_cast<uint64_t>(role_ptrs.size()));
  }
  return VEF_AUTH_OK;
}

// The client-side auth plugin the handshake ADVERTISES as the default for this
// method. Pin the built-in "mysql_clear_password": it is present in every
// client/driver, so a naive client (one that does not pass --default-auth) is
// steered to a plugin it already has and the universal token-in-password-slot
// path (mysql -p"$(token-helper)", JDBC, Grafana, service principals) works with no
// extra artifact.
//
// This is only the DEFAULT for naive clients. A client that explicitly selects
// another plugin still works: the server accepts a VEF method's token under any
// non-scrambler client-plugin name (see vsql_vef_reply_is_verbatim in the
// server). In particular MySQL's native authentication_openid_connect_client
// works with --default-auth=authentication_openid_connect_client + a token file
// (the handler decodes its lenenc framing). Verified 2026-07-11.
//
// TODO(villagesql): make this pin operator-configurable (a sysvar), so a
// deployment that ships the OIDC client plugin can make IT the zero-config
// default. See Docs/DESIGN_CLIENT_TOKEN_ACQUISITION.md and
// Docs/DESIGN_AUTH_METHOD_ENABLED_LIFECYCLE.md.
constexpr auto AUTH_METHOD =
    vsql::preview_auth::make_auth<&authenticate>("vsql_oauth2")
        .pin("mysql_clear_password")
        .auto_create(&auto_create_enabled)
        .build();
// AuthCapability is non-copyable (it self-registers at a fixed address), so
// construct it in place from the built descriptor.
vsql::preview_auth::AuthCapability g_auth{AUTH_METHOD};

} // namespace

VEF_GENERATE_ENTRY_POINTS(make_extension().with(g_auth).with(SYS_VARS))
