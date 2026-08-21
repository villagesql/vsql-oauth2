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
// By default the server advertises the built-in mysql_clear_password client
// plugin for this method, so a standard client sends the JWT verbatim in the
// password slot (the client must opt in with --enable-cleartext-plugin, which
// lets that plugin send a cleartext secret; use TLS to the server).
//
// This file wires the extension into the SDK: the vsql_oauth2.* system
// variables (each documented on its sv::make_* entry below), the authenticate
// handler, and the AuthCapability that registers the method. The README is the
// operator-facing reference for configuration, roles, and login; oauth_core
// holds the wrapper-agnostic token validation and claim->account mapping.

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
long long g_jwks_refresh_interval = 3600;
long long g_jwks_http_timeout = 5;
bool g_auto_create = false;
bool g_auto_grant = false;

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
        "valid token creates the account (CREATE USER ... IDENTIFIED WITH "
        "vsql_oauth2), then the session runs as the new account. When OFF "
        "(default), accounts that do not exist are rejected as usual. Enabling "
        "this lets a holder of a valid token tell an existing account from one "
        "that does not exist.",
        &g_auto_create, false),
    sv::make_bool(
        "auto_grant",
        "When ON, the DB roles mapped from the token's roles_claim (after "
        "roles_filter/roles_transform) that exist as DB roles are GRANTED to "
        "the resolved account on each login, so a claimed role the account was "
        "not granted takes effect. When OFF (default), roles are only "
        "ACTIVATED "
        "grant-checked -- a claimed role not already granted is skipped, so "
        "the "
        "token cannot escalate (the DBA owns grants). Independent of "
        "auto_create.",
        &g_auto_grant, false),
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
vsql_oauth2::Config build_config(vsql::preview_auth::AuthContext &c) {
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
  const char *as = c.auth_string();
  if (as != nullptr)
    config.auth_string = as;
  return config;
}

// Opt-in for handling logins to accounts that do not exist, queried live by the
// server per such login (so SET GLOBAL vsql_oauth2.auto_create takes effect
// without reinstalling). True routes these logins to this method so it can
// validate the token and create the account; false preserves the standard
// "account does not exist -> access denied".
bool auto_create_enabled() { return g_auto_create; }

// Opt-in for granting the token's mapped roles to the resolved account, queried
// live per login (so SET GLOBAL vsql_oauth2.auto_grant takes effect without
// reinstalling). True has the server grant those roles; false keeps the default
// where a claimed role that was not already granted is skipped. Independent of
// auto_create.
bool auto_grant_enabled() { return g_auto_grant; }

// The authenticator. Reads the JWT the client sent, hands it to
// oauth_core::evaluate() for validation + claim->account mapping, and maps the
// Decision to the auth context. Fail closed: only an explicit accept returns
// AuthResult::kOk.
vsql::preview_auth::AuthResult
authenticate(vsql::preview_auth::AuthContext &c) {
  using vsql::preview_auth::AuthResult;

  // Read the token. An empty span means the client disconnected or sent a
  // malformed packet -- fail closed.
  const auto pkt = c.read_packet();
  if (pkt.empty())
    return AuthResult::kError;

  // Extract the JWT from the raw handshake packet. The framing depends on which
  // client plugin the connection negotiated, so pass that name (not a byte
  // sniff) to token_from_packet.
  const std::string token(vsql_oauth2::token_from_packet(
      pkt.data(), static_cast<int64_t>(pkt.size()), c.client_auth_plugin()));

  const vsql_oauth2::Decision decision =
      vsql_oauth2::evaluate(token, build_config(c));

  // Fail closed: only an explicit accept authenticates. reject_reason is for
  // the server error log only and is never surfaced to the client.
  if (!decision.accept)
    return AuthResult::kReject;

  // A Decision marked accept must name an account; guard against a malformed
  // accept rather than authenticating as an empty user.
  if (decision.account.empty())
    return AuthResult::kError;

  // Auto-create: when this login was routed here for an account that does not
  // exist (the unknown-account opt-in above), ask the server to create the
  // mapped account -- CREATE USER ... IDENTIFIED WITH vsql_oauth2, granting the
  // token's mapped roles -- so the session then runs as the new account
  // directly. The server runs the DDL; the token has already been validated
  // above. Create the DECISION's account (the token's mapped identity), not
  // the raw handshake username, so it matches what we authenticate as. The
  // server defers the DDL until this handler returns kOk and fails the login if
  // it can't create the account, so there is nothing to check here. An account
  // that already exists skips this and authenticates normally.
  if (c.account_unknown()) {
    std::vector<const char *> role_ptrs;
    role_ptrs.reserve(decision.roles.size());
    for (const std::string &r : decision.roles)
      role_ptrs.push_back(r.c_str());
    c.request_provision(decision.account.c_str(), role_ptrs.data(),
                        static_cast<uint32_t>(role_ptrs.size()));
  }

  // authenticated_as is the account used for authorization (CURRENT_USER);
  // external_user is the original identity for the audit trail
  // (@@external_user).
  c.authenticate_as(decision.account.c_str());
  c.set_external_user(decision.external_identity.c_str());

  // Activate the roles mapped from the token's roles_claim (filter +
  // transform). The server activates only those already granted to the account
  // -- a role that is not granted is skipped, so the token cannot escalate.
  // Skip the call entirely when role mapping is not configured (roles empty),
  // so the account's default roles apply unchanged.
  if (!decision.roles.empty()) {
    std::vector<const char *> role_ptrs;
    role_ptrs.reserve(decision.roles.size());
    for (const std::string &r : decision.roles)
      role_ptrs.push_back(r.c_str());
    c.set_active_roles(role_ptrs.data(),
                       static_cast<uint32_t>(role_ptrs.size()));
  }
  return AuthResult::kOk;
}

// The client-side auth plugin the server advertises as the default for this
// method. We use the built-in "mysql_clear_password": it ships with every
// client and driver, so a client that does not name a plugin of its own is
// steered to one it already has, and the token is sent verbatim in the
// password slot (mysql -p"$(token-helper)", JDBC, Grafana, service accounts)
// with no extra client-side software.
//
// This is only the default. A client that explicitly selects another plugin
// still connects if this method accepts that plugin: the server asks
// accepts_client_plugin() below whether to take the client's offer as-is,
// otherwise it tells the client to switch to the advertised default. In
// particular MySQL's own authentication_openid_connect_client works with
// --default-auth=authentication_openid_connect_client and a token file (the
// handler decodes its length-encoded framing).
//
// TODO(villagesql): make .client_plugin() operator-configurable, so a
// deployment that ships the OIDC client plugin can make IT the zero-config
// default.

// Which client plugins this method accepts as-is (without asking the client to
// switch to the advertised default). The server asks this during handshake
// negotiation; we accept exactly the plugins token_from_packet can decode. For
// any other offer the server tells the client to switch to the default, so a
// client that named an unsupported plugin still connects. `offered` is the raw
// client-supplied name; delegate to the core accept-set so it stays in lockstep
// with the framing dispatch.
bool accepts_client_plugin(const char *offered) {
  return offered != nullptr && vsql_oauth2::accepts_client_plugin(offered);
}

constexpr auto AUTH_METHOD =
    vsql::preview_auth::make_auth<&authenticate>("vsql_oauth2")
        .client_plugin("mysql_clear_password")
        .auto_create(&auto_create_enabled)
        .auto_grant(&auto_grant_enabled)
        .accepts_client_plugin(&accepts_client_plugin)
        .build();
// AuthCapability is non-copyable (it self-registers at a fixed address), so
// construct it in place from the built descriptor.
vsql::preview_auth::AuthCapability g_auth{AUTH_METHOD};

} // namespace

VEF_GENERATE_ENTRY_POINTS(make_extension().with(g_auth).with(SYS_VARS))
