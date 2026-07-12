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

#include "oauth_core.h"

#include <exception>
#include <regex>

#include "jwt-cpp/jwt.h"

namespace vsql_oauth2 {

namespace {

// Reject a token, recording the reason for the error log only. Always returns a
// Decision with accept=false so callers can `return reject(...)`.
Decision reject(const char *reason) {
  Decision d;
  d.accept = false;
  d.reject_reason = reason;
  return d;
}

// Turn the raw string values of the roles claim into DB roles by applying the
// configured filter and transform:
//   - filter: keep only values that FULLY match roles_filter (empty = keep all)
//   - transform: rewrite each kept value via regex_replace (empty pattern =
//   as-is)
// e.g. filter "mysql-grp-.*" with transform "-" -> "_" maps
// "mysql-grp-traders" -> "mysql_grp_traders".
//
// A malformed filter/transform regex is an AUTHORIZATION config error, not an
// authentication failure: the token is already validated by this point, so a
// bad pattern yields NO roles (fail closed on authorization) rather than
// denying the login. The caller has already accepted the identity.
std::vector<std::string> map_roles(const std::vector<std::string> &values,
                                   const Config &config) {
  std::vector<std::string> roles;
  try {
    const bool has_filter = !config.roles_filter.empty();
    const bool has_transform = !config.roles_transform_pattern.empty();
    const std::regex filter =
        has_filter ? std::regex(config.roles_filter) : std::regex();
    const std::regex transform =
        has_transform ? std::regex(config.roles_transform_pattern)
                      : std::regex();

    for (const std::string &value : values) {
      if (has_filter && !std::regex_match(value, filter))
        continue;
      roles.push_back(
          has_transform ? std::regex_replace(value, transform,
                                             config.roles_transform_replacement)
                        : value);
    }
  } catch (const std::regex_error &) {
    // Bad filter/transform pattern -> map no roles (see note above).
    return {};
  }
  return roles;
}

} // namespace

Decision evaluate(const std::string &token, const Config &config) {
  // No key source configured -> we cannot trust any token. Fail closed.
  if (!config.resolve_key)
    return reject("no verification key source configured");

  try {
    const auto decoded = jwt::decode(token);

    // Resolve the verification key by the token's kid (empty kid is fine for
    // the static-key resolver, which ignores it). A resolver failure -- unknown
    // kid, JWKS fetch error -- rejects the token.
    const std::string kid =
        decoded.has_key_id() ? decoded.get_key_id() : std::string();
    std::string pem;
    std::string key_error;
    if (!config.resolve_key(kid, pem, key_error) || pem.empty())
      return reject(key_error.empty() ? "could not resolve verification key"
                                      : key_error.c_str());

    // Only RS256 and ES256 are accepted. Reading alg from the token and
    // dispatching explicitly means alg:none -- and every other algorithm,
    // including the HS* family that would let an attacker sign with the public
    // key as an HMAC secret -- is rejected before any signature check.
    const std::string alg = decoded.get_algorithm();

    auto verifier = jwt::verify();
    if (alg == "RS256") {
      verifier =
          verifier.allow_algorithm(jwt::algorithm::rs256(pem, "", "", ""));
    } else if (alg == "ES256") {
      verifier =
          verifier.allow_algorithm(jwt::algorithm::es256(pem, "", "", ""));
    } else {
      return reject("unsupported or missing alg (only RS256/ES256 allowed)");
    }

    // exp is enforced automatically by the verifier. iss/aud are enforced only
    // when configured, so an operator can opt out, but the signature check
    // above is never optional.
    if (!config.issuer.empty())
      verifier = verifier.with_issuer(config.issuer);
    if (!config.audience.empty())
      verifier = verifier.with_audience(config.audience);

    // Throws on any failure: bad signature, expired, wrong iss/aud.
    verifier.verify(decoded);

    // --- Token is valid past this point. Map claims to an account/roles. ---

    Decision d;

    if (!decoded.has_payload_claim(config.username_claim))
      return reject("token missing the configured username claim");
    const std::string identity =
        decoded.get_payload_claim(config.username_claim).as_string();
    if (identity.empty())
      return reject("username claim is empty");

    d.external_identity = identity;
    d.account = identity;

    // Roles claim -> roles: gather the claim's raw string values, then apply
    // the configured filter + transform (map_roles).
    if (!config.roles_claim.empty() &&
        decoded.has_payload_claim(config.roles_claim)) {
      std::vector<std::string> raw;
      const auto claim = decoded.get_payload_claim(config.roles_claim);
      if (claim.get_type() == jwt::json::type::array) {
        for (const auto &g : claim.as_array()) {
          if (g.is<std::string>())
            raw.push_back(g.get<std::string>());
        }
      } else if (claim.get_type() == jwt::json::type::string) {
        raw.push_back(claim.as_string());
      }
      d.roles = map_roles(raw, config);
    }

    d.accept = true;
    return d;
  } catch (const std::exception &) {
    // jwt-cpp signals every validation failure (parse error, bad signature,
    // expired, iss/aud mismatch) by throwing. Any exception -> fail closed.
    return reject("token validation failed");
  }
}

namespace {

// Decode a MySQL length-encoded integer at p[0..avail). Writes the value to
// *out and returns bytes consumed, or 0 if malformed/truncated (lead 0xfb/0xff,
// or not enough following bytes). lead < 0xfb is the value itself; 0xfc/0xfd/0xfe
// are followed by 2/3/8 little-endian bytes.
size_t read_lenenc(const unsigned char *p, size_t avail, uint64_t *out) {
  if (avail == 0) return 0;
  const unsigned char lead = p[0];
  if (lead < 0xfb) {
    *out = lead;
    return 1;
  }
  int extra;
  switch (lead) {
    case 0xfc: extra = 2; break;
    case 0xfd: extra = 3; break;
    case 0xfe: extra = 8; break;
    default: return 0;  // 0xfb (NULL) / 0xff (error) are not valid here
  }
  if (avail < 1u + static_cast<size_t>(extra)) return 0;
  uint64_t v = 0;
  for (int i = 0; i < extra; ++i)
    v |= static_cast<uint64_t>(p[1 + i]) << (8 * i);
  *out = v;
  return 1 + static_cast<size_t>(extra);
}

}  // namespace

std::string_view token_from_packet(const unsigned char *pkt, int64_t pkt_len,
                                   std::string_view client_plugin) {
  if (pkt == nullptr || pkt_len <= 0) return {};
  const size_t len = static_cast<size_t>(pkt_len);

  // Select framing by the NEGOTIATED client-plugin name (deterministic), not by
  // sniffing packet bytes: the OIDC client's leading byte is a capability
  // bitmask (not a format tag), so byte-sniffing would be fragile as
  // capabilities evolve. The plugin name is authoritative.
  if (client_plugin == "authentication_openid_connect_client") {
    // The stock MySQL 9.1+ client plugin (Community; ships with the client, not
    // this repo). We support it so a stock 9.1+ client can authenticate against
    // this server with no custom artifact. Its framing (confirmed by decoding a
    // real packet + reading upstream's client plugin): a 1-byte capability field,
    // then a MySQL length-encoded-integer length, then the raw JWT -- it writes
    // `unsigned short capability = 1` as one byte, then net_store_length(len),
    // then the token.
    uint64_t n = 0;
    const size_t hdr = read_lenenc(pkt + 1, len - 1, &n);  // after the cap byte
    if (hdr == 0) return {};             // malformed length -> fail closed
    const size_t consumed = 1 + hdr;
    if (consumed + n > len) return {};   // length overruns packet
    return {reinterpret_cast<const char *>(pkt + consumed),
            static_cast<size_t>(n)};
  }

  // Default (mysql_clear_password and any other verbatim-credential plugin): the
  // whole packet, minus a trailing NUL if present.
  size_t token_len = len;
  if (pkt[token_len - 1] == '\0') --token_len;
  return {reinterpret_cast<const char *>(pkt), token_len};
}

} // namespace vsql_oauth2
