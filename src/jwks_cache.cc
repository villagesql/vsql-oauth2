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

#include "jwks_cache.h"

#include <exception>

#include <curl/curl.h>

#include "jwt-cpp/jwt.h"

namespace vsql_oauth2 {

namespace {

// Cap the JWKS response we will buffer. Real JWKS documents are a few KB (a
// handful of keys); this leaves generous headroom while bounding memory against
// a misbehaving or hostile endpoint that streams an unbounded body.
constexpr size_t kMaxJwksBytes = 512 * 1024;

// Cap redirects we will follow on the JWKS fetch (a JWKS URL should be direct;
// a redirect chain is either misconfiguration or an attempt to bounce us).
constexpr long kMaxRedirects = 5;

struct FetchSink {
  std::string body;
  bool overflowed = false;
};

size_t curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
  auto *sink = static_cast<FetchSink *>(userdata);
  const size_t n = size * nmemb;
  if (sink->body.size() + n > kMaxJwksBytes) {
    // Signal the cap breach and short the transfer: returning a value other
    // than `n` makes curl abort with CURLE_WRITE_ERROR.
    sink->overflowed = true;
    return 0;
  }
  sink->body.append(ptr, n);
  return n;
}

// GET the JWKS document. Returns true and fills `body` on a 2xx response within
// the timeout and size cap; false otherwise. TLS verification is left at libcurl
// defaults (peer + host verified) -- a JWKS endpoint is always HTTPS in practice.
bool http_get(const std::string &url, unsigned int timeout_secs,
              std::string &body, std::string &error_detail) {
  CURL *curl = curl_easy_init();
  if (curl == nullptr) {
    error_detail = "curl_easy_init failed";
    return false;
  }

  FetchSink sink;
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(timeout_secs));
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, kMaxRedirects);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

  const CURLcode rc = curl_easy_perform(curl);
  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  curl_easy_cleanup(curl);

  // A write-callback overflow surfaces as CURLE_WRITE_ERROR; report the real
  // cause rather than the generic curl string.
  if (sink.overflowed) {
    error_detail = "JWKS document exceeds " + std::to_string(kMaxJwksBytes) +
                   " byte cap";
    return false;
  }
  if (rc != CURLE_OK) {
    error_detail = std::string("JWKS fetch failed: ") + curl_easy_strerror(rc);
    return false;
  }
  if (http_code < 200 || http_code >= 300) {
    error_detail = "JWKS endpoint returned HTTP " + std::to_string(http_code);
    return false;
  }
  body = std::move(sink.body);
  return true;
}

// Convert one JWK to a PEM public key. Supports RSA (n/e) and EC (crv/x/y),
// covering the RS* and ES* families (EC works for any curve the JWK carries --
// P-256/384/521 -- since crv is passed through to the PEM). Returns empty on an
// unsupported/malformed key.
std::string jwk_to_pem(const jwt::jwk<jwt::traits::kazuho_picojson> &key) {
  try {
    const std::string kty = key.get_key_type();
    if (kty == "RSA") {
      return jwt::helper::create_public_key_from_rsa_components(
          key.get_jwk_claim("n").as_string(),
          key.get_jwk_claim("e").as_string());
    }
    if (kty == "EC") {
      return jwt::helper::create_public_key_from_ec_components(
          key.get_jwk_claim("crv").as_string(),
          key.get_jwk_claim("x").as_string(),
          key.get_jwk_claim("y").as_string());
    }
  } catch (const std::exception &) {
    // fall through -> empty
  }
  return "";
}

} // namespace

JwksCache::Status JwksCache::lookup_pem(const std::string &jwks_url,
                                        const std::string &kid, std::time_t now,
                                        unsigned int refresh_interval_secs,
                                        unsigned int http_timeout_secs,
                                        std::string &out_pem,
                                        std::string &error_detail) {
  out_pem.clear();
  std::lock_guard<std::mutex> lock(mu_);

  // Refresh if the URL changed, the cache is empty, or the TTL elapsed.
  const bool url_changed = (jwks_url != cached_url_);
  const bool stale =
      (fetched_at_ == 0) ||
      (now - fetched_at_ >= static_cast<std::time_t>(refresh_interval_secs));
  if (url_changed || stale || kid_to_pem_.empty()) {
    if (!refresh_locked(jwks_url, http_timeout_secs, now, error_detail)) {
      // If we still have usable cached keys from a prior fetch, fall back to
      // them rather than failing on a transient fetch error.
      if (kid_to_pem_.empty())
        return Status::FETCH_FAILED;
    }
  }

  auto it = kid_to_pem_.find(kid);
  if (it == kid_to_pem_.end()) {
    // Key not found. It may have just rotated in -- force one refetch (unless
    // we already fetched this call) and retry.
    if (!stale && !url_changed) {
      if (refresh_locked(jwks_url, http_timeout_secs, now, error_detail))
        it = kid_to_pem_.find(kid);
    }
    if (it == kid_to_pem_.end()) {
      if (error_detail.empty())
        error_detail = "no JWKS key matches token kid '" + kid + "'";
      return Status::KID_NOT_FOUND;
    }
  }

  out_pem = it->second;
  return Status::OK;
}

void JwksCache::clear() {
  std::lock_guard<std::mutex> lock(mu_);
  kid_to_pem_.clear();
  cached_url_.clear();
  fetched_at_ = 0;
}

bool JwksCache::refresh_locked(const std::string &jwks_url,
                               unsigned int http_timeout_secs, std::time_t now,
                               std::string &error_detail) {
  std::string body;
  if (!http_get(jwks_url, http_timeout_secs, body, error_detail))
    return false;

  std::map<std::string, std::string> fresh;
  size_t skipped = 0;
  try {
    const auto jwks = jwt::parse_jwks(body);
    for (const auto &key : jwks) {
      if (!key.has_key_id())
        continue;
      const std::string pem = jwk_to_pem(key);
      if (pem.empty()) {
        // Unsupported kty or malformed key parameters. Don't drop it silently:
        // a key we can't convert is a JWKS problem the operator should see, not
        // a benign no-op (silent skip can mask corruption or a rotated-in key
        // in an alg we don't accept).
        ++skipped;
        continue;
      }
      fresh[key.get_key_id()] = pem;
    }
  } catch (const std::exception &e) {
    error_detail = std::string("JWKS parse failed: ") + e.what();
    return false;
  }

  if (fresh.empty()) {
    error_detail = skipped > 0
                       ? "JWKS document had " + std::to_string(skipped) +
                             " key(s), none convertible (unsupported type or "
                             "malformed)"
                       : "JWKS document contained no usable keys";
    return false;
  }
  if (skipped > 0) {
    // Partial success: usable keys exist, but flag the unconvertible ones so a
    // kid miss on a skipped key is diagnosable rather than mysterious.
    error_detail = "JWKS: skipped " + std::to_string(skipped) +
                   " unconvertible key(s); loaded " +
                   std::to_string(fresh.size());
  }

  kid_to_pem_.swap(fresh);
  cached_url_ = jwks_url;
  fetched_at_ = now;
  return true;
}

} // namespace vsql_oauth2
