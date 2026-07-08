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

#ifndef VSQL_OAUTH2_JWKS_CACHE_H
#define VSQL_OAUTH2_JWKS_CACHE_H

#include <ctime>
#include <map>
#include <mutex>
#include <string>

namespace vsql_oauth2 {

// Caches IdP signing keys fetched from a JWKS endpoint, mapping each key id
// (kid) to a PEM-encoded public key. Verification keys rotate, so the cache
// refreshes on a TTL and on a kid miss (forced refetch). Thread-safe: many
// connection threads read it; refreshes write it under a lock.
//
// Fetch model: lazy on the auth thread, with a bounded HTTP timeout. The first
// auth after expiry (or a kid miss) pays the fetch; the rest hit the cache. A
// slow or hostile JWKS server makes that one login fail closed, never hang.
class JwksCache {
public:
  JwksCache() = default;

  // Result of resolving a kid to a PEM.
  enum class Status { OK, KID_NOT_FOUND, FETCH_FAILED };

  // Resolve a kid to a PEM public key, fetching/refreshing as needed.
  //
  // `now` is passed in (not read from a clock here) so the logic is testable.
  // Returns OK and sets out_pem on success; otherwise the failure reason and
  // out_pem is left empty. A kid miss against a freshly-fetched JWKS set is
  // KID_NOT_FOUND (unknown key -> caller fails closed).
  Status lookup_pem(const std::string &jwks_url, const std::string &kid,
                    std::time_t now, unsigned int refresh_interval_secs,
                    unsigned int http_timeout_secs, std::string &out_pem,
                    std::string &error_detail);

  // Drop all cached keys (e.g. on jwks_url change). Thread-safe.
  void clear();

private:
  // Fetch the JWKS document over HTTP and rebuild the kid->PEM map. Caller
  // holds mu_. Returns false and sets error_detail on failure (cache left
  // intact).
  bool refresh_locked(const std::string &jwks_url,
                      unsigned int http_timeout_secs, std::time_t now,
                      std::string &error_detail);

  std::mutex mu_;
  std::map<std::string, std::string> kid_to_pem_; // guarded by mu_
  std::string cached_url_;                        // guarded by mu_
  std::time_t fetched_at_ = 0;                    // guarded by mu_
};

} // namespace vsql_oauth2

#endif // VSQL_OAUTH2_JWKS_CACHE_H
