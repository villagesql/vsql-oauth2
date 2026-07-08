# Testing vsql_oauth2

## Run the test suite (recommended)

```bash
export VillageSQL_BUILD_DIR=/path/to/villagesql/build
./test.sh            # build + stage the VEB + run MTR
RECORD=1 ./test.sh   # also regenerate the .result files
```

`test.sh` builds the VEB, stages it into a temporary veb-dir, and runs the suite
against the dev server. The suite is hermetic — no external IdP or network.

## Run MTR manually

Equivalent to what `test.sh` does, run from the server's `mysql-test/` directory
(the VEB must already be staged in the server's veb-dir):

```bash
cd /path/to/villagesql/build/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-oauth2/mysql-test
```

Regenerate expected results after an intended change:

```bash
perl mysql-test-run.pl --suite=/path/to/vsql-oauth2/mysql-test --record
```

## What the tests cover

**oauth_basic.test** (hermetic — uses pre-signed RS256 tokens, no external IdP):
- Installs `vsql_oauth2`, creates an account bound to it, configures a static
  `public_key` + `issuer`.
- **Valid token** → accepted; session runs as the mapped account
  (`CURRENT_USER()`), original identity in `@@external_user`.
- **Expired token** → rejected (fail closed).
- **Malformed / non-JWT token** → rejected.
- **Empty token** → rejected.
- **No key source configured** → rejected (no trust without a verification key).

## Notes

- Tokens are pre-signed and embedded in the test, so no live IdP, JWKS endpoint,
  or network access is needed — the suite runs offline.
- The client sends the token in the password slot via `mysql_clear_password`, so
  the test client uses `--enable-cleartext-plugin`.
- `suite.opt` supplies `--vsql_allow_preview_extensions=ON` (the auth capability
  is a preview capability).
