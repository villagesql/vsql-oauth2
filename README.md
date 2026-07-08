# VillageSQL OAuth2 Authentication Extension

OAuth2/OIDC JWT authentication for VillageSQL, provided as an extension via the
VillageSQL Extension Framework (VEF) `vsql::preview::auth` capability.

An account created with `IDENTIFIED WITH vsql_oauth2` authenticates by presenting
a JWT (bearer token) instead of a password. The extension validates the token's
signature and claims and maps it to a VillageSQL account.

## Status

Preview. Requires a server built with the VEF auth capability, started with
`--vsql_allow_preview_extensions=ON`.

This version validates against a **static public key** (`RS256`/`ES256`).
Fetching signing keys from a JWKS endpoint is not yet included.

## How it works

- The extension registers the auth method `vsql_oauth2`.
- It pairs with the built-in `mysql_clear_password` client plugin, so a standard
  client sends the JWT verbatim in the password slot (the client must opt in
  with `--enable-cleartext-plugin`).
- On connect, the extension reads the token, verifies the signature with the
  configured public key, checks `exp` (and `iss`/`aud` when configured), then
  maps the configured username claim to an account. Anything else fails closed.

JWT validation uses [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) (fetched at
configure time) over OpenSSL; no server-side JWT primitive is required.

## Prerequisites

- A VillageSQL build directory (`VillageSQL_BUILD_DIR`) whose server includes the
  VEF auth capability.
- CMake 3.16+, a C++17 compiler.
- OpenSSL development headers (present wherever the server builds).
- Network access at configure time (CMake `FetchContent` downloads jwt-cpp,
  pinned to a known-good commit).

## Build

```bash
export VillageSQL_BUILD_DIR=$HOME/build/villagesql
./build.sh
```

This produces `build/vsql_oauth2.veb`.

## Install and configure

```sql
INSTALL EXTENSION vsql_oauth2;

-- Extension system variables are namespaced with a '.' separator
-- (extension.variable). PEM public key verifying token signatures
-- (RS256/ES256):
SET GLOBAL vsql_oauth2.public_key = '-----BEGIN PUBLIC KEY----- ...';

-- Optional claim checks (empty disables the check).
SET GLOBAL vsql_oauth2.issuer   = 'https://idp.example';
SET GLOBAL vsql_oauth2.audience = 'my-app-client-id';

-- Which claim is the identity (default 'sub'; many IdPs use 'email').
SET GLOBAL vsql_oauth2.username_claim = 'email';
```

Create an account bound to the method. The identity the token maps to must exist
as an account, and the connecting account must be allowed to proxy onto it:

```sql
CREATE USER oidc_user IDENTIFIED WITH vsql_oauth2;
CREATE USER 'alice@example.com';
GRANT SELECT ON app.* TO 'alice@example.com';
GRANT PROXY ON 'alice@example.com' TO oidc_user;
```

## Logging in

The extension authenticates a connection from a JWT presented in the password
slot (via the built-in `mysql_clear_password` client plugin). *Obtaining* that
token is standard OAuth for your environment; *sending* it is the same across
all three cases below.

### Interactive shell — `tools/vsql` (browser sign-in)

For a human at a prompt, `tools/vsql` runs the Google browser flow and hands off
to the standard `mysql` client with the token. Configure once via environment,
then it behaves like `mysql`:

```bash
export VSQL_CLIENT_SECRETS=~/client_secret_<...>.json   # your GCP Desktop client
export VSQL_HOST=127.0.0.1 VSQL_PORT=3306

vsql                              # browser pop-up -> interactive shell
vsql mydb                         # open a database
vsql -e "SELECT CURRENT_USER(), @@external_user"
```

`CURRENT_USER()` is the mapped account (used for authorization); `@@external_user`
is the original identity from the token, for the audit trail.

### Non-interactive scripts

There is no browser in cron/CI: obtain a token non-interactively (a service
account / workload-identity / client-credentials flow that yields a JWT), then
send it. The token goes via `MYSQL_PWD` so it never lands in the process list:

```bash
MYSQL_PWD="$(get_service_token)" \
  mysql --enable-cleartext-plugin --user=svc@example.com mydb < migrate.sql
```

### Application code

Apps use a connector, not the `mysql` binary. Obtain the token with your app's
own OAuth library, then connect over `mysql_clear_password` — supported by
libmysqlclient and the connectors today. E.g. Connector/Python:

```python
mysql.connector.connect(
    host="...", user="alice@example.com", password=id_token,
    auth_plugin="mysql_clear_password",  # + a secure transport (TLS)
)
```

In all three, the credential is a bearer token in cleartext at the protocol
level — use TLS to the server.

## System variables

| Variable | Default | Description |
|----------|---------|-------------|
| `vsql_oauth2.public_key` | `''` | PEM public key verifying the JWT signature. Empty rejects all tokens. |
| `vsql_oauth2.issuer` | `''` | Expected `iss` claim. Empty disables the check. |
| `vsql_oauth2.audience` | `''` | Expected `aud` claim. Empty disables the check. |
| `vsql_oauth2.username_claim` | `sub` | Claim holding the user identity. |
| `vsql_oauth2.roles_claim` | `''` | Claim holding role/group identifiers (mapped to DB roles). IdP-specific: Entra App Roles in `roles`, Google/Okta groups in `groups`. Empty disables role activation. |
| `vsql_oauth2.roles_filter` | `''` | Regex a `roles_claim` value must fully match to become a role (empty accepts all). E.g. `mysql-grp-.*`. |
| `vsql_oauth2.roles_transform_pattern` | `''` | Regex rewritten (with the replacement) on each matched value. E.g. `-` to sanitize `mysql-grp-x`. Empty disables the transform. |
| `vsql_oauth2.roles_transform_replacement` | `''` | Replacement for `roles_transform_pattern`. E.g. `_`. |

## Roles

When `roles_claim` is set, the values of that claim in the validated token are
mapped to database roles and **activated on the session**:

1. Read the `roles_claim` values (e.g. Entra `roles`: `["mysql-grp-trading", …]`).
2. Keep those fully matching `roles_filter` (e.g. `mysql-grp-.*`).
3. Rewrite each via `roles_transform_pattern` → `roles_transform_replacement`
   (e.g. `-`→`_`, turning `mysql-grp-trading` into a valid role name).
4. Activate the resulting roles on the session — `CURRENT_ROLE()` reflects them.

The token drives **which roles are active**, never what they grant:

- The database is the source of truth for privileges. **The DBA must create each
  role and grant it to the account** (`CREATE ROLE trading; GRANT trading TO
  <account>;`). The token only selects which already-granted roles are active
  for the session.
- Activation is **grant-checked**: a role named by the token that is *not*
  granted to the account is silently skipped (logged server-side) — a token can
  never activate a role, or gain a privilege, the DBA did not provision.
- A bad `roles_filter`/`roles_transform` regex maps to **no** roles (fail closed
  on authorization). A token that carries no matching roles leaves the account's
  default roles in effect.

Role activation requires no server configuration beyond a VillageSQL build that
provides the `set_active_roles` auth op. Not all IdPs emit a usable claim: Entra
App Roles arrive in `roles`; native Google accounts carry **no** group/role
claim in the token, so role mapping cannot apply there (authorize on `sub`/`hd`
instead).

## Security notes

- **Fail closed**: only an explicitly valid token authenticates. A missing key,
  bad signature, expired token, wrong `iss`/`aud`, or unsupported algorithm
  all deny the connection.
- **Algorithm pinning**: only `RS256` and `ES256` are accepted. `alg:none` and
  the `HS*` family (which would let an attacker sign with the public key as an
  HMAC secret) are rejected before any signature check.
- The token is sent in the password slot in cleartext at the protocol level; use
  TLS for the connection.

## Testing

The MTR test (`mysql-test/`) covers accept (valid token), and fail-closed for
expired/garbage/empty tokens, missing key, and after uninstall. It uses a fixed
test keypair and pre-signed tokens, so no runtime crypto or network is needed.

### One command: `test.sh`

`test.sh` builds the extension (via `build.sh`), stages the VEB in a temp
directory, and runs the MTR suite against it (letting MTR manage its own server)
— the same steps CI runs.

```bash
export VillageSQL_BUILD_DIR=$HOME/build/villagesql
./test.sh            # build + run the test suite
RECORD=1 ./test.sh   # build + (re)generate the expected .result files
```

Use `RECORD=1` after changing the test or its expected output; commit the
resulting `mysql-test/r/*.result`.

### Manually

```bash
cd $VillageSQL_BUILD_DIR/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-oauth2/mysql-test
```

## License

GPL v2 — see LICENSE.
