# Manual test: vsql_oauth2 extension against real Google SSO

A reproducible procedure to verify the `vsql_oauth2` **extension** end to end against
a **real Google identity provider** — browser SSO, a Google-signed JWT, live JWKS
verification, and login as the mapped account.

This is a **manual** test by nature: it needs a human to complete a browser
sign-in and a Google Cloud OAuth client, so it cannot run in CI. The automated
coverage is the mtr test `oauth_basic` (static key, fail-closed cases). This
procedure validates what the fake can't: real Google keys, real claim shapes,
the real browser -> token -> login chain, and the JWKS-over-HTTP fetch path.

**Verified working on 2026-07-02 with a `villagesql.com` Workspace identity**
(`you@example.com`): `CURRENT_USER()` = `you@example.com@%`,
`@@external_user` = `you@example.com`. This reproduces, on the standalone
extension, the result first achieved with the `vsql_oauth2` plugin on
2026-06-30.

---

## Prerequisites

1. **A build of the extension with JWKS/curl.** `./build.sh` (or `./local-ci.sh`)
   produces `build/vsql_oauth2.veb`. The CMake requires libcurl
   (`find_package(CURL)`), so the JWKS fetch is always compiled in.

2. **A GCP "Desktop" OAuth client.** Create one at
   https://console.cloud.google.com/apis/credentials -> Create credentials ->
   OAuth client ID -> Application type: Desktop app. You need its **client ID**
   (which becomes the token's `aud`) and **client secret**. Download the JSON;
   treat the secret as sensitive.

3. **Python 3** (for the login helper) and a built VillageSQL `mysql` client +
   `mysqld` whose server includes the VEF auth capability.

> macOS note: the terminal (and thus python) needs file access to wherever the
> client-secrets JSON lives. `~/Downloads` is TCC-protected; either grant the
> terminal Full Disk Access, move the JSON to your home dir, or pass
> `--client-id` / `--client-secret` inline instead of `--client-secrets-file`.

> gcloud note: `gcloud auth print-identity-token` is NOT a viable shortcut for a
> human identity — it triggers reauth prompts and yields a claim-poor token (no
> `email`, fixed `aud`). Use the Desktop client + the helper script instead.

---

## Step 1 — Start a dev server with the extension VEB staged

**Server requirement:** needs a villagesql-server build with the VEF auth
capability (the `vsql::preview::auth` seam). As of 2026-07-10 that is branch
`tomas/vsql-auth-capability-2`; a plain `main` build does not have it.

Stage the built VEB in a directory and let mtr start a server pointed at it
(leaving it running). Any suite works to spin the server up; the extension's own
suite already enables preview extensions via its `suite.opt`.

```bash
VEBDIR=/tmp/vsql-oauth2-google-veb
mkdir -p "$VEBDIR"
cp /path/to/vsql-oauth2/build/vsql_oauth2.veb "$VEBDIR/"

cd $VillageSQL_BUILD_DIR
./mysql-test/mysql-test-run.pl --start-and-exit --nowarnings \
  --mysqld=--veb-dir="$VEBDIR" \
  --suite=/path/to/vsql-oauth2/mysql-test oauth_basic
```

It prints the port and socket, e.g.:

```
mysqld.1  13000  .../mysql-test/var/tmp/mysqld.1.sock
```

Note the **port** (used by the login helper over TCP) and the **socket** (used
to connect as root for setup).

## Step 2 — Configure the extension for Google (as root)

```bash
$VillageSQL_BUILD_DIR/runtime_output_directory/mysql \
  --socket=$VillageSQL_BUILD_DIR/mysql-test/var/tmp/mysqld.1.sock -u root
```

```sql
INSTALL EXTENSION vsql_oauth2;

-- Extension system variables use a '.' separator (extension.variable).
SET GLOBAL vsql_oauth2.issuer         = 'https://accounts.google.com';
SET GLOBAL vsql_oauth2.audience       = '<YOUR_CLIENT_ID>.apps.googleusercontent.com';
SET GLOBAL vsql_oauth2.jwks_url       = 'https://www.googleapis.com/oauth2/v3/certs';
SET GLOBAL vsql_oauth2.username_claim = 'email';

-- Confirm the settings (use SHOW, not SELECT @@global.`...`):
SHOW GLOBAL VARIABLES LIKE 'vsql_oauth2.%';

-- The email claim maps to an account of the same name; create it and let it
-- proxy onto itself (identity remap goes through MySQL's proxy mechanism).
CREATE USER '<you@yourdomain>'@'%' IDENTIFIED WITH vsql_oauth2;
GRANT SELECT ON *.* TO '<you@yourdomain>'@'%';
GRANT PROXY ON '<you@yourdomain>'@'%' TO '<you@yourdomain>'@'%';
```

> WARNING: do NOT read a dotted extension sysvar via ``SELECT @@global.`vsql_oauth2.issuer` ``.
> A backtick-quoted qualified extension variable name currently crashes the
> server (an assertion in `set_var.cc`); this is a known server bug, unrelated to
> the extension. Use `SHOW GLOBAL VARIABLES LIKE 'vsql_oauth2.%'` to read them,
> and bare dotted names (`SET GLOBAL vsql_oauth2.issuer = ...`) to set them.

Tip: run the login helper with `--print-claims` first (Step 3 without the DB
connect) to read the token's exact `iss`, `aud`, and `email`, and set the
sysvars to match.

## Step 3 — Log in as your Google identity

Pass the OAuth client via the JSON you downloaded from the GCP credentials page
(keeps the secret off the command line; protect the file with `chmod 600`):

```bash
python3 /path/to/vsql-oauth2/tools/vsql_google_login.py \
  --client-secrets-file ~/client_secret_<...>.json \
  --mysql               "$VillageSQL_BUILD_DIR/runtime_output_directory/mysql" \
  --mysql-host          127.0.0.1 \
  --mysql-port          13000
```

(Alternatively, pass `--client-id` and `--client-secret` directly — handy when
the JSON is in a folder the terminal can't read.)

A browser opens -> sign in with your Google account -> consent. The helper grabs
a fresh `id_token` and connects. You should land in a `mysql` prompt; verify:

```sql
SELECT CURRENT_USER(), @@external_user;
```

Both should show your email. **Success = real Google SSO into VillageSQL via the
extension.**

## Step 4 — Shut down the dev server

```bash
$VillageSQL_BUILD_DIR/runtime_output_directory/mysqladmin \
  --socket=$VillageSQL_BUILD_DIR/mysql-test/var/tmp/mysqld.1.sock -u root shutdown
```

---

## Expected results (acceptance)

| Case | Expectation |
|---|---|
| Valid fresh token | login succeeds; `CURRENT_USER()` = your email |
| Token older than ~1 hour | denied (`exp`) — re-run the helper for a fresh one |
| `vsql_oauth2.audience` not equal to the token's `aud` | denied |
| Wrong/garbage token | denied |

All denials are fail-closed and the reason is in the server error log.

## Troubleshooting

The extension logs the reject reason to the server error log (not to the
client). When a login is denied unexpectedly:

```bash
grep vsql_oauth2 $VillageSQL_BUILD_DIR/mysql-test/var/log/mysqld.1.err | tail -30
```

| Log / client message | Cause / fix |
|---|---|
| `no JWKS key matches token kid` | `jwks_url` wrong/unreachable |
| `token validation failed` | bad signature, expired, or `iss`/`aud` mismatch — re-check `vsql_oauth2.audience` against `--print-claims` |
| `no verification key source configured` | neither `jwks_url` nor `public_key` set |
| `ERROR 1045 ... missing proxy privilege` | the `GRANT PROXY ... TO ...` self-grant is missing |
| client: `mysql_clear_password ... not enabled` | the helper passes `--enable-cleartext-plugin`; if connecting by hand, add it |

## Known limitations

- Token travels in the password slot as cleartext (gated by
  `--enable-cleartext-plugin`); use TLS to the server in any real setting.
- No auto-create: the DB account must pre-exist with the self proxy grant.
- Role mapping is basic (no `roles_filter` / `roles_transform` yet).
- The login helper is a dev/demo tool, not the production client.
