# Manual test: vsql_oauth2 auto-create-on-first-login against real Azure Entra ID

A reproducible procedure to verify the `vsql_oauth2` **auto-create** feature end
to end against a **real Entra ID (Azure AD) tenant**: an account that does NOT
exist logs in with an Entra-signed JWT, and the server provisions it on the fly
(`CREATE USER ... IDENTIFIED WITH vsql_oauth2`), grants the token's mapped roles,
and completes the login AS the new account — no DBA pre-provisioning.

This is the auto-create sibling of `MANUAL_TEST_ENTRA.md`. That runbook requires
the DB account (and a self `GRANT PROXY`) to pre-exist; here the whole point is
that it does NOT — the login creates it. Everything else (Entra setup, JWKS
verification, App-Role → active MySQL role) is identical, so this file only
calls out the differences.

Like the base runbook this is **manual by nature** (a human browser sign-in +
a tenant) and cannot run in CI. Automated coverage is `auth_auto_create` (the
server-side auto-create flow with a fake auth extension).

> Verified working 2026-07-10 (against a real tenant + assigned identity): a
> non-existent account was auto-created from an Entra JWT and logged in with
> `CURRENT_ROLE()` = `` `mysql-grp-trading`@`%` ``, using the stock mysql client
> with a minted token in the password slot.

---

## Entra setup (one-time)

Identical to `MANUAL_TEST_ENTRA.md` — two app registrations plus an App-Role
assignment. See that file for the walkthrough. The IDs from the verified run
(substitute your own; they also live in `~/.vsql/entra.json` for the minter):

| | Value |
|---|---|
| Tenant (Directory) ID | `<tenant-id>` |
| CLI app (client) ID | `<cli-app-id>` |
| DB app (client) ID / `audience` | `<db-app-id>` |
| Scope | `api://<db-app-id>/.default` |

## Step 0 — inspect the token first (no DB needed)

Confirm Entra emits the role, and note the identity in `preferred_username`
(that becomes the auto-created account name):

```bash
python3 tools/vsql_entra_login.py --print-claims
```

(With `~/.vsql/entra.json` populated, `--tenant`/`--client-id`/`--scope` are
optional.) Look for `iss` ending `/v2.0`, `aud` = the DB app id, and
**`roles`: `["mysql-grp-trading"]`**.

## Step 1 — start a dev server with the VEB staged

**Server requirement:** auto-create needs a villagesql-server build that carries
the VEF auth capability AND the auto-create support (the `account_unknown` /
`request_provision` ABI ops, decoy routing in `decoy_user`, the decoy
re-resolve, and the `CREATE USER ... IDENTIFIED WITH <vef-method>`
PLUGIN_ATTR-preservation fix). As of 2026-07-10 that is branch
`tomas/vsql-auth-capability-2` **with the auto-create changes applied** (they may
not all be committed yet — verify the build actually persists a VEF method as
the account plugin; see the `caching_sha2_password` row in Troubleshooting). A
plain `main` build does NOT have auto-create. The server must also allow preview
extensions (`--vsql_allow_preview_extensions=ON`, which the mtr harness sets).

```bash
export VillageSQL_BUILD_DIR=$HOME/githome/villagesql-server/build-debug

cd "$VillageSQL_BUILD_DIR"
./mysql-test/mysql-test-run.pl --start-and-exit --nowarnings \
  --suite=/path/to/vsql-oauth2/mysql-test oauth_basic
```

Prints the port (**13000**) and the root socket. Then stage the freshly-built
VEB into the server's **actual** `veb_dir` — read it, do not guess (it is
`.../var/mysqld.1/veb/`, NOT `datadir/extensions`):

```bash
VEBDIR=$("$VillageSQL_BUILD_DIR"/runtime_output_directory/mysql \
  --socket="$VillageSQL_BUILD_DIR"/mysql-test/var/tmp/mysqld.1.sock -u root \
  -N -e "SELECT @@veb_dir")
cp /path/to/vsql-oauth2/build/vsql_oauth2.veb "$VEBDIR/"
```

## Step 2 — configure the extension, enable auto_create, pre-create the ROLE only

Connect as root:

```bash
"$VillageSQL_BUILD_DIR"/runtime_output_directory/mysql \
  --socket="$VillageSQL_BUILD_DIR"/mysql-test/var/tmp/mysqld.1.sock -u root
```

```sql
INSTALL EXTENSION vsql_oauth2;

-- Entra v2 endpoints for this tenant:
SET GLOBAL vsql_oauth2.issuer   = 'https://login.microsoftonline.com/<tenant-id>/v2.0';
SET GLOBAL vsql_oauth2.jwks_url = 'https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys';
SET GLOBAL vsql_oauth2.audience = '<db-app-id>';
SET GLOBAL vsql_oauth2.username_claim = 'preferred_username';
SET GLOBAL vsql_oauth2.roles_claim  = 'roles';
SET GLOBAL vsql_oauth2.roles_filter = 'mysql-grp-.*';

-- THE difference vs MANUAL_TEST_ENTRA.md: turn on auto-create.
SET GLOBAL vsql_oauth2.auto_create = ON;

-- Pre-create the ROLE the token maps to. Roles must exist for the auto-create
-- GRANT to stick (the DBA owns roles; the token only causes an EXISTING role to
-- be granted -- the no-escalation guarantee). The role name must match the
-- mapped value verbatim (hyphenated, so quote it).
CREATE ROLE IF NOT EXISTS 'mysql-grp-trading';
GRANT SELECT ON *.* TO 'mysql-grp-trading';

-- Do NOT create the user account, and do NOT grant proxy. Auto-create makes it.
-- Confirm it is absent, so the login is a true auto-create:
SELECT COUNT(*) AS preexisting_account
  FROM mysql.user WHERE user = 'you@example.com';   -- expect 0

SHOW GLOBAL VARIABLES LIKE 'vsql_oauth2.%';
```

> WARNING: do NOT read a dotted extension sysvar via
> ``SELECT @@global.`vsql_oauth2.issuer` `` — a backtick-quoted qualified
> extension variable name currently crashes the server. Use `SHOW GLOBAL
> VARIABLES LIKE 'vsql_oauth2.%'` to read, and bare dotted names to set.

## Step 3 — log in as the (not-yet-existing) Entra identity

Stock mysql client, token minted on the command line into the password slot
(`--enable-cleartext-plugin` lets the token travel verbatim). The minter is
cache-first: if a valid access/refresh token is cached in
`~/.vsql/oauth_cache.json` there is no browser prompt.

```bash
"$VillageSQL_BUILD_DIR"/runtime_output_directory/mysql \
  --host=127.0.0.1 --port=13000 \
  --enable-cleartext-plugin \
  --user='you@example.com' \
  --password="$(python3 /path/to/vsql-oauth2/tools/vsql_entra_login.py --print-token)" \
  -e "SELECT CURRENT_USER() AS who, @@external_user AS ext, CURRENT_ROLE() AS role"
```

**Success:**
- `who`  = `you@example.com@%` — the account that did not exist a moment ago
- `ext`  = `you@example.com` — the audit identity (`@@external_user`)
- `role` = `` `mysql-grp-trading`@`%` `` — the App Role, granted DURING
  provisioning and activated on the session

## Step 4 — verify the account was created by the login (as root)

```sql
-- Now exists, IDENTIFIED WITH the VEF method (NOT the default plugin):
SELECT user, host, plugin FROM mysql.user WHERE user = 'you@example.com';
--   you@example.com | % | vsql_oauth2

-- The mapped role was granted during provisioning:
SHOW GRANTS FOR 'you@example.com'@'%';
--   GRANT USAGE ON *.* TO `you@example.com`@`%`
--   GRANT `mysql-grp-trading`@`%` TO `you@example.com`@`%`
```

A second login as the same identity now takes the normal (already-exists) path,
no re-provisioning.

## Step 5 — reset for a clean re-run (as root)

Auto-create leaves persistent state. To re-run from a true auto-create:

```sql
DROP USER 'you@example.com'@'%';
-- (optional) DROP ROLE 'mysql-grp-trading';
-- (optional) UNINSTALL EXTENSION vsql_oauth2;
```

## Step 6 — shut down

```bash
"$VillageSQL_BUILD_DIR"/runtime_output_directory/mysqladmin \
  --socket="$VillageSQL_BUILD_DIR"/mysql-test/var/tmp/mysqld.1.sock -u root shutdown
```

---

## Troubleshooting

The extension logs reject reasons to the server error log:

```bash
grep -iE "vsql_oauth2|auto-create|provision|not granted" \
  "$VillageSQL_BUILD_DIR"/mysql-test/var/log/mysqld.1.err | tail -30
```

| Symptom | Cause / fix |
|---|---|
| `ERROR ... Access denied ... (using password: NO)` | account not routed to the method — check `auto_create = ON` and that the account really doesn't exist |
| Login OK but account has `plugin = caching_sha2_password` | old server binary — the PLUGIN_ATTR-preservation fix (2026-07-10) is required for the VEF plugin to persist |
| Login OK but `CURRENT_ROLE()` is NONE | the mapped role does not exist as a DB role (auto-create does NOT create roles — the DBA owns roles), or `roles_filter` didn't match the token's `roles` |
| `VEB file not found: vsql_oauth2.veb` | VEB not in the server's real `veb_dir` — read `SELECT @@veb_dir`, do not assume `datadir/extensions` |
| `token validation failed` / `no JWKS key matches kid` | `iss`/`aud`/`jwks_url` mismatch — same as the base runbook |

## Notes / current limitations

- **Roles are NOT auto-created** — only granted. Pre-create every role a token
  can map to; an unknown role name is skipped (logged), the account is still
  created and logs in with no role.
- **Not production-safe yet** (see the `TODO(villagesql-beta)` markers in the
  server's `request_provision`): the account name comes from the token and is
  interpolated into DDL without escaping (injection surface), and provisioning
  runs synchronous DDL from the login path — unsafe on a replica or
  `read_only`/`super_read_only` server, and unguarded against concurrent
  same-account logins. Do NOT enable `auto_create` in a replicated or read-only
  deployment until the off-thread provisioner (single-flight) lands.
- Token travels in the password slot as cleartext (gated by
  `--enable-cleartext-plugin`); use TLS in any real setting.
