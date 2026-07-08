# Manual test: vsql_oauth2 extension against real Azure Entra ID SSO

A reproducible procedure to verify the `vsql_oauth2` **extension** end to end
against a **real Entra ID (Azure AD) tenant** — browser SSO, an Entra-signed JWT,
live JWKS verification, login as the mapped account, **and token-driven role
activation** (an Entra App Role -> an active MySQL role via `set_active_roles`).

This is the Entra sibling of `MANUAL_TEST_GOOGLE.md`. The crucial thing it adds
that Google could NOT test: Google tokens carry **no** role/group claim, so the
role path was never exercised against a real IdP. Entra App Roles are emitted in
the `roles` claim as readable strings (e.g. `mysql-grp-trading`) — exactly what
`roles_filter` matches — so this validates the whole role-mapping story.

This is a **manual** test by nature (a human browser sign-in + a tenant); it
cannot run in CI. Automated coverage is `oauth_basic` (auth) + `auth_roles`
(server-side role activation with a fake auth extension).

---

## Entra setup (one-time, in the Entra admin center / Azure portal)

Two app registrations plus a role assignment. See the walkthrough that produced
the values below; the shape is:

1. **API app** (represents the DB), e.g. `villagesql-db`:
   - App registration -> note its **Application (client) ID** (-> `audience`).
   - **Expose an API** -> set Application ID URI `api://<db-app-id>` and add a
     scope (e.g. `access`), **Who can consent: Admins and users**.
   - **App roles** -> create a role with **Value = `mysql-grp-trading`** (this
     exact string lands in the token's `roles` claim), member types Users/Groups.
   - **Manifest** -> `requestedAccessTokenVersion: 2` (new apps default to 2).
2. **Public client app** (what the user signs in through), e.g. `villagesql-cli`:
   - **Authentication** -> add a Mobile/desktop platform with redirect
     `http://localhost`, and set **Allow public client flows = Yes**.
   - **API permissions** -> add a delegated permission to the API app's scope
     (find it under "APIs my organization uses" if "My APIs" is empty).
   - Note its **Application (client) ID** and the **Directory (tenant) ID**.
3. **Assign your user to the App Role**: Enterprise applications ->
   `villagesql-db` -> Users and groups -> Add user -> pick yourself -> role
   `mysql-grp-trading` -> Assign. WITHOUT this the `roles` claim is empty.
   (Group assignment needs AD P1/P2; individual-user assignment works on any
   plan — the "groups not available" notice is expected and harmless.)

**Verified working 2026-07-09** (against a real tenant + assigned identity):
`--print-claims` returned
`"roles": ["mysql-grp-trading"]` in a v2 access token audienced to the DB app.

The IDs from that run (substitute your own):

| | Value |
|---|---|
| Tenant (Directory) ID | `<tenant-id>` |
| CLI app (client) ID | `<cli-app-id>` |
| DB app (client) ID / `audience` | `<db-app-id>` |
| Scope (for `--scope`) | `api://<db-app-id>/.default` |

---

## Step 0 — inspect the token first (no DB needed)

Confirm Entra emits the role before wiring anything:

```bash
cd /path/to/vsql-oauth2
python3 tools/vsql_entra_login.py \
  --tenant    <tenant-id> \
  --client-id <cli-app-id> \
  --scope     'api://<db-app-id>/.default' \
  --print-claims
```

Look for: `iss` ends `/v2.0`, `aud` = the DB app id, and
**`roles`: `["mysql-grp-trading"]`**. The helper warns if `roles` is empty
(assign the App Role and wait ~1-2 min for propagation).

## Step 1 — start a dev server with the VEB staged

**Server requirement:** needs a villagesql-server build with the VEF auth
capability (the `vsql::preview::auth` seam). As of 2026-07-10 that is branch
`tomas/vsql-auth-capability-2`; a plain `main` build does not have it. (Role
activation via `set_active_roles` is part of that same branch.)

```bash
export VillageSQL_BUILD_DIR=$HOME/githome/villagesql-server/build-debug
VEBDIR=/tmp/vsql-oauth2-entra-veb
mkdir -p "$VEBDIR"
cp /path/to/vsql-oauth2/build/vsql_oauth2.veb "$VEBDIR/"

cd "$VillageSQL_BUILD_DIR"
./mysql-test/mysql-test-run.pl --start-and-exit --nowarnings \
  --mysqld=--veb-dir="$VEBDIR" \
  --suite=/path/to/vsql-oauth2/mysql-test oauth_basic
```

Prints the port (**13000**) and the root socket under
`mysql-test/var/tmp/mysqld.1.sock`.

## Step 2 — configure the extension for Entra (as root)

```bash
$VillageSQL_BUILD_DIR/runtime_output_directory/mysql \
  --socket=$VillageSQL_BUILD_DIR/mysql-test/var/tmp/mysqld.1.sock -u root
```

```sql
INSTALL EXTENSION vsql_oauth2;

-- Entra v2 endpoints for this tenant:
SET GLOBAL vsql_oauth2.issuer   = 'https://login.microsoftonline.com/<tenant-id>/v2.0';
SET GLOBAL vsql_oauth2.jwks_url = 'https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys';
SET GLOBAL vsql_oauth2.audience = '<db-app-id>';
SET GLOBAL vsql_oauth2.username_claim = 'preferred_username';

-- Role mapping: the `roles` claim carries App Role values like
-- 'mysql-grp-trading'; keep only mysql-grp-* and (here) use them verbatim.
SET GLOBAL vsql_oauth2.roles_claim  = 'roles';
SET GLOBAL vsql_oauth2.roles_filter = 'mysql-grp-.*';
-- (optional) rename mysql-grp-trading -> trading with a transform:
--   SET GLOBAL vsql_oauth2.roles_transform_pattern     = 'mysql-grp-(.*)';
--   SET GLOBAL vsql_oauth2.roles_transform_replacement = '$1';

-- Confirm (use SHOW, never SELECT @@global.`...` -- see WARNING):
SHOW GLOBAL VARIABLES LIKE 'vsql_oauth2.%';

-- The account (maps to preferred_username), self-proxy, and the role the token
-- will request. The DBA owns roles + grants; the token only activates a granted
-- role. The role name here must match the mapped value (verbatim -> hyphenated
-- role name, so quote it).
CREATE USER 'you@example.com'@'%' IDENTIFIED WITH vsql_oauth2;
GRANT PROXY ON 'you@example.com'@'%' TO 'you@example.com'@'%';
CREATE ROLE 'mysql-grp-trading';
GRANT SELECT ON *.* TO 'mysql-grp-trading';
GRANT 'mysql-grp-trading' TO 'you@example.com'@'%';
```

> WARNING: do NOT read a dotted extension sysvar via
> ``SELECT @@global.`vsql_oauth2.issuer` `` — a backtick-quoted qualified
> extension variable name currently crashes the server (assertion in
> `set_var.cc`; known server bug). Use `SHOW GLOBAL VARIABLES LIKE
> 'vsql_oauth2.%'` to read, and bare dotted names to set.

## Step 3 — log in as your Entra identity and check the role

```bash
python3 tools/vsql_entra_login.py \
  --tenant    <tenant-id> \
  --client-id <cli-app-id> \
  --scope     'api://<db-app-id>/.default' \
  --mysql     "$VillageSQL_BUILD_DIR/runtime_output_directory/mysql" \
  --mysql-host 127.0.0.1 --mysql-port 13000 \
  -- -e "SELECT CURRENT_USER(), @@external_user, CURRENT_ROLE()"
```

Browser opens -> sign in -> the helper connects and runs the query.

**Success:**
- `CURRENT_USER()` = `you@example.com@%` (the mapped account)
- `@@external_user` = `you@example.com` (audit identity)
- **`CURRENT_ROLE()` = `` `mysql-grp-trading`@`%` ``** — the Entra App Role became
  the active session role. This is the piece Google could not prove.

To confirm the **no-escalation** guarantee: assign yourself a *second* App Role
in Entra (e.g. `mysql-grp-ops`) but do NOT `GRANT` it in the DB, re-login, and
verify `CURRENT_ROLE()` still shows only `mysql-grp-trading` (the ungranted one
is skipped; the server logs "role ... is not granted; skipping").

## Step 4 — shut down

```bash
$VillageSQL_BUILD_DIR/runtime_output_directory/mysqladmin \
  --socket=$VillageSQL_BUILD_DIR/mysql-test/var/tmp/mysqld.1.sock -u root shutdown
```

---

## Troubleshooting

The extension logs reject reasons to the server error log:

```bash
grep vsql_oauth2 $VillageSQL_BUILD_DIR/mysql-test/var/log/mysqld.1.err | tail -30
```

| Symptom | Cause / fix |
|---|---|
| `--print-claims` shows no `roles` | App Role not assigned, or not propagated (wait 1-2 min); or signed in as an unassigned identity |
| `AADSTS650057 Invalid resource` | CLI app lacks API permission to the DB app — add it (My APIs / "APIs my organization uses") |
| `AADSTS700016 Application not found` | wrong client id / tenant on the command line |
| `token validation failed` | `iss`/`aud` mismatch — set `audience` to the DB app id, `issuer` to `.../v2.0` |
| `no JWKS key matches token kid` | `jwks_url` wrong/unreachable |
| login OK but `CURRENT_ROLE()` is NONE | DB role not created or not granted to the account, or `roles_filter` didn't match — check `roles_claim`/`roles_filter` vs the token's `roles` |
| `ERROR 1045 ... missing proxy privilege` | the self `GRANT PROXY` is missing |

## Notes

- Entra uses **App Roles** (`roles` claim, readable strings), NOT `groups`
  (object-id GUIDs + a >200 overage indirection). Always map on App Roles.
- Token travels in the password slot as cleartext (gated by
  `--enable-cleartext-plugin`); use TLS in any real setting.
- No auto-create: the DB account must pre-exist with the self proxy grant.
