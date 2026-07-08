# Client login tools

Helpers for logging into VillageSQL with an OAuth/OIDC identity via the
`vsql_oauth2` extension. The extension validates a JWT presented by the client;
these tools handle *obtaining* the token and handing it to `mysql`.

## Why these helpers exist (a stock provider CLI is NOT a drop-in token helper)

`vsql_oauth2` is provider-agnostic: it validates whatever signed JWT arrives and
maps its claims. A token comes from an external, swappable token helper
(`$VSQL_OAUTH_TOKEN_HELPER`) — see `../Docs/DESIGN_CLIENT_TOKEN_ACQUISITION.md`.

It is tempting to assume the stock provider CLI is that token helper
(`az account get-access-token`, `gcloud auth print-identity-token`). It is NOT,
by default: those authenticate as the CLI's OWN built-in client app, which is
not authorized to your DB app's API. Tested against Entra 2026-07-12,
`az account get-access-token --resource api://<db-app>` fails with
`AADSTS650057: Invalid resource`. Making it work needs an Entra admin change
(pre-authorize the Microsoft Azure CLI app to your DB API) -- broad and
undesirable.

So the DB-app token must be minted through a **dedicated client app** registered
against the DB API. That is what these helpers do -- and why they are the
PRIMARY login path, not a fallback:

- **`vsql`** -- branded interactive launcher (browser sign-in, then hands off to
  `mysql`). Everyday entry point.
- **`vsql_entra_login.py`** -- authenticates through the dedicated `villagesql-cli`
  Entra app (pre-authorized to the DB app's scope); cache-first refresh;
  `--print-claims` / `--print-token`.
- **`vsql_google_login.py`** -- authenticates through a dedicated GCP Desktop
  OAuth client (client_secret file). (Follow-up: consolidate the two into one
  `--provider` tool; see the design doc.)

A stock CLI is a viable token helper ONLY where its client app has been authorized to
the DB API (an explicit admin decision). All helpers use only the Python
standard library -- no `pip install`.

## One-time setup

1. **GCP Desktop OAuth client.** Create one at
   https://console.cloud.google.com/apis/credentials → Create credentials →
   OAuth client ID → Application type: **Desktop app**. Download the
   `client_secret_*.json`. Its client ID becomes the token's `aud` (configure
   `vsql_oauth2.audience` to match, server-side).

2. **Server configured for Google** (see the top-level README / `../Docs/MANUAL_TEST_GOOGLE.md`):
   `vsql_oauth2.issuer`, `.audience`, `.jwks_url`, `.username_claim = 'email'`,
   and an account `IDENTIFIED WITH vsql_oauth2` with a self `GRANT PROXY`.

3. **Environment for `vsql`** (set once, e.g. in your shell profile):

   ```bash
   export VSQL_CLIENT_SECRETS=~/client_secret_<...>.json   # the GCP JSON
   export VSQL_HOST=127.0.0.1
   export VSQL_PORT=3306
   # Point at the VillageSQL mysql client. Required if `mysql` is not on PATH
   # (e.g. a dev build): a bare `mysql` is looked up on PATH.
   export VSQL_MYSQL=~/build/villagesql/runtime_output_directory/mysql
   ```

   (Instead of `VSQL_CLIENT_SECRETS` you may set `VSQL_CLIENT_ID` +
   `VSQL_CLIENT_SECRET`.)

## Usage

```bash
vsql                                     # browser pop-up → interactive shell
vsql mydb                                # open a database
vsql -e "SELECT CURRENT_USER(), @@external_user"
vsql mydb < script.sql                   # run a script
```

Any arguments are forwarded verbatim to the `mysql` client. On success you are
authenticated as your Google identity: `CURRENT_USER()` is the mapped account,
`@@external_user` is your email.

## Using the helper directly

```bash
# Inspect the token's claims (no DB connect) — handy for configuring the server:
python3 vsql_google_login.py --client-secrets-file ~/client_secret_<...>.json \
  --print-claims

# Explicit flags instead of env / wrapper:
python3 vsql_google_login.py \
  --client-secrets-file ~/client_secret_<...>.json \
  --mysql ~/build/villagesql/runtime_output_directory/mysql \
  --mysql-host 127.0.0.1 --mysql-port 3306 \
  -- -e "SELECT CURRENT_USER()"          # args after `--` go to mysql
```

## How it works

1. Runs Google's OAuth 2.0 loopback flow in your browser (a local one-shot
   listener catches the redirect), exchanges the code for an OpenID `id_token`
   (a JWT).
2. `exec`s the `mysql` client with the token in **`MYSQL_PWD`** (not on the
   command line, so the ~900-char JWT never hits the process list or shell
   history), `--enable-cleartext-plugin`, and your resolved user.
3. The server-side extension reads the token, verifies it against Google's JWKS,
   and maps the `email` claim to the account.

## Notes and limitations

- **macOS file access:** if the client-secrets JSON lives in `~/Downloads`, the
  terminal (and thus python) may be denied read access by macOS privacy
  controls. Move the JSON out of `~/Downloads`, grant the terminal Full Disk
  Access, or pass `VSQL_CLIENT_ID` + `VSQL_CLIENT_SECRET` instead of the file.
- **`mysql` not on PATH:** set `VSQL_MYSQL` to the full path of the VillageSQL
  client (dev builds are not on PATH). The launcher reports this clearly rather
  than failing obscurely.
- **Token lifetime / caching:** id_tokens expire (~1 hour). The Entra helper
  (`vsql_entra_login.py`) has a three-tier cache (reuse -> silent refresh ->
  browser) at `~/.vsql/oauth_cache.json` (0600). The Google helper currently
  fetches fresh each run. The provider CLIs (`az`/`gcloud`) have their own caches.
- **Transport:** the token travels in the password slot in cleartext at the
  protocol level — use TLS to the server in any real setting.
- **Not the production client:** `vsql` is a dev/demo convenience. For
  applications, use a connector with your app's own OAuth library over
  `mysql_clear_password` (see the top-level README).
