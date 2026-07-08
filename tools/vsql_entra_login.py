#!/usr/bin/env python3
# Copyright (c) 2026 VillageSQL Contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License, version 2.0, for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

"""Dev helper: log into VillageSQL with an Azure Entra ID identity via the
vsql_oauth2 extension. The Entra sibling of vsql_google_login.py.

Runs Entra's OAuth 2.0 authorization-code + PKCE loopback flow in the browser,
obtains an Entra-signed JWT, and passes it to the mysql client in the password
slot (mysql_clear_password). The server verifies it against Entra's JWKS.

Why an ACCESS token, not the id_token: Entra emits **App Roles** in the `roles`
claim of the ACCESS token audienced to the API app (the DB), and role names are
readable strings you can filter/transform (`mysql-grp-*`). The id_token's
`groups` claim is object-id GUIDs (plus a >200 overage indirection), which the
regex mapping can't use. So this tool requests a token for the DB app's scope
and forwards that -- configure `vsql_oauth2.audience` to the DB app's client id
(or api://<app-id-uri>) and validate the access token.

Prerequisites:
  * An Entra app registration for the DB (the "API" app) that DEFINES App Roles
    (Azure portal -> App registrations -> your API app -> App roles), with those
    roles ASSIGNED to users/groups (Enterprise applications -> Users and groups).
    Emit v2 tokens (Manifest: requestedAccessTokenVersion = 2).
  * A public client (Desktop/native, "Allow public client flows" = yes) the user
    signs in through; it needs delegated permission to the API app's scope.
  * The extension configured for Entra, e.g.:
        SET GLOBAL vsql_oauth2.issuer   = 'https://login.microsoftonline.com/<tenant-guid>/v2.0';
        SET GLOBAL vsql_oauth2.jwks_url = 'https://login.microsoftonline.com/<tenant-guid>/discovery/v2.0/keys';
        SET GLOBAL vsql_oauth2.audience = '<api-app-client-id>';
        SET GLOBAL vsql_oauth2.username_claim = 'preferred_username';
        SET GLOBAL vsql_oauth2.roles_claim = 'roles';
        SET GLOBAL vsql_oauth2.roles_filter = 'mysql-grp-.*';
        SET GLOBAL vsql_oauth2.roles_transform_pattern = '-';
        SET GLOBAL vsql_oauth2.roles_transform_replacement = '_';

Usage:
  # Inspect the token's claims (esp. `roles`) and exit -- do this FIRST to
  # confirm App Roles are present before wiring the DB:
  vsql_entra_login.py --tenant <guid> --client-id <public-client-id> \\
      --scope 'api://<api-app-id>/.default' --print-claims

  # Log into the database as your Entra identity:
  vsql_entra_login.py --tenant <guid> --client-id <public-client-id> \\
      --scope 'api://<api-app-id>/.default' \\
      --mysql <client> --mysql-host 127.0.0.1 --mysql-port 13000
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import secrets
import shutil
import socket
import stat
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser

# Where the token cache lives. Holds the (sensitive) refresh token, so the file
# is created 0600 and refused if it is group/world-readable.
CACHE_PATH = os.path.expanduser("~/.vsql/oauth_cache.json")
# Default OIDC client config (tenant/client_id/scope), so those GUIDs need not
# be typed on every login. Overridable via --config or $VSQL_OAUTH_CONFIG.
DEFAULT_CONFIG_PATH = os.path.expanduser("~/.vsql/entra.json")
# Refresh a little BEFORE the access token actually expires, so a token handed
# to a client can't die mid-handshake.
EXP_SKEW_SECONDS = 60


def _b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_no_pad(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_jwt_claims(token):
    """Return the JWT payload (claims) as a dict, without verifying the
    signature -- this tool only inspects/forwards the token; the server
    verifies it."""
    try:
        payload = token.split(".")[1]
        return json.loads(_b64url_decode(payload))
    except (IndexError, ValueError) as exc:
        raise SystemExit(f"could not decode token payload: {exc}")


class _CodeCatcher(http.server.BaseHTTPRequestHandler):
    """Single-request handler that captures the ?code= from Entra's redirect."""

    def do_GET(self):  # noqa: N802 (http.server API)
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        self.server.result = {
            "code": params.get("code", [None])[0],
            "state": params.get("state", [None])[0],
            "error": params.get("error_description", params.get("error", [None]))[0],
        }
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        msg = ("Authentication complete. You can close this tab and return to "
               "the terminal.")
        self.wfile.write(f"<html><body><p>{msg}</p></body></html>".encode())

    def log_message(self, *_args):
        pass


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def get_token(tenant, client_id, scope, client_secret=None):
    """Run the loopback auth-code + PKCE flow and return Entra's access token
    (a JWT). openid scopes are added so an id_token comes too, but the access
    token is what carries the App Roles for the API app."""
    authority = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
    auth_url_base = authority + "/authorize"
    token_url = authority + "/token"
    # openid/profile so the token has identity claims; the API scope so the
    # access token is audienced to the DB app and carries its App Roles.
    scopes = f"openid profile offline_access {scope}"

    port = _free_port()
    redirect_uri = f"http://localhost:{port}"
    state = secrets.token_urlsafe(16)
    verifier = _b64url_no_pad(secrets.token_bytes(32))
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode()).digest())

    auth_params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    auth_url = auth_url_base + "?" + urllib.parse.urlencode(auth_params)

    server = http.server.HTTPServer(("127.0.0.1", port), _CodeCatcher)
    server.result = {}
    thread = threading.Thread(target=server.handle_request)
    thread.start()

    print(f"Opening browser for Entra sign-in (listening on {redirect_uri}) ...",
          file=sys.stderr)
    if not webbrowser.open(auth_url):
        print("Could not open a browser automatically. Open this URL manually:\n"
              f"\n  {auth_url}\n", file=sys.stderr)

    thread.join()
    server.server_close()

    result = server.result
    if result.get("error"):
        raise SystemExit(f"Entra returned an error: {result['error']}")
    if not result.get("code"):
        raise SystemExit("no authorization code received from Entra")
    if result.get("state") != state:
        raise SystemExit("state mismatch (possible CSRF); aborting")

    token_fields = {
        "code": result["code"],
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "scope": scopes,
        "code_verifier": verifier,
    }
    # Confidential clients pass a secret; public (Desktop) clients rely on PKCE.
    if client_secret:
        token_fields["client_secret"] = client_secret

    req = urllib.request.Request(token_url, data=urllib.parse.urlencode(
        token_fields).encode())
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            tokens = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise SystemExit(f"token exchange failed (HTTP {exc.code}): {detail}")

    if not tokens.get("access_token"):
        raise SystemExit("response had no access_token")
    return tokens


# --- token cache (three-tier: reuse -> silent refresh -> browser) ---------

def _cache_key(tenant, client_id, scope):
    return hashlib.sha256(f"{tenant}|{client_id}|{scope}".encode()).hexdigest()


def _access_token_valid(access_token):
    """True if the JWT's exp is far enough in the future to hand out safely."""
    try:
        claims = decode_jwt_claims(access_token)
        return int(claims.get("exp", 0)) - int(time.time()) > EXP_SKEW_SECONDS
    except SystemExit:
        return False


def _load_cache_entry(key):
    """Return the cached token dict for `key`, or None. Refuses a cache file
    with loose (group/world) permissions -- it holds the refresh token."""
    try:
        st = os.stat(CACHE_PATH)
    except OSError:
        return None
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(f"WARNING: {CACHE_PATH} is group/world-accessible; ignoring it. "
              f"Fix with: chmod 600 {CACHE_PATH}", file=sys.stderr)
        return None
    try:
        with open(CACHE_PATH, encoding="utf-8") as fh:
            return json.load(fh).get(key)
    except (OSError, ValueError):
        return None


def _store_cache_entry(key, tokens):
    """Merge `tokens` under `key` into the 0600 cache. Preserves an existing
    refresh token if the response did not return a new one."""
    os.makedirs(os.path.dirname(CACHE_PATH), mode=0o700, exist_ok=True)
    data = {}
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            data = {}
    prior = data.get(key, {})
    entry = {"access_token": tokens.get("access_token"),
             "refresh_token": tokens.get("refresh_token")
             or prior.get("refresh_token")}
    data[key] = entry
    # Write via a 0600 temp file then rename, so the file is never briefly
    # world-readable and the swap is atomic.
    fd = os.open(CACHE_PATH + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(CACHE_PATH + ".tmp", CACHE_PATH)


def _refresh(tenant, client_id, scope, refresh_token, client_secret=None):
    """Exchange a refresh token for a new access token. Returns the token dict,
    or None if the refresh token is expired/revoked (caller falls back to
    browser)."""
    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    fields = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": f"openid profile offline_access {scope}",
    }
    if client_secret:
        fields["client_secret"] = client_secret
    req = urllib.request.Request(token_url,
                                 data=urllib.parse.urlencode(fields).encode())
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError:
        return None  # refresh token expired/revoked -> re-auth in the browser


def acquire_token(tenant, client_id, scope, client_secret=None):
    """Return a valid access token dict, cache-first:
      1. reuse the cached access token if still valid (no network, no browser);
      2. else silently refresh from the cached refresh token (network, no
         browser);
      3. else run the full browser flow.
    The result (access + refresh tokens) is cached for next time."""
    key = _cache_key(tenant, client_id, scope)
    entry = _load_cache_entry(key)

    if entry and entry.get("access_token") \
            and _access_token_valid(entry["access_token"]):
        return entry  # tier 1: reuse

    if entry and entry.get("refresh_token"):
        refreshed = _refresh(tenant, client_id, scope, entry["refresh_token"],
                             client_secret)
        if refreshed and refreshed.get("access_token"):
            _store_cache_entry(key, refreshed)  # tier 2: silent refresh
            return refreshed

    tokens = get_token(tenant, client_id, scope, client_secret)  # tier 3
    _store_cache_entry(key, tokens)
    return tokens


def _load_config(explicit_path):
    """Load OIDC client config (tenant/client_id/scope/client_secret) from JSON.
    Path precedence: --config > $VSQL_OAUTH_CONFIG > ~/.vsql/entra.json.
    Returns {} when no file is present (flags-only use still works). An
    explicitly-named file that is missing or malformed is an error."""
    path = explicit_path or os.environ.get("VSQL_OAUTH_CONFIG") \
        or DEFAULT_CONFIG_PATH
    if not os.path.exists(path):
        # Silent only for the default path; a path the user named must exist.
        if explicit_path or os.environ.get("VSQL_OAUTH_CONFIG"):
            raise SystemExit(f"config file not found: {path}")
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"could not read config {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"config {path} must be a JSON object")
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Log into VillageSQL with an Entra identity via vsql_oauth2.")
    # tenant / client-id / scope may come from a config file instead of flags
    # (so the GUIDs need not be typed every login). Precedence: command-line
    # flag > config file > env. Not `required` here; checked after loading.
    parser.add_argument("--config",
                        help="path to a JSON config with tenant/client_id/scope "
                             "(and optional client_secret). Default: "
                             "$VSQL_OAUTH_CONFIG, else ~/.vsql/entra.json.")
    parser.add_argument("--tenant",
                        help="Entra tenant GUID (or 'organizations')")
    parser.add_argument("--client-id",
                        help="public (Desktop/native) client app id the user "
                             "signs in through")
    parser.add_argument("--client-secret",
                        help="only for a confidential client; omit for a public "
                             "client (PKCE)")
    parser.add_argument("--scope",
                        help="API app scope, e.g. 'api://<api-app-id>/.default' "
                             "-- makes the access token audienced to the DB app "
                             "so its App Roles land in the `roles` claim")
    parser.add_argument("--print-claims", action="store_true",
                        help="print the token's claims (incl. `roles`) and exit")
    parser.add_argument("--print-token", action="store_true",
                        help="print a valid access token and exit (no DB login). "
                             "Reuses the cached token if still valid, silently "
                             "refreshes it if not, and only opens a browser when "
                             "there is no usable cache. Ideal for "
                             "mysql -p\"$(... --print-token)\".")
    parser.add_argument("--mysql", default=os.environ.get("VSQL_MYSQL", "mysql"))
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", default="3306")
    parser.add_argument("--user",
                        help="DB user to connect as; defaults to the token's "
                             "preferred_username (else upn/email)")
    parser.add_argument("mysql_args", nargs=argparse.REMAINDER,
                        help="args after `--` are passed through to mysql")
    args = parser.parse_args()

    # Fill tenant/client-id/scope/client-secret from a config file when not
    # given as flags, so the common case is a GUID-free command line.
    cfg = _load_config(args.config)
    tenant = args.tenant or cfg.get("tenant")
    client_id = args.client_id or cfg.get("client_id")
    scope = args.scope or cfg.get("scope")
    client_secret = args.client_secret or cfg.get("client_secret")

    missing = [n for n, v in (("tenant", tenant), ("client-id", client_id),
                              ("scope", scope)) if not v]
    if missing:
        raise SystemExit(
            "missing required setting(s): " + ", ".join(missing) +
            f".\nProvide via flags, or a config file (default "
            f"{DEFAULT_CONFIG_PATH}) with keys tenant/client_id/scope. "
            f"Example:\n"
            f'  {{"tenant": "<guid>", "client_id": "<guid>", '
            f'"scope": "api://<db-app-id>/.default"}}')

    tokens = acquire_token(tenant, client_id, scope, client_secret)
    token = tokens["access_token"]
    claims = decode_jwt_claims(token)

    if args.print_token:
        print(token)
        return
    if args.print_claims:
        print(json.dumps(claims, indent=2, sort_keys=True))
        print("\nConfigure the extension with:", file=sys.stderr)
        print(f"  vsql_oauth2.issuer   = {claims.get('iss')!r}", file=sys.stderr)
        print(f"  vsql_oauth2.audience = {claims.get('aud')!r}", file=sys.stderr)
        roles = claims.get("roles")
        print(f"  roles claim          = {roles!r}", file=sys.stderr)
        if not roles:
            print("  WARNING: no `roles` claim -- assign App Roles to this user "
                  "and confirm requestedAccessTokenVersion=2.", file=sys.stderr)
        return

    user = (args.user or claims.get("preferred_username")
            or claims.get("upn") or claims.get("email"))
    if not user:
        raise SystemExit("token has no preferred_username/upn/email and --user "
                         "was not given")

    mysql_bin = args.mysql
    if os.sep in mysql_bin:
        mysql_bin = os.path.abspath(os.path.expanduser(mysql_bin))
        if not os.access(mysql_bin, os.X_OK):
            raise SystemExit(f"mysql client not found or not executable: "
                             f"{mysql_bin}")
    elif shutil.which(mysql_bin) is None:
        raise SystemExit(
            f"mysql client '{mysql_bin}' not found on PATH. Set --mysql (or the "
            f"VSQL_MYSQL env var) to the full path of the VillageSQL mysql "
            f"client.")

    print(f"Connecting to VillageSQL as {user} ...", file=sys.stderr)
    mysql_args = args.mysql_args
    if mysql_args and mysql_args[0] == "--":
        mysql_args = mysql_args[1:]
    cmd = [
        mysql_bin,
        "--enable-cleartext-plugin",
        f"--host={args.mysql_host}",
        f"--port={args.mysql_port}",
        f"--user={user}",
    ] + mysql_args
    env = dict(os.environ, MYSQL_PWD=token)
    os.execvpe(mysql_bin, cmd, env)


if __name__ == "__main__":
    main()
