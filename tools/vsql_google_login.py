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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

"""Dev helper: log into VillageSQL with a Google identity via the vsql_oauth2
authentication extension.

Runs Google's OAuth 2.0 loopback flow in your browser (the same flow gcloud
uses), captures the returned OpenID Connect id_token (a JWT), and hands it to
the mysql client as the password. The vsql_oauth2 extension then validates that
token against Google's JWKS and logs you in.

This is a development / demo convenience tool, not the production client story
(that would be a proper MySQL client auth plugin). It uses only the Python
standard library -- no pip installs.

Prerequisites:
  * A Google Cloud "Desktop app" OAuth client. Create one at
    https://console.cloud.google.com/apis/credentials -> Create credentials ->
    OAuth client ID -> Application type: Desktop app. Note the client ID and
    client secret. (The client ID becomes the token's `aud`, which the extension
    checks -- configure vsql_oauth2.audience to match it.)
  * A running VillageSQL server with the vsql_oauth2 extension installed and
    configured for Google, e.g.:
        SET GLOBAL vsql_oauth2.issuer         = 'https://accounts.google.com';
        SET GLOBAL vsql_oauth2.audience       = '<your-client-id>';
        SET GLOBAL vsql_oauth2.jwks_url       = 'https://www.googleapis.com/oauth2/v3/certs';
        SET GLOBAL vsql_oauth2.username_claim = 'email';
        CREATE USER '<you@domain>'@'%' IDENTIFIED WITH vsql_oauth2;
        GRANT PROXY ON '<you@domain>'@'%' TO '<you@domain>'@'%';

Examples:
  # Print the id_token's claims and exit (handy for configuring the extension):
  vsql_google_login.py --client-id ID --client-secret SECRET --print-claims

  # Log into the database as your Google identity:
  vsql_google_login.py --client-id ID --client-secret SECRET \\
      --mysql-host 127.0.0.1 --mysql-port 3306
"""

import argparse
import base64
import http.server
import json
import os
import secrets
import shutil
import socket
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPES = "openid email profile"


def load_client_secrets_file(path):
    """Read client_id/client_secret from a Google client_secret_*.json file (the
    download from the GCP credentials page). Supports both the "installed"
    (Desktop) and "web" client shapes. Returns (client_id, client_secret)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"could not read client-secrets file {path}: {exc}")
    block = data.get("installed") or data.get("web")
    if not block:
        raise SystemExit(
            f"{path} is not a Google OAuth client file "
            "(expected an 'installed' or 'web' object)")
    client_id = block.get("client_id")
    client_secret = block.get("client_secret")
    if not client_id or not client_secret:
        raise SystemExit(f"{path} is missing client_id or client_secret")
    return client_id, client_secret


def _b64url_decode(segment):
    # JWT segments are base64url without padding; restore padding before decode.
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


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
    """Single-request handler that captures the ?code= from Google's redirect."""

    # Set by the server instance before serving.
    expected_state = None
    result = {}

    def do_GET(self):  # noqa: N802 (http.server API)
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        self.server.result = {
            "code": params.get("code", [None])[0],
            "state": params.get("state", [None])[0],
            "error": params.get("error", [None])[0],
        }
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        msg = ("Authentication complete. You can close this tab and return to "
               "the terminal.")
        self.wfile.write(f"<html><body><p>{msg}</p></body></html>".encode())

    def log_message(self, *_args):
        pass  # silence the default request logging


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def get_id_token(client_id, client_secret):
    """Run the loopback OAuth flow and return Google's id_token (a JWT)."""
    port = _free_port()
    redirect_uri = f"http://127.0.0.1:{port}"
    state = secrets.token_urlsafe(16)

    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    auth_url = GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(auth_params)

    server = http.server.HTTPServer(("127.0.0.1", port), _CodeCatcher)
    server.result = {}
    thread = threading.Thread(target=server.handle_request)
    thread.start()

    print(f"Opening browser for Google sign-in (listening on {redirect_uri}) ...",
          file=sys.stderr)
    if not webbrowser.open(auth_url):
        print("Could not open a browser automatically. Open this URL manually:\n"
              f"\n  {auth_url}\n", file=sys.stderr)

    thread.join()
    server.server_close()

    result = server.result
    if result.get("error"):
        raise SystemExit(f"Google returned an error: {result['error']}")
    if not result.get("code"):
        raise SystemExit("no authorization code received from Google")
    if result.get("state") != state:
        raise SystemExit("state mismatch (possible CSRF); aborting")

    # Exchange the authorization code for tokens.
    token_body = urllib.parse.urlencode({
        "code": result["code"],
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }).encode()
    req = urllib.request.Request(GOOGLE_TOKEN_URL, data=token_body)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            tokens = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise SystemExit(f"token exchange failed (HTTP {exc.code}): {detail}")

    id_token = tokens.get("id_token")
    if not id_token:
        raise SystemExit("response had no id_token; check that the 'openid' "
                         "scope was granted")
    return id_token


def main():
    parser = argparse.ArgumentParser(
        description="Log into VillageSQL with a Google identity via vsql_oauth2.")
    parser.add_argument("--client-secrets-file",
                        help="path to the Google client_secret_*.json downloaded "
                             "from the GCP credentials page (avoids passing the "
                             "id/secret on the command line). Overrides "
                             "--client-id/--client-secret if both are given.")
    parser.add_argument("--client-id",
                        help="GCP Desktop OAuth client ID (or use "
                             "--client-secrets-file)")
    parser.add_argument("--client-secret",
                        help="GCP Desktop OAuth client secret (or use "
                             "--client-secrets-file)")
    parser.add_argument("--print-claims", action="store_true",
                        help="print the id_token's claims and exit (no DB login)")
    parser.add_argument("--print-token", action="store_true",
                        help="print the raw id_token and exit (no DB login)")
    parser.add_argument("--mysql", default="mysql",
                        help="mysql client binary (default: mysql)")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", default="3306")
    parser.add_argument("--user",
                        help="DB user to connect as; defaults to the token's "
                             "email claim")
    # Everything after `--` is forwarded verbatim to the mysql client, so this
    # launcher works for an interactive shell (no extra args), for running a
    # script (`-- -e "..."` or `-- dbname < file.sql`), and for selecting a
    # database (`-- mydb`).
    parser.add_argument("mysql_args", nargs=argparse.REMAINDER,
                        help="args after `--` are passed through to mysql "
                             "(e.g. -- -e 'SELECT 1', or -- mydb)")
    args = parser.parse_args()

    # Resolve credentials: a secrets file takes precedence, else the explicit
    # flags. One of the two must be provided.
    if args.client_secrets_file:
        client_id, client_secret = load_client_secrets_file(
            args.client_secrets_file)
    elif args.client_id and args.client_secret:
        client_id, client_secret = args.client_id, args.client_secret
    else:
        raise SystemExit(
            "provide --client-secrets-file, or both --client-id and "
            "--client-secret")

    id_token = get_id_token(client_id, client_secret)
    claims = decode_jwt_claims(id_token)

    if args.print_token:
        print(id_token)
        return
    if args.print_claims:
        print(json.dumps(claims, indent=2, sort_keys=True))
        print("\nConfigure the extension with:", file=sys.stderr)
        print(f"  vsql_oauth2.issuer   = {claims.get('iss')!r}", file=sys.stderr)
        print(f"  vsql_oauth2.audience = {claims.get('aud')!r}", file=sys.stderr)
        print(f"  username_claim 'email' -> {claims.get('email')!r}",
              file=sys.stderr)
        return

    user = args.user or claims.get("email")
    if not user:
        raise SystemExit("token has no email claim and --user was not given")

    # Resolve the mysql binary up front so a missing client fails with a clear
    # message rather than a confusing execvpe PATH-search error (which can point
    # at an unrelated directory). A path containing a separator is used as-is;
    # a bare name is looked up on PATH.
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
    # The token goes in the password slot; mysql_clear_password sends it
    # verbatim, so --enable-cleartext-plugin is required. Pass the token via
    # MYSQL_PWD in the environment rather than --password= on the command line,
    # so the ~900-char JWT never appears in the process list or shell history.
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
    env = dict(os.environ, MYSQL_PWD=id_token)
    # exec (replace this process) so the mysql client owns the TTY directly and
    # signals / exit code / interactive behavior are identical to running mysql.
    os.execvpe(mysql_bin, cmd, env)


if __name__ == "__main__":
    main()
