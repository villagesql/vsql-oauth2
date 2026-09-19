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

# Regenerates the pre-signed JWT fixtures used by the vsql-oauth2 MTR suite.
#
# WHY THIS EXISTS: the tests present real, signed JWTs so the extension verifies
# them for real, with no runtime crypto in the suite. That means the tokens are
# opaque blobs that can only be re-signed if the private keys are kept -- so we
# keep them here (keys/*.pem) and mint the tokens from them with this script.
#
# WHY A CAPPED exp: jwt-cpp's exp check builds a std::chrono::system_clock
# time_point from the token's exp; converting `exp` seconds to the clock's
# nanosecond period computes `exp * 1e9`. An exp like 9999999999 (year 2286)
# overflows int64 (9.9e18 > 9.2e18). It's benign in normal builds, but under
# -fsanitize=undefined (the server's ASan+UBSan CI, which builds bundled
# extensions with the same flags) it aborts the server mid-handshake and every
# valid-token login test fails with "Lost connection". So "far future" tokens
# use EXP_FAR = 4102444800 (2100-01-01): far enough to never expire in a test,
# small enough that exp*1e9 (4.1e18) stays within int64.
#
# USAGE:
#   pip install pyjwt cryptography
#   python3 gen_tokens.py           # reuse keys/*.pem if present, else create them
#   python3 gen_tokens.py --new-keys  # force fresh keypairs (rotates every token)
#
# It reads/writes keys/*.pem next to this script and rewrites the suite include
# mysql-test/t/oauth_fixtures.inc with the public keys + signed tokens. After
# running, re-record the .result files: `RECORD=1 ./test.sh`.

import argparse
import os

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(HERE, "keys")
# mysql-test/std_data/oauth/gen_tokens.py -> mysql-test/t/oauth_fixtures.inc
INC_PATH = os.path.normpath(
    os.path.join(HERE, "..", "..", "t", "oauth_fixtures.inc")
)

ISS = "https://idp.example"
EXP_FAR = 4102444800  # 2100-01-01T00:00:00Z; exp*1e9 stays within int64 (see above)
EXP_PAST = 1000000000  # 2001-09-09; already expired, well within int64

# Each entry is a distinct keypair + the tokens signed by it. `kind` selects the
# key type; `alg` the JWS algorithm. `tokens` maps a fixture var name to its
# claim set (exp is added per-token). The public key of each keypair is emitted
# as $<name>_pubkey. Keeping the keypairs distinct per test group mirrors the
# original fixtures (each test switched public_key to its own key).
GROUPS = [
    {
        "name": "basic",
        "kind": "rsa",
        "alg": "RS256",
        "tokens": {
            "basic_valid": {"exp": EXP_FAR, "claims": {"sub": "oauth_mapped_user", "iss": ISS}},
            "basic_expired": {"exp": EXP_PAST, "claims": {"sub": "oauth_mapped_user", "iss": ISS}},
        },
    },
    {
        "name": "autocreate",
        "kind": "rsa",
        "alg": "RS256",
        "tokens": {
            "autocreate_valid": {"exp": EXP_FAR, "claims": {"sub": "oidc_autocreated", "iss": ISS}},
        },
    },
    {
        "name": "autogrant",
        "kind": "rsa",
        "alg": "RS256",
        "tokens": {
            "autogrant_dba": {"exp": EXP_FAR, "claims": {"email": "alice@myco.example", "iss": ISS, "groups": ["app-grp-dba"]}},
            "autogrant_dba_ana": {"exp": EXP_FAR, "claims": {"email": "alice@myco.example", "iss": ISS, "groups": ["app-grp-dba", "app-grp-analyst"]}},
            "autogrant_ana": {"exp": EXP_FAR, "claims": {"email": "alice@myco.example", "iss": ISS, "groups": ["app-grp-analyst"]}},
        },
    },
    {
        "name": "existing",
        "kind": "rsa",
        "alg": "RS256",
        "tokens": {
            "existing_dba": {"exp": EXP_FAR, "claims": {"email": "bob@myco.example", "iss": ISS, "groups": ["app-grp-dba"]}},
        },
    },
    {
        "name": "es384",
        "kind": "ec",
        "curve": ec.SECP384R1(),
        "alg": "ES384",
        "tokens": {
            "es384_valid": {"exp": EXP_FAR, "claims": {"sub": "oauth_mapped_user", "iss": ISS}},
            "es384_expired": {"exp": EXP_PAST, "claims": {"sub": "oauth_mapped_user", "iss": ISS}},
        },
    },
    {
        "name": "es512",
        "kind": "ec",
        "curve": ec.SECP521R1(),
        "alg": "ES512",
        "tokens": {
            "es512_valid": {"exp": EXP_FAR, "claims": {"sub": "oauth_mapped_user", "iss": ISS}},
            "es512_expired": {"exp": EXP_PAST, "claims": {"sub": "oauth_mapped_user", "iss": ISS}},
        },
    },
]


def load_or_make_key(group, new_keys):
    """Return (private_pem_bytes, public_pem_str) for a group, reusing the
    committed keys/<name>.pem unless it is missing or --new-keys was passed."""
    path = os.path.join(KEYS_DIR, group["name"] + ".pem")
    if os.path.exists(path) and not new_keys:
        with open(path, "rb") as f:
            priv_pem = f.read()
        priv = serialization.load_pem_private_key(priv_pem, password=None)
    else:
        if group["kind"] == "rsa":
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            priv = ec.generate_private_key(group["curve"])
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        os.makedirs(KEYS_DIR, exist_ok=True)
        with open(path, "wb") as f:
            f.write(priv_pem)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


def mtr_escape_pem(pem):
    """MTR --let carries the PEM as a single line with literal \\n escapes."""
    return pem.replace("\n", "\\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new-keys", action="store_true",
                    help="generate fresh keypairs (rotates every token)")
    args = ap.parse_args()

    lines = [
        "# GENERATED by mysql-test/std_data/oauth/gen_tokens.py -- do not edit by hand.",
        "# Re-run that script to change claims/exp/keys, then RECORD=1 ./test.sh.",
        "#",
        "# Fixed keypairs + pre-signed JWTs for the vsql-oauth2 suite. 'valid'/'*_dba'",
        "# tokens use a capped far-future exp (2100) so exp*1e9 stays within int64 under",
        "# the server's ASan+UBSan build; 'expired' tokens are in the past. iss=" + ISS + ".",
        "",
    ]

    for group in GROUPS:
        priv_pem, pub_pem = load_or_make_key(group, args.new_keys)
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        lines.append("# --- %s (%s) ---" % (group["name"], group["alg"]))
        lines.append("--let $%s_pubkey= %s" % (group["name"], mtr_escape_pem(pub_pem)))
        for var, spec in group["tokens"].items():
            payload = dict(spec["claims"])
            payload["exp"] = spec["exp"]
            token = jwt.encode(payload, priv, algorithm=group["alg"])
            lines.append("--let $%s= %s" % (var, token))
        lines.append("")

    with open(INC_PATH, "w") as f:
        f.write("\n".join(lines))
    print("wrote", INC_PATH)


if __name__ == "__main__":
    main()
