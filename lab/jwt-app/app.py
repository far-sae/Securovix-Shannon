"""Deliberately vulnerable JWT target for broker e2e tests. Local lab only.

`/me` authorizes via an HS256 JWT signed with a WEAK, guessable secret, so an attacker
who guesses the secret can forge an admin token.
"""

import base64
import hashlib
import hmac
import json

from flask import Flask, jsonify, request

app = Flask(__name__)
SECRET = "secret"  # VULNERABLE BY DESIGN: weak, guessable HMAC secret


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_hs256(token: str) -> dict | None:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        if header.get("alg") != "HS256":
            return None
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
            return None
        return json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    claims = verify_hs256(token)
    if claims is None:
        return jsonify({"error": "invalid token"}), 401
    return jsonify({"user": claims.get("user"), "role": claims.get("role")})


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
