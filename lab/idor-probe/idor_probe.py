#!/usr/bin/env python3
"""In-house deterministic IDOR/BOLA prober (no GPL deps). Takes a target URL with the
marker INJECT in the object-id position, requests two distinct ids, and emits a
nuclei-style JSONL finding if both are accessible with distinct data and no auth.
"""

import json
import sys
import urllib.request


def fetch(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except Exception:
        return 0, ""


def main() -> int:
    if len(sys.argv) < 2 or "INJECT" not in sys.argv[1]:
        print("usage: idor-probe <url-with-INJECT-marker>", file=sys.stderr)
        return 2
    url_template = sys.argv[1]
    c1, b1 = fetch(url_template.replace("INJECT", "1"))
    c2, b2 = fetch(url_template.replace("INJECT", "99999"))
    if c1 == 200 and c2 == 200 and b1 != b2 and "secret" in b1 and "secret" in b2:
        finding = {
            "template-id": "idor-bola",
            "info": {"severity": "high", "name": "IDOR/BOLA: object references accessible without authorization"},
            "host": url_template,
            "matched-at": url_template.replace("INJECT", "99999"),
        }
        print(json.dumps(finding))
    return 0


if __name__ == "__main__":
    sys.exit(main())
