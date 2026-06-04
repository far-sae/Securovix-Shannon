#!/usr/bin/env python3
"""Minimal, deterministic SSTI prober — an in-house tool (no GPL deps) the broker can
run in its sandbox. Takes a target URL containing the marker `INJECT`, substitutes
arithmetic-oracle payloads, and emits a nuclei-style JSONL finding if the product is
reflected (i.e. the template engine evaluated the payload). Proof-only: no RCE.
"""

import json
import sys
import urllib.parse
import urllib.request

# (payload, expected reflected product) — distinct factors avoid coincidental matches.
ORACLES = [("{{13*17}}", "221"), ("${13*17}", "221"), ("#{13*17}", "221")]


def main() -> int:
    if len(sys.argv) < 2 or "INJECT" not in sys.argv[1]:
        print("usage: ssti-probe <url-with-INJECT-marker>", file=sys.stderr)
        return 2
    url_template = sys.argv[1]
    for payload, expected in ORACLES:
        target = url_template.replace("INJECT", urllib.parse.quote(payload))
        try:
            with urllib.request.urlopen(target, timeout=5) as resp:
                body = resp.read().decode("utf-8", "replace")
        except Exception:
            continue
        # Confirmed only if the product appears AND the raw payload was NOT echoed back.
        if expected in body and payload not in body:
            finding = {
                "template-id": "ssti-arithmetic-oracle",
                "info": {"severity": "critical", "name": f"SSTI: {payload} evaluated to {expected}"},
                "host": url_template,
                "matched-at": target,
            }
            print(json.dumps(finding))
            return 0
    return 0  # no finding; not an error


if __name__ == "__main__":
    sys.exit(main())
