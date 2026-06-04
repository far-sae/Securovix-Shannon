#!/usr/bin/env python3
"""In-house deterministic GraphQL introspection prober (no GPL deps). Sends an
introspection query to the target /graphql endpoint and emits a nuclei-style JSONL
finding if the schema is returned (introspection exposed to unauthenticated clients).
"""

import json
import sys
import urllib.request

INTROSPECTION = '{"query":"{ __schema { queryType { name } types { name } } }"}'


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: graphql-probe <graphql-url>", file=sys.stderr)
        return 2
    url = sys.argv[1]
    req = urllib.request.Request(
        url, data=INTROSPECTION.encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception:
        return 0
    if "__schema" in body and "types" in body:
        finding = {
            "template-id": "graphql-introspection",
            "info": {"severity": "medium", "name": "GraphQL introspection enabled (schema disclosed to unauthenticated clients)"},
            "host": url,
            "matched-at": url,
        }
        print(json.dumps(finding))
    return 0


if __name__ == "__main__":
    sys.exit(main())
