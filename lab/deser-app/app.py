"""Deliberately vulnerable insecure-deserialization target. Local lab only.

`/load` base64-decodes and `pickle.loads()` untrusted input, so a crafted pickle gadget
executes on the server (RCE). The lab returns repr() of the result for easy detection.
"""

import base64
import pickle  # noqa: S403 - intentionally used insecurely for the lab

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/load")
def load():
    try:
        obj = pickle.loads(base64.b64decode(request.args.get("data", "")))  # noqa: S301 - VULNERABLE BY DESIGN
        return jsonify({"result": repr(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
