"""Deliberately vulnerable IDOR/BOLA target for broker e2e tests. Local lab only.

`/api/item/<id>` returns per-object data with NO authorization check, so any object
reference is accessible (Insecure Direct Object Reference / Broken Object-Level Auth).
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/api/item/<int:item_id>")
def item(item_id: int):
    # VULNERABLE BY DESIGN: no ownership/authorization check on the object reference.
    return jsonify({"id": item_id, "owner": f"user{item_id}", "secret": f"flag-{item_id}"})


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
