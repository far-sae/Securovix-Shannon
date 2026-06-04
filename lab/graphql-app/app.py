"""Deliberately vulnerable GraphQL target for broker e2e tests. Local lab only.

A minimal /graphql endpoint with INTROSPECTION ENABLED (it answers `__schema` queries),
which leaks the full schema to unauthenticated clients.
"""

from flask import Flask, jsonify, request

app = Flask(__name__)

SCHEMA = {
    "__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"name": "Query", "fields": [{"name": "user"}, {"name": "secretNote"}]},
            {"name": "User", "fields": [{"name": "id"}, {"name": "email"}, {"name": "apiKey"}]},
        ],
    }
}


@app.route("/graphql", methods=["POST", "GET"])
def graphql():
    query = ""
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        query = body.get("query", "")
    else:
        query = request.args.get("query", "")
    # VULNERABLE BY DESIGN: introspection is enabled for everyone.
    if "__schema" in query:
        return jsonify({"data": SCHEMA})
    return jsonify({"data": {"user": {"id": 1}}})


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
