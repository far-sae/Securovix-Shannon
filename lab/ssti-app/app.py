"""Deliberately vulnerable SSTI target for Shannon's broker end-to-end tests.

DO NOT deploy this anywhere reachable. It renders user input as a Jinja2 template
on purpose (server-side template injection) so the tool-broker pipeline can be
exercised against a real, reproducible vulnerability.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/")
def index():
    name = request.args.get("name", "world")
    # VULNERABLE BY DESIGN: untrusted input concatenated into a template string.
    return render_template_string("Hello " + name + "!")


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
