#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Challenge
Port: 5008

A URL preview/fetcher tool. The /admin endpoint only responds to
requests from 127.0.0.1. Use the fetcher to make the server
request its own /admin endpoint.
"""

import os
import requests as req_lib
from flask import Flask, request, render_template_string

app = Flask(__name__)

FLAG = open(os.path.join(os.path.dirname(__file__), "flag.txt")).read().strip()

INDEX = """
<!DOCTYPE html>
<html>
<head><title>URL Preview</title></head>
<body>
<h1>URL Preview Service</h1>
<p>Enter a URL to fetch its contents:</p>
<form method="POST" action="/fetch">
  <input type="text" name="url" placeholder="https://example.com" size="50">
  <button type="submit">Fetch</button>
</form>
{% if content %}
<h3>Response:</h3>
<pre>{{ content }}</pre>
{% endif %}
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX)


@app.route("/fetch", methods=["POST"])
def fetch():
    url = request.form.get("url", "")
    if not url:
        return render_template_string(INDEX, error="Please provide a URL.")

    # VULNERABLE: no validation on the URL — allows requests to internal services
    try:
        resp = req_lib.get(url, timeout=5)
        content = resp.text[:5000]
    except Exception as e:
        content = None
        return render_template_string(INDEX, error=f"Error fetching URL: {e}")

    return render_template_string(INDEX, content=content)


@app.route("/admin")
def admin():
    # Only accessible from localhost
    remote = request.remote_addr
    if remote not in ("127.0.0.1", "::1"):
        return {"error": "Access denied. Internal only.", "your_ip": remote}, 403

    return f"<h1>Internal Admin Panel</h1><p>Flag: {FLAG}</p>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5008, debug=False)
