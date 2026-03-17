#!/usr/bin/env python3
"""
Insecure Deserialization Challenge
Port: 5009

User preferences are stored in a base64-encoded pickled cookie.
Python's pickle module will execute arbitrary code during
deserialization — craft a malicious pickle to read the flag.
"""

import os, base64, pickle
from flask import Flask, request, render_template_string, make_response

app = Flask(__name__)

FLAG = open(os.path.join(os.path.dirname(__file__), "flag.txt")).read().strip()

INDEX = """
<!DOCTYPE html>
<html>
<head><title>Preferences</title></head>
<body>
<h1>User Preferences</h1>
<p>Current preferences:</p>
<pre>{{ prefs }}</pre>
<form method="POST" action="/update">
  <label>Theme:</label>
  <select name="theme">
    <option>light</option>
    <option>dark</option>
    <option>solarized</option>
  </select>
  <label>Language:</label>
  <select name="language">
    <option>en</option>
    <option>es</option>
    <option>fr</option>
  </select>
  <button type="submit">Save</button>
</form>
<p><small>Preferences are stored in the <code>prefs</code> cookie (base64-encoded).</small></p>
{% if output %}<h3>Command output:</h3><pre>{{ output }}</pre>{% endif %}
</body>
</html>
"""

DEFAULT_PREFS = {"theme": "light", "language": "en"}


@app.route("/")
def index():
    cookie = request.cookies.get("prefs")
    if cookie:
        try:
            # VULNERABLE: pickle.loads on user-controlled data
            prefs = pickle.loads(base64.b64decode(cookie))
        except Exception:
            prefs = DEFAULT_PREFS
    else:
        prefs = DEFAULT_PREFS

    return render_template_string(INDEX, prefs=prefs)


@app.route("/update", methods=["POST"])
def update():
    prefs = {
        "theme": request.form.get("theme", "light"),
        "language": request.form.get("language", "en"),
    }

    serialized = base64.b64encode(pickle.dumps(prefs)).decode()

    resp = make_response(render_template_string(INDEX, prefs=prefs))
    resp.set_cookie("prefs", serialized)
    return resp


@app.route("/flag")
def flag():
    """Helper endpoint — RCE via pickle can also just read flag.txt directly."""
    return FLAG


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5009, debug=False)
