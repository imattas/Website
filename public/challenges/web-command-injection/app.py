#!/usr/bin/env python3
"""
Command Injection Challenge
Port: 5005

A network diagnostic tool that lets you ping a host.
The user input is passed straight to os.system() — chain
additional commands with ; or | to read the flag.
"""

import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

INDEX = """
<!DOCTYPE html>
<html>
<head><title>NetPing</title></head>
<body>
<h1>Network Diagnostic Tool</h1>
<form method="POST" action="/ping">
  <label>Enter host to ping:</label><br>
  <input type="text" name="host" placeholder="8.8.8.8" size="30">
  <button type="submit">Ping</button>
</form>
{% if output %}
<h3>Result:</h3>
<pre>{{ output }}</pre>
{% endif %}
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX)


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "")

    if not host:
        return render_template_string(INDEX, output="Please provide a host.")

    # VULNERABLE: user input is passed directly to os.popen (shell command)
    cmd = "ping -c 2 " + host
    try:
        output = os.popen(cmd).read()
    except Exception as e:
        output = str(e)

    return render_template_string(INDEX, output=output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005, debug=False)
