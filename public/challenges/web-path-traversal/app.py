#!/usr/bin/env python3
"""
Path Traversal Challenge
Port: 5003

A file download endpoint that uses os.path.join without sanitising
the user-supplied filename. Traverse out of the documents/ directory
to read flag.txt.
"""

import os
from flask import Flask, request, send_file, render_template_string

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(BASE_DIR, "documents")

INDEX = """
<!DOCTYPE html>
<html>
<head><title>DocServer</title></head>
<body>
<h1>Document Server</h1>
<p>Available files:</p>
<ul>
  <li><a href="/download?file=guide.pdf">guide.pdf</a></li>
</ul>
<form method="GET" action="/download">
  <input type="text" name="file" placeholder="filename">
  <button type="submit">Download</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX)


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    if not filename:
        return render_template_string(INDEX, error="No file specified.")

    # VULNERABLE: os.path.join does not prevent ../ traversal
    filepath = os.path.join(DOCS_DIR, filename)

    if not os.path.isfile(filepath):
        return render_template_string(INDEX, error="File not found.")

    return send_file(filepath)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=False)
