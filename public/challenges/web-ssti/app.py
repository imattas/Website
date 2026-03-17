#!/usr/bin/env python3
"""
Server-Side Template Injection (SSTI) Challenge
Port: 5004

A greeting page that renders user input directly inside a Jinja2
template via render_template_string. Inject template expressions
like {{ config }} or {{ ''.__class__.__mro__ }} to explore.
"""

import os
from flask import Flask, request, render_template_string

app = Flask(__name__)
app.config["FLAG"] = open(
    os.path.join(os.path.dirname(__file__), "flag.txt")
).read().strip()

INDEX = """
<!DOCTYPE html>
<html>
<head><title>Greeting Card</title></head>
<body>
<h1>Custom Greeting Card Generator</h1>
<form method="POST" action="/greet">
  <label>Enter your name:</label><br>
  <input type="text" name="name" size="40">
  <button type="submit">Generate</button>
</form>
</body>
</html>
"""


@app.route("/")
def index():
    return INDEX


@app.route("/greet", methods=["POST"])
def greet():
    name = request.form.get("name", "World")

    # VULNERABLE: user input placed directly into the template string
    template = (
        "<html><body>"
        "<h1>Hello, " + name + "!</h1>"
        "<p>Your greeting card is ready.</p>"
        "<a href='/'>Back</a>"
        "</body></html>"
    )

    try:
        return render_template_string(template)
    except Exception as e:
        return f"<p>Error: {e}</p>", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)
