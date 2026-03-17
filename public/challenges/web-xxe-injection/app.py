#!/usr/bin/env python3
"""
XXE (XML External Entity) Injection Challenge
Port: 5013

An API that accepts XML input and parses it with lxml (external
entities enabled). Use an XXE payload to read flag.txt from the
filesystem.
"""

import os
from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

INDEX = """
<!DOCTYPE html>
<html>
<head><title>XML Parser</title></head>
<body>
<h1>XML Data Processor</h1>
<p>Submit XML data to be parsed and displayed.</p>
<form method="POST" action="/parse">
  <textarea name="xml" rows="10" cols="60">&lt;user&gt;
  &lt;name&gt;John&lt;/name&gt;
  &lt;email&gt;john@example.com&lt;/email&gt;
&lt;/user&gt;</textarea><br>
  <button type="submit">Parse XML</button>
</form>
{% if result %}
<h3>Parsed Data:</h3>
<pre>{{ result }}</pre>
{% endif %}
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX)


@app.route("/parse", methods=["POST"])
def parse():
    xml_data = request.form.get("xml", "")
    if not xml_data:
        return render_template_string(INDEX, error="No XML provided.")

    try:
        # VULNERABLE: resolve_entities=True allows external entity expansion
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False,
        )
        root = etree.fromstring(xml_data.encode(), parser)

        # Convert parsed XML back to a readable format
        result_parts = []
        for elem in root.iter():
            if elem.text and elem.text.strip():
                result_parts.append(f"{elem.tag}: {elem.text.strip()}")

        result = "\n".join(result_parts) if result_parts else "Empty document."

    except Exception as e:
        return render_template_string(INDEX, error=f"Parse error: {e}")

    return render_template_string(INDEX, result=result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5013, debug=False)
