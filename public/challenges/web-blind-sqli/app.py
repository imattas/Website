#!/usr/bin/env python3
"""
Blind SQL Injection Challenge
Port: 5010

A product search endpoint that is vulnerable to blind SQL injection.
The flag is stored in a separate "secrets" table. Use boolean-based
or time-based techniques to extract it character by character.
"""

import sqlite3, os, time
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "store.db")

INDEX = """
<!DOCTYPE html>
<html>
<head><title>Product Search</title></head>
<body>
<h1>Product Catalog</h1>
<form method="GET" action="/search">
  <input type="text" name="q" placeholder="Search products..." size="40">
  <button type="submit">Search</button>
</form>
{% if products %}
<h3>Results:</h3>
<ul>
{% for p in products %}
  <li>{{ p[1] }} - ${{ p[2] }}</li>
{% endfor %}
</ul>
{% elif searched %}
<p>No products found.</p>
{% endif %}
</body>
</html>
"""


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/")
def index():
    return render_template_string(INDEX)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    if not q:
        return render_template_string(INDEX)

    # VULNERABLE: string concatenation in SQL query (blind injection)
    query = "SELECT * FROM products WHERE name LIKE '%" + q + "%'"

    conn = get_db()
    try:
        products = conn.execute(query).fetchall()
    except Exception:
        products = []
    finally:
        conn.close()

    return render_template_string(INDEX, products=products, searched=True)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import setup  # noqa: F401

    app.run(host="0.0.0.0", port=5010, debug=False)
