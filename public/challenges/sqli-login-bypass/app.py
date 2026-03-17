#!/usr/bin/env python3
"""
SQLi Login Bypass Challenge
Port: 5001

A simple login form backed by SQLite. The query is built via string
concatenation — classic SQL injection territory.

Try logging in as admin without knowing the password!
"""

import sqlite3, os
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

FLAG = open(os.path.join(os.path.dirname(__file__), "flag.txt")).read().strip()

HTML = """
<!DOCTYPE html>
<html>
<head><title>SecureCorp Login</title></head>
<body>
<h1>SecureCorp Employee Portal</h1>
<form method="POST" action="/login">
  <label>Username:</label><br>
  <input type="text" name="username"><br>
  <label>Password:</label><br>
  <input type="password" name="password"><br><br>
  <button type="submit">Login</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% if flag %}<p style="color:green">Welcome admin! Here is your flag: {{ flag }}</p>{% endif %}
</body>
</html>
"""


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABLE: user input is concatenated directly into the SQL query
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )

    conn = get_db()
    try:
        result = conn.execute(query).fetchone()
    except Exception as e:
        return render_template_string(HTML, error=f"SQL Error: {e}")
    finally:
        conn.close()

    if result:
        return render_template_string(HTML, flag=FLAG)
    else:
        return render_template_string(HTML, error="Invalid credentials.")


if __name__ == "__main__":
    # Auto-initialise the database if it doesn't exist
    if not os.path.exists(DB_PATH):
        import setup  # noqa: F401

    app.run(host="0.0.0.0", port=5001, debug=False)
