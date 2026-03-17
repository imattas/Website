#!/usr/bin/env python3
"""
JWT Cracking Challenge
Port: 5007

Login to receive a JWT with role=user. The /admin endpoint
requires role=admin. The signing secret is weak ("secret123") —
crack it with a wordlist and forge an admin token.
"""

import os
import jwt  # PyJWT
from flask import Flask, request, render_template_string, make_response, redirect

app = Flask(__name__)

SECRET_KEY = "secret123"  # Intentionally weak — crack this!
FLAG = open(os.path.join(os.path.dirname(__file__), "flag.txt")).read().strip()

INDEX = """
<!DOCTYPE html>
<html>
<head><title>JWT Auth</title></head>
<body>
<h1>JWT Authentication Portal</h1>
<form method="POST" action="/login">
  <label>Username:</label>
  <input type="text" name="username">
  <button type="submit">Login</button>
</form>
{% if message %}<p>{{ message }}</p>{% endif %}
</body>
</html>
"""

DASHBOARD = """
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
<h1>Dashboard</h1>
<p>Welcome, {{ username }}! Your role is <b>{{ role }}</b>.</p>
<p><a href="/admin">Access Admin Panel</a></p>
<p><small>Your JWT: <code>{{ token }}</code></small></p>
</body>
</html>
"""

ADMIN = """
<!DOCTYPE html>
<html>
<head><title>Admin</title></head>
<body>
<h1>Admin Panel</h1>
<p>Flag: {{ flag }}</p>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "guest")

    # Issue a JWT with role=user (never admin)
    token = jwt.encode(
        {"username": username, "role": "user"},
        SECRET_KEY,
        algorithm="HS256",
    )

    resp = make_response(
        render_template_string(DASHBOARD, username=username, role="user", token=token)
    )
    resp.set_cookie("token", token)
    return resp


@app.route("/admin")
def admin():
    token = request.cookies.get("token") or request.headers.get(
        "Authorization", ""
    ).replace("Bearer ", "")

    if not token:
        return render_template_string(INDEX, message="Please login first."), 401

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError as e:
        return {"error": f"Invalid token: {e}"}, 401

    if payload.get("role") != "admin":
        return {"error": "Access denied. Admin role required.", "your_role": payload.get("role")}, 403

    return render_template_string(ADMIN, flag=FLAG)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5007, debug=False)
