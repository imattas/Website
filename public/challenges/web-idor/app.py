#!/usr/bin/env python3
"""
Insecure Direct Object Reference (IDOR) Challenge
Port: 5006

A user profile API with sequential integer IDs. You are logged in
as user id=2. The admin profile (id=1) contains the flag — just
change the ID in the URL.
"""

import os
from flask import Flask, render_template_string

app = Flask(__name__)

FLAG = open(os.path.join(os.path.dirname(__file__), "flag.txt")).read().strip()

USERS = {
    1: {
        "username": "admin",
        "email": "admin@securecorp.local",
        "role": "administrator",
        "notes": f"Secret flag: {FLAG}",
    },
    2: {
        "username": "jdoe",
        "email": "jdoe@securecorp.local",
        "role": "employee",
        "notes": "Regular user account.",
    },
    3: {
        "username": "guest",
        "email": "guest@securecorp.local",
        "role": "viewer",
        "notes": "Limited access guest.",
    },
}

INDEX = """
<!DOCTYPE html>
<html>
<head><title>Employee Portal</title></head>
<body>
<h1>Employee Portal</h1>
<p>Welcome, jdoe. <a href="/api/user/2">View your profile</a></p>
</body>
</html>
"""

PROFILE = """
<!DOCTYPE html>
<html>
<head><title>User Profile</title></head>
<body>
<h1>User Profile</h1>
<table border="1" cellpadding="8">
  <tr><td><b>Username</b></td><td>{{ user.username }}</td></tr>
  <tr><td><b>Email</b></td><td>{{ user.email }}</td></tr>
  <tr><td><b>Role</b></td><td>{{ user.role }}</td></tr>
  <tr><td><b>Notes</b></td><td>{{ user.notes }}</td></tr>
</table>
<br><a href="/">Back</a>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX)


@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    # VULNERABLE: no authorisation check — any user id can be accessed
    user = USERS.get(user_id)
    if not user:
        return {"error": "User not found"}, 404
    return render_template_string(PROFILE, user=user)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5006, debug=False)
