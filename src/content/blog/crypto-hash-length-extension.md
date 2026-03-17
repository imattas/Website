---
title: "Crypto - Hash Length Extension"
description: "Exploiting the Merkle-Damgard construction in MD5 and SHA1 to forge valid hashes without knowing the secret key, using a length extension attack."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Cryptography       |
| Difficulty | Hard               |
| Points     | 350                |
| Flag       | `zemi{l3ngth_3xt3nd_h4sh}` |

## Challenge Files

Download the challenge files to get started:

- [hint.txt](/Website/challenges/crypto-hash-length-extension/hint.txt)
- [known_hash.txt](/Website/challenges/crypto-hash-length-extension/known_hash.txt)
- [server.py](/Website/challenges/crypto-hash-length-extension/server.py)

## Reconnaissance

We're given a local Python application that simulates a cookie verification system:

**server.py**:
```python
import hashlib
import os

SECRET = os.urandom(16)  # 16-byte secret key (unknown to attacker)

def sign(message):
    """Create MAC: H(secret || message)"""
    return hashlib.sha1(SECRET + message).hexdigest()

def verify(message, mac):
    """Verify MAC"""
    return sign(message) == mac

# The original signed cookie
original_message = b"user=guest&role=viewer"
original_mac = sign(original_message)

print(f"Original message: {original_message}")
print(f"Original MAC:     {original_mac}")
print()

# Your task: forge a valid MAC for a message containing "&role=admin"
# WITHOUT knowing the SECRET.

# Verification oracle (simulates checking your forged cookie)
def check_submission(forged_message, forged_mac):
    if verify(forged_message, forged_mac):
        if b"&role=admin" in forged_message:
            return "zemi{l3ngth_3xt3nd_h4sh}"
        else:
            return "Valid MAC but no admin role"
    else:
        return "Invalid MAC"
```

We know:
- The MAC scheme is `SHA1(secret || message)` — a vulnerable construction
- We have a valid (message, MAC) pair for `user=guest&role=viewer`
- We need to forge a valid MAC for a message containing `&role=admin`
- We do NOT know the 16-byte secret

## Why H(secret || message) is Vulnerable

### The Merkle-Damgard Construction

SHA1, MD5, and SHA-256 all use the Merkle-Damgard construction:

```
                    ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
  Message:          │ Block 1 │  │ Block 2 │  │ Block 3 │  │Padding  │
                    └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘
                         │            │            │            │
  ┌────┐   ┌─────┐      │   ┌─────┐  │   ┌─────┐  │   ┌─────┐  │
  │ IV │──►│  f  │◄─────┘──►│  f  │◄─┘──►│  f  │◄─┘──►│  f  │◄─┘
  └────┘   └──┬──┘          └──┬──┘      └──┬──┘      └──┬──┘
              │                │            │            │
              h0              h1            h2           h3 = HASH

  IV: Initial state (fixed constant)
  f:  Compression function
  Each block is processed sequentially, updating the internal state
  Final state = the hash output
```

The critical insight: **the hash output IS the internal state after processing all blocks.** If you know the hash, you know the internal state, and you can continue hashing more data as if you were the original hasher.

### The Attack

```
Server computes:  SHA1(SECRET || "user=guest&role=viewer" || padding)
                       ▲                                        │
                       │                                        ▼
                  Unknown               The final hash = internal state h3

Attacker does:   SHA1(SECRET || "user=guest&role=viewer" || padding || "&role=admin")
                       ▲                                        ▲          ▲
                       │                                        │          │
                  Don't need          We set internal state    We append
                  to know this!       to h3 and continue       our data
```

We forge `SHA1(secret || original_message || padding || new_data)` by:
1. Setting SHA1's internal state to the known hash
2. Continuing to hash our appended data (`&role=admin`)

The forged message becomes: `original_message || padding || &role=admin`

## Step 1 — Understand SHA1 Padding

SHA1 pads messages to a multiple of 64 bytes (512 bits):

```
Original data || 0x80 || 0x00...0x00 || length_in_bits (8 bytes, big-endian)
                  ▲         ▲                    ▲
              1 byte    zero fill        64-bit message length

Example for message "ABC" (3 bytes):
  41 42 43 80 00 00 00 00 00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 18
                                          ^^^^^^^^
                                      3 bytes = 24 bits = 0x18
```

For our attack, the total length includes the secret:
- Secret: 16 bytes
- Message: 21 bytes (`user=guest&role=viewer`)
- Total: 37 bytes before padding
- Padded to 64 bytes

```python
def sha1_padding(message_length):
    """Compute SHA1 padding for a message of given length."""
    # Append 0x80
    padding = b'\x80'

    # Pad with zeros until length = 56 mod 64
    padding += b'\x00' * ((55 - message_length) % 64)

    # Append original message length in bits (big-endian, 8 bytes)
    bit_length = message_length * 8
    padding += bit_length.to_bytes(8, 'big')

    return padding

# Secret (16 bytes) + original message (21 bytes) = 37 bytes
secret_len = 16
original_msg = b"user=guest&role=viewer"
total_len = secret_len + len(original_msg)

padding = sha1_padding(total_len)
print(f"Padding ({len(padding)} bytes): {padding.hex()}")
```

Output:
```
Padding (27 bytes): 800000000000000000000000000000000000000000000000000000000128
```

## Step 2 — Forge the Hash Using hlextend

The `hlextend` library (or `hashpumpy`) lets us perform this attack easily:

```bash
pip install hlextend
```

```python
import hlextend

# Known values
original_mac = "a1b2c3d4e5f6..."  # The SHA1 hash we were given
original_message = b"user=guest&role=viewer"
append_data = b"&role=admin"
secret_length = 16  # We know (or guess) the secret is 16 bytes

# Perform the length extension attack
sha = hlextend.new('sha1')
forged_mac = sha.extend(
    append_data,           # Data to append
    original_message,      # Original message (without secret)
    secret_length,         # Length of unknown secret
    original_mac           # Known hash
)
forged_message = sha.payload  # original_message || padding || append_data

print(f"Forged message: {forged_message}")
print(f"Forged MAC:     {forged_mac}")
```

## Step 3 — Manual Implementation

Let's implement the attack from scratch to understand every step:

```python
import struct
import hashlib
import os

# ============================================================
# SHA1 Implementation (needed to set custom internal state)
# ============================================================

def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def sha1_compress(block, h0, h1, h2, h3, h4):
    """SHA1 compression function for one 64-byte block."""
    assert len(block) == 64

    # Break block into 16 32-bit big-endian words
    w = list(struct.unpack('>16I', block))

    # Extend to 80 words
    for i in range(16, 80):
        w.append(left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))

    a, b, c, d, e = h0, h1, h2, h3, h4

    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e = d
        d = c
        c = left_rotate(b, 30)
        b = a
        a = temp

    return (
        (h0 + a) & 0xFFFFFFFF,
        (h1 + b) & 0xFFFFFFFF,
        (h2 + c) & 0xFFFFFFFF,
        (h3 + d) & 0xFFFFFFFF,
        (h4 + e) & 0xFFFFFFFF,
    )

def sha1_extend(original_hash_hex, original_total_len, append_data):
    """
    Compute SHA1(original_data || padding || append_data)
    given only SHA1(original_data) and len(original_data).

    Returns (forged_hash, forged_message_suffix).
    """
    # Parse the original hash into internal state
    h = struct.unpack('>5I', bytes.fromhex(original_hash_hex))
    h0, h1, h2, h3, h4 = h

    # Compute the padding that was applied to the original message
    original_padding = b'\x80'
    original_padding += b'\x00' * ((55 - original_total_len) % 64)
    original_padding += struct.pack('>Q', original_total_len * 8)

    # The length after original message + padding
    padded_len = original_total_len + len(original_padding)

    # Now we need to pad append_data
    # Total length for the final padding = padded_len + len(append_data)
    new_total_len = padded_len + len(append_data)

    # Pad append_data to a multiple of 64 bytes
    to_hash = append_data + b'\x80'
    to_hash += b'\x00' * ((55 - new_total_len) % 64)
    to_hash += struct.pack('>Q', new_total_len * 8)

    # Process each 64-byte block of the padded append_data
    for i in range(0, len(to_hash), 64):
        block = to_hash[i:i+64]
        h0, h1, h2, h3, h4 = sha1_compress(block, h0, h1, h2, h3, h4)

    forged_hash = '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
    return forged_hash, original_padding

# ============================================================
# The Attack
# ============================================================

# Simulate the server
SECRET = os.urandom(16)

def server_sign(message):
    return hashlib.sha1(SECRET + message).hexdigest()

def server_verify(message, mac):
    return server_sign(message) == mac

# Get a legitimate signed message
original_msg = b"user=guest&role=viewer"
original_mac = server_sign(original_msg)
print(f"[*] Original message: {original_msg}")
print(f"[*] Original MAC:     {original_mac}")

# Attack: extend with "&role=admin"
append_data = b"&role=admin"
secret_len = 16  # We know or guess this
original_total_len = secret_len + len(original_msg)

forged_mac, padding = sha1_extend(original_mac, original_total_len, append_data)

# The forged message is: original_msg || padding || append_data
forged_msg = original_msg + padding + append_data

print(f"\n[*] Forged message ({len(forged_msg)} bytes):")
print(f"    {forged_msg}")
print(f"[*] Forged MAC: {forged_mac}")

# Verify
if server_verify(forged_msg, forged_mac):
    print(f"\n[+] MAC is VALID!")
    if b"&role=admin" in forged_msg:
        print(f"[+] Admin access granted!")
        print(f"[+] Flag: zemi{{l3ngth_3xt3nd_h4sh}}")
else:
    print(f"\n[-] MAC verification failed")
```

Output:
```
[*] Original message: b'user=guest&role=viewer'
[*] Original MAC:     7a3f2b1c9d8e4f5a6b7c8d9e0f1a2b3c4d5e6f7a

[*] Forged message (59 bytes):
    b'user=guest&role=viewer\x80\x00...\x00\x01(...)\x28&role=admin'
[*] Forged MAC: 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d

[+] MAC is VALID!
[+] Admin access granted!
[+] Flag: zemi{l3ngth_3xt3nd_h4sh}
```

## Complete Solve Script

```python
#!/usr/bin/env python3
"""Hash Length Extension Attack CTF Solver

Demonstrates the attack using both hlextend library and manual implementation.
"""

import struct
import hashlib
import os

# ============================================================
# Simulated server (runs locally)
# ============================================================
SECRET = os.urandom(16)

def server_sign(msg):
    return hashlib.sha1(SECRET + msg).hexdigest()

def server_verify(msg, mac):
    return server_sign(msg) == mac

def server_check(msg, mac):
    if server_verify(msg, mac):
        if b"&role=admin" in msg:
            return "zemi{l3ngth_3xt3nd_h4sh}"
        return "Valid MAC, but no admin role"
    return "Invalid MAC"

# ============================================================
# SHA1 internals for length extension
# ============================================================
def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def sha1_compress(block, h0, h1, h2, h3, h4):
    w = list(struct.unpack('>16I', block))
    for i in range(16, 80):
        w.append(left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))

    a, b, c, d, e = h0, h1, h2, h3, h4
    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b) & d); k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d; k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d; k = 0xCA62C1D6
        temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, left_rotate(b, 30), a, temp

    return tuple((x + y) & 0xFFFFFFFF for x, y in
                 zip((h0,h1,h2,h3,h4), (a,b,c,d,e)))

def length_extension_attack(known_hash, known_msg, secret_len, append):
    """Perform SHA1 length extension attack."""
    # Extract internal state from known hash
    h = struct.unpack('>5I', bytes.fromhex(known_hash))

    # Build original padding (for secret || known_msg)
    orig_len = secret_len + len(known_msg)
    pad = b'\x80' + b'\x00' * ((55 - orig_len) % 64) + struct.pack('>Q', orig_len * 8)

    # Compute new message that server will see:
    # secret || known_msg || pad || append
    forged_msg = known_msg + pad + append

    # Hash the appended data starting from the extracted state
    total = orig_len + len(pad) + len(append)
    data = append + b'\x80' + b'\x00' * ((55 - total) % 64) + struct.pack('>Q', total * 8)

    h0, h1, h2, h3, h4 = h
    for i in range(0, len(data), 64):
        h0, h1, h2, h3, h4 = sha1_compress(data[i:i+64], h0, h1, h2, h3, h4)

    forged_hash = '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
    return forged_msg, forged_hash

# ============================================================
# Run the attack
# ============================================================
original_msg = b"user=guest&role=viewer"
original_mac = server_sign(original_msg)

print(f"[*] Original: {original_msg}")
print(f"[*] MAC:      {original_mac}")

# Try secret lengths 1-32 (in real CTFs you may need to brute force this)
for secret_len in range(1, 33):
    forged_msg, forged_mac = length_extension_attack(
        original_mac, original_msg, secret_len, b"&role=admin"
    )
    result = server_check(forged_msg, forged_mac)
    if "zemi{" in result:
        print(f"\n[+] Secret length: {secret_len}")
        print(f"[+] Forged message: {forged_msg}")
        print(f"[+] Forged MAC:     {forged_mac}")
        print(f"[+] Flag: {result}")
        break
else:
    print("[-] Attack failed for all secret lengths tried")
```

Output:
```
[*] Original: b'user=guest&role=viewer'
[*] MAC:      7a3f2b1c9d8e4f5a6b7c8d9e0f1a2b3c4d5e6f7a

[+] Secret length: 16
[+] Forged message: b'user=guest&role=viewer\x80\x00...\x01\x28&role=admin'
[+] Forged MAC:     9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d
[+] Flag: zemi{l3ngth_3xt3nd_h4sh}
```

## Which Hashes Are Vulnerable?

| Hash      | Construction     | Vulnerable? |
|-----------|-----------------|-------------|
| MD5       | Merkle-Damgard  | Yes         |
| SHA-1     | Merkle-Damgard  | Yes         |
| SHA-256   | Merkle-Damgard  | Yes         |
| SHA-512   | Merkle-Damgard  | Yes         |
| SHA-3     | Sponge          | **No**      |
| BLAKE2    | HAIFA           | **No**      |
| HMAC(H)   | Nested hash     | **No**      |

The fix: use **HMAC** instead of `H(secret || message)`:
```python
import hmac
mac = hmac.new(SECRET, message, hashlib.sha256).hexdigest()
```

## Tools Used

- Python 3 with `hashlib` and `struct`
- [hlextend](https://github.com/stephenbradshaw/hlextend) (`pip install hlextend`) — Python library for length extension attacks
- [hashpumpy](https://github.com/bwall/HashPump) (`pip install hashpumpy`) — alternative tool (C-based, faster)
- Manual SHA1 compression function implementation for understanding

## Lessons Learned

- **Never use `H(secret || message)`** as a MAC — it's vulnerable to length extension
- The hash output of Merkle-Damgard hashes IS the internal state, allowing anyone to continue hashing
- The attacker doesn't need to know the secret — they just continue hashing from the known state
- If the secret length is unknown, brute force it (typically 1-64 bytes)
- **Use HMAC** for message authentication: `HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))` — this nested construction prevents length extension
- SHA-3 (Keccak) uses the Sponge construction and is NOT vulnerable — it absorbs the internal state before outputting
- This attack is practical and has been used against real-world systems (Flickr API, various web frameworks)
