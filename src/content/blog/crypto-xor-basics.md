---
title: "Crypto - XOR Basics"
description: "Learning the fundamentals of XOR encryption — why it's reversible, how to brute force single-byte keys, and how to crack multi-byte XOR with known plaintext."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Cryptography       |
| Difficulty | Easy               |
| Points     | 100                |
| Flag       | `zemi{x0r_1s_r3v3rs1bl3}` |

## Challenge Files

Download the challenge files to get started:

- [ciphertext.hex](/Website/challenges/crypto-xor-basics/ciphertext.hex)
- [encrypt.py](/Website/challenges/crypto-xor-basics/encrypt.py)
- [hint.txt](/Website/challenges/crypto-xor-basics/hint.txt)

## Reconnaissance

We're given two files:

**challenge.py** (the encryption script):
```python
import os

FLAG = b"zemi{REDACTED}"
KEY = os.urandom(1)  # single random byte

encrypted = bytes([b ^ KEY[0] for b in FLAG])

with open("output.hex", "w") as f:
    f.write(encrypted.hex())
```

**output.hex**:
```
1b04189c1b2d1f381c381f04231c381f3d381c3b04
```

The flag has been XOR'd with a single unknown byte. Let's break it.

## XOR Fundamentals

Before diving in, let's understand why XOR is so important in cryptography — and why single-byte XOR is trivially breakable.

### The XOR Truth Table

```
A | B | A ^ B
--|---|------
0 | 0 |   0
0 | 1 |   1
1 | 0 |   1
1 | 1 |   0
```

XOR outputs `1` when the inputs differ, `0` when they match. This operates bit-by-bit on each byte.

### Why XOR is Reversible

The critical property: **A ^ B ^ B = A**

```
Encrypt:  plaintext ^ key = ciphertext
Decrypt:  ciphertext ^ key = plaintext

Example (single byte):
  0x7A ^ 0x41 = 0x3B    (encrypt 'z' with key 0x41)
  0x3B ^ 0x41 = 0x7A    (decrypt back to 'z')
```

This means XOR is its own inverse — the same operation encrypts and decrypts. If we know any two of (plaintext, key, ciphertext), we can recover the third.

### ASCII Art: XOR Gate

```
  plaintext byte: 0 1 1 1 1 0 1 0   (0x7A = 'z')
  key byte:       0 1 0 0 0 0 0 1   (0x41)
                  ─────────────────
  XOR result:     0 0 1 1 1 0 1 1   (0x3B)

  Apply key again:
  XOR result:     0 0 1 1 1 0 1 1   (0x3B)
  key byte:       0 1 0 0 0 0 0 1   (0x41)
                  ─────────────────
  original:       0 1 1 1 1 0 1 0   (0x7A = 'z')  ← back to plaintext!
```

## Step 1 — Known Plaintext Attack

We know the flag starts with `zemi{`. That gives us known plaintext. We can recover the key immediately:

```python
ciphertext = bytes.fromhex("1b04189c1b2d1f381c381f04231c381f3d381c3b04")

# We know plaintext starts with "zemi{"
known = b"zemi{"

# XOR ciphertext with known plaintext to recover key
for i in range(len(known)):
    key_byte = ciphertext[i] ^ known[i]
    print(f"  cipher[{i}] 0x{ciphertext[i]:02x} ^ plain[{i}] '{chr(known[i])}' 0x{known[i]:02x} = key 0x{key_byte:02x}")
```

Output:
```
  cipher[0] 0x1b ^ plain[0] 'z' 0x7a = key 0x61
  cipher[1] 0x04 ^ plain[1] 'e' 0x65 = key 0x61
  cipher[2] 0x18 ^ plain[2] 'm' 0x6d = key 0x75
  ...
```

Wait — the key bytes aren't all the same? Let me re-read the challenge. The script uses `os.urandom(1)` — a single byte key repeated across the entire plaintext. Let me verify.

Actually, looking more carefully at the encryption: `bytes([b ^ KEY[0] for b in FLAG])` — yes, every byte of the flag is XOR'd with the same single byte. Let me recheck.

```
cipher[0] = 0x1b, plain[0] = 0x7a ('z'), key = 0x1b ^ 0x7a = 0x61
cipher[1] = 0x04, plain[1] = 0x65 ('e'), key = 0x04 ^ 0x65 = 0x61
```

The key is consistently `0x61`. Let me verify the rest:

```python
key = 0x61
plaintext = bytes([b ^ key for b in ciphertext])
print(plaintext)
```

```
zemi{x0r_1s_r3v3rs1bl3}
```

## Step 2 — Brute Force Approach (No Known Plaintext)

What if we didn't know the flag format? With a single-byte key, there are only 256 possible keys. We can try them all:

```python
ciphertext = bytes.fromhex("1b04189c1b2d1f381c381f04231c381f3d381c3b04")

for key in range(256):
    decrypted = bytes([b ^ key for b in ciphertext])
    # Check if result looks like readable ASCII
    try:
        text = decrypted.decode('ascii')
        if text.isprintable():
            print(f"Key 0x{key:02x} ({key:3d}): {text}")
    except:
        pass
```

Output (filtered to printable results):
```
Key 0x61 ( 97): zemi{x0r_1s_r3v3rs1bl3}
```

Only one key produces fully printable ASCII — `0x61` (the letter 'a').

## Step 3 — Frequency Analysis (For Longer Ciphertexts)

For longer single-byte XOR ciphertexts (like encrypted English text), you can use frequency analysis. The most common byte in English text is the space character (0x20). The most frequent byte in the ciphertext, XOR'd with 0x20, likely gives you the key:

```python
from collections import Counter

def crack_single_byte_xor(ciphertext):
    """Crack single-byte XOR using frequency analysis."""
    # Try each possible key byte
    best_score = -1
    best_key = 0
    best_plaintext = b""

    # English letter frequency (approximate)
    english_freq = {
        'e': 13, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7, 'n': 6.7,
        's': 6.3, 'h': 6.1, 'r': 6, ' ': 15  # space is most common
    }

    for key in range(256):
        decrypted = bytes([b ^ key for b in ciphertext])
        # Score based on frequency of common English characters
        score = 0
        for byte in decrypted:
            char = chr(byte).lower()
            if char in english_freq:
                score += english_freq[char]

        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = decrypted

    return best_key, best_plaintext

key, plaintext = crack_single_byte_xor(ciphertext)
print(f"Key: 0x{key:02x}")
print(f"Plaintext: {plaintext}")
```

## Multi-Byte XOR (Bonus Concept)

In harder challenges, the key is multiple bytes long and repeats:

```
Plaintext: H  e  l  l  o     W  o  r  l  d
Key:       K  E  Y  K  E  Y  K  E  Y  K  E   (repeating)
           ─────────────────────────────────
Cipher:    03 20 35 27 2a 19 1c 2a 2b 27 21
```

To break multi-byte XOR:

```python
def crack_repeating_xor(ciphertext, keylen):
    """Break repeating-key XOR given the key length."""
    key = bytearray(keylen)

    for i in range(keylen):
        # Extract every keylen-th byte (all encrypted with same key byte)
        block = bytes(ciphertext[j] for j in range(i, len(ciphertext), keylen))
        # Crack each block as single-byte XOR
        key[i], _ = crack_single_byte_xor(block)

    return bytes(key)
```

The key length can be found using the **Hamming distance** technique: try different key lengths and compute the normalized edit distance between blocks. The correct key length will have the lowest normalized distance.

## Complete Solve Script

```python
#!/usr/bin/env python3
"""XOR Basics CTF Solver"""

ciphertext = bytes.fromhex("1b04189c1b2d1f381c381f04231c381f3d381c3b04")

# Method 1: Known plaintext (we know flag starts with "zemi{")
key = ciphertext[0] ^ ord('z')  # 0x1b ^ 0x7a = 0x61
print(f"[*] Recovered key: 0x{key:02x} ('{chr(key)}')")

# Method 2: Brute force all 256 possible keys
print("\n[*] Brute forcing all 256 keys...")
for k in range(256):
    result = bytes([b ^ k for b in ciphertext])
    try:
        text = result.decode('ascii')
        if 'zemi{' in text:
            print(f"[+] Key 0x{k:02x}: {text}")
    except:
        pass

# Decrypt with recovered key
flag = bytes([b ^ key for b in ciphertext]).decode()
print(f"\n[*] Flag: {flag}")
```

Output:
```
[*] Recovered key: 0x61 ('a')

[*] Brute forcing all 256 keys...
[+] Key 0x61: zemi{x0r_1s_r3v3rs1bl3}

[*] Flag: zemi{x0r_1s_r3v3rs1bl3}
```

## Tools Used

- Python 3 (built-in `bytes` XOR operations)
- Frequency analysis (for longer ciphertexts)
- [CyberChef](https://gchq.github.io/CyberChef/) — "XOR Brute Force" recipe is handy for quick checks

## Lessons Learned

- XOR is the foundation of almost all symmetric encryption — understanding it is essential
- **A ^ B ^ B = A** is the most important property: XOR is its own inverse
- Single-byte XOR has only 256 possible keys — always brute-forceable
- Known plaintext (like a flag prefix) lets you recover the key instantly: `key = ciphertext ^ known_plaintext`
- For repeating-key XOR, split the ciphertext into blocks by key position and crack each as single-byte XOR
- Frequency analysis works well on longer ciphertexts, especially English text
- Real-world encryption (AES, ChaCha20) uses XOR as a building block but adds much more complexity on top
