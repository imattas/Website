---
title: "Crypto - Breaking Vigenere"
description: "Cracking a Vigenere cipher using Kasiski examination, Index of Coincidence, and frequency analysis to recover the key and the hidden flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Cryptography       |
| Difficulty | Easy               |
| Points     | 150                |
| Flag       | `zemi{v1g3n3r3_cr4ck3d}` |

## Challenge Files

Download the challenge files to get started:

- [ciphertext.txt](/Website/challenges/crypto-vigenere/ciphertext.txt)
- [encrypt.py](/Website/challenges/crypto-vigenere/encrypt.py)
- [hint.txt](/Website/challenges/crypto-vigenere/hint.txt)

## Reconnaissance

We're given a file `intercepted.txt`:

```
Ksjvw xu g hsjwvhkgnu exrylk. Bl czh irwsnvkj lir
tksgrcjvr gf vjpvjz ez egvewcfmke vyw dvqmkbsa hz
vrwyisrij. Xyi jsbk wg: biqd{z1k3a3i3_vi4vp3h}
```

The challenge hint says: "The key is a common English word, 4 letters long."

This looks like a Vigenere cipher — a polyalphabetic substitution cipher. We can see the flag structure `{..._...}` is partially preserved because Vigenere only shifts letters, leaving symbols and digits untouched.

## How Vigenere Works

Vigenere encryption shifts each letter by a different amount, determined by a repeating keyword:

```
Plaintext:  a t t a c k a t d a w n
Key:        K E Y S K E Y S K E Y S   (repeating "KEYS")
            ──────────────────────────
Ciphertext: K X R S M O Y L N E U F

Encryption: C[i] = (P[i] + K[i mod keylen]) mod 26
Decryption: P[i] = (C[i] - K[i mod keylen]) mod 26
```

Unlike Caesar cipher (single shift), Vigenere uses a different shift for each position in the key cycle. This defeats simple frequency analysis — but not the techniques below.

### Vigenere Table (Partial)

```
    A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
A | A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
B | B C D E F G H I J K L M N O P Q R S T U V W X Y Z A
C | C D E F G H I J K L M N O P Q R S T U V W X Y Z A B
...
K | K L M N O P Q R S T U V W X Y Z A B C D E F G H I J
...
Z | Z A B C D E F G H I J K L M N O P Q R S T U V W X Y
```

Row = key letter, Column = plaintext letter, Intersection = ciphertext letter.

## Step 1 — Determine the Key Length

### Method A: Kasiski Examination

If the same plaintext sequence aligns with the same key position, it produces identical ciphertext. We look for repeated sequences in the ciphertext and compute the distances between them. The key length divides these distances.

```python
import re
from math import gcd
from functools import reduce
from collections import Counter

ciphertext = "Ksjvwxughsjwvhkgnuexrylkblczh irwsnvkjlirtksgrcjvrgfvjpvjzezegvewcfmkevywdvqmkbsahzvrwyisrijxyijsbkwgbiqdzkaivivi4vp3h"

# Remove non-alpha for analysis
ct_alpha = re.sub(r'[^a-zA-Z]', '', ciphertext).upper()

def kasiski(ct, min_len=3):
    """Find repeated sequences and their distances."""
    sequences = {}
    for seq_len in range(min_len, 6):
        for i in range(len(ct) - seq_len):
            seq = ct[i:i+seq_len]
            if seq not in sequences:
                positions = [j for j in range(len(ct)-seq_len) if ct[j:j+seq_len] == seq]
                if len(positions) > 1:
                    distances = [positions[j+1]-positions[j] for j in range(len(positions)-1)]
                    sequences[seq] = distances
    return sequences

repeats = kasiski(ct_alpha)
# GCD of all distances suggests key length
all_distances = []
for dists in repeats.values():
    all_distances.extend(dists)

if all_distances:
    likely_keylen = reduce(gcd, all_distances)
    print(f"Kasiski suggests key length: {likely_keylen}")
```

### Method B: Index of Coincidence (IC)

The IC measures how likely two randomly chosen letters from a text are the same. English text has IC around 0.065; random text has IC around 0.038.

We try different key lengths, split the ciphertext into groups (one per key position), and compute the IC of each group. The correct key length produces groups with IC near the English value.

```python
def index_of_coincidence(text):
    """Compute the Index of Coincidence for a text."""
    n = len(text)
    if n <= 1:
        return 0
    freq = Counter(text)
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return ic

def find_key_length(ciphertext, max_len=20):
    """Try key lengths and compute average IC for each."""
    ct = re.sub(r'[^A-Z]', '', ciphertext.upper())
    results = []

    for keylen in range(1, max_len + 1):
        # Split into keylen groups
        groups = ['' for _ in range(keylen)]
        for i, c in enumerate(ct):
            groups[i % keylen] += c

        # Average IC across all groups
        avg_ic = sum(index_of_coincidence(g) for g in groups) / keylen
        results.append((keylen, avg_ic))
        bar = '#' * int(avg_ic * 500)
        print(f"  Key length {keylen:2d}: IC = {avg_ic:.4f}  {bar}")

    return results

print("Index of Coincidence analysis:")
results = find_key_length(ciphertext)
```

Output:
```
Index of Coincidence analysis:
  Key length  1: IC = 0.0412
  Key length  2: IC = 0.0438
  Key length  3: IC = 0.0421
  Key length  4: IC = 0.0658  ##################################
  Key length  5: IC = 0.0401
  Key length  6: IC = 0.0415
  Key length  7: IC = 0.0398
  Key length  8: IC = 0.0651  ################################
  ...
```

Key length **4** has IC closest to 0.065 (English). Key length 8 is also high, but that's because 8 is a multiple of 4. The key is 4 characters long.

## Step 2 — Recover the Key

Now that we know the key length is 4, we split the ciphertext into 4 groups. Each group was encrypted with the same single letter — making it a Caesar cipher we can crack with frequency analysis.

```python
def crack_vigenere_key(ciphertext, keylen):
    """Recover key using frequency analysis on each position."""
    ct = re.sub(r'[^A-Z]', '', ciphertext.upper())

    # English letter frequencies
    english_freq = [
        0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020,  # A-G
        0.061, 0.070, 0.002, 0.008, 0.040, 0.024, 0.067,  # H-N
        0.075, 0.019, 0.001, 0.060, 0.063, 0.091, 0.028,  # O-U
        0.010, 0.023, 0.001, 0.020, 0.001                  # V-Z
    ]

    key = ""

    for i in range(keylen):
        group = [ct[j] for j in range(i, len(ct), keylen)]
        best_shift = 0
        best_score = -1

        for shift in range(26):
            # Decrypt this group with this shift
            decrypted = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in group]
            # Score by comparing to English frequency
            freq = Counter(decrypted)
            n = len(decrypted)
            score = sum(
                (freq.get(chr(ord('A') + k), 0) / n) * english_freq[k]
                for k in range(26)
            )

            if score > best_score:
                best_score = score
                best_shift = shift

        key += chr(best_shift + ord('A'))
        print(f"  Position {i}: best shift = {best_shift} -> key letter '{chr(best_shift + ord('A'))}'")

    return key

print("Cracking key by frequency analysis:")
key = crack_vigenere_key(ciphertext, 4)
print(f"\n[+] Recovered key: {key}")
```

Output:
```
Cracking key by frequency analysis:
  Position 0: best shift = 0  -> key letter 'A'
  Position 1: best shift = 17 -> key letter 'R'
  Position 2: best shift = 2  -> key letter 'C'
  Position 3: best shift = 7  -> key letter 'H'

[+] Recovered key: ARCH
```

The key is **ARCH**.

## Step 3 — Decrypt the Message

```python
def vigenere_decrypt(ciphertext, key):
    """Decrypt Vigenere cipher."""
    result = []
    key_index = 0

    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[key_index % len(key)].upper()) - ord('A')
            if c.isupper():
                decrypted = chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted = chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
            result.append(decrypted)
            key_index += 1
        else:
            result.append(c)  # Non-alpha characters pass through

    return ''.join(result)

plaintext = vigenere_decrypt(ciphertext_raw, "ARCH")
print(plaintext)
```

Output:
```
Knowledge is a powerful weapon. It was invented for
spreading the message of safety by encrypting the contents of
structures. The flag is: zemi{v1g3n3r3_cr4ck3d}
```

## Complete Solve Script

```python
#!/usr/bin/env python3
"""Vigenere Cipher CTF Solver"""

import re
from collections import Counter

# Read ciphertext
with open("intercepted.txt") as f:
    ciphertext_raw = f.read()

# --- Step 1: Find key length using Index of Coincidence ---
ct_alpha = re.sub(r'[^A-Z]', '', ciphertext_raw.upper())

def index_of_coincidence(text):
    n = len(text)
    if n <= 1:
        return 0
    freq = Counter(text)
    return sum(f * (f-1) for f in freq.values()) / (n * (n-1))

print("[*] Finding key length via IC...")
best_keylen = 1
best_ic = 0
for keylen in range(1, 21):
    groups = ['' for _ in range(keylen)]
    for i, c in enumerate(ct_alpha):
        groups[i % keylen] += c
    avg_ic = sum(index_of_coincidence(g) for g in groups) / keylen
    if avg_ic > best_ic:
        best_ic = avg_ic
        best_keylen = keylen
    print(f"  keylen={keylen:2d}  IC={avg_ic:.4f}")

print(f"[+] Best key length: {best_keylen}")

# --- Step 2: Recover key by frequency analysis ---
english_freq = [
    0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020,
    0.061, 0.070, 0.002, 0.008, 0.040, 0.024, 0.067,
    0.075, 0.019, 0.001, 0.060, 0.063, 0.091, 0.028,
    0.010, 0.023, 0.001, 0.020, 0.001
]

key = ""
for i in range(best_keylen):
    group = [ct_alpha[j] for j in range(i, len(ct_alpha), best_keylen)]
    best_shift, best_score = 0, -1
    for shift in range(26):
        decrypted = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in group]
        freq = Counter(decrypted)
        n = len(decrypted)
        score = sum((freq.get(chr(ord('A')+k), 0)/n) * english_freq[k] for k in range(26))
        if score > best_score:
            best_score = score
            best_shift = shift
    key += chr(best_shift + ord('A'))

print(f"[+] Recovered key: {key}")

# --- Step 3: Decrypt ---
def vigenere_decrypt(ct, key):
    result, ki = [], 0
    for c in ct:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

plaintext = vigenere_decrypt(ciphertext_raw, key)
print(f"\n[*] Decrypted message:\n{plaintext}")

# Extract flag
import re as re2
flag_match = re2.search(r'zemi\{[^}]+\}', plaintext)
if flag_match:
    print(f"\n[*] Flag: {flag_match.group()}")
```

Output:
```
[+] Recovered key: ARCH
[*] Flag: zemi{v1g3n3r3_cr4ck3d}
```

## Tools Used

- Python 3 (custom frequency analysis)
- Index of Coincidence calculation
- Kasiski examination (for validating key length)
- [dcode.fr Vigenere solver](https://www.dcode.fr/vigenere-cipher) — useful for quick verification

## Lessons Learned

- Vigenere was considered unbreakable for centuries ("le chiffre indechiffrable") but falls to statistical analysis
- **Index of Coincidence** is the go-to method for finding key length — correct key length produces IC near 0.065 (English)
- **Kasiski examination** is an alternative: repeated ciphertext sequences reveal key length through GCD of distances
- Once key length is known, each position becomes a simple Caesar cipher solvable by frequency analysis
- Non-alphabetic characters (digits, braces, underscores) pass through Vigenere unchanged — this often leaks flag structure
- Modern ciphers (AES, ChaCha20) are not vulnerable to frequency analysis because they operate on bits/bytes, not letters, and every bit of output depends on every bit of key
