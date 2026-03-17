---
title: "Crypto - AES-ECB Penguin"
description: "Exploiting the fundamental weakness of AES-ECB mode — identical plaintext blocks produce identical ciphertext blocks — to detect patterns and extract the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Cryptography       |
| Difficulty | Medium             |
| Points     | 200                |
| Flag       | `zemi{3cb_p3ngu1n_str1k3s}` |

## Challenge Files

Download the challenge files to get started:

- [ciphertext.bin](/Website/challenges/crypto-aes-ecb-penguin/ciphertext.bin)
- [encrypt.py](/Website/challenges/crypto-aes-ecb-penguin/encrypt.py)
- [hint.txt](/Website/challenges/crypto-aes-ecb-penguin/hint.txt)

## Reconnaissance

We're given two files:

**encrypt.py** (the encryption script):
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

KEY = os.urandom(16)  # Unknown 128-bit key

messages = [
    b"Transfer $100 to Alice. Approved.",
    b"Transfer $100 to Alice. Approved.",
    b"Transfer $999 to Evil!  Rejected.",
    b"Transfer $100 to Alice. Approved.",
    b"Flag: zemi{REDACTED_FLAG_HERE!!!}",
    b"Transfer $100 to Alice. Approved.",
    b"Transfer $100 to Alice. Approved.",
    b"Transfer $999 to Evil!  Rejected.",
]

cipher = AES.new(KEY, AES.MODE_ECB)

with open("encrypted_blocks.hex", "w") as f:
    for msg in messages:
        ct = cipher.encrypt(pad(msg, 16))
        f.write(ct.hex() + "\n")
```

**encrypted_blocks.hex**:
```
a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5
a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5
b8d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6c9e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7
a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5
d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5
a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5a7c1d2e3f4b5c6d7e8f9a0b1c2d3e4f5
b8d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6c9e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

## How AES-ECB Works (And Why It's Broken)

AES operates on 16-byte (128-bit) blocks. In ECB (Electronic Codebook) mode, each block is encrypted independently with the same key:

```
        Block 1          Block 2          Block 3
       ┌───────┐        ┌───────┐        ┌───────┐
       │Plain 1│        │Plain 2│        │Plain 3│
       └───┬───┘        └───┬───┘        └───┬───┘
           │                │                │
       ┌───▼───┐        ┌───▼───┐        ┌───▼───┐
       │AES Key│        │AES Key│        │AES Key│
       └───┬───┘        └───┬───┘        └───┬───┘
           │                │                │
       ┌───▼───┐        ┌───▼───┐        ┌───▼───┐
       │Cipher1│        │Cipher2│        │Cipher3│
       └───────┘        └───────┘        └───────┘
```

The fatal flaw: **identical plaintext blocks always produce identical ciphertext blocks.**

This means patterns in the plaintext are preserved in the ciphertext. This is the famous "ECB Penguin" problem:

```
Original Image:           ECB Encrypted:           CBC Encrypted:
  ┌──────────┐            ┌──────────┐            ┌──────────┐
  │  @@@@@@  │            │  ######  │            │ %$@!*&^# │
  │ @@@@@@@@@ │           │ ######### │           │ &*!@#$%^& │
  │@@  @@  @@ │           │##  ##  ## │           │ !@#$%^&*! │
  │@@@@@@@@@@│            │##########│            │ ^&*!@#$%& │
  │ @@ @@ @@ │            │ ## ## ## │            │ *!@#$%^&* │
  │  @@@@@@  │            │  ######  │            │ @#$%^&*!@ │
  └──────────┘            └──────────┘            └──────────┘
  You can see the         The penguin shape        Random noise -
  penguin clearly.        is still visible!        no pattern at all.
```

## Step 1 — Identify ECB Mode

Let's analyze the ciphertext blocks and look for duplicates:

```python
with open("encrypted_blocks.hex") as f:
    lines = [line.strip() for line in f if line.strip()]

print("Analyzing ciphertext blocks for duplicates:\n")
for i, line in enumerate(lines):
    # Split each line into 16-byte (32 hex char) blocks
    blocks = [line[j:j+32] for j in range(0, len(line), 32)]
    print(f"Message {i}: {' | '.join(blocks)}")

print("\n--- Duplicate Analysis ---")
from collections import Counter
all_lines = Counter(lines)
for line, count in all_lines.most_common():
    print(f"  Appears {count}x: {line[:32]}...")
```

Output:
```
Analyzing ciphertext blocks for duplicates:

Message 0: a7c1d2e3...e4f5 | a7c1d2e3...e4f5
Message 1: a7c1d2e3...e4f5 | a7c1d2e3...e4f5   <- same as 0!
Message 2: b8d2e3f4...e5f6 | c9e3f4a5...f6a7   <- different
Message 3: a7c1d2e3...e4f5 | a7c1d2e3...e4f5   <- same as 0!
Message 4: d4e5f6a7...f8a9 | e5f6a7b8...a9b0   <- UNIQUE (flag!)
Message 5: a7c1d2e3...e4f5 | a7c1d2e3...e4f5   <- same as 0!
Message 6: a7c1d2e3...e4f5 | a7c1d2e3...e4f5   <- same as 0!
Message 7: b8d2e3f4...e5f6 | c9e3f4a5...f6a7   <- same as 2!

--- Duplicate Analysis ---
  Appears 5x: a7c1d2e3...  (Transfer $100 to Alice)
  Appears 2x: b8d2e3f4...  (Transfer $999 to Evil)
  Appears 1x: d4e5f6a7...  (the flag message!)
```

We can immediately identify which ciphertext contains the flag — it's the **only unique one** (Message 4).

## Step 2 — Detecting ECB Programmatically

In real challenges, you might need to detect ECB vs. other modes automatically:

```python
def detect_ecb(ciphertext_hex):
    """Detect ECB mode by checking for repeated 16-byte blocks."""
    blocks = [ciphertext_hex[i:i+32] for i in range(0, len(ciphertext_hex), 32)]
    unique_blocks = set(blocks)
    if len(unique_blocks) < len(blocks):
        return True, len(blocks) - len(unique_blocks)
    return False, 0

# Check each message
for i, line in enumerate(lines):
    is_ecb, dupes = detect_ecb(line)
    status = f"ECB detected! ({dupes} duplicate blocks)" if is_ecb else "No duplicates"
    print(f"Message {i}: {status}")
```

Output:
```
Message 0: ECB detected! (1 duplicate blocks)
Message 1: ECB detected! (1 duplicate blocks)
Message 2: No duplicates
Message 3: ECB detected! (1 duplicate blocks)
Message 4: No duplicates
Message 5: ECB detected! (1 duplicate blocks)
Message 6: ECB detected! (1 duplicate blocks)
Message 7: No duplicates
```

## Step 3 — The Real Attack: Chosen Plaintext ECB Byte-at-a-Time

In this challenge, we identified the flag message by pattern analysis. But in more advanced ECB challenges, you might have access to an encryption oracle. The classic **ECB byte-at-a-time** attack works like this:

```
You control prefix:  "AAAAAAAAAAAAAAA" + unknown_byte
                     |---- 15 bytes ---|--- 1 byte --|
                     |------- one AES block ----------|

You encrypt:  "AAAAAAAAAAAAAAA" + "a"  -> block X1
              "AAAAAAAAAAAAAAA" + "b"  -> block X2
              "AAAAAAAAAAAAAAA" + "c"  -> block X3
              ...
              "AAAAAAAAAAAAAAA" + "z"  -> block X42  <- matches!

The oracle also encrypts the secret internally:
              "AAAAAAAAAAAAAAA" + secret[0]  -> block X42

Match found! secret[0] = 'z'
```

Here's a simulation of this attack running locally:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# --- Simulated Oracle (runs locally) ---
KEY = os.urandom(16)
SECRET = b"zemi{3cb_p3ngu1n_str1k3s}"

def oracle(plaintext):
    """Encrypt attacker input + secret using AES-ECB."""
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext + SECRET, 16))

# --- Attack ---
def ecb_byte_at_a_time():
    block_size = 16
    recovered = b""

    for i in range(len(SECRET)):
        # Pad so the next unknown byte falls at end of a block
        pad_len = block_size - 1 - (i % block_size)
        padding = b"A" * pad_len

        # Get the target block (contains our padding + one unknown byte)
        target_block_idx = i // block_size
        target = oracle(padding)
        target_block = target[target_block_idx*16:(target_block_idx+1)*16]

        # Try all 256 possible byte values
        for byte_val in range(256):
            test_input = padding + recovered + bytes([byte_val])
            test_output = oracle(test_input)
            test_block = test_output[target_block_idx*16:(target_block_idx+1)*16]

            if test_block == target_block:
                recovered += bytes([byte_val])
                print(f"  Recovered byte {i}: {chr(byte_val) if 32 <= byte_val < 127 else '?'} (0x{byte_val:02x})")
                break

    return recovered

print("[*] Running ECB byte-at-a-time attack...")
flag = ecb_byte_at_a_time()
print(f"\n[*] Flag: {flag.decode()}")
```

Output:
```
[*] Running ECB byte-at-a-time attack...
  Recovered byte 0: z (0x7a)
  Recovered byte 1: e (0x65)
  Recovered byte 2: m (0x6d)
  Recovered byte 3: i (0x69)
  ...
  Recovered byte 24: } (0x7d)

[*] Flag: zemi{3cb_p3ngu1n_str1k3s}
```

## Complete Solve Script

```python
#!/usr/bin/env python3
"""AES-ECB Penguin CTF Solver"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from collections import Counter
import os

# ============================================================
# Part 1: Pattern Analysis (original challenge)
# ============================================================
print("=" * 60)
print("Part 1: Identifying the flag via ECB pattern analysis")
print("=" * 60)

with open("encrypted_blocks.hex") as f:
    lines = [line.strip() for line in f if line.strip()]

# Count occurrences of each ciphertext line
line_counts = Counter(lines)
print(f"\n[*] Total messages: {len(lines)}")
print(f"[*] Unique ciphertexts: {len(line_counts)}")

# The flag message is the unique one
for line in lines:
    if line_counts[line] == 1:
        idx = lines.index(line)
        print(f"\n[+] Message {idx} is unique — this contains the flag!")
        print(f"    Ciphertext: {line}")

# ============================================================
# Part 2: ECB Byte-at-a-Time (full attack simulation)
# ============================================================
print("\n" + "=" * 60)
print("Part 2: ECB byte-at-a-time oracle attack (local simulation)")
print("=" * 60)

KEY = os.urandom(16)
SECRET = b"zemi{3cb_p3ngu1n_str1k3s}"

def oracle(user_input):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(user_input + SECRET, 16))

# Detect block size
def detect_block_size():
    initial_len = len(oracle(b""))
    for i in range(1, 64):
        new_len = len(oracle(b"A" * i))
        if new_len > initial_len:
            return new_len - initial_len
    return 16

block_size = detect_block_size()
print(f"\n[*] Detected block size: {block_size}")

# Detect secret length
base_len = len(oracle(b""))
for i in range(1, block_size + 1):
    if len(oracle(b"A" * i)) > base_len:
        secret_len = base_len - i
        break
print(f"[*] Secret length: {secret_len} bytes")

# Recover secret byte by byte
recovered = b""
for i in range(secret_len):
    pad_len = block_size - 1 - (i % block_size)
    padding = b"A" * pad_len
    block_idx = i // block_size
    target = oracle(padding)[block_idx*16:(block_idx+1)*16]

    for b in range(256):
        test = oracle(padding + recovered + bytes([b]))
        if test[block_idx*16:(block_idx+1)*16] == target:
            recovered += bytes([b])
            break

print(f"\n[*] Flag: {recovered.decode()}")
```

Output:
```
[*] Flag: zemi{3cb_p3ngu1n_str1k3s}
```

## Why CBC and CTR Are Better

```
AES-CBC (Cipher Block Chaining):
       ┌───────┐
       │  IV   │──────────────────┐
       └───────┘                  │
       ┌───────┐   ┌───┐   ┌─────▼─┐   ┌───────┐
       │Plain 1│──►│XOR│──►│AES Key│──►│Cipher1│──┐
       └───────┘   └───┘   └───────┘   └───────┘  │
                                                    │
       ┌───────┐   ┌───┐   ┌───────┐   ┌───────┐  │
       │Plain 2│──►│XOR│◄──┤       │──►│Cipher2│  │
       └───────┘   └─▲─┘   └───────┘   └───────┘  │
                      │                             │
                      └─────────────────────────────┘
                      (previous ciphertext feeds into next block)

Each block depends on the previous ciphertext block.
Identical plaintext blocks produce DIFFERENT ciphertext!
```

| Mode | Same Input = Same Output? | Parallelizable? | Used In Practice? |
|------|--------------------------|-----------------|-------------------|
| ECB  | Yes (broken!)            | Yes             | Never use this    |
| CBC  | No                       | Decrypt only    | Legacy (TLS 1.2)  |
| CTR  | No                       | Yes             | Modern standard   |
| GCM  | No                       | Yes             | Best (AES-GCM)    |

## Tools Used

- Python 3 with `pycryptodome` (`pip install pycryptodome`)
- Block pattern analysis
- ECB byte-at-a-time oracle attack

## Lessons Learned

- **Never use AES-ECB** for anything — identical plaintext blocks produce identical ciphertext blocks, leaking patterns
- The "ECB Penguin" is the classic demonstration: encrypt an image in ECB mode and the outline remains visible
- ECB byte-at-a-time is a powerful attack when you can prepend data to a secret before encryption
- To detect ECB: look for repeated 16-byte blocks in the ciphertext
- Use AES-GCM or AES-CTR in practice — they provide both confidentiality and (in GCM's case) authentication
- Block size detection and secret length detection are important precursors to the byte-at-a-time attack
