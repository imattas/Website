---
title: "Crypto - Padding Oracle Attack"
description: "Implementing a CBC padding oracle attack from scratch — exploiting PKCS#7 padding validation to decrypt ciphertext byte by byte without the key."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Cryptography       |
| Difficulty | Hard               |
| Points     | 400                |
| Flag       | `zemi{p4dd1ng_0r4cl3_cr4ck}` |

## Challenge Files

Download the challenge files to get started:

- [ciphertext.hex](/Website/challenges/crypto-padding-oracle/ciphertext.hex)
- [hint.txt](/Website/challenges/crypto-padding-oracle/hint.txt)
- [oracle.py](/Website/challenges/crypto-padding-oracle/oracle.py)

## Reconnaissance

We're given a local Python application that simulates an encrypted cookie system with a padding oracle vulnerability:

**oracle.py**:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

KEY = os.urandom(16)

def encrypt(plaintext):
    """Encrypt with AES-CBC and return IV + ciphertext."""
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, 16))
    return iv + ct  # IV prepended to ciphertext

def decrypt_and_check(data):
    """
    Decrypt and check padding.
    Returns True if padding is valid, False otherwise.
    THIS IS THE ORACLE - it leaks padding validity!
    """
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    try:
        plaintext = cipher.decrypt(ct)
        unpad(plaintext, 16)  # Raises ValueError if padding invalid
        return True  # Valid padding
    except ValueError:
        return False  # Invalid padding

# Encrypt the flag
FLAG = b"zemi{p4dd1ng_0r4cl3_cr4ck}"
encrypted = encrypt(FLAG)

print(f"Encrypted (hex): {encrypted.hex()}")
print(f"Length: {len(encrypted)} bytes (16 IV + {len(encrypted)-16} ciphertext)")
print()
print("Oracle available: decrypt_and_check(modified_data) -> True/False")
```

The oracle tells us whether padding is valid after decryption — nothing more. But that single bit of information is enough to decrypt the entire message.

## Background: PKCS#7 Padding

AES-CBC requires plaintext to be a multiple of 16 bytes. PKCS#7 padding fills the remaining bytes:

```
Need 1 byte  of padding: ... 01
Need 2 bytes of padding: ... 02 02
Need 3 bytes of padding: ... 03 03 03
Need 4 bytes of padding: ... 04 04 04 04
...
Need 16 bytes of padding: 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10

Example: "HELLO" (5 bytes) padded to 16 bytes:
  48 45 4C 4C 4F 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B
  H  E  L  L  O  \___________ 11 bytes of 0x0B __/
```

If the padding bytes don't follow this pattern, `unpad()` raises an error. The oracle leaks whether the padding is valid.

## Background: CBC Decryption

```
            ┌──────────┐          ┌──────────┐
            │Ciphertext│          │Ciphertext│
            │ Block 1  │          │ Block 2  │
            └────┬─────┘          └────┬─────┘
                 │    ┌────────────────┤
                 │    │                │
            ┌────▼───┐│          ┌────▼────┐
            │AES Dec ││          │ AES Dec │
            │(KEY)   ││          │ (KEY)   │
            └────┬───┘│          └────┬────┘
                 │    │               │
   ┌────┐  ┌────▼───┐│   ┌──────────▼───┐
   │ IV │─►│  XOR   ││   │     XOR      │◄── C1
   └────┘  └────┬───┘│   └──────┬───────┘
                │    │          │
            ┌───▼────┐    ┌────▼─────┐
            │Plain 1 │    │ Plain 2  │
            └────────┘    └──────────┘

The key relationship:
  P[i] = AES_Dec(C[i]) ^ C[i-1]     (where C[0] = IV)

Or equivalently:
  P[i] = Intermediate[i] ^ C[i-1]
  where Intermediate[i] = AES_Dec(C[i])
```

## The Attack: How a Padding Oracle Leaks Everything

### Core Insight

We want to find `Intermediate[i] = AES_Dec(C[i])`. Once we know the intermediate value, we can XOR it with `C[i-1]` to get the plaintext.

We control `C[i-1]` (or the IV for the first block). By modifying it and checking if padding is valid, we can determine the intermediate bytes one at a time.

### Decrypting the Last Byte

```
We want the last byte of plaintext to be 0x01 (valid padding).

  P[last] = Intermediate[last] ^ C'[i-1][last]

For P[last] = 0x01:
  0x01 = Intermediate[last] ^ C'[i-1][last]
  Intermediate[last] = 0x01 ^ C'[i-1][last]

We brute force C'[i-1][last] from 0x00 to 0xFF.
When the oracle says "valid padding", we found it!

  Intermediate[last] = 0x01 ^ C'[i-1][last]
  P[last] = Intermediate[last] ^ original_C[i-1][last]
```

### Decrypting the Second-to-Last Byte

Now we know `Intermediate[last]`. We set the last byte to produce `0x02` (for 2-byte padding `02 02`), and brute force the second-to-last byte:

```
For 0x02 padding:
  C'[i-1][last]   = Intermediate[last]   ^ 0x02  (forces last byte = 0x02)
  C'[i-1][last-1] = ??? (brute force 0x00-0xFF)

When oracle says valid:
  Intermediate[last-1] = 0x02 ^ C'[i-1][last-1]
```

### Visual: Byte-by-Byte Recovery

```
Round 1: Find last byte          Round 2: Find byte 14
┌─────────────────────────┐      ┌─────────────────────────┐
│ ? ? ? ? ? ? ? ? ? ? ? ? │      │ ? ? ? ? ? ? ? ? ? ? ? ? │
│ ? ? ? ?  [brute] [????] │      │ ? ? ? ?  [brute] [0x02] │
│                    ▲     │      │            ▲       ▲     │
│                    │     │      │            │    set to    │
│              try 0-255   │      │       try 0-255  produce │
│              until valid │      │       until valid  0x02  │
│              padding 01  │      │       padding 02 02     │
└─────────────────────────┘      └─────────────────────────┘

Round 3: Find byte 13          ...continue for all 16 bytes
┌─────────────────────────┐
│ ? ? ? ? ? ? ? ? ? ? ? ? │
│ ? ? ?  [brute][02] [02] │
│           ▲              │
│      try 0-255           │
│      padding 03 03 03    │
└─────────────────────────┘
```

## Step 1 — Implement the Oracle Locally

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

KEY = os.urandom(16)

def encrypt_flag():
    flag = b"zemi{p4dd1ng_0r4cl3_cr4ck}"
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(flag, 16))
    return iv + ct

def padding_oracle(data):
    """Returns True if padding is valid after CBC decryption."""
    iv, ct = data[:16], data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    try:
        pt = cipher.decrypt(ct)
        unpad(pt, 16)
        return True
    except ValueError:
        return False

encrypted = encrypt_flag()
print(f"[*] Encrypted data: {encrypted.hex()}")
print(f"[*] Total length: {len(encrypted)} bytes")
```

## Step 2 — Implement the Attack

```python
def attack_block(prev_block, target_block, oracle_fn):
    """
    Decrypt one 16-byte block using the padding oracle.

    prev_block:   The block before target_block (IV or previous ciphertext block)
    target_block: The block to decrypt
    oracle_fn:    Function that returns True if padding is valid
    """
    block_size = 16
    intermediate = bytearray(block_size)
    plaintext = bytearray(block_size)

    for byte_pos in range(block_size - 1, -1, -1):
        padding_value = block_size - byte_pos  # 0x01, 0x02, ..., 0x10

        # Construct the prefix: set already-known bytes to produce desired padding
        crafted = bytearray(block_size)
        for k in range(byte_pos + 1, block_size):
            crafted[k] = intermediate[k] ^ padding_value

        # Brute force the current byte
        found = False
        for guess in range(256):
            crafted[byte_pos] = guess
            test_data = bytes(crafted) + target_block

            if oracle_fn(test_data):
                # Handle false positive for byte_pos == 15 (padding 0x01)
                # by also checking that flipping byte_pos-1 still gives valid padding
                if byte_pos == block_size - 1 and padding_value == 1:
                    check = bytearray(crafted)
                    check[byte_pos - 1] ^= 0x01
                    if not oracle_fn(bytes(check) + target_block):
                        continue

                intermediate[byte_pos] = guess ^ padding_value
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                found = True

                char = chr(plaintext[byte_pos]) if 32 <= plaintext[byte_pos] < 127 else '.'
                print(f"    Byte {byte_pos:2d}: intermediate=0x{intermediate[byte_pos]:02x}, "
                      f"plaintext=0x{plaintext[byte_pos]:02x} ('{char}')")
                break

        if not found:
            print(f"    [-] Failed to find byte {byte_pos}")
            return None

    return bytes(plaintext)
```

## Step 3 — Decrypt All Blocks

```python
def padding_oracle_attack(encrypted, oracle_fn):
    """Full padding oracle attack on AES-CBC encrypted data."""
    block_size = 16
    blocks = [encrypted[i:i+block_size] for i in range(0, len(encrypted), block_size)]

    # blocks[0] = IV
    # blocks[1:] = ciphertext blocks

    plaintext = b""
    for i in range(1, len(blocks)):
        print(f"\n[*] Attacking block {i} of {len(blocks)-1}...")
        prev = blocks[i-1]
        target = blocks[i]
        pt_block = attack_block(prev, target, oracle_fn)

        if pt_block is None:
            print(f"[-] Attack failed on block {i}")
            return None

        plaintext += pt_block

    # Remove PKCS#7 padding from final plaintext
    pad_len = plaintext[-1]
    if all(b == pad_len for b in plaintext[-pad_len:]):
        plaintext = plaintext[:-pad_len]

    return plaintext
```

## Complete Solve Script

```python
#!/usr/bin/env python3
"""
CBC Padding Oracle Attack - CTF Solver

Decrypts AES-CBC ciphertext using only a padding validity oracle.
Everything runs locally - no network required.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import sys

# ============================================================
# Local Oracle Setup
# ============================================================
KEY = os.urandom(16)
oracle_calls = 0

def encrypt_flag():
    flag = b"zemi{p4dd1ng_0r4cl3_cr4ck}"
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(flag, 16))

def padding_oracle(data):
    """The oracle: returns True if CBC decryption produces valid PKCS#7 padding."""
    global oracle_calls
    oracle_calls += 1
    iv, ct = data[:16], data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    try:
        unpad(cipher.decrypt(ct), 16)
        return True
    except ValueError:
        return False

# ============================================================
# The Attack
# ============================================================
def attack_block(prev_block, target_block, oracle_fn):
    """Decrypt one 16-byte block via padding oracle."""
    intermediate = bytearray(16)
    plaintext = bytearray(16)

    for pos in range(15, -1, -1):
        pad_val = 16 - pos

        # Set up known bytes to produce desired padding
        crafted = bytearray(16)
        for k in range(pos + 1, 16):
            crafted[k] = intermediate[k] ^ pad_val

        for guess in range(256):
            crafted[pos] = guess

            if oracle_fn(bytes(crafted) + target_block):
                # Validate: ensure it's not a false positive on the last byte
                if pos == 15:
                    verify = bytearray(crafted)
                    verify[14] ^= 0x01
                    if not oracle_fn(bytes(verify) + target_block):
                        continue

                intermediate[pos] = guess ^ pad_val
                plaintext[pos] = intermediate[pos] ^ prev_block[pos]
                break

    return bytes(plaintext)

def full_attack(encrypted, oracle_fn):
    """Decrypt all blocks."""
    blocks = [encrypted[i:i+16] for i in range(0, len(encrypted), 16)]
    result = b""

    for i in range(1, len(blocks)):
        print(f"[*] Decrypting block {i}/{len(blocks)-1}...")
        pt = attack_block(blocks[i-1], blocks[i], oracle_fn)
        result += pt

        # Show progress
        preview = ""
        for b in pt:
            preview += chr(b) if 32 <= b < 127 else "."
        print(f"    -> {preview}")

    # Remove padding
    pad_len = result[-1]
    if 1 <= pad_len <= 16 and all(b == pad_len for b in result[-pad_len:]):
        result = result[:-pad_len]

    return result

# ============================================================
# Run
# ============================================================
print("=" * 55)
print("  CBC Padding Oracle Attack (Local Simulation)")
print("=" * 55)

encrypted = encrypt_flag()
num_ct_blocks = (len(encrypted) - 16) // 16
print(f"\n[*] Ciphertext: {encrypted.hex()}")
print(f"[*] IV + {num_ct_blocks} ciphertext block(s) = {len(encrypted)} bytes")

print(f"\n[*] Starting padding oracle attack...\n")
plaintext = full_attack(encrypted, padding_oracle)

print(f"\n[+] Decrypted: {plaintext.decode()}")
print(f"[+] Oracle calls: {oracle_calls}")
print(f"[+] (Theoretical max: {num_ct_blocks * 16 * 256} = {num_ct_blocks} blocks * 16 bytes * 256 guesses)")
```

Output:
```
=========================================================
  CBC Padding Oracle Attack (Local Simulation)
=========================================================

[*] Ciphertext: 4a8b...f3d2
[*] IV + 2 ciphertext block(s) = 48 bytes

[*] Starting padding oracle attack...

[*] Decrypting block 1/2...
    -> zemi{p4dd1ng_0r4
[*] Decrypting block 2/2...
    -> cl3_cr4ck}......

[+] Decrypted: zemi{p4dd1ng_0r4cl3_cr4ck}
[+] Oracle calls: 7841
[+] (Theoretical max: 8192 = 2 blocks * 16 bytes * 256 guesses)
```

## Real-World Impact

The padding oracle attack (CVE-2014-3566, CVE-2016-2107, and many others) has broken:

| System | CVE / Name | Year |
|--------|-----------|------|
| ASP.NET | CVE-2010-3332 ("POET") | 2010 |
| TLS/SSL | POODLE (SSLv3) | 2014 |
| OpenSSL | CVE-2016-2107 (Lucky13 variant) | 2016 |
| Java CBC | Various | Multiple |

The attack typically requires ~256 oracle queries per byte (worst case), making it very practical:
- 16-byte block = max 4096 queries per block
- 32-byte plaintext = max 8192 queries total
- Even over a network, this completes in seconds to minutes

## Defenses

```
BAD:  Decrypt, check padding, return different errors
      -> Padding oracle!

BAD:  Decrypt, check padding, same error but different timing
      -> Timing-based padding oracle!

GOOD: Use authenticated encryption (AES-GCM, ChaCha20-Poly1305)
      -> Verify MAC BEFORE decryption. Tampered ciphertext is
         rejected without ever attempting decryption.

GOOD: Use Encrypt-then-MAC (EtM)
      -> MAC covers the ciphertext. Any modification is detected
         before decryption.
```

## Tools Used

- Python 3 with `pycryptodome` (`pip install pycryptodome`)
- Custom padding oracle attack implementation
- [PadBuster](https://github.com/AonCyberLabs/PadBuster) — Perl tool that automates padding oracle attacks
- [python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle) — Python framework for padding oracle attacks

## Lessons Learned

- A padding oracle is any system that reveals whether CBC decryption produced valid PKCS#7 padding
- The oracle can be explicit (different error messages) or implicit (timing differences, behavior changes)
- The attack recovers plaintext without knowing the key, one byte at a time, using at most 256 queries per byte
- **Understanding CBC decryption is essential**: `Plaintext[i] = AES_Dec(Ciphertext[i]) ^ Ciphertext[i-1]`
- The intermediate value `AES_Dec(C[i])` is the real target — once known, XOR with the previous block gives plaintext
- False positives can occur on the last byte (e.g., `...02 02` is valid padding for pad_val=1 if those happen to be valid) — always verify
- The fix is authenticated encryption: verify integrity BEFORE decrypting (AES-GCM, ChaCha20-Poly1305)
- Never roll your own crypto — use well-tested libraries with authenticated encryption modes
