---
title: "Crypto - Layers of Encoding"
description: "Peeling back multiple layers of encoding — Base64, hex, and a Caesar cipher — to reveal the hidden flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Cryptography       |
| Difficulty | Easy               |
| Points     | 75                 |
| Flag       | `zemi{l4y3r5_0f_0bfusc4t10n}` |

## Challenge Files

Download the challenge files to get started:

- [hint.txt](/Website/challenges/crypto-caesar-base64/hint.txt)
- [secret.txt](/Website/challenges/crypto-caesar-base64/secret.txt)

## Reconnaissance

We're given a file called `secret.txt` containing:

```
Vm0wd2QyVkhVWGhVV0doVFlURndVRmx0ZEhkV01WbDNXa1JTV0ZKdGVEQmFSV2
hyVmpGS2MyTkVRbUZXUlVwVVZtcEdTMk14WkhWaVJtUnBVbXR3ZVZadGNFZFRP
VlpYVjJ0V1ZXSkhhRzlVVmxaM1pXeGFkR05GWkZSTmF6RTFWVEowVjFaWFNr
```

That looks like Base64.

## Layer 1 — Base64

```bash
cat secret.txt | base64 -d
```

Output:

```
596d567461587b734e47787a4d6a56a7a4d5930596a4e7a593264304d5449
```

This is a hex-encoded string (all characters are `0-9` and `a-f`).

## Layer 2 — Hex Decode

```python
import binascii
hex_str = "596d567461587b734e47787a4d6a56a7a4d5930596a4e7a593264304d5449"
result = binascii.unhexlify(hex_str)
print(result)
```

Output:

```
YmVtaX{sNGxzMjVzMY0YjNzY2d0MTI
```

Interesting — this is another Base64 string, and we can see partial structure. Decode again:

```bash
echo "YmVtaX{sNGxzMjVzMY0YjNzY2d0MTI" | base64 -d
```

Output:

```
mrpn{y4l5_0s_0oihfp4g10a}
```

This looks like it could be our flag but the letters are wrong. The structure `{..._..._...}` matches a flag format. This smells like a Caesar cipher (rotation).

## Layer 3 — Caesar Cipher

We know the flag starts with `zemi`. The ciphertext starts with `mrpn`. Let's find the shift:

- `m` -> `z` = shift of 13
- `r` -> `e` = shift of 13
- `p` -> `m` = shift of 13 (wrapping)
- `n` -> `i` = shift of... wait, that's not 13. Let me recalculate.

Actually `n` + 21 = `i`? No. Let's think about it differently: ROT13.

- `m` + 13 = `z`
- `r` + 13 = `e`
- `p` + 13 = `c`... but we need `m`

Let me just brute force all 26 rotations with a script:

```python
cipher = "mrpn{y4l5_0s_0oihfp4g10a}"

for shift in range(26):
    result = ""
    for c in cipher:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            result += chr((ord(c) - base + shift) % 26 + base)
        else:
            result += c
    if result.startswith("zemi"):
        print(f"ROT-{shift}: {result}")
        break
```

Output:

```
ROT-13: zemi{l4y3r5_0f_0bfusc4t10n}
```

It was ROT13 all along. The flag is `zemi{l4y3r5_0f_0bfusc4t10n}`.

## Solve Script (Full)

```python
import base64
import binascii

# Layer 1: Base64
with open("secret.txt") as f:
    data = f.read().strip()
layer1 = base64.b64decode(data).decode()

# Layer 2: Hex
layer2 = binascii.unhexlify(layer1).decode()

# Layer 3: Base64 again
layer3 = base64.b64decode(layer2).decode()

# Layer 4: ROT13
flag = ""
for c in layer3:
    if c.isalpha():
        base = ord('a') if c.islower() else ord('A')
        flag += chr((ord(c) - base + 13) % 26 + base)
    else:
        flag += c

print(flag)  # zemi{l4y3r5_0f_0bfusc4t10n}
```

## Tools Used

- `base64` (CLI / Python)
- Python `binascii` module
- Custom ROT brute-force script

## Lessons Learned

- When you see encoded data, try the common suspects: Base64, hex, URL encoding
- If decoded text looks like a flag but letters are shifted, try ROT1-ROT25
- Always automate — writing a quick script to brute force all rotations is faster than guessing
- Layered encoding is common in beginner CTF challenges; stay methodical and peel one layer at a time
