---
title: "Crypto - RSA for Beginners"
description: "Breaking a weak RSA implementation where the primes are too small, allowing us to factor the public modulus and decrypt the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Cryptography       |
| Difficulty | Medium             |
| Points     | 250                |
| Flag       | `zemi{sm4ll_pr1m3s_b1g_pr0bl3ms}` |

## Challenge Files

Download the challenge files to get started:

- [encrypt.py](/Website/challenges/crypto-rsa-beginner/encrypt.py)
- [output.txt](/Website/challenges/crypto-rsa-beginner/output.txt)

## Reconnaissance

We're given a file `output.txt`:

```
n = 882564595536224140639625987659416029426880322601594803649153108963399
e = 65537
c = 772005650677714658381739127873355727585727581548536571400784425246820
```

This is textbook RSA:
- `n` = public modulus (product of two primes)
- `e` = public exponent (standard value 65537)
- `c` = ciphertext (encrypted flag)

To decrypt, we need the private key `d`, which requires knowing the prime factors of `n`.

## RSA Refresher

```
Encryption: c = m^e mod n
Decryption: m = c^d mod n

Where:
  n = p * q          (p and q are large primes)
  phi = (p-1)(q-1)   (Euler's totient)
  d = e^(-1) mod phi  (modular inverse)
```

The security of RSA relies on `n` being hard to factor. But this `n` is suspiciously small — only 69 digits. Real RSA uses 2048+ bit keys (617+ digits).

## Factoring n

For small values of `n`, we can use online tools or brute force. Let's try [factordb.com](http://factordb.com) or use Python:

```python
from sympy import factorint

n = 882564595536224140639625987659416029426880322601594803649153108963399

factors = factorint(n)
print(factors)
```

```
{857504083339712752489993810777: 1, 1029224947942998075080348647219: 1}
```

So:
- `p = 857504083339712752489993810777`
- `q = 1029224947942998075080348647219`

Let's verify: `p * q == n` ✓

## Computing the Private Key

```python
p = 857504083339712752489993810777
q = 1029224947942998075080348647219
e = 65537

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)  # Modular inverse (Python 3.8+)
print(f"d = {d}")
```

## Decrypting the Flag

```python
c = 772005650677714658381739127873355727585727581548536571400784425246820

m = pow(c, d, n)  # m = c^d mod n

# Convert integer back to bytes
flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
print(flag)
```

```
zemi{sm4ll_pr1m3s_b1g_pr0bl3ms}
```

## Complete Solve Script

```python
from sympy import factorint

# Given values
n = 882564595536224140639625987659416029426880322601594803649153108963399
e = 65537
c = 772005650677714658381739127873355727585727581548536571400784425246820

# Factor n
factors = list(factorint(n).keys())
p, q = factors[0], factors[1]

# Compute private key
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# Decrypt
m = pow(c, d, n)
flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
print(flag)  # zemi{sm4ll_pr1m3s_b1g_pr0bl3ms}
```

## When RSA Gets Harder

In harder challenges, you might encounter:

| Weakness | Attack |
|----------|--------|
| Small `e` with small `m` | Cube root attack |
| Same `m` encrypted with same `e`, different `n` | Hastad's broadcast attack |
| `p` and `q` are close together | Fermat's factorization |
| Known partial plaintext | Coppersmith's attack |
| Reused `n` with different `e` | Common modulus attack |
| Very large `e` | Wiener's attack (small `d`) |

## Tools Used

- Python with `sympy` for factoring
- [factordb.com](http://factordb.com) — online factorization database
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) — automates many RSA attacks

## Lessons Learned

- RSA security depends entirely on the size of the primes
- 2048-bit keys (minimum) are the current standard; 4096-bit is recommended
- If you can factor `n`, RSA is completely broken
- `sympy.factorint()` and factordb.com can factor small numbers quickly
- Always check if `n` appears in factordb — someone may have factored it before
- `pow(base, exp, mod)` is Python's built-in modular exponentiation — very efficient
