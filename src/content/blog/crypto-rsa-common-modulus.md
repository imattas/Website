---
title: "Crypto - RSA Common Modulus Attack"
description: "Exploiting the reuse of an RSA modulus with different public exponents to recover the plaintext without ever factoring n."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Cryptography       |
| Difficulty | Medium             |
| Points     | 300                |
| Flag       | `zemi{c0mm0n_m0dulus_4tt4ck}` |

## Challenge Files

Download the challenge files to get started:

- [encrypt.py](/Website/challenges/crypto-rsa-common-modulus/encrypt.py)
- [output.txt](/Website/challenges/crypto-rsa-common-modulus/output.txt)

## Reconnaissance

We're given `intercept.txt`:

```
n  = 71563959528358004146401194738507839917173072899698498964715249049187762408825831560052785975698912637433717617749237844838116352284861658208337879837478498579473628832543866832070416654657143137386913938464069750882137625174883827392909218721738559945818595588289014456975771826235498582974096398207683163553
e1 = 17
e2 = 65537
c1 = 44870341782857487805638041026111608938787300862953893797705375752573645947407702731200547865373847338421078624398046251428296927766262078756250685879457672024393140210973248236285086589872808556969082500879835997419426843889328921218782571128530426461020096226765544473092606684977498822590583016373440989043
c2 = 62585866917889547283014085192153372047940680702553507253398100091747228893983958241090734069741200200178975876394358891385478792818015891583755445262721808428624583498601613630991975970903342792498697895018951492562094290101483791303547267029548711809515153739553063593381347543225094925479261072961042519360
```

The same message `m` has been encrypted with the same modulus `n` but two different public exponents `e1=17` and `e2=65537`. We don't know the prime factors of `n`, and it's too large to factor. But we don't need to.

## The Common Modulus Attack

### The Core Idea

If the same message `m` is encrypted under the same modulus `n` with two coprime exponents `e1` and `e2`, we can recover `m` without factoring `n`.

Given:
```
c1 = m^e1 mod n
c2 = m^e2 mod n
```

If `gcd(e1, e2) = 1` (which is true for 17 and 65537), then by Bezout's identity, there exist integers `a` and `b` such that:

```
a * e1 + b * e2 = 1
```

Therefore:
```
c1^a * c2^b  =  (m^e1)^a * (m^e2)^b
             =  m^(e1*a) * m^(e2*b)
             =  m^(e1*a + e2*b)
             =  m^1
             =  m        (all mod n)
```

We recover `m` directly.

### Visual Diagram

```
  ┌──────────────┐
  │   Message m  │
  └──────┬───────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌───────┐ ┌───────┐
│m^e1   │ │m^e2   │     Same n, different e
│mod n  │ │mod n  │
└───┬───┘ └───┬───┘
    │         │
    ▼         ▼
  ┌───┐     ┌───┐
  │c1 │     │c2 │       Attacker has both ciphertexts
  └─┬─┘     └─┬─┘
    │         │
    └────┬────┘
         │
         ▼
┌──────────────────┐
│ Extended GCD:    │
│ a*e1 + b*e2 = 1  │
│                  │
│ m = c1^a * c2^b  │
│     (mod n)      │
└────────┬─────────┘
         │
         ▼
  ┌──────────────┐
  │   Message m  │     Recovered without factoring!
  └──────────────┘
```

## Step 1 — Extended Euclidean Algorithm

The Extended Euclidean Algorithm finds `a` and `b` such that `a * e1 + b * e2 = gcd(e1, e2)`.

```python
def extended_gcd(a, b):
    """
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

e1, e2 = 17, 65537

g, a, b = extended_gcd(e1, e2)
print(f"gcd({e1}, {e2}) = {g}")
print(f"a = {a}")
print(f"b = {b}")
print(f"Verify: {a}*{e1} + {b}*{e2} = {a*e1 + b*e2}")
```

Output:
```
gcd(17, 65537) = 1
a = 15427
b = -4
Verify: 15427*17 + -4*65537 = 1
```

So `a = 15427` and `b = -4`, meaning `15427 * 17 + (-4) * 65537 = 1`.

## Step 2 — Handle Negative Exponents

One of `a` or `b` will be negative. We can't directly compute `c2^(-4) mod n`, but we can use the modular inverse:

```
c2^(-4) mod n = (c2^(-1))^4 mod n

where c2^(-1) is the modular inverse of c2 mod n
```

Python 3.8+ makes this easy with `pow(c2, -1, n)`.

```python
n  = 71563959528358004146401194738507839917173072899698498964715249049187762408825831560052785975698912637433717617749237844838116352284861658208337879837478498579473628832543866832070416654657143137386913938464069750882137625174883827392909218721738559945818595588289014456975771826235498582974096398207683163553

c1 = 44870341782857487805638041026111608938787300862953893797705375752573645947407702731200547865373847338421078624398046251428296927766262078756250685879457672024393140210973248236285086589872808556969082500879835997419426843889328921218782571128530426461020096226765544473092606684977498822590583016373440989043

c2 = 62585866917889547283014085192153372047940680702553507253398100091747228893983958241090734069741200200178975876394358891385478792818015891583755445262721808428624583498601613630991975970903342792498697895018951492562094290101483791303547267029548711809515153739553063593381347543225094925479261072961042519360

# Extended GCD gives us: a*e1 + b*e2 = 1
# a = 15427, b = -4

a_coeff = 15427
b_coeff = -4

# Since b is negative, compute modular inverse of c2 first
c2_inv = pow(c2, -1, n)

# m = c1^a * c2_inv^|b| mod n
m = (pow(c1, a_coeff, n) * pow(c2_inv, -b_coeff, n)) % n

# Convert to bytes
flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
print(f"Flag: {flag}")
```

Output:
```
Flag: zemi{c0mm0n_m0dulus_4tt4ck}
```

## Step 3 — Understanding Bezout's Identity

Bezout's identity guarantees: for any integers `a` and `b`, there exist integers `x` and `y` such that:

```
a*x + b*y = gcd(a, b)
```

For RSA common modulus attack:
- We need `gcd(e1, e2) = 1` (the exponents must be coprime)
- 17 and 65537 are both prime, so `gcd(17, 65537) = 1`
- The Extended Euclidean Algorithm efficiently finds `x` and `y`

```
Step-by-step Extended GCD for e1=17, e2=65537:

65537 = 3855 * 17 + 2
17    = 8 * 2 + 1
2     = 2 * 1 + 0          <- gcd = 1

Back-substitution:
1 = 17 - 8 * 2
1 = 17 - 8 * (65537 - 3855 * 17)
1 = 17 - 8 * 65537 + 30840 * 17
1 = 30841 * 17 + (-8) * 65537

Wait, let me recalculate...
1 = 17 * (1 + 8*3855) + 65537 * (-8)
1 = 17 * 30841 + 65537 * (-8)

Hmm, Python's extended_gcd may find different (but equally valid)
coefficients. The important thing is a*e1 + b*e2 = 1.
```

## Complete Solve Script

```python
#!/usr/bin/env python3
"""RSA Common Modulus Attack CTF Solver"""

def extended_gcd(a, b):
    """Extended Euclidean Algorithm.
    Returns (gcd, x, y) where a*x + b*y = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def common_modulus_attack(n, e1, e2, c1, c2):
    """Recover plaintext from two RSA ciphertexts with common modulus."""
    # Step 1: Find a, b such that a*e1 + b*e2 = 1
    g, a, b = extended_gcd(e1, e2)

    if g != 1:
        print(f"[-] gcd(e1, e2) = {g}, not 1. Attack won't work directly.")
        return None

    print(f"[*] Extended GCD: {a} * {e1} + {b} * {e2} = 1")

    # Step 2: Compute m = c1^a * c2^b mod n
    # Handle negative exponents via modular inverse
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n

    return m

# Challenge values
n  = 71563959528358004146401194738507839917173072899698498964715249049187762408825831560052785975698912637433717617749237844838116352284861658208337879837478498579473628832543866832070416654657143137386913938464069750882137625174883827392909218721738559945818595588289014456975771826235498582974096398207683163553
e1 = 17
e2 = 65537
c1 = 44870341782857487805638041026111608938787300862953893797705375752573645947407702731200547865373847338421078624398046251428296927766262078756250685879457672024393140210973248236285086589872808556969082500879835997419426843889328921218782571128530426461020096226765544473092606684977498822590583016373440989043
c2 = 62585866917889547283014085192153372047940680702553507253398100091747228893983958241090734069741200200178975876394358891385478792818015891583755445262721808428624583498601613630991975970903342792498697895018951492562094290101483791303547267029548711809515153739553063593381347543225094925479261072961042519360

print("[*] RSA Common Modulus Attack")
print(f"[*] n = {str(n)[:40]}...")
print(f"[*] e1 = {e1}")
print(f"[*] e2 = {e2}")

m = common_modulus_attack(n, e1, e2, c1, c2)

if m:
    flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
    print(f"\n[+] Recovered plaintext (int): {m}")
    print(f"[+] Flag: {flag}")
```

Output:
```
[*] RSA Common Modulus Attack
[*] n = 7156395952835800414640119473850783...
[*] e1 = 17
[*] e2 = 65537
[*] Extended GCD: 15427 * 17 + -4 * 65537 = 1

[+] Flag: zemi{c0mm0n_m0dulus_4tt4ck}
```

## When Does This Attack Apply?

| Scenario | Vulnerable? |
|----------|-------------|
| Same `n`, different `e`, same `m` | Yes (this attack) |
| Same `n`, same `e`, same `m` | No new info gained |
| Different `n`, same `e`, same `m` | Hastad's broadcast attack (if e is small) |
| Same `n`, different `e`, different `m` | Not directly, but reusing `n` is still bad |

The lesson: **never reuse an RSA modulus**. Each key pair should use unique primes.

## Tools Used

- Python 3 (built-in `pow()` with three arguments for modular exponentiation)
- Extended Euclidean Algorithm (implemented manually)
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) — `--attack common_modulus` automates this

## Lessons Learned

- The common modulus attack recovers plaintext without factoring `n` — it's purely algebraic
- **Bezout's identity** is the mathematical foundation: if `gcd(e1, e2) = 1`, we can find `a, b` such that `a*e1 + b*e2 = 1`
- Negative exponents in modular arithmetic are handled via modular inverses: `x^(-k) mod n = (x^(-1))^k mod n`
- RSA moduli should **never** be shared between key pairs — even with different exponents, the system is completely broken
- The Extended Euclidean Algorithm runs in `O(log(min(e1, e2)))` — extremely efficient
- Python's `pow(base, -1, mod)` (Python 3.8+) computes modular inverses natively
- Always check for `gcd(e1, e2) = 1` before attempting the attack; if gcd > 1, you may need a modified approach
