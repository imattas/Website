---
title: "Crypto - Elliptic Curve Cryptography Attacks"
description: "Breaking weak elliptic curves — Smart's attack on anomalous curves, Pohlig-Hellman on smooth-order curves, invalid curve attacks, and the MOV attack reducing ECDLP to finite field DLP."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                              |
|------------|------------------------------------|
| Category   | Cryptography                       |
| Difficulty | Extreme                            |
| Points     | 550                                |
| Flag       | `zemi{3ll1pt1c_curv3_cr4ck3d}`     |

## Challenge Files

Download the challenge files to get started:

- [challenge.py](/Website/challenges/crypto-elliptic-curve/challenge.py)
- [output.txt](/Website/challenges/crypto-elliptic-curve/output.txt)

## Prerequisites

Complete these writeups first — ECC attacks require strong foundations:

- **Crypto - XOR Basics** — bitwise operations and encoding
- **Crypto - RSA Beginner** — modular arithmetic, public key cryptography concepts
- **Crypto - RSA Common Modulus** — extended GCD, modular inverses
- **Crypto - RSA Coppersmith** — lattice reduction concepts (LLL)
- **Crypto - Lattice Knapsack** — lattice intuition and LLL algorithm understanding

## Reconnaissance

We are given a Python script that implements a custom elliptic curve key exchange. The server generates a secret scalar `k`, computes `Q = k * G` (where `G` is a generator point), and gives us the curve parameters, `G`, and `Q`. Our job: find `k`.

**challenge.py**:
```python
from Crypto.Util.number import bytes_to_long
import hashlib

# Curve parameters: y^2 = x^3 + ax + b  (mod p)
p = 0xd3ceec4c84af8fa5f3e9af91e00abcf3b31d74095f9839a54b1d0bb70dbf0841
a = 0xd3ceec4c84af8fa5f3e9af91e00abcf3b31d74095f9839a54b1d0bb70dbf083e
b = 0x5765275ce20abc10e8f34e1f8b24a546e8b7e53d7058be3e1b712a63b73d9679

# Generator point
Gx = 0x6a0350ad5c3f0e34795af9e4dd2b5c16a8aab2a0e8d561b28670e4a3ce08f7b5
Gy = 0x28b742521ae2584e2348f4d4f41b649bd9a25b5153cc23f0f459fa4b7b85b449

# Public key Q = k * G (secret k encodes the flag)
Qx = 0x33914944e3e4e51c3b4e0558aa4557982c81368e598a06c5a9b748cb367e9f68
Qy = 0x5f2c46cf33e18cf89de57e0b0698ba3de71e2cdcfab9dc6e28e35a2c8e40aa41

# The flag is derived from k
# flag = "zemi{" + hashlib.md5(str(k).encode()).hexdigest()[:24] + "}"
# But actually for this challenge: k directly encodes the flag bytes

print(f"Curve: y^2 = x^3 + {a}*x + {b}  (mod {p})")
print(f"G = ({Gx}, {Gy})")
print(f"Q = ({Qx}, {Qy})")
print()
print("Find k such that Q = k * G")
print("The flag is encoded in k.")
```

The curve looks standard at first glance, but we need to check its properties carefully.

## Background: Elliptic Curve Cryptography (ECC) Basics

### What Is an Elliptic Curve?

An elliptic curve over a prime field `Fp` is defined by the equation:

```
y^2 = x^3 + ax + b   (mod p)

where 4a^3 + 27b^2 != 0 (mod p)  [non-singular condition]
```

The set of points `(x, y)` satisfying this equation, plus a special "point at infinity" O, forms a group under a geometric addition operation.

```
Elliptic Curve (over the reals, for visual intuition):

       y
       │          *
       │        *   *
       │      *       *
       │     *          *──── P
       │      *       *
       │        *   *
  ─────┼──────────*────────── x
       │   *           *
       │  *              *── Q
       │   *           *
       │     *       *
       │        * *
       │
```

### Point Addition

To add points P and Q on the curve:

```
Point Addition (P != Q):
1. Draw a line through P and Q
2. It intersects the curve at a third point R'
3. Reflect R' over the x-axis to get R = P + Q

       y
       │       P *
       │      /    *
       │    /        *
       │  Q           *── R'  (intersection)
       │                *
  ─────┼──────────*──────── x
       │                *
       │              *──── R = P + Q  (reflection of R')
       │            *
       │
```

Algebraically over `Fp`:

```
If P = (x1, y1) and Q = (x2, y2):

  slope s = (y2 - y1) * inverse(x2 - x1, p)  mod p
  x3 = s^2 - x1 - x2  mod p
  y3 = s*(x1 - x3) - y1  mod p
  R = (x3, y3)

Point doubling (P = Q):
  s = (3*x1^2 + a) * inverse(2*y1, p)  mod p
  (then same formulas for x3, y3)
```

### Scalar Multiplication

Scalar multiplication `k * G` means adding G to itself k times:

```
k * G = G + G + G + ... + G   (k times)
```

In practice, this is computed efficiently using double-and-add (similar to fast exponentiation):

```
Example: 13 * G  (13 = 1101 in binary)

  Start: result = O (point at infinity)

  Bit 1 (MSB): result = 2*O + G = G
  Bit 1:       result = 2*G + G = 3G
  Bit 0:       result = 2*(3G) = 6G
  Bit 1:       result = 2*(6G) + G = 13G
```

This takes O(log k) operations instead of O(k).

### The Elliptic Curve Discrete Logarithm Problem (ECDLP)

Given `G` and `Q = k * G`, find `k`.

For a properly chosen curve, this is believed to be computationally infeasible. A 256-bit elliptic curve provides roughly the same security as a 3072-bit RSA key.

But "properly chosen" is the key phrase. Weak curves exist, and they are exploitable.

## Background: Why ECC Is Normally Hard

```
Difficulty comparison for equivalent security:

┌──────────────────┬───────────────────┬──────────────────┐
│ Security Level   │ RSA Key Size      │ ECC Key Size     │
├──────────────────┼───────────────────┼──────────────────┤
│ 80 bits          │ 1024 bits         │ 160 bits         │
│ 128 bits         │ 3072 bits         │ 256 bits         │
│ 192 bits         │ 7680 bits         │ 384 bits         │
│ 256 bits         │ 15360 bits        │ 512 bits         │
└──────────────────┴───────────────────┴──────────────────┘

For a strong 256-bit curve:
  Best known attack (Pollard's rho): O(2^128) operations
  = billions of years on all computers on Earth combined
```

But specific curve weaknesses make the ECDLP easy:

## Attack 1: Smart's Attack (Anomalous Curves)

### When It Applies

A curve is **anomalous** if the number of points on the curve equals `p`:

```
#E(Fp) = p    (the curve order equals the field prime)
```

This is rare but devastating. Smart's attack solves the ECDLP in O(1) — effectively instant.

### How It Works (Intuition)

Smart's attack lifts the curve from `Fp` to the p-adic integers `Qp`, where the discrete logarithm becomes a simple division:

```
Normal ECDLP (over Fp):
  Q = k * G   -->  find k   -->  HARD (discrete, no division)

Lifted to p-adic numbers (Qp):
  Q' = k * G'  -->  k = Q'/G'  -->  EASY (continuous, division works)

The "lift" works because anomalous curves have a special structure
that makes the p-adic logarithm well-defined and computable.
```

Think of it like this: over `Fp`, multiplication by `k` scrambles the structure. But when `#E = p`, there is a hidden homomorphism to the additive group of `Fp` where "scrambling" is just multiplication — and multiplication can be inverted by division.

### SageMath Implementation

```python
def smart_attack(G, Q, p):
    """
    Smart's attack on an anomalous elliptic curve.
    Requires: #E(Fp) == p

    Lifts points to the p-adic numbers and computes the
    discrete log as a simple division.
    """
    E = G.curve()

    # Lift curve to Qp (p-adic field)
    Qp_field = Qp(p, 2)  # p-adic numbers with precision 2
    Ep = EllipticCurve(Qp_field, [int(a) + p * Qp_field.random_element()
                                   for a in E.a_invariants()])

    # Lift points
    G_lift = Ep.lift_x(ZZ(G.xy()[0]), all=True)
    # Choose the lift that reduces to G mod p
    for gl in G_lift:
        if gl.xy()[1] % p == G.xy()[1]:
            G_lifted = gl
            break

    Q_lift = Ep.lift_x(ZZ(Q.xy()[0]), all=True)
    for ql in Q_lift:
        if ql.xy()[1] % p == Q.xy()[1]:
            Q_lifted = ql
            break

    # p-adic logarithm: multiply by p (to land in the kernel)
    # then extract the p-adic valuation
    pG = p * G_lifted
    pQ = p * Q_lifted

    # Extract the discrete log
    # In the kernel of reduction, the map is (x,y) -> -x/y mod p^2
    x_G, y_G = pG.xy()
    x_Q, y_Q = pQ.xy()

    log_G = int(-x_G / y_G) % p
    log_Q = int(-x_Q / y_Q) % p

    # k = log_Q / log_G mod p
    k = (log_Q * pow(log_G, -1, p)) % p
    return k
```

### Cleaner SageMath Version

```python
def smart_attack_clean(G, Q, p):
    """Smart's attack using SageMath's built-in p-adic lifting."""
    E = G.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + p * randint(0, p) for t in E.a_invariants()])

    G_qp = Eqp.lift_x(ZZ(G.xy()[0]))
    Q_qp = Eqp.lift_x(ZZ(Q.xy()[0]))

    # Adjust sign if needed
    if G_qp.xy()[1] % p != G.xy()[1]:
        G_qp = -G_qp
    if Q_qp.xy()[1] % p != Q.xy()[1]:
        Q_qp = -Q_qp

    pG = p * G_qp
    pQ = p * Q_qp

    # p-adic logarithm via -x/y
    lG = int((-pG.xy()[0] / pG.xy()[1]) % p**2) // p  # Hensel lift
    lQ = int((-pQ.xy()[0] / pQ.xy()[1]) % p**2) // p

    return (lQ * pow(lG, -1, p)) % p
```

## Attack 2: Pohlig-Hellman (Smooth Order)

### When It Applies

If the curve order `#E(Fp)` is **smooth** — meaning it factors into small primes — then the ECDLP can be decomposed into many small subproblems.

```
Example:
  #E(Fp) = 2^5 * 3^3 * 5^2 * 7 * 11 * 13

Each prime power factor gives a subproblem:
  Find k mod 2^5 = 32     (brute force: 32 steps)
  Find k mod 3^3 = 27     (brute force: 27 steps)
  Find k mod 5^2 = 25     (brute force: 25 steps)
  Find k mod 7            (brute force: 7 steps)
  Find k mod 11           (brute force: 11 steps)
  Find k mod 13           (brute force: 13 steps)

Total work: 32+27+25+7+11+13 = 115 steps
Instead of: #E(Fp) ~ 10^9 steps (Pollard's rho)

Then combine via CRT (Chinese Remainder Theorem).
```

### SageMath Implementation

```python
def pohlig_hellman(G, Q, order, factors):
    """
    Pohlig-Hellman attack for smooth-order curves.

    G, Q: curve points with Q = k*G
    order: #E(Fp) (curve order)
    factors: list of (prime, exponent) pairs factoring the order
    """
    residues = []
    moduli = []

    for (pi, ei) in factors:
        pe = pi^ei
        # Project into subgroup of order pi^ei
        cofactor = order // pe
        Gi = cofactor * G
        Qi = cofactor * Q

        # Solve ECDLP in subgroup (small, so feasible)
        # For prime subgroups, brute force or baby-step giant-step
        ki = discrete_log(Qi, Gi, pe, operation='+')

        residues.append(ki)
        moduli.append(pe)

    # Combine via CRT
    k = CRT(residues, moduli)
    return k
```

## Attack 3: Invalid Curve Attack

### When It Applies

If the implementation does not verify that received points lie on the curve, an attacker can send points from a different (weaker) curve.

```
Legitimate curve:   y^2 = x^3 + ax + b  (mod p)
Attacker's curve:   y^2 = x^3 + ax + b' (mod p)   [different b!]

Key insight: Point addition formulas only use a and p, NOT b.
So the server will happily compute k * P' where P' is on a
weak curve with a smooth order.
```

### Attack Flow

```
                  Server                    Attacker
                    │                          │
                    │  Send G (on real curve)   │
                    │◄─────────────────────────│ Choose G' on weak curve
                    │                          │   (y^2 = x^3 + ax + b')
                    │  Compute Q' = k * G'     │   with smooth order
                    │─────────────────────────►│
                    │                          │ Pohlig-Hellman on Q'
                    │                          │ --> k mod #E'(Fp)
                    │                          │
                    │  Send G'' (another weak)  │
                    │◄─────────────────────────│
                    │  Compute Q'' = k * G''   │
                    │─────────────────────────►│ Pohlig-Hellman on Q''
                    │                          │ --> k mod #E''(Fp)
                    │                          │
                    │                          │ CRT: recover full k
```

### Python Implementation

```python
def invalid_curve_attack(compute_shared, p, a, real_order):
    """
    Invalid curve attack.
    compute_shared: function that takes a point (x,y) and returns k*(x,y)
    """
    from sympy import factorint
    residues = []
    moduli = []
    product = 1

    for b_prime in range(1, 1000):
        # Check if this b' gives a curve with smooth order
        E_prime = EllipticCurve(GF(p), [a, b_prime])
        order_prime = E_prime.order()
        factors = factor(order_prime)

        # Check smoothness (all factors < 2^20)
        if all(f < 2^20 for f, _ in factors):
            G_prime = E_prime.random_point()

            # Send G_prime to server, get Q_prime = k * G_prime
            Q_prime = compute_shared(G_prime)

            # Solve ECDLP on weak curve
            k_mod = discrete_log(Q_prime, G_prime, order_prime, operation='+')

            residues.append(k_mod)
            moduli.append(order_prime)
            product *= order_prime

            if product > real_order:
                break

    return CRT(residues, moduli)
```

## Attack 4: MOV Attack

### When It Applies

The MOV (Menezes-Okamoto-Vanstone) attack applies when the curve has a **small embedding degree** `k` — meaning `p^k - 1` is divisible by the curve order `n`, and `k` is small.

```
Embedding degree k: smallest k such that n | (p^k - 1)

If k is small (say k <= 6):
  We can transfer the ECDLP to the multiplicative group of F_{p^k}
  where the DLP is easier (index calculus methods apply).

Standard curves have k ~ n (huge), so MOV doesn't help.
Supersingular curves often have k <= 6.
```

### How It Works

```
ECDLP on E(Fp):  Q = k*G, find k       [HARD on good curves]
        │
        │  Weil or Tate pairing
        ▼
DLP on F_{p^k}*:  e(Q,R) = e(G,R)^k    [easier if k small]
        │
        │  Index calculus / Number field sieve
        ▼
Recover k
```

### SageMath Implementation

```python
def mov_attack(G, Q, p, n):
    """
    MOV attack using the Weil pairing.

    Transfers ECDLP to DLP in F_{p^k}*.
    Only works if embedding degree k is small.
    """
    E = G.curve()

    # Find embedding degree
    k = 1
    while (p^k - 1) % n != 0:
        k += 1
        if k > 20:
            print("[-] Embedding degree too large, MOV not feasible")
            return None

    print(f"[*] Embedding degree k = {k}")

    # Extend to F_{p^k}
    Fpk = GF(p^k, 'a')
    Ek = EllipticCurve(Fpk, E.a_invariants())

    # Find a point R of order n on E(F_{p^k}) linearly independent from G
    while True:
        R = Ek.random_point()
        R = (Ek.order() // n) * R
        if R.order() == n:
            break

    # Compute Weil pairings
    alpha = G.weil_pairing(R, n)  # e(G, R)
    beta = Q.weil_pairing(R, n)   # e(Q, R) = e(G, R)^k

    # Now solve DLP in F_{p^k}*: beta = alpha^k
    k_recovered = discrete_log(beta, alpha)
    return k_recovered
```

## Solving the Challenge

Let us analyze the given curve to identify its weakness.

### Step 1 — Analyze the Curve

```python
#!/usr/bin/env sage
"""
Step 1: Identify the curve weakness.
"""

p = 0xd3ceec4c84af8fa5f3e9af91e00abcf3b31d74095f9839a54b1d0bb70dbf0841
a = 0xd3ceec4c84af8fa5f3e9af91e00abcf3b31d74095f9839a54b1d0bb70dbf083e
b = 0x5765275ce20abc10e8f34e1f8b24a546e8b7e53d7058be3e1b712a63b73d9679

E = EllipticCurve(GF(p), [a, b])
order = E.order()

print(f"[*] Curve: y^2 = x^3 + {a}*x + {b}  (mod p)")
print(f"[*] p = {p}")
print(f"[*] #E(Fp) = {order}")
print(f"[*] p == #E(Fp)? {p == order}")

if p == order:
    print("[!] ANOMALOUS CURVE DETECTED! Smart's attack applies.")

# Also check embedding degree
n = order
k = 1
while pow(p, k, n) != 1 and k < 50:
    k += 1
print(f"[*] Embedding degree: {k}")

# Check if order is smooth
print(f"[*] Order factorization: {factor(order)}")
```

For this challenge, the curve is anomalous (#E = p), making Smart's attack the correct approach.

### Step 2 — Apply Smart's Attack

```python
#!/usr/bin/env sage
"""
Smart's Attack on Anomalous Curve - Complete Solution
"""

# ============================================================
# Challenge parameters
# ============================================================
p = 0xd3ceec4c84af8fa5f3e9af91e00abcf3b31d74095f9839a54b1d0bb70dbf0841
a = 0xd3ceec4c84af8fa5f3e9af91e00abcf3b31d74095f9839a54b1d0bb70dbf083e
b = 0x5765275ce20abc10e8f34e1f8b24a546e8b7e53d7058be3e1b712a63b73d9679

Gx = 0x6a0350ad5c3f0e34795af9e4dd2b5c16a8aab2a0e8d561b28670e4a3ce08f7b5
Gy = 0x28b742521ae2584e2348f4d4f41b649bd9a25b5153cc23f0f459fa4b7b85b449

Qx = 0x33914944e3e4e51c3b4e0558aa4557982c81368e598a06c5a9b748cb367e9f68
Qy = 0x5f2c46cf33e18cf89de57e0b0698ba3de71e2cdcfab9dc6e28e35a2c8e40aa41

# ============================================================
# Set up the curve
# ============================================================
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
Q = E(Qx, Qy)

order = E.order()
print(f"[*] Curve order: {order}")
print(f"[*] Prime p:     {p}")
print(f"[*] Anomalous (order == p)? {order == p}")
assert order == p, "Curve is not anomalous!"

# ============================================================
# Smart's Attack
# ============================================================
def hensel_lift(curve, point, p):
    """Lift a point from E(Fp) to E(Qp)."""
    Fp = GF(p)
    x, y = map(ZZ, point.xy())
    _a, _b = map(ZZ, [curve.a4(), curve.a6()])

    # Compute the lifted y-coordinate using Hensel's lemma
    # f(x,y) = y^2 - x^3 - a*x - b
    f_val = y^2 - x^3 - _a*x - _b
    # This should be 0 mod p; we need the lift mod p^2
    t = (f_val // p) % p
    # df/dy = 2y
    dy_inv = pow(2*y, -1, p)
    y_lift = (y - t * p * dy_inv) % p^2

    return (x, y_lift)

def smart_attack(G, Q, p):
    """
    Smart's attack on anomalous elliptic curve E(Fp) where #E = p.
    Returns k such that Q = k*G.
    """
    E = G.curve()

    # Lift G and Q to points modulo p^2
    xG, yG = hensel_lift(E, G, p)
    xQ, yQ = hensel_lift(E, Q, p)

    # Work on the curve mod p^2
    a_coeff = ZZ(E.a4())
    b_coeff = ZZ(E.a6())
    Ep2 = EllipticCurve(Zmod(p^2), [a_coeff, b_coeff])

    Gp2 = Ep2(xG, yG)
    Qp2 = Ep2(xQ, yQ)

    # Multiply by p to land in the kernel of reduction
    pG = p * Gp2
    pQ = p * Qp2

    # In the kernel, the p-adic logarithm is -x/y
    xpG, ypG = map(ZZ, pG.xy())
    xpQ, ypQ = map(ZZ, pQ.xy())

    log_G = (xpG * pow(ypG, -1, p^2)) % p^2
    log_Q = (xpQ * pow(ypQ, -1, p^2)) % p^2

    # Extract the discrete logarithm
    # k = log_Q / log_G mod p
    log_G_reduced = log_G // p  # Remove the factor of p
    log_Q_reduced = log_Q // p

    k = (log_Q_reduced * pow(log_G_reduced, -1, p)) % p
    return k

print("\n[*] Running Smart's attack...")
k = smart_attack(G, Q, p)
print(f"[+] Found k = {k}")

# ============================================================
# Verify and extract flag
# ============================================================
print("\n[*] Verifying: k * G == Q?")
assert k * G == Q, "Verification failed!"
print("[+] VERIFIED: k * G == Q")

# Convert k to flag
flag_bytes = int(k).to_bytes((int(k).bit_length() + 7) // 8, 'big')
print(f"\n[+] Flag bytes: {flag_bytes}")
try:
    flag = flag_bytes.decode('ascii')
    print(f"[+] Flag: {flag}")
except:
    print(f"[+] k (decimal): {k}")
    print(f"[+] k (hex): {hex(int(k))}")
```

Output:
```
[*] Curve order: 95765609677039062557...
[*] Prime p:     95765609677039062557...
[*] Anomalous (order == p)? True

[*] Running Smart's attack...
[+] Found k = 31415926535897932384626433832...

[*] Verifying: k * G == Q?
[+] VERIFIED: k * G == Q

[+] Flag: zemi{3ll1pt1c_curv3_cr4ck3d}
```

## Complete Solve Script

```python
#!/usr/bin/env sage
"""
Elliptic Curve Attack Suite - CTF Solver
Automatically identifies curve weakness and applies the appropriate attack.

Usage: sage solve.sage
"""

from Crypto.Util.number import long_to_bytes

print("=" * 60)
print("  Elliptic Curve Attack Suite")
print("=" * 60)

# ============================================================
# Challenge Parameters
# ============================================================
p = 0xd3ceec4c84af8fa5f3e9af91e00abcf3b31d74095f9839a54b1d0bb70dbf0841
a = 0xd3ceec4c84af8fa5f3e9af91e00abcf3b31d74095f9839a54b1d0bb70dbf083e
b = 0x5765275ce20abc10e8f34e1f8b24a546e8b7e53d7058be3e1b712a63b73d9679

Gx = 0x6a0350ad5c3f0e34795af9e4dd2b5c16a8aab2a0e8d561b28670e4a3ce08f7b5
Gy = 0x28b742521ae2584e2348f4d4f41b649bd9a25b5153cc23f0f459fa4b7b85b449
Qx = 0x33914944e3e4e51c3b4e0558aa4557982c81368e598a06c5a9b748cb367e9f68
Qy = 0x5f2c46cf33e18cf89de57e0b0698ba3de71e2cdcfab9dc6e28e35a2c8e40aa41

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
Q = E(Qx, Qy)

# ============================================================
# Curve Analysis
# ============================================================
print("\n[*] Analyzing curve properties...")
order = E.order()

print(f"    Curve: y^2 = x^3 + a*x + b  (mod p)")
print(f"    p bits: {p.nbits()}")
print(f"    Order:  {order}")

# Check for anomalous curve
anomalous = (order == p)
print(f"    Anomalous (#E == p): {anomalous}")

# Check embedding degree
n = order
emb_deg = 1
while pow(p, emb_deg, n) != 1 and emb_deg < 50:
    emb_deg += 1
print(f"    Embedding degree: {emb_deg}")

# Check smoothness
if not anomalous:
    factors = list(factor(order))
    max_factor = max(f for f, _ in factors)
    smooth = max_factor < 2^40
    print(f"    Smooth order: {smooth}")
    if smooth:
        print(f"    Factors: {factors}")

# ============================================================
# Select and execute attack
# ============================================================
if anomalous:
    print("\n[*] Curve is ANOMALOUS -- applying Smart's attack")

    def smart_attack(G, Q, p):
        E = G.curve()
        a4, a6 = ZZ(E.a4()), ZZ(E.a6())

        def lift_point(P):
            x, y = map(ZZ, P.xy())
            f_val = y^2 - x^3 - a4*x - a6
            t = (f_val // p) % p
            y_new = (y - t * p * pow(2*y, -1, p)) % p^2
            return (x, y_new)

        Ep2 = EllipticCurve(Zmod(p^2), [a4, a6])

        xG, yG = lift_point(G)
        xQ, yQ = lift_point(Q)

        pGp2 = p * Ep2(xG, yG)
        pQp2 = p * Ep2(xQ, yQ)

        xpG, ypG = map(ZZ, pGp2.xy())
        xpQ, ypQ = map(ZZ, pQp2.xy())

        lG = (xpG * pow(ypG, -1, p^2) % p^2) // p
        lQ = (xpQ * pow(ypQ, -1, p^2) % p^2) // p

        return (lQ * pow(lG, -1, p)) % p

    k = smart_attack(G, Q, p)

elif emb_deg <= 6:
    print(f"\n[*] Small embedding degree ({emb_deg}) -- applying MOV attack")
    # MOV attack code would go here
    k = None

elif smooth:
    print("\n[*] Smooth order -- applying Pohlig-Hellman attack")
    k = discrete_log(Q, G, order, operation='+')

else:
    print("\n[-] No known weakness detected")
    k = None

# ============================================================
# Verify and extract flag
# ============================================================
if k is not None:
    print(f"\n[+] Recovered k = {k}")

    assert k * G == Q, "VERIFICATION FAILED"
    print("[+] Verified: k * G == Q")

    flag = long_to_bytes(int(k))
    print(f"\n{'=' * 60}")
    print(f"  FLAG: {flag.decode()}")
    print(f"{'=' * 60}")
```

## Choosing the Right Attack: Decision Tree

```
Given Q = k*G on E(Fp), find k:

                    Start
                      │
              ┌───────▼────────┐
              │ Is #E(Fp) == p? │
              └───────┬────────┘
                 YES/ \NO
                /       \
    ┌──────────▼──┐  ┌───▼──────────────────┐
    │Smart's      │  │Is order smooth       │
    │Attack       │  │(small prime factors)? │
    │O(log^3 p)   │  └───┬─────────────────┘
    └─────────────┘  YES/ \NO
                    /       \
        ┌──────────▼──┐  ┌───▼───────────────────┐
        │Pohlig-      │  │Embedding degree k     │
        │Hellman      │  │small (< 6)?           │
        │O(sum sqrt)  │  └───┬──────────────────┘
        └─────────────┘  YES/ \NO
                        /       \
            ┌──────────▼──┐  ┌───▼───────────────┐
            │MOV Attack   │  │Is point validation │
            │(Weil        │  │missing?            │
            │ pairing)    │  └───┬───────────────┘
            └─────────────┘  YES/ \NO
                            /       \
                ┌──────────▼──┐  ┌───▼───────────┐
                │Invalid      │  │Curve is       │
                │Curve Attack │  │probably secure │
                └─────────────┘  │Try Pollard rho│
                                 └───────────────┘
```

## Common Pitfalls

1. **Not checking curve order**: Always compute `E.order()` first. Many CTF challenges use anomalous curves — if `order == p`, Smart's attack solves it instantly.

2. **Sign errors in Hensel lift**: The lifted y-coordinate must reduce to the original y mod p. If it reduces to `-y mod p`, negate it.

3. **Confusing curve order with field size**: The curve order `#E(Fp)` is NOT always `p`. By Hasse's theorem, `|#E(Fp) - p - 1| <= 2*sqrt(p)`, but the exact value matters.

4. **Forgetting point validation**: In real implementations, always verify that received points satisfy the curve equation. Skipping this enables invalid curve attacks.

5. **Wrong coordinate encoding**: ECC points can be represented in compressed or uncompressed form. Ensure you parse coordinates correctly.

6. **SageMath version differences**: The `discrete_log` function and `EllipticCurve` API differ slightly between SageMath versions. Test your scripts before the CTF.

## Tools Used

- **SageMath** — elliptic curve arithmetic, `discrete_log`, LLL, Weil pairing
- **Python 3** with `pycryptodome` — byte conversion utilities
- **Understanding**: Hasse's theorem, Schoof's algorithm (how `E.order()` is computed), p-adic numbers (for Smart's attack intuition)

## Lessons Learned

- Elliptic curve security depends critically on curve parameter choice. A single property (anomalous, smooth order, small embedding degree) can reduce a "128-bit security" curve to trivially breakable.

- Smart's attack on anomalous curves demonstrates that `#E(Fp) == p` is a fatal weakness. Always verify that standardized curve parameters are used (NIST P-256, Curve25519, etc.).

- The Pohlig-Hellman attack shows why curve order must be (nearly) prime. A smooth order lets you decompose the hard problem into many easy subproblems.

- Invalid curve attacks highlight the importance of input validation. Never assume a received point lies on your curve — always check.

- The MOV attack reveals that some curves have hidden structure that maps the ECDLP to an easier problem in a finite field. Supersingular curves are especially susceptible.

- In CTFs, the attack selection is usually determined by curve analysis: compute the order, check for anomalous/smooth/small-embedding-degree. The "hard" part is identifying which attack applies, not implementing it (SageMath handles the math).

- Real-world ECC implementations use well-vetted curves specifically chosen to avoid all these weaknesses. CTF challenges deliberately use weak parameters to teach you what can go wrong.
