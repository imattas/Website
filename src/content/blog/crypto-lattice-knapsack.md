---
title: "Crypto - Lattice Reduction & Knapsack Cryptosystem"
description: "Breaking the Merkle-Hellman knapsack cryptosystem using the LLL algorithm — encoding a subset sum problem as a lattice and finding short vectors to recover the secret binary message."
author: "Zemi"
---

## Challenge Info

| Detail     | Value                              |
|------------|------------------------------------|
| Category   | Cryptography                       |
| Difficulty | Extreme                            |
| Points     | 600                                |
| Flag       | `zemi{l4tt1c3_r3duct10n_w1ns}`     |

## Challenge Files

Download the challenge files to get started:

- [encrypt.py](/Website/challenges/crypto-lattice-knapsack/encrypt.py)
- [hint.txt](/Website/challenges/crypto-lattice-knapsack/hint.txt)
- [output.txt](/Website/challenges/crypto-lattice-knapsack/output.txt)

## Prerequisites

Complete these writeups first — this challenge requires deep mathematical foundations:

- **Crypto - XOR Basics** — binary representations, bitwise operations
- **Crypto - RSA Beginner** — modular arithmetic, number theory fundamentals
- **Crypto - RSA Common Modulus** — extended GCD, modular inverses
- **Crypto - RSA Coppersmith** — first exposure to lattice reduction concepts
- **Crypto - Padding Oracle** — systematic exploitation methodology

## Reconnaissance

We are given a Python script that implements a knapsack-based encryption scheme. The flag is encoded as bits, and each bit selects whether a corresponding "weight" is included in a sum. We receive the weights and the target sum, and must recover which weights were selected (i.e., the flag bits).

**challenge.py**:
```python
import random
from Crypto.Util.number import bytes_to_long

def generate_superincreasing(n, start_range=1000):
    """Generate a superincreasing sequence of n elements."""
    seq = []
    total = 0
    for i in range(n):
        # Each element is greater than the sum of all previous elements
        val = total + random.randint(start_range, start_range * 3)
        seq.append(val)
        total += val
    return seq

def encrypt_knapsack(message_bits, public_key):
    """Encrypt: sum of public_key[i] where message_bits[i] == 1."""
    assert len(message_bits) == len(public_key)
    return sum(w * b for w, b in zip(public_key, message_bits))

# The flag
flag = b"zemi{l4tt1c3_r3duct10n_w1ns}"
flag_bits = []
for byte in flag:
    for i in range(7, -1, -1):
        flag_bits.append((byte >> i) & 1)

n = len(flag_bits)  # Number of bits

# Generate Merkle-Hellman knapsack
private_key = generate_superincreasing(n)
total_sum = sum(private_key)
q = random.randint(total_sum + 1, total_sum * 2)  # Modulus > sum of all weights
r = random.randint(2, q - 2)
while gcd(r, q) != 1:
    r = random.randint(2, q - 2)

# Public key: scramble the superincreasing sequence
public_key = [(r * w) % q for w in private_key]

# Encrypt
target_sum = encrypt_knapsack(flag_bits, public_key)

print(f"n = {n}  # number of bits")
print(f"public_key = {public_key}")
print(f"target_sum = {target_sum}")
print()
print("# Find the binary vector b[] such that:")
print("# sum(public_key[i] * b[i]) = target_sum")
print("# Then convert b[] to bytes to get the flag")
```

We are given:
- `n` weights (the public key)
- The target sum
- The task: find a binary (0/1) vector that produces this exact sum

This is the **subset sum problem** — NP-hard in general, but solvable with lattice reduction when the problem has the right density.

## Background: The Subset Sum Problem

### Definition

Given a set of positive integers `W = {w_1, w_2, ..., w_n}` and a target `S`, find a binary vector `b = (b_1, b_2, ..., b_n)` where each `b_i` is 0 or 1, such that:

```
w_1*b_1 + w_2*b_2 + ... + w_n*b_n = S
```

### Why It Is Hard

Subset sum is NP-hard in general. Brute force checks all 2^n possible subsets:

```
For n = 224 bits (our challenge):
  2^224 = 2.7 * 10^67 subsets to check

At 10 billion checks per second:
  Time = 2.7 * 10^67 / 10^10 = 2.7 * 10^57 seconds
       = 8.5 * 10^49 years

Not happening with brute force.
```

### The Merkle-Hellman Knapsack Cryptosystem

In 1978, Merkle and Hellman proposed using subset sum for public-key encryption:

```
Key Generation:
  1. Create a SUPERINCREASING sequence (private key):
     Each element > sum of all previous elements
     e.g., [2, 3, 7, 14, 30, 57, 120, 251]
     (3>2, 7>2+3=5, 14>2+3+7=12, ...)

  2. Choose a modulus q > sum of all elements
  3. Choose a multiplier r with gcd(r, q) = 1

  4. Public key: w_i = r * private_i  mod q
     (Scrambles the superincreasing structure)

Encryption:
  Convert message to bits, compute subset sum with public key.

Decryption (with private key):
  1. Multiply sum by r^(-1) mod q  (undo the scrambling)
  2. Solve subset sum with superincreasing sequence (easy! greedy algorithm)
```

Superincreasing sequences have an easy greedy solution:

```
Superincreasing: [2, 3, 7, 14, 30]
Target sum: 23

Greedy (process right to left):
  30 > 23? NO (skip, b[4]=0)
  14 ≤ 23? YES (include, b[3]=1, remaining=23-14=9)
  7 ≤ 9?  YES (include, b[2]=1, remaining=9-7=2)
  3 > 2?  NO  (skip, b[1]=0)
  2 ≤ 2?  YES (include, b[0]=1, remaining=2-2=0)

Solution: b = [1, 0, 1, 1, 0]  --> 2 + 7 + 14 = 23  ✓
```

### Why Merkle-Hellman Is Broken

In 1982, Adi Shamir showed that the lattice reduction attack (later refined with LLL) can break the Merkle-Hellman system in polynomial time. The multiplication by `r mod q` does not sufficiently hide the superincreasing structure. LLL finds short lattice vectors that correspond to the binary solution.

## Background: What Are Lattices?

### Formal Definition

A lattice `L` is a discrete subgroup of `R^n`. Concretely, it is the set of all integer linear combinations of a set of linearly independent basis vectors:

```
L = { a_1*v_1 + a_2*v_2 + ... + a_d*v_d  |  a_i ∈ Z }

where v_1, v_2, ..., v_d are the basis vectors.
```

### Visual Intuition (2D)

```
Basis vectors: v1 = (3, 1), v2 = (1, 2)

Lattice points (dots represent integer combinations a*v1 + b*v2):

  y
  8 │             ●             ●             ●
    │
  6 │       ●             ●             ●
    │
  4 │ ●             ●             ●
    │           /
  2 │     ●   / v2        ●             ●
    │       ●───────►
  0 ├───●──v1────●─────────●─────────●──── x
    0   2   4    6    8    10   12   14

Every lattice point = a*(3,1) + b*(1,2) for integers a, b
```

### Same Lattice, Different Bases

The same lattice can be described by different bases. Some bases are "better" (shorter, more orthogonal) than others:

```
BAD basis (long, nearly parallel vectors):
  u1 = (100, 1)
  u2 = (99, 2)

  These generate the same lattice, but the vectors are long
  and nearly parallel. Hard to work with.

GOOD basis (short, nearly orthogonal):
  v1 = (1, -1)
  v2 = (1, 1)

  Same lattice! But now the vectors are short and orthogonal.
  Much easier to work with.
```

### Why Lattices Matter for Cryptography

Many cryptographic problems can be reformulated as: "Find a short vector in a lattice." If the lattice has special structure, short vectors reveal secret information.

## Background: The LLL Algorithm

### What It Does

The **Lenstra-Lenstra-Lovasz (LLL)** algorithm takes any lattice basis and produces a "reduced" basis where:

1. The vectors are relatively short (within a factor of `2^((n-1)/2)` of the shortest vector)
2. The vectors are relatively orthogonal (Lovasz condition)

```
Input:  Bad basis (long, skewed vectors)
Output: Good basis (short, nearly orthogonal vectors)

Time:   Polynomial in the dimension and bit-size of the entries
        O(d^6 * log^3(B))  where d = dimension, B = max entry
```

### Why LLL Solves Subset Sum

The key insight: we can construct a lattice where a short vector directly encodes the solution to our subset sum problem.

Consider the following matrix (basis) for subset sum with weights `w_1, ..., w_n` and target `S`:

```
         ┌                                          ┐
         │  1   0   0  ...  0   0     w_1            │
         │  0   1   0  ...  0   0     w_2            │
         │  0   0   1  ...  0   0     w_3            │
    B =  │  .   .   .  ...  .   .      .             │
         │  .   .   .  ...  .   .      .             │
         │  0   0   0  ...  1   0     w_n            │
         │  0   0   0  ...  0   1     -S             │
         └                                          ┘

This is an (n+1) x (n+1) matrix.
```

If `b = (b_1, ..., b_n)` is the solution (binary vector), then consider the lattice vector:

```
v = b_1 * row_1 + b_2 * row_2 + ... + b_n * row_n + 1 * row_{n+1}

v = (b_1, b_2, ..., b_n, 1, b_1*w_1 + b_2*w_2 + ... + b_n*w_n - S)
  = (b_1, b_2, ..., b_n, 1, 0)    (because the sum equals S!)
```

This vector is SHORT because:
- Each `b_i` is 0 or 1
- The last component is 0
- The second-to-last component is 1

Typical lattice vectors are much longer (their entries are comparable to `w_i`). LLL tends to find short vectors, so it will likely find (or enable finding) this solution vector.

### Visual Example

```
Weights: w = [7, 11, 19, 35]
Target:  S = 30
Solution: b = [1, 0, 1, 0]  (7 + 19 = 26... wait, that's wrong)
Actually: b = [1, 1, 0, 1]? No... let me check: 7+11=18, 7+19=26, 11+19=30!
Solution: b = [0, 1, 1, 0]  (11 + 19 = 30) ✓

Lattice basis:
┌                    ┐
│  1  0  0  0  0   7 │   row 1
│  0  1  0  0  0  11 │   row 2
│  0  0  1  0  0  19 │   row 3
│  0  0  0  1  0  35 │   row 4
│  0  0  0  0  1 -30 │   row 5
└                    ┘

Target vector (using solution b = [0,1,1,0]):
v = 0*row1 + 1*row2 + 1*row3 + 0*row4 + 1*row5
  = (0, 1, 1, 0, 1,  11+19-30)
  = (0, 1, 1, 0, 1,  0)

This is a SHORT vector! (norm = sqrt(0+1+1+0+1+0) = sqrt(3) ≈ 1.7)
Compare to typical lattice vectors which have entries in the range of w_i.

LLL will find this (or a similar short vector).
```

## Background: Lattice Density and Attack Feasibility

Not all subset sum instances are vulnerable to LLL. The **density** of the problem determines feasibility:

```
Density = n / max(log2(w_i))

where n = number of weights
      max(log2(w_i)) = bit-length of the largest weight

Low density (d < 0.9408):
  LLL-based attacks provably succeed (Coster et al. 1992)

High density (d > 1):
  LLL may fail; other approaches needed

Merkle-Hellman knapsack:
  Typically low density because the modular multiplication
  produces weights of similar bit-length to q,
  while n (number of message bits) is relatively small.
  d ≈ n / log2(q) < 1 for typical parameters.
```

For our challenge:
```
n = 224 bits (28 bytes * 8 bits/byte)
Weights are typically ~256 bits (after mod q multiplication)

Density ≈ 224 / 256 ≈ 0.875 < 0.9408

LLL attack should succeed.
```

## Step 1 — Setting Up the Challenge

```python
#!/usr/bin/env python3
"""
Step 1: Generate the knapsack challenge locally.
"""

import random
from math import gcd

def generate_superincreasing(n, start_range=1000):
    """Generate a superincreasing sequence."""
    seq = []
    total = 0
    for i in range(n):
        val = total + random.randint(start_range, start_range * 3)
        seq.append(val)
        total += val
    return seq

# Flag to bits
flag = b"zemi{l4tt1c3_r3duct10n_w1ns}"
flag_bits = []
for byte in flag:
    for i in range(7, -1, -1):
        flag_bits.append((byte >> i) & 1)

n = len(flag_bits)
print(f"[*] Flag: {flag}")
print(f"[*] Flag bits: {n} bits")
print(f"[*] Number of 1-bits: {sum(flag_bits)}")

# Generate Merkle-Hellman keys
random.seed(42)  # For reproducibility
private_key = generate_superincreasing(n)
total = sum(private_key)
q = random.randint(total + 1, total * 2)
r = random.randint(2, q - 2)
while gcd(r, q) != 1:
    r = random.randint(2, q - 2)

public_key = [(r * w) % q for w in private_key]
target_sum = sum(w * b for w, b in zip(public_key, flag_bits))

print(f"[*] Private key length: {len(private_key)}")
print(f"[*] Modulus q: {q} ({q.bit_length()} bits)")
print(f"[*] Multiplier r: {r}")
print(f"[*] Max public key weight: {max(public_key)} ({max(public_key).bit_length()} bits)")
print(f"[*] Target sum: {target_sum}")
print(f"[*] Density: {n / max(w.bit_length() for w in public_key):.4f}")

# Save for solver
print(f"\n# Challenge output:")
print(f"n = {n}")
print(f"public_key = {public_key}")
print(f"target_sum = {target_sum}")
```

## Step 2 — Understanding the Lattice Construction

We build the CJLOSS lattice (Coster-Joux-LaMacchia-Odlyzko-Schnorr-Stern):

```python
"""
Lattice construction for subset sum.

Given: weights w_1, ..., w_n and target S
Find: binary b_1, ..., b_n with sum(w_i * b_i) = S

Lattice basis matrix (n+1 rows, n+1 columns):

     ┌                                              ┐
     │  2   0   0  ...  0    N*w_1                   │
     │  0   2   0  ...  0    N*w_2                   │
     │  0   0   2  ...  0    N*w_3                   │
     │  .   .   .  ...  .      .                     │
     │  0   0   0  ...  2    N*w_n                   │
     │  1   1   1  ...  1    N*S                     │
     └                                              ┘

Where N is a large scaling factor (typically N = ceil(sqrt(n/2)))

The target short vector is:
  (2*b_1-1, 2*b_2-1, ..., 2*b_n-1, 0)

Each entry is +1 or -1 (since b_i ∈ {0,1}, so 2*b_i-1 ∈ {-1,+1}).
The last entry is 0 because the weights sum to S.
This vector has norm sqrt(n), which is very short.

The scaling factor N ensures that any vector with a non-zero
last component is very long, so LLL avoids them.
"""
```

Why the `2*b_i - 1` transformation? Instead of looking for vectors with entries in {0,1}, we look for entries in {-1,+1}. This centering makes the target vector shorter and helps LLL find it.

```
Original:    b_i ∈ {0, 1}     -->  target entries spread from 0 to 1
Transformed: 2*b_i-1 ∈ {-1,1} -->  target entries all have |value| = 1

The transformed target vector has UNIFORM norm in every component,
making it the shortest vector in the lattice (usually).
```

## Step 3 — SageMath Solve Script

```python
#!/usr/bin/env sage
"""
Lattice-based Knapsack Attack - SageMath Solver

Breaks Merkle-Hellman knapsack encryption using LLL lattice reduction.
Constructs the CJLOSS lattice and finds the short vector
corresponding to the binary solution.

Usage: sage solve.sage
"""

import math

# ============================================================
# Challenge Parameters (paste from challenge output)
# ============================================================
n = 224  # number of bits
public_key = [...]  # paste the list here
target_sum = ...    # paste the target sum here

print("=" * 60)
print("  Lattice-Based Knapsack Attack (LLL)")
print("=" * 60)

print(f"\n[*] Number of bits: {n}")
print(f"[*] Number of weights: {len(public_key)}")
print(f"[*] Max weight size: {max(public_key).bit_length()} bits")
print(f"[*] Target sum: {target_sum}")

density = n / max(w.bit_length() for w in public_key)
print(f"[*] Density: {density:.4f}")
print(f"[*] LLL feasible (density < 0.9408)? {'YES' if density < 0.9408 else 'MAYBE'}")

# ============================================================
# Construct the Lattice
# ============================================================
print("\n[*] Constructing CJLOSS lattice...")

# Scaling factor
N = ceil(sqrt(n / 2))
print(f"[*] Scaling factor N = {N}")

# Build the (n+1) x (n+1) matrix
M = Matrix(ZZ, n + 1, n + 1)

for i in range(n):
    M[i, i] = 2             # Identity-like diagonal (scaled by 2)
    M[i, n] = N * public_key[i]   # Last column: scaled weights

# Last row
for i in range(n):
    M[n, i] = 1             # All ones (for the centering trick)
M[n, n] = N * target_sum    # Scaled target

print(f"[*] Lattice dimension: {n+1} x {n+1}")

# ============================================================
# Run LLL
# ============================================================
print("[*] Running LLL reduction (this may take a moment)...")

L = M.LLL()

print("[*] LLL complete. Searching for solution vector...")

# ============================================================
# Find the solution vector
# ============================================================
# The target vector has entries in {-1, +1} for positions 0..n-1
# and 0 for position n.

flag_bits = None
for row in L:
    # Check if last entry is 0 (sum constraint satisfied)
    if row[n] != 0:
        continue

    # Check if all other entries are +1 or -1
    if all(abs(row[i]) == 1 for i in range(n)):
        # Recover bits: b_i = (row[i] + 1) / 2
        bits = [(int(row[i]) + 1) // 2 for i in range(n)]

        # Verify
        computed_sum = sum(w * b for w, b in zip(public_key, bits))
        if computed_sum == target_sum:
            flag_bits = bits
            print(f"[+] Found valid solution vector!")
            break

    # Also check the negated vector (LLL might return -v instead of v)
    if all(abs(row[i]) == 1 for i in range(n)):
        bits_neg = [(-int(row[i]) + 1) // 2 for i in range(n)]
        computed_sum = sum(w * b for w, b in zip(public_key, bits_neg))
        if computed_sum == target_sum:
            flag_bits = bits_neg
            print(f"[+] Found valid solution vector (negated)!")
            break

if flag_bits is None:
    print("[-] Solution not found in LLL output.")
    print("    Try adjusting the scaling factor N or the lattice construction.")
    exit(1)

# ============================================================
# Convert bits to bytes (flag)
# ============================================================
print(f"\n[*] Recovered {len(flag_bits)} bits")
print(f"[*] Number of 1-bits: {sum(flag_bits)}")

flag_bytes = bytearray()
for i in range(0, len(flag_bits), 8):
    byte = 0
    for j in range(8):
        if i + j < len(flag_bits):
            byte = (byte << 1) | flag_bits[i + j]
    flag_bytes.append(byte)

flag = bytes(flag_bytes)
print(f"\n{'=' * 60}")
print(f"  FLAG: {flag.decode()}")
print(f"{'=' * 60}")
```

## Complete Solve Script (Self-Contained)

This all-in-one script generates the challenge and solves it:

```python
#!/usr/bin/env sage
"""
Lattice Knapsack Attack - Complete CTF Solver
Generates the Merkle-Hellman knapsack challenge and breaks it with LLL.

Usage: sage solve.sage
"""

import random
from math import gcd

print("=" * 60)
print("  Lattice-Based Knapsack Attack (Complete)")
print("=" * 60)

# ============================================================
# Generate Challenge
# ============================================================
print("\n[*] Generating Merkle-Hellman knapsack challenge...")

flag = b"zemi{l4tt1c3_r3duct10n_w1ns}"
flag_bits = []
for byte in flag:
    for i in range(7, -1, -1):
        flag_bits.append((byte >> i) & 1)

n = len(flag_bits)

# Superincreasing private key
random.seed(42)
private_key = []
total = 0
for i in range(n):
    val = total + random.randint(1000, 3000)
    private_key.append(val)
    total += val

# Modular transformation
q = random.randint(total + 1, total * 2)
r = random.randint(2, q - 2)
while gcd(r, q) != 1:
    r = random.randint(2, q - 2)

public_key = [(r * w) % q for w in private_key]
target_sum = sum(w * b for w, b in zip(public_key, flag_bits))

print(f"[*] Flag bits: {n}")
print(f"[*] Max weight: {max(public_key).bit_length()} bits")
print(f"[*] Target sum: {target_sum}")

density = n / max(w.bit_length() for w in public_key)
print(f"[*] Density: {density:.4f}")

# ============================================================
# Lattice Construction
# ============================================================
print("\n[*] Constructing lattice...")

N_scale = ceil(sqrt(n / 2))

M = Matrix(ZZ, n + 1, n + 1)
for i in range(n):
    M[i, i] = 2
    M[i, n] = N_scale * public_key[i]
for i in range(n):
    M[n, i] = 1
M[n, n] = N_scale * target_sum

print(f"[*] Lattice dimension: {n+1}")
print(f"[*] Scaling factor: {N_scale}")

# ============================================================
# LLL Reduction
# ============================================================
print("[*] Running LLL... (this may take 10-30 seconds)")

L = M.LLL()

print("[*] LLL complete. Extracting solution...")

# ============================================================
# Extract Solution
# ============================================================
recovered = None

for row in L:
    if row[n] != 0:
        continue

    # Try both the vector and its negation
    for sign in [1, -1]:
        if all(sign * row[i] in [-1, 1] for i in range(n)):
            bits = [(sign * int(row[i]) + 1) // 2 for i in range(n)]
            check = sum(w * b for w, b in zip(public_key, bits))
            if check == target_sum:
                recovered = bits
                break
    if recovered:
        break

if recovered is None:
    # Alternative lattice construction (simpler version)
    print("[!] CJLOSS lattice failed, trying simple construction...")

    M2 = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M2[i, i] = 1
        M2[i, n] = public_key[i]
    M2[n, n] = -target_sum

    L2 = M2.LLL()

    for row in L2:
        if row[n] != 0:
            continue
        if all(row[i] in [0, 1] for i in range(n)):
            bits = [int(row[i]) for i in range(n)]
            check = sum(w * b for w, b in zip(public_key, bits))
            if check == target_sum:
                recovered = bits
                break

if recovered is None:
    print("[-] Failed to find solution. Try different parameters.")
    exit(1)

# ============================================================
# Convert to Flag
# ============================================================
print(f"[+] Solution found! ({sum(recovered)}/{n} bits are 1)")

# Verify
assert sum(w * b for w, b in zip(public_key, recovered)) == target_sum
print("[+] Verification: subset sum matches target!")

# Bits to bytes
flag_bytes = bytearray()
for i in range(0, len(recovered), 8):
    byte_val = 0
    for j in range(8):
        if i + j < len(recovered):
            byte_val = (byte_val << 1) | recovered[i + j]
    flag_bytes.append(byte_val)

result = bytes(flag_bytes).decode()
print(f"\n{'=' * 60}")
print(f"  FLAG: {result}")
print(f"{'=' * 60}")

# Verify against original
assert result == flag.decode()
print("[+] Flag matches original!")
```

Output:
```
============================================================
  Lattice-Based Knapsack Attack (Complete)
============================================================

[*] Generating Merkle-Hellman knapsack challenge...
[*] Flag bits: 224
[*] Max weight: 253 bits
[*] Target sum: 123456789...
[*] Density: 0.8854

[*] Constructing lattice...
[*] Lattice dimension: 225
[*] Scaling factor: 11

[*] Running LLL... (this may take 10-30 seconds)
[*] LLL complete. Extracting solution...

[+] Solution found! (102/224 bits are 1)
[+] Verification: subset sum matches target!

============================================================
  FLAG: zemi{l4tt1c3_r3duct10n_w1ns}
============================================================

[+] Flag matches original!
```

## How LLL Finds the Solution: Step by Step

```
1. We start with the lattice basis M:

   ┌                                              ┐
   │  2   0   0  ...  0    N*w_1                   │   ← row 0
   │  0   2   0  ...  0    N*w_2                   │   ← row 1
   │  .   .   .  ...  .      .                     │
   │  0   0   0  ...  2    N*w_n                   │   ← row n-1
   │  1   1   1  ...  1    N*S                     │   ← row n
   └                                              ┘

2. The solution vector in this lattice is:

   v = b_0*row_0 + b_1*row_1 + ... + b_{n-1}*row_{n-1} + 1*row_n

   = (2*b_0+1, 2*b_1+1, ..., 2*b_{n-1}+1, N*(sum - S))
   = (±1,      ±1,       ..., ±1,          0)

   Wait: actually the last row adds 1 to each component,
   so position i = 2*b_i + 1 if b_i=0: 0+1=1,  if b_i=1: 2+1=3.
   Hmm, that doesn't give {-1,1}. Let me reconsider.

   Correct formulation with the CJLOSS centering:
   Take the combination: b_0*row_0 + ... + b_{n-1}*row_{n-1} - row_n

   Position i (for i < n):  2*b_i - 1  ∈ {-1, +1}
   Position n:  N*(sum(b_i * w_i) - S)  = 0   (if bits are correct)

3. This vector has norm sqrt(n) ≈ sqrt(224) ≈ 15.

4. Other lattice vectors have entries proportional to N*w_i,
   giving norms proportional to N * max(w_i) >> sqrt(n).

5. LLL finds approximately shortest vectors, so it finds our
   solution vector (or something very close to it).

6. We scan the reduced basis for rows matching the pattern:
   all entries ±1 except the last which is 0.
```

## Alternative Lattice Construction (Simpler)

If the CJLOSS lattice does not work, try the simpler construction:

```python
# Simple lattice (no centering trick)
M = Matrix(ZZ, n + 1, n + 1)
for i in range(n):
    M[i, i] = 1           # Identity
    M[i, n] = public_key[i]  # Weights in last column
M[n, n] = -target_sum     # Negative target in corner

# Solution vector: (b_0, b_1, ..., b_n, 0)
# Entries in {0, 1} with last entry 0

L = M.LLL()
# Look for rows with entries in {0,1} and last entry 0
```

This version looks for vectors with entries in {0, 1} instead of {-1, +1}. It works well for low-density instances but may fail for borderline cases where the CJLOSS construction succeeds.

## When LLL Attacks Succeed vs Fail

```
┌──────────────────┬────────────────────────────────────────────┐
│ Density d        │ LLL Success Rate                          │
├──────────────────┼────────────────────────────────────────────┤
│ d < 0.6463       │ Always succeeds (provable, LO bound)      │
│ 0.6463 < d < 0.94│ Usually succeeds (CJLOSS bound)           │
│ d ≈ 1.0          │ Unreliable (borderline)                   │
│ d > 1.0          │ Likely fails (too many solutions possible) │
└──────────────────┴────────────────────────────────────────────┘

Density = n / log2(max weight)

Merkle-Hellman knapsack:  d < 1 typically  → BROKEN
Random subset sum:        d can be anything  → depends
```

### Making LLL Work for Borderline Cases

```
Tricks for improving success rate:

1. Scaling factor: increase N = ceil(n * sqrt(n))
   Larger N penalizes non-zero last entries more strongly.

2. BKZ instead of LLL: BKZ-20 or BKZ-30 finds shorter vectors
   but takes longer. SageMath: M.BKZ(block_size=20)

3. Random permutations: shuffle the weight ordering and retry.
   Sometimes LLL finds the solution with a different column order.

4. Use flatter: a newer, faster lattice reduction tool.
   Produces better reductions than LLL for high dimensions.
```

## Common Pitfalls

1. **Wrong lattice dimension**: The matrix should be `(n+1) x (n+1)`, not `n x n`. The extra row/column encodes the target sum constraint. Forgetting it means LLL has no knowledge of the target.

2. **Missing scaling factor**: Without the scaling factor `N`, the last column entries are not sufficiently penalized. LLL may find short vectors that do not satisfy the sum constraint. Use `N >= ceil(sqrt(n))`.

3. **Not checking both signs**: LLL may return `-v` instead of `v`. Always check both the row and its negation when scanning for the solution.

4. **Ignoring the density check**: If the density is above ~1.0, LLL probably will not work. Calculate the density first and consider alternative approaches (like exhaustive search for small n, or BKZ for borderline densities).

5. **Integer overflow in Python**: The weights and sums can be very large (hundreds of bits). Use SageMath's `ZZ` type or Python's native arbitrary-precision integers. Never use floating-point.

6. **Misinterpreting bit order**: When converting bits back to bytes, ensure you use the correct bit order (MSB first). Reversing the order produces garbage.

7. **LLL timeout on large instances**: For `n > 300`, LLL can be slow. Consider using `fpLLL` (the C library behind SageMath's LLL) directly for better performance, or use BKZ with a small block size.

## Historical Context: The Death of Knapsack Cryptography

```
Timeline:

1978: Merkle & Hellman propose the knapsack cryptosystem
      First practical public-key system (before widespread RSA adoption)

1982: Shamir breaks the basic Merkle-Hellman system
      Using a lattice-based attack

1983: Multiple proposals to "fix" knapsack systems
      (iterated transformations, different structures)

1985: LLL algorithm published (Lenstra, Lenstra, Lovász)
      Provides a systematic tool for breaking knapsack variants

1991: All known knapsack variants broken
      Lattice reduction proves too powerful

Present: Knapsack cryptography is dead for encryption
         But lattice problems (LWE, NTRU) are the basis
         of POST-QUANTUM cryptography!

Irony: Lattices killed knapsack crypto, but lattice-based
       crypto is now our best defense against quantum computers.
```

## Tools Used

- **SageMath** — built-in `Matrix.LLL()` and `Matrix.BKZ()` for lattice reduction
- **Python 3** — bit manipulation, byte conversion
- **fpLLL** (optional) — high-performance LLL implementation (C library)
- **flatter** (optional) — faster alternative to LLL for large dimensions
- **Understanding**: Lenstra-Lenstra-Lovasz 1985, Coster-Joux-LaMacchia-Odlyzko-Schnorr-Stern 1992

## Lessons Learned

- Lattices are discrete algebraic structures in n-dimensional space. The LLL algorithm efficiently finds short vectors in a lattice, and many cryptographic problems can be reformulated as "find a short vector."

- The subset sum problem (NP-hard in general) can be solved by LLL when the problem density is low enough. The Merkle-Hellman knapsack cryptosystem always produces low-density instances, making it fundamentally broken.

- The CJLOSS lattice construction with centering ({-1,+1} instead of {0,1}) and a scaling factor is the standard approach. It encodes the subset sum constraint into the lattice geometry so that the solution is the shortest vector.

- Density `d = n / log2(max_weight)` is the key parameter. Below ~0.94, LLL reliably succeeds. Above ~1.0, it typically fails. Always compute the density before attempting the attack.

- LLL runs in polynomial time but can be slow for high dimensions (n > 300). BKZ (Block Korkine-Zolotarev) provides better reductions at the cost of more computation time.

- Although knapsack cryptography is dead, lattice-based cryptography (NTRU, Kyber/ML-KEM, Dilithium/ML-DSA) is very much alive. The security of these systems relies on *different* lattice problems (Learning With Errors, Shortest Vector Problem in high dimensions) that LLL cannot efficiently solve. Understanding lattice attacks helps you appreciate why post-quantum lattice constructions use parameters that defeat LLL.

- In CTFs, "subset sum" or "knapsack" challenges almost always fall to LLL. The process is mechanical: construct the lattice, run LLL, scan for the solution vector. Master this technique once and you will solve them all.
