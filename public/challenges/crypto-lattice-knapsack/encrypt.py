#!/usr/bin/env python3
"""
Merkle-Hellman Knapsack - Crypto CTF Challenge

The Merkle-Hellman knapsack cryptosystem was one of the first public-key
cryptosystems. It was broken by Shamir in 1984 using lattice reduction (LLL).

The encryption works by:
1. Private key: a superincreasing sequence w[]
2. Choose q > sum(w) and r coprime to q
3. Public key: beta[i] = (r * w[i]) mod q
4. Encrypt: convert message to bits, sum beta[i] where bit[i] == 1

To break it: use the LLL lattice basis reduction algorithm to solve the
subset sum problem. SageMath makes this straightforward.
"""

import random
from math import gcd

def generate_keys(n_bits, seed=2024):
    """Generate Merkle-Hellman knapsack keys."""
    random.seed(seed)

    # Private key: superincreasing sequence
    w = []
    total = 0
    for i in range(n_bits):
        next_val = total + random.randint(1, 100)
        w.append(next_val)
        total += next_val

    # Choose q > sum(w) and r coprime to q
    q = total + random.randint(1, 10000)
    while True:
        r = random.randint(2, q - 1)
        if gcd(r, q) == 1:
            break

    # Public key
    beta = [(r * wi) % q for wi in w]

    return w, q, r, beta

def encrypt(message: bytes, public_key: list) -> int:
    """Encrypt a message using the knapsack public key."""
    bits = ''.join(format(byte, '08b') for byte in message)
    assert len(bits) <= len(public_key), "Message too long for key"

    return sum(public_key[i] for i in range(len(bits)) if bits[i] == '1')

def decrypt(ciphertext: int, w: list, q: int, r: int, n_bits: int) -> bytes:
    """Decrypt using the private key."""
    r_inv = pow(r, -1, q)
    s = (ciphertext * r_inv) % q

    # Solve superincreasing knapsack
    bits = []
    remaining = s
    for i in range(n_bits - 1, -1, -1):
        if remaining >= w[i]:
            bits.append('1')
            remaining -= w[i]
        else:
            bits.append('0')
    bits.reverse()

    bit_str = ''.join(bits)
    return bytes(int(bit_str[i:i + 8], 2) for i in range(0, len(bit_str), 8))

def main():
    flag = b"zemi{m3rkl3_h3llm4n_br0k3n}"
    n_bits = len(flag) * 8

    # Generate keys
    w, q, r, public_key = generate_keys(n_bits)

    # Encrypt
    ciphertext = encrypt(flag, public_key)

    # Verify decryption
    recovered = decrypt(ciphertext, w, q, r, n_bits)
    assert recovered == flag, f"Decryption failed: {recovered}"

    # Write output (only public information)
    with open("output.txt", "w") as f:
        f.write(f"# Merkle-Hellman Knapsack Cryptosystem\n")
        f.write(f"# Public key and ciphertext only — can you break it?\n\n")
        f.write(f"# Public key (list of {n_bits} weights)\n")
        f.write(f"public_key = {public_key}\n\n")
        f.write(f"# Ciphertext (subset sum of selected weights)\n")
        f.write(f"ciphertext = {ciphertext}\n\n")
        f.write(f"# Message length: {len(flag)} bytes ({n_bits} bits)\n")

    print(f"[+] Merkle-Hellman knapsack encryption complete")
    print(f"[+] Public key: {n_bits} weights")
    print(f"[+] Ciphertext: {ciphertext}")
    print(f"[+] Written to output.txt")
    print(f"[+] Break with LLL lattice reduction!")

if __name__ == "__main__":
    main()
