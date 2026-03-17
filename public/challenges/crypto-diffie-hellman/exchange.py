#!/usr/bin/env python3
"""
Weak Diffie-Hellman - Crypto CTF Challenge

This DH key exchange uses a prime p where p-1 is SMOOTH (all prime
factors of p-1 are small, <= 97). This makes it vulnerable to the
Pohlig-Hellman algorithm, which solves the discrete log by breaking
it into small subgroup problems.

Steps to attack:
1. Factor p-1 (it's B-smooth, all factors <= 97)
2. Use Pohlig-Hellman to find Alice's secret 'a' from g and A
3. Compute shared_secret = B^a mod p
4. Derive AES key: SHA256(str(shared_secret))[:16]
5. Decrypt the flag with AES-CBC

Requires: pip install cryptography sympy
"""

from math import gcd
from hashlib import sha256
from sympy import isprime
import random

def main():
    # Smooth prime construction
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
                    47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

    random.seed(42)
    product = 1
    for pr in small_primes:
        product *= pr
    for pr in small_primes[:15]:
        product *= pr
    for pr in small_primes[:10]:
        product *= pr
    for pr in small_primes[:5]:
        product *= pr

    while not isprime(product + 1) or (product + 1).bit_length() < 256:
        pr = small_primes[random.randint(0, len(small_primes) - 1)]
        product *= pr
        if (product + 1).bit_length() > 300:
            product = 1
            random.seed(random.randint(0, 10000))
            for _ in range(80):
                pr = small_primes[random.randint(0, len(small_primes) - 1)]
                product *= pr

    p = product + 1

    # Generator
    g = 2
    while pow(g, product // 2, p) == 1:
        g += 1

    # Key exchange
    a = random.randint(2, p - 2)  # Alice's secret
    b = random.randint(2, p - 2)  # Bob's secret
    A = pow(g, a, p)  # Alice's public
    B = pow(g, b, p)  # Bob's public

    # Shared secret
    shared = pow(B, a, p)

    # Encrypt flag with AES-CBC using shared secret
    aes_key = sha256(str(shared).encode()).digest()[:16]
    flag = b"zemi{sm00th_pr1m3_p0hl1g_h3llm4n}"

    # PKCS7 pad
    pad_len = 16 - (len(flag) % 16)
    padded = flag + bytes([pad_len] * pad_len)

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = sha256(b"dh_challenge_iv").digest()[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()

    # Write output (public values only)
    with open("output.txt", "w") as f:
        f.write("# Diffie-Hellman Key Exchange (weak parameters)\n")
        f.write(f"p = {p}\n")
        f.write(f"g = {g}\n")
        f.write(f"A = {A}  # Alice's public key: g^a mod p\n")
        f.write(f"B = {B}  # Bob's public key:   g^b mod p\n")
        f.write(f"\n")
        f.write(f"# Encrypted flag (AES-128-CBC)\n")
        f.write(f"# Key derivation: AES_key = SHA256(str(shared_secret))[:16]\n")
        f.write(f"# shared_secret = B^a mod p = A^b mod p\n")
        f.write(f'iv = "{iv.hex()}"\n')
        f.write(f'encrypted_flag = "{ct.hex()}"\n')
        f.write(f"\n")
        f.write(f"# Hint: p-1 is {p.bit_length()}-smooth (all prime factors <= 97)\n")
        f.write(f"# Use Pohlig-Hellman to solve the discrete log!\n")

    print(f"[+] Weak DH challenge generated")
    print(f"[+] p is {p.bit_length()} bits with smooth p-1")
    print(f"[+] All factors of p-1 are <= 97")
    print(f"[+] Written to output.txt")

if __name__ == "__main__":
    main()
