#!/usr/bin/env python3
"""
RSA Common Modulus - Crypto CTF Challenge

The same message is encrypted with the same modulus n but two different
public exponents e1 and e2 where gcd(e1, e2) = 1.

This is vulnerable to the Common Modulus Attack:
  If gcd(e1, e2) = 1, find s1, s2 via extended GCD such that:
    e1*s1 + e2*s2 = 1
  Then:
    m = c1^s1 * c2^s2 mod n
"""

from math import gcd
from sympy import nextprime
import random

def main():
    # Generate RSA parameters
    random.seed(100)
    while True:
        p = nextprime(random.getrandbits(512))
        q = nextprime(random.getrandbits(512))
        phi = (p - 1) * (q - 1)
        if gcd(17, phi) == 1 and gcd(65537, phi) == 1:
            break

    n = p * q
    e1 = 17
    e2 = 65537

    assert gcd(e1, e2) == 1, "e1 and e2 must be coprime for the attack"

    # Encrypt the flag with both public keys
    flag = b"zemi{c0mm0n_m0dulus_4tt4ck}"
    m = int.from_bytes(flag, "big")
    assert m < n

    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)

    # Write output
    with open("output.txt", "w") as f:
        f.write(f"n = {n}\n")
        f.write(f"e1 = {e1}\n")
        f.write(f"e2 = {e2}\n")
        f.write(f"c1 = {c1}\n")
        f.write(f"c2 = {c2}\n")

    print("[+] Same message encrypted with two different exponents")
    print(f"[+] gcd(e1, e2) = {gcd(e1, e2)}")
    print("[+] Written to output.txt")

if __name__ == "__main__":
    main()
