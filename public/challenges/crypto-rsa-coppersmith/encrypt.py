#!/usr/bin/env python3
"""
RSA Coppersmith - Crypto CTF Challenge

RSA with a small public exponent (e=3) and a partially known message.
You know the prefix of the plaintext. Use Coppersmith's method
(small roots of polynomials modulo n) to recover the full message.

The idea:
  m = known_prefix_int * 256^unknown_len + x
  c = m^e mod n

  You need to find x (the unknown suffix) using Coppersmith's theorem.

Tools: SageMath's small_roots() function is ideal for this.
"""

from math import gcd
from sympy import nextprime
import random

def main():
    # Generate RSA parameters with e=3
    random.seed(0)
    while True:
        p = nextprime(random.getrandbits(512))
        q = nextprime(random.getrandbits(512))
        phi = (p - 1) * (q - 1)
        if gcd(3, phi) == 1:
            break

    n = p * q
    e = 3

    # Message with known prefix
    flag = b"The flag is: zemi{c0pp3rsm1th_sh0rt_p4d}"
    known_prefix = b"The flag is: zemi{"
    unknown_suffix = flag[len(known_prefix):]

    m = int.from_bytes(flag, "big")
    assert m < n, "Message must be smaller than n"

    c = pow(m, e, n)

    # Write output
    with open("output.txt", "w") as f:
        f.write(f"n = {n}\n")
        f.write(f"e = {e}\n")
        f.write(f"c = {c}\n")
        f.write(f'known_prefix = "{known_prefix.decode()}"\n')
        f.write(f"unknown_suffix_length = {len(unknown_suffix)}  # bytes\n")
        f.write(f"total_message_length = {len(flag)}  # bytes\n")

    print("[+] RSA Coppersmith challenge generated")
    print(f"[+] e = {e} (small exponent)")
    print(f"[+] Known prefix: {known_prefix.decode()}")
    print(f"[+] Unknown suffix: {len(unknown_suffix)} bytes")
    print("[+] Written to output.txt")
    print()
    print("[+] Solve with SageMath:")
    print("    # In SageMath:")
    print("    # P.<x> = PolynomialRing(Zmod(n))")
    print("    # prefix_int = int.from_bytes(known_prefix, 'big')")
    print("    # f = (prefix_int * 256^suffix_len + x)^e - c")
    print("    # roots = f.small_roots(X=256^suffix_len, beta=1)")

if __name__ == "__main__":
    main()
