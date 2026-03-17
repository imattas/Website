#!/usr/bin/env python3
"""
RSA Beginner - Crypto CTF Challenge
RSA encryption with small primes. Can you factor n?

The primes used here are small enough to be factored by online tools
like factordb.com or local tools like yafu/msieve.
"""

from math import gcd

def main():
    # Two "small" primes (128-bit each) — factorable with modern tools
    p = 170141183460469231731687303715884105757
    q = 340282366920938463463374607431768211507

    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)

    assert gcd(e, phi) == 1

    # The flag
    flag = b"zemi{sm4ll_pr1m3s_ar3_w34k}"
    m = int.from_bytes(flag, "big")
    assert m < n, "Message must be smaller than n"

    # Encrypt
    c = pow(m, e, n)

    # Write output
    with open("output.txt", "w") as f:
        f.write(f"n = {n}\n")
        f.write(f"e = {e}\n")
        f.write(f"c = {c}\n")

    print("[+] RSA encryption complete")
    print(f"[+] n ({n.bit_length()} bits) = {n}")
    print(f"[+] e = {e}")
    print(f"[+] c = {c}")
    print("[+] Written to output.txt")
    print("[+] Hint: n is small enough to factor!")

if __name__ == "__main__":
    main()
