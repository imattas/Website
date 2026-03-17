#!/usr/bin/env python3
"""
Elliptic Curve ECDLP - Crypto CTF Challenge

This challenge uses an ANOMALOUS elliptic curve where #E(Fp) == p.
This makes the curve vulnerable to Smart's attack (also called the
SSSA attack - Satoh, Araki, Smart, Semaev).

Smart's attack lifts the curve to Q_p (p-adic numbers) and solves
the discrete log in O(1) — no brute force needed!

Find the secret scalar k such that Q = k * G.
The flag is: zemi{k} where k is the decimal value.

Solve with SageMath:
    E = EllipticCurve(GF(p), [a, b])
    assert E.order() == p  # Anomalous!
    G = E(Gx, Gy)
    Q = E(Qx, Qy)
    # Use Smart's attack / E.lift_x() with p-adic lifting
"""

def point_add(P, Q, a, p):
    """Add two points on the elliptic curve y^2 = x^3 + ax + b over Fp."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None  # Point at infinity
        lam = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    else:
        lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(k, P, a, p):
    """Scalar multiplication using double-and-add."""
    result = None
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1
    return result

def main():
    # Anomalous elliptic curve parameters
    # y^2 = x^3 + ax + b over Fp
    # The order of the curve #E(Fp) == p (this is what makes it anomalous)
    p = 233970423115425145524320034830162017933
    a = -95051
    b = 11279326

    # Generator point
    G = (2, 231680015444488040975472335857702294121)

    # Secret scalar (this is what you need to find!)
    k = 177777773333333377777777

    # Public point Q = k * G
    Q = point_mul(k, G, a, p)

    # Write challenge output
    with open("output.txt", "w") as f:
        f.write("# Elliptic Curve: y^2 = x^3 + ax + b (mod p)\n")
        f.write(f"p = {p}\n")
        f.write(f"a = {a}\n")
        f.write(f"b = {b}\n")
        f.write(f"\n")
        f.write(f"# Generator point G\n")
        f.write(f"Gx = {G[0]}\n")
        f.write(f"Gy = {G[1]}\n")
        f.write(f"\n")
        f.write(f"# Public point Q = k * G (find k!)\n")
        f.write(f"Qx = {Q[0]}\n")
        f.write(f"Qy = {Q[1]}\n")
        f.write(f"\n")
        f.write(f"# Hint: This curve is anomalous (#E(Fp) == p)\n")
        f.write(f"# Flag format: zemi{{k}} where k is the decimal value of the scalar\n")

    print("[+] Anomalous elliptic curve challenge generated")
    print(f"[+] Curve: y^2 = x^3 + ({a})x + {b} over F_{p}")
    print(f"[+] G = {G}")
    print(f"[+] Q = {Q}")
    print(f"[+] Hint: #E(Fp) == p (anomalous!)")
    print(f"[+] Written to output.txt")

if __name__ == "__main__":
    main()
