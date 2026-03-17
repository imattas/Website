#!/usr/bin/env python3
"""
AES-CBC Bitflip Attack - Crypto CTF Challenge

This server creates an encrypted cookie with "role=user" and checks
for "role=admin". You can't control the plaintext directly, but you
CAN modify the ciphertext.

In CBC mode, flipping bit i of ciphertext block j-1 flips bit i of
plaintext block j (but corrupts block j-1). Since the IV is the
"ciphertext block -1" for block 0, you can modify the IV to flip
bits in the first plaintext block without losing any data.

Run locally:
    python3 server.py

Requires: pip install cryptography
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import sha256
import sys

# Secret key (you don't know this)
KEY = sha256(b"cbc_bitflip_key_2024").digest()[:16]
FLAG = "zemi{cbc_b1tfl1p_t0_4dm1n}"

def pad(data: bytes) -> bytes:
    """PKCS#7 padding."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    pad_len = data[-1]
    if pad_len > 16 or pad_len == 0:
        raise ValueError("Invalid padding")
    for i in range(pad_len):
        if data[-(i + 1)] != pad_len:
            raise ValueError("Invalid padding")
    return data[:-pad_len]

def encrypt_cookie() -> tuple:
    """Create an encrypted cookie with role=user."""
    iv = sha256(b"cbc_bitflip_iv_2024").digest()[:16]
    cookie = b"role=user;name=guest;session=abc"
    padded = pad(cookie)

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    return iv, ct

def decrypt_and_check(iv: bytes, ct: bytes) -> tuple:
    """Decrypt cookie and check for admin role."""
    try:
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        plaintext = unpad(padded)
        return True, plaintext
    except Exception as e:
        return False, str(e).encode()

def main():
    print("=" * 60)
    print("  AES-CBC Bitflip Challenge")
    print("=" * 60)
    print()

    # Generate the cookie
    iv, ct = encrypt_cookie()

    print("Your encrypted cookie:")
    print(f"  IV (hex):         {iv.hex()}")
    print(f"  Ciphertext (hex): {ct.hex()}")
    print()
    print("Cookie format: role=user;name=guest;session=abc")
    print("Block layout:")
    print("  Block 0 (XORed with IV): role=user;name=g")
    print("  Block 1 (XORed with CT0): uest;session=abc")
    print("  Block 2: PKCS#7 padding")
    print()
    print("Goal: Modify the IV and/or ciphertext so that the")
    print("      decrypted cookie contains 'role=admin'")
    print()
    print("Hint: In CBC, IV XOR decrypted_block0 = plaintext_block0")
    print("      Flip IV bytes to change 'user' to 'admn' (or get creative!)")
    print()

    while True:
        try:
            print("-" * 40)
            new_iv_hex = input("Enter modified IV (hex, 32 chars): ").strip()
            new_ct_hex = input("Enter ciphertext (hex, or press Enter for original): ").strip()

            if not new_ct_hex:
                new_ct_hex = ct.hex()

            new_iv = bytes.fromhex(new_iv_hex)
            new_ct = bytes.fromhex(new_ct_hex)

            if len(new_iv) != 16:
                print("ERROR: IV must be exactly 16 bytes (32 hex chars)")
                continue

            if len(new_ct) % 16 != 0:
                print("ERROR: Ciphertext must be a multiple of 16 bytes")
                continue

            success, plaintext = decrypt_and_check(new_iv, new_ct)

            if not success:
                print(f"[-] Decryption failed: {plaintext.decode()}")
                continue

            print(f"[*] Decrypted cookie: {plaintext}")

            if b"role=admin" in plaintext:
                print(f"[+] ACCESS GRANTED! You are admin!")
                print(f"[+] FLAG: {FLAG}")
                break
            else:
                print("[-] Access denied. 'role=admin' not found.")
                print("    Keep flipping those bits!")

        except ValueError as e:
            print(f"ERROR: {e}")
        except KeyboardInterrupt:
            print("\nBye!")
            sys.exit(0)

if __name__ == "__main__":
    main()
