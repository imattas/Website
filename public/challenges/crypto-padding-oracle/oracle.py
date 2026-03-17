#!/usr/bin/env python3
"""
Padding Oracle - Crypto CTF Challenge

This script simulates a padding oracle. It decrypts AES-CBC ciphertext
and tells you whether the PKCS#7 padding is valid or not.

Run locally:
    python3 oracle.py

The oracle accepts hex-encoded ciphertext (IV prepended) and responds
with "VALID" or "INVALID" padding. Use this information to perform a
padding oracle attack and recover the plaintext.

Requires: pip install cryptography
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import sha256
import sys

# Deterministic key (you don't know this)
KEY = sha256(b"padding_oracle_key").digest()[:16]

def check_padding(iv: bytes, ciphertext: bytes) -> bool:
    """
    Decrypt the ciphertext with AES-CBC and check PKCS#7 padding.
    Returns True if padding is valid, False otherwise.
    """
    try:
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Check PKCS#7 padding
        if len(plaintext) == 0:
            return False

        pad_byte = plaintext[-1]
        if pad_byte == 0 or pad_byte > 16:
            return False

        # Verify all padding bytes are correct
        for i in range(pad_byte):
            if plaintext[-(i + 1)] != pad_byte:
                return False

        return True

    except Exception:
        return False

def main():
    print("=" * 60)
    print("  Padding Oracle Challenge")
    print("=" * 60)
    print()
    print("Submit hex-encoded data (IV + ciphertext, each 16 bytes).")
    print("The oracle will tell you if the padding is valid.")
    print()
    print("Original ciphertext is in ciphertext.hex")
    print("(First 16 bytes = IV, rest = ciphertext)")
    print()
    print("Type 'quit' to exit.")
    print()

    query_count = 0

    while True:
        try:
            data_hex = input("Enter hex (IV+CT): ").strip()

            if data_hex.lower() in ("quit", "exit", "q"):
                print(f"\nTotal queries: {query_count}")
                print("Bye!")
                break

            data = bytes.fromhex(data_hex)

            if len(data) < 32 or len(data) % 16 != 0:
                print("ERROR: Data must be at least 32 bytes and a multiple of 16.")
                continue

            iv = data[:16]
            ct = data[16:]

            query_count += 1
            result = check_padding(iv, ct)

            if result:
                print("VALID")
            else:
                print("INVALID")

        except ValueError as e:
            print(f"ERROR: Invalid hex input - {e}")
        except KeyboardInterrupt:
            print(f"\nTotal queries: {query_count}")
            print("Bye!")
            sys.exit(0)

if __name__ == "__main__":
    main()
