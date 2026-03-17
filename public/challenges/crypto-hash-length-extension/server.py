#!/usr/bin/env python3
"""
Hash Length Extension - Crypto CTF Challenge

This server uses MAC = MD5(secret || message) to authenticate requests.
The secret is 16 bytes long. You know a valid (message, MAC) pair.
Can you forge a new MAC for a message containing "admin=true"?

Run this script locally:
    python3 server.py

Then interact with it to submit your forged MAC.

Hint: Look into hash length extension attacks and tools like HashPump.
"""

import hashlib
import sys
from urllib.parse import unquote

# The secret key (you don't know this!)
SECRET = b"supersecretkey42"
FLAG = "zemi{h4sh_l3ngth_3xt3ns10n_ftw}"

def compute_mac(message: bytes) -> str:
    """Compute MAC = MD5(secret || message)."""
    return hashlib.md5(SECRET + message).hexdigest()

def parse_params(message: str) -> dict:
    """Parse key=value&key=value format."""
    params = {}
    for pair in message.split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            params[key] = value
    return params

def main():
    print("=" * 60)
    print("  Hash Length Extension Challenge")
    print("=" * 60)
    print()
    print("This server validates requests using MAC = MD5(secret || message)")
    print("The secret is 16 bytes long.")
    print()
    print("Known valid pair:")
    known_message = b"user=guest&admin=false"
    known_mac = compute_mac(known_message)
    print(f"  Message: {known_message.decode()}")
    print(f"  MAC:     {known_mac}")
    print()
    print("Your goal: Submit a message containing 'admin=true' with a valid MAC.")
    print("(The message must still start with the original message + padding)")
    print()

    while True:
        try:
            print("-" * 40)
            msg_hex = input("Enter your message (hex-encoded): ").strip()
            mac = input("Enter your MAC: ").strip()

            if not msg_hex or not mac:
                print("Empty input. Try again.")
                continue

            message = bytes.fromhex(msg_hex)

            # Verify the MAC
            expected_mac = compute_mac(message)

            if mac.lower() != expected_mac.lower():
                print(f"[-] Invalid MAC!")
                print(f"    Expected: {expected_mac}")
                print(f"    Got:      {mac.lower()}")
                continue

            # Check if the message (decoded) contains admin=true
            # We need to find admin=true anywhere in the message bytes
            if b"admin=true" in message:
                print(f"[+] Valid MAC and admin=true found!")
                print(f"[+] FLAG: {FLAG}")
                break
            else:
                print("[+] Valid MAC, but 'admin=true' not found in message.")
                print("    Try appending '&admin=true' using the length extension attack.")

        except (ValueError, KeyboardInterrupt) as e:
            if isinstance(e, KeyboardInterrupt):
                print("\nBye!")
                sys.exit(0)
            print(f"Error: {e}")
            continue

if __name__ == "__main__":
    main()
