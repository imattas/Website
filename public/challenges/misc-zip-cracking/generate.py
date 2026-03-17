#!/usr/bin/env python3
"""
Misc Challenge: ZIP Cracking
Creates a password-protected ZIP file containing flag.txt.
The password ("dragon") is in common wordlists like rockyou.txt.

Usage: python3 generate.py
Output: challenge.zip
Dependencies: pip install pyzipper  (for AES-encrypted ZIP)
              OR falls back to using the system 'zip' command

Players should use: fcrackzip, john, hashcat, or a custom brute-force script.
"""

import os
import subprocess
import sys

FLAG = "zemi{z1p_cr4ck3d_w1d3_0p3n}"
PASSWORD = "dragon"  # Common password found in rockyou.txt


def generate_with_pyzipper():
    """Create password-protected ZIP using pyzipper (AES encryption)."""
    import pyzipper

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.zip")

    with pyzipper.AESZipFile(output_path, "w",
                              compression=pyzipper.ZIP_DEFLATED,
                              encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(PASSWORD.encode())
        zf.writestr("flag.txt", FLAG + "\n")
        zf.writestr("readme.txt", "Congratulations! You cracked the ZIP.\n")

    return output_path


def generate_with_zipfile():
    """Create password-protected ZIP using standard zipfile (ZipCrypto - weaker but more compatible)."""
    import zipfile

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.zip")
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Write temp files
    flag_path = os.path.join(script_dir, "_tmp_flag.txt")
    readme_path = os.path.join(script_dir, "_tmp_readme.txt")

    with open(flag_path, "w") as f:
        f.write(FLAG + "\n")
    with open(readme_path, "w") as f:
        f.write("Congratulations! You cracked the ZIP.\n")

    # Use system zip command for password protection (zipfile module can't set passwords)
    try:
        subprocess.run(
            ["zip", "-P", PASSWORD, output_path, "_tmp_flag.txt", "_tmp_readme.txt"],
            cwd=script_dir,
            check=True,
            capture_output=True,
        )
    except FileNotFoundError:
        print("[!] 'zip' command not found and pyzipper not installed.")
        print("    Install pyzipper: pip install pyzipper")
        print("    Or install zip:   apt install zip")
        os.unlink(flag_path)
        os.unlink(readme_path)
        sys.exit(1)

    os.unlink(flag_path)
    os.unlink(readme_path)

    return output_path


def main():
    try:
        import pyzipper
        output_path = generate_with_pyzipper()
        method = "pyzipper (AES)"
    except ImportError:
        output_path = generate_with_zipfile()
        method = "system zip (ZipCrypto)"

    print(f"[+] Created {output_path}")
    print(f"    Method: {method}")
    print(f"    Password: {PASSWORD} (from rockyou.txt)")
    print()
    print("To solve:")
    print(f"  fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt challenge.zip")
    print(f"  # Or: zip2john challenge.zip > hash.txt && john hash.txt --wordlist=rockyou.txt")
    print(f"  # Or: hashcat -m 13600 hash.txt rockyou.txt  (for AES-encrypted ZIP)")
    print(f"  unzip -P dragon challenge.zip")


if __name__ == "__main__":
    main()
