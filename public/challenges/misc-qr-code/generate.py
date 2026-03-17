#!/usr/bin/env python3
"""
Misc Challenge: QR Code
Creates a QR code image containing the flag, then adds noise/damage
to make it harder to scan directly. Players may need to clean it up
or use error correction to decode it.

Usage: python3 generate.py
Output: challenge.png
Dependencies: pip install qrcode Pillow

If dependencies are unavailable, generates a text-based QR representation.
"""

import os
import random
import struct
import zlib

FLAG = "zemi{qr_d3c0d3_m4st3r}"


def create_qr_matrix(data):
    """
    Create a QR code matrix using the qrcode library.
    Falls back to a simple encoding if not available.
    """
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=2,
            error_correction=qrcode.constants.ERROR_CORRECT_H,  # High EC for resilience
            box_size=1,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        # Get the matrix
        matrix = []
        for row in qr.modules:
            matrix.append([1 if cell else 0 for cell in row])
        return matrix
    except ImportError:
        return None


def matrix_to_png(matrix, scale=10, noise_level=0.03):
    """Convert a binary matrix to PNG bytes with optional noise."""
    random.seed(42)

    height = len(matrix) * scale
    width = len(matrix[0]) * scale

    # Generate pixel data with noise
    raw_data = b""
    for y in range(height):
        raw_data += b"\x00"  # PNG filter: None
        for x in range(width):
            cell = matrix[y // scale][x // scale]

            # Add random noise to some pixels
            if random.random() < noise_level:
                # Flip the pixel or add gray noise
                if cell:
                    gray = random.randint(100, 200)  # Light noise on dark
                else:
                    gray = random.randint(50, 150)    # Dark noise on light
                raw_data += bytes([gray])
            else:
                raw_data += bytes([0 if cell else 255])

    # Build PNG file
    def make_chunk(chunk_type, data):
        chunk = chunk_type + data
        crc = struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)
        return struct.pack(">I", len(data)) + chunk + crc

    signature = b"\x89PNG\r\n\x1a\n"

    # IHDR: grayscale, 8-bit
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    ihdr = make_chunk(b"IHDR", ihdr_data)

    # IDAT
    compressed = zlib.compress(raw_data, 9)
    idat = make_chunk(b"IDAT", compressed)

    # IEND
    iend = make_chunk(b"IEND", b"")

    return signature + ihdr + idat + iend


def generate_text_qr_fallback(data, output_path):
    """Generate a text-based QR representation if libraries are unavailable."""
    # Create a simple visual encoding as a fallback
    lines = []
    lines.append("# QR Code Challenge")
    lines.append(f"# This file represents a damaged QR code encoding the flag.")
    lines.append(f"# Use an online QR code generator to re-create and compare.")
    lines.append("")

    # Create a simple pattern that encodes the flag in a grid
    binary = "".join(format(ord(c), "08b") for c in data)
    size = 25
    matrix = [[0] * size for _ in range(size)]

    # Place finder patterns (top-left, top-right, bottom-left)
    finder = [
        [1, 1, 1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0, 0, 1],
        [1, 0, 1, 1, 1, 0, 1],
        [1, 0, 1, 1, 1, 0, 1],
        [1, 0, 1, 1, 1, 0, 1],
        [1, 0, 0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 1, 1],
    ]
    for dy in range(7):
        for dx in range(7):
            matrix[dy][dx] = finder[dy][dx]
            matrix[dy][size - 7 + dx] = finder[dy][dx]
            matrix[size - 7 + dy][dx] = finder[dy][dx]

    # Fill data area with binary flag data
    idx = 0
    for y in range(8, size - 1):
        for x in range(8, size - 1):
            if idx < len(binary):
                matrix[y][x] = int(binary[idx])
                idx += 1

    # Render as text
    for row in matrix:
        line = ""
        for cell in row:
            line += "##" if cell else "  "
        lines.append(line)

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    return True


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    png_path = os.path.join(script_dir, "challenge.png")
    txt_path = os.path.join(script_dir, "challenge_qr.txt")

    matrix = create_qr_matrix(FLAG)

    if matrix:
        # Generate PNG with noise
        png_data = matrix_to_png(matrix, scale=10, noise_level=0.03)
        with open(png_path, "wb") as f:
            f.write(png_data)
        print(f"[+] Created {png_path}")
        print(f"    QR matrix: {len(matrix)}x{len(matrix[0])}")
        print(f"    Image: {len(matrix)*10}x{len(matrix[0])*10} pixels")
        print(f"    Noise level: 3% (some pixels flipped)")
        print(f"    Error correction: HIGH (allows ~30% damage)")
    else:
        print("[!] qrcode library not found, generating text-based QR fallback")
        generate_text_qr_fallback(FLAG, txt_path)
        print(f"[+] Created {txt_path}")

    print()
    print("To solve:")
    print("  # Scan with a QR reader (may need to clean noise first)")
    print("  # Use: zbarimg challenge.png")
    print("  # Or: python3 -c \"from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('challenge.png')))\"")


if __name__ == "__main__":
    main()
