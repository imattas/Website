#!/usr/bin/env python3
"""
Forensics Challenge: Hidden in Plain Sight
Creates a PNG image with a ZIP file appended after the PNG end marker (IEND).
The ZIP contains flag.txt. Tools like binwalk or manual inspection reveal it.

Usage: python3 generate.py
Output: challenge.png (a valid PNG that also contains a hidden ZIP)
"""

import struct
import zlib
import zipfile
import io
import os

FLAG = "zemi{st3g0_1s_fr33_r34l_3st4t3}"

def create_minimal_png(width=100, height=100):
    """Create a minimal valid PNG image (solid red square)."""
    def make_chunk(chunk_type, data):
        chunk = chunk_type + data
        crc = struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)
        return struct.pack(">I", len(data)) + chunk + crc

    # PNG signature
    signature = b"\x89PNG\r\n\x1a\n"

    # IHDR chunk: width, height, bit depth 8, color type 2 (RGB)
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr = make_chunk(b"IHDR", ihdr_data)

    # IDAT chunk: raw image data (solid red pixels)
    raw_rows = b""
    for _ in range(height):
        raw_rows += b"\x00"  # filter byte (None)
        raw_rows += b"\xff\x00\x00" * width  # red pixels
    compressed = zlib.compress(raw_rows)
    idat = make_chunk(b"IDAT", compressed)

    # IEND chunk
    iend = make_chunk(b"IEND", b"")

    return signature + ihdr + idat + iend


def create_hidden_zip(flag_text):
    """Create a ZIP file in memory containing flag.txt."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("flag.txt", flag_text + "\n")
    return buf.getvalue()


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.png")

    png_data = create_minimal_png()
    zip_data = create_hidden_zip(FLAG)

    # Append the ZIP after the PNG IEND marker
    with open(output_path, "wb") as f:
        f.write(png_data)
        f.write(zip_data)

    png_size = len(png_data)
    total_size = png_size + len(zip_data)
    print(f"[+] Created {output_path}")
    print(f"    PNG data ends at byte {png_size}")
    print(f"    ZIP data appended ({len(zip_data)} bytes)")
    print(f"    Total file size: {total_size} bytes")
    print()
    print("To solve:")
    print("  binwalk challenge.png")
    print("  binwalk -e challenge.png")
    print("  # or: dd if=challenge.png bs=1 skip={} | funzip".format(png_size))


if __name__ == "__main__":
    main()
