#!/usr/bin/env python3
"""
Misc Challenge: LSB Steganography
Creates a PNG image with the flag hidden in the Least Significant Bit
of the red channel pixels.

Usage: python3 generate.py
Output: challenge.png
No external dependencies required (builds raw PNG).

To extract:
  Read pixel values, take LSB of red channel for each pixel,
  collect bits into bytes until null terminator.
"""

import struct
import zlib
import os

FLAG = "zemi{lsb_p1x3l_p3rf3ct}"


def create_image_with_lsb(width=200, height=200, flag_text=""):
    """Create a PNG image with flag hidden in LSB of red channel."""
    # Convert flag to bits (with null terminator)
    flag_bytes = flag_text.encode() + b"\x00"
    flag_bits = []
    for byte in flag_bytes:
        for bit_pos in range(7, -1, -1):
            flag_bits.append((byte >> bit_pos) & 1)

    # Generate image pixel data (a gradient image so it looks natural)
    raw_rows = b""
    bit_index = 0

    for y in range(height):
        raw_rows += b"\x00"  # PNG filter: None
        for x in range(width):
            # Base colors: a blue-purple gradient
            r = int(100 + 80 * (x / width))
            g = int(80 + 60 * (y / height))
            b = int(150 + 50 * ((x + y) / (width + height)))

            # Embed flag bit in LSB of red channel
            if bit_index < len(flag_bits):
                r = (r & 0xFE) | flag_bits[bit_index]
                bit_index += 1
            else:
                # After flag is embedded, keep LSB random-ish (based on position)
                r = (r & 0xFE) | ((x * y + x + y) & 1)

            raw_rows += bytes([r & 0xFF, g & 0xFF, b & 0xFF])

    return raw_rows, width, height


def build_png(raw_rows, width, height):
    """Build a PNG file from raw pixel data."""
    def make_chunk(chunk_type, data):
        chunk = chunk_type + data
        crc = struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)
        return struct.pack(">I", len(data)) + chunk + crc

    signature = b"\x89PNG\r\n\x1a\n"

    # IHDR: RGB, 8-bit
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr = make_chunk(b"IHDR", ihdr_data)

    # IDAT
    compressed = zlib.compress(raw_rows, 9)
    idat = make_chunk(b"IDAT", compressed)

    # tEXt chunk (innocent-looking metadata)
    text_data = b"Comment\x00A beautiful gradient image. Nothing to see here."
    text = make_chunk(b"tEXt", text_data)

    # IEND
    iend = make_chunk(b"IEND", b"")

    return signature + ihdr + text + idat + iend


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.png")

    print("[*] Creating gradient image with LSB-encoded flag...")
    raw_rows, width, height = create_image_with_lsb(200, 200, FLAG)

    print("[*] Building PNG...")
    png_data = build_png(raw_rows, width, height)

    with open(output_path, "wb") as f:
        f.write(png_data)

    flag_bits = (len(FLAG) + 1) * 8  # +1 for null terminator
    print(f"[+] Created {output_path}")
    print(f"    Image: {width}x{height} RGB")
    print(f"    Flag bits embedded: {flag_bits}")
    print(f"    Pixels used: {flag_bits} out of {width * height}")
    print()
    print("To solve:")
    print("  python3 -c \"")
    print("    from PIL import Image")
    print("    img = Image.open('challenge.png')")
    print("    pixels = list(img.getdata())")
    print("    bits = [p[0] & 1 for p in pixels]  # LSB of red channel")
    print("    chars = []")
    print("    for i in range(0, len(bits), 8):")
    print("        byte = 0")
    print("        for j in range(8):")
    print("            if i + j < len(bits):")
    print("                byte = (byte << 1) | bits[i + j]")
    print("        if byte == 0: break")
    print("        chars.append(chr(byte))")
    print("    print(''.join(chars))")
    print("  \"")
    print()
    print("  # Or use: zsteg challenge.png")
    print("  # Or use: stegsolve (check Red plane 0)")


if __name__ == "__main__":
    main()
