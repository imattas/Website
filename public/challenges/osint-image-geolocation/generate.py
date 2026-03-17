#!/usr/bin/env python3
"""
OSINT Challenge: Image Geolocation
Creates a JPEG image with EXIF metadata containing GPS coordinates
and the flag hidden in the EXIF UserComment field.

Usage: python3 generate.py
Output: challenge.jpg
No external dependencies required (builds raw JPEG with EXIF from scratch).

Players should use exiftool, exiv2, or Python's PIL/Pillow to extract metadata.
"""

import struct
import os

FLAG = "zemi{g30l0c4t10n_f0und}"

# GPS coordinates for the Eiffel Tower, Paris (48.8584, 2.2945)
GPS_LAT = (48, 51, 30.24)     # 48 degrees, 51 minutes, 30.24 seconds N
GPS_LON = (2, 17, 40.20)      # 2 degrees, 17 minutes, 40.20 seconds E
GPS_LAT_REF = "N"
GPS_LON_REF = "E"


def encode_rational(numerator, denominator):
    """Encode a TIFF rational value (two unsigned longs)."""
    return struct.pack("<II", int(numerator), int(denominator))


def encode_string(s):
    """Encode a string for EXIF (null-terminated)."""
    return s.encode("ascii") + b"\x00"


def make_ifd_entry(tag, type_id, count, value_or_offset):
    """Create a single IFD entry (12 bytes)."""
    return struct.pack("<HHI", tag, type_id, count) + value_or_offset


def build_exif_data():
    """Build EXIF APP1 segment with GPS and flag metadata."""
    # We'll build a simplified EXIF structure
    # EXIF is essentially TIFF format embedded in JPEG

    # TIFF header (little-endian)
    tiff_header = b"II"  # Little-endian
    tiff_header += struct.pack("<H", 42)  # TIFF magic
    tiff_header += struct.pack("<I", 8)   # Offset to first IFD

    # We'll collect data areas that go after the IFDs
    data_area = b""
    # Start of data area (after TIFF header + IFD0 entries + next IFD pointer)
    # IFD0: we'll have ~8 entries (12 bytes each) + 2 bytes count + 4 bytes next
    # = 2 + 8*12 + 4 = 102 bytes from start of TIFF = offset 110

    # === IFD0 (main image metadata) ===
    ifd0_entries = []

    # Prepare strings and their offsets
    # We need to know the IFD size first to calculate data offsets
    num_ifd0_entries = 7
    ifd0_size = 2 + num_ifd0_entries * 12 + 4  # count + entries + next_ifd_ptr
    data_offset_base = 8 + ifd0_size  # TIFF header (8) + IFD0

    # We'll also have a GPS IFD and an EXIF IFD
    # For simplicity, put GPS IFD right after IFD0's data area

    # Tag 0x010E - ImageDescription
    desc = b"Forensics OSINT Challenge Photo\x00"
    desc_offset = data_offset_base + len(data_area)
    if len(desc) <= 4:
        ifd0_entries.append(make_ifd_entry(0x010E, 2, len(desc), desc.ljust(4, b"\x00")))
    else:
        ifd0_entries.append(make_ifd_entry(0x010E, 2, len(desc), struct.pack("<I", desc_offset)))
        data_area += desc

    # Tag 0x010F - Make
    make = b"Canon\x00"
    make_offset = data_offset_base + len(data_area)
    ifd0_entries.append(make_ifd_entry(0x010F, 2, len(make), struct.pack("<I", make_offset)))
    data_area += make

    # Tag 0x0110 - Model
    model = b"Canon EOS R5\x00"
    model_offset = data_offset_base + len(data_area)
    ifd0_entries.append(make_ifd_entry(0x0110, 2, len(model), struct.pack("<I", model_offset)))
    data_area += model

    # Tag 0x0131 - Software
    software = b"Adobe Lightroom 6.0\x00"
    sw_offset = data_offset_base + len(data_area)
    ifd0_entries.append(make_ifd_entry(0x0131, 2, len(software), struct.pack("<I", sw_offset)))
    data_area += software

    # Tag 0x013B - Artist (hide a hint here)
    artist = b"CTF Photographer\x00"
    artist_offset = data_offset_base + len(data_area)
    ifd0_entries.append(make_ifd_entry(0x013B, 2, len(artist), struct.pack("<I", artist_offset)))
    data_area += artist

    # Tag 0x9286 - UserComment (THE FLAG IS HERE)
    # UserComment format: 8-byte charset ID + comment
    user_comment = b"ASCII\x00\x00\x00" + FLAG.encode()
    uc_offset = data_offset_base + len(data_area)
    ifd0_entries.append(make_ifd_entry(0x9286, 7, len(user_comment), struct.pack("<I", uc_offset)))
    data_area += user_comment

    # Tag 0x8825 - GPSInfoIFDPointer (offset to GPS IFD)
    # GPS IFD will be placed after data_area
    gps_ifd_offset = data_offset_base + len(data_area)
    ifd0_entries.append(make_ifd_entry(0x8825, 4, 1, struct.pack("<I", gps_ifd_offset)))

    # === Build IFD0 ===
    ifd0 = struct.pack("<H", len(ifd0_entries))
    for entry in ifd0_entries:
        ifd0 += entry
    ifd0 += struct.pack("<I", 0)  # Next IFD offset (0 = no more IFDs)

    # === GPS IFD ===
    # Build GPS data
    gps_entries = []
    gps_num_entries = 4
    gps_ifd_size = 2 + gps_num_entries * 12 + 4
    gps_data_offset_base = gps_ifd_offset + gps_ifd_size

    gps_data = b""

    # Tag 0x0001 - GPSLatitudeRef ("N")
    lat_ref = b"N\x00"
    gps_entries.append(make_ifd_entry(0x0001, 2, 2, lat_ref.ljust(4, b"\x00")))

    # Tag 0x0002 - GPSLatitude (3 rationals: degrees, minutes, seconds)
    lat_data = encode_rational(int(GPS_LAT[0]), 1)
    lat_data += encode_rational(int(GPS_LAT[1]), 1)
    lat_data += encode_rational(int(GPS_LAT[2] * 100), 100)
    lat_offset = gps_data_offset_base + len(gps_data)
    gps_entries.append(make_ifd_entry(0x0002, 5, 3, struct.pack("<I", lat_offset)))
    gps_data += lat_data

    # Tag 0x0003 - GPSLongitudeRef ("E")
    lon_ref = b"E\x00"
    gps_entries.append(make_ifd_entry(0x0003, 2, 2, lon_ref.ljust(4, b"\x00")))

    # Tag 0x0004 - GPSLongitude (3 rationals)
    lon_data = encode_rational(int(GPS_LON[0]), 1)
    lon_data += encode_rational(int(GPS_LON[1]), 1)
    lon_data += encode_rational(int(GPS_LON[2] * 100), 100)
    lon_offset = gps_data_offset_base + len(gps_data)
    gps_entries.append(make_ifd_entry(0x0004, 5, 3, struct.pack("<I", lon_offset)))
    gps_data += lon_data

    # Build GPS IFD
    gps_ifd = struct.pack("<H", len(gps_entries))
    for entry in gps_entries:
        gps_ifd += entry
    gps_ifd += struct.pack("<I", 0)  # No next IFD

    # === Assemble complete TIFF/EXIF structure ===
    exif_body = tiff_header + ifd0 + data_area + gps_ifd + gps_data

    # EXIF APP1 marker
    # "Exif\x00\x00" header + TIFF data
    app1_data = b"Exif\x00\x00" + exif_body
    app1_length = len(app1_data) + 2  # +2 for the length field itself
    app1 = b"\xFF\xE1" + struct.pack(">H", app1_length) + app1_data

    return app1


def create_minimal_jpeg_image():
    """Create a minimal valid JPEG image (8x8 solid blue)."""
    # This is a minimal valid JPEG: SOI + DQT + SOF0 + DHT + SOS + data + EOI
    # Using a pre-built minimal JPEG for a small blue square

    # Quantization table (all 1s for simplicity)
    dqt = b"\xFF\xDB\x00\x43\x00"
    dqt += bytes([1] * 64)

    # Start of Frame (SOF0): 8x8, 3 components (YCbCr)
    sof = b"\xFF\xC0\x00\x11\x08"
    sof += struct.pack(">HH", 8, 8)  # height, width
    sof += b"\x03"  # 3 components
    sof += b"\x01\x11\x00"  # Y: 1x1 sampling, QT 0
    sof += b"\x02\x11\x00"  # Cb: 1x1 sampling, QT 0
    sof += b"\x03\x11\x00"  # Cr: 1x1 sampling, QT 0

    # Huffman tables (minimal DC and AC tables)
    # DC table
    dht_dc = b"\xFF\xC4\x00\x1F\x00"
    dht_dc += bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
    dht_dc += bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])

    # AC table
    dht_ac = b"\xFF\xC4\x00\xB5\x10"
    ac_counts = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125]
    dht_ac += bytes(ac_counts)
    # Standard Huffman AC values (abbreviated)
    ac_values = list(range(162))
    dht_ac += bytes(ac_values[:sum(ac_counts)])

    # SOS + compressed data (minimal - solid color)
    sos = b"\xFF\xDA\x00\x0C\x03\x01\x00\x02\x11\x03\x11\x00\x3F\x00"
    # Minimal entropy-coded data for a blue-ish block
    scan_data = b"\x7B\x40\x00\x00\x00\x00\x00\x00"

    return dqt + sof + dht_dc + sos + scan_data


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.jpg")

    print("[*] Building EXIF metadata with GPS and flag...")
    exif_app1 = build_exif_data()

    print("[*] Creating JPEG image...")
    # JPEG structure: SOI + APP1(EXIF) + image data + EOI
    jpeg = b"\xFF\xD8"  # SOI
    jpeg += exif_app1    # EXIF metadata
    jpeg += create_minimal_jpeg_image()  # Image data
    jpeg += b"\xFF\xD9"  # EOI

    with open(output_path, "wb") as f:
        f.write(jpeg)

    print(f"[+] Created {output_path}")
    print(f"    GPS: {GPS_LAT[0]}°{GPS_LAT[1]}'{GPS_LAT[2]}\"{GPS_LAT_REF}, "
          f"{GPS_LON[0]}°{GPS_LON[1]}'{GPS_LON[2]}\"{GPS_LON_REF}")
    print(f"    Location: Near the Eiffel Tower, Paris")
    print(f"    Flag hidden in: EXIF UserComment field")
    print()
    print("To solve:")
    print("  exiftool challenge.jpg")
    print("  # Look for UserComment, GPS coordinates")
    print("  # Or: python3 -c \"from PIL import Image; img = Image.open('challenge.jpg'); print(img.getexif())\"")
    print("  # Or: identify -verbose challenge.jpg")


if __name__ == "__main__":
    main()
