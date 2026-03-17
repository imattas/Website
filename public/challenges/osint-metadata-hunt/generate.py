#!/usr/bin/env python3
"""
OSINT Challenge: Metadata Hunt
Creates a PDF file with the flag hidden in custom metadata fields
(Author, Subject, Keywords). Players must extract and examine the
PDF metadata to find the flag.

Usage: python3 generate.py
Output: challenge.pdf
No external dependencies required (builds raw PDF).
"""

import os
import time
import zlib

FLAG = "zemi{m3t4d4t4_l34ks_3v3ryth1ng}"


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.pdf")
    creation_date = time.strftime("D:%Y%m%d%H%M%S")

    # Page content - a document that looks like a normal report
    page_content = (
        "BT\n"
        "/F1 24 Tf\n"
        "50 700 Td\n"
        "(OSINT Investigation Report) Tj\n"
        "/F1 12 Tf\n"
        "0 -40 Td\n"
        "(Classification: UNCLASSIFIED) Tj\n"
        "0 -25 Td\n"
        "(Date: 2025-03-15) Tj\n"
        "0 -25 Td\n"
        "(Subject: Open Source Intelligence Findings) Tj\n"
        "0 -40 Td\n"
        "(This document contains the results of our OSINT analysis.) Tj\n"
        "0 -20 Td\n"
        "(All sources are publicly available.) Tj\n"
        "0 -20 Td\n"
        "(The flag is not in the visible text of this document.) Tj\n"
        "0 -20 Td\n"
        "(Have you checked the document properties?) Tj\n"
        "0 -40 Td\n"
        "(Hint: Metadata is data about data.) Tj\n"
        "0 -20 Td\n"
        "(Every file carries more information than meets the eye.) Tj\n"
        "ET\n"
    )
    compressed_content = zlib.compress(page_content.encode())

    # Build PDF
    objects = {}
    obj_num = 1

    # Catalog
    objects[obj_num] = f"{obj_num} 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj_num += 1

    # Pages
    objects[obj_num] = f"{obj_num} 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    obj_num += 1

    # Page
    objects[obj_num] = (
        f"{obj_num} 0 obj\n"
        f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n"
        f"   /Contents 5 0 R /Resources << /Font << /F1 4 0 R >> >> >>\n"
        f"endobj\n"
    )
    obj_num += 1

    # Font
    objects[obj_num] = f"{obj_num} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    obj_num += 1

    # Content stream
    stream_obj = (
        f"{obj_num} 0 obj\n"
        f"<< /Length {len(compressed_content)} /Filter /FlateDecode >>\n"
        f"stream\n"
    )
    objects[obj_num] = stream_obj
    obj_num += 1

    # Info dictionary - THE FLAG IS HIDDEN HERE in multiple fields
    info_num = obj_num
    objects[info_num] = (
        f"{info_num} 0 obj\n"
        f"<< /Title (OSINT Investigation Report - Q1 2025)\n"
        f"   /Author ({FLAG})\n"
        f"   /Subject (Flag: {FLAG})\n"
        f"   /Keywords (osint, metadata, {FLAG})\n"
        f"   /Creator (ReportGenerator v3.2)\n"
        f"   /Producer (Python PDF Builder)\n"
        f"   /CreationDate ({creation_date})\n"
        f"   /ModDate ({creation_date})\n"
        f">>\n"
        f"endobj\n"
    )
    obj_num += 1

    # Write PDF
    with open(output_path, "wb") as f:
        f.write(b"%PDF-1.4\n")
        f.write(b"%\xe2\xe3\xcf\xd3\n")

        offsets = {}
        for num in sorted(objects.keys()):
            offsets[num] = f.tell()
            if num == 5:
                # Stream object needs special handling
                f.write(objects[num].encode("latin-1"))
                f.write(compressed_content)
                f.write(b"\nendstream\nendobj\n")
            else:
                f.write(objects[num].encode("latin-1"))

        # Xref
        xref_offset = f.tell()
        f.write(b"xref\n")
        f.write(f"0 {len(objects) + 1}\n".encode())
        f.write(b"0000000000 65535 f \n")
        for num in sorted(objects.keys()):
            f.write(f"{offsets[num]:010d} 00000 n \n".encode())

        # Trailer
        f.write(b"trailer\n")
        f.write(f"<< /Size {len(objects) + 1} /Root 1 0 R /Info {info_num} 0 R >>\n".encode())
        f.write(b"startxref\n")
        f.write(f"{xref_offset}\n".encode())
        f.write(b"%%EOF\n")

    print(f"[+] Created {output_path}")
    print(f"    Flag hidden in: Author, Subject, and Keywords metadata fields")
    print()
    print("To solve:")
    print("  exiftool challenge.pdf")
    print("  pdfinfo challenge.pdf")
    print("  # Or: python3 -c \"")
    print("  #   from PyPDF2 import PdfReader")
    print("  #   r = PdfReader('challenge.pdf')")
    print("  #   print(r.metadata)")
    print("  # \"")
    print("  # Check Author, Subject, Keywords fields")


if __name__ == "__main__":
    main()
