#!/usr/bin/env python3
"""
Forensics Challenge: PDF Analysis
Creates a PDF file with the flag hidden in two places:
  1. A custom metadata field (Info dictionary)
  2. Inside a FlateDecode stream object

The visible text is a decoy. Players must inspect the raw PDF structure
or use tools like pdf-parser, qpdf, or pdftotext with the right options.

Usage: python3 generate.py
Output: challenge.pdf
No external dependencies required (builds raw PDF from scratch).
"""

import zlib
import os
import time

FLAG = "zemi{pdf_str34ms_h1dd3n}"


def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.pdf")

    # The hidden stream content (compressed with FlateDecode)
    hidden_text = f"CONFIDENTIAL FLAG: {FLAG}\n"
    compressed_hidden = zlib.compress(hidden_text.encode())

    # Visible page content stream
    visible_content = (
        "BT\n"
        "/F1 16 Tf\n"
        "50 700 Td\n"
        "(Welcome to the Forensics Challenge!) Tj\n"
        "0 -30 Td\n"
        "(The flag is not on this page.) Tj\n"
        "0 -30 Td\n"
        "(Look deeper into the PDF structure.) Tj\n"
        "0 -30 Td\n"
        "(Hint: streams can hide things.) Tj\n"
        "ET\n"
    )
    compressed_visible = zlib.compress(visible_content.encode())

    creation_date = time.strftime("D:%Y%m%d%H%M%S")

    # Build PDF objects manually
    objects = {}
    offsets = {}
    obj_num = 1

    # Object 1: Catalog
    cat_num = obj_num
    objects[cat_num] = (
        f"{cat_num} 0 obj\n"
        "<< /Type /Catalog /Pages 2 0 R >>\n"
        "endobj\n"
    )
    obj_num += 1

    # Object 2: Pages
    pages_num = obj_num
    objects[pages_num] = (
        f"{pages_num} 0 obj\n"
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        "endobj\n"
    )
    obj_num += 1

    # Object 3: Page
    page_num = obj_num
    objects[page_num] = (
        f"{page_num} 0 obj\n"
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n"
        "   /Contents 5 0 R /Resources << /Font << /F1 4 0 R >> >> >>\n"
        "endobj\n"
    )
    obj_num += 1

    # Object 4: Font
    font_num = obj_num
    objects[font_num] = (
        f"{font_num} 0 obj\n"
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
        "endobj\n"
    )
    obj_num += 1

    # Object 5: Visible content stream
    vis_num = obj_num
    objects[vis_num] = (
        f"{vis_num} 0 obj\n"
        f"<< /Length {len(compressed_visible)} /Filter /FlateDecode >>\n"
        "stream\n"
    )
    objects[vis_num] += compressed_visible.decode("latin-1")
    objects[vis_num] += "\nendstream\nendobj\n"
    obj_num += 1

    # Object 6: Hidden stream (not referenced by any page -- orphaned object)
    hidden_num = obj_num
    objects[hidden_num] = (
        f"{hidden_num} 0 obj\n"
        f"<< /Length {len(compressed_hidden)} /Filter /FlateDecode\n"
        f"   /Type /EmbeddedFile /Subtype /text#2Fplain >>\n"
        "stream\n"
    )
    objects[hidden_num] += compressed_hidden.decode("latin-1")
    objects[hidden_num] += "\nendstream\nendobj\n"
    obj_num += 1

    # Object 7: Info dictionary with flag in custom metadata
    info_num = obj_num
    objects[info_num] = (
        f"{info_num} 0 obj\n"
        f"<< /Title (Forensics Challenge)\n"
        f"   /Author (CTF Admin)\n"
        f"   /Subject (PDF Analysis)\n"
        f"   /Creator (challenge generator)\n"
        f"   /CreationDate ({creation_date})\n"
        f"   /SecretFlag ({FLAG})\n"
        f">>\n"
        "endobj\n"
    )
    obj_num += 1

    # Write PDF
    with open(output_path, "wb") as f:
        f.write(b"%PDF-1.4\n")
        # Binary comment to mark as binary PDF
        f.write(b"%\xe2\xe3\xcf\xd3\n")

        for num in sorted(objects.keys()):
            offsets[num] = f.tell()
            f.write(objects[num].encode("latin-1"))

        # Cross-reference table
        xref_offset = f.tell()
        f.write(b"xref\n")
        f.write(f"0 {len(objects) + 1}\n".encode())
        f.write(b"0000000000 65535 f \n")
        for num in sorted(objects.keys()):
            f.write(f"{offsets[num]:010d} 00000 n \n".encode())

        # Trailer
        f.write(b"trailer\n")
        f.write(f"<< /Size {len(objects) + 1} /Root {cat_num} 0 R /Info {info_num} 0 R >>\n".encode())
        f.write(b"startxref\n")
        f.write(f"{xref_offset}\n".encode())
        f.write(b"%%EOF\n")

    print(f"[+] Created {output_path}")
    print()
    print("To solve:")
    print("  pdfinfo challenge.pdf            # check metadata fields")
    print("  pdf-parser.py challenge.pdf       # look at all objects")
    print("  qpdf --show-objects challenge.pdf # decompress streams")
    print("  python3 -c \"")
    print("    import zlib")
    print("    # Extract and decompress the hidden FlateDecode stream")
    print("  \"")


if __name__ == "__main__":
    main()
