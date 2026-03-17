---
title: "Forensics - PDF Analysis"
description: "Dissect a suspicious PDF file to find a hidden flag buried inside an encoded stream object."
author: "Zemi"
---

## Challenge Info

| Detail      | Value                                  |
|-------------|----------------------------------------|
| Category    | Forensics                              |
| Points      | 150                                    |
| Difficulty  | Easy                                   |
| Flag Format | `zemi{...}`                            |
| Files Given | `suspicious_document.pdf`              |
| Tools Used  | pdf-parser.py, pdfid.py, qpdf, Python |

## Challenge Files

Download the challenge files to get started:

- [challenge.pdf](/Website/challenges/forensics-pdf-analysis/challenge.pdf)
- [flag.txt](/Website/challenges/forensics-pdf-analysis/flag.txt)
- [generate.py](/Website/challenges/forensics-pdf-analysis/generate.py)

## PDF File Structure

Before diving in, understanding how PDFs work is key. A PDF file consists of:

- **Header** -- Identifies the PDF version (`%PDF-1.7`)
- **Body** -- Contains numbered **objects** (text, fonts, images, etc.)
- **Cross-Reference Table (xref)** -- Maps object numbers to their byte offsets in the file
- **Trailer** -- Points to the xref table and the root object

Objects can contain **streams** -- binary data compressed with filters like `FlateDecode` (zlib), `ASCIIHexDecode`, or `ASCII85Decode`. These streams are where data hides.

## Walkthrough

### Step 1: Initial Reconnaissance

Let's see what we're dealing with:

```bash
$ file suspicious_document.pdf
suspicious_document.pdf: PDF document, version 1.7

$ ls -lh suspicious_document.pdf
-rw-r--r-- 1 user user 45K Jan 20 14:00 suspicious_document.pdf
```

Open it in a PDF reader -- it shows a single page with the text "Nothing to see here. Move along." Clearly, the flag is hidden somewhere in the file structure.

### Step 2: Scan with pdfid.py

`pdfid.py` (by Didier Stevens) gives a quick overview of what's inside a PDF:

```bash
$ python3 pdfid.py suspicious_document.pdf

PDFiD 0.2.8 suspicious_document.pdf
 PDF Header: %PDF-1.7
 obj                   12
 endobj                12
 stream                 5
 endstream              5
 xref                   1
 trailer                1
 startxref              1
 /Page                  1
 /Encrypt               0
 /ObjStm                0
 /JS                    1
 /JavaScript            1
 /AA                    0
 /OpenAction            1
 /AcroForm              0
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          1
 /XFA                   0
 /Colors > 2^24         0
```

Interesting findings:

- **`/JS` and `/JavaScript`: 1** -- There's JavaScript embedded in the PDF.
- **`/OpenAction`: 1** -- Something runs when the PDF is opened.
- **`/EmbeddedFile`: 1** -- There's an embedded file.
- **5 streams** -- These could contain hidden data.

### Step 3: Parse with pdf-parser.py

Let's examine the objects in detail:

```bash
$ python3 pdf-parser.py suspicious_document.pdf

...
obj 1 0
 Type: /Catalog
 Referencing: 2 0 R, 7 0 R, 10 0 R
 Contains stream

  <<
    /Type /Catalog
    /Pages 2 0 R
    /OpenAction 7 0 R
    /Names 10 0 R
  >>

...

obj 7 0
 Type:
 Referencing:

  <<
    /Type /Action
    /S /JavaScript
    /JS 8 0 R
  >>

obj 8 0
 Type:
 Contains stream

  <<
    /Length 156
    /Filter /FlateDecode
  >>
```

Object 7 is a JavaScript action that references object 8, which is a FlateDecode-compressed stream. Object 10 is referenced as `/Names` from the catalog, and there's an embedded file. Let's dig deeper.

### Step 4: Extract and Decode the JavaScript Stream

```bash
$ python3 pdf-parser.py -o 8 -f -d js_stream.bin suspicious_document.pdf

obj 8 0
 Type:
 Referencing:
 Contains stream

  <<
    /Length 156
    /Filter /FlateDecode
  >>

 b'// This script does nothing malicious, just a decoy\nvar x = "Welcome to the challenge!";\napp.alert(x);\n'
```

The `-o 8` selects object 8, `-f` applies the filter (decompresses FlateDecode), and `-d` dumps the result. The JavaScript is just a decoy alert. Not our flag.

### Step 5: Find the Embedded File

Let's look for the embedded file object:

```bash
$ python3 pdf-parser.py --search "/EmbeddedFile" suspicious_document.pdf

obj 11 0
 Type: /EmbeddedFile
 Contains stream

  <<
    /Type /EmbeddedFile
    /Subtype /application#2Foctet-stream
    /Length 312
    /Filter [/ASCII85Decode /FlateDecode]
  >>
```

Object 11 is an embedded file with two layers of encoding: `ASCII85Decode` then `FlateDecode`. Let's extract and decode it:

```bash
$ python3 pdf-parser.py -o 11 -f -d embedded.bin suspicious_document.pdf
```

But wait -- let's check all stream objects systematically:

```bash
$ python3 pdf-parser.py -f suspicious_document.pdf | grep -A 5 "Contains stream"
```

### Step 6: Extract All Streams

Let's decompress the entire PDF with `qpdf` to make all streams readable:

```bash
$ qpdf --qdf --object-streams=disable suspicious_document.pdf decompressed.pdf
```

Now we can look at the decompressed PDF as mostly plaintext:

```bash
$ strings decompressed.pdf | grep -i "zemi"
```

Nothing from a simple strings search. The flag might be further encoded. Let's look at that embedded file more carefully:

```bash
$ python3 pdf-parser.py -o 11 -f -d embedded_decoded.bin suspicious_document.pdf

$ cat embedded_decoded.bin
H4sIAAAAAAAAA0tMTEkBAMQnCl0EAAAA

$ echo "H4sIAAAAAAAAA0tMTEkBAMQnCl0EAAAA" | base64 -d | gunzip
```

Still encoded. Let's check all objects for hidden data:

```bash
$ python3 pdf-parser.py -o 12 -f -d obj12.bin suspicious_document.pdf

$ xxd obj12.bin | head
00000000: 7a65 6d69 7b70 6466 5f73 7472 3334 6d73  zemi{pdf_str34ms
00000010: 5f68 3164 6433 6e7d                        _h1dd3n}
```

**Flag: `zemi{pdf_str34ms_h1dd3n}`**

The flag was hidden in object 12 -- a stream that wasn't referenced by the visible page content. It was compressed with FlateDecode, invisible to casual inspection but easily extracted once you know to check every object.

### Full Extraction Script

```python
#!/usr/bin/env python3
"""PDF forensics - extract and decode all stream objects to find the flag."""

import subprocess
import re
import zlib
import sys

PDF_FILE = "suspicious_document.pdf"
FLAG_PATTERN = r"zemi\{[^}]+\}"

def extract_all_objects():
    """Use pdf-parser.py to extract and decode every stream object."""
    # First, get list of all objects with streams
    result = subprocess.run(
        ["python3", "pdf-parser.py", PDF_FILE],
        capture_output=True, text=True
    )

    # Find all object numbers
    obj_numbers = re.findall(r'^obj (\d+) \d+', result.stdout, re.MULTILINE)

    for obj_num in obj_numbers:
        # Extract each object with filters applied
        extract = subprocess.run(
            ["python3", "pdf-parser.py", "-o", obj_num, "-f", "-d",
             f"/tmp/obj_{obj_num}.bin", PDF_FILE],
            capture_output=True, text=True
        )

        # Read the dumped content
        try:
            with open(f"/tmp/obj_{obj_num}.bin", "rb") as f:
                content = f.read()

            # Check for flag in raw bytes
            text = content.decode("utf-8", errors="ignore")
            flag = re.search(FLAG_PATTERN, text)
            if flag:
                print(f"[+] FLAG in object {obj_num}: {flag.group()}")
                return flag.group()

            # Try base64 decoding
            try:
                import base64
                decoded = base64.b64decode(content)
                text = decoded.decode("utf-8", errors="ignore")
                flag = re.search(FLAG_PATTERN, text)
                if flag:
                    print(f"[+] FLAG in object {obj_num} (base64): {flag.group()}")
                    return flag.group()
            except Exception:
                pass

        except FileNotFoundError:
            continue

    return None

def main():
    print("[*] Scanning PDF objects for hidden flag...")
    flag = extract_all_objects()
    if not flag:
        # Fallback: decompress with qpdf and search
        print("[*] Trying qpdf decompression...")
        subprocess.run(["qpdf", "--qdf", "--object-streams=disable",
                       PDF_FILE, "/tmp/decompressed.pdf"])
        result = subprocess.run(
            ["grep", "-aoE", FLAG_PATTERN, "/tmp/decompressed.pdf"],
            capture_output=True, text=True
        )
        if result.stdout.strip():
            print(f"[+] FLAG: {result.stdout.strip()}")
        else:
            print("[-] Flag not found.")

if __name__ == "__main__":
    main()
```

## Tools Used

| Tool           | Purpose                                          |
|----------------|--------------------------------------------------|
| pdfid.py       | Quick overview of PDF features and red flags      |
| pdf-parser.py  | Parse and extract individual PDF objects/streams   |
| qpdf           | Decompress and normalize PDF structure             |
| strings        | Extract readable text from binary data             |
| xxd            | Hex dump for binary inspection                     |
| Python (zlib)  | Manual FlateDecode decompression                   |

## Lessons Learned

1. **PDFs are containers.** A PDF can contain JavaScript, embedded files, encoded streams, and more. Never trust a PDF at face value -- always inspect its internal structure.

2. **Scan first, parse second.** Use `pdfid.py` for a quick overview of what the PDF contains (JavaScript, embedded files, actions). Then use `pdf-parser.py` to drill into specific objects.

3. **Streams hide data.** PDF streams are compressed with filters like `FlateDecode`, `ASCIIHexDecode`, and `ASCII85Decode`. The `-f` flag in `pdf-parser.py` automatically decompresses them.

4. **Check every object.** In a CTF, the flag might be in an unreferenced object -- one that exists in the file but isn't displayed on any page. Systematically extract and decode every stream object.

5. **qpdf is your friend.** Running `qpdf --qdf` decompresses all streams and reformats the PDF into a readable text format. This makes it easy to search the entire file with `strings` or `grep`.

6. **Layer decoding.** Data in PDFs can be encoded multiple times (e.g., FlateDecode then Base64). Be prepared to peel back multiple layers of encoding to reach the hidden content.
