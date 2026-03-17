---
title: "Misc - Scripting Challenge"
description: "Automating the solution of 100 timed math and logic puzzles with a Python solver script to beat a challenge server's time limit."
author: "Zemi"
---

## Challenge Info

| Detail     | Value        |
|------------|--------------|
| Category   | Misc         |
| Difficulty | Medium       |
| Points     | 250          |
| Flag       | `zemi{4ut0m4t10n_1s_k3y}` |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/misc-scripting-challenge/flag.txt)
- [server.py](/Website/challenges/misc-scripting-challenge/server.py)

## Reconnaissance

The challenge provides a Python script that runs a local challenge server. When we connect:

```bash
python3 challenge_server.py &
nc localhost 9999
```

```
===================================
  SPEED MATH CHALLENGE v2.0
  Solve 100 questions in 60 seconds
  Good luck, human!
===================================

Question 1/100: What is 347 + 892?
>
```

We have 60 seconds to solve 100 questions. Each question is one of several types:

```
Question 1/100: What is 347 + 892?
Question 2/100: What is 9841 - 3729?
Question 3/100: What is 47 * 83?
Question 4/100: What is 9876 / 4? (integer division)
Question 5/100: What is 2 ** 10?
Question 6/100: Convert "48656c6c6f" from hex to ASCII
Question 7/100: What is the MD5 hash of "challenge42"? (first 8 chars)
Question 8/100: Decode base64: "emVtaQ=="
Question 9/100: What is len("supercalifragilistic")?
Question 10/100: Reverse the string "flag{test}"
```

No human can solve 100 of these in 60 seconds. We need to automate it.

## Analysis

### Understanding the challenge server

Here is the local challenge server code we were given:

```python
#!/usr/bin/env python3
"""challenge_server.py - Local speed math challenge"""
import socket, random, hashlib, base64, time, threading

def generate_question():
    qtype = random.choice(["add","sub","mul","div","pow","hex","md5","b64","strlen","reverse"])
    if qtype == "add":
        a, b = random.randint(100,9999), random.randint(100,9999)
        return f"What is {a} + {b}?", str(a + b)
    elif qtype == "sub":
        a, b = random.randint(100,9999), random.randint(100,9999)
        return f"What is {a} - {b}?", str(a - b)
    elif qtype == "mul":
        a, b = random.randint(10,99), random.randint(10,99)
        return f"What is {a} * {b}?", str(a * b)
    elif qtype == "div":
        b = random.randint(2,20)
        a = b * random.randint(100,999)
        return f"What is {a} / {b}? (integer division)", str(a // b)
    elif qtype == "pow":
        a, b = random.randint(2,10), random.randint(2,15)
        return f"What is {a} ** {b}?", str(a ** b)
    elif qtype == "hex":
        word = random.choice(["Hello","World","Flag","Admin","Secret","Python"])
        hexval = word.encode().hex()
        return f'Convert "{hexval}" from hex to ASCII', word
    elif qtype == "md5":
        word = f"challenge{random.randint(1,100)}"
        h = hashlib.md5(word.encode()).hexdigest()[:8]
        return f'What is the MD5 hash of "{word}"? (first 8 chars)', h
    elif qtype == "b64":
        word = random.choice(["zemi","flag","ctf","hack","code","byte"])
        b = base64.b64encode(word.encode()).decode()
        return f'Decode base64: "{b}"', word
    elif qtype == "strlen":
        word = random.choice(["supercalifragilistic","antidisestablishment",
                              "pneumonoultramicroscopic","floccinaucinihilipilification"])
        return f'What is len("{word}")?', str(len(word))
    elif qtype == "reverse":
        word = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789",k=random.randint(8,20)))
        return f'Reverse the string "{word}"', word[::-1]

def handle_client(conn):
    flag = "zemi{4ut0m4t10n_1s_k3y}"
    conn.sendall(b"===================================\n")
    conn.sendall(b"  SPEED MATH CHALLENGE v2.0\n")
    conn.sendall(b"  Solve 100 questions in 60 seconds\n")
    conn.sendall(b"  Good luck, human!\n")
    conn.sendall(b"===================================\n\n")
    start = time.time()
    for i in range(1, 101):
        if time.time() - start > 60:
            conn.sendall(b"\nTime's up! Too slow.\n")
            conn.close()
            return
        q, a = generate_question()
        conn.sendall(f"Question {i}/100: {q}\n> ".encode())
        answer = conn.recv(1024).decode().strip()
        if answer != a:
            conn.sendall(f"Wrong! Expected: {a}\n".encode())
            conn.close()
            return
    conn.sendall(f"\nCongratulations! Here is your flag: {flag}\n".encode())
    conn.close()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999))
s.listen(5)
print("[*] Challenge server running on port 9999")
while True:
    conn, addr = s.accept()
    threading.Thread(target=handle_client, args=(conn,)).start()
```

### Question types to handle

| Type | Example | Parsing Strategy |
|------|---------|------------------|
| Arithmetic | "What is 347 + 892?" | Extract numbers and operator |
| Power | "What is 2 ** 10?" | Extract base and exponent |
| Hex decode | `Convert "48656c6c6f" from hex to ASCII` | `bytes.fromhex()` |
| MD5 hash | `What is the MD5 hash of "challenge42"?` | `hashlib.md5()` |
| Base64 decode | `Decode base64: "emVtaQ=="` | `base64.b64decode()` |
| String length | `What is len("word")?` | `len()` |
| Reverse | `Reverse the string "word"` | Slice `[::-1]` |

## Step-by-Step Walkthrough

### Step 1: Write the solver script

```python
#!/usr/bin/env python3
"""solver.py - Automated speed math challenge solver"""
import socket
import re
import hashlib
import base64

def solve_question(question):
    """Parse a question and return the answer as a string."""

    # Arithmetic: What is A OP B?
    m = re.search(r'What is (\-?\d+) ([+\-*/]) (\-?\d+)\?', question)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == '+': return str(a + b)
        if op == '-': return str(a - b)
        if op == '*': return str(a * b)
        if op == '/': return str(a // b)

    # Integer division (explicit)
    m = re.search(r'What is (\d+) / (\d+)\? \(integer division\)', question)
    if m:
        return str(int(m.group(1)) // int(m.group(2)))

    # Power: What is A ** B?
    m = re.search(r'What is (\d+) \*\* (\d+)\?', question)
    if m:
        return str(int(m.group(1)) ** int(m.group(2)))

    # Hex to ASCII: Convert "hex" from hex to ASCII
    m = re.search(r'Convert "([0-9a-fA-F]+)" from hex to ASCII', question)
    if m:
        return bytes.fromhex(m.group(1)).decode()

    # MD5 hash: What is the MD5 hash of "word"? (first 8 chars)
    m = re.search(r'What is the MD5 hash of "(.+?)"\? \(first 8 chars\)', question)
    if m:
        return hashlib.md5(m.group(1).encode()).hexdigest()[:8]

    # Base64 decode: Decode base64: "encoded"
    m = re.search(r'Decode base64: "(.+?)"', question)
    if m:
        return base64.b64decode(m.group(1)).decode()

    # String length: What is len("word")?
    m = re.search(r'What is len\("(.+?)"\)\?', question)
    if m:
        return str(len(m.group(1)))

    # Reverse string: Reverse the string "word"
    m = re.search(r'Reverse the string "(.+?)"', question)
    if m:
        return m.group(1)[::-1]

    return None

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 9999))

    # Receive the banner
    banner = sock.recv(4096).decode()
    print(banner)

    for i in range(100):
        # Receive the question
        data = sock.recv(4096).decode()
        print(data, end="")

        # Extract the question line
        lines = data.strip().split('\n')
        question_line = ""
        for line in lines:
            if line.startswith("Question") or line.startswith(">"):
                continue
            if "Congratulations" in line:
                print(line)
                return

        # Parse the question from received data
        # Question format: "Question N/100: <question>\n> "
        m = re.search(r'Question \d+/\d+: (.+)', data)
        if not m:
            print(f"[!] Could not parse question from: {data}")
            break

        question = m.group(1)
        answer = solve_question(question)

        if answer is None:
            print(f"\n[!] Unknown question type: {question}")
            break

        print(f"{answer}")
        sock.sendall((answer + "\n").encode())

    # Receive the flag
    response = sock.recv(4096).decode()
    print(response)

    sock.close()

if __name__ == "__main__":
    main()
```

### Step 2: Start the challenge server

```bash
python3 challenge_server.py &
```

```
[*] Challenge server running on port 9999
```

### Step 3: Run the solver

```bash
python3 solver.py
```

```
===================================
  SPEED MATH CHALLENGE v2.0
  Solve 100 questions in 60 seconds
  Good luck, human!
===================================

Question 1/100: What is 4721 + 832?
5553
Question 2/100: What is 67 * 43?
2881
Question 3/100: Convert "507974686f6e" from hex to ASCII
Python
Question 4/100: What is the MD5 hash of "challenge17"? (first 8 chars)
a3c1f9d2
...
Question 99/100: What is 5 ** 12?
244140625
Question 100/100: Reverse the string "k8m3xq7v2p"
p2v7qx3m8k

Congratulations! Here is your flag: zemi{4ut0m4t10n_1s_k3y}
```

All 100 questions solved in under 2 seconds.

### Step 4: Using pwntools (alternative approach)

The `pwntools` library makes socket interaction cleaner:

```python
#!/usr/bin/env python3
"""solver_pwntools.py - Solver using pwntools"""
from pwn import *
import re, hashlib, base64

def solve(q):
    # Arithmetic
    m = re.search(r'What is (\-?\d+) ([+\-*]) (\-?\d+)\?', q)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        ops = {'+': a+b, '-': a-b, '*': a*b}
        return str(ops[op])
    # Integer division
    m = re.search(r'What is (\d+) / (\d+)', q)
    if m: return str(int(m.group(1)) // int(m.group(2)))
    # Power
    m = re.search(r'What is (\d+) \*\* (\d+)', q)
    if m: return str(int(m.group(1)) ** int(m.group(2)))
    # Hex
    m = re.search(r'Convert "([0-9a-f]+)" from hex', q)
    if m: return bytes.fromhex(m.group(1)).decode()
    # MD5
    m = re.search(r'MD5 hash of "(.+?)"', q)
    if m: return hashlib.md5(m.group(1).encode()).hexdigest()[:8]
    # Base64
    m = re.search(r'Decode base64: "(.+?)"', q)
    if m: return base64.b64decode(m.group(1)).decode()
    # Strlen
    m = re.search(r'len\("(.+?)"\)', q)
    if m: return str(len(m.group(1)))
    # Reverse
    m = re.search(r'Reverse the string "(.+?)"', q)
    if m: return m.group(1)[::-1]

r = remote("localhost", 9999)
r.recvuntil(b"===")
r.recvuntil(b"===")

for i in range(100):
    r.recvuntil(b"Question ")
    line = r.recvuntil(b"> ").decode()
    question = re.search(r'\d+/\d+: (.+)', line).group(1).strip()
    answer = solve(question)
    log.info(f"Q{i+1}: {question} -> {answer}")
    r.sendline(answer.encode())

flag = r.recvall().decode()
log.success(flag)
```

## Design Principles for Solver Scripts

### 1. Use regex, not string splitting

Questions can have varying formats. Regex handles edge cases:

```python
# Bad: breaks on negative numbers or extra spaces
parts = question.split()
a, op, b = int(parts[2]), parts[3], int(parts[4])

# Good: handles all arithmetic formats
m = re.search(r'What is (\-?\d+) ([+\-*/]) (\-?\d+)', question)
```

### 2. Avoid `eval()` or use it carefully

```python
# Dangerous: arbitrary code execution
answer = str(eval(question.split("What is ")[1].rstrip("?")))

# Safer: whitelist operations
import ast
expr = question.split("What is ")[1].rstrip("?").strip()
answer = str(ast.literal_eval(compile(expr, "<>", "eval")))
```

### 3. Handle timeouts

```python
import socket
sock.settimeout(5)  # 5 second timeout per receive
try:
    data = sock.recv(4096)
except socket.timeout:
    print("[!] Server timed out - solver too slow")
```

## Tools Used

- Python 3 — solver script
- `socket` module — TCP communication
- `re` module — regex parsing of question text
- `hashlib` / `base64` — answering encoding questions
- `pwntools` — alternative socket interaction library
- Netcat — initial manual testing

## Lessons Learned

- Scripting challenges test automation skills, not math — the key is parsing questions reliably
- Always manually test a few questions first to understand all question types before writing the solver
- Use regex for robust parsing; string splitting breaks on edge cases
- `pwntools` makes socket interaction much cleaner with `recvuntil()`, `sendline()`, and logging
- Add error handling for unknown question types — print the raw question so you can add a new handler
- Test your solver multiple times — randomized questions may include types you did not see on the first run
- Time the solver to ensure it finishes well within the limit; network latency can add up over 100 rounds
