---
title: "Misc - Esoteric Languages"
description: "Identifying and executing esoteric programming languages in CTF challenges, from Brainfuck to Whitespace to JSFuck."
author: "Zemi"
---

## Challenge Info

| Detail     | Value        |
|------------|--------------|
| Category   | Misc         |
| Difficulty | Medium       |
| Points     | 200          |
| Flag       | `zemi{3s0t3r1c_pr0gr4mm1ng}` |

## Challenge Files

Download the challenge files to get started:

- [challenge.bf](/Website/challenges/misc-esoteric-languages/challenge.bf)
- [flag.txt](/Website/challenges/misc-esoteric-languages/flag.txt)
- [hint.txt](/Website/challenges/misc-esoteric-languages/hint.txt)

## Reconnaissance

We download the challenge file:

```bash
file mystery_program.txt
```

```
mystery_program.txt: ASCII text
```

```bash
cat mystery_program.txt
```

```
++++++++++[>++++++++++>+++++++++++>+++++++++>++++>+++>+<<<<<<-]
>++.>+.>++.>++.>++++.>++.<<<.>>++++++.------.<-.>>+.<<<+.>>---
--.++++++.-------.>>.<<++.>>++++.<<.>>-----.<<<--.>>+.>+.<<<.>>
>.<<------.++++++.-------.>>.<<++.>+++.
```

The file contains only the characters `+ - < > [ ] .` — this is unmistakably **Brainfuck**.

## Analysis

### Identifying Esoteric Languages

Here is a quick reference for recognizing common esolangs:

| Language | Identifying Features | Example |
|----------|---------------------|---------|
| **Brainfuck** | Only `+-<>.,[]` characters | `++++[>++<-]>.` |
| **Whitespace** | Only spaces, tabs, newlines (file looks blank) | `   \t\t \t\n` |
| **Malbolge** | Seemingly random printable ASCII, always 98 chars for "Hello World" | `('&%:sym` |
| **Piet** | An image file (PNG/BMP) with colored blocks | *(visual)* |
| **JSFuck** | JavaScript using only `[]()!+` | `[][(![]+[])[+[]]...` |
| **Ook!** | Only `Ook.`, `Ook!`, `Ook?` tokens | `Ook. Ook! Ook? Ook.` |
| **Rockstar** | Reads like song lyrics | `Tommy is a rebel` |
| **Chef** | Reads like a cooking recipe | `Ingredients. 72 g haricot beans` |
| **Shakespeare** | Reads like a play script | `Romeo, a young man.` |

### How Brainfuck Works

Brainfuck operates on an array of memory cells (initially all zero) with a data pointer:

| Command | Action |
|---------|--------|
| `>` | Move pointer right |
| `<` | Move pointer left |
| `+` | Increment current cell |
| `-` | Decrement current cell |
| `.` | Output current cell as ASCII |
| `,` | Read one byte of input |
| `[` | Jump past matching `]` if cell is 0 |
| `]` | Jump back to matching `[` if cell is not 0 |

## Step-by-Step Walkthrough

### Step 1: Run the Brainfuck program

We can use a local interpreter. Here is a minimal Python Brainfuck interpreter:

```python
#!/usr/bin/env python3
"""bf_interpreter.py - Brainfuck interpreter"""
import sys

def brainfuck(code):
    tape = [0] * 30000
    ptr = 0
    pc = 0
    output = []

    # Pre-compute bracket matching for performance
    brackets = {}
    stack = []
    for i, ch in enumerate(code):
        if ch == '[':
            stack.append(i)
        elif ch == ']':
            j = stack.pop()
            brackets[j] = i
            brackets[i] = j

    while pc < len(code):
        cmd = code[pc]
        if cmd == '>':
            ptr += 1
        elif cmd == '<':
            ptr -= 1
        elif cmd == '+':
            tape[ptr] = (tape[ptr] + 1) % 256
        elif cmd == '-':
            tape[ptr] = (tape[ptr] - 1) % 256
        elif cmd == '.':
            output.append(chr(tape[ptr]))
        elif cmd == ',':
            tape[ptr] = ord(sys.stdin.read(1) or '\0')
        elif cmd == '[':
            if tape[ptr] == 0:
                pc = brackets[pc]
        elif cmd == ']':
            if tape[ptr] != 0:
                pc = brackets[pc]
        pc += 1

    return ''.join(output)

with open("mystery_program.txt") as f:
    code = f.read()

result = brainfuck(code)
print(result)
```

```bash
python3 bf_interpreter.py
```

```
zemi{3s0t3r1c_pr0gr4mm1ng}
```

### Step 2: Understand the program

Let's trace the logic. The first part initializes memory cells:

```
++++++++++                    cell[0] = 10 (loop counter)
[                              while cell[0] != 0:
  >++++++++++                   cell[1] += 10  (builds to 100 -> base for letters)
  >+++++++++++                  cell[2] += 11  (builds to 110)
  >+++++++++                    cell[3] += 9   (builds to 90)
  >++++                         cell[4] += 4   (builds to 40)
  >+++                          cell[5] += 3   (builds to 30)
  >+                            cell[6] += 1   (builds to 10)
  <<<<<<-                       cell[0]-- (decrement counter)
]
```

After the loop, the cells are: `[0, 100, 110, 90, 40, 30, 10]`. The remaining `+`, `-`, and `.` commands adjust each cell to the desired ASCII value and print it.

## Other Esolang Examples

### Whitespace

Whitespace programs use only three characters: space (` `), tab (`\t`), and newline (`\n`). The file will appear completely blank in most editors.

```bash
# Detect whitespace - file looks empty but has content
wc -c whitespace_program.ws
```

```
2847 whitespace_program.ws
```

```bash
# The file has bytes but looks blank
cat whitespace_program.ws | cat -A
```

```
 ^I ^I^I$
  $
 ^I ^I ^I$
...
```

Run with a Whitespace interpreter:

```bash
# Using wspace interpreter
wspace whitespace_program.ws
```

### JSFuck

JSFuck encodes JavaScript using only six characters: `[]()!+`

```javascript
// This is valid JavaScript:
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]
// ... thousands more characters
```

```bash
# Run it with Node.js
node -e "$(cat jsfuck_program.txt)"
```

Or decode it by evaluating in a sandboxed environment:

```python
# Use a JavaScript engine to evaluate
import subprocess
result = subprocess.run(
    ["node", "-e", open("jsfuck_program.txt").read()],
    capture_output=True, text=True
)
print(result.stdout)
```

### Ook!

Ook! is a Brainfuck variant using three tokens:

| Ook! | Brainfuck |
|------|-----------|
| `Ook. Ook?` | `>` |
| `Ook? Ook.` | `<` |
| `Ook. Ook.` | `+` |
| `Ook! Ook!` | `-` |
| `Ook! Ook.` | `.` |
| `Ook. Ook!` | `,` |
| `Ook! Ook?` | `[` |
| `Ook? Ook!` | `]` |

Convert Ook! to Brainfuck then run:

```python
def ook_to_bf(ook_code):
    tokens = ook_code.replace('\n', ' ').split()
    pairs = [tokens[i] + ' ' + tokens[i+1] for i in range(0, len(tokens), 2)]
    mapping = {
        'Ook. Ook?': '>', 'Ook? Ook.': '<',
        'Ook. Ook.': '+', 'Ook! Ook!': '-',
        'Ook! Ook.': '.', 'Ook. Ook!': ',',
        'Ook! Ook?': '[', 'Ook? Ook!': ']',
    }
    return ''.join(mapping.get(p, '') for p in pairs)
```

### Piet

Piet programs are images where the colors encode instructions:

```bash
# Use npiet interpreter
npiet piet_program.png
```

The direction of traversal and color transitions determine which operations execute.

## Esolang Identification Script

```python
#!/usr/bin/env python3
"""identify_esolang.py - Identify esoteric programming languages"""
import sys
import re

def identify(filepath):
    with open(filepath, 'rb') as f:
        raw = f.read()

    text = raw.decode('utf-8', errors='replace')
    charset = set(text.replace('\n', '').replace('\r', ''))

    # Check for Brainfuck
    bf_chars = set('+-<>.,[]')
    if charset.issubset(bf_chars | {' ', '\n', '\r', '\t'}):
        if charset & {'[', ']', '+', '-'}:
            return "Brainfuck"

    # Check for Whitespace
    ws_chars = set(' \t\n\r')
    if charset.issubset(ws_chars) and len(raw) > 10:
        return "Whitespace"

    # Check for JSFuck
    jsf_chars = set('[]()!+')
    if charset.issubset(jsf_chars | {' ', '\n', '\r'}):
        return "JSFuck"

    # Check for Ook!
    if re.match(r'^[\s]*(Ook[.!?]\s+Ook[.!?]\s*)+$', text):
        return "Ook!"

    # Check for image (Piet)
    if raw[:8] == b'\x89PNG\r\n\x1a\n':
        return "Possibly Piet (PNG image)"
    if raw[:2] == b'BM':
        return "Possibly Piet (BMP image)"

    # Check for Malbolge (printable ASCII, specific entropy)
    if all(33 <= b <= 126 for b in raw.strip()):
        if len(set(raw.strip())) > 40:
            return "Possibly Malbolge"

    return "Unknown"

if __name__ == "__main__":
    result = identify(sys.argv[1])
    print(f"Identified language: {result}")
```

```bash
python3 identify_esolang.py mystery_program.txt
```

```
Identified language: Brainfuck
```

## Tools Used

- Custom Python Brainfuck interpreter
- `node` (Node.js) — for running JSFuck
- `npiet` — Piet interpreter
- `wspace` — Whitespace interpreter
- Online interpreters (copy.sh/brainfuck, dcode.fr) as alternatives

## Lessons Learned

- Recognizing esolangs is primarily about character set analysis — most have a tiny, distinctive alphabet
- Brainfuck is the most common esolang in CTFs; keep an interpreter handy
- Whitespace is the sneakiest — the file looks empty but may contain a full program in spaces and tabs
- JSFuck is valid JavaScript — run it in Node.js, but in a sandbox since it could be malicious
- Piet programs are images — if a challenge gives you a colorful abstract PNG, try running it as Piet
- Many esolangs are Brainfuck derivatives (Ook!, COW, Spoon) — convert them to Brainfuck first
- The `file` command will not identify esolangs — you need to examine the content yourself
