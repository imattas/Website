#!/usr/bin/env python3
"""
Misc Challenge: Python Jail
A restricted Python environment that blacklists common escape functions.
Players must find creative ways to read flag.txt despite the restrictions.

Usage: python3 jail.py
Intended solution examples:
  - Use __class__.__mro__ chain to access builtins
  - Use getattr() tricks
  - Use __subclasses__() to find file-reading classes
"""

import sys
import os

FLAG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag.txt")

# Write the flag file if it doesn't exist
if not os.path.exists(FLAG_FILE):
    with open(FLAG_FILE, "w") as f:
        f.write("zemi{pyth0n_j41l_br34k}\n")

BANNER = """
  ____        _   _                     _       _ _
 |  _ \\ _   _| |_| |__   ___  _ __    | | __ _(_) |
 | |_) | | | | __| '_ \\ / _ \\| '_ \\   | |/ _` | | |
 |  __/| |_| | |_| | | | (_) | | | |  | | (_| | | |
 |_|    \\__, |\\__|_| |_|\\___/|_| |_| _/ |\\__,_|_|_|
        |___/                        |__/

 Welcome to the Python Jail!
 The flag is in flag.txt. Can you read it?
 Type 'exit' or 'quit' to leave.
"""

# Blacklisted keywords
BLACKLIST = [
    "import",
    "open",
    "__builtins__",
    "exec",
    "eval",
    "compile",
    "execfile",
    "input",
    "__import__",
    "breakpoint",
]


def check_input(user_input):
    """Check if the input contains any blacklisted keywords."""
    for word in BLACKLIST:
        if word in user_input:
            print(f"[!] Blocked: '{word}' is not allowed!")
            return False
    return True


def jail():
    """Run the restricted Python jail."""
    print(BANNER)
    print(f"Blacklisted keywords: {', '.join(BLACKLIST)}")
    print()

    # Restricted globals - remove dangerous builtins
    restricted_globals = {"__builtins__": {}}

    # Allow some safe builtins
    safe_builtins = [
        "print", "type", "str", "int", "float", "bool", "list", "dict",
        "tuple", "set", "len", "range", "enumerate", "zip", "map", "filter",
        "sorted", "reversed", "chr", "ord", "hex", "bin", "oct",
        "hasattr", "getattr", "setattr", "dir", "vars", "id",
        "isinstance", "issubclass", "repr", "hash",
        "True", "False", "None",
    ]

    import builtins
    for name in safe_builtins:
        if hasattr(builtins, name):
            restricted_globals["__builtins__"][name] = getattr(builtins, name)

    while True:
        try:
            user_input = input("jail>>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit"):
            print("Bye!")
            break

        if not check_input(user_input):
            continue

        try:
            # Try as expression first (to print result)
            try:
                result = eval(user_input, restricted_globals)
                if result is not None:
                    print(result)
            except SyntaxError:
                # Fall back to exec for statements
                exec(user_input, restricted_globals)
        except Exception as e:
            print(f"Error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    jail()
