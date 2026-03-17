#!/usr/bin/env python3
"""Initialise the SQLite database with products and a hidden secrets table."""

import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), "store.db")

conn = sqlite3.connect(DB_PATH)

conn.execute(
    "CREATE TABLE IF NOT EXISTS products "
    "(id INTEGER PRIMARY KEY, name TEXT, price REAL)"
)
products = [
    ("Laptop", 999.99),
    ("Keyboard", 49.99),
    ("Mouse", 29.99),
    ("Monitor", 349.99),
    ("Headphones", 79.99),
    ("USB Cable", 9.99),
    ("Webcam", 59.99),
]
conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)", products)

# Hidden table with the flag
conn.execute(
    "CREATE TABLE IF NOT EXISTS secrets "
    "(id INTEGER PRIMARY KEY, flag TEXT)"
)
conn.execute(
    "INSERT INTO secrets (flag) VALUES (?)",
    ("zemi{bl1nd_sqli_b1t_by_b1t}",),
)

conn.commit()
conn.close()
print("[+] Database initialised at", DB_PATH)
