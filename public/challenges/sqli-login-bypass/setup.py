#!/usr/bin/env python3
"""Initialise the SQLite database with an admin user."""

import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

conn = sqlite3.connect(DB_PATH)
conn.execute(
    "CREATE TABLE IF NOT EXISTS users "
    "(id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
)
conn.execute(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    ("admin", "S3cur3P@ssw0rd!2024"),
)
conn.execute(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    ("guest", "guest"),
)
conn.commit()
conn.close()
print("[+] Database initialised at", DB_PATH)
