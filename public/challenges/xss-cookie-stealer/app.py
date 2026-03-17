#!/usr/bin/env python3
"""
XSS Cookie Stealer Challenge
Port: 5002

A search page that reflects user input without escaping.
Submit a /report URL to have a simulated admin bot visit it
with the flag stored in its cookie.
"""

import os, threading, time
from flask import Flask, request, render_template_string, make_response

app = Flask(__name__)

FLAG = open(os.path.join(os.path.dirname(__file__), "flag.txt")).read().strip()

SEARCH_PAGE = """
<!DOCTYPE html>
<html>
<head><title>SearchBox</title></head>
<body>
<h1>SearchBox&trade;</h1>
<form method="GET" action="/search">
  <input type="text" name="q" placeholder="Search..." size="40">
  <button type="submit">Search</button>
</form>
{% if query %}
  <h3>Results for: """ + "{{ query | safe }}" + """</h3>
  <p>No results found.</p>
{% endif %}
</body>
</html>
"""

REPORT_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Report to Admin</title></head>
<body>
<h1>Report a Link</h1>
<p>Submit a URL and our admin will review it.</p>
<form method="POST" action="/report">
  <input type="text" name="url" placeholder="http://..." size="50">
  <button type="submit">Report</button>
</form>
{% if message %}<p>{{ message }}</p>{% endif %}
</body>
</html>
"""

STOLEN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Cookie Jar</title></head>
<body>
<h1>Stolen Cookies</h1>
<ul>
{% for c in cookies %}
  <li>{{ c }}</li>
{% endfor %}
</ul>
<p>Hint: use <code>/steal?cookie=VALUE</code> as your exfil endpoint.</p>
</body>
</html>
"""

stolen_cookies = []


@app.route("/")
def index():
    return render_template_string(SEARCH_PAGE)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # VULNERABLE: query is rendered with |safe — no escaping
    return render_template_string(SEARCH_PAGE, query=query)


@app.route("/report", methods=["GET", "POST"])
def report():
    if request.method == "GET":
        return render_template_string(REPORT_PAGE)

    url = request.form.get("url", "")
    if not url.startswith("http"):
        return render_template_string(REPORT_PAGE, message="Invalid URL.")

    # Simulate an admin bot visiting the URL with the flag cookie
    def admin_visit(target_url):
        """In a real CTF this would be a headless browser.
        Here we just demonstrate the concept."""
        time.sleep(1)
        print(f"[BOT] Admin bot would visit: {target_url}")
        print(f"[BOT] Admin cookie: flag={FLAG}")

    threading.Thread(target=admin_visit, args=(url,), daemon=True).start()
    return render_template_string(
        REPORT_PAGE,
        message="Admin will review your link shortly. "
        "(Hint: in a real CTF, a headless browser visits your URL "
        "with the flag in document.cookie.)",
    )


@app.route("/steal")
def steal():
    """Exfil endpoint — attacker points XSS payload here."""
    cookie = request.args.get("cookie", "")
    if cookie:
        stolen_cookies.append(cookie)
    return "OK"


@app.route("/cookies")
def cookies():
    return render_template_string(STOLEN_PAGE, cookies=stolen_cookies)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
