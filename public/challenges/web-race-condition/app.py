#!/usr/bin/env python3
"""
Race Condition Challenge
Port: 5012

A simple bank app with a coupon redemption endpoint. The balance
check and deduction are not atomic — send concurrent requests
to redeem the coupon multiple times and accumulate enough balance
to buy the flag.
"""

import os, time
from flask import Flask, request, render_template_string, session

app = Flask(__name__)
app.secret_key = "not-very-secret-key"

FLAG = open(os.path.join(os.path.dirname(__file__), "flag.txt")).read().strip()

# In-memory state (intentionally not thread-safe)
balances = {}
redeemed = {}

INDEX = """
<!DOCTYPE html>
<html>
<head><title>ZemiBank</title></head>
<body>
<h1>ZemiBank</h1>
<p>Balance: ${{ balance }}</p>
<hr>
<h3>Redeem Coupon</h3>
<form method="POST" action="/redeem">
  <input type="text" name="code" value="WELCOME50" size="20">
  <button type="submit">Redeem</button>
</form>
<h3>Buy Flag ($200)</h3>
<form method="POST" action="/buy-flag">
  <button type="submit">Purchase</button>
</form>
{% if message %}<p><b>{{ message }}</b></p>{% endif %}
</body>
</html>
"""

COUPONS = {
    "WELCOME50": 50,
}


@app.route("/")
def index():
    uid = session.get("uid", "default")
    bal = balances.get(uid, 0)
    return render_template_string(INDEX, balance=bal)


@app.route("/init")
def init():
    """Reset your account."""
    import uuid
    uid = str(uuid.uuid4())
    session["uid"] = uid
    balances[uid] = 0
    redeemed[uid] = set()
    return render_template_string(INDEX, balance=0, message="Account created! UID: " + uid)


@app.route("/redeem", methods=["POST"])
def redeem():
    uid = session.get("uid", "default")
    if uid not in balances:
        balances[uid] = 0
        redeemed[uid] = set()

    code = request.form.get("code", "").strip().upper()
    amount = COUPONS.get(code)

    if not amount:
        return render_template_string(INDEX, balance=balances[uid], message="Invalid coupon.")

    # VULNERABLE: check-then-act with a sleep in between (race window)
    if code in redeemed.get(uid, set()):
        return render_template_string(
            INDEX, balance=balances[uid], message="Coupon already redeemed!"
        )

    # Simulate slow processing — widens the race window
    time.sleep(0.5)

    redeemed.setdefault(uid, set()).add(code)
    balances[uid] = balances.get(uid, 0) + amount

    return render_template_string(
        INDEX, balance=balances[uid], message=f"Coupon redeemed! +${amount}"
    )


@app.route("/buy-flag", methods=["POST"])
def buy_flag():
    uid = session.get("uid", "default")
    bal = balances.get(uid, 0)

    if bal >= 200:
        balances[uid] -= 200
        return render_template_string(
            INDEX, balance=balances[uid], message=f"Flag: {FLAG}"
        )
    else:
        return render_template_string(
            INDEX, balance=bal, message=f"Not enough funds. Need $200, have ${bal}."
        )


if __name__ == "__main__":
    # threaded=True is required for the race condition to work
    app.run(host="0.0.0.0", port=5012, debug=False, threaded=True)
