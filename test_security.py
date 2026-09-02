"""End-to-end checks for the security controls in app.py.

Covers the CSRF layer, the Socket.IO authentication and DM-room membership
rules, and the encrypt/HMAC round trip.

Run against a throwaway database -- it creates test users and messages, and
app.py hardcodes "database.db":

    python db.py && python createadmindb.py
    python test_security.py
"""

import re
import sqlite3
import sys

import app as A

A.app.config["TESTING"] = True
client = A.app.test_client()

failures = []

# The test users are recreated on every run so the suite is repeatable.
_db = sqlite3.connect("database.db")
_db.execute("DELETE FROM users WHERE username IN ('alice', 'bob')")
_db.execute("DELETE FROM messages WHERE room LIKE '%alice%' OR room LIKE '%bob%'")
_db.commit()
_db.close()


def check(name, condition):
    print("PASS" if condition else "FAIL", name)
    if not condition:
        failures.append(name)


def csrf_token(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return match.group(1) if match else None


def names(socket_client):
    return [event["name"] for event in socket_client.get_received()]


# ---------------- CSRF ----------------
token = csrf_token(client.get("/").get_data(as_text=True))
check("login page renders a CSRF token", bool(token))

r = client.post("/signup", data={"username": "alice", "password": "hunter22"})
check("signup without a CSRF token is rejected", r.status_code == 400)

r = client.post("/signup", data={"username": "alice", "password": "hunter22", "csrf_token": token})
check("signup with a CSRF token succeeds", r.status_code == 302)
r = client.post("/signup", data={"username": "bob", "password": "hunter22", "csrf_token": token})
check("a second account can be created", r.status_code == 302)

# ---------------- login + OTP ----------------
token = csrf_token(client.get("/").get_data(as_text=True))
r = client.post("/login", data={"username": "alice", "password": "hunter22", "csrf_token": token})
check("valid login redirects to the OTP step", r.status_code == 302 and "/otp" in r.headers["Location"])

with client.session_transaction() as flask_session:
    otp = flask_session["otp"]

token = csrf_token(client.get("/otp").get_data(as_text=True))
r = client.post("/otp", data={"otp": str(otp), "csrf_token": token})
check("correct OTP completes MFA", r.status_code == 302 and "/home" in r.headers["Location"])
check("home is reachable once MFA is set", client.get("/home").status_code == 200)

token = csrf_token(client.get("/account").get_data(as_text=True))
r = client.post(
    "/change_password",
    data={"current_password": "hunter22", "new_password": "hunter33",
          "confirm_password": "hunter33", "csrf_token": token},
)
check("password change works with a token", r.status_code in (200, 302))
r = client.post("/change_password", data={"current_password": "hunter33", "new_password": "x1"})
check("password change without a token is rejected", r.status_code == 400)

# ---------------- Socket.IO access control ----------------
anonymous = A.socketio.test_client(A.app)
anonymous.emit("join", {"room": "group"})
received = names(anonymous)
check("anonymous join leaks no message history", "room_messages" not in received)
check("anonymous join returns an error", "error" in received)

authed = A.socketio.test_client(A.app, flask_test_client=client)
authed.emit("join", {"room": "group"})
check("authenticated join receives history", "room_messages" in names(authed))

authed.emit("join", {"room": "bob|carol"})
received = names(authed)
check("joining someone else's DM is denied", "room_messages" not in received and "error" in received)

authed.emit("join", {"room": "alice|bob"})
check("your own DM is joinable", "room_messages" in names(authed))

authed.emit("send_message", {"room": "alice|bob", "message": "hello bob"})
check("sending into your own DM works", "new_message" in names(authed))

authed.emit("send_message", {"room": "bob|carol", "message": "snoop"})
check("sending into someone else's DM is denied", "error" in names(authed))

# ---------------- encryption + integrity ----------------
messages = A.fetch_messages("alice|bob")
check("message survives the encrypt/HMAC round trip",
      any(m["message"] == "hello bob" for m in messages))

stored = sqlite3.connect("database.db").execute(
    "SELECT message FROM messages WHERE room='alice|bob'"
).fetchone()[0]
check("the database row holds ciphertext, not plaintext", "hello bob" not in stored)

print()
if failures:
    print(f"{len(failures)} check(s) failed:", ", ".join(failures))
    sys.exit(1)
print("All checks passed.")
