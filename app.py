from flask import Flask, render_template, request, redirect, session
import sqlite3
import secrets
import hashlib
import time
import base64
import hmac
from cryptography.fernet import Fernet
import os

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.secret_key = "lab-secret-key"

# ---------------- ACCESS CONTROL LIST ----------------
ACL = {
    "admin": ["read", "send", "delete"],
    "user": ["read", "send"]
}

def check_access(action):
    role = session.get("role")
    return role and action in ACL.get(role, [])

# ---------------- PASSWORD HASHING ----------------
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# ---------------- ENCRYPTION + INTEGRITY ----------------

KEY_FILE = "fernet.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as f:
    FERNET_KEY = f.read()
cipher = Fernet(FERNET_KEY)

INTEGRITY_KEY = b"lab-integrity-key"

def encrypt_message(plain_text):
    encrypted = cipher.encrypt(plain_text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(encoded_text):
    encrypted = base64.b64decode(encoded_text.encode())
    return cipher.decrypt(encrypted).decode()

def generate_hmac(message):
    return hmac.new(INTEGRITY_KEY, message.encode(), hashlib.sha256).hexdigest()
def verify_hmac(message, signature):
    expected = generate_hmac(message)
    return hmac.compare_digest(expected, signature)

# ---------------- DATABASE ----------------
def get_db():
    return sqlite3.connect("database.db")

# ---------------- ROUTES ----------------
@app.route("/")
def index():
    return render_template("login.html")

# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt)

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                (username, password_hash, salt, "user")
            )
            conn.commit()
            conn.close()
        except:
            return "Username already exists"

        return redirect("/")

    return render_template("signup.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT password_hash, salt, role FROM users WHERE username=?",
        (username,)
    )
    user = cur.fetchone()
    conn.close()

    if not user:
        return "Invalid username or password"

    stored_hash, salt, role = user
    if hash_password(password, salt) != stored_hash:
        return "Invalid username or password"

    session.clear()
    session["temp_user"] = username
    session["role"] = role
    session["otp"] = secrets.randbelow(1000000)
    session["otp_time"] = time.time()

    print("OTP (for demo):", session["otp"])
    return redirect("/otp")

# ---------------- OTP ----------------
@app.route("/otp", methods=["GET", "POST"])
def otp():
    if "otp" not in session:
        return redirect("/")

    if request.method == "POST":
        if time.time() - session["otp_time"] > 60:
            return "OTP expired"

        if request.form["otp"] == str(session["otp"]):
            session["user"] = session["temp_user"]
            session.pop("temp_user")
            session.pop("otp")
            session.pop("otp_time")
            session["mfa"] = True
            return redirect("/home")

        return "Invalid OTP"

    return """
    <h3>Enter OTP</h3>
    <form method="POST">
        <input name="otp" required>
        <button>Verify</button>
    </form>
    """

# ---------------- HOME ----------------
@app.route("/home")
def home():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")
    return render_template("homepage.html")

# ---------------- DM CHAT ----------------
@app.route("/dmchat", methods=["GET", "POST"])
def dmchat():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")

    target = request.args.get("user")
    if not target:
        return render_template("dmchat.html", messages=[], target=None)

    users = sorted([session["user"], target])
    room = "|".join(users)

    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        if not check_access("send"):
            return "Access Denied"

        plain = request.form["message"]
        encrypted = encrypt_message(plain)
        signature = generate_hmac(plain)

        cur.execute(
            "INSERT INTO messages (sender, room, message, signature) VALUES (?, ?, ?, ?)",
            (session["user"], room, encrypted, signature)
        )
        conn.commit()
        conn.close()
        return redirect(f"/dmchat?user={target}")


    cur.execute(
        "SELECT id, sender, message, signature, timestamp FROM messages WHERE room=? ORDER BY timestamp",
        (room,)
    )

    rows = cur.fetchall()
    messages = []

    for msg_id, sender, enc_msg, sig, ts in rows:
        try:
            plain = decrypt_message(enc_msg)
            if verify_hmac(plain, sig):
                messages.append((msg_id, sender, plain, ts))
            else:
                messages.append((msg_id, sender, "[Integrity check failed]", ts))
        except Exception:
            messages.append((msg_id, sender, "[Corrupted message]", ts))


    conn.close()
    return render_template("dmchat.html", messages=messages, target=target)

# ---------------- GROUP CHAT ----------------
@app.route("/groupchat", methods=["GET", "POST"])
def groupchat():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        if not check_access("send"):
            return "Access Denied"

        plain = request.form["message"]
        encrypted = encrypt_message(plain)
        signature = generate_hmac(plain)

        cur.execute(
            "INSERT INTO messages (sender, room, message, signature) VALUES (?, ?, ?, ?)",
            (session["user"], "group", encrypted, signature)
        )
        conn.commit()
        conn.close()
        return redirect("/groupchat")


    cur.execute(
    "SELECT id, sender, message, signature, timestamp FROM messages WHERE room='group' ORDER BY timestamp"
)

    rows = cur.fetchall()

    messages = []

    for msg_id, sender, enc_msg, sig, ts in rows:
        try:
            plain = decrypt_message(enc_msg)
            if verify_hmac(plain, sig):
                messages.append((msg_id, sender, plain, ts))
            else:
                messages.append((msg_id, sender, "[Integrity check failed]", ts))
        except Exception:
            messages.append((msg_id, sender, "[Corrupted message]", ts))



    conn.close()
    return render_template("groupchat.html", messages=messages)

# ---------------- SEARCH ----------------
@app.route("/search")
def search():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")

    q = request.args.get("query")
    users = []

    if q:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT username FROM users WHERE username LIKE ? AND username != ?",
            (f"%{q}%", session["user"])
        )
        users = cur.fetchall()
        conn.close()

    return render_template("search.html", users=users)

# ---------------- ACCOUNT ----------------
@app.route("/account")
def account():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")
    return render_template("accountsetting.html")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- DELETE (ADMIN ONLY) ----------------
from flask import request, redirect

@app.route("/delete_message/<int:msg_id>", methods=["POST"])
def delete_message(msg_id):
    if not check_access("delete"):
        return "Access Denied"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM messages WHERE id=?", (msg_id,))
    conn.commit()
    conn.close()

    return redirect(request.referrer or "/groupchat")



# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
