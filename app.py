from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import secrets
import hashlib
import time
import base64
import hmac
from cryptography.fernet import Fernet
import pyotp
import os
from flask_socketio import SocketIO, join_room, leave_room, emit

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "lab-secret-key")

# Socket.IO (real-time)
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

# ---------------- ACCESS CONTROL LIST ----------------
ACL = {
    "admin": ["read", "send", "delete"],
    "user": ["read", "send"]
}

def check_access(action):
    role = session.get("role")
    return role and action in ACL.get(role, [])

# ---------------- PASSWORD HASHING ----------------
def hash_password(password, salt, iterations=260000):
    # PBKDF2-HMAC-SHA256 with configurable iterations. Store as: pbkdf2$<iters>$<hex>
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    return f"pbkdf2${iterations}${dk.hex()}"


def verify_password(password, stored_hash, salt):
    # Support new pbkdf2 format and legacy sha256(password+salt)
    if stored_hash and stored_hash.startswith('pbkdf2$'):
        try:
            parts = stored_hash.split('$')
            iterations = int(parts[1])
            expected = parts[2]
            dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
            return hmac.compare_digest(dk.hex(), expected)
        except Exception:
            return False
    else:
        # legacy fallback
        return hashlib.sha256((password + salt).encode()).hexdigest() == stored_hash

# ---------------- ENCRYPTION + INTEGRITY ----------------

KEY_FILE = "fernet.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as f:
    FERNET_KEY = f.read()
cipher = Fernet(FERNET_KEY)

# Integrity key: always load from file for consistency (prevents key rotation issues)
INTEGRITY_FILE = "integrity.key"
if not os.path.exists(INTEGRITY_FILE):
    # Create key file on first run
    with open(INTEGRITY_FILE, "wb") as f:
        f.write(secrets.token_bytes(32))

with open(INTEGRITY_FILE, "rb") as f:
    INTEGRITY_KEY = f.read()
    
# Verify key is 32 bytes
if len(INTEGRITY_KEY) != 32:
    raise ValueError("Integrity key must be 32 bytes. File may be corrupted. Delete integrity.key and restart.")

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
    conn = sqlite3.connect("database.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Security: Enable foreign keys and set strict mode
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")  # Write-ahead logging for consistency
    conn.execute("PRAGMA query_only = OFF")  # Allow writes
    # Disable dangerous SQL functions
    conn.execute("PRAGMA trusted_schema = OFF")
    return conn


def fetch_messages(room):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, sender, message, signature, timestamp FROM messages WHERE room=? ORDER BY timestamp",
        (room,)
    )
    rows = cur.fetchall()
    messages = []
    for row in rows:
        msg_id = row["id"]
        sender = row["sender"]
        enc_msg = row["message"]
        sig = row["signature"] if "signature" in row.keys() else None
        ts = row["timestamp"]
        try:
            plain = decrypt_message(enc_msg)
            # If no signature (old messages), just display. Otherwise verify integrity.
            if sig:
                if verify_hmac(plain, sig):
                    body = plain
                else:
                    body = "[Integrity check failed]"
            else:
                body = plain
        except Exception as e:
            body = "[Corrupted message]"

        messages.append({"id": msg_id, "sender": sender, "message": body, "timestamp": ts})

    conn.close()
    return messages

# ---------------- ROUTES ----------------
@app.route("/")
def index():
    return render_template("login.html")

# ---- INPUT VALIDATION ----
def validate_username(username):
    """Validate username format and length"""
    if not username or not isinstance(username, str):
        return False, "Invalid username"
    username = username.strip()
    if len(username) < 3 or len(username) > 50:
        return False, "Username must be 3-50 characters"
    if not username.isalnum():
        return False, "Username must be alphanumeric"
    return True, username

def validate_password(password):
    """Validate password strength"""
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters"
    if len(password) > 200:
        return False, "Password too long"
    return True, password

# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        raw_username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        # Validate inputs
        valid, msg = validate_username(raw_username)
        if not valid:
            return msg
        username = msg
        
        valid, msg = validate_password(password)
        if not valid:
            return msg

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
        except sqlite3.IntegrityError:
            return "Username already exists"
        except Exception as e:
            return f"Error: {str(e)}"

        return redirect("/")

    return render_template("signup.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

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
    if not verify_password(password, stored_hash, salt):
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

    # render a nicer OTP page
    return render_template('otp.html', ttl=60)


@app.route('/otp/resend', methods=['POST'])
def otp_resend():
    # rate limit: allow resend every 20 seconds
    if 'otp_time' in session and time.time() - session['otp_time'] < 20:
        return {"error": "Please wait before resending"}, 429

    session['otp'] = secrets.randbelow(1000000)
    session['otp_time'] = time.time()
    print("OTP (resend, for demo):", session['otp'])
    return {"ok": True}

# ---------------- HOME ----------------
@app.route("/home")
def home():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")
    return render_template("homepage.html")

# ---------------- DM CHAT ----------------
@app.route("/dmchat", methods=["GET"])
def dmchat():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")

    target = request.args.get("user")
    if not target:
        return render_template("dmchat.html", messages=[], target=None)

    users = sorted([session["user"], target])
    room = "|".join(users)

    messages = fetch_messages(room)
    return render_template("dmchat.html", messages=messages, target=target)

# ---------------- GROUP CHAT ----------------
@app.route("/groupchat", methods=["GET"])
def groupchat():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")

    messages = fetch_messages("group")
    return render_template("groupchat.html", messages=messages)

# ---------------- GET DM LIST ----------------
@app.route("/api/dms")
def get_dms():
    if "user" not in session or not session.get("mfa"):
        return {"error": "Unauthorized"}, 401
    
    conn = get_db()
    cur = conn.cursor()
    current_user = session['user']
    
    # Get all DM conversations for this user by parsing room field
    cur.execute("SELECT DISTINCT room FROM messages WHERE room LIKE ?", (f"%|%",))
    rows = cur.fetchall()
    
    users = set()
    for row in rows:
        room = row[0]
        parts = room.split("|")
        if len(parts) == 2:
            user1, user2 = parts[0], parts[1]
            # Add the other user if this room contains current user
            if user1 == current_user:
                users.add(user2)
            elif user2 == current_user:
                users.add(user1)
    
    conn.close()
    
    # Convert set to sorted list
    users = sorted(list(users))
    
    return {"users": users}


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

# ---- CHANGE USERNAME ----
@app.route("/change_username", methods=["POST"])
def change_username():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")
    
    new_username = request.form.get("new_username", "").strip()
    password = request.form.get("password", "")
    
    # Validate input
    if not new_username or len(new_username) < 3:
        return "Username must be at least 3 characters"
    if not password:
        return "Password required"
    if len(new_username) > 50:
        return "Username too long"
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Get current user's salt and hash
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (session["user"],))
        row = cur.fetchone()
        
        if not row:
            conn.close()
            return "User not found"
        
        stored_hash, salt = row[0], row[1]
        
        # Verify password
        if not verify_password(password, stored_hash, salt):
            conn.close()
            return "Incorrect password"
        
        # Check if new username already exists
        cur.execute("SELECT username FROM users WHERE username=?", (new_username,))
        if cur.fetchone():
            conn.close()
            return "Username already taken"
        
        # Update username
        cur.execute("UPDATE users SET username=? WHERE username=?", (new_username, session["user"]))
        conn.commit()
        conn.close()
        
        # Update session
        session["user"] = new_username
        return redirect("/account")
    except Exception as e:
        conn.close()
        return f"Error: {str(e)}"

# ---- DELETE ACCOUNT ----
@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")
    
    password = request.form.get("password", "")
    confirm_username = request.form.get("confirm_username", "").strip()
    
    current_user = session["user"]
    
    if not password or not confirm_username:
        return "Password and username confirmation required"
    
    if confirm_username != current_user:
        return "Username confirmation doesn't match"
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Get user's password hash to verify
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (current_user,))
        row = cur.fetchone()
        
        if not row:
            conn.close()
            return "User not found"
        
        stored_hash, salt = row[0], row[1]
        
        # Verify password before deletion
        if not verify_password(password, stored_hash, salt):
            conn.close()
            return "Incorrect password"
        
        # Delete all messages from this user
        cur.execute("DELETE FROM messages WHERE sender=?", (current_user,))
        
        # Delete all messages in DMs involving this user
        cur.execute("DELETE FROM messages WHERE room LIKE ? OR room LIKE ?", 
                   (f"{current_user}|%", f"%|{current_user}"))
        
        # Delete the user account
        cur.execute("DELETE FROM users WHERE username=?", (current_user,))
        
        conn.commit()
        conn.close()
        
        # Clear session and redirect
        session.clear()
        return redirect("/")
    except Exception as e:
        conn.close()
        return f"Error: {str(e)}"

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

    # notify clients
    socketio.emit("message_deleted", {"id": msg_id}, broadcast=True)
    return redirect(request.referrer or "/groupchat")


# ---------------- Socket.IO events ----------------
@socketio.on("join")
def handle_join(data):
    room = data.get("room")
    if not room:
        return
    join_room(room)
    # send existing messages
    msgs = fetch_messages(room)
    emit("room_messages", {"messages": msgs})


@socketio.on("send_message")
def handle_send_message(data):
    if "user" not in session or not session.get("mfa"):
        emit("error", {"error": "Not authenticated"})
        return

    if not check_access("send"):
        emit("error", {"error": "Access Denied"})
        return

    room = data.get("room")
    plain = data.get("message", "").strip()
    if not room or not plain:
        return

    encrypted = encrypt_message(plain)
    signature = generate_hmac(plain)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages (sender, room, message, signature) VALUES (?, ?, ?, ?)",
        (session["user"], room, encrypted, signature)
    )
    conn.commit()
    msg_id = cur.lastrowid
    conn.close()

    msg = {"id": msg_id, "sender": session["user"], "message": plain, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    emit("new_message", msg, room=room)


@socketio.on("delete_message")
def handle_delete_message(data):
    msg_id = data.get("id")
    if not msg_id:
        return
    if not check_access("delete"):
        emit("error", {"error": "Access Denied"})
        return

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM messages WHERE id=?", (msg_id,))
    conn.commit()
    conn.close()

    emit("message_deleted", {"id": msg_id}, broadcast=True)


# ---------------- RUN ----------------
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
