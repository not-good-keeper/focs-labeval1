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
    # Allow alphanumeric, underscores, hyphens, dots
    if not all(c.isalnum() or c in '_-.' for c in username):
        return False, "Username can only contain letters, numbers, underscores, hyphens, or dots"
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
            return render_template("error.html", error_title="Invalid Username", error_message=msg, error_type="account_error")
        username = msg
        
        valid, msg = validate_password(password)
        if not valid:
            return render_template("error.html", error_title="Weak Password", error_message=msg, error_type="account_error")
        
        # Check if username already exists
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE username=?", (username,))
        if cur.fetchone():
            conn.close()
            return render_template("error.html", error_title="Username Taken", error_message="This username is already registered. Try another one.", error_type="account_error")
        conn.close()

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
            return render_template("error.html", error_title="Signup Failed", error_message="Username already exists. Try another one.", error_type="account_error")
        except Exception as e:
            return render_template("error.html", error_title="Error", error_message=f"Signup failed. Please try again.", error_type="account_error")

        return redirect("/")

    return render_template("signup.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    
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
        return render_template("error.html", error_title="Login Failed", error_message="Invalid username or password. Please try again or create a new account.", error_type="invalid_credentials")

    stored_hash, salt, role = user
    if not verify_password(password, stored_hash, salt):
        return render_template("error.html", error_title="Login Failed", error_message="Invalid username or password. Please try again or create a new account.", error_type="invalid_credentials")

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
            return render_template("error.html", error_title="OTP Expired", error_message="Your one-time password has expired. Please login again.", error_type="otp_expired")

        if request.form.get("otp", "").strip() == str(session["otp"]):
            session["user"] = session["temp_user"]
            session.pop("temp_user")
            session.pop("otp")
            session.pop("otp_time")
            session["mfa"] = True
            return redirect("/home")

        return render_template("error.html", error_title="Invalid OTP", error_message="The code you entered is incorrect. Check the terminal or request a new code.", error_type="invalid_otp")

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
    
    # Admin cannot change username
    if session.get("role") == "admin":
        return render_template("error.html", error_title="Access Denied", error_message="Admin accounts cannot be modified for security reasons.", error_type="account_error")
    
    new_username = request.form.get("new_username", "").strip()
    password = request.form.get("password", "")
    
    # Validate input
    valid, msg = validate_username(new_username)
    if not valid:
        print(f"[DEBUG] Username validation failed for {session['user']}: {msg}")
        return render_template("error.html", error_title="Invalid Username", error_message=msg, error_type="account_error")
    
    if not password:
        print(f"[DEBUG] Password not provided for {session['user']}")
        return render_template("error.html", error_title="Password Required", error_message="Please enter your password to change username.", error_type="account_error")
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Get current user's salt and hash
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (session["user"],))
        row = cur.fetchone()
        
        if not row:
            conn.close()
            print(f"[DEBUG] User {session['user']} not found in database")
            return render_template("error.html", error_title="Error", error_message="User not found.", error_type="account_error")
        
        stored_hash, salt = row[0], row[1]
        
        # Verify password
        if not verify_password(password, stored_hash, salt):
            conn.close()
            print(f"[DEBUG] Password verification failed for {session['user']}")
            return render_template("error.html", error_title="Incorrect Password", error_message="The password you entered is incorrect.", error_type="account_error")
        
        print(f"[DEBUG] Changing username from {session['user']} to {new_username}")
        
        # Check if new username already exists (excluding current user)
        cur.execute("SELECT username FROM users WHERE username=? AND username != ?", (new_username, session["user"]))
        if cur.fetchone():
            conn.close()
            return render_template("error.html", error_title="Username Taken", error_message="This username is already in use. Choose another.", error_type="account_error")
        
        # Update username in users table
        cur.execute("UPDATE users SET username=? WHERE username=?", (new_username, session["user"]))
        
        # Update all messages where this user is the sender
        cur.execute("UPDATE messages SET sender=? WHERE sender=?", (new_username, session["user"]))
        
        # Update all DM rooms containing the old username
        # Get all rooms with old username
        cur.execute("SELECT DISTINCT room FROM messages WHERE room LIKE ? OR room LIKE ?", 
                   (f"{session['user']}|%", f"%|{session['user']}"))
        rooms = cur.fetchall()
        
        old_user = session["user"]
        for room_row in rooms:
            old_room = room_row[0]
            # Replace old username with new one in room name
            new_room = old_room.replace(old_user, new_username)
            if old_room != new_room:
                cur.execute("UPDATE messages SET room=? WHERE room=?", (new_room, old_room))
        
        conn.commit()
        conn.close()
        
        # Update session
        session["user"] = new_username
        return redirect("/account")
    except Exception as e:
        conn.close()
        print(f"[DEBUG] Exception in change_username for {session['user']}: {str(e)}")
        return render_template("error.html", error_title="Error", error_message="Failed to update username. Please try again.", error_type="account_error")

# ---- DELETE ACCOUNT ----
@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")
    
    # Admin cannot delete account
    if session.get("role") == "admin":
        return render_template("error.html", error_title="Access Denied", error_message="Admin accounts cannot be deleted for security reasons.", error_type="account_error")
    
    password = request.form.get("password", "")
    confirm_username = request.form.get("confirm_username", "").strip()
    
    current_user = session["user"]
    
    if not password or not confirm_username:
        return render_template("error.html", error_title="Missing Information", error_message="Please provide password and confirm your username.", error_type="account_error")
    
    if confirm_username != current_user:
        return render_template("error.html", error_title="Username Mismatch", error_message=f"Username confirmation doesn't match. Please enter '{current_user}'.", error_type="account_error")
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Get user's password hash to verify
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (current_user,))
        row = cur.fetchone()
        
        if not row:
            conn.close()
            return render_template("error.html", error_title="Error", error_message="User not found.", error_type="account_error")
        
        stored_hash, salt = row[0], row[1]
        
        # Verify password before deletion
        if not verify_password(password, stored_hash, salt):
            conn.close()
            return render_template("error.html", error_title="Incorrect Password", error_message="The password you entered is incorrect.", error_type="account_error")
        
        # Delete all user data in transaction
        # 1. Delete all messages sent by this user
        cur.execute("DELETE FROM messages WHERE sender=?", (current_user,))
        
        # 2. Delete all messages in DM rooms involving this user (user1|user2 format)
        cur.execute("DELETE FROM messages WHERE room LIKE ? OR room LIKE ?", 
                   (f"{current_user}|%", f"%|{current_user}"))
        
        # 3. Delete the user account
        cur.execute("DELETE FROM users WHERE username=?", (current_user,))
        
        # Commit all deletions
        conn.commit()
        conn.close()
        
        # Clear session and redirect
        session.clear()
        return redirect("/")
    except Exception as e:
        try:
            conn.rollback()
            conn.close()
        except:
            pass
        print(f"[DEBUG] Exception in delete_account for {session['user']}: {str(e)}")
        return render_template("error.html", error_title="Error", error_message="Failed to delete account. Please try again.", error_type="account_error")

# ---------------- CHANGE PASSWORD ----------------
@app.route("/change_password", methods=["POST"])
def change_password():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")
    
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    
    current_user = session["user"]
    
    if not current_password or not new_password or not confirm_password:
        return render_template("error.html", error_title="Missing Information", error_message="Please fill in all password fields.", error_type="account_error")
    
    if new_password != confirm_password:
        return render_template("error.html", error_title="Password Mismatch", error_message="New passwords do not match.", error_type="account_error")
    
    if not validate_password(new_password):
        return render_template("error.html", error_title="Invalid Password", error_message="Password must be 6-200 characters.", error_type="account_error")
    
    if current_password == new_password:
        return render_template("error.html", error_title="Same Password", error_message="New password must be different from current password.", error_type="account_error")
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Get user's current password hash and salt
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (current_user,))
        row = cur.fetchone()
        
        if not row:
            conn.close()
            return render_template("error.html", error_title="Error", error_message="User not found.", error_type="account_error")
        
        stored_hash, salt = row[0], row[1]
        
        # Verify current password
        if not verify_password(current_password, stored_hash, salt):
            conn.close()
            return render_template("error.html", error_title="Incorrect Password", error_message="Current password is incorrect.", error_type="account_error")
        
        # Generate new salt and hash for new password
        new_salt = secrets.token_hex(16)
        new_hash = hash_password(new_password, new_salt)
        
        # Update password in database
        cur.execute("UPDATE users SET password_hash=?, salt=? WHERE username=?", 
                   (new_hash, new_salt, current_user))
        conn.commit()
        conn.close()
        
        # Redirect to account settings with success message
        session["password_changed"] = True
        return redirect("/account")
    except Exception as e:
        try:
            conn.rollback()
            conn.close()
        except:
            pass
        print(f"[DEBUG] Exception in change_password for {session['user']}: {str(e)}")
        return render_template("error.html", error_title="Error", error_message="Failed to change password. Please try again.", error_type="account_error")

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


# ---- DATABASE CONSISTENCY CHECK (admin debug) ----
@app.route("/api/debug/consistency", methods=["GET"])
def check_consistency():
    """Check database consistency - verify no orphaned messages or invalid sender references"""
    if "user" not in session or session.get("role") != "admin":
        return {"error": "Admin only"}, 403
    
    conn = get_db()
    cur = conn.cursor()
    
    # Get all unique senders in messages
    cur.execute("SELECT DISTINCT sender FROM messages")
    senders = set(row[0] for row in cur.fetchall())
    
    # Get all users
    cur.execute("SELECT username FROM users")
    users = set(row[0] for row in cur.fetchall())
    
    # Check for orphaned messages (sender not in users table)
    orphaned = senders - users
    
    # Get database stats
    cur.execute("SELECT COUNT(*) FROM messages")
    msg_count = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM users")
    user_count = cur.fetchone()[0]
    
    conn.close()
    
    return {
        "status": "ok" if not orphaned else "warning",
        "message_count": msg_count,
        "user_count": user_count,
        "orphaned_senders": list(orphaned) if orphaned else [],
        "warning": f"Found {len(orphaned)} orphaned message senders (from deleted users)" if orphaned else "Database is consistent"
    }


# ---- CLEANUP ORPHANED DATA (admin only) ----
@app.route("/api/debug/cleanup", methods=["POST"])
def cleanup_orphaned():
    """Remove orphaned messages from deleted users - admin only"""
    if "user" not in session or session.get("role") != "admin":
        return {"error": "Admin only"}, 403
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # Get all valid users
        cur.execute("SELECT username FROM users")
        valid_users = set(row[0] for row in cur.fetchall())
        
        # Get all unique senders
        cur.execute("SELECT DISTINCT sender FROM messages")
        all_senders = set(row[0] for row in cur.fetchall())
        
        # Find orphaned senders
        orphaned_senders = all_senders - valid_users
        
        deleted_count = 0
        for sender in orphaned_senders:
            cur.execute("DELETE FROM messages WHERE sender=?", (sender,))
            deleted_count += cur.rowcount
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success",
            "orphaned_senders_removed": len(orphaned_senders),
            "messages_deleted": deleted_count
        }
    except Exception as e:
        conn.rollback()
        conn.close()
        return {"error": str(e)}, 500


# ---------------- RUN ----------------
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
