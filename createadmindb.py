import sqlite3
import secrets
import hashlib

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

conn = sqlite3.connect("database.db")
cur = conn.cursor()

# Create default admin
salt = secrets.token_hex(16)
password_hash = hash_password("admin@123", salt)

try:
    cur.execute(
        "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
        ("admin", password_hash, salt, "admin")
    )
    conn.commit()
    print("Default admin created")
except:
    print("Admin already exists")

# Create default owner
salt = secrets.token_hex(16)
password_hash = hash_password("owner@123", salt)

try:
    cur.execute(
        "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
        ("owner", password_hash, salt, "owner")
    )
    conn.commit()
    print("Default owner created")
except:
    print("Owner already exists")

conn.close()
