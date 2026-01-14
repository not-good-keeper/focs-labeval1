import sqlite3
import secrets
import hashlib

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

conn = sqlite3.connect("database.db")
cur = conn.cursor()

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

conn.close()
