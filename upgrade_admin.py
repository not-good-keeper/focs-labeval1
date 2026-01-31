"""
Helper script to update admin password to new PBKDF2 format
Run this once to upgrade the admin account
"""
import sqlite3
import secrets
import hashlib
import hmac

def hash_password(password, salt, iterations=260000):
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    return f"pbkdf2${iterations}${dk.hex()}"

# Connect to database
conn = sqlite3.connect("database.db")
cur = conn.cursor()

try:
    # Get admin account
    cur.execute("SELECT username FROM users WHERE username=?", ("admin",))
    if not cur.fetchone():
        print("Admin account not found. Creating new admin account...")
        salt = secrets.token_hex(16)
        password_hash = hash_password("admin@123", salt)
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
            ("admin", password_hash, salt, "admin")
        )
        print("Admin account created with PBKDF2 hashing")
    else:
        # Update existing admin to PBKDF2
        print("Updating existing admin account to PBKDF2...")
        salt = secrets.token_hex(16)
        password_hash = hash_password("admin@123", salt)
        cur.execute(
            "UPDATE users SET password_hash=?, salt=? WHERE username=?",
            (password_hash, salt, "admin")
        )
        print("Admin account updated to PBKDF2 hashing")
    
    conn.commit()
    print("Done! Admin password: admin@123")
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
