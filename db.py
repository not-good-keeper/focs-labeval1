import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()
cur.execute("DROP TABLE IF EXISTS messages")
cur.execute("""
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    room TEXT,
    message TEXT,
    signature TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
)
""")

conn.commit()
conn.close()
print("Database initialised")
