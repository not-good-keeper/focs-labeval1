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
conn.commit()
conn.close()
