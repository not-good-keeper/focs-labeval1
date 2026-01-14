import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()

cur.execute("ALTER TABLE messages ADD COLUMN signature TEXT")
conn.commit()
conn.close()

print("signature column added")
