import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# -------------------------------
# USERS TABLE (with subscription)
# -------------------------------
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    subscription_end TEXT
)
''')

# -------------------------------
# PAYMENTS TABLE (FIXED)
# -------------------------------
cursor.execute('''
CREATE TABLE IF NOT EXISTS manual_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    plan TEXT,
    payment_code TEXT,
    utr TEXT,
    status TEXT DEFAULT 'Pending',
    amount REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

# -------------------------------
# OPTIONAL: SYSTEM LOGS TABLE
# -------------------------------
cursor.execute('''
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT,
    level TEXT,
    message TEXT,
    ip TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

# -------------------------------
# CREATE ADMIN USER
# -------------------------------
test_username = "admin"
test_email = "jashthakkar77@gmail.com"
test_password = "admin@123"
hashed_pw = generate_password_hash(test_password)

try:
    cursor.execute(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', 
        (test_username, test_email, hashed_pw)
    )
    print("✅ Admin user created")
except sqlite3.IntegrityError:
    print("ℹ️ Admin already exists")

# -------------------------------
# COMMIT & CLOSE
# -------------------------------
conn.commit()
conn.close()

print("✅ Database fully configured successfully!")