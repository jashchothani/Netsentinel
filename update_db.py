import sqlite3

conn = sqlite3.connect('database.db')
conn.execute('''
    CREATE TABLE IF NOT EXISTS manual_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        plan TEXT,
        payment_code TEXT,
        utr TEXT UNIQUE,
        status TEXT DEFAULT 'Pending',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')
conn.commit()
conn.close()
print("Manual payments table created!")