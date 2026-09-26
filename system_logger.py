import sqlite3
from datetime import datetime

def init_log_db():
    """Creates the unified system logs table if it doesn't exist."""
    conn = sqlite3.connect('system_logs.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            category TEXT,
            severity TEXT,
            message TEXT,
            ip_address TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize it immediately
init_log_db()

def log_event(category, severity, message, ip_address="System"):
    """Saves a system event permanently to the database."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = sqlite3.connect('system_logs.db')
        
        # Prevent spamming the exact same log within a short timeframe
        last_log = conn.execute(
            'SELECT * FROM logs WHERE message = ? AND ip_address = ? ORDER BY id DESC LIMIT 1', 
            (message, ip_address)
        ).fetchone()

        conn.execute('INSERT INTO logs (timestamp, category, severity, message, ip_address) VALUES (?, ?, ?, ?, ?)',
                    (current_time, category, severity, message, ip_address))
        conn.commit()
        conn.close()
        print(f"[LOG] [{category}] {severity}: {message} | {ip_address}")
    except Exception as e:
        print(f"[DB ERROR] Could not write system log: {e}")