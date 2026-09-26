import sqlite3

conn = sqlite3.connect("alerts.db", check_same_thread=False)

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts(
id INTEGER PRIMARY KEY AUTOINCREMENT,
message TEXT
)
""")

conn.commit()

def add_alert(msg):

    cursor.execute(
        "INSERT INTO alerts(message) VALUES(?)",
        (msg,)
    )

    conn.commit()

def get_alerts():

    cursor.execute("SELECT * FROM alerts")

    return cursor.fetchall()