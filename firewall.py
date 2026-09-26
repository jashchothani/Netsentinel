import subprocess
import sqlite3
from datetime import datetime
from system_logger import log_event

def init_firewall_db():
    """Creates a database to track our active firewall rules."""
    conn = sqlite3.connect('firewall.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_firewall_db()

def get_active_rules():
    """Fetches all currently blocked IPs."""
    conn = sqlite3.connect('firewall.db')
    conn.row_factory = sqlite3.Row
    rules = conn.execute('SELECT * FROM rules ORDER BY id DESC').fetchall()
    conn.close()
    return [dict(r) for r in rules]

def block_ip_in_firewall(ip_address):
    """Executes a Windows command to drop packets from this IP."""
    safe_ips = ['127.0.0.1', '192.168.1.1', '192.168.0.1', 'localhost']
    if ip_address in safe_ips: 
        return {"success": False, "error": f"Cannot block protected system IP: {ip_address}"}

    rule_name = f"NetSentinel_Block_{ip_address}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 or "Ok." in result.stdout:
            log_event("Security", "High", f"Firewall rule created to block {ip_address}", ip_address)
            
            # Save to our tracking database
            try:
                conn = sqlite3.connect('firewall.db')
                conn.execute('INSERT INTO rules (ip_address, timestamp) VALUES (?, ?)', 
                            (ip_address, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
                conn.close()
            except sqlite3.IntegrityError:
                pass # IP is already in the database

            return {"success": True, "message": f"Successfully blocked {ip_address}"}
        else:
            return {"success": False, "error": "Run server as Administrator to modify firewall."}
            
    except Exception as e:
        return {"success": False, "error": str(e)}

def unblock_ip_in_firewall(ip_address):
    """Deletes the block rule from Windows Defender."""
    rule_name = f"NetSentinel_Block_{ip_address}"
    command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    
    try:
        subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Remove from our tracking database
        conn = sqlite3.connect('firewall.db')
        conn.execute('DELETE FROM rules WHERE ip_address = ?', (ip_address,))
        conn.commit()
        conn.close()
        
        log_event("Security", "Info", f"Firewall block removed for {ip_address}", ip_address)
        return {"success": True, "message": f"Unblocked {ip_address}"}
    except Exception as e:
        return {"success": False, "error": str(e)}