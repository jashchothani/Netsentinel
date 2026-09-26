import numpy as np
from sklearn.ensemble import IsolationForest
import random
import subprocess
import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import warnings
import os

# --- CONFIGURATION ---
ADMIN_EMAIL = os.environ.get("NETSENTINEL_MAIL_USERNAME", "")
APP_PASSWORD = os.environ.get("NETSENTINEL_MAIL_PASSWORD", "")
DB_PATH = "alerts.db"                  # Path to your SQLite DB

# In-memory set to prevent spamming emails and duplicate firewall rules
ALREADY_BLOCKED_IPS = set()

# 1. SYNTHETIC TRAINING DATA
print("[SYSTEM] Booting AI Threat Engine (Isolation Forest)...")
normal_traffic = np.array([
    [random.randint(5, 50), random.randint(1, 3), random.randint(60, 1500)] for _ in range(500)
])
anomalous_traffic = np.array([
    [random.randint(300, 1000), random.randint(20, 100), random.randint(40, 60)] for _ in range(20)
])
training_data = np.vstack([normal_traffic, anomalous_traffic])

# 2. INITIALIZE AND TRAIN THE AI MODEL
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(training_data)
print("[SYSTEM] AI Model Trained Successfully.")


# --- ACTIVE DEFENSE FUNCTIONS ---

def block_ip_firewall(ip_address):
    """Executes a Windows system command to instantly sever connection to the IP."""
    try:
        rule_name = f"NetSentinel Auto-Block {ip_address}"
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
        subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[FIREWALL] Successfully blocked inbound traffic from {ip_address}")
    except Exception as e:
        print(f"[FIREWALL ERROR] Could not block {ip_address}: {e}")


def send_alert_email(ip_address, risk_score, pkts, ports):
    """Fires a high-priority email to the administrator."""
    try:
        subject = f"🚨 CRITICAL ALERT: Intrusion Blocked ({ip_address})"
        body = (f"NetSentinel AI Engine has detected and blocked a hostile network intrusion.\n\n"
                f"Threat Details:\n"
                f"- Source IP: {ip_address}\n"
                f"- AI Risk Score: {risk_score}%\n"
                f"- Packets Sent: {pkts}\n"
                f"- Unique Ports Scanned: {ports}\n\n"
                f"Action Taken: IP has been automatically neutralized via Windows Defender Firewall.\n"
                f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = ADMIN_EMAIL
        msg['To'] = ADMIN_EMAIL

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(ADMIN_EMAIL, APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[ALERT] Emergency email sent for {ip_address}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send alert: {e}")


def log_intrusion_to_db(ip_address, risk_score, pkts, ports, avg_size):
    """Writes the immutable forensic evidence to the SQLite database."""
    try:
        # Note: Make sure DB_PATH matches your actual database name!
        # If your file is named alerts.db instead of database.db, change it here.
        conn = sqlite3.connect("alerts.db") 
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"Suspicious Traffic Detected: {pkts} packets on {ports} ports."
        
        conn.execute(
            "INSERT INTO alerts (message, src_ip, risk_score, packets, ports, avg_size, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (message, ip_address, risk_score, pkts, ports, avg_size, timestamp, "Blocked")
        )
        conn.commit()
        conn.close()
        print(f"[DATABASE] Intrusion logged for {ip_address}")
    except Exception as e:
        print(f"[DB ERROR] Could not write alert: {e}")


# --- MAIN EVALUATION ENGINE ---

def evaluate_devices(device_stats):
    """
    Takes live traffic data, evaluates it, and triggers defenses if necessary.
    """
    results = []
    
    for ip, stats in device_stats.items():
        # Ignore safe internal IPs like your router (adjust as needed)
        if ip in ['127.0.0.1', '192.168.1.1', '192.168.0.1']:
            continue

        pkts = stats.get('packets', 0)
        ports = stats.get('ports', 1)
        bytes_total = stats.get('bytes', 0)
        avg_size = bytes_total / pkts if pkts > 0 else 0

        prediction = model.predict([[pkts, ports, avg_size]])
        score = model.decision_function([[pkts, ports, avg_size]])[0]

        if prediction[0] == -1: 
            risk_level = "High"
            risk_score = min(99, round(abs(score) * 100) + 50) 
        else:
            normalized = 50 - (score * 50)
            if normalized > 30:
                risk_level = "Medium"
                risk_score = round(normalized)
            else:
                risk_level = "Low"
                risk_score = max(1, round(normalized))

        device_type = stats.get('type', 'Unknown')
        if device_type == 'Unknown' and risk_level == 'Low':
            risk_level = "Medium"
            risk_score += 15

        # 🔥 THE ACTIVE DEFENSE TRIGGER 🔥
        # If the risk is critical and we haven't blocked them yet
        if risk_level == "High" and risk_score >= 60 and ip not in ALREADY_BLOCKED_IPS:
            print(f"\n[!!!] CRITICAL THREAT DETECTED: {ip} (Score: {risk_score})")
            
            # 1. Block the IP
            block_ip_firewall(ip)
            
            # 2. Log it to the database
            log_intrusion_to_db(ip, risk_score, pkts, ports, avg_size)
            
            # 3. Send the email
            send_alert_email(ip, risk_score, pkts, ports)
            
            # 4. Remember them so we don't spam the system
            ALREADY_BLOCKED_IPS.add(ip)

        results.append({
            "ip": ip,
            "type": device_type,
            "packets": pkts,
            "avg_size": round(avg_size),
            "ports": ports,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "status": "Blocked" if ip in ALREADY_BLOCKED_IPS else "Active"
        })
        
    return sorted(results, key=lambda x: x['risk_score'], reverse=True)