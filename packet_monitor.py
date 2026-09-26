from scapy.all import sniff, IP, TCP, UDP, DNS
import threading
from collections import deque, defaultdict
import time
import sqlite3
# --- NEW: AI Data Tracker ---
from collections import defaultdict
ai_device_stats = defaultdict(lambda: {"packets": 0, "ports": set(), "bytes": 0})
# Existing traffic trackers
traffic_stats = {"TCP": 0, "UDP": 0, "DNS": 0, "HTTP": 0, "total_bytes": 0}
recent_packets = deque(maxlen=20)

# --- NEW: IDS TRACKING VARIABLES ---
alerts = deque(maxlen=50) # Stores recent security alerts
port_scan_tracker = defaultdict(set) # Tracks {src_ip: set(ports_accessed)}
packet_rate_tracker = defaultdict(int) # Tracks {src_ip: packet_count}
last_reset_time = time.time()

def init_alert_db():
    """Creates the alerts table if it doesn't exist yet."""
    conn = sqlite3.connect('alerts.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity TEXT,
            message TEXT,
            src_ip TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Run this once when the file loads
init_alert_db()

def generate_alert(severity, message, src_ip):
    """Creates a security alert and permanently stores it in the database."""
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. Save to the database for permanent logging
    try:
        conn = sqlite3.connect('alerts.db')
        # Check if this exact alert happened in the last few seconds to prevent spamming the DB
        last_alert = conn.execute(
            'SELECT * FROM alerts WHERE src_ip = ? AND message = ? ORDER BY id DESC LIMIT 1', 
            (src_ip, message)
        ).fetchone()
        
        # Simple anti-spam: only log if we haven't logged this exact thing recently
        # (In a production app, you'd check the timestamp difference)
        conn.execute('INSERT INTO alerts (timestamp, severity, message, src_ip) VALUES (?, ?, ?, ?)',
                    (current_time, severity, message, src_ip))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] Could not write alert: {e}")

    # 2. Add to the temporary RAM queue for instant UI popups (Toasts)
    alert = {"time": current_time, "severity": severity, "message": message, "src_ip": src_ip}
    recent_alerts = list(alerts)[-5:]
    if not any(a['src_ip'] == src_ip and a['message'] == message for a in recent_alerts):
        alerts.append(alert)
        print(f"\n[⚠️ IDS ALERT LOGGED] {severity} | {message} | IP: {src_ip}\n")

def process_packet(packet):
    global last_reset_time
    current_time = time.time()

    # IDS MEMORY RESET: Clear trackers every 5 seconds to analyze rate-based attacks
    if current_time - last_reset_time > 5:
        port_scan_tracker.clear()
        packet_rate_tracker.clear()
        last_reset_time = current_time

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        # Feed data to the AI tracker
        ai_device_stats[src_ip]["packets"] += 1
        ai_device_stats[src_ip]["bytes"] += size
        if TCP in packet: 
            ai_device_stats[src_ip]["ports"].add(packet[TCP].dport)
        traffic_stats["total_bytes"] += size
        protocol = "Other"

        # --- IDS: DDoS / Traffic Spike Detection ---
        packet_rate_tracker[src_ip] += 1
        if packet_rate_tracker[src_ip] > 500: # Threshold: 500 packets in 5 seconds
            generate_alert("High", "Suspicious Traffic Spike (Possible DoS)", src_ip)
            packet_rate_tracker[src_ip] = -5000 # Temporarily mute this IP from spamming alerts

        if TCP in packet:
            dport = packet[TCP].dport
            sport = packet[TCP].sport

            if sport == 80 or dport == 80 or sport == 443 or dport == 443:
                protocol = "HTTP(S)"
                traffic_stats["HTTP"] += 1
            else:
                protocol = "TCP"
                traffic_stats["TCP"] += 1

            # --- IDS: Port Scan Detection ---
            # 'S' means SYN flag. Scanners send SYN packets to check if a port is open.
            if packet[TCP].flags == 'S':
                port_scan_tracker[src_ip].add(dport)
                
                # Threshold: 15 distinct ports accessed by one IP in 5 seconds
                if len(port_scan_tracker[src_ip]) > 15: 
                    generate_alert("High", "Possible Port Scan Detected", src_ip)
                    port_scan_tracker[src_ip].clear() # Reset to avoid alert spam

        elif UDP in packet:
            if packet.haslayer(DNS):
                protocol = "DNS"
                traffic_stats["DNS"] += 1
            else:
                protocol = "UDP"
                traffic_stats["UDP"] += 1

        recent_packets.append({
            "time": time.strftime("%H:%M:%S"),
            "src": src_ip, "dst": dst_ip, "protocol": protocol, "size": size
        })

def start_sniffing_thread():
    print("[SYSTEM] Starting active IDS and packet sniffer...")
    sniff_thread = threading.Thread(target=lambda: sniff(prn=process_packet, store=False))
    sniff_thread.daemon = True
    sniff_thread.start()

def get_traffic_data():
    """Returns the stats, feed, and alerts to the Flask API."""
    return {
        "stats": traffic_stats,
        "live_feed": list(recent_packets)[::-1],
        "alerts": list(alerts)[::-1] # Send newest alerts first
    }