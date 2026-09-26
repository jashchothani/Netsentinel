from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import threading

# Global dictionary to hold live traffic
traffic = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set(), "type": "Unknown"})

def process_packet(packet):
    if IP in packet:
        ip = packet[IP].src
        
        # Ignore local router/self traffic to avoid noise
        if ip.startswith("192.168.") and ip.endswith(".1"): return
        if ip == "127.0.0.1": return

        traffic[ip]["packets"] += 1
        traffic[ip]["bytes"] += len(packet)

        if TCP in packet:
            traffic[ip]["ports"].add(packet[TCP].dport)
        elif UDP in packet:
            traffic[ip]["ports"].add(packet[UDP].dport)

def reset_memory():
    """Clears the traffic dictionary every 5 minutes to prevent RAM crashes."""
    global traffic
    while True:
        time.sleep(300)
        traffic.clear()
        print("[SYSTEM] Cleared sniffer memory cache.")

def start_sniffing():
    print("[SYSTEM] Packet Sniffer Started in Background...")
    # Start the memory manager on a separate thread
    threading.Thread(target=reset_memory, daemon=True).start()
    # Start sniffing
    sniff(prn=process_packet, store=False)