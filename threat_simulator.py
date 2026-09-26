from scapy.all import IP, TCP, send
import time
import random

# The IP of the machine running NetSentinel (Use 127.0.0.1 for local testing)
TARGET_IP = "127.0.0.1" 

# We spoof the source IP so NetSentinel doesn't accidentally block your real Wi-Fi IP
SPOOFED_IP = "185.20.9.44" # Pretend we are an attacker from a remote server

def simulate_port_scan():
    """Simulates an Nmap scan by hitting 100 different ports in 2 seconds."""
    print(f"\n[⚔️] Launching Aggressive Port Scan from {SPOOFED_IP}...")
    for port in range(20, 120):
        # Create a tiny packet hitting a new port every time
        pkt = IP(src=SPOOFED_IP, dst=TARGET_IP)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
    print("[+] Attack Payload Delivered.")

def simulate_ddos_flood():
    """Simulates a Denial of Service attack by hammering one port with packets."""
    print(f"\n[⚔️] Launching DDoS Packet Flood from {SPOOFED_IP}...")
    for _ in range(800):
        # Hit port 80 repeatedly as fast as possible
        pkt = IP(src=SPOOFED_IP, dst=TARGET_IP)/TCP(dport=80, flags="S")
        send(pkt, verbose=False)
    print("[+] Attack Payload Delivered.")

def main():
    print("="*40)
    print(" NETSENTINEL THREAT SIMULATOR v1.0")
    print("="*40)
    print("1. Simulate Nmap Port Scan (High Port Variance)")
    print("2. Simulate DDoS Flood (High Packet Rate)")
    print("3. Exit")
    
    choice = input("\nSelect attack vector (1-3): ")
    
    if choice == '1':
        simulate_port_scan()
    elif choice == '2':
        simulate_ddos_flood()
    else:
        print("Exiting...")

if __name__ == "__main__":
    main()