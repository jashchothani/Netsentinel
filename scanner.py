import nmap
import socket
from datetime import datetime
from system_logger import log_event
# This global dictionary acts as our memory to track devices joining/leaving
known_devices = {}

def get_local_network_range():
    """Automatically finds your computer's IP to scan the correct network."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
        s.close()
        ip_parts = my_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24" # Fallback

def classify_device(vendor, ip):
    """Basic heuristics to guess device type based on vendor and IP."""
    v = vendor.lower()
    if ip.endswith('.1'): return 'Router'
    if any(brand in v for brand in ['apple', 'samsung', 'google', 'oneplus']): return 'Phone/Tablet'
    if any(brand in v for brand in ['dell', 'hp', 'lenovo', 'intel', 'microsoft']): return 'Laptop/PC'
    if any(brand in v for brand in ['amazon', 'philips', 'nest', 'roku', 'tuya']): return 'IoT Device'
    return 'Unknown'

def scan_network():
    global known_devices
    scanner = nmap.PortScanner()
    network = get_local_network_range()
    
    # Run the scan
    scanner.scan(hosts=network, arguments='-sn -T4')
    
    current_scan_macs = []
    
    # 1. Process all devices currently found on the network
    for host in scanner.all_hosts():
        ip = host
        mac = scanner[host]['addresses'].get('mac', 'Unknown')
        
        # Skip devices without a MAC (usually the host machine running the script)
        if mac == 'Unknown': 
            continue
            
        current_scan_macs.append(mac)
        vendor = scanner[host]['vendor'].get(mac, 'Unknown')
        
        # Determine Hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        device_type = classify_device(vendor, ip)

        # Update our memory
        known_devices[mac] = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "type": device_type,
            "status": "Active",
            "last_seen": datetime.now().strftime("%H:%M:%S")
        }
        # Determine if this is a brand new device
        is_new_device = mac not in known_devices

        # Update our memory

        if is_new_device:
            log_event("Network", "Info", f"New device connected: {vendor} ({device_type})", ip)

    # 2. Check for devices that left the network
    for mac, device in known_devices.items():
        if mac not in current_scan_macs and device["status"] != "Offline":
            known_devices[mac]["status"] = "Offline"
            log_event("Network", "Warning", f"Device went offline: {device['vendor']}", device['ip'])

    # 2. Check for devices that left the network
    for mac, device in known_devices.items():
        if mac not in current_scan_macs:
            known_devices[mac]["status"] = "Offline"

    # Return the full list of historical and current devices
    return list(known_devices.values())