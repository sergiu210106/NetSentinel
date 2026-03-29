import socket
import json
import time
from scapy.all import sniff, IP, TCP, UDP

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999

# Global socket connection
client_socket = None

def connect_to_server():
    """Establishes a TCP connection to the server."""
    global client_socket
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to server at {SERVER_HOST}:{SERVER_PORT}")
    except ConnectionRefusedError:
        print("[-] Connection failed. Is the server running?")
        exit(1)

def process_packet(packet):
    """Callback for every packet sniffed."""
    
    # We only care about IP packets (ignore ARP, etc. for now)
    if not packet.haslayer(IP):
        return

    # Initialize data dictionary
    packet_info = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto, # Protocol number (e.g., 6 for TCP, 17 for UDP)
        "size": len(packet),
        "dst_port": 0 # Default if no port exists
    }

    # Extract ports if TCP or UDP
    if packet.haslayer(TCP):
        packet_info["dst_port"] = packet[TCP].dport
        packet_info["protocol"] = "TCP"
    elif packet.haslayer(UDP):
        packet_info["dst_port"] = packet[UDP].dport
        packet_info["protocol"] = "UDP"

    # Send to server
    send_data(packet_info)

def send_data(data):
    """Serializes data and sends it to the server."""
    global client_socket
    try:
        # Convert to JSON, add newline (delimiter), encode to bytes
        message = json.dumps(data) + "\n"
        client_socket.sendall(message.encode('utf-8'))
        print(f"[SENT] {data['src_ip']} -> {data['dst_ip']} : {data['size']} bytes")
    except BrokenPipeError:
        print("[-] Lost connection to server. Reconnecting...")
        connect_to_server() # Simple reconnection logic
        send_data(data)     # Retry sending

def start_sniffing():
    print("[*] Starting packet sniffer...")
    # count=0 means sniff indefinitely
    # prn=process_packet calls our function on every packet
    # store=0 prevents storing packets in memory (saves RAM)
    sniff(prn=process_packet, store=0)

if __name__ == "__main__":
    connect_to_server()
    start_sniffing()