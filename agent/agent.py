import socket
import json
import time
import os
from scapy.all import sniff, IP, TCP, UDP

# Configuration
SERVER_HOST = os.getenv('SERVER_IP', '127.0.0.1')
SERVER_PORT = int(os.getenv('SERVER_PORT', 9999))

# Global socket connection
client_socket = None

def connect_to_server():
    """Establishes a TCP connection to the server with retry logic."""
    global client_socket
    while True: # Keep trying until successful
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[+] Connected to server at {SERVER_HOST}:{SERVER_PORT}")
            return # Exit the loop once connected
        except ConnectionRefusedError:
            print(f"[-] Server not ready at {SERVER_HOST}:{SERVER_PORT}. Retrying in 5s...")
            time.sleep(5)
        except Exception as e:
            print(f"[-] Unexpected error: {e}. Retrying...")
            time.sleep(5)

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
    
    # FILTER EXPLANATION:
    # "not port 9999" -> Ignore traffic to/from the Agent-to-Server TCP link
    # "not port 8000" -> Ignore traffic to/from the FastAPI/WebSocket link
    # "not port 80"   -> Ignore traffic to/from the Frontend web server
    
    bpf_filter = f"not port {SERVER_PORT} and not port 8000 and not port 80"
    
    # Add the 'filter' argument here:
    sniff(
        prn=process_packet, 
        filter=bpf_filter, 
        store=0
    )

if __name__ == "__main__":
    connect_to_server()
    start_sniffing()