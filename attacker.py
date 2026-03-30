import socket
import time

TARGET_IP = "netsentinel-server" # Run this on your host machine against the exposed docker ports
TARGET_PORT = 9999

# Trigger Rule 2: Blocklisted Ports
MALICIOUS_PORTS = [4444, 31337, 9001]

print("[*] Initiating simulated attack sequence...")

# 1. Port Scanning Phase (Heuristics)
for port in MALICIOUS_PORTS:
    print(f"[-] Probing suspicious port {port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((TARGET_IP, port))
        s.close()
    except Exception:
        pass
    time.sleep(0.5)

# 2. Volumetric Attack Phase (Rule 1: Over 9001 Bytes)
print(f"[-] Launching volumetric UDP flood on port {TARGET_PORT}...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Send a massive 65,000 byte packet
    s.sendto(b'X' * 65000, (TARGET_IP, TARGET_PORT))
except Exception as e:
    print(f"Error: {e}")

# 3. Neptune/SYN flood simulation (ML Layer)
print(f"[-] Sending zero-byte TCP packets...")
for _ in range(5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((TARGET_IP, TARGET_PORT))
        # Immediate close without sending data
        s.close()
    except Exception:
        pass

print("[+] Attack sequence complete. Check your NetSentinel Dashboard!")