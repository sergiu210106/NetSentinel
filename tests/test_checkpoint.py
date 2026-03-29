"""
Sprint 2 - Checkpoint: Manual Packet Replay (updated)

Sends crafted benign and malicious-looking packet dicts directly to the
server over TCP. Each packet is annotated with which detection layer should
catch it so you can verify both paths work.

Usage:
    python3 test_checkpoint.py
"""

import socket
import json
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999

TEST_PACKETS = [
    # ── Benign — should pass both heuristics and ML ─────────────────────
    {
        "label_hint": "BENIGN (HTTPS)  → expect: [INFO]",
        "src_ip": "192.168.1.10", "dst_ip": "93.184.216.34",
        "protocol": "TCP", "size": 74, "dst_port": 443,
    },
    {
        "label_hint": "BENIGN (DNS)    → expect: [INFO]",
        "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
        "protocol": "UDP", "size": 60, "dst_port": 53,
    },
    {
        "label_hint": "BENIGN (HTTP)   → expect: [INFO]",
        "src_ip": "192.168.1.22", "dst_ip": "142.250.80.46",
        "protocol": "TCP", "size": 512, "dst_port": 80,
    },

    # ── Malicious via HEURISTIC Rule 1: flood-sized packet ───────────────
    {
        "label_hint": "MALICIOUS (flood, Rule 1: size >= 9001) → expect: [ALERT]",
        "src_ip": "10.0.0.99", "dst_ip": "192.168.1.1",
        "protocol": "TCP", "size": 65535, "dst_port": 80,
    },
    {
        "label_hint": "MALICIOUS (flood, Rule 1: size >= 9001) → expect: [ALERT]",
        "src_ip": "10.0.0.99", "dst_ip": "192.168.1.1",
        "protocol": "UDP", "size": 65000, "dst_port": 0,
    },

    # ── Malicious via HEURISTIC Rule 2: known malware port ───────────────
    {
        "label_hint": "MALICIOUS (Metasploit port 4444, Rule 2) → expect: [ALERT]",
        "src_ip": "203.0.113.45", "dst_ip": "192.168.1.100",
        "protocol": "TCP", "size": 200, "dst_port": 4444,
    },
    {
        "label_hint": "MALICIOUS (Back Orifice port 31337, Rule 2) → expect: [ALERT]",
        "src_ip": "172.16.0.200", "dst_ip": "192.168.1.50",
        "protocol": "TCP", "size": 44, "dst_port": 31337,
    },

    # ── Malicious via ML model (normal-sized, normal port — rules won't fire) ─
    # NSL-KDD neptune records: duration=0, protocol=tcp, src_bytes=0, dst_bytes=0
    # Our ML model should catch these since they look like the dataset's attack rows
    {
        "label_hint": "MALICIOUS (neptune-like, zero-byte SYN) → expect: [ALERT] via ML",
        "src_ip": "10.0.0.50", "dst_ip": "192.168.1.1",
        "protocol": "TCP", "size": 0, "dst_port": 80,
    },
]


def send_packets():
    print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...\n")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
    except ConnectionRefusedError:
        print("[-] Connection refused. Start the server first.")
        return

    print(f"[*] Sending {len(TEST_PACKETS)} test packets...\n")
    print("─" * 70)

    for pkt in TEST_PACKETS:
        hint = pkt.pop("label_hint")
        print(f"→ {hint}")
        message = json.dumps(pkt) + "\n"
        sock.sendall(message.encode("utf-8"))
        time.sleep(0.4)

    print("─" * 70)
    print("[+] Done. Check the server terminal for results.")
    sock.close()


if __name__ == "__main__":
    send_packets()
