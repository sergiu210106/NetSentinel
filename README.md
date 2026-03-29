# 🛡️ NetSentinel — Sprint 1: The Data Pipeline

> **Status:** ✅ Complete  
> **Goal:** Capture live network packets on one machine and stream them in real-time to a server via TCP sockets.

---

## Overview

Sprint 1 establishes the core data pipeline of the NetSentinel IDS (Intrusion Detection System). A lightweight **Agent** sniffs raw network packets using Scapy, extracts key features, serializes them as JSON, and transmits them over TCP to a **Server** that listens asynchronously and prints incoming data to the console.

---

## Architecture

```
┌─────────────────────────────┐         TCP Socket          ┌──────────────────────────────┐
│           AGENT             │   ────────────────────►     │           SERVER             │
│                             │                             │                              │
│  scapy sniff()              │    {"src_ip": "...",        │  asyncio TCP listener        │
│     │                       │     "dport": 443,           │     │                        │
│     ▼                       │     "size": 1200,           │     ▼                        │
│  extract features           │     "protocol": "TCP"}      │  deserialize JSON            │
│     │                       │                             │     │                        │
│     ▼                       │                             │     ▼                        │
│  JSON serialize             │                             │  print to console            │
│     │                       │                             │                              │
│     ▼                       │                             │                              │
│  TCP socket send            │                             │                              │
└─────────────────────────────┘                             └──────────────────────────────┘
```

---

## Project Structure

```
top-repo-git/
├── agent/
│   ├── venv/
│   ├── agent.py          # Packet sniffer + TCP socket client
│   └── requirements.txt
└── server/
    ├── venv/
    ├── server.py         # Async TCP socket server
    └── requirements.txt
```

---

## Features Extracted Per Packet

| Field      | Description                          | Example           |
|------------|--------------------------------------|-------------------|
| `src_ip`   | Source IP address of the packet      | `192.168.1.5`     |
| `dport`    | Destination port                     | `443`             |
| `size`     | Total packet size in bytes           | `1200`            |
| `protocol` | Transport protocol (TCP / UDP / Other) | `TCP`           |

---

## Setup & Installation

### Prerequisites

- Python 3.10+
- Two terminal windows (or two machines on the same network)
- Root / sudo privileges on the agent machine (required for raw packet sniffing)

---

### Agent Setup

```bash
cd agent/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**`requirements.txt`**
```
scapy
```

---

### Server Setup

```bash
cd server/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**`requirements.txt`**
```
# no third-party deps — uses stdlib asyncio only
```

---

## Running the Pipeline

### 1. Start the Server first

```bash
cd server/
source venv/bin/activate
python3 server.py
```

You should see:
```
[SERVER] Listening on 0.0.0.0:9999...
```

---

### 2. Start the Agent

> ⚠️ Raw packet sniffing requires root. Use the venv Python explicitly to avoid the `ModuleNotFoundError` with sudo.

```bash
cd agent/
sudo venv/bin/python3 agent.py
```

Or, to avoid sudo entirely, grant network capabilities to the Python binary once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f venv/bin/python3)
# Then run without sudo:
venv/bin/python3 agent.py
```

---

## Checkpoint Verification ✅

With both processes running, generate some traffic on the agent machine (open a browser, ping a host, etc.). You should see output like this on the **server terminal**:

```
[SERVER] Connection from ('192.168.1.5', 52341)
[PACKET] {"src_ip": "192.168.1.5", "dport": 443, "size": 1200, "protocol": "TCP"}
[PACKET] {"src_ip": "192.168.1.5", "dport": 53,  "size": 74,   "protocol": "UDP"}
[PACKET] {"src_ip": "10.0.0.1",    "dport": 80,  "size": 512,  "protocol": "TCP"}
```

Sprint 1 is complete when packets captured on the agent terminal appear printed on the server terminal in real time. ✅

---

## Known Issues & Notes

- **`ModuleNotFoundError: No module named 'scapy'` when using `sudo`** — `sudo` resets `PATH` and drops the venv. Fix: call the venv Python binary directly (`sudo venv/bin/python3 agent.py`) or use `setcap` as shown above.
- The agent currently sends **every** sniffed packet. Filtering (e.g., by interface or port range) can be added to the `sniff()` call to reduce noise.
- The server address and port are currently hardcoded. These will be moved to environment variables in Sprint 4 during Dockerization.

---

## Up Next — Sprint 2: Intelligence & Logic

Sprint 2 will replace the server's `print` statement with a **Random Forest classifier** trained on the NSL-KDD dataset, adding real-time `Benign` / `Malicious` classification to every packet received.
