```markdown
# 🛡️ NetSentinel

A real-time network intrusion detection system built across 4 sprints — from raw packet capture to a live ML-powered dashboard.

---

## Quick Start

```bash
# 1. Train the ML model (one-time)
cd server && source venv/bin/activate && python3 train_model.py

# 2. Start the server
python3 server.py

# 3. In a new terminal — start the agent (requires root)
cd agent && sudo venv/bin/python3 agent.py
```

Packets are now captured, streamed, and classified in real time. Open a browser or run `ping` to see alerts in your server terminal.

---

## Architecture

```
┌──────────────────┐       TCP + JSON       ┌─────────────────────────────────────────┐
│      AGENT       │  ──────────────────►   │                 SERVER                  │
│                  │                        │                                         │
│  scapy sniff()   │  {"src_ip": "...",     │  asyncio TCP listener                   │
│       │          │   "dst_port": 443,     │       │                                 │
│       ▼          │   "size": 1200,        │       ▼                                 │
│  extract features│   "protocol": "TCP"}   │  ThreatDetector.predict()              │
│       │          │                        │       │                                 │
│       ▼          │                        │       ├─ Heuristics (size, blocked ports)│
│  JSON serialize  │                        │       │                                 │
│       │          │                        │       └─ Random Forest (NSL-KDD)        │
│       ▼          │                        │       │                                 │
│  TCP send        │                        │       ▼                                 │
└──────────────────┘                        │  [ALERT] or [INFO]                      │
                                            └─────────────────────────────────────────┘
```

---

## Sprint Roadmap

| Sprint | Goal | Status |
|--------|------|--------|
| 1 | Live packet capture → TCP socket pipeline | ✅ Complete |
| 2 | ML classification with Random Forest on NSL-KDD | ✅ Complete |
| 3 | FastAPI backend + SQLite + React dashboard | 🔜 Upcoming |
| 4 | Docker, docker-compose, attack demo | 🔜 Upcoming |

---

## Project Structure

```
netsentinel/
│
├── agent/                          # Sprint 1 — Packet capture
│   ├── venv/
│   ├── agent.py
│   └── requirements.txt
│
├── server/                         # Sprints 1 & 2 — Listener + ML inference
│   ├── venv/
│   ├── server.py
│   ├── threat_detector.py          # Sprint 2
│   ├── train_model.py              # Sprint 2
│   ├── test_checkpoint.py          # Sprint 2
│   ├── model.pkl                   # Sprint 2 — generated, not committed
│   ├── KDDTrain+.txt               # Sprint 2 — generated, not committed
│   └── requirements.txt
│
├── frontend/                       # Sprint 3 — React dashboard
│
├── docker-compose.yml              # Sprint 4 — orchestration
├── .gitignore
└── README.md
```

---

# Sprint 1: The Data Pipeline ✅

Capture live network packets on one machine and stream them in real-time to a server via TCP sockets.

## Features Extracted Per Packet

| Field | Description | Example |
|-------|-------------|---------|
| `src_ip` | Source IP address | `192.168.1.5` |
| `dst_ip` | Destination IP address | `93.184.216.34` |
| `dst_port` | Destination port | `443` |
| `size` | Total packet size in bytes | `1200` |
| `protocol` | Transport protocol | `TCP` |

## Setup

### Prerequisites
- Python 3.10+
- Root / sudo privileges on the agent machine (required for raw packet sniffing)

### Agent
```bash
cd agent/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # scapy
```

### Server
```bash
cd server/
python3 -m venv venv
source venv/bin/activate
# Sprint 1 uses stdlib asyncio only — no third-party deps yet
```

## Running

**1. Start the server**
```bash
cd server && source venv/bin/activate
python3 server.py
# [*] Server listening on ('127.0.0.1', 9999)
```

**2. Start the agent**

> ⚠️ Raw sniffing requires root. Call the venv Python directly to keep scapy available under sudo.

```bash
cd agent && sudo venv/bin/python3 agent.py
```

Or grant capabilities once to skip `sudo` permanently:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f venv/bin/python3)
venv/bin/python3 agent.py
```

## Checkpoint ✅

With both processes running, generate traffic on the agent machine (open a browser, run `ping`). The server terminal should print:

```
[+] New connection from ('127.0.0.1', 52341)
[RECEIVED] {'src_ip': '192.168.1.5', 'dst_ip': '93.184.216.34', 'protocol': 'TCP', 'size': 1200, 'dst_port': 443}
[RECEIVED] {'src_ip': '192.168.1.5', 'dst_ip': '8.8.8.8',       'protocol': 'UDP', 'size': 74,   'dst_port': 53}
```

---

# Sprint 2: Intelligence and Logic ✅

Replace the `print` statement with a classifier that labels every packet **Benign** or **Malicious** in real time using a two-layer detection approach: fast rule-based heuristics backed by a Random Forest model trained on NSL-KDD.

## Detection Logic

`ThreatDetector.predict()` runs two layers in order. The ML model only runs if no heuristic fires:

```
packet
  │
  ▼
Rule 1: size >= 9001 bytes?         → Malicious (confidence: 0.97)
Rule 2: dst_port in blocklist?      → Malicious (confidence: 0.91)
  │ (no rule fired)
  ▼
Random Forest (4 features)          → Benign / Malicious + probability
```

**Why heuristics first?** NSL-KDD records are *session-level* (total bytes across an entire connection). A model trained on session totals cannot reliably classify a single 65,535-byte packet as a flood — that packet is statistically normal as a session total. Rules give reliable signal for the obvious cases; the ML model handles subtler patterns like zero-byte SYN floods (neptune-style attacks), where the training data provides genuine signal.

## Feature Mapping: Agent dict → NSL-KDD features

| NSL-KDD feature | Agent field | Rationale |
|-----------------|-------------|-----------|
| `duration` | `0` | Session duration not tracked per-packet |
| `protocol_type` | `protocol` | TCP→0, UDP→1, ICMP→2, other→-1 |
| `src_bytes` | `size` | Packet size is the best live proxy |
| `dst_bytes` | `0` | Not observable at capture time |

## Blocked Ports (Rule 2)

| Port | Associated threat |
|------|-------------------|
| 4444 | Metasploit default listener |
| 1337 | Common backdoor |
| 31337 | Back Orifice RAT |
| 6667 | IRC botnet C2 |
| 9001 | Tor / Cobalt Strike |
| 8888 | Common RAT port |
| 12345 | NetBus |
| 27374 | Sub7 |

## Setup

```bash
cd server && source venv/bin/activate
pip install -r requirements.txt   # scikit-learn, pandas, numpy
```

## Running

**Step 1 — Train the model (one-time)**
```bash
python3 train_model.py
```

```
[*] Downloading NSL-KDD dataset...
[*] Loaded 125,973 rows from dataset.
[*] Class distribution — Benign: 67,343  |  Malicious: 58,630
[*] Training Random Forest on 100,778 samples…
[+] Training complete.

── Evaluation on hold-out test set ──────────────────────────────
              precision    recall  f1-score   support

      Benign       1.00      0.95      0.97     13469
   Malicious       0.95      1.00      0.97     11726

    accuracy                           0.97     25195

[+] Model saved to 'model.pkl'
```

**Step 2 — Start the server**
```bash
python3 server.py
# [+] ThreatDetector: model loaded from 'model.pkl'
# [*] NetSentinel server listening on ('127.0.0.1', 9999)
```

**Step 3 — Run the live agent OR the checkpoint test**

Live (requires Sprint 1 agent running):
```bash
cd ../agent && sudo venv/bin/python3 agent.py
```

Or replay crafted packets without scapy:
```bash
cd server && python3 test_checkpoint.py
```

## Checkpoint ✅

All 8 test packets classified correctly across both detection layers:

```
[INFO]  Normal traffic             | 192.168.1.10 → 93.184.216.34:443  | TCP |     74B | confidence: 100.0%
[INFO]  Normal traffic             | 192.168.1.10 → 8.8.8.8:53         | UDP |     60B | confidence: 100.0%
[INFO]  Normal traffic             | 192.168.1.22 → 142.250.80.46:80   | TCP |    512B | confidence: 100.0%
[ALERT] Malicious traffic detected | 10.0.0.99    → 192.168.1.1:80     | TCP |  65535B | confidence:  97.0%  ← Rule 1
[ALERT] Malicious traffic detected | 10.0.0.99    → 192.168.1.1:0      | UDP |  65000B | confidence:  97.0%  ← Rule 1
[ALERT] Malicious traffic detected | 203.0.113.45 → 192.168.1.100:4444 | TCP |    200B | confidence:  91.0%  ← Rule 2
[ALERT] Malicious traffic detected | 172.16.0.200 → 192.168.1.50:31337 | TCP |     44B | confidence:  91.0%  ← Rule 2
[ALERT] Malicious traffic detected | 10.0.0.50    → 192.168.1.1:80     | TCP |      0B | confidence:  93.4%  ← ML
```

The last packet (zero-byte SYN, normal port) is the most significant — both heuristic rules passed it through, and the Random Forest identified it as a neptune-style attack from the NSL-KDD training data alone.

---

# Sprint 3: The Frontend & Database 🔜

**Goal:** Persist the data and visualize it in a browser instead of the console.

## Planned Architecture

```
┌──────────┐   TCP/JSON   ┌──────────────────────────────────────────┐
│  AGENT   │ ──────────►  │                 SERVER                   │
└──────────┘              │                                          │
                          │  ThreatDetector.predict()                │
                          │       │                                  │
                          │       ▼                                  │
                          │  SQLite  ──►  FastAPI                   │
                          │                │    │                    │
                          │                │    ├─ GET /alerts       │
                          │                │    └─ WS  /ws          │
                          │                │         │              │
                          └────────────────┼─────────┼──────────────┘
                                           │         │
                                           │    WebSocket
                                           │         │
                                     ┌─────▼─────────▼─────┐
                                     │      REACT APP      │
                                     │                     │
                                     │  ┌───────────────┐  │
                                     │  │  Alerts Table  │  │
                                     │  │  (live update) │  │
                                     │  └───────────────┘  │
                                     └─────────────────────┘
```

## Tasks

| Task | Description |
|------|-------------|
| 3.1 | Set up SQLite — create `alerts` table (`id`, `timestamp`, `src_ip`, `prediction`, `confidence`) |
| 3.2 | Wrap server logic in FastAPI — `GET /alerts` (last 50) + `WS /ws` (real-time push) |
| 3.3 | Build React dashboard — alerts table, native WebSocket connection, live state updates |

---

# Sprint 4: Containerization & Attack Demo 🔜

**Goal:** Dockerize the full stack and prove detection works against a simulated threat.

## Planned Architecture

```
                    docker-compose network
    ┌─────────────────────────────────────────────────────────┐
    │                                                         │
    │  ┌──────────┐   TCP    ┌────────────┐   API/WS   ┌──────────┐
    │  │  AGENT   │ ──────► │   SERVER   │ ─────────► │ FRONTEND │
    │  │ (NET_ADMIN)│        │            │            │  (Nginx) │
    │  └──────────┘         │  SQLite    │            └──────────┘
    │                        └────────────┘                    │
    │                             ▲                           │
    │                             │                           │
    │  ┌──────────┐   raw pkts   │                           │
    │  │ ATTACKER │ ─────────────┘                           │
    │  │ (temp)   │                                          │
    │  └──────────┘                                          │
    └─────────────────────────────────────────────────────────┘
```

## Tasks

| Task | Description |
|------|-------------|
| 4.1 | Dockerize all components (Agent needs `NET_ADMIN`, Frontend uses Nginx) |
| 4.2 | Write `docker-compose.yml` with service definitions and environment variables |
| 4.3 | Write attack script — rapid requests (DoS sim) + blocked-port probes |
| 4.4 | Final verification — `docker-compose up`, trigger attacker, watch dashboard |
| 4.5 | Add dashboard screenshot and architecture diagram to this README |

---

## .gitignore

```gitignore
# Python
venv/
__pycache__/
*.pyc

# Model artefacts — not portable across Python versions
server/model.pkl
server/KDDTrain+.txt

# Frontend (Sprint 3)
frontend/node_modules/
frontend/build/
```

---

## License

This project is for educational and research purposes.
```