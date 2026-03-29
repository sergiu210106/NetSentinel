# Sprint 1: The Data Pipeline
## **Goal**: Capture live network data on one machine and send it to another machine (or container) via sockets 
- **Setup environment**
  - Create Github Repository
  - Set up two Python virtual environments: one for the `agent`, one for the server 
- **Task 1.1: Build the Packet Sniffer (Agent Side)**:
  - use `scapy` to write a script that sniff packages on my local machine
  - Extract 4 key features: **Source IP, Destination Port, Packet Size, Protocol**
  - store these in a Python dictionary (e.g., `{"src_ip": "192.168.1.5, "dport": "80", "size": 1200}`).
- **Task 1.2: Implement Socket Transmission:** 
  - Write a TCP Socket Client in the Agent Script
  - Serialize the dictionary using `JSON`
  - Send the data to a specific IP and Port.
- **Task 1.3: Build the Listener (Server Side):**
  - Write a TCP Socket Server using Python's `asyncio`
  - The server should listen for connections, receive the JSON data, and simply print it to the console.
- **Checkpoint**: *Run the Agent and Server in two separate terminal windows. Verify that packets appearing on the Agent terminal are printed on the Server terminal.*


# Sprint 2: Intelligence and Logic
## **Goal**: Replace the print statement with a Machine Learning model that classifies the traffic.
- **Task 2.1: Dataset Preparation:**
  - Download the **NSL-KDD** dataset (a smaller, cleaner version of the famous KDD'99 dataset).
  - Write a script to load it into Pandas. Drop columns you aren't using (keep it simple: duration, protocol, src_bytes, dst_bytes).
  - Train a **Random Forest Classifier** (using `sklearn`). It is fast and requires less tuning than Neural Networks.
  - Save the trained model using `pickle`.
- **Task 2.2: OOP Refactoring (Server Side):**
  - Create a class `ThreatDetector`.
  - Method `load_model()`: Loads the pickle file.
  - Method `predict(packet_data)`: Takes the dictionary from sprint 1, preprocesses it (encoding protocols to numbers), and returns `Benign` or `Malicious`.
- **Task 2.3: Integrate inference:**
  - Update your Server to instantiate `ThreatDetector` on startup.
  - For every packet received, call `predict()`.
  - Log the result to the console: `[ALERT] Malicious traffic detected from 192.168.1.5` or `[INFO] Normal Traffic`.
- **Checkpoint**: Run the system. Manually craft a "malicious-looking" packet (or replay part of the dataset) to see if the model flags it.

# Sprint 3: The Frontend & Database (Fullstack)
## **Goal**: Persist the data and visualize it in a browser instead of the console.

- **Task 3.1: Database Integration:**
  - Set up a simple SQLite database (or Redis for speed) on the Server.
  - Create a table alerts with columns: id, timestamp, src_ip, prediction, confidence.
- **Task 3.2: Backend API (Server Side):**
  - Wrap your Server logic in FastAPI.
  - Endpoint `GET /alerts`: Returns the last 50 alerts from the database.
  - Endpoint `WS /ws`: A WebSocket endpoint that pushes new alerts to connected clients in real-time.
- **Task 3.3: The Dashboard (Frontend):**
  - Initialize a React app.
  - Create a simple UI: A table to list alerts.
  - Use the native browser WebSocket API to connect to the server.
  - When a message arrives, update the state to add the new alert to the list instantly.
- **Checkpoint:** Open the browser. See the alerts populating in real-time as the Agent sends data.


# Sprint 4: Containerization & The "Attack" Demo (DevOps & Security)
## **Goal**: Dockerize the application and prove it works against a simulated threat.

- **Task 4.1: Dockerize the Components:**
  - Write a Dockerfile for the Agent. (Note: It requires network privileges: NET_ADMIN to sniff).
  - Write a Dockerfile for the Server.
  - Write a Dockerfile for the Frontend (using Nginx to serve the React build).
- **Task 4.2: Orchestration:**
  - Write a docker-compose.yml.
  - Define services: agent, server, frontend.
  - Ensure the Agent knows the Server's hostname via environment variables.
- **Task 4.3: The Attack Script:**
  - Write a simple Python script that acts as an "Attacker." It should send thousands of requests rapidly (simulating a DoS) or use specific ports associated with malware.
  - Run this script inside a temporary container on the same network.
- **Task 4.4: Final Verification:**
  - Run docker-compose up.
  - Open the Dashboard.
  - Trigger the "Attacker" script.
  - Visual Proof: Watch the Dashboard light up with "Malicious" alerts.
- **Task 4.5: Documentation:**
  - Add a README.md with a screenshot of the dashboard, architecture diagram, and instructions on how to run docker-compose up.