"""
Sprint 3 - Task 3.2: Backend API
Replaces server.py entirely.

Three things run concurrently inside one asyncio event loop:
  1. FastAPI HTTP server (uvicorn)       — GET /alerts, GET /stats
  2. FastAPI WebSocket endpoint          — WS /ws  (real-time broadcast)
  3. Raw TCP listener                    — receives JSON from the agent
"""

import asyncio
import json

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from database import init_db, insert_alert, get_recent_alerts, get_stats
from threat_detector import ThreatDetector

# ── Configuration ─────────────────────────────────────────────────────────────
TCP_HOST  = "0.0.0.0"
TCP_PORT  = 9999
HTTP_PORT = 8000

# ── App setup ─────────────────────────────────────────────────────────────────
app      = FastAPI(title="NetSentinel")
detector = ThreatDetector()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tightened in Sprint 4 via env var
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── WebSocket connection manager ──────────────────────────────────────────────

class ConnectionManager:
    """Tracks all live browser WebSocket connections and fans out messages."""

    def __init__(self):
        self._clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)
        print(f"[WS] Client connected  — {len(self._clients)} active")

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)
        print(f"[WS] Client disconnected — {len(self._clients)} active")

    async def broadcast(self, payload: dict) -> None:
        """Send payload to every connected browser tab."""
        dead: set[WebSocket] = set()
        for client in self._clients:
            try:
                await client.send_json(payload)
            except Exception:
                dead.add(client)
        self._clients -= dead


manager = ConnectionManager()


# ── HTTP routes ───────────────────────────────────────────────────────────────

@app.get("/alerts")
async def read_alerts(limit: int = 50):
    """Returns the last `limit` alerts (default 50), newest first."""
    return await get_recent_alerts(limit)


@app.get("/stats")
async def read_stats():
    """Returns aggregate counts: total, benign, malicious."""
    return await get_stats()


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # Keep the connection alive; we only push, never pull from browser
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── TCP packet receiver ───────────────────────────────────────────────────────

async def handle_agent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handles one persistent TCP connection from the agent."""
    addr = writer.get_extra_info("peername")
    print(f"[TCP] Agent connected from {addr}")

    try:
        while True:
            raw = await reader.readline()
            if not raw:
                break

            try:
                packet_data = json.loads(raw.decode())
            except json.JSONDecodeError:
                print(f"[TCP] Bad JSON from {addr}")
                continue

            # Classify
            try:
                label, confidence = detector.predict(packet_data)
            except Exception as e:
                print(f"[ERR] predict() failed: {e}")
                continue

            # Persist
            row_id = await insert_alert(packet_data, label, confidence)

            # Build the broadcast payload (same shape the frontend expects)
            payload = {
                "id":         row_id,
                "timestamp":  None,   # DB assigned; frontend uses Date.now() for display
                "src_ip":     packet_data.get("src_ip", ""),
                "dst_ip":     packet_data.get("dst_ip", ""),
                "dst_port":   packet_data.get("dst_port", 0),
                "protocol":   packet_data.get("protocol", ""),
                "size":       packet_data.get("size", 0),
                "prediction": label,
                "confidence": round(confidence * 100, 1),
            }

            # Broadcast to all browser tabs
            await manager.broadcast(payload)

            # Console log (matches Sprint 2 style)
            tag = "[ALERT]" if label == "Malicious" else "[INFO] "
            print(
                f"{tag} {label:9s} | "
                f"{packet_data.get('src_ip')} → "
                f"{packet_data.get('dst_ip')}:{packet_data.get('dst_port')} | "
                f"{packet_data.get('protocol')} | "
                f"{packet_data.get('size')}B | "
                f"{confidence*100:.1f}%"
            )

    except ConnectionResetError:
        pass
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"[TCP] Agent disconnected from {addr}")


async def start_tcp_server():
    server = await asyncio.start_server(handle_agent, TCP_HOST, TCP_PORT)
    print(f"[TCP] Listening on {TCP_HOST}:{TCP_PORT}")
    async with server:
        await server.serve_forever()


# ── Startup hook ──────────────────────────────────────────────────────────────

@app.on_event("startup")
async def on_startup():
    await init_db()
    detector.load_model()
    # Run TCP server as a background task alongside uvicorn's event loop
    asyncio.create_task(start_tcp_server())
    print(f"[*] NetSentinel API ready at http://localhost:{HTTP_PORT}")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=HTTP_PORT, reload=False)